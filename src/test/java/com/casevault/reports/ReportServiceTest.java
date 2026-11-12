package com.casevault.reports;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.dto.ReportRequestDto;
import com.casevault.dto.ReportResponseDto;
import com.casevault.exception.BadRequestException;
import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Report;
import com.casevault.model.ReportStatus;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.ReportRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AuditLogService;
import com.casevault.service.ReportService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 7A: report workflow at the service layer (H2, real Spring context, the real security-proxied
 * {@link ReportService} bean with a real authentication in the security context, chained audit recorder).
 * There are no HTTP endpoints for reports yet (Phase 7C), so the service bean is the real entry point today.
 */
@SpringBootTest
class ReportServiceTest {

    @TempDir
    static Path sharedTempDir;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("casevault.audit.key-path", () -> sharedTempDir.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
    }

    @Autowired
    private ReportService reports;
    @Autowired
    private ReportRepository reportRepository;
    @Autowired
    private CaseRepository caseRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private OrganisationRepository organisationRepository;
    @Autowired
    private AuditLogService auditLogService;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private ObjectMapper objectMapper;

    private Organisation orgA;
    private Organisation orgB;
    private User analyst;
    private User managerOne;
    private User managerTwo;
    private User clientA;
    private User clientB;
    private User auditor;
    private Case caseA;
    private Case caseB;
    private String suffix;

    private Logger rootLogger;
    private ListAppender<ILoggingEvent> logs;

    private record Row(String type, String userId, String caseId, String reason) {
    }

    @BeforeEach
    void setUp() {
        rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        logs = new ListAppender<>();
        logs.start();
        rootLogger.addAppender(logs);

        suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        Organisation internal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(
                        new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        orgA = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Rep A " + suffix, "REP_A_" + suffix, now));
        orgB = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Rep B " + suffix, "REP_B_" + suffix, now));
        analyst = user("rep_an_" + suffix, internal, Role.ANALYST);
        managerOne = user("rep_m1_" + suffix, internal, Role.MANAGER);
        managerTwo = user("rep_m2_" + suffix, internal, Role.MANAGER);
        clientA = user("rep_ca_" + suffix, orgA, Role.CLIENT);
        clientB = user("rep_cb_" + suffix, orgB, Role.CLIENT);
        auditor = user("rep_au_" + suffix, internal, Role.AUDITOR_ADMIN);
        caseA = caseRepository.save(new Case(UUID.randomUUID().toString(), orgA, "Report case A " + suffix,
                "RANSOMWARE", "HIGH", "IN_PROGRESS", clientA, analyst, now));
        caseB = caseRepository.save(new Case(UUID.randomUUID().toString(), orgB, "Report case B " + suffix,
                "PHISHING", "LOW", "IN_PROGRESS", clientB, analyst, now));
        jdbc.update("DELETE FROM audit_events");
    }

    @AfterEach
    void tearDown() {
        com.casevault.support.TestDatabaseCleaner.deleteReports(jdbc); // F-008: leave no committed report rows behind
        SecurityContextHolder.clearContext();
        rootLogger.detachAppender(logs);
        logs.stop();
    }

    private User user(String name, Organisation org, Role role) {
        return userRepository.save(new User(UUID.randomUUID().toString(), org, name, "{noop}unused", role,
                name + "@test.local", true, Instant.now()));
    }

    /** Puts a real authentication into the security context, as the web layer would. */
    private CaseVaultUserPrincipal as(User u) {
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(u, Instant.now());
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities()));
        return principal;
    }

    private ReportResponseDto draft(String body) {
        return reports.createDraft(caseA.getId(), new ReportRequestDto(body), as(analyst));
    }

    private ReportResponseDto submitted() {
        ReportResponseDto d = draft("Findings " + suffix);
        return reports.submit(caseA.getId(), d.id(), as(analyst));
    }

    private void assertNotFound(Executable call) {
        assertThrows(ResourceNotFoundException.class, call);
    }

    private void assertBadRequest(Executable call) {
        assertThrows(BadRequestException.class, call);
    }

    private List<Row> rows() {
        return jdbc.query("SELECT event_type, CAST(user_id AS VARCHAR), CAST(case_id AS VARCHAR), reason_code "
                        + "FROM audit_events ORDER BY sequence_no",
                (rs, i) -> new Row(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)));
    }

    @Test
    @DisplayName("SEC-REPORT-01: four-eyes: the author cannot approve (400, denial audited); a different manager can")
    void fourEyes() {
        // A report authored by a MANAGER cannot arise through createDraft, so seed the overlap directly.
        Report own = new Report(UUID.randomUUID().toString(), caseA, managerOne, "Manager authored", Instant.now());
        own.markSubmitted(Instant.now());
        reportRepository.save(own);

        assertBadRequest(() -> reports.approve(caseA.getId(), own.getId(), as(managerOne)));
        assertEquals(ReportStatus.SUBMITTED, reportRepository.findById(own.getId()).orElseThrow().getStatus());
        assertEquals(List.of(new Row("ACCESS_DENIED", managerOne.getId(), caseA.getId(), "NOT_PERMITTED")), rows());

        ReportResponseDto approved = reports.approve(caseA.getId(), own.getId(), as(managerTwo));
        assertEquals("APPROVED", approved.status());
        assertEquals(managerTwo.getId(), approved.approvedById());
        assertEquals(managerOne.getId(), approved.authorId());
    }

    @Test
    @DisplayName("SEC-REPORT-02: workflow: skipping SUBMITTED, approving twice, editing or submitting at the wrong state => 400")
    void workflow() {
        ReportResponseDto d = draft("Draft one");
        assertBadRequest(() -> reports.approve(caseA.getId(), d.id(), as(managerOne)));

        ReportResponseDto s = reports.submit(caseA.getId(), d.id(), as(analyst));
        assertEquals("SUBMITTED", s.status());
        assertBadRequest(() -> reports.updateDraft(caseA.getId(), d.id(), new ReportRequestDto("late edit"), as(analyst)));
        assertBadRequest(() -> reports.submit(caseA.getId(), d.id(), as(analyst)));

        assertEquals("APPROVED", reports.approve(caseA.getId(), d.id(), as(managerOne)).status());
        assertBadRequest(() -> reports.approve(caseA.getId(), d.id(), as(managerTwo)));
        assertBadRequest(() -> reports.submit(caseA.getId(), d.id(), as(analyst)));
        assertBadRequest(() -> reports.updateDraft(caseA.getId(), d.id(), new ReportRequestDto("after approval"), as(analyst)));
        assertEquals("Draft one", reports.get(caseA.getId(), d.id(), as(managerOne)).body());
    }

    @Test
    @DisplayName("SEC-REPORT-03: CLIENT sees only APPROVED reports: DRAFT and SUBMITTED are 404 on get and absent from the list")
    void clientSeesApprovedOnly() {
        ReportResponseDto d = draft("client visibility");
        assertNotFound(() -> reports.get(caseA.getId(), d.id(), as(clientA)));
        assertEquals(0, reports.list(caseA.getId(), as(clientA)).size());

        reports.submit(caseA.getId(), d.id(), as(analyst));
        assertNotFound(() -> reports.get(caseA.getId(), d.id(), as(clientA)));
        assertEquals(0, reports.list(caseA.getId(), as(clientA)).size());
        assertEquals(1, reports.list(caseA.getId(), as(managerOne)).size());

        reports.approve(caseA.getId(), d.id(), as(managerOne));
        assertEquals(d.id(), reports.get(caseA.getId(), d.id(), as(clientA)).id());
        assertEquals(List.of(d.id()), reports.list(caseA.getId(), as(clientA)).stream().map(ReportResponseDto::id).toList());
        // another organisation's client and the auditor never see it
        assertNotFound(() -> reports.get(caseA.getId(), d.id(), as(clientB)));
        assertNotFound(() -> reports.list(caseA.getId(), as(clientB)));
        assertNotFound(() -> reports.get(caseA.getId(), d.id(), as(auditor)));
        assertNotFound(() -> reports.list(caseA.getId(), as(auditor)));
    }

    @Test
    @DisplayName("SEC-REPORT-04: IDOR: a report of case B under case A is 404 for every operation; random ids are 404")
    void idor() {
        ReportResponseDto inB = reports.createDraft(caseB.getId(), new ReportRequestDto("belongs to B"), as(analyst));
        // the same analyst is assigned to both cases, so only the path/report mismatch can cause the 404
        assertNotFound(() -> reports.get(caseA.getId(), inB.id(), as(analyst)));
        assertNotFound(() -> reports.updateDraft(caseA.getId(), inB.id(), new ReportRequestDto("x"), as(analyst)));
        assertNotFound(() -> reports.submit(caseA.getId(), inB.id(), as(analyst)));
        assertNotFound(() -> reports.approve(caseA.getId(), inB.id(), as(managerOne)));
        assertEquals("DRAFT", reportRepository.findById(inB.id()).orElseThrow().getStatus().name());

        assertNotFound(() -> reports.get(caseA.getId(), UUID.randomUUID().toString(), as(analyst)));
        assertNotFound(() -> reports.get(UUID.randomUUID().toString(), inB.id(), as(analyst)));
        assertNotFound(() -> reports.list(UUID.randomUUID().toString(), as(managerOne)));
        assertNotFound(() -> reports.createDraft(UUID.randomUUID().toString(), new ReportRequestDto("x"), as(analyst)));
    }

    @Test
    @DisplayName("SEC-REPORT-05: body limits: empty, blank, over-length and control characters are rejected; script text is stored unchanged")
    void bodyLimits() {
        for (String bad : new String[]{null, "", "   \n\t ", "x".repeat(10001), "a\u0000b", "a\u0007b", "esc\u001b[31m",
                "del\u007f", "lone\rcr", "c1\u0085"}) {
            assertBadRequest(() -> reports.createDraft(caseA.getId(), new ReportRequestDto(bad), as(analyst)));
        }
        assertBadRequest(() -> reports.createDraft(caseA.getId(), null, as(analyst)));
        assertEquals(0, reports.list(caseA.getId(), as(managerOne)).size(), "nothing was stored");

        assertEquals(10000, draft("y".repeat(10000)).body().length());
        assertEquals("line1\nline2\ttab", draft("line1\nline2\ttab").body());
        assertEquals("crlf\nnormalised", draft("crlf\r\nnormalised").body(), "CRLF from browsers is normalised to LF");

        String script = "<script>alert(1)</script> & \"quotes\" <img src=x onerror=alert(1)>";
        ReportResponseDto stored = draft(script);
        assertEquals(script, stored.body());
        assertEquals(script, reportRepository.findById(stored.id()).orElseThrow().getBody(), "stored as is");

        ReportResponseDto edit = reports.updateDraft(caseA.getId(), stored.id(), new ReportRequestDto("y".repeat(10001).substring(1)), as(analyst));
        assertEquals(10000, edit.body().length());
        assertBadRequest(() -> reports.updateDraft(caseA.getId(), stored.id(), new ReportRequestDto("bad\u0000"), as(analyst)));
        assertEquals(10000, reports.get(caseA.getId(), stored.id(), as(analyst)).body().length(), "a rejected edit changes nothing");
    }

    @Test
    @DisplayName("SEC-REPORT-06: closed case: create, edit and submit are rejected (400); an already submitted report can still be approved")
    void closedCase() {
        ReportResponseDto d = draft("before close");
        ReportResponseDto s = submitted();
        jdbc.update("UPDATE cases SET status = 'CLOSED' WHERE id = ?", caseA.getId());

        assertBadRequest(() -> reports.createDraft(caseA.getId(), new ReportRequestDto("new"), as(analyst)));
        assertBadRequest(() -> reports.updateDraft(caseA.getId(), d.id(), new ReportRequestDto("edit"), as(analyst)));
        assertBadRequest(() -> reports.submit(caseA.getId(), d.id(), as(analyst)));
        assertEquals("APPROVED", reports.approve(caseA.getId(), s.id(), as(managerOne)).status());
    }

    @Test
    @DisplayName("SEC-REPORT-07: mass assignment: status, author, approver, case and organisation in the input are ignored")
    void massAssignment() throws Exception {
        String json = "{\"body\":\"mass body\",\"status\":\"APPROVED\",\"authorId\":\"" + managerOne.getId()
                + "\",\"approvedBy\":\"" + managerOne.getId() + "\",\"approvedById\":\"" + managerOne.getId()
                + "\",\"caseId\":\"" + caseB.getId() + "\",\"organisationId\":\"" + orgB.getId() + "\",\"id\":\"fixed-id\"}";
        ReportRequestDto input = objectMapper.readValue(json, ReportRequestDto.class);
        assertEquals(1, ReportRequestDto.class.getDeclaredFields().length, "the input object has only the body field");

        ReportResponseDto created = reports.createDraft(caseA.getId(), input, as(analyst));
        assertEquals("DRAFT", created.status());
        assertEquals(analyst.getId(), created.authorId());
        assertEquals(caseA.getId(), created.caseId());
        assertNull(created.approvedById());
        assertTrue(!"fixed-id".equals(created.id()));
        Report persisted = reportRepository.findById(created.id()).orElseThrow();
        assertEquals(caseA.getId(), persisted.getCaseId());
        assertNull(persisted.getApprovedAt());

        ReportResponseDto edited = reports.updateDraft(caseA.getId(), created.id(), input, as(analyst));
        assertEquals("DRAFT", edited.status());
        assertEquals(analyst.getId(), edited.authorId());
        assertNull(edited.approvedById());
    }

    @Test
    @DisplayName("SEC-REPORT-08: one REPORT_TRANSITION per transition with the actor and case; no body in any audit column or log line; chain stays valid")
    void auditTrail() {
        String secretBody = "SECRET-REPORT-BODY-" + suffix + " <script>x</script>";
        ReportResponseDto d = draft(secretBody);
        reports.updateDraft(caseA.getId(), d.id(), new ReportRequestDto(secretBody + " edited"), as(analyst));
        assertBadRequest(() -> reports.approve(caseA.getId(), d.id(), as(managerOne)));   // invalid transition: no event
        reports.submit(caseA.getId(), d.id(), as(analyst));
        assertNotFound(() -> reports.approve(caseA.getId(), d.id(), as(clientA)));          // unauthorised: ACCESS_DENIED
        reports.approve(caseA.getId(), d.id(), as(managerOne));

        assertEquals(List.of(
                new Row("REPORT_TRANSITION", analyst.getId(), caseA.getId(), "REPORT_CREATED"),
                new Row("REPORT_TRANSITION", analyst.getId(), caseA.getId(), "REPORT_SUBMITTED"),
                new Row("ACCESS_DENIED", clientA.getId(), caseA.getId(), "NOT_VISIBLE"),
                new Row("REPORT_TRANSITION", managerOne.getId(), caseA.getId(), "REPORT_APPROVED")), rows());

        String everything = String.join("|", jdbc.query("SELECT CAST(id AS VARCHAR), event_type, CAST(user_id AS VARCHAR), "
                        + "CAST(case_id AS VARCHAR), reason_code, CAST(occurred_at AS VARCHAR), prev_hash, hmac FROM audit_events",
                (rs, i) -> rs.getString(1) + rs.getString(2) + rs.getString(3) + rs.getString(4) + rs.getString(5)
                        + rs.getString(6) + rs.getString(7) + rs.getString(8)));
        assertFalse(everything.contains("SECRET-REPORT-BODY"));
        for (ILoggingEvent event : logs.list) {
            assertFalse(event.getFormattedMessage().contains("SECRET-REPORT-BODY"), "report body in a log line");
        }
        assertTrue(auditLogService.verifyChain().valid());
    }

    @Test
    @DisplayName("SEC-REPORT-09: a failed transition (rolled back) writes no REPORT_TRANSITION; the event is written only after commit")
    void noEventWithoutCommit() {
        ReportResponseDto d = draft("rollback check");
        jdbc.update("DELETE FROM audit_events");
        assertBadRequest(() -> reports.approve(caseA.getId(), d.id(), as(managerOne)));
        assertBadRequest(() -> reports.updateDraft(caseA.getId(), d.id(), new ReportRequestDto("bad\u0000"), as(analyst)));
        assertEquals(List.of(), rows());
    }

    @Test
    @DisplayName("SEC-REPORT-10: without an authenticated user the service refuses (security proxy); a null principal is 404")
    void unauthenticated() {
        SecurityContextHolder.clearContext();
        assertThrows(RuntimeException.class, () -> reports.list(caseA.getId(), null));
        assertThrows(ResourceNotFoundException.class, () -> {
            as(analyst);
            reports.list(caseA.getId(), null);
        });
    }
}
