package com.casevault.reports;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Report;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.ReportRepository;
import com.casevault.repository.UserRepository;
import com.casevault.service.AuditEventRecorder;
import com.casevault.service.AuditEventType;
import com.casevault.service.AuditLogService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Phase 7C: report pages over HTTP (real filter chain, real logins through /login, H2, chained audit log). */
@SpringBootTest
@AutoConfigureMockMvc
// Phase 8A: this class performs many real logins from one address; the login limiter keeps its default
// behaviour but with a higher limit so the unrelated scenarios below are not throttled.
@org.springframework.test.context.TestPropertySource(properties = "casevault.ratelimit.login-limit=100000")
class ReportWebTest {

    private static final String PASSWORD = "Report-Web-Password-1234!";
    private static final String CONFLICT_TEXT = "changed by someone else";

    @TempDir
    static Path sharedTempDir;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("casevault.audit.key-path", () -> sharedTempDir.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private OrganisationRepository organisationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CaseRepository caseRepository;
    @Autowired
    private ReportRepository reportRepository;
    @Autowired
    private AuditLogService realAuditLogService;
    @MockitoSpyBean
    private AuditEventRecorder recorderSpy;
    @MockitoSpyBean
    private AuditLogService auditLogService;

    private Organisation orgA;
    private Organisation orgB;
    private User analyst;
    private User analystOther;
    private User manager1;
    private User manager2;
    private User clientManagerA;
    private User clientA;
    private User clientB;
    private User auditor;
    private Case caseA;
    private Case caseB;
    private String suffix;
    private final Map<String, MockHttpSession> sessions = new HashMap<>();
    private Logger rootLogger;
    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void setUp() {
        rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        logs = new ListAppender<>();
        logs.start();
        rootLogger.addAppender(logs);
        sessions.clear();

        suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        Organisation internal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(
                        new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        orgA = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "RW A " + suffix, "RW_A_" + suffix, now));
        orgB = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "RW B " + suffix, "RW_B_" + suffix, now));
        String hash = passwordEncoder.encode(PASSWORD);
        analyst = user("rw_an_" + suffix, internal, Role.ANALYST, hash);
        analystOther = user("rw_ao_" + suffix, internal, Role.ANALYST, hash);
        manager1 = user("rw_m1_" + suffix, internal, Role.MANAGER, hash);
        manager2 = user("rw_m2_" + suffix, internal, Role.MANAGER, hash);
        clientManagerA = user("rw_cm_" + suffix, orgA, Role.MANAGER, hash);
        clientA = user("rw_ca_" + suffix, orgA, Role.CLIENT, hash);
        clientB = user("rw_cb_" + suffix, orgB, Role.CLIENT, hash);
        auditor = user("rw_au_" + suffix, internal, Role.AUDITOR_ADMIN, hash);
        caseA = caseRepository.save(new Case(UUID.randomUUID().toString(), orgA, "Web case A " + suffix,
                "RANSOMWARE", "HIGH", "IN_PROGRESS", clientA, analyst, now));
        caseB = caseRepository.save(new Case(UUID.randomUUID().toString(), orgB, "Web case B " + suffix,
                "PHISHING", "LOW", "IN_PROGRESS", clientB, analyst, now));
    }

    @AfterEach
    void tearDown() {
        com.casevault.support.TestDatabaseCleaner.deleteReports(jdbc); // F-008: leave no committed report rows behind
        rootLogger.detachAppender(logs);
        logs.stop();
    }

    private User user(String name, Organisation org, Role role, String hash) {
        return userRepository.save(new User(UUID.randomUUID().toString(), org, name, hash, role,
                name + "@test.local", true, Instant.now()));
    }

    /** Real login through /login; the session is kept per user for the duration of one test. */
    private MockHttpSession as(User u) throws Exception {
        MockHttpSession existing = sessions.get(u.getId());
        if (existing != null) {
            return existing;
        }
        MvcResult result = mockMvc.perform(post("/login").with(csrf())
                .param("username", u.getUsername()).param("password", PASSWORD)).andReturn();
        assertEquals(302, result.getResponse().getStatus());
        assertTrue(result.getResponse().getRedirectedUrl().endsWith("/dashboard"), "login must succeed");
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        sessions.put(u.getId(), session);
        return session;
    }

    private MvcResult getAs(User u, String path) throws Exception {
        return mockMvc.perform(get(path).session(as(u))).andReturn();
    }

    private MvcResult postAs(User u, String path, String... params) throws Exception {
        MockHttpServletRequestBuilder request = post(path).session(as(u)).with(csrf());
        for (int i = 0; i + 1 < params.length; i += 2) {
            request.param(params[i], params[i + 1]);
        }
        return mockMvc.perform(request).andReturn();
    }

    private String reportsPath(Case c) {
        return "/cases/" + c.getId() + "/reports";
    }

    /** Creates a draft over HTTP as the analyst and returns its id. */
    private String createDraft(Case c, String body) throws Exception {
        MvcResult result = postAs(analyst, reportsPath(c), "body", body);
        assertEquals(302, result.getResponse().getStatus(), result.getResponse().getContentAsString());
        String url = result.getResponse().getRedirectedUrl();
        assertTrue(url.startsWith(reportsPath(c) + "/"));
        return url.substring(url.lastIndexOf('/') + 1);
    }

    private String createSubmitted(Case c, String body) throws Exception {
        String id = createDraft(c, body);
        assertEquals(302, postAs(analyst, reportsPath(c) + "/" + id + "/submit").getResponse().getStatus());
        return id;
    }

    private String status(String reportId) {
        return jdbc.queryForObject("SELECT status FROM reports WHERE id = ?", String.class, reportId);
    }

    private int code(MvcResult r) {
        return r.getResponse().getStatus();
    }

    private String html(MvcResult r) throws Exception {
        return r.getResponse().getContentAsString();
    }

    // ---- access matrix ----

    @Test
    @DisplayName("SEC-REPORT-WEB-01: role matrix over HTTP for list, detail, create, update, submit and approve (404, never 403); POST without CSRF is 403")
    void roleMatrix() throws Exception {
        String id = createDraft(caseA, "Matrix body");
        String list = reportsPath(caseA);
        String detail = list + "/" + id;

        // GET list: assigned analyst, internal manager, client-org manager and own client are served; others 404
        for (User ok : List.of(analyst, manager1, clientManagerA, clientA)) {
            assertEquals(200, code(getAs(ok, list)), "list " + ok.getRole());
        }
        for (User denied : List.of(clientB, analystOther, auditor)) {
            assertEquals(404, code(getAs(denied, list)), "list " + denied.getRole());
        }
        // GET detail of a DRAFT
        for (User ok : List.of(analyst, manager1, clientManagerA)) {
            assertEquals(200, code(getAs(ok, detail)), "detail " + ok.getRole());
        }
        for (User denied : List.of(clientA, clientB, analystOther, auditor)) {
            assertEquals(404, code(getAs(denied, detail)), "detail " + denied.getRole());
        }
        // the client's list does not contain the draft
        assertFalse(html(getAs(clientA, list)).contains(id));
        assertTrue(html(getAs(manager1, list)).contains(id));

        // POST create: only the assigned analyst
        assertEquals(302, code(postAs(analyst, list, "body", "second")));
        for (User denied : List.of(analystOther, manager1, clientManagerA, clientA, clientB, auditor)) {
            assertEquals(404, code(postAs(denied, list, "body", "nope")), "create " + denied.getRole());
        }
        assertEquals(2, jdbc.queryForObject("SELECT COUNT(*) FROM reports WHERE case_id = ?", Integer.class, caseA.getId()));

        // POST update and submit: only the author
        for (String action : List.of("update", "submit")) {
            for (User denied : List.of(analystOther, manager1, clientManagerA, clientA, clientB, auditor)) {
                assertEquals(404, code(postAs(denied, detail + "/" + action, "body", "x")), action + " " + denied.getRole());
            }
        }
        assertEquals("DRAFT", status(id));
        // POST approve: managers only; non-managers get 404 before any state check
        for (User denied : List.of(analyst, analystOther, clientA, clientB, auditor)) {
            assertEquals(404, code(postAs(denied, detail + "/approve")), "approve " + denied.getRole());
        }
        assertEquals("DRAFT", status(id));

        // CSRF: every POST without a token is 403, also for the right user
        for (String path : List.of(list, detail + "/update", detail + "/submit", detail + "/approve")) {
            assertEquals(403, code(mockMvc.perform(post(path).session(as(analyst)).param("body", "x")).andReturn()), path);
        }
        assertEquals("DRAFT", status(id));
    }

    @Test
    @DisplayName("SEC-REPORT-WEB-02: unauthenticated requests behave like /cases; the Reports tab is absent for the auditor and the direct request is 404")
    void unauthenticatedAndTab() throws Exception {
        String id = createDraft(caseA, "tab body");
        int casesStatus = mockMvc.perform(get("/cases")).andReturn().getResponse().getStatus();
        for (String path : List.of(reportsPath(caseA), reportsPath(caseA) + "/" + id)) {
            assertEquals(casesStatus, mockMvc.perform(get(path)).andReturn().getResponse().getStatus(), path);
        }
        for (String path : List.of(reportsPath(caseA), reportsPath(caseA) + "/" + id + "/submit",
                reportsPath(caseA) + "/" + id + "/approve", reportsPath(caseA) + "/" + id + "/update")) {
            assertEquals(casesStatus, mockMvc.perform(post(path).with(csrf())).andReturn().getResponse().getStatus(), path);
            assertEquals(403, mockMvc.perform(post(path)).andReturn().getResponse().getStatus(), path);
        }
        assertEquals("DRAFT", status(id));

        String caseDetail = html(getAs(analyst, "/cases/" + caseA.getId()));
        assertTrue(caseDetail.contains("href=\"" + reportsPath(caseA) + "\""), "Reports tab for the analyst");
        assertTrue(html(getAs(clientA, "/cases/" + caseA.getId())).contains("href=\"" + reportsPath(caseA) + "\""));
        assertEquals(404, code(getAs(auditor, "/cases/" + caseA.getId())));
        assertEquals(404, code(getAs(auditor, reportsPath(caseA))));
    }

    // ---- output safety ----

    @Test
    @DisplayName("SEC-REPORT-WEB-03: script-like report text is shown escaped as text (detail, rejected create form, rejected edit form), never as markup")
    void xssIsEscaped() throws Exception {
        String payload = "<script>alert(1)</script>\n<img src=x onerror=alert(1)> \"quoted\" & 'single'";
        String id = createDraft(caseA, payload);
        Pattern attackTag = Pattern.compile("<[^>]*\\bonerror\\s*=", Pattern.CASE_INSENSITIVE);

        for (User viewer : List.of(analyst, manager1, clientManagerA)) {
            String body = html(getAs(viewer, reportsPath(caseA) + "/" + id));
            assertTrue(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "escaped script for " + viewer.getRole());
            assertTrue(body.contains("&lt;img src=x onerror=alert(1)&gt;"));
            assertFalse(body.contains("<script>alert"));
            assertFalse(body.contains("<img src=x"));
            assertFalse(attackTag.matcher(body).find());
            assertTrue(body.contains("class=\"report-body\""));
            assertTrue(body.contains("&lt;/script&gt;\n&lt;img"), "line breaks are kept as text for CSS pre-wrap");
        }
        // The same payload with a control character is rejected; the create form shows it back escaped.
        MvcResult rejectedCreate = postAs(analyst, reportsPath(caseA), "body", payload + "\u0000");
        assertEquals(400, code(rejectedCreate));
        String createPage = html(rejectedCreate);
        assertTrue(createPage.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assertFalse(createPage.contains("<script>alert"));
        assertFalse(createPage.contains("<img src=x"));
        assertFalse(attackTag.matcher(createPage).find());
        // And on the edit form of the detail page.
        MvcResult rejectedEdit = postAs(analyst, reportsPath(caseA) + "/" + id + "/update", "body", payload + "\u0007");
        assertEquals(400, code(rejectedEdit));
        String editPage = html(rejectedEdit);
        assertTrue(editPage.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assertFalse(editPage.contains("<script>alert"));
        assertFalse(attackTag.matcher(editPage).find());
        // After approval the client sees the escaped text too.
        postAs(analyst, reportsPath(caseA) + "/" + id + "/submit");
        postAs(manager1, reportsPath(caseA) + "/" + id + "/approve");
        String clientView = html(getAs(clientA, reportsPath(caseA) + "/" + id));
        assertTrue(clientView.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assertFalse(clientView.contains("<script>alert"));
    }

    @Test
    @DisplayName("SEC-REPORT-WEB-13: the report list shows the newest report first and a friendly empty state when there is none")
    void listIsNewestFirst() throws Exception {
        String empty = html(getAs(manager1, reportsPath(caseA)));
        assertTrue(empty.contains("No reports to show"));
        String first = createDraft(caseA, "first");
        Thread.sleep(5);
        String second = createDraft(caseA, "second");
        String page = html(getAs(manager1, reportsPath(caseA)));
        assertTrue(page.indexOf(second) >= 0 && page.indexOf(first) >= 0);
        assertTrue(page.indexOf(second) < page.indexOf(first), "newest report is listed first");
    }

    // ---- IDOR ----

    @Test
    @DisplayName("SEC-REPORT-WEB-04: IDOR over HTTP: a report of case B under case A, random and malformed ids are 404 on every route")
    void idor() throws Exception {
        String idA = createDraft(caseA, "report A");
        String idB = createDraft(caseB, "report B");
        for (String bad : List.of(idB, UUID.randomUUID().toString(), "not-a-uuid", "1' OR '1'='1", "00000000-0000-0000-0000-000000000000")) {
            String base = reportsPath(caseA) + "/{id}";
            assertEquals(404, mockMvc.perform(get(base, bad).session(as(analyst))).andReturn().getResponse().getStatus(), bad);
            for (String action : List.of("update", "submit", "approve")) {
                User actor = action.equals("approve") ? manager1 : analyst;
                assertEquals(404, mockMvc.perform(post(base + "/" + action, bad).session(as(actor)).with(csrf())
                        .param("body", "x")).andReturn().getResponse().getStatus(), action + " " + bad);
            }
        }
        for (String badCase : List.of(UUID.randomUUID().toString(), "not-a-uuid")) {
            assertEquals(404, mockMvc.perform(get("/cases/{c}/reports", badCase).session(as(analyst))).andReturn().getResponse().getStatus());
            assertEquals(404, mockMvc.perform(get("/cases/{c}/reports/{r}", badCase, idA).session(as(analyst))).andReturn().getResponse().getStatus());
            assertEquals(404, mockMvc.perform(post("/cases/{c}/reports", badCase).session(as(analyst)).with(csrf())
                    .param("body", "x")).andReturn().getResponse().getStatus());
        }
        assertEquals("DRAFT", status(idA));
        assertEquals("DRAFT", status(idB));
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM reports WHERE case_id = ?", Integer.class, caseB.getId()));
        // the report of case B stays reachable under its own case
        assertEquals(200, code(getAs(analyst, reportsPath(caseB) + "/" + idB)));
    }

    // ---- four-eyes, visibility, workflow ----

    @Test
    @DisplayName("SEC-REPORT-WEB-05: four-eyes over HTTP: the author cannot approve (message, no change); another manager can; the client sees APPROVED only")
    void fourEyesAndClientVisibility() throws Exception {
        // A manager-authored SUBMITTED report (cannot arise through the pages) to prove the service-side rule over HTTP.
        Report own = new Report(UUID.randomUUID().toString(), caseA, manager1, "Manager authored", Instant.now());
        own.markSubmitted(Instant.now());
        reportRepository.save(own);
        MvcResult self = postAs(manager1, reportsPath(caseA) + "/" + own.getId() + "/approve");
        assertEquals(400, code(self));
        assertTrue(html(self).contains("The author of a report cannot approve it"));
        assertEquals("SUBMITTED", status(own.getId()));
        String ownPage = html(getAs(manager1, reportsPath(caseA) + "/" + own.getId()));
        assertFalse(ownPage.contains("Approve report"), "no approve button for the author");
        assertEquals(302, code(postAs(manager2, reportsPath(caseA) + "/" + own.getId() + "/approve")));
        assertEquals("APPROVED", status(own.getId()));

        // Normal flow with the analyst as author.
        String id = createDraft(caseA, "Flow body");
        assertEquals(404, code(getAs(clientA, reportsPath(caseA) + "/" + id)));
        assertFalse(html(getAs(clientA, reportsPath(caseA))).contains(id));
        assertEquals(302, code(postAs(analyst, reportsPath(caseA) + "/" + id + "/submit")));
        assertEquals(404, code(getAs(clientA, reportsPath(caseA) + "/" + id)), "SUBMITTED is hidden from the client");
        assertFalse(html(getAs(clientA, reportsPath(caseA))).contains(id));
        assertFalse(html(getAs(analyst, reportsPath(caseA) + "/" + id)).contains("Approve report"));
        assertTrue(html(getAs(manager2, reportsPath(caseA) + "/" + id)).contains("Approve report"));
        assertEquals(302, code(postAs(manager2, reportsPath(caseA) + "/" + id + "/approve")));
        assertEquals("APPROVED", status(id));
        assertEquals(manager2.getId(), jdbc.queryForObject("SELECT approved_by FROM reports WHERE id = ?", String.class, id));
        assertEquals(200, code(getAs(clientA, reportsPath(caseA) + "/" + id)));
        String clientList = html(getAs(clientA, reportsPath(caseA)));
        assertTrue(clientList.contains(id) && clientList.contains(own.getId()));
        assertEquals(404, code(getAs(clientB, reportsPath(caseA) + "/" + id)));
    }

    @Test
    @DisplayName("SEC-REPORT-WEB-06: workflow errors over HTTP give a friendly 400 message and change nothing")
    void workflowErrors() throws Exception {
        String id = createDraft(caseA, "workflow body");
        String detail = reportsPath(caseA) + "/" + id;

        MvcResult skip = postAs(manager1, detail + "/approve");
        assertEquals(400, code(skip));
        assertTrue(html(skip).contains("Only a SUBMITTED report can be approved"));
        assertEquals("DRAFT", status(id));

        assertEquals(302, code(postAs(analyst, detail + "/submit")));
        MvcResult again = postAs(analyst, detail + "/submit");
        assertEquals(400, code(again));
        assertTrue(html(again).contains("Only a DRAFT report can be submitted"));
        MvcResult edit = postAs(analyst, detail + "/update", "body", "late edit");
        assertEquals(400, code(edit));
        assertTrue(html(edit).contains("Only a DRAFT report can be edited"));
        assertEquals("workflow body", jdbc.queryForObject("SELECT body FROM reports WHERE id = ?", String.class, id));

        assertEquals(302, code(postAs(manager1, detail + "/approve")));
        MvcResult twice = postAs(manager2, detail + "/approve");
        assertEquals(400, code(twice));
        assertTrue(html(twice).contains("Only a SUBMITTED report can be approved"));
        assertEquals(manager1.getId(), jdbc.queryForObject("SELECT approved_by FROM reports WHERE id = ?", String.class, id));
        for (MvcResult r : List.of(skip, again, edit, twice)) {
            String body = html(r);
            assertFalse(body.contains("Exception") || body.contains("at com.") || body.contains("Caused by"));
        }
    }

    @Test
    @DisplayName("SEC-REPORT-WEB-07: body limits over HTTP: empty, blank, over-length and control characters are rejected with a message; the form states the limit")
    void bodyLimits() throws Exception {
        for (String bad : new String[]{"", "   \n\t ", "x".repeat(10001), "a\u0000b", "a\u001bb", "lone\rcr", "del\u007f"}) {
            MvcResult r = postAs(analyst, reportsPath(caseA), "body", bad);
            assertEquals(400, code(r), "rejected: " + bad.length() + " chars");
            String body = html(r);
            assertTrue(body.contains("The report could not be saved") || body.contains("Report body"));
            assertFalse(body.contains("Exception") || body.contains("at com."));
        }
        assertEquals(400, code(mockMvc.perform(post(reportsPath(caseA)).session(as(analyst)).with(csrf())).andReturn()),
                "a missing body field is a friendly 400");
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM reports WHERE case_id = ?", Integer.class, caseA.getId()));

        assertEquals(302, code(postAs(analyst, reportsPath(caseA), "body", "y".repeat(10000))));
        String page = html(getAs(analyst, reportsPath(caseA)));
        assertTrue(page.contains("maxlength=\"10000\""));
        assertTrue(page.contains("<label for=\"report-body\">"));
        assertTrue(page.contains("10000 characters"));
        assertFalse(page.contains("<script"));
    }

    @Test
    @DisplayName("SEC-REPORT-WEB-08: mass assignment over HTTP: status, authorId, approvedBy, caseId, organisationId and id form fields are ignored")
    void massAssignment() throws Exception {
        MvcResult created = postAs(analyst, reportsPath(caseA), "body", "mass body", "status", "APPROVED",
                "authorId", manager1.getId(), "approvedBy", manager1.getId(), "approvedById", manager1.getId(),
                "caseId", caseB.getId(), "organisationId", orgB.getId(), "id", "fixed-id", "version", "99");
        assertEquals(302, code(created));
        String id = created.getResponse().getRedirectedUrl().substring(created.getResponse().getRedirectedUrl().lastIndexOf('/') + 1);
        assertFalse("fixed-id".equals(id));
        var row = jdbc.queryForMap("SELECT status, author_id, case_id, approved_by FROM reports WHERE id = ?", id);
        assertEquals("DRAFT", row.get("STATUS"));
        assertEquals(analyst.getId(), row.get("AUTHOR_ID"));
        assertEquals(caseA.getId(), row.get("CASE_ID"));
        assertEquals(null, row.get("APPROVED_BY"));

        assertEquals(302, code(postAs(analyst, reportsPath(caseA) + "/" + id + "/update", "body", "edited", "status", "APPROVED",
                "authorId", manager1.getId(), "approvedBy", manager1.getId(), "caseId", caseB.getId())));
        row = jdbc.queryForMap("SELECT status, author_id, case_id, approved_by, body FROM reports WHERE id = ?", id);
        assertEquals("DRAFT", row.get("STATUS"));
        assertEquals(analyst.getId(), row.get("AUTHOR_ID"));
        assertEquals(caseA.getId(), row.get("CASE_ID"));
        assertEquals("edited", row.get("BODY"));
        // extra fields on the transition posts change nothing either
        assertEquals(302, code(postAs(analyst, reportsPath(caseA) + "/" + id + "/submit", "status", "APPROVED", "approvedBy", manager1.getId())));
        assertEquals("SUBMITTED", status(id));
        assertEquals(null, jdbc.queryForObject("SELECT approved_by FROM reports WHERE id = ?", String.class, id));
    }

    // ---- audit ----

    @Test
    @DisplayName("SEC-REPORT-WEB-09: over HTTP exactly one REPORT_TRANSITION per successful create, submit and approve (actor, case id); no body in audit or logs; chain valid")
    void auditOverHttp() throws Exception {
        as(analyst);
        as(manager1);
        jdbc.update("DELETE FROM audit_events");
        String secret = "SECRET-WEB-REPORT-BODY-" + suffix;
        String id = createDraft(caseA, secret);
        postAs(analyst, reportsPath(caseA) + "/" + id + "/update", "body", secret + " edited");     // not a transition
        postAs(manager1, reportsPath(caseA) + "/" + id + "/approve");                                 // 400: draft, no event
        postAs(analyst, reportsPath(caseA) + "/" + id + "/submit");
        postAs(analystOther, reportsPath(caseA) + "/" + id + "/submit");                             // 404 for another analyst
        postAs(manager1, reportsPath(caseA) + "/" + id + "/approve");

        List<String> rows = jdbc.queryForList("SELECT event_type || '|' || CAST(user_id AS VARCHAR) || '|' || CAST(case_id AS VARCHAR) || '|' || reason_code "
                + "FROM audit_events WHERE event_type = 'REPORT_TRANSITION' ORDER BY sequence_no", String.class);
        assertEquals(List.of(
                "REPORT_TRANSITION|" + analyst.getId() + "|" + caseA.getId() + "|REPORT_CREATED",
                "REPORT_TRANSITION|" + analyst.getId() + "|" + caseA.getId() + "|REPORT_SUBMITTED",
                "REPORT_TRANSITION|" + manager1.getId() + "|" + caseA.getId() + "|REPORT_APPROVED"), rows);
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM audit_events WHERE event_type = 'ACCESS_DENIED' AND CAST(user_id AS VARCHAR) = ?",
                Integer.class, analystOther.getId()), "the refused attempt of the other analyst is audited once");

        String everything = String.join("|", jdbc.query("SELECT CAST(id AS VARCHAR), event_type, CAST(user_id AS VARCHAR), "
                        + "CAST(case_id AS VARCHAR), reason_code, CAST(occurred_at AS VARCHAR), prev_hash, hmac FROM audit_events",
                (rs, i) -> rs.getString(1) + rs.getString(2) + rs.getString(3) + rs.getString(4) + rs.getString(5)
                        + rs.getString(6) + rs.getString(7) + rs.getString(8)));
        assertFalse(everything.contains("SECRET-WEB-REPORT-BODY"));
        for (ILoggingEvent event : logs.list) {
            assertFalse(event.getFormattedMessage().contains("SECRET-WEB-REPORT-BODY"), "report body in a log line");
        }
        assertTrue(realAuditLogService.verifyChain().valid());
    }

    // ---- concurrency ----

    @Test
    @DisplayName("SEC-REPORT-WEB-10: two managers approving the same SUBMITTED report at once: exactly one succeeds, the loser gets HTTP 409 with a friendly message, one event, approved_by is the winner")
    void concurrentApproval() throws Exception {
        as(manager1);
        as(manager2);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < 3; round++) {
                String id = createSubmitted(caseA, "concurrent body " + round);
                jdbc.update("DELETE FROM audit_events WHERE event_type = 'REPORT_TRANSITION' AND reason_code = 'REPORT_APPROVED'");
                // Both requests read SUBMITTED and reach the audit call before either commits.
                CyclicBarrier barrier = new CyclicBarrier(2);
                Mockito.doAnswer(invocation -> {
                    if (invocation.getArgument(0) == AuditEventType.REPORT_TRANSITION
                            && "REPORT_APPROVED".equals(invocation.getArgument(3))) {
                        barrier.await(30, TimeUnit.SECONDS);
                    }
                    return invocation.callRealMethod();
                }).when(recorderSpy).record(any(), any(), any(), any());

                Future<MvcResult> first = executor.submit(() -> postAs(manager1, reportsPath(caseA) + "/" + id + "/approve"));
                Future<MvcResult> second = executor.submit(() -> postAs(manager2, reportsPath(caseA) + "/" + id + "/approve"));
                MvcResult r1 = first.get(60, TimeUnit.SECONDS);
                MvcResult r2 = second.get(60, TimeUnit.SECONDS);

                int c1 = code(r1);
                int c2 = code(r2);
                assertTrue((c1 == 302 && c2 == 409) || (c1 == 409 && c2 == 302), "statuses " + c1 + "/" + c2);
                MvcResult loser = c1 == 409 ? r1 : r2;
                User winner = c1 == 302 ? manager1 : manager2;
                assertTrue(html(loser).contains(CONFLICT_TEXT));
                assertFalse(html(loser).contains("Exception"));
                assertEquals("APPROVED", status(id));
                assertEquals(winner.getId(), jdbc.queryForObject("SELECT approved_by FROM reports WHERE id = ?", String.class, id));
                assertEquals(List.of(winner.getId()), jdbc.queryForList(
                        "SELECT CAST(user_id AS VARCHAR) FROM audit_events WHERE event_type = 'REPORT_TRANSITION' AND reason_code = 'REPORT_APPROVED' "
                                + "AND CAST(case_id AS VARCHAR) = ?", String.class, caseA.getId()));
                Mockito.reset(recorderSpy);
            }
        } finally {
            executor.shutdownNow();
            Mockito.reset(recorderSpy);
        }
    }

    // ---- failure mode ----

    @Test
    @DisplayName("SEC-REPORT-WEB-11: if the audit append fails after the commit, the user gets the safe error page with a correlation id and the report change stays committed")
    void auditAppendFailure() throws Exception {
        String id = createDraft(caseA, "failure mode body");
        as(analyst);
        doThrow(new IllegalStateException("simulated audit database outage SECRET-DETAIL"))
                .when(auditLogService).recordEvent(eq(AuditEventType.REPORT_TRANSITION), any(), any(), any());
        MvcResult result = postAs(analyst, reportsPath(caseA) + "/" + id + "/submit");
        assertEquals(500, code(result));
        String body = html(result);
        assertTrue(body.contains("Internal Server Error"));
        assertTrue(Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").matcher(body).find(), "correlation id");
        assertFalse(body.contains("SECRET-DETAIL") || body.contains("simulated") || body.contains("at com.")
                || body.contains("IllegalStateException"));
        assertEquals("SUBMITTED", status(id), "the business change is committed");
        boolean errorLogged = false;
        for (ILoggingEvent event : logs.list) {
            assertFalse(event.getFormattedMessage().contains("SECRET-DETAIL"), "outage text must not be logged");
            if (event.getLevel() == Level.ERROR && event.getFormattedMessage().contains("Audit append failed correlationId=")) {
                errorLogged = true;
            }
        }
        assertTrue(errorLogged, "ERROR line with a correlation id");
    }

    // ---- templates ----

    @Test
    @DisplayName("SEC-REPORT-WEB-12: report templates have no th:utext, inline script, style or handler")
    void templatesAreClean() throws Exception {
        Pattern forbidden = Pattern.compile("th:utext|innerHTML|javascript:|<script|style=|\\son[a-z]+\\s*=", Pattern.CASE_INSENSITIVE);
        try (Stream<Path> files = Files.list(Paths.get("src/main/resources/templates/reports"))) {
            List<Path> templates = files.filter(p -> p.toString().endsWith(".html")).toList();
            assertEquals(2, templates.size());
            for (Path template : templates) {
                for (String line : Files.readAllLines(template)) {
                    assertFalse(forbidden.matcher(line).find(), template.getFileName() + ": " + line.trim());
                }
            }
        }
    }
}
