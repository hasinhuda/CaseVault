package com.casevault.audit;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.model.Case;
import com.casevault.model.Evidence;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.EvidenceRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AuditEventRecorder;
import com.casevault.service.AuditEventType;
import com.casevault.service.AuditLogService;
import com.casevault.service.ChainVerificationResult;
import com.casevault.service.ChainedAuditEventRecorder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Phase 6B: the chained audit log is wired into login, cases and evidence (H2, real Spring context). */
@SpringBootTest
@AutoConfigureMockMvc
class AuditWiringTest {

    private static final String PASSWORD = "Wire-Test-Password-1234!";
    private static final byte[] TXT = "2026-11-10 14:00:00 wiring test incident note".getBytes(StandardCharsets.UTF_8);

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
    private EvidenceRepository evidenceRepository;
    @Autowired
    private AuditEventRecorder recorder;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @MockitoSpyBean
    private AuditLogService auditLogService;

    private ListAppender<ILoggingEvent> logs;
    private Logger rootLogger;

    private Organisation orgA;
    private Organisation orgB;
    private Organisation internal;
    private User clientA;
    private User clientB;
    private User manager;
    private User analyst;
    private String suffix;

    private record Row(String type, String userId, String caseId, String reason) {
    }

    @BeforeEach
    void setUp() {
        jdbc.update("DELETE FROM audit_events");
        rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        logs = new ListAppender<>();
        logs.start();
        rootLogger.addAppender(logs);

        suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        internal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(
                        new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        orgA = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Wire A " + suffix, "WIRE_A_" + suffix, now));
        orgB = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Wire B " + suffix, "WIRE_B_" + suffix, now));
        String hash = passwordEncoder.encode(PASSWORD);
        clientA = user("wire_ca_" + suffix, orgA, Role.CLIENT, hash);
        clientB = user("wire_cb_" + suffix, orgB, Role.CLIENT, hash);
        manager = user("wire_mg_" + suffix, internal, Role.MANAGER, hash);
        analyst = user("wire_an_" + suffix, internal, Role.ANALYST, hash);
        // The user setup above does not audit anything: start every test from an empty chain.
        jdbc.update("DELETE FROM audit_events");
    }

    @AfterEach
    void tearDown() {
        rootLogger.detachAppender(logs);
        logs.stop();
    }

    private User user(String name, Organisation org, Role role, String hash) {
        return userRepository.save(new User(UUID.randomUUID().toString(), org, name, hash, role,
                name + "@test.local", true, Instant.now()));
    }

    private Authentication auth(User u) {
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(u, Instant.now());
        return new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities());
    }

    private List<Row> rows() {
        return new ArrayList<>(jdbc.query(
                "SELECT event_type, user_id, case_id, reason_code FROM audit_events ORDER BY sequence_no",
                (rs, i) -> new Row(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4))));
    }

    private MvcResult login(String username, String password) throws Exception {
        return mockMvc.perform(post("/login").with(csrf()).param("username", username).param("password", password))
                .andReturn();
    }

    private Case caseFor(User owner, Organisation org, User assigned) {
        return caseRepository.save(new Case(UUID.randomUUID().toString(), org, "Wire case " + suffix, "RANSOMWARE",
                "HIGH", "OPEN", owner, assigned, Instant.now()));
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-01: successful login writes exactly one LOGIN_SUCCESS with the user's UUID")
    void loginSuccess() throws Exception {
        MvcResult result = login(clientA.getUsername(), PASSWORD);
        assertEquals(302, result.getResponse().getStatus());
        assertEquals(List.of(new Row("LOGIN_SUCCESS", clientA.getId(), null, "SUCCESS")), rows());
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-02: wrong password for an existing user writes LOGIN_FAILURE with that user's UUID")
    void loginFailureExistingUser() throws Exception {
        login(clientA.getUsername(), "not-the-password");
        assertEquals(List.of(new Row("LOGIN_FAILURE", clientA.getId(), null, "BAD_CREDENTIALS")), rows());
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-03: unknown username writes LOGIN_FAILURE with a null user_id")
    void loginFailureUnknownUser() throws Exception {
        login("nobody_" + suffix, "whatever-pass");
        assertEquals(List.of(new Row("LOGIN_FAILURE", null, null, "BAD_CREDENTIALS")), rows());
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-04: five failures write ACCOUNT_LOCKED; a correct password while locked is LOGIN_FAILURE")
    void accountLocked() throws Exception {
        for (int i = 0; i < 5; i++) {
            login(clientB.getUsername(), "wrong-" + i);
        }
        List<Row> afterFive = rows();
        assertEquals(6, afterFive.size());
        assertEquals(5, afterFive.stream().filter(r -> r.type().equals("LOGIN_FAILURE")).count());
        assertEquals(List.of(new Row("ACCOUNT_LOCKED", clientB.getId(), null, "ACCOUNT_LOCKED")),
                afterFive.stream().filter(r -> r.type().equals("ACCOUNT_LOCKED")).toList());

        login(clientB.getUsername(), PASSWORD);
        assertEquals(new Row("LOGIN_FAILURE", clientB.getId(), null, "ACCOUNT_LOCKED"), rows().get(6));
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-05: logout writes LOGOUT; a logout without a session writes nothing")
    void logout() throws Exception {
        MvcResult loginResult = login(clientA.getUsername(), PASSWORD);
        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        mockMvc.perform(post("/logout").with(csrf()).session(session)).andExpect(status().is3xxRedirection());
        assertEquals(List.of(new Row("LOGIN_SUCCESS", clientA.getId(), null, "SUCCESS"),
                new Row("LOGOUT", clientA.getId(), null, "SUCCESS")), rows());

        mockMvc.perform(post("/logout").with(csrf())).andExpect(status().is3xxRedirection());
        assertEquals(2, rows().size());
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-06: no audit column and no log line contains the typed username, password or session id")
    void noCredentialsInRowsOrLogs() throws Exception {
        String typedUnknown = "typed_unknown_" + suffix;
        String typedPassword = "Typed-Secret-" + suffix;
        login(typedUnknown, typedPassword);
        login(clientA.getUsername(), typedPassword);
        String preAuthSessionId = "SESSIONID-" + suffix;
        MvcResult ok = mockMvc.perform(post("/login").with(csrf()).session(new MockHttpSession(null, preAuthSessionId))
                .param("username", clientA.getUsername()).param("password", PASSWORD)).andReturn();
        String sessionId = ok.getRequest().getSession(false).getId();
        mockMvc.perform(post("/logout").with(csrf()).session((MockHttpSession) ok.getRequest().getSession(false)));

        String everything = String.join("|", jdbc.query("SELECT CAST(id AS VARCHAR), event_type, CAST(user_id AS VARCHAR), "
                        + "CAST(case_id AS VARCHAR), reason_code, CAST(occurred_at AS VARCHAR), prev_hash, hmac FROM audit_events",
                (rs, i) -> rs.getString(1) + rs.getString(2) + rs.getString(3) + rs.getString(4) + rs.getString(5)
                        + rs.getString(6) + rs.getString(7) + rs.getString(8)));
        StringBuilder logText = new StringBuilder();
        for (ILoggingEvent event : logs.list) {
            logText.append(event.getFormattedMessage()).append('\n');
        }
        // Spring's MockHttpSession hands out short counter ids ("1", "2"), which would match digits in any UUID, so
        // the rotated id is only checked when it is long enough to be meaningful; the pre-auth id is distinctive.
        List<String> secrets = new ArrayList<>(List.of(typedUnknown, typedPassword, PASSWORD, clientA.getUsername(),
                preAuthSessionId));
        if (sessionId.length() >= 16) {
            secrets.add(sessionId);
        }
        for (String secret : secrets) {
            assertFalse(everything.contains(secret), "audit rows must not contain a typed or session value");
            assertFalse(logText.toString().contains(secret), "log lines must not contain a typed or session value");
        }
        assertEquals(Set.of("LOGIN_FAILURE", "LOGIN_SUCCESS", "LOGOUT"),
                Set.copyOf(rows().stream().map(Row::type).toList()));
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-07: cross-tenant case request is 404 with exactly one ACCESS_DENIED; nonexistent id and "
            + "unauthenticated requests write no row with a user id")
    void crossTenantAccessDenied() throws Exception {
        Case caseA = caseFor(clientA, orgA, null);

        mockMvc.perform(get("/api/cases/{id}", caseA.getId()).with(authentication(auth(clientB))))
                .andExpect(status().isNotFound());
        assertEquals(List.of(new Row("ACCESS_DENIED", clientB.getId(), caseA.getId(), "NOT_VISIBLE")), rows());

        mockMvc.perform(get("/api/cases/{id}", UUID.randomUUID().toString()).with(authentication(auth(clientB))))
                .andExpect(status().isNotFound());
        assertEquals(1, rows().size(), "a nonexistent id is not recorded as a masked denial");

        mockMvc.perform(get("/api/cases/{id}", caseA.getId()).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
        assertTrue(rows().stream().noneMatch(r -> r.userId() != null && r.type().equals("ACCESS_DENIED")
                && !r.userId().equals(clientB.getId())));
        assertEquals(1, rows().size());
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-08: an AccessDeniedException (403) writes exactly one ACCESS_DENIED NOT_PERMITTED")
    void accessDeniedException() throws Exception {
        mockMvc.perform(post("/api/cases").with(authentication(auth(analyst))).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"x\",\"category\":\"RANSOMWARE\",\"severity\":\"HIGH\"}"))
                .andExpect(status().isForbidden());
        assertEquals(List.of(new Row("ACCESS_DENIED", analyst.getId(), null, "NOT_PERMITTED")), rows());
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-09: case create, assign, status change and note each write exactly one row with the actor")
    void caseLifecycleEvents() throws Exception {
        MvcResult created = mockMvc.perform(post("/api/cases").with(authentication(auth(clientA))).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Wire lifecycle " + suffix + "\",\"category\":\"RANSOMWARE\",\"severity\":\"HIGH\"}"))
                .andExpect(status().isCreated()).andReturn();
        Matcher idMatcher = Pattern.compile("\"id\"\\s*:\\s*\"([0-9a-f-]{36})\"").matcher(created.getResponse().getContentAsString());
        assertTrue(idMatcher.find());
        String caseId = idMatcher.group(1);
        assertEquals(List.of(new Row("CASE_CREATED", clientA.getId(), caseId, "CREATED")), rows());

        mockMvc.perform(post("/api/cases/{id}/assign", caseId).with(authentication(auth(manager))).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"analystId\":\"" + analyst.getId() + "\"}"))
                .andExpect(status().isOk());
        assertEquals(new Row("CASE_ASSIGNED", manager.getId(), caseId, "ASSIGNED"), rows().get(1));
        assertEquals(2, rows().size());

        mockMvc.perform(put("/api/cases/{id}/status", caseId).with(authentication(auth(analyst))).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"IN_PROGRESS\"}"))
                .andExpect(status().isOk());
        assertEquals(new Row("CASE_UPDATED", analyst.getId(), caseId, "STATUS_CHANGED"), rows().get(2));
        assertEquals(3, rows().size());

        mockMvc.perform(put("/api/cases/{id}/status", caseId).with(authentication(auth(analyst))).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"IN_PROGRESS\"}"))
                .andExpect(status().isOk());
        assertEquals(3, rows().size(), "an unchanged status is not an event");

        mockMvc.perform(post("/api/cases/{id}/notes", caseId).with(authentication(auth(analyst))).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content("{\"body\":\"internal note\"}"))
                .andExpect(status().is2xxSuccessful());
        assertEquals(new Row("CASE_UPDATED", analyst.getId(), caseId, "UPDATED"), rows().get(3));
        assertEquals(4, rows().size());
    }

    private Evidence uploadOk(Case c, User uploader, String name) throws Exception {
        mockMvc.perform(multipart("/cases/{id}/evidence", c.getId())
                        .file(new MockMultipartFile("file", name, "text/plain", TXT))
                        .with(authentication(auth(uploader))).with(csrf()))
                .andExpect(status().is3xxRedirection());
        return evidenceRepository.findByACaseId(c.getId()).stream()
                .filter(e -> name.equals(e.getOriginalName())).findFirst().orElseThrow();
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-10: evidence upload, rejected upload, download, tampered file and missing file each write exactly one row")
    void evidenceEvents() throws Exception {
        Case c = caseFor(clientA, orgA, null);

        Evidence ev = uploadOk(c, clientA, "wire_upload_" + suffix + ".txt");
        assertEquals(List.of(new Row("EVIDENCE_UPLOADED", clientA.getId(), c.getId(), "ACCEPTED")), rows());

        mockMvc.perform(multipart("/cases/{id}/evidence", c.getId())
                        .file(new MockMultipartFile("file", "fake.png", "image/png", "plain text, not a png".getBytes(StandardCharsets.UTF_8)))
                        .with(authentication(auth(clientA))).with(csrf()))
                .andExpect(status().isBadRequest());
        assertEquals(new Row("EVIDENCE_REJECTED", clientA.getId(), c.getId(), "VALIDATION_REJECTED"), rows().get(1));
        assertEquals(2, rows().size());

        mockMvc.perform(get("/cases/{c}/evidence/{e}", c.getId(), ev.getId()).with(authentication(auth(clientA))))
                .andExpect(status().isOk());
        assertEquals(new Row("EVIDENCE_DOWNLOADED", clientA.getId(), c.getId(), "INTEGRITY_VERIFIED"), rows().get(2));
        assertEquals(3, rows().size());

        Path stored = sharedTempDir.resolve("evidence").resolve(ev.getStoredName());
        byte[] original = Files.readAllBytes(stored);
        byte[] tampered = original.clone();
        tampered[tampered.length - 1] ^= 1;
        Files.write(stored, tampered);
        mockMvc.perform(get("/cases/{c}/evidence/{e}", c.getId(), ev.getId()).with(authentication(auth(clientA))))
                .andExpect(status().isNotFound());
        assertEquals(new Row("EVIDENCE_REJECTED", clientA.getId(), c.getId(), "INTEGRITY_FAILED"), rows().get(3));
        assertEquals(4, rows().size());

        Files.delete(stored);
        mockMvc.perform(get("/cases/{c}/evidence/{e}", c.getId(), ev.getId()).with(authentication(auth(clientA))))
                .andExpect(status().isNotFound());
        assertEquals(new Row("EVIDENCE_REJECTED", clientA.getId(), c.getId(), "FILE_NOT_FOUND"), rows().get(4));
        assertEquals(5, rows().size());
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-11: after a mixed scenario the chain verifies with no gap and rows hold no file name or hash")
    void mixedScenarioChainValid() throws Exception {
        String fileName = "mixed_secret_name_" + suffix + ".txt";
        login(clientA.getUsername(), PASSWORD);
        MvcResult created = mockMvc.perform(post("/api/cases").with(authentication(auth(clientA))).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"Mixed " + suffix + "\",\"category\":\"RANSOMWARE\",\"severity\":\"HIGH\"}"))
                .andExpect(status().isCreated()).andReturn();
        Matcher m = Pattern.compile("\"id\"\\s*:\\s*\"([0-9a-f-]{36})\"").matcher(created.getResponse().getContentAsString());
        assertTrue(m.find());
        Case c = caseRepository.findById(m.group(1)).orElseThrow();
        Evidence ev = uploadOk(c, clientA, fileName);
        mockMvc.perform(get("/cases/{c}/evidence/{e}", c.getId(), ev.getId()).with(authentication(auth(clientA))))
                .andExpect(status().isOk());
        login(clientA.getUsername(), "wrong");

        assertEquals(List.of("LOGIN_SUCCESS", "CASE_CREATED", "EVIDENCE_UPLOADED", "EVIDENCE_DOWNLOADED", "LOGIN_FAILURE"),
                rows().stream().map(Row::type).toList());
        ChainVerificationResult result = auditLogService.verifyChain();
        assertTrue(result.valid());
        assertEquals(5, result.eventsVerified());
        assertEquals(List.of(1L, 2L, 3L, 4L, 5L),
                jdbc.queryForList("SELECT sequence_no FROM audit_events ORDER BY sequence_no", Long.class));

        String all = String.join("|", jdbc.query("SELECT CAST(user_id AS VARCHAR), CAST(case_id AS VARCHAR), reason_code, "
                        + "event_type FROM audit_events", (rs, i) -> rs.getString(1) + rs.getString(2) + rs.getString(3) + rs.getString(4)));
        assertFalse(all.contains(fileName));
        assertFalse(all.contains("mixed_secret_name"));
        assertFalse(all.contains(ev.getSha256Hex()));
        assertFalse(all.contains(ev.getStoredName()));
        assertEquals(Set.of("id", "sequence_no", "event_type", "user_id", "case_id", "reason_code", "occurred_at",
                        "prev_hash", "hmac"),
                Set.copyOf(jdbc.queryForList("SELECT LOWER(column_name) FROM information_schema.columns "
                        + "WHERE LOWER(table_name) = 'audit_events'", String.class)));
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-12: if the append fails after the commit, the case stays committed and the user gets the safe "
            + "error page with a correlation id (JSON and HTML)")
    void appendFailureAfterCommit() throws Exception {
        doThrow(new IllegalStateException("db down secret-marker-" + suffix)).when(auditLogService)
                .recordEvent(eq(AuditEventType.CASE_CREATED), any(), any(), any());
        String title = "Failing audit " + suffix;

        MvcResult json = mockMvc.perform(post("/api/cases").with(authentication(auth(clientA))).with(csrf())
                        .accept(MediaType.APPLICATION_JSON).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"" + title + "\",\"category\":\"RANSOMWARE\",\"severity\":\"HIGH\"}"))
                .andExpect(status().isInternalServerError()).andReturn();
        String jsonBody = json.getResponse().getContentAsString();
        Matcher idMatcher = Pattern.compile("\"correlationId\"\\s*:\\s*\"([0-9a-f-]{36})\"").matcher(jsonBody);
        assertTrue(idMatcher.find(), "correlation id must be present: " + jsonBody);
        String correlationId = idMatcher.group(1);
        assertFalse(jsonBody.contains("secret-marker"));
        assertFalse(jsonBody.contains("IllegalStateException"));
        assertFalse(jsonBody.contains("at com.casevault"));

        assertEquals(1, caseRepository.findAll().stream().filter(x -> title.equals(x.getTitle())).count(),
                "the business change must remain committed");
        assertEquals(0, rows().stream().filter(r -> r.type().equals("CASE_CREATED")).count());

        List<ILoggingEvent> errors = logs.list.stream().filter(e -> e.getLevel() == Level.ERROR
                && e.getLoggerName().endsWith("ChainedAuditEventRecorder")).toList();
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).getFormattedMessage().contains(correlationId));
        assertNull(errors.get(0).getThrowableProxy(), "the ERROR line must not carry the exception");
        assertFalse(errors.get(0).getFormattedMessage().contains("secret-marker"));

        String htmlTitle = "Failing audit html " + suffix;
        MvcResult html = mockMvc.perform(post("/cases").with(authentication(auth(clientA))).with(csrf())
                        .param("title", htmlTitle).param("category", "RANSOMWARE").param("severity", "HIGH"))
                .andExpect(status().isInternalServerError()).andReturn();
        String page = html.getResponse().getContentAsString();
        assertTrue(page.contains("Incident Correlation ID"));
        assertTrue(Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").matcher(page).find());
        assertFalse(page.contains("secret-marker"));
        assertFalse(page.contains("IllegalStateException"));
        assertFalse(page.contains("at com.casevault"));
        assertEquals(1, caseRepository.findAll().stream().filter(x -> htmlTitle.equals(x.getTitle())).count());
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-13: outcome events are appended only after commit and dropped on rollback; attempt events survive rollback")
    void orderingAroundTransactions() {
        TransactionTemplate template = new TransactionTemplate(transactionManager);
        String user = UUID.randomUUID().toString();

        template.executeWithoutResult(status -> {
            recorder.record(AuditEventType.CASE_CREATED, user, null, "CREATED");
            assertEquals(0, rows().size(), "nothing may be appended before the business transaction commits");
        });
        assertEquals(List.of(new Row("CASE_CREATED", user, null, "CREATED")), rows());

        template.executeWithoutResult(status -> {
            recorder.record(AuditEventType.CASE_UPDATED, user, null, "UPDATED");
            recorder.record(AuditEventType.ACCESS_DENIED, user, null, "NOT_VISIBLE");
            status.setRollbackOnly();
        });
        assertEquals(List.of(new Row("CASE_CREATED", user, null, "CREATED"),
                new Row("ACCESS_DENIED", user, null, "NOT_VISIBLE")), rows(),
                "a rolled-back action is not an event, a denied attempt still is");
        assertTrue(auditLogService.verifyChain().valid());
    }

    @Test
    @DisplayName("SEC-AUDIT-WIRE-14: the chained recorder is the default bean")
    void chainedIsDefault() {
        assertInstanceOf(ChainedAuditEventRecorder.class, recorder);
    }
}
