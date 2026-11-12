package com.casevault.audit;

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
import com.casevault.service.AuditEventType;
import com.casevault.service.AuditLogService;
import com.casevault.service.AuditQueryService.AuditPageView;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Phase 6C: auditor view of the audit log (H2, real Spring context, real HTTP stack via MockMvc). */
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuditUiTest {

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
    private OrganisationRepository organisationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CaseRepository caseRepository;
    @Autowired
    private EvidenceRepository evidenceRepository;
    @MockitoSpyBean
    private AuditLogService auditLogService;

    private User auditor;
    private User client;
    private User analyst;
    private User manager;
    private Organisation orgA;
    private String suffix;

    @BeforeEach
    void setUp() {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        Organisation internal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(
                        new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        orgA = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "UI A " + suffix, "UI_A_" + suffix, now));
        auditor = user("ui_au_" + suffix, internal, Role.AUDITOR_ADMIN);
        client = user("ui_cl_" + suffix, orgA, Role.CLIENT);
        analyst = user("ui_an_" + suffix, internal, Role.ANALYST);
        manager = user("ui_mg_" + suffix, internal, Role.MANAGER);
        jdbc.update("DELETE FROM audit_events");
    }

    private User user(String name, Organisation org, Role role) {
        return userRepository.save(new User(UUID.randomUUID().toString(), org, name, "{noop}unused-hash", role,
                name + "@test.local", true, Instant.now()));
    }

    private Authentication auth(User u) {
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(u, Instant.now());
        return new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities());
    }

    private void seed(AuditEventType type, UUID userId, UUID caseId, String reason) {
        auditLogService.append(type, userId, caseId, reason);
    }

    private void seedMixed() {
        seed(AuditEventType.LOGIN_SUCCESS, UUID.fromString(client.getId()), null, "SUCCESS");
        seed(AuditEventType.LOGIN_FAILURE, UUID.fromString(analyst.getId()), null, "BAD_CREDENTIALS");
        seed(AuditEventType.CASE_CREATED, UUID.fromString(client.getId()), UUID.randomUUID(), "CREATED");
        seed(AuditEventType.LOGIN_FAILURE, null, null, "BAD_CREDENTIALS");
    }

    private MvcResult getAudit(String query) throws Exception {
        return mockMvc.perform(get("/audit" + query).with(authentication(auth(auditor))))
                .andExpect(status().isOk()).andReturn();
    }

    private static AuditPageView view(MvcResult result) {
        AuditPageView view = (AuditPageView) result.getModelAndView().getModel().get("audit");
        assertNotNull(view);
        return view;
    }

    private int count(String type) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM audit_events WHERE event_type = ?", Integer.class, type);
    }

    // ---- verification status (must run first: the last result is kept in memory for the whole context) ----

    @Test
    @Order(1)
    @DisplayName("SEC-AUDIT-UI-01: before any verification the badge says \"Not verified yet\" and the page does not verify the chain")
    void notVerifiedYet() throws Exception {
        seedMixed();
        Mockito.clearInvocations(auditLogService);
        String body = getAudit("").getResponse().getContentAsString();
        assertTrue(body.contains("Not verified yet"));
        Mockito.verify(auditLogService, Mockito.never()).verifyChain();
        Mockito.verify(auditLogService, Mockito.never()).verifyChain(Mockito.anyInt());
        assertEquals(0, count("AUDIT_CHAIN_VERIFIED"), "viewing the list is not an event");
    }

    // ---- access matrix ----

    @Test
    @DisplayName("SEC-AUDIT-UI-02: only AUDITOR_ADMIN gets 200; CLIENT, ANALYST and MANAGER get 404 on GET /audit and POST /audit/verify")
    void roleMatrix() throws Exception {
        mockMvc.perform(get("/audit").with(authentication(auth(auditor)))).andExpect(status().isOk());
        for (User denied : List.of(client, analyst, manager)) {
            mockMvc.perform(get("/audit").with(authentication(auth(denied)))).andExpect(status().isNotFound());
            mockMvc.perform(post("/audit/verify").with(authentication(auth(denied))).with(csrf()))
                    .andExpect(status().isNotFound());
        }
        assertEquals(0, count("AUDIT_CHAIN_VERIFIED"));
        assertEquals(6, count("ACCESS_DENIED"), "each masked attempt is recorded as ACCESS_DENIED");
    }

    @Test
    @DisplayName("SEC-AUDIT-UI-03: unauthenticated requests are redirected to login or refused; no verification happens")
    void unauthenticated() throws Exception {
        // Same behaviour as the existing protected page /cases (a generic client gets 401, a browser is redirected).
        int casesStatus = mockMvc.perform(get("/cases")).andReturn().getResponse().getStatus();
        assertEquals(casesStatus, mockMvc.perform(get("/audit")).andReturn().getResponse().getStatus());
        assertEquals(casesStatus, mockMvc.perform(post("/audit/verify").with(csrf())).andReturn().getResponse().getStatus());
        MvcResult browser = mockMvc.perform(get("/audit").accept("text/html")).andReturn();
        assertEquals(302, browser.getResponse().getStatus());
        assertTrue(browser.getResponse().getRedirectedUrl().endsWith("/login"));
        mockMvc.perform(post("/audit/verify")).andExpect(status().isForbidden());
        assertEquals(0, count("AUDIT_CHAIN_VERIFIED"));
    }

    @Test
    @DisplayName("SEC-AUDIT-UI-04: POST /audit/verify without a CSRF token is 403 for the auditor and verifies nothing")
    void postWithoutCsrf() throws Exception {
        seedMixed();
        mockMvc.perform(post("/audit/verify").with(authentication(auth(auditor)))).andExpect(status().isForbidden());
        assertEquals(0, count("AUDIT_CHAIN_VERIFIED"));
    }

    @Test
    @DisplayName("SEC-AUDIT-UI-05: the \"Audit log\" link is shown only to the auditor; the page form carries a CSRF token")
    void navLinkOnlyForAuditor() throws Exception {
        for (User other : List.of(client, analyst, manager)) {
            String body = mockMvc.perform(get("/dashboard").with(authentication(auth(other))))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
            assertFalse(body.contains("href=\"/audit\""), "no audit link for " + other.getRole());
            assertFalse(body.contains("Audit log"));
        }
        String dashboard = mockMvc.perform(get("/dashboard").with(authentication(auth(auditor))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(dashboard.contains("href=\"/audit\""));
        String page = getAudit("").getResponse().getContentAsString();
        assertTrue(page.contains("href=\"/audit\""));
        assertTrue(page.contains("name=\"_csrf\""), "verify form has a CSRF token");
        assertTrue(page.contains("class=\"skip-link\""));
        assertFalse(page.contains("<script"), "works without JavaScript");
    }

    @Test
    @DisplayName("SEC-AUDIT-UI-06: the auditor still has no case content; the audit page shows no title, note, file name, username or hash")
    void auditorSeesNoCaseContent() throws Exception {
        String title = "Secret-Case-Title-" + suffix;
        String noteText = "secret note text " + suffix;
        String fileName = "secret_file_" + suffix + ".txt";
        Case c = caseRepository.save(new Case(UUID.randomUUID().toString(), orgA, title, "RANSOMWARE", "HIGH",
                "OPEN", client, null, Instant.now()));
        mockMvc.perform(multipart("/cases/{id}/evidence", c.getId())
                        .file(new MockMultipartFile("file", fileName, "text/plain",
                                "synthetic evidence line".getBytes(StandardCharsets.UTF_8)))
                        .with(authentication(auth(client))).with(csrf()))
                .andExpect(status().is3xxRedirection());
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/cases/{id}/notes", c.getId()).with(authentication(auth(manager))).with(csrf())
                        .contentType("application/json").content("{\"body\":\"" + noteText + "\"}"))
                .andExpect(status().is2xxSuccessful());
        Evidence ev = evidenceRepository.findByACaseId(c.getId()).stream().findFirst().orElseThrow();

        mockMvc.perform(get("/cases/{id}", c.getId()).with(authentication(auth(auditor)))).andExpect(status().isNotFound());
        mockMvc.perform(get("/api/cases/{id}", c.getId()).with(authentication(auth(auditor)))).andExpect(status().isNotFound());
        mockMvc.perform(get("/cases/{c}/evidence/{e}", c.getId(), ev.getId()).with(authentication(auth(auditor))))
                .andExpect(status().isNotFound());

        String body = getAudit("?size=50").getResponse().getContentAsString();
        for (String secret : List.of(title, noteText, fileName, client.getUsername(), manager.getUsername(),
                ev.getStoredName())) {
            assertFalse(body.contains(secret), "audit page must not contain: " + secret);
        }
        List<String> hashes = jdbc.queryForList("SELECT hmac FROM audit_events", String.class);
        assertFalse(hashes.isEmpty());
        for (String hash : hashes) {
            assertFalse(body.contains(hash), "full HMAC must not be shown");
        }
        assertTrue(body.contains(c.getId()), "the case id (a UUID) is shown");
        String head = jdbc.queryForObject("SELECT hmac FROM audit_events ORDER BY sequence_no DESC LIMIT 1", String.class);
        assertTrue(body.contains(head.substring(0, 12)), "first 12 hex chars of the head HMAC are shown");
    }

    // ---- filters ----

    @Test
    @DisplayName("SEC-AUDIT-UI-07: filters by event type, user id and date range, alone and combined")
    void filters() throws Exception {
        seedMixed();
        UUID clientId = UUID.fromString(client.getId());
        jdbc.update("UPDATE audit_events SET occurred_at = ? WHERE sequence_no = 1",
                Timestamp.from(Instant.parse("2020-01-15T12:00:00Z")));

        assertEquals(2, view(getAudit("?eventType=LOGIN_FAILURE")).totalElements());
        assertEquals(1, view(getAudit("?eventType=CASE_CREATED")).totalElements());
        assertEquals(2, view(getAudit("?userId=" + clientId)).totalElements());
        assertEquals(1, view(getAudit("?from=2020-01-01&to=2020-01-31")).totalElements());
        assertEquals(1, view(getAudit("?from=2020-01-15&to=2020-01-15")).totalElements(), "to is inclusive");
        String today = LocalDate.now(ZoneOffset.UTC).toString();
        assertEquals(3, view(getAudit("?from=" + today)).totalElements());
        // combined: client's events only from 2021 on => only CASE_CREATED
        AuditPageView combined = view(getAudit("?userId=" + clientId + "&from=2021-01-01&eventType=CASE_CREATED"));
        assertEquals(1, combined.totalElements());
        assertEquals("CASE_CREATED", combined.rows().get(0).eventType());
        assertEquals(0, view(getAudit("?userId=" + clientId + "&eventType=LOGIN_FAILURE")).totalElements());
        String empty = getAudit("?eventType=LOGOUT").getResponse().getContentAsString();
        assertTrue(empty.contains("No audit events found"), "friendly empty state");
    }

    @Test
    @DisplayName("SEC-AUDIT-UI-08: invalid event type, UUID, date or from > to give a friendly message, no rows, no 500, no echo of the input")
    void invalidFilters() throws Exception {
        seedMixed();
        record Case8(String query, String message, String rawInput) {
        }
        List<Case8> cases = List.of(
                new Case8("?eventType=NOT_AN_EVENT_xyz", "Unknown event type", "NOT_AN_EVENT_xyz"),
                new Case8("?userId=not-a-uuid-qqq", "must be a UUID", "not-a-uuid-qqq"),
                new Case8("?from=2026-13-45", "valid date", "2026-13-45"),
                new Case8("?to=31.12.2026", "valid date", "31.12.2026"),
                new Case8("?from=2026-05-02&to=2026-05-01", "must not be after", "2026-05-02"));
        for (Case8 c : cases) {
            MvcResult result = getAudit(c.query());
            String body = result.getResponse().getContentAsString();
            assertTrue(body.contains(c.message()), c.query());
            assertFalse(body.contains(c.rawInput()), "raw input must not be echoed: " + c.query());
            assertTrue(view(result).rows().isEmpty(), "no rows are shown while a filter is invalid");
        }
    }

    @Test
    @DisplayName("SEC-AUDIT-UI-09: SQL-injection-looking and script-looking values are harmless and never reflected unescaped")
    void injectionValues() throws Exception {
        seedMixed();
        String sql = "' OR '1'='1' --";
        String script = "<script>alert(1)</script>";
        String img = "\"><img src=x onerror=alert(1)>";
        List<String> queries = List.of(
                "?eventType=" + enc(sql), "?userId=" + enc(script), "?from=" + enc(img), "?to=" + enc(script),
                "?page=" + enc(sql) + "&size=" + enc(script) + "&sort=" + enc(sql),
                "?eventType=" + enc(script) + "&userId=" + enc(sql) + "&from=" + enc(img));
        for (String query : queries) {
            String body = getAudit(query).getResponse().getContentAsString();
            assertFalse(body.contains("<script>alert(1)"), query);
            assertFalse(body.contains("<img src=x"), query);
            assertFalse(body.contains("onerror=alert"), query);
            assertFalse(body.contains("OR '1'='1'"), query);
            assertFalse(body.contains("OR &#39;1&#39;=&#39;1&#39;"), "not even escaped: invalid input is dropped, not echoed");
        }
        assertEquals(4, view(getAudit("?page=" + enc(sql))).totalElements(), "injection text did not change the query");
    }

    private static String enc(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    // ---- pagination ----

    @Test
    @DisplayName("SEC-AUDIT-UI-10: size is capped at 50, negative or huge page is safe, the sort parameter is ignored (newest first)")
    void pagination() throws Exception {
        for (int i = 0; i < 60; i++) {
            seed(AuditEventType.LOGIN_FAILURE, null, null, "BAD_CREDENTIALS");
        }
        AuditPageView big = view(getAudit("?size=1000"));
        assertEquals(50, big.size());
        assertEquals(50, big.rows().size());
        assertEquals(60L, big.rows().get(0).sequenceNo(), "newest first");
        assertEquals(11L, big.rows().get(49).sequenceNo());
        assertEquals(25, view(getAudit("")).size(), "default page size");
        assertEquals(25, view(getAudit("?size=0")).size());
        assertEquals(25, view(getAudit("?size=-5")).size());
        assertEquals(25, view(getAudit("?size=abc")).size());
        assertEquals(0, view(getAudit("?page=-1")).page());
        assertEquals(0, view(getAudit("?page=abc")).page());
        assertEquals(0, view(getAudit("?page=99999999999999999999")).page());

        MvcResult far = getAudit("?page=99999999");
        assertTrue(view(far).rows().isEmpty());
        assertTrue(far.getResponse().getContentAsString().contains("No audit events found"));

        AuditPageView second = view(getAudit("?page=1&size=50"));
        assertEquals(10, second.rows().size());
        assertEquals(10L, second.rows().get(0).sequenceNo());

        for (String sort : List.of("sequenceNo,asc", "eventType", "hmac,desc", "user_id")) {
            AuditPageView sorted = view(getAudit("?sort=" + enc(sort)));
            assertEquals(60L, sorted.rows().get(0).sequenceNo(), "sort parameter must be ignored: " + sort);
            assertEquals(36L, sorted.rows().get(24).sequenceNo());
        }
    }

    // ---- verification ----

    @Test
    @DisplayName("SEC-AUDIT-UI-11: valid chain => POST redirects to /audit and the badge says \"Chain valid\"; exactly one AUDIT_CHAIN_VERIFIED with the auditor's UUID")
    void verifyValid() throws Exception {
        seedMixed();
        mockMvc.perform(post("/audit/verify").with(authentication(auth(auditor))).with(csrf()))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/audit"));
        String body = getAudit("").getResponse().getContentAsString();
        assertTrue(body.contains("Chain valid"));
        assertTrue(body.contains("4 events verified"));
        assertFalse(body.contains("Not verified yet"));
        assertFalse(body.contains("BROKEN"));
        assertTrue(body.contains("aria-live=\"polite\""));

        List<String> rows = jdbc.queryForList(
                "SELECT CAST(user_id AS VARCHAR) || '|' || reason_code FROM audit_events WHERE event_type = 'AUDIT_CHAIN_VERIFIED'",
                String.class);
        assertEquals(List.of(auditor.getId() + "|CHAIN_VALID"), rows);
        assertEquals(5, jdbc.queryForObject("SELECT COUNT(*) FROM audit_events", Integer.class));
        // The appended verification event keeps the chain valid.
        assertTrue(auditLogService.verifyChain().valid());
    }

    @Test
    @DisplayName("SEC-AUDIT-UI-12: a tampered row => badge \"Chain BROKEN at sequence N: kind\" with the right sequence and kind; one AUDIT_CHAIN_VERIFIED CHAIN_INVALID")
    void verifyBroken() throws Exception {
        seedMixed();
        jdbc.update("UPDATE audit_events SET reason_code = 'CREATED' WHERE sequence_no = 2");
        mockMvc.perform(post("/audit/verify").with(authentication(auth(auditor))).with(csrf()))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/audit"));
        String body = getAudit("").getResponse().getContentAsString();
        assertTrue(body.contains("Chain BROKEN at sequence 2: HMAC_MISMATCH"), body);
        assertFalse(body.contains("Chain valid"));
        assertEquals(1, count("AUDIT_CHAIN_VERIFIED"));
        assertEquals(List.of(auditor.getId() + "|CHAIN_INVALID"), jdbc.queryForList(
                "SELECT CAST(user_id AS VARCHAR) || '|' || reason_code FROM audit_events WHERE event_type = 'AUDIT_CHAIN_VERIFIED'",
                String.class));
    }

    @Test
    @DisplayName("SEC-AUDIT-UI-13: two overlapping verifications => the second gets a friendly message and starts nothing; one event only")
    void overlappingVerifications() throws Exception {
        seedMixed();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Mockito.doAnswer(invocation -> {
            started.countDown();
            assertTrue(release.await(30, TimeUnit.SECONDS));
            return invocation.callRealMethod();
        }).when(auditLogService).verifyChain();

        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<MvcResult> first = executor.submit(() ->
                    mockMvc.perform(post("/audit/verify").with(authentication(auth(auditor))).with(csrf())).andReturn());
            assertTrue(started.await(30, TimeUnit.SECONDS));

            mockMvc.perform(post("/audit/verify").with(authentication(auth(auditor))).with(csrf()))
                    .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/audit"))
                    .andExpect(flash().attribute("verifyBusy",
                            "A verification is already running. Please wait for it to finish and reload the page."));
            assertEquals(0, count("AUDIT_CHAIN_VERIFIED"), "nothing is recorded while the first run is still going");

            release.countDown();
            assertEquals(302, first.get(30, TimeUnit.SECONDS).getResponse().getStatus());
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
        assertEquals(1, count("AUDIT_CHAIN_VERIFIED"));
        Mockito.verify(auditLogService, Mockito.times(1)).verifyChain();
        // The lock is released afterwards: a later verification runs normally.
        Mockito.reset(auditLogService);
        mockMvc.perform(post("/audit/verify").with(authentication(auth(auditor))).with(csrf()))
                .andExpect(status().is3xxRedirection());
        assertEquals(2, count("AUDIT_CHAIN_VERIFIED"));
    }

    // ---- templates and headers ----

    @Test
    @DisplayName("SEC-AUDIT-UI-14: audit template has no th:utext, inline script, style or handler; CSP stays strict")
    void templateAndHeaders() throws Exception {
        Path template = Paths.get("src/main/resources/templates/audit/list.html");
        assertTrue(Files.exists(template));
        Pattern forbidden = Pattern.compile(
                "th:utext|innerHTML|javascript:|<script|style=|\\son[a-z]+\\s*=", Pattern.CASE_INSENSITIVE);
        try (Stream<String> lines = Files.lines(template)) {
            lines.forEach(line -> assertFalse(forbidden.matcher(line).find(), "forbidden pattern: " + line.trim()));
        }
        String csp = getAudit("").getResponse().getHeader("Content-Security-Policy");
        assertNotNull(csp);
        assertFalse(csp.contains("unsafe-inline"));
        assertTrue(csp.contains("default-src 'self'"));
        assertEquals("nosniff", getAudit("").getResponse().getHeader("X-Content-Type-Options"));
    }
}
