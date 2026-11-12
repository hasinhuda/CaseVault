package com.casevault.admin;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AdminUserService;
import com.casevault.service.AuditLogService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Phase 7B: admin pages over HTTP (real filter chain, real logins, H2, chained audit log). */
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
// Phase 8A: this class performs many real logins from one address; the login limiter keeps its default
// behaviour but with a higher limit so the unrelated scenarios below are not throttled.
@org.springframework.test.context.TestPropertySource(properties = "casevault.ratelimit.login-limit=100000")
class AdminHttpTest {

    private static final String PASSWORD = "Admin-Test-Password-1234!";

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
    private AuditLogService auditLogService;
    @Autowired
    private AdminUserService adminUserService;

    private User admin1;
    private User admin2;
    private User client;
    private User analyst;
    private User manager;
    private User victim;
    private String suffix;
    private final List<String> disabledForTest = new ArrayList<>();
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
        Organisation org = organisationRepository.save(
                new Organisation(UUID.randomUUID().toString(), "Adm " + suffix, "ADM_" + suffix, now));
        String hash = passwordEncoder.encode(PASSWORD);
        admin1 = user("adm_one_" + suffix, internal, Role.AUDITOR_ADMIN, hash);
        admin2 = user("adm_two_" + suffix, internal, Role.AUDITOR_ADMIN, hash);
        client = user("adm_cl_" + suffix, org, Role.CLIENT, hash);
        analyst = user("adm_an_" + suffix, internal, Role.ANALYST, hash);
        manager = user("adm_mg_" + suffix, internal, Role.MANAGER, hash);
        victim = user("adm_vi_" + suffix, org, Role.CLIENT, hash);
        // Other test classes (and the bootstrap) may have left active admins in the shared in-memory database.
        // Disable them for this test so "last active admin" is deterministic; they are restored afterwards.
        disabledForTest.clear();
        disabledForTest.addAll(jdbc.queryForList(
                "SELECT id FROM users WHERE role = 'AUDITOR_ADMIN' AND enabled = TRUE AND id NOT IN (?, ?)",
                String.class, admin1.getId(), admin2.getId()));
        for (String id : disabledForTest) {
            jdbc.update("UPDATE users SET enabled = FALSE WHERE id = ?", id);
        }
        jdbc.update("DELETE FROM audit_events");
    }

    @AfterEach
    void tearDown() {
        for (String id : disabledForTest) {
            jdbc.update("UPDATE users SET enabled = TRUE WHERE id = ?", id);
        }
        jdbc.update("DELETE FROM users WHERE username LIKE 'zzpg_%'");
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

    private MockHttpSession login(User u) throws Exception {
        MvcResult result = mockMvc.perform(post("/login").with(csrf())
                .param("username", u.getUsername()).param("password", PASSWORD)).andReturn();
        assertEquals(302, result.getResponse().getStatus());
        assertTrue(result.getResponse().getRedirectedUrl().endsWith("/dashboard"), "login must succeed for " + u.getUsername());
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    private boolean enabled(User u) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT enabled FROM users WHERE id = ?", Boolean.class, u.getId()));
    }

    private List<Row> adminRows() {
        return jdbc.query("SELECT event_type, CAST(user_id AS VARCHAR), CAST(case_id AS VARCHAR), reason_code "
                        + "FROM audit_events WHERE event_type LIKE 'ADMIN_%' OR reason_code = 'ADMIN_REFUSED' ORDER BY sequence_no",
                (rs, i) -> new Row(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)));
    }

    // ---- health (first: the last verification is kept in memory for the whole context) ----

    @Test
    @Order(1)
    @DisplayName("SEC-ADMIN-01: health page shows DB and storage as reachable, \"Not verified yet\" before any verification, and leaks no path, version, host or exception text")
    void healthBeforeVerification() throws Exception {
        auditLogService.append(com.casevault.service.AuditEventType.LOGIN_SUCCESS, UUID.randomUUID(), null, "SUCCESS");
        String body = mockMvc.perform(get("/admin/health").with(authentication(auth(admin1))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()
                // The random CSRF token in the sign-out form could contain any letters (for example "H2").
                .replaceAll("<input type=\"hidden\"[^>]*>", "");
        assertTrue(body.contains("Not verified yet"));
        assertTrue(body.contains("Database reachable"));
        assertTrue(body.contains("Evidence storage writable"));
        assertTrue(body.contains("Audit head sequence"));
        assertFalse(body.contains("No</span>"), "both checks pass in the test environment");
        for (String forbidden : List.of(sharedTempDir.toString(), sharedTempDir.getFileName().toString(), ".local-data",
                "jdbc", "H2", "PostgreSQL", "postgres", "Exception", "at com.", "java.", "Spring", "localhost",
                "password", "secret", "keyset", "audit.key", "\\Users", "/Users", "Caused by")) {
            assertFalse(body.contains(forbidden), "health page must not contain: " + forbidden);
        }
    }

    @Test
    @Order(2)
    @DisplayName("SEC-ADMIN-02: health reflects an earlier verification and does not verify on page load")
    void healthReflectsEarlierVerification() throws Exception {
        auditLogService.append(com.casevault.service.AuditEventType.LOGIN_SUCCESS, UUID.randomUUID(), null, "SUCCESS");
        mockMvc.perform(post("/audit/verify").with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection());
        String valid = mockMvc.perform(get("/admin/health").with(authentication(auth(admin1))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(valid.contains("Chain valid"));

        // Tamper after the verification: the page must still show the last result (it never re-verifies).
        jdbc.update("UPDATE audit_events SET reason_code = 'CREATED' WHERE sequence_no = 1");
        String stillValid = mockMvc.perform(get("/admin/health").with(authentication(auth(admin1))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(stillValid.contains("Chain valid"));
        assertFalse(stillValid.contains("BROKEN"));

        mockMvc.perform(post("/audit/verify").with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection());
        String broken = mockMvc.perform(get("/admin/health").with(authentication(auth(admin1))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(broken.contains("Chain BROKEN at sequence 1"));
    }

    // ---- access ----

    @Test
    @DisplayName("SEC-ADMIN-03: role matrix over HTTP: AUDITOR_ADMIN works; CLIENT, ANALYST, MANAGER get 404 on every admin route and POST, without any state change")
    void roleMatrix() throws Exception {
        String id = victim.getId();
        for (User denied : List.of(client, analyst, manager)) {
            mockMvc.perform(get("/admin/users").with(authentication(auth(denied)))).andExpect(status().isNotFound());
            mockMvc.perform(get("/admin/health").with(authentication(auth(denied)))).andExpect(status().isNotFound());
            mockMvc.perform(get("/admin/users/{id}/disable-confirm", id).with(authentication(auth(denied))))
                    .andExpect(status().isNotFound());
            for (String action : List.of("disable", "enable", "revoke-sessions")) {
                mockMvc.perform(post("/admin/users/{id}/" + action, id).with(authentication(auth(denied))).with(csrf()))
                        .andExpect(status().isNotFound());
            }
        }
        assertTrue(enabled(victim));
        assertEquals(List.of(), adminRows().stream().filter(r -> r.type().startsWith("ADMIN_")).toList());

        mockMvc.perform(get("/admin/users").with(authentication(auth(admin1)))).andExpect(status().isOk());
        mockMvc.perform(get("/admin/health").with(authentication(auth(admin1)))).andExpect(status().isOk());
        mockMvc.perform(get("/admin/users/{id}/disable-confirm", id).with(authentication(auth(admin1))))
                .andExpect(status().isOk());
        mockMvc.perform(post("/admin/users/{id}/revoke-sessions", id).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/admin/users"));
        mockMvc.perform(post("/admin/users/{id}/disable", id).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/admin/users"));
        mockMvc.perform(post("/admin/users/{id}/enable", id).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/admin/users"));
        assertTrue(enabled(victim));
    }

    @Test
    @DisplayName("SEC-ADMIN-04: unauthenticated requests behave like /cases; every POST without a CSRF token is 403, also for the admin")
    void unauthenticatedAndCsrf() throws Exception {
        int casesStatus = mockMvc.perform(get("/cases")).andReturn().getResponse().getStatus();
        for (String path : List.of("/admin/users", "/admin/health", "/admin/users/" + victim.getId() + "/disable-confirm")) {
            assertEquals(casesStatus, mockMvc.perform(get(path)).andReturn().getResponse().getStatus(), path);
        }
        for (String action : List.of("disable", "enable", "revoke-sessions")) {
            String path = "/admin/users/" + victim.getId() + "/" + action;
            assertEquals(casesStatus, mockMvc.perform(post(path).with(csrf())).andReturn().getResponse().getStatus(), path);
            mockMvc.perform(post(path)).andExpect(status().isForbidden());
            mockMvc.perform(post(path).with(authentication(auth(admin1)))).andExpect(status().isForbidden());
        }
        assertTrue(enabled(victim));
        assertEquals(List.of(), adminRows());
    }

    @Test
    @DisplayName("SEC-ADMIN-05: \"Users\" and \"Health\" links appear only for the auditor; the admin pages carry CSRF tokens and no script")
    void navigationLinks() throws Exception {
        for (User other : List.of(client, analyst, manager)) {
            String body = mockMvc.perform(get("/dashboard").with(authentication(auth(other))))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
            assertFalse(body.contains("/admin/"), "no admin link for " + other.getRole());
        }
        String dashboard = mockMvc.perform(get("/dashboard").with(authentication(auth(admin1))))
                .andReturn().getResponse().getContentAsString();
        assertTrue(dashboard.contains("href=\"/admin/users\""));
        assertTrue(dashboard.contains("href=\"/admin/health\""));
        String users = mockMvc.perform(get("/admin/users").with(authentication(auth(admin1))))
                .andReturn().getResponse().getContentAsString();
        assertTrue(users.contains("href=\"/admin/users\"") && users.contains("href=\"/admin/health\""));
        assertTrue(users.contains("name=\"_csrf\""));
        assertTrue(users.contains("class=\"skip-link\""));
        assertFalse(users.contains("<script"));
        String confirm = mockMvc.perform(get("/admin/users/{id}/disable-confirm", victim.getId())
                .with(authentication(auth(admin1)))).andReturn().getResponse().getContentAsString();
        assertTrue(confirm.contains("name=\"_csrf\"") && confirm.contains("Confirm disable"));
    }

    // ---- safety rules ----

    @Test
    @DisplayName("SEC-ADMIN-06: an admin cannot disable himself or revoke his own sessions; nothing changes, the refusal is audited as ACCESS_DENIED / ADMIN_REFUSED")
    void selfActionsBlocked() throws Exception {
        MockHttpSession session = login(admin1);
        mockMvc.perform(post("/admin/users/{id}/disable", admin1.getId()).session(session).with(csrf()))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("errorMessage", "You cannot disable your own account."));
        mockMvc.perform(post("/admin/users/{id}/revoke-sessions", admin1.getId()).session(session).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("errorMessage", "You cannot revoke your own sessions with this action."));
        assertTrue(enabled(admin1));
        mockMvc.perform(get("/admin/users").session(session)).andExpect(status().isOk());
        assertEquals(List.of(
                new Row("ACCESS_DENIED", admin1.getId(), null, "ADMIN_REFUSED"),
                new Row("ACCESS_DENIED", admin1.getId(), null, "ADMIN_REFUSED")), adminRows());
    }

    @Test
    @DisplayName("SEC-ADMIN-07: after one admin disabled the other, the disabled admin cannot act any more; the remaining admin stays enabled")
    void lastAdminProtected() throws Exception {
        mockMvc.perform(post("/admin/users/{id}/disable", admin2.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/admin/users"));
        assertFalse(enabled(admin2));
        // admin2 still holds a valid-looking principal: the next request is rejected by the status filter.
        MvcResult stale = mockMvc.perform(post("/admin/users/{id}/disable", admin1.getId())
                .with(authentication(auth(admin2))).with(csrf())).andReturn();
        assertEquals(302, stale.getResponse().getStatus());
        assertTrue(stale.getResponse().getRedirectedUrl().contains("/login"));
        assertTrue(enabled(admin1));
        assertEquals(1L, jdbc.queryForObject("SELECT COUNT(*) FROM users WHERE role = 'AUDITOR_ADMIN' AND enabled = TRUE", Long.class));
        // The service also refuses a disabled actor on its own (defence in depth, no filter involved).
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> adminUserService.disable(new CaseVaultUserPrincipal(admin2, Instant.now()), admin1.getId()));
        assertTrue(enabled(admin1));
    }

    @Test
    @DisplayName("SEC-ADMIN-08: two admins disabling each other at the same moment never leave zero active admins (repeated)")
    void concurrentDoubleDisable() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            for (int round = 0; round < 8; round++) {
                jdbc.update("UPDATE users SET enabled = TRUE WHERE id IN (?, ?)", admin1.getId(), admin2.getId());
                CountDownLatch go = new CountDownLatch(1);
                Future<Integer> a = executor.submit(() -> disableConcurrently(go, admin1, admin2));
                Future<Integer> b = executor.submit(() -> disableConcurrently(go, admin2, admin1));
                go.countDown();
                int statusA = a.get(60, TimeUnit.SECONDS);
                int statusB = b.get(60, TimeUnit.SECONDS);
                assertTrue(statusA < 500 && statusB < 500, "no server error in round " + round);
                long active = jdbc.queryForObject("SELECT COUNT(*) FROM users WHERE id IN (?, ?) AND enabled = TRUE",
                        Long.class, admin1.getId(), admin2.getId());
                assertEquals(1L, active, "exactly one of the two admins stays active in round " + round);
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private int disableConcurrently(CountDownLatch go, User actor, User target) throws Exception {
        go.await();
        return mockMvc.perform(post("/admin/users/{id}/disable", target.getId())
                .with(authentication(auth(actor))).with(csrf())).andReturn().getResponse().getStatus();
    }

    // ---- sessions ----

    @Test
    @DisplayName("SEC-ADMIN-09: a disabled user cannot log in; after enabling, login works again")
    void disabledUserCannotLogin() throws Exception {
        mockMvc.perform(post("/admin/users/{id}/disable", victim.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection());
        assertFalse(enabled(victim));
        MvcResult denied = mockMvc.perform(post("/login").with(csrf())
                .param("username", victim.getUsername()).param("password", PASSWORD)).andReturn();
        assertEquals(302, denied.getResponse().getStatus());
        assertTrue(denied.getResponse().getRedirectedUrl().contains("/login?error"));

        mockMvc.perform(post("/admin/users/{id}/enable", victim.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection());
        login(victim);
    }

    @Test
    @DisplayName("SEC-ADMIN-10: a logged-in session of a user dies on the next request after an admin disables the account (browser and API)")
    void sessionDiesAfterDisable() throws Exception {
        MockHttpSession victimSession = login(victim);
        mockMvc.perform(get("/dashboard").session(victimSession)).andExpect(status().isOk());

        MockHttpSession adminSession = login(admin1);
        mockMvc.perform(post("/admin/users/{id}/disable", victim.getId()).session(adminSession).with(csrf()))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/admin/users"));

        MvcResult next = mockMvc.perform(get("/dashboard").session(victimSession)).andReturn();
        assertEquals(302, next.getResponse().getStatus());
        assertTrue(next.getResponse().getRedirectedUrl().contains("/login"));
        assertEquals(401, mockMvc.perform(get("/api/cases").session(victimSession)).andReturn().getResponse().getStatus());
        // The admin's own session is unaffected.
        mockMvc.perform(get("/admin/users").session(adminSession)).andExpect(status().isOk());
    }

    @Test
    @DisplayName("SEC-ADMIN-11: revoke-sessions: the user's existing session is rejected on the next request, the account stays enabled and can log in again")
    void revokeSessions() throws Exception {
        MockHttpSession victimSession = login(victim);
        MockHttpSession secondSession = login(victim);
        mockMvc.perform(get("/dashboard").session(victimSession)).andExpect(status().isOk());

        MockHttpSession adminSession = login(admin1);
        mockMvc.perform(post("/admin/users/{id}/revoke-sessions", victim.getId()).session(adminSession).with(csrf()))
                .andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("successMessage", "Sessions revoked. The user must sign in again."));

        for (MockHttpSession dead : List.of(victimSession, secondSession)) {
            MvcResult next = mockMvc.perform(get("/dashboard").session(dead)).andReturn();
            assertEquals(302, next.getResponse().getStatus());
            assertTrue(next.getResponse().getRedirectedUrl().contains("/login?expired"), next.getResponse().getRedirectedUrl());
        }
        assertTrue(enabled(victim));
        MockHttpSession again = login(victim);
        mockMvc.perform(get("/dashboard").session(again)).andExpect(status().isOk());
        mockMvc.perform(get("/admin/users").session(adminSession)).andExpect(status().isOk());
    }

    // ---- list, ids, content boundary ----

    @Test
    @DisplayName("SEC-ADMIN-12: the user list shows status, never password hashes, session ids or case data; admin still has no case content access")
    void listContent() throws Exception {
        Organisation org = organisationRepository.findByCode("ADM_" + suffix).orElseThrow();
        String caseTitle = "Hidden-Case-Title-" + suffix;
        Case c = caseRepository.save(new Case(UUID.randomUUID().toString(), org, caseTitle, "RANSOMWARE", "HIGH",
                "OPEN", client, null, Instant.now()));
        jdbc.update("UPDATE users SET enabled = FALSE WHERE id = ?", victim.getId());
        MockHttpSession session = login(admin1);
        // The shared test database holds many users: ask for the page that contains the victim (sorted by username).
        long before = jdbc.queryForObject("SELECT COUNT(*) FROM users WHERE username < ?", Long.class, victim.getUsername());
        String body = mockMvc.perform(get("/admin/users?size=50&page=" + (before / 50)).session(session))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(body.contains(victim.getUsername()));
        assertTrue(body.contains("Disabled") && body.contains("Enabled"), "status is shown as text");
        String hash = jdbc.queryForObject("SELECT password_hash FROM users WHERE id = ?", String.class, admin1.getId());
        assertFalse(body.contains(hash));
        assertFalse(body.contains("argon2"));
        // MockHttpSession ids are short counters that match any digit, so only a long id is meaningful to look for.
        if (session.getId().length() >= 16) {
            assertFalse(body.contains(session.getId()));
        }
        assertFalse(body.contains("JSESSIONID"));
        assertFalse(body.contains(caseTitle));
        assertFalse(body.toLowerCase().contains("password_hash") || body.contains("failedLogin"));
        mockMvc.perform(get("/cases/{id}", c.getId()).session(session)).andExpect(status().isNotFound());
        mockMvc.perform(get("/api/cases/{id}", c.getId()).session(session)).andExpect(status().isNotFound());
        mockMvc.perform(get("/cases").session(session)).andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("SEC-ADMIN-13: paging: size capped at 50, bad page values safe, sort parameter ignored (username order); unknown or malformed ids are 404")
    void pagingAndIds() throws Exception {
        Organisation org = organisationRepository.findByCode("ADM_" + suffix).orElseThrow();
        String hash = passwordEncoder.encode(PASSWORD);
        for (int i = 0; i < 55; i++) {
            user(String.format("zzpg_%02d_%s", i, suffix), org, Role.CLIENT, hash);
        }
        String body = mockMvc.perform(get("/admin/users?size=1000").with(authentication(auth(admin1))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertEquals(50, countOccurrences(body, "<td>CLIENT</td>") + countOccurrences(body, "<td>ANALYST</td>")
                + countOccurrences(body, "<td>MANAGER</td>") + countOccurrences(body, "<td>AUDITOR_ADMIN</td>"),
                "a page has at most 50 rows");
        for (String query : List.of("?page=-1", "?page=abc", "?page=99999999999999999999", "?size=0", "?size=-4", "?size=x",
                "?page=999999", "?sort=password_hash,desc", "?sort=" + "'%3B%20DROP%20TABLE%20users")) {
            mockMvc.perform(get("/admin/users" + query).with(authentication(auth(admin1)))).andExpect(status().isOk());
        }
        String sorted = mockMvc.perform(get("/admin/users?sort=role,desc&size=50").with(authentication(auth(admin1))))
                .andReturn().getResponse().getContentAsString();
        List<String> names = new ArrayList<>();
        var matcher = Pattern.compile("<td>([^<]+)</td>\\s*<td>(?:CLIENT|ANALYST|MANAGER|AUDITOR_ADMIN)</td>").matcher(sorted);
        while (matcher.find()) {
            names.add(matcher.group(1));
        }
        assertFalse(names.isEmpty());
        List<String> expected = new ArrayList<>(names);
        expected.sort(null);
        assertEquals(expected, names, "fixed sort by username");

        String unknown = UUID.randomUUID().toString();
        for (String bad : List.of(unknown, "not-a-uuid", "1' OR '1'='1", "00000000-0000-0000-0000-000000000000")) {
            mockMvc.perform(get("/admin/users/{id}/disable-confirm", bad).with(authentication(auth(admin1))))
                    .andExpect(status().isNotFound());
            for (String action : List.of("disable", "enable", "revoke-sessions")) {
                mockMvc.perform(post("/admin/users/{id}/" + action, bad).with(authentication(auth(admin1))).with(csrf()))
                        .andExpect(status().isNotFound());
            }
        }
        assertEquals(List.of(), adminRows());
    }

    private static int countOccurrences(String text, String part) {
        int count = 0;
        for (int i = text.indexOf(part); i >= 0; i = text.indexOf(part, i + part.length())) {
            count++;
        }
        return count;
    }

    // ---- audit ----

    @Test
    @DisplayName("SEC-ADMIN-14: one audit row per action with the acting admin's UUID; no-ops and refusals as documented; target traceable via users.status_changed_*; no username, password or session id in rows or logs; chain valid")
    void auditTrail() throws Exception {
        MockHttpSession adminSession = login(admin1);
        MockHttpSession victimSession = login(victim);
        String adminId = admin1.getId();

        mockMvc.perform(post("/admin/users/{id}/disable", victim.getId()).session(adminSession).with(csrf()));
        mockMvc.perform(post("/admin/users/{id}/disable", victim.getId()).session(adminSession).with(csrf()))
                .andExpect(flash().attribute("successMessage", "The account was already disabled."));
        mockMvc.perform(post("/admin/users/{id}/enable", victim.getId()).session(adminSession).with(csrf()));
        mockMvc.perform(post("/admin/users/{id}/enable", victim.getId()).session(adminSession).with(csrf()))
                .andExpect(flash().attribute("successMessage", "The account was already enabled."));
        mockMvc.perform(post("/admin/users/{id}/revoke-sessions", victim.getId()).session(adminSession).with(csrf()));
        mockMvc.perform(post("/admin/users/{id}/disable", adminId).session(adminSession).with(csrf()));

        assertEquals(List.of(
                new Row("ADMIN_ACCOUNT_DISABLED", adminId, null, "DISABLED_BY_ADMIN"),
                new Row("ADMIN_ACCOUNT_ENABLED", adminId, null, "ENABLED_BY_ADMIN"),
                new Row("ADMIN_SESSION_REVOKED", adminId, null, "SESSIONS_REVOKED"),
                new Row("ACCESS_DENIED", adminId, null, "ADMIN_REFUSED")), adminRows());

        var trace = jdbc.queryForMap("SELECT status_changed_by, status_changed_at FROM users WHERE id = ?", victim.getId());
        assertEquals(adminId, trace.get("STATUS_CHANGED_BY"));
        assertNotNull(trace.get("STATUS_CHANGED_AT"));
        var untouched = jdbc.queryForMap("SELECT status_changed_by, status_changed_at FROM users WHERE id = ?", client.getId());
        assertNull(untouched.get("STATUS_CHANGED_BY"));

        String everything = String.join("|", jdbc.query("SELECT CAST(id AS VARCHAR), event_type, CAST(user_id AS VARCHAR), "
                        + "CAST(case_id AS VARCHAR), reason_code, CAST(occurred_at AS VARCHAR), prev_hash, hmac FROM audit_events",
                (rs, i) -> rs.getString(1) + rs.getString(2) + rs.getString(3) + rs.getString(4) + rs.getString(5)
                        + rs.getString(6) + rs.getString(7) + rs.getString(8)));
        StringBuilder logText = new StringBuilder();
        for (ILoggingEvent event : logs.list) {
            logText.append(event.getFormattedMessage()).append('\n');
        }
        List<String> secrets = new ArrayList<>(List.of(victim.getUsername(), admin1.getUsername(), PASSWORD));
        if (victimSession.getId().length() >= 16) {
            secrets.add(victimSession.getId());
        }
        if (adminSession.getId().length() >= 16) {
            secrets.add(adminSession.getId());
        }
        for (String secret : secrets) {
            assertFalse(everything.contains(secret), "audit rows must not contain: " + secret);
            assertFalse(logText.toString().contains(secret), "log lines must not contain: " + secret);
        }
        assertTrue(auditLogService.verifyChain().valid());
    }

    // ---- templates ----

    @Test
    @DisplayName("SEC-ADMIN-15: admin templates have no th:utext, inline script, style or handler")
    void templatesAreClean() throws Exception {
        Path dir = Paths.get("src/main/resources/templates/admin");
        Pattern forbidden = Pattern.compile("th:utext|innerHTML|javascript:|<script|style=|\\son[a-z]+\\s*=", Pattern.CASE_INSENSITIVE);
        try (Stream<Path> files = Files.list(dir)) {
            List<Path> templates = files.filter(p -> p.toString().endsWith(".html")).toList();
            assertEquals(3, templates.size());
            for (Path template : templates) {
                for (String line : Files.readAllLines(template)) {
                    assertFalse(forbidden.matcher(line).find(), template.getFileName() + ": " + line.trim());
                }
            }
        }
    }
}
