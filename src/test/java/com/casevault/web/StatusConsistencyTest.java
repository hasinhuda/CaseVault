package com.casevault.web;

import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 8B, 404-or-403 consistency over HTTP with real logins and the real filter chain.
 *
 * <p>The policy that the existing Phase 3/4 tests pin (SEC-AUTHZ-10, SEC-CASE-02, SEC-CASE-xx notes/actions/assign,
 * SEC-AUDIT-WIRE-08) and that these tests assert:
 * <ul>
 *   <li>an object the caller may not see (other tenant, unassigned analyst, auditor on case or evidence endpoints)
 *       is HTTP 404 and audited once as ACCESS_DENIED / NOT_VISIBLE (when a service lookup masks it);</li>
 *   <li>an action the caller is not allowed to perform on an object they CAN see is HTTP 403 and audited once as
 *       ACCESS_DENIED / NOT_PERMITTED;</li>
 *   <li>a missing or invalid CSRF token is 403 (documented exception); unauthenticated requests keep the
 *       existing redirect or 401.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "casevault.ratelimit.login-limit=100000")
class StatusConsistencyTest {

    private static final String PASSWORD = "Status-Consistency-1234!";

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

    private User clientA;
    private User clientB;
    private User analyst;
    private User analystOther;
    private User manager;
    private User managerB;
    private User auditor;
    private Case caseA;
    private final List<MockHttpSession> unused = new ArrayList<>();
    private final java.util.Map<String, MockHttpSession> sessions = new java.util.HashMap<>();

    @BeforeEach
    void setUp() {
        sessions.clear();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        Organisation internal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(
                        new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        Organisation orgA = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "SC A " + suffix, "SC_A_" + suffix, now));
        Organisation orgB = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "SC B " + suffix, "SC_B_" + suffix, now));
        String hash = passwordEncoder.encode(PASSWORD);
        clientA = user("sc_ca_" + suffix, orgA, Role.CLIENT, hash);
        clientB = user("sc_cb_" + suffix, orgB, Role.CLIENT, hash);
        analyst = user("sc_an_" + suffix, internal, Role.ANALYST, hash);
        analystOther = user("sc_ao_" + suffix, internal, Role.ANALYST, hash);
        manager = user("sc_mg_" + suffix, internal, Role.MANAGER, hash);
        managerB = user("sc_mb_" + suffix, orgB, Role.MANAGER, hash);
        auditor = user("sc_au_" + suffix, internal, Role.AUDITOR_ADMIN, hash);
        caseA = caseRepository.save(new Case(UUID.randomUUID().toString(), orgA, "SC case A " + suffix,
                "RANSOMWARE", "HIGH", "OPEN", clientA, analyst, now));
    }

    private User user(String name, Organisation org, Role role, String hash) {
        return userRepository.save(new User(UUID.randomUUID().toString(), org, name, hash, role,
                name + "@test.local", true, Instant.now()));
    }

    private MockHttpSession as(User u) throws Exception {
        MockHttpSession existing = sessions.get(u.getId());
        if (existing != null) {
            return existing;
        }
        MvcResult result = mockMvc.perform(post("/login").with(csrf())
                .param("username", u.getUsername()).param("password", PASSWORD)).andReturn();
        assertEquals(302, result.getResponse().getStatus());
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        sessions.put(u.getId(), session);
        return session;
    }

    private enum Denial { NONE, NOT_VISIBLE, NOT_PERMITTED, NOT_VISIBLE_UNAUDITED }

    private Executable probe(String label, User actor, MockHttpServletRequestBuilder request, int expectedStatus, int expectedDenials,
                             String expectedReason) {
        return () -> {
            as(actor);
            jdbc.update("DELETE FROM audit_events WHERE event_type = 'ACCESS_DENIED'");
            MvcResult result = mockMvc.perform(request.session(as(actor))).andReturn();
            assertEquals(expectedStatus, result.getResponse().getStatus(), label + ": status");
            List<String> reasons = jdbc.queryForList("SELECT reason_code FROM audit_events WHERE event_type = 'ACCESS_DENIED'", String.class);
            assertEquals(expectedDenials, reasons.size(), label + ": ACCESS_DENIED rows " + reasons);
            if (expectedDenials == 1) {
                assertEquals(expectedReason, reasons.get(0), label + ": reason");
            }
        };
    }

    private MockHttpServletRequestBuilder form(String path, String... params) {
        MockHttpServletRequestBuilder request = post(path).with(csrf());
        for (int i = 0; i + 1 < params.length; i += 2) {
            request.param(params[i], params[i + 1]);
        }
        return request;
    }

    @Test
    @DisplayName("SEC-HDR-404-01: objects the caller may not see are 404 (audited once as NOT_VISIBLE); actions forbidden on a visible case are 403 (audited once as NOT_PERMITTED); the documented Phase 3 policy over HTTP")
    void statusPolicyForCaseOperations() throws Exception {
        String a = caseA.getId();
        List<Executable> checks = new ArrayList<>();

        // Notes, remediation actions and status changes
        checks.add(probe("client of the case adds a note", clientA, form("/cases/" + a + "/notes", "body", "x"), 403, 1, "NOT_PERMITTED"));
        checks.add(probe("other tenant adds a note", clientB, form("/cases/" + a + "/notes", "body", "x"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("unassigned analyst adds a note", analystOther, form("/cases/" + a + "/notes", "body", "x"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("auditor adds a note", auditor, form("/cases/" + a + "/notes", "body", "x"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("client of the case adds an action", clientA, form("/cases/" + a + "/actions", "description", "x"), 403, 1, "NOT_PERMITTED"));
        checks.add(probe("other tenant adds an action", clientB, form("/cases/" + a + "/actions", "description", "x"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("unassigned analyst adds an action", analystOther, form("/cases/" + a + "/actions", "description", "x"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("auditor adds an action", auditor, form("/cases/" + a + "/actions", "description", "x"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("client of the case changes the status", clientA, form("/cases/" + a + "/status", "status", "IN_PROGRESS"), 403, 1, "NOT_PERMITTED"));
        checks.add(probe("other tenant changes the status", clientB, form("/cases/" + a + "/status", "status", "IN_PROGRESS"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("manager of another tenant changes the status", managerB, form("/cases/" + a + "/status", "status", "IN_PROGRESS"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("unassigned analyst changes the status", analystOther, form("/cases/" + a + "/status", "status", "IN_PROGRESS"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("auditor changes the status", auditor, form("/cases/" + a + "/status", "status", "IN_PROGRESS"), 404, 1, "NOT_VISIBLE"));

        // Reading
        checks.add(probe("other tenant reads the case", clientB, get("/cases/" + a), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("unassigned analyst reads the case", analystOther, get("/cases/" + a), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("manager of another tenant reads the case", managerB, get("/cases/" + a), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("auditor reads the case", auditor, get("/cases/" + a), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("auditor opens the case list", auditor, get("/cases"), 404, 0, null));
        checks.add(probe("unknown case id", clientA, get("/cases/" + UUID.randomUUID()), 404, 0, null));

        // Evidence
        MockMultipartFile file = new MockMultipartFile("file", "sc.txt", "text/plain", "synthetic".getBytes(StandardCharsets.UTF_8));
        for (User denied : List.of(clientB, analystOther, manager, auditor)) {
            checks.add(probe("evidence upload by " + denied.getRole(), denied,
                    multipart("/cases/" + a + "/evidence").file(file).with(csrf()), 404, 1, "NOT_VISIBLE"));
        }

        // Creating a case
        checks.add(probe("analyst creates a case", analyst, form("/cases", "title", "x", "category", "RANSOMWARE", "severity", "HIGH"), 403, 1, "NOT_PERMITTED"));
        checks.add(probe("manager creates a case", manager, form("/cases", "title", "x", "category", "RANSOMWARE", "severity", "HIGH"), 403, 1, "NOT_PERMITTED"));
        checks.add(probe("auditor creates a case", auditor, form("/cases", "title", "x", "category", "RANSOMWARE", "severity", "HIGH"), 404, 0, null));

        // Reports and admin pages (7A/7B/7C policy: always 404)
        checks.add(probe("auditor opens the report list", auditor, get("/cases/" + a + "/reports"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("other tenant opens the report list", clientB, get("/cases/" + a + "/reports"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("client opens the admin users page", clientA, get("/admin/users"), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("manager opens the audit log", manager, get("/audit"), 404, 1, "NOT_VISIBLE"));
        assertAll(checks);
    }

    @Test
    @DisplayName("SEC-HDR-404-02: assigning an analyst: a non-manager who can see the case gets 403 (audited once); the auditor, another tenant and a manager of another tenant get 404 (audited once)")
    void assignPolicy() throws Exception {
        String a = caseA.getId();
        List<Executable> checks = new ArrayList<>();
        checks.add(probe("client assigns", clientA, form("/cases/" + a + "/assign", "analystId", analyst.getId()), 403, 1, "NOT_PERMITTED"));
        checks.add(probe("analyst assigns", analyst, form("/cases/" + a + "/assign", "analystId", analyst.getId()), 403, 1, "NOT_PERMITTED"));
        checks.add(probe("auditor assigns", auditor, form("/cases/" + a + "/assign", "analystId", analyst.getId()), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("other tenant client assigns", clientB, form("/cases/" + a + "/assign", "analystId", analyst.getId()), 404, 1, "NOT_VISIBLE"));
        checks.add(probe("manager of another tenant assigns", managerB, form("/cases/" + a + "/assign", "analystId", analyst.getId()), 404, 1, "NOT_VISIBLE"));
        assertAll(checks);
    }

    @Test
    @DisplayName("SEC-HDR-404-03: CSRF failures stay 403 for every state-changing route, no matter the role; unauthenticated requests keep the existing redirect or 401")
    void csrfAndUnauthenticated() throws Exception {
        String a = caseA.getId();
        for (String path : List.of("/cases/" + a + "/notes", "/cases/" + a + "/actions", "/cases/" + a + "/status",
                "/cases/" + a + "/assign", "/cases/" + a + "/reports", "/cases", "/admin/users/" + clientA.getId() + "/disable")) {
            for (User actor : List.of(clientA, analyst, manager, auditor)) {
                assertEquals(403, mockMvc.perform(post(path).session(as(actor)).param("body", "x")).andReturn().getResponse().getStatus(),
                        "no CSRF token, " + actor.getRole() + ", " + path);
                assertEquals(403, mockMvc.perform(post(path).session(as(actor)).param("_csrf", "forged-token").param("body", "x"))
                        .andReturn().getResponse().getStatus(), "forged CSRF token, " + actor.getRole() + ", " + path);
            }
        }
        int expected = mockMvc.perform(get("/cases")).andReturn().getResponse().getStatus();
        assertEquals(401, expected, "unauthenticated generic client: existing 401");
        MvcResult browser = mockMvc.perform(get("/cases/" + a).accept("text/html")).andReturn();
        assertEquals(302, browser.getResponse().getStatus());
        assertEquals(true, browser.getResponse().getRedirectedUrl().endsWith("/login"));
        assertEquals(302, mockMvc.perform(post("/cases/" + a + "/notes").with(csrf()).accept("text/html")).andReturn().getResponse().getStatus());
    }
}
