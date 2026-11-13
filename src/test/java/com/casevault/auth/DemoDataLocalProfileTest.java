package com.casevault.auth;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.exception.AdminActionRefusedException;
import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.security.PasswordPolicyValidator;
import com.casevault.service.AdminUserService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Phase 9E: the demo data of the LOCAL profile (second client organisation with a user and a case, second
 * administrator). The class has its own in-memory database so the first start really runs the bootstrap.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("local")
@TestPropertySource(properties = {
        "casevault.ratelimit.login-limit=100000",
        "spring.datasource.url=jdbc:h2:mem:casevault_demo_local_test;DB_CLOSE_DELAY=-1"
})
class DemoDataLocalProfileTest {

    @TempDir
    static Path sharedTempDir;

    /** Collects every log line from before the context starts (the bootstrap runs at start-up). */
    private static final ListAppender<ILoggingEvent> LOGS = new ListAppender<>();

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        if (!LOGS.isStarted()) {
            LOGS.start();
            ((Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME)).addAppender(LOGS);
        }
        registry.add("casevault.audit.key-path", () -> sharedTempDir.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
        registry.add("casevault.bootstrap.credentials-dir", () -> sharedTempDir.resolve("bootstrap").toString());
    }

    @AfterAll
    static void detach() {
        ((Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME)).detachAppender(LOGS);
        LOGS.stop();
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private OrganisationRepository organisationRepository;
    @Autowired
    private CaseRepository caseRepository;
    @Autowired
    private AdminUserService adminUserService;
    @Autowired
    private JdbcTemplate jdbc;

    private User user(String name) {
        return userRepository.findByUsername(name).orElseThrow(() -> new AssertionError(name + " must exist"));
    }

    private static RequestPostProcessor as(User u) {
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(u, Instant.now());
        return authentication(new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities()));
    }

    private static CaseVaultUserPrincipal principalOf(User u) {
        return new CaseVaultUserPrincipal(u, Instant.now());
    }

    private int accessDenied(String caseId) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM audit_events WHERE event_type = 'ACCESS_DENIED' AND case_id = ?",
                Integer.class, UUID.fromString(caseId));
    }

    private Case demoCase() {
        Organisation orgB = organisationRepository.findByCode("ORG_DEMO_B").orElseThrow();
        List<Case> cases = caseRepository.findByOrganisationId(orgB.getId());
        assertEquals(1, cases.size(), "exactly one demo case");
        return cases.get(0);
    }

    @Test
    @DisplayName("DEMO-LOCAL-01: the local profile creates Demo Client Org B, its client user, one clearly named demo case and a second AUDITOR_ADMIN, next to the four normal accounts")
    void demoDataExists() {
        Organisation orgB = organisationRepository.findByCode("ORG_DEMO_B").orElseThrow();
        assertEquals("Demo Client Org B", orgB.getName());
        User clientB = user("demo_client_b");
        assertEquals(Role.CLIENT, clientB.getRole());
        assertEquals(orgB.getId(), clientB.getOrganisation().getId());
        User admin2 = user("demo_admin_2");
        assertEquals(Role.AUDITOR_ADMIN, admin2.getRole());
        assertTrue(admin2.isEnabled());
        assertTrue(demoCase().getTitle().startsWith("DEMO case"), demoCase().getTitle());
        assertNotEquals(user("client_charlie").getOrganisation().getId(), orgB.getId(), "a second organisation");
        for (String normal : List.of("admin_auditor", "manager_alice", "analyst_bob", "client_charlie")) {
            assertTrue(userRepository.findByUsername(normal).isPresent(), normal);
        }
    }

    @Test
    @DisplayName("DEMO-LOCAL-02: tenant isolation: a CLIENT of organisation A gets 404 (not 403) for organisation B's case and the denial is audited once as ACCESS_DENIED; B's client gets 404 for A's case; the lists do not leak")
    void tenantIsolation() throws Exception {
        User clientA = user("client_charlie");
        User clientB = user("demo_client_b");
        Case caseB = demoCase();
        int before = accessDenied(caseB.getId());
        MvcResult denied = mockMvc.perform(get("/cases/" + caseB.getId()).with(as(clientA))).andReturn();
        assertEquals(404, denied.getResponse().getStatus());
        assertEquals(before + 1, accessDenied(caseB.getId()), "one ACCESS_DENIED row for the masked access");

        String titleA = "DEMO test case of organisation A " + UUID.randomUUID().toString().substring(0, 8);
        Case caseA = caseRepository.save(new Case(UUID.randomUUID().toString(), clientA.getOrganisation(), titleA,
                "OTHER", "LOW", "OPEN", clientA, null, Instant.now()));
        assertEquals(404, mockMvc.perform(get("/cases/" + caseA.getId()).with(as(clientB))).andReturn().getResponse().getStatus());

        String listA = mockMvc.perform(get("/cases").with(as(clientA))).andReturn().getResponse().getContentAsString();
        String listB = mockMvc.perform(get("/cases").with(as(clientB))).andReturn().getResponse().getContentAsString();
        assertTrue(listA.contains(titleA) && !listA.contains(caseB.getTitle()), "A sees only A");
        assertTrue(listB.contains(caseB.getTitle()) && !listB.contains(titleA), "B sees only B");
        assertEquals(200, mockMvc.perform(get("/cases/" + caseB.getId()).with(as(clientB))).andReturn().getResponse().getStatus());
    }

    @Test
    @DisplayName("DEMO-LOCAL-03: two administrators: disabling the second succeeds and ends its ability to act; the remaining administrator cannot disable itself; one active administrator remains (the 'last administrator' message itself is not reachable one step at a time, see SEC-ADMIN-08)")
    void twoAdministrators() {
        User first = user("admin_auditor");
        User second = user("demo_admin_2");
        CaseVaultUserPrincipal firstPrincipal = principalOf(first);
        CaseVaultUserPrincipal secondPrincipal = principalOf(second);
        try {
            assertEquals(2, userRepository.findByRoleAndEnabledTrue(Role.AUDITOR_ADMIN).size());
            assertEquals(AdminUserService.ActionResult.DONE, adminUserService.disable(firstPrincipal, second.getId()));
            assertEquals(1, userRepository.findByRoleAndEnabledTrue(Role.AUDITOR_ADMIN).size());
            AdminActionRefusedException self = assertThrows(AdminActionRefusedException.class,
                    () -> adminUserService.disable(firstPrincipal, first.getId()));
            assertEquals("You cannot disable your own account.", self.getMessage());
            assertThrows(ResourceNotFoundException.class, () -> adminUserService.disable(secondPrincipal, first.getId()),
                    "a disabled administrator can no longer act");
            assertEquals(1, userRepository.findByRoleAndEnabledTrue(Role.AUDITOR_ADMIN).size(), "the last administrator is still active");
        } finally {
            adminUserService.enable(firstPrincipal, second.getId());
        }
    }

    @Test
    @DisplayName("DEMO-LOCAL-04: demo passwords are random per start, policy-valid, distinct, stored only as Argon2id hashes, written only to the credentials file, and never appear in any log line")
    void demoPasswordsAreNotLeaked() throws IOException {
        Path file = sharedTempDir.resolve("bootstrap").resolve("bootstrap-credentials.txt");
        assertTrue(Files.exists(file), "the credentials-dir property is honoured");
        Map<String, String> passwords = new HashMap<>();
        for (String line : Files.readAllLines(file)) {
            if (line.startsWith("demo_")) {
                passwords.put(line.substring(0, line.indexOf('=')), line.substring(line.indexOf('=') + 1));
            }
        }
        assertEquals(2, passwords.size());
        assertNotEquals(passwords.get("demo_client_b"), passwords.get("demo_admin_2"));
        for (Map.Entry<String, String> entry : passwords.entrySet()) {
            String pw = entry.getValue();
            assertEquals(18, pw.length());
            assertTrue(PasswordPolicyValidator.isValid(pw));
            assertFalse(pw.toLowerCase().contains("demo") || pw.toLowerCase().contains("password"), "not guessable from the name");
            String hash = user(entry.getKey()).getPasswordHash();
            assertTrue(hash.startsWith("$argon2id$"));
            assertFalse(hash.contains(pw));
            for (ILoggingEvent event : LOGS.list) {
                assertFalse(event.getFormattedMessage().contains(pw), "no log line contains a demo password");
            }
        }
        for (String other : List.of("admin_auditor", "manager_alice", "analyst_bob", "client_charlie")) {
            assertFalse(passwords.containsValue(other), other);
        }
    }
}
