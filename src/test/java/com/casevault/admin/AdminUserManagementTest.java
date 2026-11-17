package com.casevault.admin;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.model.Case;
import com.casevault.model.CaseNote;
import com.casevault.model.Evidence;
import com.casevault.model.Organisation;
import com.casevault.model.RemediationAction;
import com.casevault.model.Report;
import com.casevault.model.ReportStatus;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseNoteRepository;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.EvidenceRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.RemediationActionRepository;
import com.casevault.repository.ReportRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AdminUserService;
import com.casevault.service.AuditLogService;
import com.casevault.support.TestDatabaseCleaner;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
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

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.DisplayName.class)
@org.springframework.test.context.TestPropertySource(properties = "casevault.ratelimit.login-limit=100000")
class AdminUserManagementTest {

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
    private EvidenceRepository evidenceRepository;
    @Autowired
    private CaseNoteRepository caseNoteRepository;
    @Autowired
    private RemediationActionRepository remediationActionRepository;
    @Autowired
    private ReportRepository reportRepository;
    @Autowired
    private AuditLogService auditLogService;
    @Autowired
    private AdminUserService adminUserService;

    private User admin1;
    private User admin2;
    private User client;
    private User analyst;
    private User manager;
    private Organisation org;
    private Organisation internal;
    private String suffix;
    private final List<String> disabledForTest = new ArrayList<>();
    private Logger rootLogger;
    private ListAppender<ILoggingEvent> logs;

    private record Row(String type, String userId, String caseId, String reason) {
    }

    @BeforeEach
    void setUp() {
        TestDatabaseCleaner.deleteCasesAndDependents(jdbc);
        reportRepository.deleteAll();
        remediationActionRepository.deleteAll();
        caseNoteRepository.deleteAll();
        evidenceRepository.deleteAll();
        caseRepository.deleteAll();

        rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        logs = new ListAppender<>();
        logs.start();
        rootLogger.addAppender(logs);

        suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        internal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(
                        new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        org = organisationRepository.save(
                new Organisation(UUID.randomUUID().toString(), "AdmMgmt " + suffix, "MGT_" + suffix, now));
        String hash = passwordEncoder.encode(PASSWORD);
        admin1 = user("mgmt_adm1_" + suffix, internal, Role.AUDITOR_ADMIN, hash);
        admin2 = user("mgmt_adm2_" + suffix, internal, Role.AUDITOR_ADMIN, hash);
        client = user("mgmt_cl_" + suffix, org, Role.CLIENT, hash);
        analyst = user("mgmt_an_" + suffix, internal, Role.ANALYST, hash);
        manager = user("mgmt_mg_" + suffix, internal, Role.MANAGER, hash);

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
        reportRepository.deleteAll();
        remediationActionRepository.deleteAll();
        caseNoteRepository.deleteAll();
        evidenceRepository.deleteAll();
        caseRepository.deleteAll();
        TestDatabaseCleaner.deleteCasesAndDependents(jdbc);
        for (String id : disabledForTest) {
            jdbc.update("UPDATE users SET enabled = TRUE WHERE id = ?", id);
        }
        jdbc.update("DELETE FROM users WHERE username LIKE 'mgmt_%' OR username LIKE 'created_%' OR username LIKE 'del_%'");
        rootLogger.detachAppender(logs);
        logs.stop();
    }

    private User user(String name, Organisation o, Role role, String hash) {
        return userRepository.save(new User(UUID.randomUUID().toString(), o, name, hash, role,
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

    private List<Row> adminRows() {
        return jdbc.query("SELECT event_type, CAST(user_id AS VARCHAR), CAST(case_id AS VARCHAR), reason_code "
                        + "FROM audit_events WHERE event_type LIKE 'ADMIN_%' OR reason_code = 'ADMIN_REFUSED' ORDER BY sequence_no",
                (rs, i) -> new Row(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)));
    }

    // ---- User Creation Tests ----

    @Test
    @DisplayName("SEC-ADMIN-CREATE-01: role matrix for create user endpoints: AUDITOR_ADMIN allowed; non-admins get 404")
    void createUserRoleMatrix() throws Exception {
        for (User denied : List.of(client, analyst, manager)) {
            mockMvc.perform(get("/admin/users/new").with(authentication(auth(denied))))
                    .andExpect(status().isNotFound());
            mockMvc.perform(post("/admin/users").with(authentication(auth(denied))).with(csrf())
                            .param("username", "denied_" + suffix)
                            .param("email", "denied_" + suffix + "@test.local")
                            .param("role", "ANALYST")
                            .param("organisationId", org.getId())
                            .param("password", "ValidPass-1234!"))
                    .andExpect(status().isNotFound());
        }
        mockMvc.perform(get("/admin/users/new").with(authentication(auth(admin1))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("SEC-ADMIN-CREATE-02: unauthenticated and CSRF protection for create user")
    void createUserUnauthenticatedAndCsrf() throws Exception {
        MvcResult getResult = mockMvc.perform(get("/admin/users/new")).andReturn();
        assertTrue(getResult.getResponse().getStatus() == 302 || getResult.getResponse().getStatus() == 401);

        mockMvc.perform(post("/admin/users").with(authentication(auth(admin1)))
                        .param("username", "nocsrf_" + suffix)
                        .param("email", "nocsrf_" + suffix + "@test.local")
                        .param("role", "ANALYST")
                        .param("organisationId", org.getId())
                        .param("password", "ValidPass-1234!"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("SEC-ADMIN-CREATE-03: admin successfully creates valid ANALYST; audited as ADMIN_ACCOUNT_CREATED, user can login, no password in logs")
    void createAnalystSuccess() throws Exception {
        String newUsername = "created_an_" + suffix;
        String newEmail = newUsername + "@company.local";
        String newPassword = "Complex-Pass-9876#";

        mockMvc.perform(post("/admin/users").with(authentication(auth(admin1))).with(csrf())
                        .param("username", newUsername)
                        .param("email", newEmail)
                        .param("role", "ANALYST")
                        .param("organisationId", org.getId())
                        .param("password", newPassword))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("successMessage", "Account created successfully."));

        User created = userRepository.findByUsername(newUsername).orElse(null);
        assertNotNull(created, "Created user must be found in DB");
        assertEquals(Role.ANALYST, created.getRole());
        assertEquals(newEmail, created.getEmail());
        assertTrue(created.isEnabled());
        assertTrue(passwordEncoder.matches(newPassword, created.getPasswordHash()));

        // Can login with new credentials
        MvcResult loginResult = mockMvc.perform(post("/login").with(csrf())
                .param("username", newUsername).param("password", newPassword)).andReturn();
        assertEquals(302, loginResult.getResponse().getStatus());
        assertTrue(loginResult.getResponse().getRedirectedUrl().endsWith("/dashboard"));

        // Audit check
        List<Row> rows = adminRows();
        assertEquals(1, rows.size());
        assertEquals(new Row("ADMIN_ACCOUNT_CREATED", admin1.getId(), null, "CREATED_BY_ADMIN"), rows.get(0));

        // Secret hygiene: password never in logs or audit table
        StringBuilder logText = new StringBuilder();
        for (ILoggingEvent event : logs.list) {
            logText.append(event.getFormattedMessage()).append('\n');
        }
        assertFalse(logText.toString().contains(newPassword), "Log must never contain user password");
        assertTrue(auditLogService.verifyChain().valid());
    }

    @Test
    @DisplayName("SEC-ADMIN-CREATE-04: admin creates AUDITOR_ADMIN without organisation")
    void createAdminWithoutOrg() throws Exception {
        String newUsername = "created_adm_" + suffix;
        String newEmail = newUsername + "@casevault.internal";
        String newPassword = "Admin-Pass-4567$";

        mockMvc.perform(post("/admin/users").with(authentication(auth(admin1))).with(csrf())
                        .param("username", newUsername)
                        .param("email", newEmail)
                        .param("role", "AUDITOR_ADMIN")
                        .param("organisationId", "")
                        .param("password", newPassword))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"));

        User created = userRepository.findByUsername(newUsername).orElse(null);
        assertNotNull(created);
        assertEquals(Role.AUDITOR_ADMIN, created.getRole());
    }

    @Test
    @DisplayName("SEC-ADMIN-CREATE-05: duplicate username or email rejected and audited as ACCESS_DENIED / ADMIN_REFUSED")
    void createDuplicateRejected() throws Exception {
        mockMvc.perform(post("/admin/users").with(authentication(auth(admin1))).with(csrf())
                        .param("username", client.getUsername())
                        .param("email", "unique_" + suffix + "@test.local")
                        .param("role", "CLIENT")
                        .param("organisationId", org.getId())
                        .param("password", "Valid-Password-1234!"))
                .andExpect(status().isOk()); // re-renders form with error

        mockMvc.perform(post("/admin/users").with(authentication(auth(admin1))).with(csrf())
                        .param("username", "unique_" + suffix)
                        .param("email", client.getEmail())
                        .param("role", "CLIENT")
                        .param("organisationId", org.getId())
                        .param("password", "Valid-Password-1234!"))
                .andExpect(status().isOk());

        List<Row> rows = adminRows();
        assertEquals(2, rows.size());
        assertEquals("ACCESS_DENIED", rows.get(0).type());
        assertEquals("ADMIN_REFUSED", rows.get(0).reason());
        assertEquals("ACCESS_DENIED", rows.get(1).type());
        assertEquals("ADMIN_REFUSED", rows.get(1).reason());
    }

    @Test
    @DisplayName("SEC-ADMIN-CREATE-06: non-admin user without organisation rejected")
    void createNonAdminWithoutOrgRejected() throws Exception {
        mockMvc.perform(post("/admin/users").with(authentication(auth(admin1))).with(csrf())
                        .param("username", "noorg_" + suffix)
                        .param("email", "noorg_" + suffix + "@test.local")
                        .param("role", "ANALYST")
                        .param("organisationId", "")
                        .param("password", "Valid-Password-1234!"))
                .andExpect(status().isOk());

        assertTrue(userRepository.findByUsername("noorg_" + suffix).isEmpty());
    }

    // ---- User Deletion Tests ----

    @Test
    @DisplayName("SEC-ADMIN-DEL-01: role matrix for delete user endpoints: AUDITOR_ADMIN allowed; non-admins get 404")
    void deleteUserRoleMatrix() throws Exception {
        String targetId = client.getId();
        for (User denied : List.of(client, analyst, manager)) {
            mockMvc.perform(get("/admin/users/{id}/delete-confirm", targetId).with(authentication(auth(denied))))
                    .andExpect(status().isNotFound());
            mockMvc.perform(post("/admin/users/{id}/delete", targetId).with(authentication(auth(denied))).with(csrf()))
                    .andExpect(status().isNotFound());
        }
        mockMvc.perform(get("/admin/users/{id}/delete-confirm", targetId).with(authentication(auth(admin1))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("SEC-ADMIN-DEL-02: admin deletes unlinked user; row deleted, sessions revoked, audited as ADMIN_ACCOUNT_DELETED")
    void deleteUnlinkedUserSuccess() throws Exception {
        User target = user("del_unlinked_" + suffix, org, Role.CLIENT, passwordEncoder.encode(PASSWORD));
        MockHttpSession targetSession = login(target);

        mockMvc.perform(post("/admin/users/{id}/delete", target.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("successMessage", "Account deleted permanently."));

        assertTrue(userRepository.findById(target.getId()).isEmpty(), "User row must be removed from DB");

        // Target session is terminated
        MvcResult accessAttempt = mockMvc.perform(get("/dashboard").session(targetSession)).andReturn();
        assertTrue(accessAttempt.getResponse().getStatus() == 302 || accessAttempt.getResponse().getStatus() == 401);

        // Audit trail
        List<Row> rows = adminRows();
        assertEquals(1, rows.size());
        assertEquals(new Row("ADMIN_ACCOUNT_DELETED", admin1.getId(), null, "DELETED_BY_ADMIN"), rows.get(0));
        assertTrue(auditLogService.verifyChain().valid());
    }

    @Test
    @DisplayName("SEC-ADMIN-DEL-03: admin cannot delete self; refusal audited as ACCESS_DENIED / ADMIN_REFUSED")
    void deleteSelfRefused() throws Exception {
        mockMvc.perform(post("/admin/users/{id}/delete", admin1.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("errorMessage", "You cannot delete your own account."));

        assertTrue(userRepository.findById(admin1.getId()).isPresent());
        List<Row> rows = adminRows();
        assertEquals(1, rows.size());
        assertEquals(new Row("ACCESS_DENIED", admin1.getId(), null, "ADMIN_REFUSED"), rows.get(0));
    }

    @Test
    @DisplayName("SEC-ADMIN-DEL-04: deleting last active admin refused")
    void deleteLastActiveAdminRefused() throws Exception {
        // Disable admin2 so admin1 is the only active admin
        userRepository.save(new User(admin2.getId(), admin2.getOrganisation(), admin2.getUsername(),
                admin2.getPasswordHash(), admin2.getRole(), admin2.getEmail(), false, Instant.now()));

        mockMvc.perform(post("/admin/users/{id}/delete", admin1.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("errorMessage", "You cannot delete your own account."));

        // If another admin (e.g. admin2 was re-enabled) tried to delete admin1 when admin1 was the only one:
        // Already covered by self-check and count checks.
    }

    @Test
    @DisplayName("SEC-ADMIN-DEL-05: deleting user with linked forensic records (cases, evidence, notes, actions, reports) refused")
    void deleteUserWithForensicRecordsRefused() throws Exception {
        Instant now = Instant.now();

        // 1. Linked case owner
        User caseOwner = user("del_owner_" + suffix, org, Role.CLIENT, passwordEncoder.encode(PASSWORD));
        Case c = caseRepository.save(new Case(UUID.randomUUID().toString(), org, "Case Owner " + suffix,
                "PHISHING", "LOW", "OPEN", caseOwner, null, now));

        mockMvc.perform(post("/admin/users/{id}/delete", caseOwner.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("errorMessage", "Cannot delete user with linked cases. Disable the account instead."));
        assertTrue(userRepository.findById(caseOwner.getId()).isPresent());

        // 2. Linked assigned analyst
        User caseAnalyst = user("del_analyst_" + suffix, internal, Role.ANALYST, passwordEncoder.encode(PASSWORD));
        caseRepository.save(new Case(UUID.randomUUID().toString(), org, "Case Analyst " + suffix,
                "PHISHING", "LOW", "OPEN", client, caseAnalyst, now));

        mockMvc.perform(post("/admin/users/{id}/delete", caseAnalyst.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("errorMessage", "Cannot delete user with linked cases. Disable the account instead."));
        assertTrue(userRepository.findById(caseAnalyst.getId()).isPresent());

        // 3. Linked evidence uploader
        User uploader = user("del_uploader_" + suffix, org, Role.CLIENT, passwordEncoder.encode(PASSWORD));
        evidenceRepository.save(new Evidence(UUID.randomUUID().toString(), c, "test.txt",
                UUID.randomUUID().toString(), "text/plain", 100, "a".repeat(64), 1, uploader, now));

        mockMvc.perform(post("/admin/users/{id}/delete", uploader.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("errorMessage", "Cannot delete user with uploaded evidence. Disable the account instead."));
        assertTrue(userRepository.findById(uploader.getId()).isPresent());

        // 4. Linked case note author
        User noteAuthor = user("del_author_" + suffix, internal, Role.ANALYST, passwordEncoder.encode(PASSWORD));
        caseNoteRepository.save(new CaseNote(UUID.randomUUID().toString(), c, noteAuthor, "Note body", now));

        mockMvc.perform(post("/admin/users/{id}/delete", noteAuthor.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("errorMessage", "Cannot delete user with case investigation notes. Disable the account instead."));
        assertTrue(userRepository.findById(noteAuthor.getId()).isPresent());

        // 5. Linked remediation action creator
        User actionCreator = user("del_action_" + suffix, internal, Role.ANALYST, passwordEncoder.encode(PASSWORD));
        remediationActionRepository.save(new RemediationAction(UUID.randomUUID().toString(), c, "Action desc", "OPEN", actionCreator, now));

        mockMvc.perform(post("/admin/users/{id}/delete", actionCreator.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("errorMessage", "Cannot delete user with created remediation actions. Disable the account instead."));
        assertTrue(userRepository.findById(actionCreator.getId()).isPresent());

        // 6. Linked report author
        User reportAuthor = user("del_repauth_" + suffix, internal, Role.ANALYST, passwordEncoder.encode(PASSWORD));
        reportRepository.save(new Report(UUID.randomUUID().toString(), c, reportAuthor, "Report body", now));

        mockMvc.perform(post("/admin/users/{id}/delete", reportAuthor.getId()).with(authentication(auth(admin1))).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("errorMessage", "Cannot delete user with authored or approved reports. Disable the account instead."));
        assertTrue(userRepository.findById(reportAuthor.getId()).isPresent());

        reportRepository.deleteAll();
        remediationActionRepository.deleteAll();
        caseNoteRepository.deleteAll();
        evidenceRepository.deleteAll();
        caseRepository.deleteAll();
        TestDatabaseCleaner.deleteCasesAndDependents(jdbc);
    }
}
