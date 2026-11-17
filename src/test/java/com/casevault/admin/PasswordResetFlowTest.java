package com.casevault.admin;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.model.Organisation;
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
import com.casevault.service.AuditEventType;
import com.casevault.service.AuditReasonCode;
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
class PasswordResetFlowTest {

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

    private User admin1;
    private User client;
    private User analyst;
    private User manager;
    private Organisation org;
    private Organisation internal;
    private String suffix;
    private final List<String> disabledForTest = new ArrayList<>();
    private Logger rootLogger;
    private ListAppender<ILoggingEvent> logs;

    private record AuditRow(String type, String userId, String reason) {
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
                new Organisation(UUID.randomUUID().toString(), "PwdReset " + suffix, "RST_" + suffix, now));
        String hash = passwordEncoder.encode(PASSWORD);
        admin1 = user("rst_adm1_" + suffix, internal, Role.AUDITOR_ADMIN, hash);
        client = user("rst_cl_" + suffix, org, Role.CLIENT, hash);
        analyst = user("rst_an_" + suffix, internal, Role.ANALYST, hash);
        manager = user("rst_mg_" + suffix, internal, Role.MANAGER, hash);

        disabledForTest.clear();
        disabledForTest.addAll(jdbc.queryForList(
                "SELECT id FROM users WHERE role = 'AUDITOR_ADMIN' AND enabled = TRUE AND id != ?",
                String.class, admin1.getId()));
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
        jdbc.update("DELETE FROM users WHERE username LIKE 'rst_%'");
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

    private List<AuditRow> auditRows() {
        return jdbc.query("SELECT event_type, CAST(user_id AS VARCHAR), reason_code FROM audit_events ORDER BY sequence_no",
                (rs, i) -> new AuditRow(rs.getString(1), rs.getString(2), rs.getString(3)));
    }

    @Test
    @DisplayName("SEC-PWD-RESET-01: unauthenticated user cannot access /account/credentials")
    void unauthenticatedCannotAccessCredentials() throws Exception {
        MvcResult result = mockMvc.perform(get("/account/credentials")).andReturn();
        int status = result.getResponse().getStatus();
        assertTrue(status == 302 || status == 401);
        if (status == 302) {
            assertTrue(result.getResponse().getRedirectedUrl().contains("/login"));
        }
    }

    @Test
    @DisplayName("SEC-PWD-RESET-02: non-admin roles receive 404 for reset-password endpoints")
    void nonAdminGets404ForResetPassword() throws Exception {
        for (User denied : List.of(client, analyst, manager)) {
            mockMvc.perform(get("/admin/users/" + client.getId() + "/reset-password-confirm")
                            .with(authentication(auth(denied))))
                    .andExpect(status().isNotFound());

            mockMvc.perform(post("/admin/users/" + client.getId() + "/reset-password")
                            .with(authentication(auth(denied)))
                            .with(csrf()))
                    .andExpect(status().isNotFound());
        }
    }

    @Test
    @DisplayName("SEC-PWD-RESET-03: admin reset password requires CSRF")
    void resetPasswordRequiresCsrf() throws Exception {
        mockMvc.perform(post("/admin/users/" + analyst.getId() + "/reset-password")
                        .with(authentication(auth(admin1))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("SEC-PWD-RESET-04: admin cannot reset their own password via administrative reset")
    void adminCannotResetOwnPassword() throws Exception {
        mockMvc.perform(post("/admin/users/" + admin1.getId() + "/reset-password")
                        .with(authentication(auth(admin1)))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attributeExists("errorMessage"));

        User refreshed = userRepository.findById(admin1.getId()).orElseThrow();
        assertFalse(refreshed.isPasswordResetRequired());
    }

    @Test
    @DisplayName("SEC-PWD-RESET-05: admin resets user password; generates OTP, sets passwordResetRequired=true, audits event, no OTP in logs")
    void adminResetsUserPasswordSuccess() throws Exception {
        MvcResult result = mockMvc.perform(post("/admin/users/" + analyst.getId() + "/reset-password")
                        .with(authentication(auth(admin1)))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attributeExists("temporaryPassword"))
                .andExpect(flash().attributeExists("resetUsername"))
                .andReturn();

        String tempPassword = (String) result.getFlashMap().get("temporaryPassword");
        assertNotNull(tempPassword);
        assertEquals(18, tempPassword.length());

        User refreshed = userRepository.findById(analyst.getId()).orElseThrow();
        assertTrue(refreshed.isPasswordResetRequired());
        assertTrue(passwordEncoder.matches(tempPassword, refreshed.getPasswordHash()));

        // Verify audit event
        List<AuditRow> rows = auditRows();
        boolean foundAudit = rows.stream().anyMatch(r ->
                AuditEventType.ADMIN_PASSWORD_RESET.name().equals(r.type()) &&
                        AuditReasonCode.PASSWORD_RESET_BY_ADMIN.name().equals(r.reason()));
        assertTrue(foundAudit, "ADMIN_PASSWORD_RESET event must be recorded");

        // Verify no password in logs
        for (ILoggingEvent event : logs.list) {
            String msg = event.getFormattedMessage();
            assertFalse(msg.contains(tempPassword), "Logs must never contain the generated temporary password");
        }
    }

    @Test
    @DisplayName("SEC-PWD-RESET-06: user with passwordResetRequired=true is redirected to /account/credentials")
    void userWithResetRequiredIsRedirected() throws Exception {
        // Set user to require password reset
        analyst.setPasswordResetRequired(true);
        userRepository.save(analyst);

        mockMvc.perform(get("/dashboard").with(authentication(auth(analyst))))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/credentials"));

        mockMvc.perform(get("/cases").with(authentication(auth(analyst))))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/credentials"));

        // But can access /account/credentials
        mockMvc.perform(get("/account/credentials").with(authentication(auth(analyst))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("SEC-PWD-RESET-07: user successfully changes password; passwordResetRequired cleared, audited, can access dashboard")
    void userChangesPasswordSuccess() throws Exception {
        // Admin resets analyst's password
        MvcResult resetResult = mockMvc.perform(post("/admin/users/" + analyst.getId() + "/reset-password")
                        .with(authentication(auth(admin1)))
                        .with(csrf()))
                .andReturn();
        String tempPassword = (String) resetResult.getFlashMap().get("temporaryPassword");

        User updatedAnalyst = userRepository.findById(analyst.getId()).orElseThrow();
        Authentication analystAuth = auth(updatedAnalyst);

        String newPassword = "Brand-New-Secure-Password-999#";

        mockMvc.perform(post("/account/credentials")
                        .with(authentication(analystAuth))
                        .with(csrf())
                        .param("currentPassword", tempPassword)
                        .param("newPassword", newPassword)
                        .param("confirmPassword", newPassword))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"))
                .andExpect(flash().attributeExists("successMessage"));

        User postChange = userRepository.findById(analyst.getId()).orElseThrow();
        assertFalse(postChange.isPasswordResetRequired());
        assertTrue(passwordEncoder.matches(newPassword, postChange.getPasswordHash()));

        // Audit event USER_PASSWORD_CHANGED
        List<AuditRow> rows = auditRows();
        boolean foundAudit = rows.stream().anyMatch(r ->
                AuditEventType.USER_PASSWORD_CHANGED.name().equals(r.type()) &&
                        AuditReasonCode.PASSWORD_CHANGED.name().equals(r.reason()));
        assertTrue(foundAudit, "USER_PASSWORD_CHANGED event must be recorded");

        // Verify user can now reach dashboard
        mockMvc.perform(get("/dashboard").with(authentication(auth(postChange))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("SEC-PWD-RESET-08: incorrect current password rejected")
    void wrongCurrentPasswordRejected() throws Exception {
        analyst.setPasswordResetRequired(true);
        userRepository.save(analyst);

        mockMvc.perform(post("/account/credentials")
                        .with(authentication(auth(analyst)))
                        .with(csrf())
                        .param("currentPassword", "Wrong-Current-Password-123!")
                        .param("newPassword", "Valid-New-Password-1234!")
                        .param("confirmPassword", "Valid-New-Password-1234!"))
                .andExpect(status().isOk());

        User unchanged = userRepository.findById(analyst.getId()).orElseThrow();
        assertTrue(unchanged.isPasswordResetRequired());
    }

    @Test
    @DisplayName("SEC-PWD-RESET-09: new password identical to current password rejected")
    void sameNewPasswordRejected() throws Exception {
        analyst.setPasswordResetRequired(true);
        userRepository.save(analyst);

        mockMvc.perform(post("/account/credentials")
                        .with(authentication(auth(analyst)))
                        .with(csrf())
                        .param("currentPassword", PASSWORD)
                        .param("newPassword", PASSWORD)
                        .param("confirmPassword", PASSWORD))
                .andExpect(status().isOk());

        User unchanged = userRepository.findById(analyst.getId()).orElseThrow();
        assertTrue(unchanged.isPasswordResetRequired());
    }

    @Test
    @DisplayName("SEC-PWD-RESET-10: new password failing complexity policy rejected")
    void weakNewPasswordRejected() throws Exception {
        analyst.setPasswordResetRequired(true);
        userRepository.save(analyst);

        mockMvc.perform(post("/account/credentials")
                        .with(authentication(auth(analyst)))
                        .with(csrf())
                        .param("currentPassword", PASSWORD)
                        .param("newPassword", "short")
                        .param("confirmPassword", "short"))
                .andExpect(status().isOk());

        User unchanged = userRepository.findById(analyst.getId()).orElseThrow();
        assertTrue(unchanged.isPasswordResetRequired());
    }

    @Test
    @DisplayName("SEC-PWD-RESET-11: password and confirm password mismatch rejected")
    void mismatchedConfirmPasswordRejected() throws Exception {
        analyst.setPasswordResetRequired(true);
        userRepository.save(analyst);

        mockMvc.perform(post("/account/credentials")
                        .with(authentication(auth(analyst)))
                        .with(csrf())
                        .param("currentPassword", PASSWORD)
                        .param("newPassword", "Valid-New-Password-1234!")
                        .param("confirmPassword", "Different-Password-5678!"))
                .andExpect(status().isOk());

        User unchanged = userRepository.findById(analyst.getId()).orElseThrow();
        assertTrue(unchanged.isPasswordResetRequired());
    }

    @Test
    @DisplayName("SEC-PWD-RESET-12: API call returns 403 JSON when password reset is required")
    void apiCallReturns403WhenResetRequired() throws Exception {
        analyst.setPasswordResetRequired(true);
        userRepository.save(analyst);

        mockMvc.perform(get("/api/cases").with(authentication(auth(analyst))))
                .andExpect(status().isForbidden());
    }
}
