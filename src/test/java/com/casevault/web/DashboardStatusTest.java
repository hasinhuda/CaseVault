package com.casevault.web;

import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AdminUserService;
import com.casevault.service.AdminUserService.HealthView;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Phase 9B (finding F-009): the auditor dashboard shows the real result of the health service instead of constants.
 * The health service is replaced by a mock so each state is forced deterministically.
 */
@SpringBootTest
@AutoConfigureMockMvc
class DashboardStatusTest {

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
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @MockitoBean
    private AdminUserService adminUserService;

    private String dashboard(Role role) throws Exception {
        String name = "ds_" + UUID.randomUUID().toString().substring(0, 8);
        User user = userRepository.save(new User(UUID.randomUUID().toString(), null, name,
                passwordEncoder.encode("Dashboard-Status-1234!"), role, name + "@test.local", true, Instant.now()));
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(user, Instant.now());
        MvcResult r = mockMvc.perform(get("/dashboard")
                .with(authentication(new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities())))).andReturn();
        assertEquals(200, r.getResponse().getStatus(), "the dashboard always renders");
        return r.getResponse().getContentAsString();
    }

    private static void assertNoOldConstants(String body) {
        for (String constant : new String[]{"ENFORCED", "Telemetry Online", "HMAC-SHA256 Chained", "Uniform 404 Masking"}) {
            assertFalse(body.contains(constant), "constant removed: " + constant);
        }
    }

    @Test
    @DisplayName("UI-DASH-01: healthy system: the auditor dashboard shows HEALTHY and the real audit chain state")
    void healthy() throws Exception {
        when(adminUserService.health(any())).thenReturn(new HealthView(true, true, "Chain valid", 7L));
        String body = dashboard(Role.AUDITOR_ADMIN);
        assertTrue(body.contains("HEALTHY"));
        assertTrue(body.contains("Chain valid"));
        assertNoOldConstants(body);
    }

    @Test
    @DisplayName("UI-DASH-02: database down shows DOWN, never HEALTHY")
    void databaseDown() throws Exception {
        when(adminUserService.health(any())).thenReturn(new HealthView(false, true, "Not verified yet", null));
        String body = dashboard(Role.AUDITOR_ADMIN);
        assertTrue(body.contains("DOWN"));
        assertFalse(body.contains("HEALTHY"));
        assertTrue(body.contains("Not verified yet"));
    }

    @Test
    @DisplayName("UI-DASH-03: evidence storage not writable shows DEGRADED, never HEALTHY; a broken chain is shown as reported")
    void storageDegraded() throws Exception {
        when(adminUserService.health(any())).thenReturn(new HealthView(true, false, "Chain BROKEN at sequence 4", 9L));
        String body = dashboard(Role.AUDITOR_ADMIN);
        assertTrue(body.contains("DEGRADED"));
        assertFalse(body.contains("HEALTHY"));
        assertTrue(body.contains("Chain BROKEN at sequence 4"));
    }

    @Test
    @DisplayName("UI-DASH-04: the health check throws: the page still returns 200, shows UNKNOWN, never HEALTHY, and shows no exception text")
    void healthCheckThrows() throws Exception {
        when(adminUserService.health(any())).thenThrow(new IllegalStateException("secret-detail /var/secret/path jdbc:h2:mem"));
        String body = dashboard(Role.AUDITOR_ADMIN);
        assertTrue(body.contains("UNKNOWN"));
        assertFalse(body.contains("HEALTHY"));
        for (String leak : new String[]{"secret-detail", "/var/secret", "jdbc", "IllegalStateException", "at com."}) {
            assertFalse(body.contains(leak), "dashboard must not show: " + leak);
        }
        assertNoOldConstants(body);
    }

    @Test
    @DisplayName("UI-DASH-05: other roles do not call the health service and see no system health card; the auditor sees the Restricted cases label")
    void otherRolesAndLabel() throws Exception {
        String client = dashboard(Role.CLIENT);
        assertFalse(client.contains("System Health"));
        assertFalse(client.contains("HEALTHY"));
        verifyNoInteractions(adminUserService);
        when(adminUserService.health(any())).thenReturn(new HealthView(true, true, "Chain valid", 1L));
        String auditor = dashboard(Role.AUDITOR_ADMIN);
        assertTrue(auditor.contains("Cases (Restricted)"));
        assertFalse(auditor.contains("Quarantined"));
    }
}
