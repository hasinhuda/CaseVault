package com.casevault.auth;

import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import com.casevault.security.SessionAbsoluteTimeoutFilter;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class SessionLifecycleSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ServerProperties serverProperties;

    private User testUser;
    private final String rawPassword = "ValidSessionPassword123!";

    @BeforeEach
    void setUp() {
        String username = "session_user_" + UUID.randomUUID().toString().substring(0, 8);
        testUser = new User(
                UUID.randomUUID().toString(),
                null,
                username,
                passwordEncoder.encode(rawPassword),
                Role.ANALYST,
                username + "@casevault.local",
                true,
                Instant.now()
        );
        userRepository.save(testUser);
    }

    @Test
    @DisplayName("SEC-AUTH-06: Successful login authenticates user, establishes session, and rotates session ID")
    void testLoginSessionFixationProtection() throws Exception {
        MockHttpSession preAuthSession = new MockHttpSession();
        String preAuthSessionId = preAuthSession.getId();

        var result = mockMvc.perform(post("/login")
                        .with(csrf())
                        .session(preAuthSession)
                        .param("username", testUser.getUsername())
                        .param("password", rawPassword))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"))
                .andReturn();

        HttpSession postAuthSession = result.getRequest().getSession(false);
        assertNotNull(postAuthSession, "Authenticated session must exist");
        assertNotEquals(preAuthSessionId, postAuthSession.getId(), "Session ID must change upon authentication (Session Fixation Defense)");
    }

    @Test
    @DisplayName("SEC-AUTH-07: Logout invalidates active session and deletes cookies")
    void testLogoutSessionInvalidation() throws Exception {
        var loginResult = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", testUser.getUsername())
                        .param("password", rawPassword))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertNotNull(session);

        mockMvc.perform(post("/logout")
                        .with(csrf())
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout=true"))
                .andExpect(header().exists("Set-Cookie"));

        assertTrue(session.isInvalid(), "HTTP session must be invalidated upon logout");
    }

    @Test
    @DisplayName("SEC-AUTH-08: Session idle timeout is configured to 15 minutes")
    void testSessionIdleTimeoutConfiguration() {
        Duration timeout = serverProperties.getServlet().getSession().getTimeout();
        assertNotNull(timeout, "Session timeout must be configured");
        assertEquals(Duration.ofMinutes(15), timeout, "Session idle timeout must be exactly 15 minutes");
    }

    @Test
    @DisplayName("SEC-AUTH-09: Session absolute timeout enforces 8-hour maximum lifetime")
    void testSessionAbsoluteTimeoutFilter() throws Exception {
        var loginResult = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", testUser.getUsername())
                        .param("password", rawPassword))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertNotNull(session);

        // Manually simulate session created 8 hours and 1 minute ago
        long oldStartTime = System.currentTimeMillis() - (8 * 3600 * 1000 + 60_000);
        session.setAttribute(SessionAbsoluteTimeoutFilter.SESSION_START_TIME_KEY, oldStartTime);

        // Next request must detect absolute timeout, invalidate session, and redirect to login
        mockMvc.perform(get("/dashboard").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?expired=true"));

        assertTrue(session.isInvalid(), "Session must be invalidated after 8 hours absolute timeout");
    }

    @Test
    @DisplayName("SEC-AUTH-11: Active session of disabled user is immediately terminated on next request")
    void testActiveSessionRevokedWhenUserDisabled() throws Exception {
        var loginResult = mockMvc.perform(post("/login")
                        .with(csrf())
                        .param("username", testUser.getUsername())
                        .param("password", rawPassword))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertNotNull(session);

        // Verify authenticated request works before disabling
        mockMvc.perform(get("/dashboard").session(session))
                .andExpect(status().isOk());

        // Admin disables the user account in database
        testUser.setEnabled(false);
        userRepository.save(testUser);

        // Subsequent request using existing session must be rejected and invalidated
        mockMvc.perform(get("/dashboard").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?disabled=true"));

        assertTrue(session.isInvalid(), "Session must be invalidated when account is disabled");
    }

    @Test
    @DisplayName("SEC-AUTH-12: CSRF protection rejects state-changing POST requests without CSRF token")
    void testCsrfProtectionEnforced() throws Exception {
        // Attempt login without CSRF token
        mockMvc.perform(post("/login")
                        .param("username", testUser.getUsername())
                        .param("password", rawPassword))
                .andExpect(status().isForbidden());
    }
}

