package com.casevault.auth;

import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 8C: concurrent session cap (casevault.session.max-per-user, default 3). Every login goes through the real
 * POST /login; the oldest session of the user is expired when the cap is exceeded (the new login wins).
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "casevault.ratelimit.login-limit=100000")
class SessionCapTest {

    private static final String PASSWORD = "Session-Cap-Password-1234!";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Value("${casevault.session.max-per-user}")
    private int configuredCap;

    private User newUser(Role role) {
        String name = "cap_" + UUID.randomUUID().toString().substring(0, 8);
        return userRepository.save(new User(UUID.randomUUID().toString(), null, name, passwordEncoder.encode(PASSWORD),
                role, name + "@casevault.local", true, Instant.now()));
    }

    private MockHttpSession login(User user) throws Exception {
        MvcResult r = mockMvc.perform(post("/login").with(csrf()).param("username", user.getUsername()).param("password", PASSWORD)).andReturn();
        assertEquals(302, r.getResponse().getStatus());
        assertEquals("/dashboard", r.getResponse().getRedirectedUrl());
        MockHttpSession session = (MockHttpSession) r.getRequest().getSession(false);
        assertNotNull(session);
        return session;
    }

    private int dashboardStatus(MockHttpSession s) throws Exception {
        return mockMvc.perform(get("/dashboard").session(s)).andReturn().getResponse().getStatus();
    }

    @Test
    @DisplayName("SEC-SESSION-01: the default cap is 3; the 4th login of the same user expires the 1st (oldest) session, the 2nd, 3rd and 4th keep working")
    void fourthLoginExpiresFirst() throws Exception {
        assertEquals(3, configuredCap, "default casevault.session.max-per-user");
        User user = newUser(Role.ANALYST);
        MockHttpSession s1 = login(user);
        MockHttpSession s2 = login(user);
        MockHttpSession s3 = login(user);
        assertEquals(200, dashboardStatus(s1));
        assertEquals(200, dashboardStatus(s2));
        assertEquals(200, dashboardStatus(s3));
        MockHttpSession s4 = login(user);

        MvcResult expired = mockMvc.perform(get("/dashboard").session(s1)).andReturn();
        assertEquals(302, expired.getResponse().getStatus());
        assertEquals("/login?expired=true", expired.getResponse().getRedirectedUrl());
        assertEquals(200, dashboardStatus(s2));
        assertEquals(200, dashboardStatus(s3));
        assertEquals(200, dashboardStatus(s4), "the new login wins and is not blocked");
    }

    @Test
    @DisplayName("SEC-SESSION-02: the expired session gets 401 on /api/** and the redirect to /login?expired=true elsewhere")
    void expiredSessionApiAndPage() throws Exception {
        // two users: the first request with an expired session also ends it, so each check needs its own user
        User apiUser = newUser(Role.ANALYST);
        MockHttpSession api1 = login(apiUser);
        login(apiUser);
        login(apiUser);
        login(apiUser);
        assertEquals(401, mockMvc.perform(get("/api/cases").session(api1)).andReturn().getResponse().getStatus());
        User user = newUser(Role.ANALYST);
        MockHttpSession s1 = login(user);
        login(user);
        login(user);
        login(user);
        MvcResult page = mockMvc.perform(get("/cases").session(s1)).andReturn();
        assertEquals(302, page.getResponse().getStatus());
        assertEquals("/login?expired=true", page.getResponse().getRedirectedUrl());
    }

    @Test
    @DisplayName("SEC-SESSION-03: other users are unaffected by the cap of one user")
    void otherUsersUnaffected() throws Exception {
        User other = newUser(Role.ANALYST);
        MockHttpSession otherSession = login(other);
        User busy = newUser(Role.ANALYST);
        MockHttpSession busyFirst = login(busy);
        login(busy);
        login(busy);
        login(busy);
        assertEquals(302, dashboardStatus(busyFirst));
        assertEquals(200, dashboardStatus(otherSession), "the other user's session is untouched");
        MockHttpSession otherSecond = login(other);
        assertEquals(200, dashboardStatus(otherSession));
        assertEquals(200, dashboardStatus(otherSecond));
    }

    @Test
    @DisplayName("SEC-SESSION-04: admin revoke-sessions still expires every session of the user and the user can log in again (cap does not interfere)")
    void revokeStillWorks() throws Exception {
        User victim = newUser(Role.ANALYST);
        User admin = newUser(Role.AUDITOR_ADMIN);
        MockHttpSession v1 = login(victim);
        MockHttpSession v2 = login(victim);
        MockHttpSession adminSession = login(admin);
        mockMvc.perform(post("/admin/users/{id}/revoke-sessions", victim.getId()).session(adminSession).with(csrf()))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().is3xxRedirection());
        for (MockHttpSession dead : new MockHttpSession[]{v1, v2}) {
            MvcResult r = mockMvc.perform(get("/dashboard").session(dead)).andReturn();
            assertEquals(302, r.getResponse().getStatus());
            assertTrue(r.getResponse().getRedirectedUrl().contains("/login?expired"), r.getResponse().getRedirectedUrl());
        }
        assertEquals(200, dashboardStatus(login(victim)));
        assertEquals(200, dashboardStatus(adminSession));
    }

    @Test
    @DisplayName("SEC-SESSION-05: disabling an account still terminates its sessions on the next request (unchanged by the cap)")
    void disableStillWorks() throws Exception {
        User user = newUser(Role.ANALYST);
        MockHttpSession s = login(user);
        assertEquals(200, dashboardStatus(s));
        user.setEnabled(false);
        userRepository.save(user);
        MvcResult r = mockMvc.perform(get("/dashboard").session(s)).andReturn();
        assertEquals(302, r.getResponse().getStatus());
        assertTrue(r.getResponse().getRedirectedUrl().contains("/login"));
    }
}
