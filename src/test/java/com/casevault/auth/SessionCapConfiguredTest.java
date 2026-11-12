package com.casevault.auth;

import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
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
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Phase 8C: the cap value comes from the property (here 1: every new login expires the previous session). */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {"casevault.ratelimit.login-limit=100000", "casevault.session.max-per-user=1"})
class SessionCapConfiguredTest {

    private static final String PASSWORD = "Session-Cap-Password-1234!";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private MockHttpSession login(User user) throws Exception {
        MvcResult r = mockMvc.perform(post("/login").with(csrf()).param("username", user.getUsername()).param("password", PASSWORD)).andReturn();
        assertEquals(302, r.getResponse().getStatus());
        return (MockHttpSession) r.getRequest().getSession(false);
    }

    @Test
    @DisplayName("SEC-SESSION-06: casevault.session.max-per-user=1 is honoured: the 2nd login expires the 1st")
    void capComesFromProperty() throws Exception {
        String name = "cap1_" + UUID.randomUUID().toString().substring(0, 8);
        User user = userRepository.save(new User(UUID.randomUUID().toString(), null, name, passwordEncoder.encode(PASSWORD),
                Role.ANALYST, name + "@casevault.local", true, Instant.now()));
        MockHttpSession first = login(user);
        assertEquals(200, mockMvc.perform(get("/dashboard").session(first)).andReturn().getResponse().getStatus());
        MockHttpSession second = login(user);
        MvcResult r = mockMvc.perform(get("/dashboard").session(first)).andReturn();
        assertEquals(302, r.getResponse().getStatus());
        assertEquals("/login?expired=true", r.getResponse().getRedirectedUrl());
        assertEquals(200, mockMvc.perform(get("/dashboard").session(second)).andReturn().getResponse().getStatus());
    }
}
