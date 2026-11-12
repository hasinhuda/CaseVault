package com.casevault.ratelimit;

import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 9B: the filter-rendered 429 page links to the Dashboard for a signed-in user and to the login page for a
 * signed-out visitor. Status 429 and a numeric Retry-After are asserted in both cases. The page is rendered inside
 * the security filter chain, so "signed in" comes from the SecurityContext.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "casevault.ratelimit.login-limit=3",
        "casevault.ratelimit.search-limit=2"
})
class RateLimitPageLinksTest {

    private static final String PASSWORD = "Rate-Links-Password-1234!";
    private static final java.util.concurrent.atomic.AtomicInteger ADDRESS_COUNTER = new java.util.concurrent.atomic.AtomicInteger();

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
    private PasswordEncoder passwordEncoder;
    @Autowired
    private OrganisationRepository organisationRepository;
    @Autowired
    private UserRepository userRepository;

    private User newClient() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        Organisation org = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "RP " + suffix, "RP_" + suffix, now));
        return userRepository.save(new User(UUID.randomUUID().toString(), org, "rp_cl_" + suffix,
                passwordEncoder.encode(PASSWORD), Role.CLIENT, "rp_" + suffix + "@test.local", true, now));
    }

    private static void assertLimited(MvcResult r) {
        assertEquals(429, r.getResponse().getStatus());
        assertTrue(Integer.parseInt(r.getResponse().getHeader("Retry-After")) >= 1, "Retry-After is a number");
        assertTrue(r.getResponse().getContentType().startsWith("text/html"));
    }

    @Test
    @DisplayName("UI-RATE-01: signed-out 429 page (login limit) shows Back to login and no Dashboard link; status 429 and Retry-After unchanged")
    void anonymousLimited() throws Exception {
        String address = "10.91.0." + (ADDRESS_COUNTER.incrementAndGet() % 250 + 1);
        MvcResult last = null;
        for (int i = 0; i < 4; i++) {
            last = mockMvc.perform(post("/login").with(csrf()).with(req -> {
                req.setRemoteAddr(address);
                return req;
            }).param("username", "nobody").param("password", "x")).andReturn();
        }
        assertLimited(last);
        String body = last.getResponse().getContentAsString();
        assertTrue(body.contains("Back to login"));
        assertTrue(body.contains("href=\"/login\""));
        assertFalse(body.contains("Return to Dashboard"));
        assertFalse(body.contains("href=\"/dashboard\""));
        assertTrue(body.contains("Try again in about"), "the retry text is unchanged");
    }

    @Test
    @DisplayName("UI-RATE-02: signed-in 429 page (search limit) shows Return to Dashboard and no Back to login; status 429 and Retry-After unchanged")
    void signedInLimited() throws Exception {
        User client = newClient();
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(client, Instant.now());
        MvcResult last = null;
        for (int i = 0; i < 3; i++) {
            last = mockMvc.perform(get("/cases").param("q", "x").header("Accept", "text/html")
                    .with(authentication(new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities())))).andReturn();
        }
        assertLimited(last);
        String body = last.getResponse().getContentAsString();
        assertTrue(body.contains("Return to Dashboard"));
        assertTrue(body.contains("href=\"/dashboard\""));
        assertFalse(body.contains("Back to login"));
        assertFalse(body.contains("href=\"/login\""));
        assertTrue(body.contains("Try again in about"), "the retry text is unchanged");
    }
}
