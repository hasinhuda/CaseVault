package com.casevault.ratelimit;

import com.casevault.ratelimit.InMemoryRateLimiterTest.MutableClock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 8A: with trust-forwarded-for=true (only for a known reverse proxy) the LAST X-Forwarded-For entry, the one
 * the proxy appended, is the client key. The default (false) is proven in {@link RateLimitHttpTest}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "casevault.ratelimit.trust-forwarded-for=true",
        "casevault.ratelimit.login-limit=3"
})
class RateLimitForwardedForTest {

    @TestConfiguration
    static class ClockConfig {
        @Bean
        @Primary
        MutableClock testClock() {
            return new MutableClock();
        }
    }

    @Autowired
    private MockMvc mockMvc;

    private static RequestPostProcessor remote(String address) {
        return request -> {
            request.setRemoteAddr(address);
            return request;
        };
    }

    private int attempt(String remoteAddress, String forwardedFor) throws Exception {
        var request = post("/login").with(csrf()).with(remote(remoteAddress))
                .param("username", "nobody_" + UUID.randomUUID()).param("password", "x");
        if (forwardedFor != null) {
            request.header("X-Forwarded-For", forwardedFor);
        }
        return mockMvc.perform(request).andReturn().getResponse().getStatus();
    }

    @Test
    @DisplayName("SEC-RATE-WEB-12: with the flag on, the proxy-appended (last) X-Forwarded-For entry is the key: different clients behind one proxy are separate, the same client is limited")
    void forwardedForHonouredWhenEnabled() throws Exception {
        String proxy = "10.99.0.1";
        for (int i = 0; i < 3; i++) {
            assertEquals(302, attempt(proxy, "203.0.113.10"));
        }
        assertEquals(429, attempt(proxy, "203.0.113.10"), "the same forwarded client is limited");
        assertEquals(302, attempt(proxy, "203.0.113.11"), "another client behind the same proxy is not");
        // The client controls everything before the last entry; changing it does not change the key.
        assertEquals(429, attempt(proxy, "198.51.100.1, 203.0.113.10"));
        assertEquals(429, attempt(proxy, "192.0.2.77, 203.0.113.10"));
        // The remote address of the proxy itself is no longer the key.
        for (int i = 0; i < 3; i++) {
            assertEquals(302, attempt(proxy, "203.0.113." + (50 + i)));
        }
    }

    @Test
    @DisplayName("SEC-RATE-WEB-13: with the flag on, a malformed X-Forwarded-For falls back to the remote address (no free key choice, no echo)")
    void malformedForwardedForFallsBack() throws Exception {
        String remote = "10.99.1.1";
        for (int i = 0; i < 3; i++) {
            assertEquals(302, attempt(remote, "<script>alert(" + i + ")</script>"));
        }
        assertEquals(429, attempt(remote, "not an address at all"));
        assertEquals(429, attempt(remote, null));
        assertEquals(429, attempt(remote, "x".repeat(500)));
    }
}
