package com.casevault.ratelimit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Phase 8A: the enabled switch really turns the limiter off (a documented configuration, off by default only in this test). */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "casevault.ratelimit.enabled=false",
        "casevault.ratelimit.login-limit=1"
})
class RateLimitDisabledTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("SEC-RATE-WEB-14: with casevault.ratelimit.enabled=false no request is limited, even with a limit of 1")
    void disabledSwitch() throws Exception {
        for (int i = 0; i < 15; i++) {
            assertEquals(302, mockMvc.perform(post("/login").with(csrf())
                    .param("username", "nobody_" + UUID.randomUUID()).param("password", "x")).andReturn().getResponse().getStatus());
        }
    }
}
