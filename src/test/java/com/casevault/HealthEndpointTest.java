package com.casevault;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class HealthEndpointTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("TEST-BASE-002: Actuator health endpoint returns UP with security headers")
    void healthEndpointReturnsUp() throws Exception {
        mockMvc.perform(get("/actuator/health")
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'"))
                .andExpect(header().string("Permissions-Policy", "camera=(), microphone=(), geolocation=()"));
    }

    @Autowired
    private org.springframework.boot.autoconfigure.web.ServerProperties serverProperties;

    @Test
    @DisplayName("TEST-BASE-003: Unauthenticated access to non-public endpoints is unauthorized")
    void unauthenticatedAccessSecured() throws Exception {
        mockMvc.perform(get("/api/cases"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("TEST-BASE-005: Session cookies are configured Secure, HttpOnly, and SameSite=Strict")
    void sessionCookiesConfiguredSecure() {
        var cookie = serverProperties.getServlet().getSession().getCookie();
        org.junit.jupiter.api.Assertions.assertTrue(Boolean.TRUE.equals(cookie.getSecure()), "Session cookie must be Secure");
        org.junit.jupiter.api.Assertions.assertTrue(Boolean.TRUE.equals(cookie.getHttpOnly()), "Session cookie must be HttpOnly");
        org.junit.jupiter.api.Assertions.assertEquals(
                org.springframework.boot.web.server.Cookie.SameSite.STRICT,
                cookie.getSameSite(),
                "Session cookie SameSite must be STRICT"
        );
    }
}
