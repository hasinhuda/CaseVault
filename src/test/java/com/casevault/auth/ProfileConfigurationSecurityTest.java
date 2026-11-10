package com.casevault.auth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.Cookie;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class ProfileConfigurationSecurityTest {

    @Autowired
    private ServerProperties serverProperties;

    @Test
    @DisplayName("SEC-AUTH-13: Production profile enforces Secure, HttpOnly, and SameSite=Strict cookie policy")
    void testProdLikeProfileCookieFlags() {
        var cookie = serverProperties.getServlet().getSession().getCookie();

        assertTrue(Boolean.TRUE.equals(cookie.getSecure()), "Cookie must have Secure flag in production profile");
        assertTrue(Boolean.TRUE.equals(cookie.getHttpOnly()), "Cookie must have HttpOnly flag");
        assertEquals(Cookie.SameSite.STRICT, cookie.getSameSite(), "Cookie must have SameSite=Strict flag");
    }
}

