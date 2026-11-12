package com.casevault.web;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

/** SEC-COOKIE-01..05 on the local http profile: Secure is intentionally ABSENT (a browser would not send it over http). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("local")
@TestPropertySource(properties = "casevault.ratelimit.login-limit=100000")
class SessionCookieLocalHttpTest extends AbstractSessionCookieHttpTest {
    @Override
    boolean secureExpected() {
        return false;
    }
}
