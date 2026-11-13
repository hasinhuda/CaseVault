package com.casevault.web;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

/** SEC-COOKIE-01..05 on the local http profile: Secure is intentionally ABSENT (a browser would not send it over http). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("local")
// Phase 9E: its own in-memory database. The local profile now also creates demo data on first start; that must not
// land in the database shared by the other test classes.
@TestPropertySource(properties = {
        "casevault.ratelimit.login-limit=100000",
        "spring.datasource.url=jdbc:h2:mem:casevault_cookie_local_test;DB_CLOSE_DELAY=-1"
})
class SessionCookieLocalHttpTest extends AbstractSessionCookieHttpTest {
    @Override
    boolean secureExpected() {
        return false;
    }
}
