package com.casevault.web;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

/**
 * SEC-COOKIE-01..05 on the prod-like profile: Secure is expected. The PostgreSQL datasource of the profile is replaced
 * by H2 (as in HstsProfileTest); the cookie properties come from application-prod-like.properties unchanged.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("prod-like")
@TestPropertySource(properties = {
        "casevault.ratelimit.login-limit=100000",
        "spring.datasource.url=jdbc:h2:mem:casevault_cookie_prod_test;DB_CLOSE_DELAY=-1",
        "spring.datasource.driverClassName=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
class SessionCookieProdLikeHttpTest extends AbstractSessionCookieHttpTest {
    @Override
    boolean secureExpected() {
        return true;
    }
}
