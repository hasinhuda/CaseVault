package com.casevault.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Phase 8B: Strict-Transport-Security is PRESENT with the prod-like profile (max-age one year, includeSubDomains).
 * The profile's PostgreSQL datasource is replaced by H2 so the test needs no database. HSTS is only honoured by a
 * browser over https, and Spring Security writes it only on secure requests; MockMvc marks the request secure.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("prod-like")
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:casevault_hsts_test;DB_CLOSE_DELAY=-1",
        "spring.datasource.driverClassName=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect"
})
class HstsProfileTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("SEC-HDR-02: with the prod-like profile an https request gets Strict-Transport-Security max-age=31536000 and includeSubDomains; a plain http request does not (a browser ignores HSTS over http anyway)")
    void hstsPresentOnProdLike() throws Exception {
        MvcResult secure = mockMvc.perform(get("/login").secure(true)).andReturn();
        String hsts = secure.getResponse().getHeader("Strict-Transport-Security");
        assertTrue(hsts != null && hsts.contains("max-age=31536000") && hsts.contains("includeSubDomains"), String.valueOf(hsts));
        assertEquals(null, mockMvc.perform(get("/login")).andReturn().getResponse().getHeader("Strict-Transport-Security"));
        // the other headers are the same on this profile
        assertEquals("nosniff", secure.getResponse().getHeader("X-Content-Type-Options"));
        assertEquals("same-origin", secure.getResponse().getHeader("Cross-Origin-Opener-Policy"));
        assertTrue(secure.getResponse().getHeaders("Content-Security-Policy").size() >= 2);
    }
}
