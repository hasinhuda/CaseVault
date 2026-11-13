package com.casevault.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 12A: the prod-like profile behind a TLS-terminating reverse proxy, over REAL HTTP. The test client plays the
 * proxy: it connects from 127.0.0.1 (an internal proxy address) and sets X-Forwarded-Proto/Host/For the way the
 * documented proxy configuration does. PostgreSQL is replaced by H2 (as in HstsProfileTest).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("prod-like")
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:casevault_proxy_test;DB_CLOSE_DELAY=-1",
        "spring.datasource.driverClassName=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "casevault.ratelimit.login-limit=3"
})
class ProxyHeadersHttpTest {

    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"|value=\"([^\"]+)\"[^>]*name=\"_csrf\"");

    @TempDir
    static Path sharedTempDir;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("casevault.audit.key-path", () -> sharedTempDir.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
    }

    @LocalServerPort
    int port;

    private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    private HttpRequest.Builder request(String path, String forwardedFor) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("Accept", "text/html")
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", "casevault.example.test")
                .header("X-Forwarded-Port", "443");
        if (forwardedFor != null) {
            b.header("X-Forwarded-For", forwardedFor);
        }
        return b;
    }

    private HttpResponse<String> send(HttpRequest.Builder b) throws Exception {
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** One login attempt with an unknown user: GET /login for session and token, then POST /login. Returns the POST status. */
    private int loginAttempt(String forwardedFor) throws Exception {
        HttpResponse<String> page = send(request("/login", forwardedFor));
        String setCookie = page.headers().allValues("Set-Cookie").stream().filter(c -> c.startsWith("JSESSIONID=")).findFirst().orElseThrow();
        String cookie = setCookie.substring(0, setCookie.indexOf(';'));
        Matcher m = CSRF.matcher(page.body());
        assertTrue(m.find(), "csrf token");
        String token = m.group(1) != null ? m.group(1) : m.group(2);
        String form = "username=" + URLEncoder.encode("nobody_" + UUID.randomUUID(), StandardCharsets.UTF_8)
                + "&password=x&_csrf=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
        HttpResponse<String> post = send(request("/login", forwardedFor).header("Cookie", cookie)
                .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)));
        return post.statusCode();
    }

    @Test
    @DisplayName("PROXY-01: behind the proxy a redirect for a signed-out request uses https and the forwarded host, with no ;jsessionid")
    void redirectUsesForwardedSchemeAndHost() throws Exception {
        HttpResponse<String> r = send(request("/dashboard", "203.0.113.9"));
        assertEquals(302, r.statusCode());
        String location = r.headers().firstValue("Location").orElse("");
        assertEquals("https://casevault.example.test/login", location);
        assertFalse(location.toLowerCase(Locale.ROOT).contains("jsessionid"));
    }

    @Test
    @DisplayName("PROXY-02: the login page behind the proxy sets a Secure, HttpOnly, SameSite=Strict session cookie and has no ;jsessionid anywhere")
    void cookieIsSecureAndNoSessionIdInBody() throws Exception {
        HttpResponse<String> r = send(request("/login", "203.0.113.9"));
        assertEquals(200, r.statusCode());
        String cookie = r.headers().allValues("Set-Cookie").stream().filter(c -> c.startsWith("JSESSIONID=")).findFirst().orElseThrow().toLowerCase(Locale.ROOT);
        assertTrue(cookie.contains("; secure"), cookie.replaceFirst("jsessionid=[^;]*", "jsessionid=<id>"));
        assertTrue(cookie.contains("; httponly"));
        assertTrue(cookie.contains("samesite=strict"));
        assertFalse(r.body().toLowerCase(Locale.ROOT).contains("jsessionid"));
        assertFalse(r.headers().firstValue("Location").isPresent());
    }

    @Test
    @DisplayName("PROXY-03: the limiter key is the client address the proxy saw: spoofed X-Forwarded-For entries on the left are ignored, rotating them does not reset the limit, and another client has its own budget")
    void spoofedForwardedForCannotChooseTheKey() throws Exception {
        // the proxy overwrote the header with the real client address; a client-supplied prefix may be present
        assertEquals(302, loginAttempt("9.9.9.1, 203.0.113.50"));
        assertEquals(302, loginAttempt("9.9.9.2, 203.0.113.50"));
        assertEquals(302, loginAttempt("9.9.9.3, 203.0.113.50"));
        assertEquals(429, loginAttempt("9.9.9.4, 203.0.113.50"), "rotating the spoofed prefix does not give a fresh budget");
        assertEquals(429, loginAttempt("203.0.113.50"), "the same real client is limited without the prefix too");
        assertEquals(302, loginAttempt("203.0.113.51"), "another real client behind the same proxy has its own budget");
    }

    @Test
    @DisplayName("PROXY-04: with the documented overwrite configuration (one header entry written by the proxy) a client on a private address is its own key: its budget is counted per address, not shared; "
            + "residual risk: if a proxy APPENDED instead of overwriting and the real client address is private, the left-most entry would be believed (see ADR 0009)")
    void singleInternalEntryIsTheKey() throws Exception {
        assertEquals(302, loginAttempt("10.1.1.1"));
        assertEquals(302, loginAttempt("10.1.1.1"));
        assertEquals(302, loginAttempt("10.1.1.1"));
        assertEquals(429, loginAttempt("10.1.1.1"), "same address, same budget");
        assertEquals(302, loginAttempt("10.1.1.2"), "another address has its own budget");
    }

    @Test
    @DisplayName("PROXY-05: /actuator/health without authentication answers 200 with status UP and no component details; /actuator/info leaks nothing")
    void healthEndpointForTheContainerHealthcheck() throws Exception {
        HttpResponse<String> health = client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/actuator/health"))
                .header("Accept", "application/json").build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, health.statusCode());
        assertEquals("{\"status\":\"UP\"}", health.body());
        HttpResponse<String> info = client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/actuator/info"))
                .header("Accept", "application/json").build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, info.statusCode());
        assertEquals("{}", info.body());
        for (String leak : new String[]{"components", "details", "jdbc", "postgres", "h2", "diskSpace", "version", "java"}) {
            assertFalse((health.body() + info.body()).toLowerCase(Locale.ROOT).contains(leak), leak);
        }
    }
}
