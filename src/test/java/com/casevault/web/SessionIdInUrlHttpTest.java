package com.casevault.web;

import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 9B follow-up (finding F-010): a session id must never appear in a URL, link, form action or redirect target.
 * Real server, real HTTP, no cookie jar for the signed-out requests (a client without a cookie is exactly the case in
 * which the container used to rewrite URLs with ";jsessionid=").
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "casevault.ratelimit.login-limit=100000",
        "server.servlet.session.cookie.secure=false"
})
class SessionIdInUrlHttpTest {

    private static final String PASSWORD = "Session-Url-Password-1234!";
    private static final String MARKER = ";jsessionid=";

    @TempDir
    static Path sharedTempDir;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("casevault.audit.key-path", () -> sharedTempDir.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
    }

    @LocalServerPort
    private int port;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).header("Accept", "text/html");
    }

    private static HttpClient noCookieClient() {
        return HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    }

    private static HttpResponse<String> send(HttpClient client, HttpRequest.Builder b) throws Exception {
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static void assertNoSessionIdInUrls(HttpResponse<String> r, String where) {
        assertFalse(r.body().toLowerCase(Locale.ROOT).contains(MARKER), where + ": body has " + MARKER);
        assertFalse(r.headers().firstValue("Location").orElse("").toLowerCase(Locale.ROOT).contains(MARKER), where + ": Location has " + MARKER);
        assertFalse(r.headers().firstValue("Refresh").orElse("").toLowerCase(Locale.ROOT).contains(MARKER), where + ": Refresh has " + MARKER);
    }

    private static String csrfToken(String html) {
        Matcher m = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"|value=\"([^\"]+)\"[^>]*name=\"_csrf\"").matcher(html);
        assertTrue(m.find(), "a CSRF token must be in the page");
        return m.group(1) != null ? m.group(1) : m.group(2);
    }

    @Test
    @DisplayName("SEC-SESSURL-01: GET /login with no cookie: no ;jsessionid in body (form action, stylesheet) or Location")
    void loginPageWithoutCookie() throws Exception {
        HttpResponse<String> r = send(noCookieClient(), request("/login"));
        assertEquals(200, r.statusCode());
        assertNoSessionIdInUrls(r, "GET /login");
        assertTrue(r.body().contains("action=\"/login\""), "the form action is the plain path");
        assertTrue(r.body().contains("href=\"/css/app.css\""), "the stylesheet link is the plain path");
    }

    @Test
    @DisplayName("SEC-SESSURL-02: signed-out CSRF failure (POST /login without token, no cookie) is a 403 page with no ;jsessionid anywhere and the exact plain links")
    void csrfFailurePage() throws Exception {
        HttpResponse<String> r = send(noCookieClient(), request("/login").header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("username=a&password=b")));
        assertEquals(403, r.statusCode());
        assertNoSessionIdInUrls(r, "CSRF 403");
        assertTrue(r.body().contains("href=\"/login\""));
        assertTrue(r.body().contains("href=\"/css/app.css\""));
    }

    @Test
    @DisplayName("SEC-SESSURL-03: redirect of a signed-out request to a protected page (no cookie) goes to the plain /login")
    void protectedPageRedirect() throws Exception {
        HttpResponse<String> r = send(noCookieClient(), request("/dashboard"));
        assertEquals(302, r.statusCode());
        assertTrue(r.headers().firstValue("Location").orElse("").endsWith("/login"), r.headers().firstValue("Location").orElse(""));
        assertNoSessionIdInUrls(r, "GET /dashboard signed out");
    }

    @Test
    @DisplayName("SEC-SESSURL-04: successful login: 302 to the plain /dashboard (no ;jsessionid), the cookie is still HttpOnly + SameSite=Strict, and the dashboard works with it")
    void loginRedirectAndCookie() throws Exception {
        String name = "su_" + UUID.randomUUID().toString().substring(0, 8);
        userRepository.save(new User(UUID.randomUUID().toString(), null, name, passwordEncoder.encode(PASSWORD),
                Role.ANALYST, name + "@test.local", true, Instant.now()));
        HttpClient client = HttpClient.newBuilder().cookieHandler(new CookieManager()).followRedirects(HttpClient.Redirect.NEVER).build();
        HttpResponse<String> page = send(client, request("/login"));
        assertNoSessionIdInUrls(page, "GET /login");
        HttpResponse<String> post = send(client, request("/login").header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("username=" + URLEncoder.encode(name, StandardCharsets.UTF_8)
                        + "&password=" + URLEncoder.encode(PASSWORD, StandardCharsets.UTF_8)
                        + "&_csrf=" + URLEncoder.encode(csrfToken(page.body()), StandardCharsets.UTF_8))));
        assertEquals(302, post.statusCode());
        assertTrue(post.headers().firstValue("Location").orElse("").endsWith("/dashboard"));
        assertNoSessionIdInUrls(post, "POST /login");
        String cookie = post.headers().allValues("Set-Cookie").stream().filter(c -> c.startsWith("JSESSIONID=")).findFirst().orElse("");
        assertTrue(cookie.toLowerCase(Locale.ROOT).contains("; httponly"), "HttpOnly");
        assertTrue(cookie.toLowerCase(Locale.ROOT).contains("samesite=strict"), "SameSite=Strict");
        HttpResponse<String> dashboard = send(client, request("/dashboard"));
        assertEquals(200, dashboard.statusCode());
        assertNoSessionIdInUrls(dashboard, "GET /dashboard signed in");
        assertTrue(dashboard.body().contains("href=\"/cases\""), "plain links in a signed-in page");
    }
}
