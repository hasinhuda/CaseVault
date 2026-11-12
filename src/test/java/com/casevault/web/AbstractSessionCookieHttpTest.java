package com.casevault.web;

import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 8C: the session cookie as a browser would see it, over REAL HTTP (embedded server). The cookies are handled
 * by hand (no cookie manager) so the raw Set-Cookie header lines can be inspected, also with the Secure flag, which a
 * client would not send back over http. Subclasses choose the profile and whether Secure is expected.
 */
abstract class AbstractSessionCookieHttpTest {

    private static final String PASSWORD = "Cookie-Test-Password-1234!";

    @TempDir
    static Path sharedTempDir;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("casevault.audit.key-path", () -> sharedTempDir.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> sharedTempDir.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> sharedTempDir.resolve("keyset.json").toString());
        registry.add("casevault.bootstrap.credentials-dir", () -> sharedTempDir.resolve("bootstrap").toString());
    }

    @LocalServerPort
    private int port;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private final List<HttpResponse<String>> seen = new ArrayList<>();

    /** True on the prod-like profile (Secure expected), false on the local http profile (Secure intentionally absent). */
    abstract boolean secureExpected();

    private HttpResponse<String> send(String method, String path, String cookie, String form) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).header("Accept", "text/html");
        if (cookie != null) {
            b.header("Cookie", cookie);
        }
        if (form != null) {
            b.header("Content-Type", "application/x-www-form-urlencoded").method(method, HttpRequest.BodyPublishers.ofString(form));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> r = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        seen.add(r);
        return r;
    }

    private static List<String> setCookies(HttpResponse<String> r) {
        return r.headers().allValues("Set-Cookie");
    }

    private static String sessionSetCookie(HttpResponse<String> r) {
        return setCookies(r).stream().filter(c -> c.startsWith("JSESSIONID=")).findFirst().orElse(null);
    }

    private static String idOf(String setCookie) {
        return setCookie.substring("JSESSIONID=".length(), setCookie.indexOf(';'));
    }

    private static String csrf(String html) {
        Matcher m = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"|value=\"([^\"]+)\"[^>]*name=\"_csrf\"").matcher(html);
        assertTrue(m.find(), "a CSRF token must be in the page");
        return m.group(1) != null ? m.group(1) : m.group(2);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private User user() {
        String name = "ck_" + UUID.randomUUID().toString().substring(0, 8);
        return userRepository.save(new User(UUID.randomUUID().toString(), null, name, passwordEncoder.encode(PASSWORD),
                Role.ANALYST, name + "@casevault.local", true, Instant.now()));
    }

    private void assertFlags(String setCookie, String where) {
        String lower = setCookie.toLowerCase(Locale.ROOT);
        assertTrue(lower.contains("; httponly"), where + " HttpOnly: " + redact(setCookie));
        assertTrue(lower.contains("samesite=strict"), where + " SameSite=Strict: " + redact(setCookie));
        assertTrue(lower.contains("path=/"), where + " Path=/: " + redact(setCookie));
        assertEquals(secureExpected(), lower.contains("; secure"), where + " Secure flag: " + redact(setCookie));
        assertFalse(lower.contains("max-age"), where + " no Max-Age (session cookie): " + redact(setCookie));
        assertFalse(lower.contains("expires"), where + " no Expires (session cookie): " + redact(setCookie));
        assertFalse(lower.contains("domain="), where + " host-only cookie, no Domain: " + redact(setCookie));
    }

    private static String redact(String setCookie) {
        return setCookie.replaceFirst("JSESSIONID=[^;]*", "JSESSIONID=<id>");
    }

    /** Logs in over HTTP: returns {cookie after login, csrf token of the new session}. */
    private String[] loginFlow(User user, String[] preLoginIdOut) throws Exception {
        HttpResponse<String> page = send("GET", "/login", null, null);
        String pre = sessionSetCookie(page);
        assertTrue(pre != null, "the login page creates the pre-login session (it holds the CSRF token)");
        assertFlags(pre, "login page");
        if (preLoginIdOut != null) {
            preLoginIdOut[0] = idOf(pre);
        }
        HttpResponse<String> post = send("POST", "/login", "JSESSIONID=" + idOf(pre),
                "username=" + enc(user.getUsername()) + "&password=" + enc(PASSWORD) + "&_csrf=" + enc(csrf(page.body())));
        assertEquals(302, post.statusCode());
        String after = sessionSetCookie(post);
        assertTrue(after != null, "POST /login sets a new session cookie");
        assertFlags(after, "POST /login");
        return new String[]{"JSESSIONID=" + idOf(after), after};
    }

    @Test
    @DisplayName("SEC-COOKIE-01: Set-Cookie of POST /login: HttpOnly, SameSite=Strict, Path=/, Secure only on prod-like, no Max-Age/Expires/Domain")
    void flagsOnLogin() throws Exception {
        loginFlow(user(), null);
    }

    @Test
    @DisplayName("SEC-COOKIE-02: the session id changes on login (fixation): the id before login is not valid and differs from the id after")
    void idChangesOnLogin() throws Exception {
        String[] pre = new String[1];
        String[] after = loginFlow(user(), pre);
        assertNotEquals(pre[0], idOf(after[1]));
        // the old (pre-login) id does not give access
        HttpResponse<String> old = send("GET", "/dashboard", "JSESSIONID=" + pre[0], null);
        assertEquals(302, old.statusCode());
        assertTrue(old.headers().firstValue("Location").orElse("").contains("/login"));
        HttpResponse<String> fresh = send("GET", "/dashboard", after[0], null);
        assertEquals(200, fresh.statusCode());
    }

    @Test
    @DisplayName("SEC-COOKIE-03: no remember-me cookie and no other cookie than JSESSIONID in any response of the login/logout flow")
    void onlySessionCookie() throws Exception {
        String[] login = loginFlow(user(), null);
        send("GET", "/dashboard", login[0], null);
        HttpResponse<String> logout = send("POST", "/logout", login[0], "_csrf=" + enc(csrf(send("GET", "/dashboard", login[0], null).body())));
        assertEquals(302, logout.statusCode());
        for (HttpResponse<String> r : seen) {
            for (String c : setCookies(r)) {
                assertTrue(c.startsWith("JSESSIONID="), "only the session cookie may be set, saw: " + c.substring(0, Math.min(12, c.length())));
                assertFalse(c.toLowerCase(Locale.ROOT).contains("remember"));
            }
        }
    }

    @Test
    @DisplayName("SEC-COOKIE-04: logout invalidates the server session and clears the cookie (empty value, Max-Age=0); the old id no longer works")
    void logoutClears() throws Exception {
        String[] login = loginFlow(user(), null);
        HttpResponse<String> logout = send("POST", "/logout", login[0], "_csrf=" + enc(csrf(send("GET", "/dashboard", login[0], null).body())));
        assertEquals(302, logout.statusCode());
        assertTrue(logout.headers().firstValue("Location").orElse("").endsWith("/login?logout=true"));
        String cleared = sessionSetCookie(logout);
        assertTrue(cleared != null && cleared.startsWith("JSESSIONID=;"), "the cookie is cleared: " + (cleared == null ? null : redact(cleared)));
        assertTrue(cleared.toLowerCase(Locale.ROOT).contains("max-age=0"));
        HttpResponse<String> reuse = send("GET", "/dashboard", login[0], null);
        assertEquals(302, reuse.statusCode(), "the invalidated session id gives no access");
        assertTrue(reuse.headers().firstValue("Location").orElse("").contains("/login"));
    }

    @Test
    @DisplayName("SEC-COOKIE-05: the session id never appears in a URL, a redirect Location or a response body")
    void sessionIdNeverInUrlOrBody() throws Exception {
        String[] pre = new String[1];
        String[] login = loginFlow(user(), pre);
        send("GET", "/dashboard", login[0], null);
        send("GET", "/cases", login[0], null);
        send("GET", "/no-such-page-" + UUID.randomUUID(), login[0], null);
        String id = idOf(login[1]);
        for (HttpResponse<String> r : seen) {
            assertFalse(r.uri().toString().contains(id) || r.uri().toString().contains(pre[0]), "request URL");
            assertFalse(r.headers().firstValue("Location").orElse("").toLowerCase(Locale.ROOT).contains("jsessionid"), "Location");
            assertFalse(r.headers().firstValue("Location").orElse("").contains(id), "Location");
            assertFalse(r.body().contains(id) || r.body().contains(pre[0]), "response body");
            assertFalse(r.body().toLowerCase(Locale.ROOT).contains("jsessionid"), "response body");
        }
    }
}
