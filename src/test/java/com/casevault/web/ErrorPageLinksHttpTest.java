package com.casevault.web;

import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
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
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 9B: the link on the error page depends on whether the visitor is signed in. Real HTTP (embedded server, real
 * container error dispatch, real login). Status codes are asserted so a link change can never hide a status change.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "casevault.ratelimit.login-limit=100000",
        "server.servlet.session.cookie.secure=false"
})
class ErrorPageLinksHttpTest {

    private static final String PASSWORD = "Error-Links-Password-1234!";
    private static final String BACK_TO_LOGIN = "Back to login";
    private static final String DASHBOARD = "Return to Dashboard";
    private static final Pattern LOGIN_LINK = Pattern.compile("href=\"/login(;jsessionid=[^\"]*)?\"");
    private static final Pattern DASHBOARD_LINK = Pattern.compile("href=\"/dashboard(;jsessionid=[^\"]*)?\"");

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
    private PasswordEncoder passwordEncoder;
    @Autowired
    private OrganisationRepository organisationRepository;
    @Autowired
    private UserRepository userRepository;

    private User user;
    private HttpClient anonymous;
    private HttpClient signedIn;

    @BeforeEach
    void setUp() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        Organisation org = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "EL " + suffix, "EL_" + suffix, now));
        user = userRepository.save(new User(UUID.randomUUID().toString(), org, "el_cl_" + suffix,
                passwordEncoder.encode(PASSWORD), Role.CLIENT, "el_" + suffix + "@test.local", true, now));
        anonymous = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        signedIn = HttpClient.newBuilder().cookieHandler(new CookieManager()).followRedirects(HttpClient.Redirect.NEVER).build();
        login();
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).header("Accept", "text/html");
    }

    private HttpResponse<String> send(HttpClient client, HttpRequest.Builder builder) throws Exception {
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String csrfToken(String html) {
        Matcher m = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"|value=\"([^\"]+)\"[^>]*name=\"_csrf\"").matcher(html);
        assertTrue(m.find(), "a CSRF token must be in the page");
        return m.group(1) != null ? m.group(1) : m.group(2);
    }

    private void login() throws Exception {
        String token = csrfToken(send(signedIn, request("/login")).body());
        HttpResponse<String> result = send(signedIn, request("/login").header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("username=" + URLEncoder.encode(user.getUsername(), StandardCharsets.UTF_8)
                        + "&password=" + URLEncoder.encode(PASSWORD, StandardCharsets.UTF_8) + "&_csrf=" + URLEncoder.encode(token, StandardCharsets.UTF_8))));
        assertEquals(302, result.statusCode());
    }

    private static void assertBackToLoginOnly(HttpResponse<String> r, int status) {
        assertEquals(status, r.statusCode(), r.body());
        assertTrue(r.body().contains(BACK_TO_LOGIN), "signed-out visitor sees Back to login");
        // the optional ;jsessionid suffix is URL rewriting that Tomcat adds after a signed-out CSRF failure (finding F-010)
        assertTrue(LOGIN_LINK.matcher(r.body()).find(), "the link goes to /login");
        assertFalse(r.body().contains(DASHBOARD), "signed-out visitor must not see the Dashboard link");
        assertFalse(DASHBOARD_LINK.matcher(r.body()).find());
    }

    private static void assertDashboardOnly(HttpResponse<String> r, int status) {
        assertEquals(status, r.statusCode(), r.body());
        assertTrue(r.body().contains(DASHBOARD), "signed-in user sees Dashboard");
        assertTrue(DASHBOARD_LINK.matcher(r.body()).find(), "the link goes to /dashboard");
        assertFalse(r.body().contains(BACK_TO_LOGIN), "signed-in user must not see Back to login");
        assertFalse(LOGIN_LINK.matcher(r.body()).find());
    }

    @Test
    @DisplayName("UI-ERR-01: signed-out 404 page (missing static file, real error dispatch) shows Back to login and no Dashboard link; status stays 404")
    void anonymousNotFound() throws Exception {
        assertBackToLoginOnly(send(anonymous, request("/css/no-such-file-" + UUID.randomUUID() + ".css")), 404);
    }

    @Test
    @DisplayName("UI-ERR-02: signed-out CSRF failure (POST /login without token) is a 403 page with Back to login and no Dashboard link")
    void anonymousCsrfFailure() throws Exception {
        HttpResponse<String> r = send(anonymous, request("/login").header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("username=a&password=b")));
        assertBackToLoginOnly(r, 403);
        assertTrue(r.body().contains("HTTP 403"));
    }

    @Test
    @DisplayName("UI-ERR-03: signed-in 404 pages (unknown URL and unknown case) show Return to Dashboard and no Back to login; status stays 404")
    void signedInNotFound() throws Exception {
        assertDashboardOnly(send(signedIn, request("/no-such-page-" + UUID.randomUUID())), 404);
        assertDashboardOnly(send(signedIn, request("/cases/" + UUID.randomUUID())), 404);
    }

    @Test
    @DisplayName("UI-ERR-04: signed-in CSRF failure (POST without token) is a 403 page with Return to Dashboard and no Back to login")
    void signedInCsrfFailure() throws Exception {
        HttpResponse<String> r = send(signedIn, request("/cases/" + UUID.randomUUID() + "/notes")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("body=x")));
        assertDashboardOnly(r, 403);
    }

    @Test
    @DisplayName("UI-ERR-05: signed-in client opening an auditor-only page gets the uniform 404 (unchanged) with the Dashboard link and the correlation id")
    void signedInControllerForbidden() throws Exception {
        HttpResponse<String> r = send(signedIn, request("/admin/users"));
        // AUDITOR_ADMIN-only page: a client gets the uniform 404 (unchanged), still with the Dashboard link
        assertDashboardOnly(r, 404);
        assertTrue(Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").matcher(r.body()).find(),
                "the correlation id is still shown");
    }
}
