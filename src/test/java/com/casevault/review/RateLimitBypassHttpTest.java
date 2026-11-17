package com.casevault.review;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Stage A code review (CR-01, CR-02): the login rate limit must not be avoidable by writing the URL differently or by
 * sending credentials in an HTTP Basic header to a page outside /api. Real HTTP, no cookie jar (the session cookie
 * and CSRF token are passed by hand), the limit is lowered to 3 so the test is short.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "casevault.ratelimit.login-limit=3",
        "casevault.ratelimit.api-basic-limit=3"
})
class RateLimitBypassHttpTest {

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

    private HttpResponse<String> send(HttpRequest.Builder builder) throws Exception {
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    @DisplayName("CR-01: a percent-encoded login URL (/%6Cogin = /login) is processed as a login AND counted by the login limiter (the 4th attempt is 429)")
    void encodedLoginPathIsStillRateLimited() throws Exception {
        HttpResponse<String> page = send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/login")).header("Accept", "text/html"));
        String cookie = page.headers().allValues("Set-Cookie").stream().filter(c -> c.startsWith("JSESSIONID=")).findFirst().orElseThrow();
        cookie = cookie.substring(0, cookie.indexOf(';'));
        Matcher m = CSRF.matcher(page.body());
        assertTrue(m.find());
        String token = m.group(1) != null ? m.group(1) : m.group(2);
        List<Integer> statuses = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/%6Cogin"))
                    .header("Cookie", cookie).header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString("username=nobody_" + UUID.randomUUID() + "&password=x&_csrf=" + token)));
            statuses.add(r.statusCode());
            if (i < 3) {
                assertEquals(302, r.statusCode(), "the encoded URL is processed as a normal (failed) login");
                assertTrue(r.headers().firstValue("Location").orElse("").contains("/login?error"), r.headers().firstValue("Location").orElse(""));
            }
        }
        assertEquals(429, statuses.get(3), "statuses " + statuses);
        assertEquals(429, statuses.get(5), "statuses " + statuses);
    }

    @Test
    @DisplayName("CR-02: guessing credentials with an HTTP Basic header on a page OUTSIDE /api is limited per address like /api (the 4th attempt is 429)")
    void basicHeaderOutsideApiIsRateLimited() throws Exception {
        String header = "Basic " + Base64.getEncoder().encodeToString("nobody_x:wrong-password".getBytes(StandardCharsets.UTF_8));
        List<Integer> statuses = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            statuses.add(send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/dashboard"))
                    .header("Authorization", header).header("Accept", "text/html")).statusCode());
        }
        assertEquals(429, statuses.get(3), "statuses " + statuses);
        assertEquals(429, statuses.get(5), "statuses " + statuses);
    }
}
