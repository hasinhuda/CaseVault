package com.casevault.web;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 8B: safe error handling over REAL HTTP (embedded server, real container error dispatch to /error, real
 * login with a session cookie and CSRF token). Error causes are produced by a test-only controller registered here
 * (src/test), never by production code.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "casevault.ratelimit.login-limit=100000",
        "server.servlet.session.cookie.secure=false"
})
class ErrorHandlingHttpTest {

    private static final String PASSWORD = "Error-Handling-Password-1234!";
    private static final Pattern UUID_TEXT = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final List<String> LEAKS = List.of("Whitelabel", "Exception", "exception", "at com.", "at org.", "org.springframework",
            "java.lang", "java.sql", "jakarta.", "Caused by", "SQL", "select ", "insert ", "secret_table", "/var/secret",
            "C:\\", "SECRET", "stackTrace", "trace", "Klass", "undefinedModelValue", "secretMethod");

    /** Test-only endpoints that fail on purpose. They live in src/test and are not part of the application. */
    @TestConfiguration
    static class FaultConfig {
        @Bean
        FaultController faultController() {
            return new FaultController();
        }
    }

    @Controller
    static class FaultController {
        @GetMapping("/test-only/boom")
        @ResponseBody
        String boom() {
            throw new IllegalStateException("SECRET select * from secret_table at com.secret.Klass /var/secret/path");
        }

        @GetMapping("/test-only/db")
        @ResponseBody
        String db() {
            throw new DataIntegrityViolationException("could not execute statement; SQL [insert into secret_table]; constraint [uk_secret]");
        }

        @GetMapping("/test-only/render-boom")
        String renderBoom() {
            return "test-render-boom";
        }

        @PostMapping("/test-only/post-only")
        @ResponseBody
        String postOnly() {
            return "ok";
        }

        @GetMapping("/test-only/needs-int")
        @ResponseBody
        String needsInt(@RequestParam("n") int n) {
            return "n=" + n;
        }

        @PostMapping("/test-only/echo")
        @ResponseBody
        String echo() {
            return "echo";
        }
    }

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
    @Autowired
    private CaseRepository caseRepository;

    private HttpClient client;
    private User clientUser;
    private Case caseA;
    private Logger rootLogger;
    private ListAppender<ILoggingEvent> logs;

    private record Response(int status, HttpResponse<String> raw) {
        String body() {
            return raw.body();
        }

        String header(String name) {
            return raw.headers().firstValue(name).orElse(null);
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        logs = new ListAppender<>();
        logs.start();
        rootLogger.addAppender(logs);

        String suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        Organisation org = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "EH " + suffix, "EH_" + suffix, now));
        clientUser = userRepository.save(new User(UUID.randomUUID().toString(), org, "eh_cl_" + suffix,
                passwordEncoder.encode(PASSWORD), Role.CLIENT, "eh_" + suffix + "@test.local", true, now));
        caseA = caseRepository.save(new Case(UUID.randomUUID().toString(), org, "EH case " + suffix,
                "RANSOMWARE", "HIGH", "OPEN", clientUser, null, now));
        client = HttpClient.newBuilder().cookieHandler(new CookieManager()).followRedirects(HttpClient.Redirect.NEVER).build();
        login();
    }

    @AfterEach
    void tearDown() {
        rootLogger.detachAppender(logs);
        logs.stop();
    }

    private Response send(HttpRequest.Builder builder) throws Exception {
        HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response);
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).header("Accept", "text/html");
    }

    private void login() throws Exception {
        Response page = send(request("/login"));
        String token = csrfToken(page.body());
        Response result = send(request("/login").header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("username=" + URLEncoder.encode(clientUser.getUsername(), StandardCharsets.UTF_8)
                        + "&password=" + URLEncoder.encode(PASSWORD, StandardCharsets.UTF_8) + "&_csrf=" + URLEncoder.encode(token, StandardCharsets.UTF_8))));
        assertEquals(302, result.status());
        assertTrue(result.header("Location").endsWith("/dashboard"), result.header("Location"));
    }

    private static String csrfToken(String html) {
        Matcher m = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"|value=\"([^\"]+)\"[^>]*name=\"_csrf\"").matcher(html);
        assertTrue(m.find(), "a CSRF token must be in the page");
        return m.group(1) != null ? m.group(1) : m.group(2);
    }

    private String sessionCsrfToken() throws Exception {
        return csrfToken(send(request("/dashboard")).body());
    }

    /** The shared assertions of every error page: status, header id equals page id, nothing technical leaks. */
    private String assertSafeErrorPage(Response r, int expectedStatus) {
        assertEquals(expectedStatus, r.status(), r.body());
        String headerId = r.header("X-Correlation-ID");
        assertTrue(headerId != null && UUID_TEXT.matcher(headerId).matches(), "X-Correlation-ID header: " + headerId);
        String body = r.body();
        assertTrue(body.contains("HTTP " + expectedStatus), "page shows the status");
        assertTrue(body.contains(headerId), "the page shows the same correlation id as the header");
        for (String leak : LEAKS) {
            assertFalse(body.contains(leak), "error page must not contain: " + leak);
        }
        assertTrue(r.header("Content-Type").startsWith("text/html"));
        assertTrue(String.valueOf(r.header("Cache-Control")).contains("no-store"), "error pages are not cached");
        assertTrue(r.header("Content-Security-Policy").contains("default-src 'self'"));
        return headerId;
    }

    @Test
    @DisplayName("SEC-ERR-01: unknown URL is a safe 404 page (it used to be a 500); wrong method is a safe 405 page")
    void notFoundAndMethodNotAllowed() throws Exception {
        assertSafeErrorPage(send(request("/no-such-page-" + UUID.randomUUID())), 404);
        assertSafeErrorPage(send(request("/test-only/post-only")), 405);
        assertSafeErrorPage(send(request("/css/no-such-file.css")), 404);
    }

    @Test
    @DisplayName("SEC-ERR-02: type-mismatch parameter, bad filter value and malformed UUID give safe 400/404 pages that do not echo the input")
    void badInputPages() throws Exception {
        Response mismatch = send(request("/test-only/needs-int?n=abc-ECHO-ME"));
        assertSafeErrorPage(mismatch, 400);
        assertFalse(mismatch.body().contains("ECHO-ME"));
        Response badPage = send(request("/cases?page=abc-ECHO-ME"));
        assertSafeErrorPage(badPage, 400);
        assertFalse(badPage.body().contains("ECHO-ME"));
        Response badId = send(request("/cases/not-a-uuid-ECHO-ME"));
        assertSafeErrorPage(badId, 404);
        assertFalse(badId.body().contains("ECHO-ME"));
    }

    @Test
    @DisplayName("SEC-ERR-03: a malformed multipart request is a safe 400 page")
    void malformedMultipart() throws Exception {
        String token = sessionCsrfToken();
        Response r = send(request("/cases/" + caseA.getId() + "/evidence?_csrf=" + URLEncoder.encode(token, StandardCharsets.UTF_8))
                .header("Content-Type", "multipart/form-data; boundary=zzzz")
                .POST(HttpRequest.BodyPublishers.ofString("this is not a multipart body at all")));
        assertSafeErrorPage(r, 400);
    }

    @Test
    @DisplayName("SEC-ERR-04: a missing CSRF token is 403 and uses the safe page with a correlation id")
    void csrfFailure() throws Exception {
        Response r = send(request("/test-only/echo").POST(HttpRequest.BodyPublishers.noBody()));
        assertSafeErrorPage(r, 403);
        Response forged = send(request("/cases/" + caseA.getId() + "/reports").header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("body=x&_csrf=forged")));
        assertSafeErrorPage(forged, 403);
    }

    @Test
    @DisplayName("SEC-ERR-05: an unexpected runtime exception is a safe 500 page; the same id is in the header, the page and the ERROR log line; the exception text never reaches the client")
    void unexpectedException() throws Exception {
        Response r = send(request("/test-only/boom"));
        String id = assertSafeErrorPage(r, 500);
        List<ILoggingEvent> errors = logs.list.stream().filter(e -> e.getLevel() == Level.ERROR).toList();
        assertTrue(errors.stream().anyMatch(e -> id.equals(e.getMDCPropertyMap().get("correlationId"))),
                "an ERROR log line carries the correlation id of the response");
    }

    @Test
    @DisplayName("SEC-ERR-06: a database exception is a safe 500 page without SQL or constraint names")
    void databaseException() throws Exception {
        assertSafeErrorPage(send(request("/test-only/db")), 500);
    }

    @Test
    @DisplayName("SEC-ERR-07: an exception thrown while the template is rendered is a safe 500 page (served by the /error mechanism) with a correlation id")
    void templateRenderingException() throws Exception {
        Response r = send(request("/test-only/render-boom"));
        assertSafeErrorPage(r, 500);
    }

    @Test
    @DisplayName("SEC-ERR-08: API clients get JSON errors with the correlation id (404 for an unknown case and an unknown path), no stack trace")
    void jsonErrors() throws Exception {
        for (String path : List.of("/api/cases/" + UUID.randomUUID(), "/api/no-such-endpoint")) {
            Response r = send(request(path).header("Accept", "application/json"));
            assertEquals(404, r.status(), path);
            String id = r.header("X-Correlation-ID");
            assertTrue(r.header("Content-Type").startsWith("application/json"));
            assertTrue(r.body().contains("\"correlationId\":\"" + id + "\""), r.body());
            for (String leak : LEAKS) {
                assertFalse(r.body().contains(leak), "JSON error must not contain: " + leak);
            }
        }
    }

    @Test
    @DisplayName("SEC-ERR-09: an unauthenticated request for an unknown URL still goes to the login page, not to an error page")
    void unauthenticatedStillRedirects() throws Exception {
        HttpClient anonymous = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        HttpResponse<String> r = anonymous.send(request("/no-such-page").build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(302, r.statusCode());
        assertTrue(r.headers().firstValue("Location").orElse("").endsWith("/login"));
        assertTrue(r.headers().firstValue("X-Correlation-ID").isPresent());
    }
}
