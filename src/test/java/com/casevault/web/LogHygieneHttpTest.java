package com.casevault.web;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.service.AuditEventType;
import com.casevault.service.AuditLogService;
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
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.OutputStream;
import java.io.InputStream;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.Socket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

/**
 * Phase 8C: log hygiene over REAL HTTP. A Logback appender on the root logger captures everything the application
 * writes (at the levels it is configured for) while the main flows run; the captured text must not contain any
 * secret or personal marker used in the test, and injected CR/LF text must not forge a log line.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "casevault.ratelimit.login-limit=100000",
        "casevault.ratelimit.search-limit=4",
        "casevault.ratelimit.api-basic-limit=100000",
        "server.servlet.session.cookie.secure=false"
})
class LogHygieneHttpTest {

    private static final String PASSWORD = "Zq-Log-Hygiene-Password-1234!";
    private static final String WRONG_PASSWORD = "Zq-Wrong-Password-5678!";
    private static final String FORGED = "FORGED_LOG_LINE_MARKER";

    @TestConfiguration
    static class FaultConfig {
        @Bean
        LogFaultController logFaultController() {
            return new LogFaultController();
        }
    }

    @Controller
    static class LogFaultController {
        @GetMapping("/test-only/log-boom")
        @ResponseBody
        String boom() {
            throw new IllegalStateException("zq-secret-exception-text");
        }

        @PostMapping("/test-only/log-post-only")
        @ResponseBody
        String postOnly() {
            return "ok";
        }
    }

    @TempDir
    static Path tmp;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("casevault.audit.key-path", () -> tmp.resolve("keys").resolve("audit.key").toString());
        registry.add("casevault.storage.evidence-dir", () -> tmp.resolve("evidence").toString());
        registry.add("casevault.storage.keyset-path", () -> tmp.resolve("keyset.json").toString());
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
    @Autowired
    private Environment environment;
    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.jdbc.core.JdbcTemplate cleanupJdbc;

    @MockitoSpyBean
    private AuditLogService auditLogService;

    private Logger rootLogger;
    private ListAppender<ILoggingEvent> logs;
    private final Set<String> sessionIds = new HashSet<>();
    private final Set<String> csrfTokens = new HashSet<>();
    private final List<String> authorizationValues = new ArrayList<>();

    private String marker;
    private User client;
    private User analyst;
    private User manager;
    private User admin;
    private User victim;
    private Case caseA;

    /** One browser: its own cookie jar. */
    private final class Browser {
        final HttpClient http;
        final CookieManager cookies = new CookieManager();

        Browser() {
            http = HttpClient.newBuilder().cookieHandler(cookies).followRedirects(HttpClient.Redirect.NEVER).build();
        }

        HttpResponse<String> get(String path) throws Exception {
            return exec(HttpRequest.newBuilder(uri(path)).header("Accept", "text/html").GET().build());
        }

        HttpResponse<String> form(String path, String body) throws Exception {
            return exec(HttpRequest.newBuilder(uri(path)).header("Accept", "text/html")
                    .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body)).build());
        }

        HttpResponse<String> multipart(String path, String filename, String content, String csrf) throws Exception {
            String boundary = "----zq" + UUID.randomUUID().toString().replace("-", "");
            String body = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n" + csrf + "\r\n"
                    + "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n"
                    + "Content-Type: text/plain\r\n\r\n" + content + "\r\n--" + boundary + "--\r\n";
            return exec(HttpRequest.newBuilder(uri(path)).header("Accept", "text/html")
                    .header("Content-Type", "multipart/form-data; boundary=" + boundary).POST(HttpRequest.BodyPublishers.ofString(body)).build());
        }

        HttpResponse<String> exec(HttpRequest request) throws Exception {
            HttpResponse<String> r = http.send(request, HttpResponse.BodyHandlers.ofString());
            for (HttpCookie c : cookies.getCookieStore().getCookies()) {
                if ("JSESSIONID".equals(c.getName())) {
                    sessionIds.add(c.getValue());
                }
            }
            Matcher m = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"|value=\"([^\"]+)\"[^>]*name=\"_csrf\"").matcher(r.body());
            while (m.find()) {
                csrfTokens.add(m.group(1) != null ? m.group(1) : m.group(2));
            }
            return r;
        }

        String csrf(String pagePath) throws Exception {
            Matcher m = Pattern.compile("name=\"_csrf\"[^>]*value=\"([^\"]+)\"|value=\"([^\"]+)\"[^>]*name=\"_csrf\"").matcher(get(pagePath).body());
            assertTrue(m.find(), "csrf token in " + pagePath);
            return m.group(1) != null ? m.group(1) : m.group(2);
        }

        HttpResponse<String> login(String username, String password) throws Exception {
            String token = csrf("/login");
            return form("/login", "username=" + enc(username) + "&password=" + enc(password) + "&_csrf=" + enc(token));
        }

        Browser loginOk(User user) throws Exception {
            HttpResponse<String> r = login(user.getUsername(), PASSWORD);
            assertEquals(302, r.statusCode());
            assertTrue(r.headers().firstValue("Location").orElse("").endsWith("/dashboard"));
            return this;
        }

        HttpResponse<String> post(String path, String sourcePage, String extra) throws Exception {
            return form(path, "_csrf=" + enc(csrf(sourcePage)) + (extra == null ? "" : "&" + extra));
        }
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    @BeforeEach
    void setUp() {
        rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        logs = new ListAppender<>();
        logs.start();
        rootLogger.addAppender(logs);

        String suffix = UUID.randomUUID().toString().substring(0, 8);
        marker = "zqmark" + suffix;
        Instant now = Instant.now();
        Organisation internal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        Organisation org = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "LH " + suffix, "LH_" + suffix, now));
        String hash = passwordEncoder.encode(PASSWORD);
        client = user(marker + "_client", org, Role.CLIENT, hash);
        analyst = user(marker + "_analyst", internal, Role.ANALYST, hash);
        manager = user(marker + "_manager", internal, Role.MANAGER, hash);
        admin = user(marker + "_admin", internal, Role.AUDITOR_ADMIN, hash);
        victim = user(marker + "_victim", internal, Role.ANALYST, hash);
        caseA = caseRepository.save(new Case(UUID.randomUUID().toString(), org, "LH case " + suffix, "RANSOMWARE", "HIGH",
                "IN_PROGRESS", client, analyst, now));
    }

    @AfterEach
    void tearDown() {
        com.casevault.support.TestDatabaseCleaner.deleteReports(cleanupJdbc); // F-008: leave no committed report rows behind
        reset(auditLogService);
        rootLogger.detachAppender(logs);
        logs.stop();
    }

    private User user(String name, Organisation org, Role role, String hash) {
        return userRepository.save(new User(UUID.randomUUID().toString(), org, name, hash, role, name + "@test.local", true, Instant.now()));
    }

    private String captured() {
        StringBuilder sb = new StringBuilder();
        for (ILoggingEvent e : new ArrayList<>(logs.list)) {
            sb.append(e.getLoggerName()).append(' ').append(e.getLevel()).append(' ').append(e.getFormattedMessage()).append('\n');
            e.getMDCPropertyMap().forEach((k, v) -> sb.append(k).append('=').append(v).append('\n'));
            if (e.getThrowableProxy() != null) {
                sb.append(ThrowableProxyUtil.asString(e.getThrowableProxy())).append('\n');
            }
        }
        return sb.toString();
    }

    @Test
    @DisplayName("SEC-LOG-01: across login (success, wrong password, unknown user, lockout), logout, case create, evidence upload/reject/download, "
            + "report create/submit/approve, admin disable/enable/revoke, 429, 404/405/500 and an audit append failure, the captured log never "
            + "contains passwords, usernames, session ids, CSRF tokens, Authorization values, file names/content, report text, key material, hashes or SQL")
    void noSecretsInLogs() throws Exception {
        String fileMarker = "zq-evidence-name-" + UUID.randomUUID().toString().substring(0, 8);
        String contentMarker = "zq-evidence-content-" + UUID.randomUUID();
        String reportMarker = "zq-report-body-" + UUID.randomUUID();
        String unknownUser = marker + "_nobody";

        // --- login success / failure / unknown user / lockout / logout
        Browser anonymous = new Browser();
        assertEquals(302, anonymous.login(client.getUsername(), WRONG_PASSWORD).statusCode());
        assertEquals(302, anonymous.login(unknownUser, WRONG_PASSWORD).statusCode());
        User locked = user(marker + "_locked", client.getOrganisation(), Role.CLIENT, passwordEncoder.encode(PASSWORD));
        for (int i = 0; i < 6; i++) {
            anonymous.login(locked.getUsername(), i < 5 ? WRONG_PASSWORD : PASSWORD);
        }
        Browser clientBrowser = new Browser().loginOk(client);
        String basic = Base64.getEncoder().encodeToString((client.getUsername() + ":" + PASSWORD).getBytes(StandardCharsets.UTF_8));
        authorizationValues.add(basic);
        HttpResponse<String> basicCall = anonymous.exec(HttpRequest.newBuilder(uri("/api/cases")).header("Authorization", "Basic " + basic)
                .header("Accept", "application/json").GET().build());
        assertEquals(200, basicCall.statusCode());
        String badBasic = Base64.getEncoder().encodeToString((client.getUsername() + ":" + WRONG_PASSWORD).getBytes(StandardCharsets.UTF_8));
        authorizationValues.add(badBasic);
        anonymous.exec(HttpRequest.newBuilder(uri("/api/cases")).header("Authorization", "Basic " + badBasic).header("Accept", "application/json").GET().build());

        // --- case create (form) and evidence upload / reject / download
        String title = "zq-case-title-" + UUID.randomUUID().toString().substring(0, 8);
        HttpResponse<String> created = clientBrowser.post("/cases", "/cases/new", "title=" + enc(title) + "&category=PHISHING&severity=LOW");
        assertEquals(302, created.statusCode());
        String casePath = "/cases/" + caseA.getId();
        String csrf = clientBrowser.csrf(casePath);
        HttpResponse<String> upload = clientBrowser.multipart(casePath + "/evidence", fileMarker + ".txt", contentMarker, csrf);
        assertEquals(302, upload.statusCode(), upload.body());
        HttpResponse<String> rejected = clientBrowser.multipart(casePath + "/evidence", fileMarker + "-bad.exe", contentMarker, csrf);
        assertTrue(rejected.statusCode() >= 400, "rejected upload: " + rejected.statusCode());
        String evidenceTab = clientBrowser.get(casePath + "?tab=evidence").body();
        Matcher link = Pattern.compile("/cases/" + caseA.getId() + "/evidence/([0-9a-f-]{36})").matcher(evidenceTab);
        assertTrue(link.find(), "an evidence link must be listed");
        HttpResponse<String> download = clientBrowser.get(casePath + "/evidence/" + link.group(1));
        assertEquals(200, download.statusCode());
        assertTrue(download.body().contains(contentMarker), "the download returns the stored content");

        // --- reports: analyst creates and submits, manager approves
        Browser analystBrowser = new Browser().loginOk(analyst);
        String reportsPath = casePath + "/reports";
        HttpResponse<String> report = analystBrowser.post(reportsPath, reportsPath, "body=" + enc(reportMarker));
        assertEquals(302, report.statusCode(), report.body());
        String reportPath = report.headers().firstValue("Location").orElseThrow().replaceFirst("^https?://[^/]+", "");
        assertEquals(302, analystBrowser.post(reportPath + "/submit", reportPath, null).statusCode());
        Browser managerBrowser = new Browser().loginOk(manager);
        assertEquals(302, managerBrowser.post(reportPath + "/approve", reportPath, null).statusCode());

        // --- admin disable / enable / revoke
        Browser adminBrowser = new Browser().loginOk(admin);
        assertEquals(302, adminBrowser.post("/admin/users/" + victim.getId() + "/revoke-sessions", "/admin/users", null).statusCode());
        assertEquals(302, adminBrowser.post("/admin/users/" + victim.getId() + "/disable", "/admin/users", null).statusCode());
        assertEquals(302, adminBrowser.post("/admin/users/" + victim.getId() + "/enable", "/admin/users", null).statusCode());

        // --- rate limit (search limit is 4 in this test), 404 / 405 / 500
        int limited = 0;
        for (int i = 0; i < 8; i++) {
            if (clientBrowser.get("/cases?q=" + enc(marker + "_search")).statusCode() == 429) {
                limited++;
            }
        }
        assertTrue(limited > 0, "the 429 path must have been exercised");
        assertEquals(404, clientBrowser.get("/no-such-page-" + marker).statusCode());
        assertEquals(405, clientBrowser.get("/test-only/log-post-only").statusCode());
        assertEquals(500, clientBrowser.get("/test-only/log-boom").statusCode());

        // --- audit append failure: the business action commits, the user gets the safe 500 page
        doThrow(new IllegalStateException("zq-audit-secret-" + marker)).when(auditLogService)
                .recordEvent(eq(AuditEventType.CASE_CREATED), any(), any(), any());
        HttpResponse<String> failing = new Browser().loginOk(client).post("/cases", "/cases/new",
                "title=" + enc("zq-failing-" + title) + "&category=PHISHING&severity=LOW");
        assertEquals(500, failing.statusCode());
        reset(auditLogService);

        // --- assertions on the captured text
        String text = captured();
        assertTrue(text.length() > 500, "the application wrote log lines during the flows");
        List<String> forbidden = new ArrayList<>(List.of(PASSWORD, WRONG_PASSWORD, marker, fileMarker, contentMarker, reportMarker,
                "$argon2", "argon2id"));
        // Not listed on purpose: the text of an unexpected exception (the test-only 500 and the audit failure). The
        // server log keeps it for diagnosis; it never reaches the user (SEC-ERR-05, SEC-AUDIT-WIRE-12).
        forbidden.addAll(sessionIds);
        forbidden.addAll(csrfTokens);
        forbidden.addAll(authorizationValues);
        forbidden.add("Basic " + basic);
        for (String needle : forbidden) {
            assertFalse(text.contains(needle), "the log must not contain: " + (needle.length() > 12 ? needle.substring(0, 8) + "..." : needle));
        }
        assertFalse(sessionIds.isEmpty() || csrfTokens.isEmpty(), "the test did collect session ids and CSRF tokens");
        // key material
        Path auditKey = tmp.resolve("keys").resolve("audit.key");
        if (Files.exists(auditKey)) {
            byte[] raw = Files.readAllBytes(auditKey);
            String asText = new String(raw, StandardCharsets.UTF_8).trim();
            assertFalse(asText.length() >= 16 && text.contains(asText), "audit HMAC key text");
            assertFalse(text.contains(Base64.getEncoder().encodeToString(raw)), "audit HMAC key (base64)");
            assertFalse(text.contains(java.util.HexFormat.of().formatHex(raw)), "audit HMAC key (hex)");
        }
        Path keyset = tmp.resolve("keyset.json");
        if (Files.exists(keyset)) {
            Matcher values = Pattern.compile("\"(?:value|keyMaterial|encryptedKeyset)\"\\s*:\\s*\"([^\"]{16,})\"").matcher(Files.readString(keyset));
            while (values.find()) {
                assertFalse(text.contains(values.group(1)), "Tink keyset material");
            }
        }
        // SQL
        String lower = text.toLowerCase(Locale.ROOT);
        for (String sql : List.of("select ", "insert into", "update users", "delete from", " where ", "from users", "values (")) {
            assertFalse(lower.contains(sql), "no SQL text in the log: " + sql);
        }
    }

    @Test
    @DisplayName("SEC-LOG-02: CR/LF and fake log text sent through a form field, a file name and a request header never forge a log line (the marker text does not reach the log at all)")
    void logForgingIsHarmless() throws Exception {
        Browser anonymous = new Browser();
        String forgedUser = "zqinj\r\n2026-01-01 INFO " + FORGED + " admin logged in";
        anonymous.login(forgedUser, WRONG_PASSWORD);
        anonymous.login("zqinj%0D%0A" + FORGED, WRONG_PASSWORD);

        Browser clientBrowser = new Browser().loginOk(client);
        String casePath = "/cases/" + caseA.getId();
        String csrf = clientBrowser.csrf(casePath);
        clientBrowser.multipart(casePath + "/evidence", "zq-inj%0D%0A" + FORGED + ".txt", "synthetic text", csrf);
        clientBrowser.multipart(casePath + "/evidence", "zq-inj\\r\\n" + FORGED + ".txt", "synthetic text", csrf);
        clientBrowser.multipart(casePath + "/evidence", "zq-inj\n" + FORGED + "-lf.txt", "synthetic text", csrf);
        anonymous.get("/no-such-" + enc("x\r\n" + FORGED));
        anonymous.exec(HttpRequest.newBuilder(uri("/login")).header("X-Correlation-ID", "not-a-uuid%0d%0a" + FORGED).GET().build());

        // a REAL line break inside a request header value, which an HTTP client library refuses to send
        try (Socket socket = new Socket("localhost", port)) {
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            out.write(("GET /no-such-raw HTTP/1.1\r\nHost: localhost\r\nUser-Agent: zq\n" + FORGED + " fake line\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[256];
            int ignored = in.read(buffer);
            assertNotEquals(-2, ignored);
        } catch (java.net.SocketTimeoutException e) {
            // no answer is acceptable; the assertion below is about the log
        }

        String text = captured();
        assertFalse(text.contains(FORGED), "injected text must not reach the log");
        for (ILoggingEvent e : new ArrayList<>(logs.list)) {
            // Tomcat's own fixed two-line text for a malformed header ("Error parsing HTTP request header / Note: ...")
            // is not request-derived; the marker assertion above proves the injected text is not in it.
            if (e.getLoggerName().startsWith("org.apache.coyote") || e.getLoggerName().startsWith("org.apache.tomcat")
                    || e.getLoggerName().startsWith("org.apache.catalina")) {
                continue;
            }
            assertFalse(e.getFormattedMessage().contains("\r") || e.getFormattedMessage().contains("\n"),
                    "no log message may contain a line break: " + e.getLoggerName() + " | "
                            + e.getFormattedMessage().replace("\n", "<LF>").replace("\r", "<CR>"));
        }
    }

    @Test
    @DisplayName("SEC-LOG-03: logging configuration: the root level is not DEBUG/TRACE, SQL and bind logging are off, show-sql is false, also in the prod-like property file")
    void loggingConfiguration() throws Exception {
        assertTrue(rootLogger.getLevel() == null || rootLogger.getLevel().isGreaterOrEqual(Level.INFO), "root level: " + rootLogger.getLevel());
        for (String name : List.of("org.hibernate.SQL", "org.hibernate.orm.jdbc.bind", "org.hibernate.type.descriptor.sql", "org.springframework.jdbc.core")) {
            Logger l = (Logger) LoggerFactory.getLogger(name);
            assertTrue(l.getEffectiveLevel().isGreaterOrEqual(Level.INFO), name + " effective level " + l.getEffectiveLevel());
        }
        assertTrue(!"true".equalsIgnoreCase(environment.getProperty("spring.jpa.show-sql", "false")));

        for (String file : List.of("src/main/resources/application.properties", "src/main/resources/application-prod-like.properties",
                "src/main/resources/application-local.properties")) {
            Properties props = new Properties();
            try (var in = Files.newBufferedReader(Path.of(file))) {
                props.load(in);
            }
            for (String key : props.stringPropertyNames()) {
                String value = props.getProperty(key).trim().toUpperCase(Locale.ROOT);
                if (key.startsWith("logging.level.") || key.equals("debug") || key.equals("trace")) {
                    assertFalse(value.equals("DEBUG") || value.equals("TRACE") || value.equals("TRUE") || value.equals("ALL"), file + " " + key);
                }
                assertFalse(key.equals("spring.jpa.show-sql") && value.equals("TRUE"), file + " " + key);
                assertFalse(key.equals("spring.jpa.properties.hibernate.show_sql") && value.equals("TRUE"), file + " " + key);
                assertFalse(key.equals("spring.jpa.properties.hibernate.format_sql") && value.equals("TRUE"), file + " " + key);
                assertFalse(key.contains("org.hibernate.SQL") || key.contains("hibernate.orm.jdbc.bind"), file + " " + key);
            }
        }
    }
}
