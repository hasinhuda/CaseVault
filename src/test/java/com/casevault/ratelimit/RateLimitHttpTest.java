package com.casevault.ratelimit;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.ratelimit.InMemoryRateLimiterTest.MutableClock;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 8A: the rate limits over HTTP through the real security filter chain (H2, injectable clock, no sleeping).
 * Every test uses its own client address and its own users, because the limiter state lives as long as the context.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "casevault.ratelimit.login-limit=10",
        "casevault.ratelimit.api-basic-limit=3",
        "casevault.ratelimit.search-limit=3",
        "casevault.ratelimit.upload-limit=2",
        "casevault.ratelimit.report-write-limit=3"
})
class RateLimitHttpTest {

    private static final String PASSWORD = "Rate-Limit-Password-1234!";
    private static final Pattern UUID_TEXT = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final AtomicInteger ADDRESS_COUNTER = new AtomicInteger();

    @TestConfiguration
    static class ClockConfig {
        @Bean
        @Primary
        MutableClock testClock() {
            return new MutableClock();
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

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private MutableClock clock;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private OrganisationRepository organisationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CaseRepository caseRepository;

    private Organisation orgA;
    private Organisation orgB;
    private Organisation internal;
    private User clientA;
    private User clientB;
    private User analyst;
    private User analystTwo;
    private Case caseA;
    private Case caseB;
    private String suffix;
    private String address;
    private Logger rootLogger;
    private ListAppender<ILoggingEvent> logs;

    @BeforeEach
    void setUp() {
        rootLogger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        logs = new ListAppender<>();
        logs.start();
        rootLogger.addAppender(logs);
        int n = ADDRESS_COUNTER.incrementAndGet();
        address = "10.77." + (n / 250) + "." + (n % 250 + 1);

        suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        internal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(
                        new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        orgA = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "RL A " + suffix, "RL_A_" + suffix, now));
        orgB = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "RL B " + suffix, "RL_B_" + suffix, now));
        String hash = passwordEncoder.encode(PASSWORD);
        clientA = user("rl_ca_" + suffix, orgA, Role.CLIENT, hash);
        clientB = user("rl_cb_" + suffix, orgB, Role.CLIENT, hash);
        analyst = user("rl_an_" + suffix, internal, Role.ANALYST, hash);
        analystTwo = user("rl_a2_" + suffix, internal, Role.ANALYST, hash);
        caseA = caseRepository.save(new Case(UUID.randomUUID().toString(), orgA, "RL case A " + suffix,
                "RANSOMWARE", "HIGH", "IN_PROGRESS", clientA, analyst, now));
        caseB = caseRepository.save(new Case(UUID.randomUUID().toString(), orgB, "RL case B " + suffix,
                "PHISHING", "LOW", "IN_PROGRESS", clientB, analystTwo, now));
    }

    @AfterEach
    void tearDown() {
        com.casevault.support.TestDatabaseCleaner.deleteReports(jdbc); // F-008: leave no committed report rows behind
        rootLogger.detachAppender(logs);
        logs.stop();
    }

    private User user(String name, Organisation org, Role role, String hash) {
        return userRepository.save(new User(UUID.randomUUID().toString(), org, name, hash, role,
                name + "@test.local", true, Instant.now()));
    }

    private static Authentication auth(User u) {
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(u, Instant.now());
        return new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities());
    }

    private static RequestPostProcessor from(String remoteAddress) {
        return request -> {
            request.setRemoteAddr(remoteAddress);
            return request;
        };
    }

    private MvcResult login(String from, String username, String password) throws Exception {
        return mockMvc.perform(post("/login").with(csrf()).with(from(from))
                .param("username", username).param("password", password)).andReturn();
    }

    private static String nextAddress() {
        int n = ADDRESS_COUNTER.incrementAndGet();
        return "10.78." + (n / 250) + "." + (n % 250 + 1);
    }

    private int count(String sql, Object... args) {
        return jdbc.queryForObject(sql, Integer.class, args);
    }

    // ---- login ----

    @Test
    @DisplayName("SEC-RATE-WEB-01: the 11th POST /login in a window is 429 for known and unknown users alike, with the same body shape; after the window it works again; another address is unaffected")
    void loginLimit() throws Exception {
        String unknown = "nobody_" + suffix;
        for (int i = 0; i < 10; i++) {
            MvcResult r = login(address, i % 2 == 0 ? clientA.getUsername() : unknown, "wrong-" + i);
            assertEquals(302, r.getResponse().getStatus(), "attempt " + i + " is processed");
            assertTrue(r.getResponse().getRedirectedUrl().contains("/login?error"));
        }
        MvcResult known = login(address, clientA.getUsername(), PASSWORD);
        MvcResult missing = login(address, unknown, PASSWORD);
        assertEquals(429, known.getResponse().getStatus());
        assertEquals(429, missing.getResponse().getStatus());
        assertEquals(known.getResponse().getContentType(), missing.getResponse().getContentType());
        assertEquals(known.getResponse().getHeader("Retry-After"), missing.getResponse().getHeader("Retry-After"));
        assertEquals(normalise(known.getResponse().getContentAsString()), normalise(missing.getResponse().getContentAsString()),
                "identical pages apart from the correlation id");
        assertEquals(5, count("SELECT failed_login_attempts FROM users WHERE id = ?", clientA.getId()),
                "only the 5 processed wrong attempts of the known user counted; the limited ones changed nothing");

        // a different client address is unaffected
        String other = nextAddress();
        assertEquals(302, login(other, clientB.getUsername(), PASSWORD).getResponse().getStatus());

        // the window passes (virtual time): the first address works again
        clock.advanceSeconds(61);
        MvcResult again = login(address, clientB.getUsername(), PASSWORD);
        assertEquals(302, again.getResponse().getStatus());
        assertTrue(again.getResponse().getRedirectedUrl().endsWith("/dashboard"));
    }

    private static String normalise(String html) {
        return UUID_TEXT.matcher(html).replaceAll("ID").replaceAll("\\s+", " ");
    }

    @Test
    @DisplayName("SEC-RATE-WEB-02: successful logins count too; legitimate use within the limit is never affected")
    void successfulLoginsCount() throws Exception {
        for (int i = 0; i < 10; i++) {
            MvcResult r = login(address, clientA.getUsername(), PASSWORD);
            assertEquals(302, r.getResponse().getStatus());
            assertTrue(r.getResponse().getRedirectedUrl().endsWith("/dashboard"));
        }
        assertEquals(429, login(address, clientA.getUsername(), PASSWORD).getResponse().getStatus());
        assertEquals(429, login(address, "nobody_" + suffix, "x").getResponse().getStatus());
    }

    @Test
    @DisplayName("SEC-RATE-WEB-03: the 429 page: HTML, Retry-After, correlation id, no-store, strict CSP unchanged, no stack trace, class name, address, username or password")
    void blockedPageContent() throws Exception {
        for (int i = 0; i < 10; i++) {
            login(address, "typed_user_" + suffix, "typed-secret-" + suffix);
        }
        MvcResult r = login(address, "typed_user_" + suffix, "typed-secret-" + suffix);
        assertEquals(429, r.getResponse().getStatus());
        assertTrue(r.getResponse().getContentType().startsWith("text/html"));
        int retry = Integer.parseInt(r.getResponse().getHeader("Retry-After"));
        assertTrue(retry >= 1 && retry <= 60, "Retry-After " + retry);
        assertEquals("no-store", r.getResponse().getHeader("Cache-Control"));
        assertEquals("default-src 'self'; frame-ancestors 'none'; object-src 'none'", r.getResponse().getHeader("Content-Security-Policy"));
        assertEquals("nosniff", r.getResponse().getHeader("X-Content-Type-Options"));
        assertEquals("DENY", r.getResponse().getHeader("X-Frame-Options"));
        String body = r.getResponse().getContentAsString();
        assertTrue(body.contains("Too many requests"));
        assertTrue(UUID_TEXT.matcher(body).find(), "correlation id");
        assertTrue(body.contains(">" + retry + "<"), "retry hint");
        assertFalse(body.contains("<script"));
        for (String forbidden : List.of(address, "typed_user_" + suffix, "typed-secret-" + suffix, "Exception", "at com.",
                "com.casevault", "RateLimit", "Caused by", "limiter", "LOGIN", ".java")) {
            assertFalse(body.contains(forbidden), "page must not contain: " + forbidden);
        }
    }

    @Test
    @DisplayName("SEC-RATE-WEB-04: a spoofed X-Forwarded-For does not bypass the login limit while trust-forwarded-for is false")
    void spoofedForwardedForIgnored() throws Exception {
        for (int i = 0; i < 10; i++) {
            MvcResult r = mockMvc.perform(post("/login").with(csrf()).with(from(address))
                    .header("X-Forwarded-For", "203.0.113." + i)
                    .param("username", "nobody_" + suffix).param("password", "x")).andReturn();
            assertEquals(302, r.getResponse().getStatus());
        }
        MvcResult blocked = mockMvc.perform(post("/login").with(csrf()).with(from(address))
                .header("X-Forwarded-For", "198.51.100.77")
                .param("username", "nobody_" + suffix).param("password", "x")).andReturn();
        assertEquals(429, blocked.getResponse().getStatus());
    }

    @Test
    @DisplayName("SEC-RATE-WEB-05: no audit row and exactly one WARN line per limiter and window (limiter name and correlation id only)")
    void logOnceAndNoAuditRows() throws Exception {
        jdbc.update("DELETE FROM audit_events");
        for (int i = 0; i < 30; i++) {
            login(address, "typed_user_" + suffix, "typed-secret-" + suffix);
        }
        assertEquals(10, count("SELECT COUNT(*) FROM audit_events"), "only the 10 processed attempts are audited; 20 limited ones wrote nothing");
        assertEquals(0, count("SELECT COUNT(*) FROM audit_events WHERE event_type NOT IN ('LOGIN_FAILURE', 'ACCOUNT_LOCKED')"));

        List<String> warnings = rateLimitWarnings();
        assertEquals(1, warnings.size(), "one WARN line for 20 limited requests in one window");
        assertTrue(Pattern.compile("^Rate limit exceeded limiter=login correlationId=" + UUID_TEXT.pattern() + "$")
                .matcher(warnings.get(0)).matches(), warnings.get(0));
        for (String forbidden : List.of(address, "typed_user_" + suffix, "typed-secret-" + suffix)) {
            assertFalse(warnings.get(0).contains(forbidden));
        }
        // next window: the next limited request warns again
        clock.advanceSeconds(61);
        for (int i = 0; i < 11; i++) {
            login(address, "typed_user_" + suffix, "x");
        }
        assertEquals(2, rateLimitWarnings().size());
    }

    private List<String> rateLimitWarnings() {
        return logs.list.stream().map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.startsWith("Rate limit exceeded")).toList();
    }

    @Test
    @DisplayName("SEC-RATE-WEB-06: 50 parallel POST /login from one address with a limit of 10: exactly 10 are processed, 40 get 429")
    void parallelLogins() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(50);
        try {
            CountDownLatch go = new CountDownLatch(1);
            List<Future<Integer>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < 50; i++) {
                String name = "nobody_" + suffix + "_" + i;
                futures.add(executor.submit(() -> {
                    go.await();
                    return login(address, name, "x").getResponse().getStatus();
                }));
            }
            go.countDown();
            int processed = 0;
            int limited = 0;
            for (Future<Integer> f : futures) {
                int status = f.get(120, TimeUnit.SECONDS);
                if (status == 302) {
                    processed++;
                } else if (status == 429) {
                    limited++;
                }
            }
            assertEquals(10, processed);
            assertEquals(40, limited);
        } finally {
            executor.shutdownNow();
        }
    }

    // ---- HTTP Basic on /api ----

    @Test
    @DisplayName("SEC-RATE-WEB-07: HTTP Basic requests to /api are limited per address: 429 with a fixed text body and Retry-After; another address is unaffected")
    void apiBasicLimit() throws Exception {
        String basic = "Basic " + Base64.getEncoder().encodeToString(("nobody_" + suffix + ":wrong").getBytes(StandardCharsets.UTF_8));
        for (int i = 0; i < 3; i++) {
            MvcResult r = mockMvc.perform(get("/api/cases").with(from(address)).header("Authorization", basic)).andReturn();
            assertEquals(401, r.getResponse().getStatus(), "attempt " + i);
        }
        MvcResult limited = mockMvc.perform(get("/api/cases").with(from(address)).header("Authorization", basic)).andReturn();
        assertEquals(429, limited.getResponse().getStatus());
        assertTrue(limited.getResponse().getContentType().startsWith("text/plain"));
        assertEquals("Too many requests. Please try again later.", limited.getResponse().getContentAsString());
        assertTrue(Integer.parseInt(limited.getResponse().getHeader("Retry-After")) >= 1);
        MvcResult other = mockMvc.perform(get("/api/cases").with(from(nextAddress())).header("Authorization", basic)).andReturn();
        assertEquals(401, other.getResponse().getStatus());
    }

    // ---- per-user limits ----

    @Test
    @DisplayName("SEC-RATE-WEB-08: case search is limited per authenticated user (HTML and API share the counter); other users and unfiltered lists are unaffected; limited requests write nothing")
    void searchLimit() throws Exception {
        jdbc.update("DELETE FROM audit_events");
        for (int i = 0; i < 3; i++) {
            assertEquals(200, mockMvc.perform(get("/cases").param("q", "RL").with(authentication(auth(clientA)))).andReturn().getResponse().getStatus());
        }
        MvcResult limited = mockMvc.perform(get("/cases").param("q", "RL").with(authentication(auth(clientA)))).andReturn();
        assertEquals(429, limited.getResponse().getStatus());
        assertTrue(limited.getResponse().getContentAsString().contains("Too many requests"));
        assertFalse(limited.getResponse().getContentAsString().contains("RL case A"), "the controller did not run");
        MvcResult api = mockMvc.perform(get("/api/cases/search").param("q", "RL").with(authentication(auth(clientA)))).andReturn();
        assertEquals(429, api.getResponse().getStatus());
        assertTrue(api.getResponse().getContentType().startsWith("text/plain"));

        assertEquals(200, mockMvc.perform(get("/cases").param("q", "RL").with(authentication(auth(clientB)))).andReturn().getResponse().getStatus());
        for (int i = 0; i < 10; i++) {
            assertEquals(200, mockMvc.perform(get("/cases").with(authentication(auth(clientA)))).andReturn().getResponse().getStatus(),
                    "a plain list without filters is not a search");
        }
        assertEquals(0, count("SELECT COUNT(*) FROM audit_events"));

        clock.advanceSeconds(61);
        assertEquals(200, mockMvc.perform(get("/cases").param("q", "RL").with(authentication(auth(clientA)))).andReturn().getResponse().getStatus());
    }

    @Test
    @DisplayName("SEC-RATE-WEB-09: evidence upload is limited per user (2 per window): the third is 429, nothing is stored, no EVIDENCE_UPLOADED row; another user is unaffected")
    void uploadLimit() throws Exception {
        jdbc.update("DELETE FROM audit_events");
        long filesBefore = filesInEvidenceDir();
        for (int i = 0; i < 2; i++) {
            MvcResult r = upload(caseA, clientA, "rl_upload_" + i + "_" + suffix + ".txt");
            assertEquals(302, r.getResponse().getStatus(), "upload " + i);
        }
        assertEquals(2, count("SELECT COUNT(*) FROM evidence WHERE case_id = ?", caseA.getId()));
        long filesAfterTwo = filesInEvidenceDir();
        assertEquals(filesBefore + 2, filesAfterTwo);

        MvcResult limited = upload(caseA, clientA, "rl_blocked_" + suffix + ".txt");
        assertEquals(429, limited.getResponse().getStatus());
        assertEquals(2, count("SELECT COUNT(*) FROM evidence WHERE case_id = ?", caseA.getId()));
        assertEquals(filesAfterTwo, filesInEvidenceDir(), "no file was stored for the limited upload");
        assertEquals(2, count("SELECT COUNT(*) FROM audit_events WHERE event_type = 'EVIDENCE_UPLOADED'"));
        assertEquals(0, count("SELECT COUNT(*) FROM audit_events WHERE event_type NOT IN ('EVIDENCE_UPLOADED')"));

        assertEquals(302, upload(caseB, clientB, "rl_other_" + suffix + ".txt").getResponse().getStatus());
    }

    private MvcResult upload(Case c, User u, String fileName) throws Exception {
        return mockMvc.perform(multipart("/cases/{id}/evidence", c.getId())
                .file(new MockMultipartFile("file", fileName, "text/plain", "synthetic evidence line".getBytes(StandardCharsets.UTF_8)))
                .with(authentication(auth(u))).with(csrf())).andReturn();
    }

    private long filesInEvidenceDir() throws IOException {
        Path dir = sharedTempDir.resolve("evidence");
        if (!Files.exists(dir)) {
            return 0;
        }
        try (Stream<Path> files = Files.list(dir)) {
            return files.count();
        }
    }

    @Test
    @DisplayName("SEC-RATE-WEB-10: report writes are limited per user (3 per window, create/update/submit/approve share it): the 4th is 429 and changes nothing; another user is unaffected")
    void reportWriteLimit() throws Exception {
        jdbc.update("DELETE FROM audit_events");
        String base = "/cases/" + caseA.getId() + "/reports";
        String firstId = null;
        for (int i = 0; i < 3; i++) {
            MvcResult r = mockMvc.perform(post(base).param("body", "report " + i).with(authentication(auth(analyst))).with(csrf())).andReturn();
            assertEquals(302, r.getResponse().getStatus());
            if (firstId == null) {
                String url = r.getResponse().getRedirectedUrl();
                firstId = url.substring(url.lastIndexOf('/') + 1);
            }
        }
        assertEquals(3, count("SELECT COUNT(*) FROM reports WHERE case_id = ?", caseA.getId()));

        MvcResult create = mockMvc.perform(post(base).param("body", "blocked").with(authentication(auth(analyst))).with(csrf())).andReturn();
        assertEquals(429, create.getResponse().getStatus());
        MvcResult submit = mockMvc.perform(post(base + "/" + firstId + "/submit").with(authentication(auth(analyst))).with(csrf())).andReturn();
        assertEquals(429, submit.getResponse().getStatus());
        MvcResult update = mockMvc.perform(post(base + "/" + firstId + "/update").param("body", "blocked edit")
                .with(authentication(auth(analyst))).with(csrf())).andReturn();
        assertEquals(429, update.getResponse().getStatus());
        assertEquals(3, count("SELECT COUNT(*) FROM reports WHERE case_id = ?", caseA.getId()));
        assertEquals("DRAFT", jdbc.queryForObject("SELECT status FROM reports WHERE id = ?", String.class, firstId));
        assertEquals("report 0", jdbc.queryForObject("SELECT body FROM reports WHERE id = ?", String.class, firstId));
        assertEquals(3, count("SELECT COUNT(*) FROM audit_events WHERE event_type = 'REPORT_TRANSITION'"));
        assertEquals(0, count("SELECT COUNT(*) FROM audit_events WHERE event_type <> 'REPORT_TRANSITION'"));

        MvcResult otherUser = mockMvc.perform(post("/cases/" + caseB.getId() + "/reports").param("body", "other analyst")
                .with(authentication(auth(analystTwo))).with(csrf())).andReturn();
        assertEquals(302, otherUser.getResponse().getStatus());
        assertNotEquals(429, mockMvc.perform(get(base).with(authentication(auth(analyst)))).andReturn().getResponse().getStatus(),
                "reading reports is not limited");
    }

    @Test
    @DisplayName("SEC-RATE-WEB-11: the rate-limited template has no th:utext, inline script, style or handler")
    void templateIsClean() throws Exception {
        Pattern forbidden = Pattern.compile("th:utext|innerHTML|javascript:|<script|style=|\\son[a-z]+\\s*=", java.util.regex.Pattern.CASE_INSENSITIVE);
        for (String line : Files.readAllLines(java.nio.file.Paths.get("src/main/resources/templates/rate-limited.html"))) {
            assertFalse(forbidden.matcher(line).find(), line.trim());
        }
    }
}
