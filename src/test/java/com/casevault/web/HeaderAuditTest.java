package com.casevault.web;

import com.casevault.model.Case;
import com.casevault.model.Evidence;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.EvidenceRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Phase 8B header audit: records the headers of every page type (written to target/header-audit.txt) and asserts the
 * required values. Headers are verified through MockMvc and the real security filter chain with real logins, not in
 * a real browser.
 */
@SpringBootTest
@AutoConfigureMockMvc
class HeaderAuditTest {

    private static final String PASSWORD = "Header-Audit-Password-1234!";
    private static final AtomicInteger ADDRESS = new AtomicInteger();
    private static final List<String> RECORDED = new ArrayList<>();

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
    private PasswordEncoder passwordEncoder;
    @Autowired
    private OrganisationRepository organisationRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CaseRepository caseRepository;
    @Autowired
    private EvidenceRepository evidenceRepository;

    private User client;
    private User analyst;
    private User auditor;
    private Case caseA;

    @BeforeEach
    void setUp() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        Instant now = Instant.now();
        Organisation internal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(
                        new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        Organisation org = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "HDR " + suffix, "HDR_" + suffix, now));
        String hash = passwordEncoder.encode(PASSWORD);
        client = user("hd_cl_" + suffix, org, Role.CLIENT, hash);
        analyst = user("hd_an_" + suffix, internal, Role.ANALYST, hash);
        auditor = user("hd_au_" + suffix, internal, Role.AUDITOR_ADMIN, hash);
        caseA = caseRepository.save(new Case(UUID.randomUUID().toString(), org, "Header case " + suffix,
                "RANSOMWARE", "HIGH", "IN_PROGRESS", client, analyst, now));
    }

    private User user(String name, Organisation org, Role role, String hash) {
        return userRepository.save(new User(UUID.randomUUID().toString(), org, name, hash, role,
                name + "@test.local", true, Instant.now()));
    }

    private static RequestPostProcessor from(String address) {
        return request -> {
            request.setRemoteAddr(address);
            return request;
        };
    }

    private static String freshAddress() {
        int n = ADDRESS.incrementAndGet();
        return "10.55." + (n / 250) + "." + (n % 250 + 1);
    }

    private MockHttpSession login(User u) throws Exception {
        MvcResult result = mockMvc.perform(post("/login").with(csrf()).with(from(freshAddress()))
                .param("username", u.getUsername()).param("password", PASSWORD)).andReturn();
        assertEquals(302, result.getResponse().getStatus());
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    private static final List<String> HEADERS = List.of("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
            "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
            "Strict-Transport-Security", "Cache-Control", "Pragma", "Expires", "X-Correlation-ID", "Content-Type");

    private record Page(String name, MvcResult result, boolean cacheable) {
    }

    private Page page(String name, MvcResult result) {
        StringBuilder text = new StringBuilder("## " + name + " (HTTP " + result.getResponse().getStatus() + ")\n");
        for (String header : HEADERS) {
            List<String> values = result.getResponse().getHeaders(header);
            text.append("  ").append(header).append(": ").append(values.isEmpty() ? "(absent)" : String.join(" || ", values)).append('\n');
        }
        synchronized (RECORDED) {
            RECORDED.add(text.toString());
        }
        return new Page(name, result, false);
    }

    /** Parses all Content-Security-Policy header values (several headers combine as an intersection). */
    private static Map<String, List<String>> csp(MvcResult r) {
        Map<String, List<String>> directives = new LinkedHashMap<>();
        for (String value : r.getResponse().getHeaders("Content-Security-Policy")) {
            for (String part : value.split(";")) {
                String[] tokens = part.trim().split("\\s+");
                if (tokens.length > 0 && !tokens[0].isEmpty()) {
                    directives.computeIfAbsent(tokens[0], k -> new ArrayList<>())
                            .addAll(Arrays.asList(tokens).subList(1, tokens.length));
                }
            }
        }
        return directives;
    }

    private static List<Executable> securityHeaderChecks(Page p, boolean checkCaching) {
        MvcResult r = p.result();
        String n = p.name();
        Map<String, List<String>> csp = csp(r);
        List<Executable> checks = new ArrayList<>();
        checks.add(() -> assertEquals(List.of("'self'"), csp.get("default-src"), n + ": default-src"));
        checks.add(() -> assertEquals(List.of("'none'"), csp.get("object-src"), n + ": object-src"));
        checks.add(() -> assertEquals(List.of("'none'"), csp.get("frame-ancestors"), n + ": frame-ancestors"));
        checks.add(() -> assertEquals(List.of("'self'"), csp.get("base-uri"), n + ": base-uri"));
        checks.add(() -> assertEquals(List.of("'self'"), csp.get("form-action"), n + ": form-action"));
        checks.add(() -> assertEquals(List.of("'self'"), csp.get("script-src"), n + ": script-src"));
        checks.add(() -> assertEquals(List.of("'self'"), csp.get("style-src"), n + ": style-src"));
        checks.add(() -> assertFalse(String.join(" ", r.getResponse().getHeaders("Content-Security-Policy")).contains("unsafe-"), n + ": no unsafe-inline or unsafe-eval"));
        checks.add(() -> assertEquals("nosniff", r.getResponse().getHeader("X-Content-Type-Options"), n));
        checks.add(() -> assertEquals("DENY", r.getResponse().getHeader("X-Frame-Options"), n));
        checks.add(() -> assertEquals("strict-origin-when-cross-origin", r.getResponse().getHeader("Referrer-Policy"), n));
        checks.add(() -> {
            String policy = r.getResponse().getHeader("Permissions-Policy");
            assertTrue(policy != null && policy.contains("camera=()") && policy.contains("microphone=()")
                    && policy.contains("geolocation=()"), n + ": Permissions-Policy " + policy);
        });
        checks.add(() -> assertEquals("same-origin", r.getResponse().getHeader("Cross-Origin-Opener-Policy"), n));
        checks.add(() -> assertEquals("same-origin", r.getResponse().getHeader("Cross-Origin-Resource-Policy"), n));
        checks.add(() -> assertEquals(null, r.getResponse().getHeader("Strict-Transport-Security"),
                n + ": no HSTS on the local http profile"));
        checks.add(() -> assertTrue(r.getResponse().getHeader("X-Correlation-ID") != null
                && r.getResponse().getHeader("X-Correlation-ID").matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
                n + ": X-Correlation-ID"));
        if (checkCaching) {
            checks.add(() -> assertTrue(String.valueOf(r.getResponse().getHeader("Cache-Control")).contains("no-store"),
                    n + ": Cache-Control " + r.getResponse().getHeader("Cache-Control")));
        }
        return checks;
    }

    @Test
    @DisplayName("SEC-HDR-01: every page type carries the required security headers (CSP directives, nosniff, DENY, Referrer-Policy, Permissions-Policy, COOP, CORP, no HSTS on http) and a correlation id; all dynamic pages are no-store")
    void headersOfEveryPageType() throws Exception {
        MockHttpSession clientSession = login(client);
        MockHttpSession analystSession = login(analyst);
        MockHttpSession auditorSession = login(auditor);
        String reportsPath = "/cases/" + caseA.getId() + "/reports";

        MvcResult createdReport = mockMvc.perform(post(reportsPath).session(analystSession).with(csrf()).param("body", "header report")).andReturn();
        String reportId = createdReport.getResponse().getRedirectedUrl().substring(createdReport.getResponse().getRedirectedUrl().lastIndexOf('/') + 1);
        mockMvc.perform(multipart("/cases/{id}/evidence", caseA.getId())
                .file(new MockMultipartFile("file", "header_evidence.txt", "text/plain", "synthetic evidence".getBytes(StandardCharsets.UTF_8)))
                .session(clientSession).with(csrf()));
        Evidence evidence = evidenceRepository.findByACaseId(caseA.getId()).stream().findFirst().orElseThrow();

        String floodAddress = freshAddress();
        MvcResult limited = null;
        for (int i = 0; i < 11; i++) {
            limited = mockMvc.perform(post("/login").with(csrf()).with(from(floodAddress))
                    .param("username", "nobody_" + i).param("password", "x")).andReturn();
        }

        List<Page> dynamic = new ArrayList<>(List.of(
                page("login page", mockMvc.perform(get("/login")).andReturn()),
                page("dashboard", mockMvc.perform(get("/dashboard").session(clientSession)).andReturn()),
                page("case list", mockMvc.perform(get("/cases").session(clientSession)).andReturn()),
                page("case detail", mockMvc.perform(get("/cases/" + caseA.getId()).session(clientSession)).andReturn()),
                page("evidence tab", mockMvc.perform(get("/cases/" + caseA.getId()).param("tab", "evidence").session(clientSession)).andReturn()),
                page("report list", mockMvc.perform(get(reportsPath).session(analystSession)).andReturn()),
                page("report detail", mockMvc.perform(get(reportsPath + "/" + reportId).session(analystSession)).andReturn()),
                page("redirect with state (report created)", createdReport),
                page("audit list", mockMvc.perform(get("/audit").session(auditorSession)).andReturn()),
                page("admin users", mockMvc.perform(get("/admin/users").session(auditorSession)).andReturn()),
                page("admin health", mockMvc.perform(get("/admin/health").session(auditorSession)).andReturn()),
                page("404 page", mockMvc.perform(get("/no-such-page-" + UUID.randomUUID()).session(clientSession)).andReturn()),
                page("429 page", limited),
                page("evidence download", mockMvc.perform(get("/cases/{c}/evidence/{e}", caseA.getId(), evidence.getId()).session(clientSession)).andReturn()),
                page("actuator health", mockMvc.perform(get("/actuator/health")).andReturn())));
        Page css = page("static css", mockMvc.perform(get("/css/app.css")).andReturn());

        List<Executable> checks = new ArrayList<>();
        for (Page p : dynamic) {
            checks.addAll(securityHeaderChecks(p, true));
        }
        checks.addAll(securityHeaderChecks(css, false));
        checks.add(() -> assertEquals(429, dynamic.get(12).result().getResponse().getStatus()));
        checks.add(() -> assertEquals(200, dynamic.get(13).result().getResponse().getStatus()));
        // Static CSS could be cached, but today it is not: Spring Security's default no-store applies to it as well.
        checks.add(() -> assertTrue(css.result().getResponse().getHeader("Cache-Control").contains("no-store"),
                "css Cache-Control is " + css.result().getResponse().getHeader("Cache-Control")));
        writeRecording();
        assertAll(checks);
    }

    private static void writeRecording() throws Exception {
        Path out = Paths.get("target", "header-audit.txt");
        Files.createDirectories(out.getParent());
        synchronized (RECORDED) {
            Files.writeString(out, String.join("\n", RECORDED));
        }
    }

    @Test
    @DisplayName("SEC-HDR-03: on the local http profile Strict-Transport-Security is ABSENT, even for a request marked secure (the header is configured for the prod-like profile only)")
    void hstsAbsentOnLocalProfile() throws Exception {
        for (boolean secure : new boolean[]{false, true}) {
            MvcResult r = mockMvc.perform(get("/login").secure(secure)).andReturn();
            assertEquals(null, r.getResponse().getHeader("Strict-Transport-Security"), "secure=" + secure);
        }
    }

    @Test
    @DisplayName("SEC-HDR-04: the audit and admin pages (backlog item from Phase 6C/7B) and every authenticated page are no-store; a login POST redirect and a logout redirect too")
    void authenticatedPagesAreNoStore() throws Exception {
        MockHttpSession auditorSession = login(auditor);
        for (String path : List.of("/audit", "/admin/users", "/admin/health", "/dashboard")) {
            String cacheControl = mockMvc.perform(get(path).session(auditorSession)).andReturn().getResponse().getHeader("Cache-Control");
            assertTrue(cacheControl != null && cacheControl.contains("no-store"), path + ": " + cacheControl);
        }
        MvcResult loginRedirect = mockMvc.perform(post("/login").with(csrf()).with(from(freshAddress()))
                .param("username", client.getUsername()).param("password", PASSWORD)).andReturn();
        assertTrue(loginRedirect.getResponse().getHeader("Cache-Control").contains("no-store"));
        MvcResult logout = mockMvc.perform(post("/logout").with(csrf()).session(auditorSession)).andReturn();
        assertTrue(String.valueOf(logout.getResponse().getHeader("Cache-Control")).contains("no-store"));
    }
}
