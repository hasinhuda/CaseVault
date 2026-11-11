package com.casevault.cases;

import com.casevault.dto.CreateCaseNoteRequestDto;
import com.casevault.dto.CreateRemediationActionRequestDto;
import com.casevault.model.Case;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseNoteRepository;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.RemediationActionRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class CaseSearchAndUiSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private OrganisationRepository organisationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CaseRepository caseRepository;

    @Autowired
    private com.casevault.repository.EvidenceRepository evidenceRepository;

    @Autowired
    private CaseNoteRepository caseNoteRepository;

    @Autowired
    private RemediationActionRepository remediationActionRepository;

    private Organisation orgInternal;
    private Organisation orgA;
    private Organisation orgB;

    private User managerAlice;
    private User analystBob;
    private User clientUserA;
    private User clientUserB;
    private User auditorUser;

    private Case caseWildcardPercent;
    private Case caseWildcardUnderscore;
    private Case caseNormalAlpha;
    private Case caseNormalBeta;
    private Case caseForeignB;

    @BeforeEach
    void setUp() {
        evidenceRepository.deleteAll();
        remediationActionRepository.deleteAll();
        caseNoteRepository.deleteAll();
        caseRepository.deleteAll();

        Instant now = Instant.now();

        orgInternal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        orgA = organisationRepository.findByCode("ORG_SRCH_A")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Search Client Org A", "ORG_SRCH_A", now)));
        orgB = organisationRepository.findByCode("ORG_SRCH_B")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Search Client Org B", "ORG_SRCH_B", now)));

        managerAlice = createUser("srch_manager_alice", orgInternal, Role.MANAGER, now);
        analystBob = createUser("srch_analyst_bob", orgInternal, Role.ANALYST, now);
        clientUserA = createUser("srch_client_a", orgA, Role.CLIENT, now);
        clientUserB = createUser("srch_client_b", orgB, Role.CLIENT, now);
        auditorUser = createUser("srch_auditor", null, Role.AUDITOR_ADMIN, now);

        // Synthetic cases for wildcard testing
        caseWildcardPercent = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgA, "100% CPU Utilization Incident", "RANSOMWARE", "CRITICAL", "OPEN", clientUserA, analystBob, now
        ));

        caseWildcardUnderscore = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgA, "Incident_Alpha Investigation", "PHISHING", "HIGH", "OPEN", clientUserA, analystBob, now
        ));

        caseNormalAlpha = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgA, "Incident Alpha Investigation", "PHISHING", "MEDIUM", "OPEN", clientUserA, analystBob, now
        ));

        caseNormalBeta = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgA, "Incident Beta Exfiltration", "DATA_EXFILTRATION", "LOW", "IN_PROGRESS", clientUserA, analystBob, now
        ));

        // Foreign case belonging to Org B
        caseForeignB = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgB, "Incident Foreign B Breach", "RANSOMWARE", "CRITICAL", "OPEN", clientUserB, null, now
        ));
    }

    private User createUser(String username, Organisation org, Role role, Instant now) {
        String randomSuffix = UUID.randomUUID().toString().substring(0, 8);
        return userRepository.save(new User(
                UUID.randomUUID().toString(),
                org,
                username + "_" + randomSuffix,
                "$argon2id$v=19$m=65536,t=3,p=1$fakeHashForSearchTests",
                role,
                username + "_" + randomSuffix + "@test.local",
                true,
                now
        ));
    }

    private Authentication authFor(User user) {
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(user, Instant.now());
        return new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities());
    }

    @Test
    @DisplayName("SEC-CASE-07: LIKE wildcard escaping in q query parameter (SR-10)")
    void testWildcardEscaping() throws Exception {
        // Querying with "%" should ONLY match literal "%" ("100% CPU Utilization Incident"), NOT all cases!
        mockMvc.perform(get("/api/cases/search")
                        .param("q", "%")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].title", is("100% CPU Utilization Incident")));

        // Querying with "_" should ONLY match literal "_" ("Incident_Alpha Investigation"), NOT "Incident Alpha" with space!
        mockMvc.perform(get("/api/cases/search")
                        .param("q", "Incident_Alpha")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].title", is("Incident_Alpha Investigation")));
    }

    @Test
    @DisplayName("SEC-CASE-08: SQL injection safety across search parameters (SR-10)")
    void testSqlInjectionSafety() throws Exception {
        // Injecting SQL injection strings into free text q
        mockMvc.perform(get("/api/cases/search")
                        .param("q", "test' OR '1'='1' --")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(0)));

        // Injecting SQL statement terminator and command into q
        mockMvc.perform(get("/api/cases/search")
                        .param("q", "'; DROP TABLE cases; --")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(0)));

        // Verifying cases table still exists and data intact
        assertTrue(caseRepository.count() >= 5, "Database tables must remain intact after SQLi attempt");
    }

    @Test
    @DisplayName("SEC-CASE-09: Capped pagination limit (max 50) and sort field allow-list")
    void testPaginationCappingAndSortAllowList() throws Exception {
        // Requesting page size 1000 must be capped at 50
        mockMvc.perform(get("/api/cases/search")
                        .param("size", "1000")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size", is(50)));

        // Negative size must default to 10
        mockMvc.perform(get("/api/cases/search")
                        .param("size", "-5")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size", is(10)));

        // Invalid / SQLi sort field must fall back safely to createdAt without throwing 500
        mockMvc.perform(get("/api/cases/search")
                        .param("sort", "untrusted_column; DROP TABLE--")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("SEC-CASE-10: Strict tenant boundaries in case search")
    void testTenantBoundariesInSearch() throws Exception {
        // CLIENT User A must only see cases from Org A (4 cases), never Foreign Case B
        mockMvc.perform(get("/api/cases/search")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements", is(4)));

        // AUDITOR_ADMIN receives empty page (0 cases) per SR-07
        mockMvc.perform(get("/api/cases/search")
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements", is(0)))
                .andExpect(jsonPath("$.content", hasSize(0)));
    }

    @Test
    @DisplayName("SEC-CASE-11: AUDITOR_ADMIN web route boundary - returns 404 on /cases/** (SR-07)")
    void testAuditorAdminWebBoundaryReturns404() throws Exception {
        // GET /cases -> 404
        mockMvc.perform(get("/cases")
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isNotFound());

        // GET /cases/new -> 404
        mockMvc.perform(get("/cases/new")
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isNotFound());

        // GET /cases/{id} -> 404
        mockMvc.perform(get("/cases/{id}", caseWildcardPercent.getId())
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("SEC-CASE-12: Context-aware HTML output encoding / XSS prevention in UI (SR-08)")
    void testOutputEncodingXssPrevention() throws Exception {
        // Create a case with polyglot XSS payload in title
        String xssPayload = "<script>alert('xss-case-title')</script>";
        Case xssCase = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgA, xssPayload, "OTHER", "LOW", "OPEN", clientUserA, analystBob, Instant.now()
        ));

        // Add note and action with XSS payloads
        String xssNoteBody = "<img src=x onerror=alert('xss-note')>";
        caseNoteRepository.save(new com.casevault.model.CaseNote(
                UUID.randomUUID().toString(), xssCase, analystBob, xssNoteBody, Instant.now()
        ));

        String xssActionDesc = "<u>Underline</u><script>fetch('/cookie')</script>";
        remediationActionRepository.save(new com.casevault.model.RemediationAction(
                UUID.randomUUID().toString(), xssCase, xssActionDesc, "OPEN", analystBob, Instant.now()
        ));

        // 1. Check Case List view HTML: raw script tags must NOT appear; HTML entity escaped instead
        mockMvc.perform(get("/cases")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("<script>alert('xss-case-title')</script>"))))
                .andExpect(content().string(containsString("&lt;script&gt;alert(&#39;xss-case-title&#39;)&lt;/script&gt;")));

        // 2. Check Case Detail view HTML: note and action payloads must be entity escaped
        mockMvc.perform(get("/cases/{id}", xssCase.getId())
                        .param("tab", "notes")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("<img src=x onerror=alert('xss-note')>"))))
                .andExpect(content().string(containsString("&lt;img src=x onerror=alert(&#39;xss-note&#39;)&gt;")));

        mockMvc.perform(get("/cases/{id}", xssCase.getId())
                        .param("tab", "actions")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("<script>fetch('/cookie')</script>"))))
                .andExpect(content().string(containsString("&lt;script&gt;fetch(&#39;/cookie&#39;)&lt;/script&gt;")));
    }

    @Test
    @DisplayName("SEC-CASE-13: Template scanner asserts zero th:utext, innerHTML, inline scripts or inline styles (SR-08, SR-09)")
    void testTemplateScannerSecurityGate() throws IOException {
        Path templatesDir = Paths.get("src/main/resources/templates");
        assertTrue(Files.exists(templatesDir), "Templates directory must exist");

        Pattern forbiddenPattern = Pattern.compile("th:utext|innerHTML|onclick|onload|onerror|javascript:|<script(?!.*\\bsrc=)|style=");

        try (Stream<Path> stream = Files.walk(templatesDir)) {
            List<Path> templateFiles = stream.filter(p -> p.toString().endsWith(".html")).toList();
            assertFalse(templateFiles.isEmpty(), "Must find Thymeleaf template files");

            for (Path template : templateFiles) {
                List<String> lines = Files.readAllLines(template);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    assertFalse(forbiddenPattern.matcher(line).find(),
                            "Forbidden unsafe pattern found in " + template.getFileName() + " at line " + (i + 1) + ": " + line.trim());
                }
            }
        }
    }

    @Test
    @DisplayName("FUNC-CASE-02: Client incident reporting workflow through web UI")
    void testClientIncidentReportingWebFlow() throws Exception {
        // 1. Client loads /cases/new
        mockMvc.perform(get("/cases/new")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Report Security Incident")));

        // 2. Client submits incident creation form
        mockMvc.perform(post("/cases")
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf())
                        .param("title", "Web UI Reported Ransomware Breach")
                        .param("category", "RANSOMWARE")
                        .param("severity", "CRITICAL"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("/cases/*"));

        // 3. Verify newly created case exists in database and is scoped to Org A
        List<Case> orgACases = caseRepository.findByOrganisationId(orgA.getId());
        boolean found = orgACases.stream().anyMatch(c -> "Web UI Reported Ransomware Breach".equals(c.getTitle()));
        assertTrue(found, "Newly reported case must exist in Org A database records");
    }

    @Test
    @DisplayName("SEC-EVID-HARDEN-03: Rejected upload error message with HTML tags is entity-escaped in rendered view")
    void testRejectedExtensionHtmlEscapingInErrorPage() throws Exception {
        org.springframework.mock.web.MockMultipartFile maliciousUpload = new org.springframework.mock.web.MockMultipartFile(
                "file",
                "attack.<script>",
                "text/plain",
                "test payload".getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart("/cases/{id}/evidence", caseWildcardPercent.getId())
                        .file(maliciousUpload)
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf())
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("&lt;script&gt;")))
                .andExpect(content().string(not(containsString("<script>"))));
    }
}

