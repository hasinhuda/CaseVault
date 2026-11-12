package com.casevault.evidence;

import com.casevault.model.Case;
import com.casevault.model.Evidence;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.EvidenceRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.CaseVaultUserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@org.junit.jupiter.api.extension.ExtendWith(com.casevault.support.RestoreBootstrapDataAfterAll.class)
public class EvidenceUiSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private OrganisationRepository organisationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CaseRepository caseRepository;

    @Autowired
    private EvidenceRepository evidenceRepository;

    private User clientUser;
    private User analystUser;
    private User managerUser;
    private User auditorUser;
    private Case aCase;
    private Evidence xssEvidence;

    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.jdbc.core.JdbcTemplate cleanupJdbc;

    @BeforeEach
    void setUp() {
        // F-008: FK-safe cleanup (reports, actions, notes, evidence, cases); other classes may have committed rows
        com.casevault.support.TestDatabaseCleaner.deleteCasesAndDependents(cleanupJdbc);
        evidenceRepository.deleteAll();
        caseRepository.deleteAll();
        userRepository.deleteAll();
        organisationRepository.deleteAll();

        Instant now = Instant.now();
        Organisation internalOrg = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now));
        Organisation clientOrg = organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Client Corporation", "ORG_CLIENT", now));

        clientUser = userRepository.save(new User(UUID.randomUUID().toString(), clientOrg, "client_ui_user", "hash", Role.CLIENT, "client_ui@test.local", true, now));
        analystUser = userRepository.save(new User(UUID.randomUUID().toString(), internalOrg, "analyst_ui_user", "hash", Role.ANALYST, "analyst_ui@test.local", true, now));
        managerUser = userRepository.save(new User(UUID.randomUUID().toString(), internalOrg, "manager_ui_user", "hash", Role.MANAGER, "manager_ui@test.local", true, now));
        auditorUser = userRepository.save(new User(UUID.randomUUID().toString(), internalOrg, "auditor_ui_user", "hash", Role.AUDITOR_ADMIN, "auditor_ui@test.local", true, now));

        aCase = caseRepository.save(new Case(
                UUID.randomUUID().toString(), clientOrg, "Incident Response Case 101", "DATA_EXFILTRATION", "HIGH",
                "ASSIGNED", clientUser, analystUser, now));

        xssEvidence = evidenceRepository.save(new Evidence(
                UUID.randomUUID().toString(), aCase, "<script>alert(1)</script>.txt", UUID.randomUUID().toString(),
                "text/plain", 1024L, "a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef", 1, clientUser, now));
    }

    private Authentication authFor(User user) {
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(user, Instant.now());
        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }

    @Test
    @DisplayName("SEC-EVID-UI-01: Evidence tab renders for CLIENT, ANALYST and MANAGER with role-appropriate controls")
    void evidenceTabRendersForClientAnalystManager() throws Exception {
        // 1. CLIENT can view Evidence tab with upload form
        mockMvc.perform(get("/cases/{id}?tab=evidence", aCase.getId())
                        .with(authentication(authFor(clientUser))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Evidence (<span>1</span>)")))
                .andExpect(content().string(containsString("Upload encrypted evidence")))
                .andExpect(content().string(containsString("Stored Evidence")));

        // 2. Assigned ANALYST can view Evidence tab with upload form
        mockMvc.perform(get("/cases/{id}?tab=evidence", aCase.getId())
                        .with(authentication(authFor(analystUser))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Evidence (<span>1</span>)")))
                .andExpect(content().string(containsString("Upload encrypted evidence")))
                .andExpect(content().string(containsString("Stored Evidence")));

        // 3. Internal MANAGER can view Evidence tab, but upload form is hidden (per FR-08)
        mockMvc.perform(get("/cases/{id}?tab=evidence", aCase.getId())
                        .with(authentication(authFor(managerUser))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Evidence (<span>1</span>)")))
                .andExpect(content().string(not(containsString("Upload encrypted evidence"))))
                .andExpect(content().string(containsString("Stored Evidence")));
    }

    @Test
    @DisplayName("SEC-EVID-UI-02: Stored display name with script tags is HTML-escaped in Evidence tab")
    void storedDisplayNameHtmlEscapedInEvidenceTab() throws Exception {
        mockMvc.perform(get("/cases/{id}?tab=evidence", aCase.getId())
                        .with(authentication(authFor(clientUser))))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("&lt;script&gt;alert(1)&lt;/script&gt;.txt")))
                .andExpect(content().string(not(containsString("<script>alert(1)</script>.txt"))));
    }

    @Test
    @DisplayName("SEC-EVID-UI-03: Evidence tab is hidden from AUDITOR_ADMIN and direct request returns HTTP 404")
    void auditorAdminDeniedAccessToEvidenceTab() throws Exception {
        mockMvc.perform(get("/cases/{id}?tab=evidence", aCase.getId())
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isNotFound())
                .andExpect(content().string(containsString("HTTP 404")))
                .andExpect(content().string(not(containsString("Stored Evidence"))))
                .andExpect(content().string(not(containsString("<script>alert(1)</script>.txt"))));
    }

    @Test
    @DisplayName("SEC-EVID-UI-04: Template scanner security gate confirms zero th:utext or unsafe inline handlers across all templates")
    void templateScannerConfirmsNoUnescapedContentOrInlineHandlers() throws IOException {
        Path templatesDir = Paths.get("src/main/resources/templates");
        assertTrue(Files.exists(templatesDir), "Templates directory must exist");

        Pattern forbiddenPattern = Pattern.compile("th:utext|innerHTML|onclick|onload|onerror|javascript:|<script(?!.*\\bsrc=)|style=");

        try (Stream<Path> stream = Files.walk(templatesDir)) {
            List<Path> templateFiles = stream.filter(p -> p.toString().endsWith(".html")).toList();
            assertFalse(templateFiles.isEmpty(), "Templates must exist");

            for (Path template : templateFiles) {
                List<String> lines = Files.readAllLines(template);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    assertFalse(forbiddenPattern.matcher(line).find(),
                            "Forbidden pattern found in " + template.getFileName() + " at line " + (i + 1) + ": " + line.trim());
                }
            }
        }
    }
}
