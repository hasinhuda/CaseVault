package com.casevault.authz;

import com.casevault.dto.CreateCaseRequestDto;
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
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthorisationOperationMatrixTest {

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

    @Autowired
    private ObjectMapper objectMapper;

    private Organisation orgInternal;
    private Organisation orgA;
    private Organisation orgB;

    private User managerAlice;     // Internal Consultancy Manager (ORG_INTERNAL)
    private User analystBob;        // Internal Consultancy Analyst (ORG_INTERNAL)
    private User clientUserA;       // Client Org A User
    private User clientUserB;       // Client Org B User
    private User clientManagerA;    // Client Org A Manager (Non-internal)
    private User auditorUser;       // System Auditor

    private Case caseA1AssignedToBob;
    private Case caseA2Unassigned;
    private Case caseB1;

    private Evidence evidenceA1;
    private Evidence evidenceB1;

    @BeforeEach
    void setUp() {
        evidenceRepository.deleteAll();
        caseRepository.deleteAll();

        Instant now = Instant.now();

        // 1. Internal consultancy organisation (matches DataBootstrapService)
        orgInternal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "CyberConsulting IR Consultancy", "ORG_INTERNAL", now)));

        // 2. Client organisations
        orgA = organisationRepository.findByCode("ORG_AUTHZ_A")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Authz Client Corp A", "ORG_AUTHZ_A", now)));

        orgB = organisationRepository.findByCode("ORG_AUTHZ_B")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Authz Client Corp B", "ORG_AUTHZ_B", now)));

        // 3. Synthetic staff and client users
        managerAlice = createUser("manager_alice_" + UUID.randomUUID().toString().substring(0, 8), orgInternal, Role.MANAGER, now);
        analystBob = createUser("analyst_bob_" + UUID.randomUUID().toString().substring(0, 8), orgInternal, Role.ANALYST, now);
        clientUserA = createUser("client_a_" + UUID.randomUUID().toString().substring(0, 8), orgA, Role.CLIENT, now);
        clientUserB = createUser("client_b_" + UUID.randomUUID().toString().substring(0, 8), orgB, Role.CLIENT, now);
        clientManagerA = createUser("client_manager_a_" + UUID.randomUUID().toString().substring(0, 8), orgA, Role.MANAGER, now);
        auditorUser = createUser("auditor_" + UUID.randomUUID().toString().substring(0, 8), null, Role.AUDITOR_ADMIN, now);

        // 4. Cases across client organisations
        // Case A1 belongs to Org A, assigned to analystBob (ORG_INTERNAL)
        caseA1AssignedToBob = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgA, "Case A1 Security Incident", "RANSOMWARE", "CRITICAL", "OPEN", clientUserA, analystBob, now
        ));

        // Case A2 belongs to Org A, unassigned
        caseA2Unassigned = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgA, "Case A2 Phishing Campaign", "PHISHING", "MEDIUM", "INVESTIGATING", clientUserA, null, now
        ));

        // Case B1 belongs to Org B, unassigned
        caseB1 = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgB, "Case B1 Data Leak", "DATA_LEAK", "HIGH", "OPEN", clientUserB, null, now
        ));

        // Evidence artifacts
        evidenceA1 = evidenceRepository.save(new Evidence(
                UUID.randomUUID().toString(), caseA1AssignedToBob, "ransomware_note.txt", clientUserA, now
        ));

        evidenceB1 = evidenceRepository.save(new Evidence(
                UUID.randomUUID().toString(), caseB1, "confidential_dump.csv", clientUserB, now
        ));
    }

    private User createUser(String username, Organisation org, Role role, Instant now) {
        return userRepository.save(new User(
                UUID.randomUUID().toString(),
                org,
                username,
                "$argon2id$v=19$m=65536,t=3,p=1$fakeHashForAuthzTests",
                role,
                username + "@test.local",
                true,
                now
        ));
    }

    private Authentication authFor(User user) {
        CaseVaultUserPrincipal principal = new CaseVaultUserPrincipal(user, Instant.now());
        return new UsernamePasswordAuthenticationToken(principal, "N/A", principal.getAuthorities());
    }

    @Test
    @DisplayName("SEC-AUTHZ-01: CLIENT can read cases of own organisation and gets 404 for other cases")
    void clientOwnOrgCases() throws Exception {
        // Can read own organisation case A1
        mockMvc.perform(get("/api/cases/{id}", caseA1AssignedToBob.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(caseA1AssignedToBob.getId())))
                .andExpect(jsonPath("$.title", is("Case A1 Security Incident")));

        // Can read own organisation case A2
        mockMvc.perform(get("/api/cases/{id}", caseA2Unassigned.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk());

        // Cross-tenant IDOR attempt on Org B case -> MUST return 404 Not Found (never 403)
        mockMvc.perform(get("/api/cases/{id}", caseB1.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("SEC-AUTHZ-02: ANALYST can read assigned client-org case regardless of org, and gets 404 for unassigned cases")
    void analystAssignedCasesOnly() throws Exception {
        // analyst_bob (ORG_INTERNAL) can read Case A1 (client Org A) because it is assigned to him
        mockMvc.perform(get("/api/cases/{id}", caseA1AssignedToBob.getId())
                        .with(authentication(authFor(analystBob))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(caseA1AssignedToBob.getId())));

        // analyst_bob CANNOT read Case A2 (unassigned) -> 404 Not Found
        mockMvc.perform(get("/api/cases/{id}", caseA2Unassigned.getId())
                        .with(authentication(authFor(analystBob))))
                .andExpect(status().isNotFound());

        // analyst_bob CANNOT read Case B1 (unassigned in Org B) -> 404 Not Found
        mockMvc.perform(get("/api/cases/{id}", caseB1.getId())
                        .with(authentication(authFor(analystBob))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("SEC-AUTHZ-03: Internal staff manager (manager_alice, ORG_INTERNAL) reads client-org cases across all organisations")
    void internalStaffManagerAllCases() throws Exception {
        // manager_alice (ORG_INTERNAL) reads Case A1 (Org A)
        mockMvc.perform(get("/api/cases/{id}", caseA1AssignedToBob.getId())
                        .with(authentication(authFor(managerAlice))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(caseA1AssignedToBob.getId())));

        // manager_alice (ORG_INTERNAL) reads Case A2 (Org A)
        mockMvc.perform(get("/api/cases/{id}", caseA2Unassigned.getId())
                        .with(authentication(authFor(managerAlice))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(caseA2Unassigned.getId())));

        // manager_alice (ORG_INTERNAL) reads Case B1 (Org B)
        mockMvc.perform(get("/api/cases/{id}", caseB1.getId())
                        .with(authentication(authFor(managerAlice))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(caseB1.getId())));

        // Listing for manager_alice returns all cases across all organisations (3 total)
        mockMvc.perform(get("/api/cases")
                        .with(authentication(authFor(managerAlice))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)));
    }

    @Test
    @DisplayName("SEC-AUTHZ-03B: Non-internal manager (clientManagerA, Org A) can only read own organisation and gets 404 for other orgs")
    void nonInternalManagerRestrictedToOwnOrg() throws Exception {
        // clientManagerA reads own Org A cases
        mockMvc.perform(get("/api/cases/{id}", caseA1AssignedToBob.getId())
                        .with(authentication(authFor(clientManagerA))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/cases/{id}", caseA2Unassigned.getId())
                        .with(authentication(authFor(clientManagerA))))
                .andExpect(status().isOk());

        // clientManagerA CANNOT read Org B case -> 404 Not Found
        mockMvc.perform(get("/api/cases/{id}", caseB1.getId())
                        .with(authentication(authFor(clientManagerA))))
                .andExpect(status().isNotFound());

        // Listing for clientManagerA returns only Org A cases (2 total)
        mockMvc.perform(get("/api/cases")
                        .with(authentication(authFor(clientManagerA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)));
    }

    @Test
    @DisplayName("SEC-AUTHZ-04: AUDITOR_ADMIN has strict zero-access to case content -> returns 404")
    void auditorZeroAccessToCases() throws Exception {
        // Auditor attempting to read case A1 -> 404
        mockMvc.perform(get("/api/cases/{id}", caseA1AssignedToBob.getId())
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isNotFound());

        // Auditor attempting to read case B1 -> 404
        mockMvc.perform(get("/api/cases/{id}", caseB1.getId())
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isNotFound());

        // Auditor listing cases receives empty list (no leakage)
        mockMvc.perform(get("/api/cases")
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    @DisplayName("SEC-AUTHZ-05: Case listing strictly isolates records by organisation and analyst assignment")
    void caseListStrictTenantScoping() throws Exception {
        // Client A sees only cases belonging to Org A (2 cases)
        mockMvc.perform(get("/api/cases")
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)));

        // Client B sees only cases belonging to Org B (1 case)
        mockMvc.perform(get("/api/cases")
                        .with(authentication(authFor(clientUserB))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].id", is(caseB1.getId())));

        // Analyst Bob (ORG_INTERNAL) sees only assigned cases regardless of organisation (1 case)
        mockMvc.perform(get("/api/cases")
                        .with(authentication(authFor(analystBob))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].id", is(caseA1AssignedToBob.getId())));
    }

    @Test
    @DisplayName("SEC-AUTHZ-06: Cross-tenant evidence metadata access returns 404 (IDOR protection)")
    void evidenceTenantIsolationAndIdor() throws Exception {
        // Client A can read evidence A1 (belongs to case in Org A)
        mockMvc.perform(get("/api/evidence/{id}", evidenceA1.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", is(evidenceA1.getId())))
                .andExpect(jsonPath("$.originalName", is("ransomware_note.txt")));

        // Client A requesting Evidence B1 (Org B) -> 404 Not Found
        mockMvc.perform(get("/api/evidence/{id}", evidenceB1.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isNotFound());

        // Analyst Bob requesting Evidence A1 -> 200 OK (case is assigned to analyst)
        mockMvc.perform(get("/api/evidence/{id}", evidenceA1.getId())
                        .with(authentication(authFor(analystBob))))
                .andExpect(status().isOk());

        // Auditor requesting Evidence A1 -> 404 Not Found (SR-07 boundary)
        mockMvc.perform(get("/api/evidence/{id}", evidenceA1.getId())
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("SEC-AUTHZ-07: Guessing nonexistent UUIDs returns uniform 404 indistinguishable from cross-tenant access")
    void nonExistentIdsUniform404() throws Exception {
        String randomUuid = UUID.randomUUID().toString();

        mockMvc.perform(get("/api/cases/{id}", randomUuid)
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/api/evidence/{id}", randomUuid)
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("SEC-AUTHZ-08: Unauthenticated requests to API endpoints return HTTP 401 Unauthorized")
    void unauthenticatedReturns401() throws Exception {
        mockMvc.perform(get("/api/cases"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/cases/{id}", caseA1AssignedToBob.getId()))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/evidence/{id}", evidenceA1.getId()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("SEC-AUTHZ-09: Mass assignment protection - client cannot bind organisationId, role, status, owner, or assignedAnalyst")
    void massAssignmentIgnored() throws Exception {
        Map<String, Object> maliciousPayload = new HashMap<>();
        maliciousPayload.put("title", "Legitimate Title");
        maliciousPayload.put("category", "MALWARE");
        maliciousPayload.put("severity", "HIGH");
        maliciousPayload.put("organisationId", orgB.getId());
        maliciousPayload.put("role", "MANAGER");
        maliciousPayload.put("status", "CLOSED");
        maliciousPayload.put("owner", clientUserB.getId());
        maliciousPayload.put("assignedAnalyst", analystBob.getId());

        String json = objectMapper.writeValueAsString(maliciousPayload);

        String responseBody = mockMvc.perform(post("/api/cases")
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title", is("Legitimate Title")))
                .andExpect(jsonPath("$.category", is("MALWARE")))
                .andExpect(jsonPath("$.severity", is("HIGH")))
                .andReturn().getResponse().getContentAsString();

        Map<?, ?> responseMap = objectMapper.readValue(responseBody, Map.class);
        String createdCaseId = (String) responseMap.get("id");

        Case createdCase = caseRepository.findById(createdCaseId).orElseThrow();

        // 1. OrganisationId MUST be derived from caller session (Org A), NOT from payload (Org B)
        assertEquals(orgA.getId(), createdCase.getOrganisation().getId(),
                "Case organisationId must match the caller's session, defeating mass assignment");
        assertNotEquals(orgB.getId(), createdCase.getOrganisation().getId());

        // 2. Status MUST be default OPEN, NOT malicious payload's CLOSED
        assertEquals("OPEN", createdCase.getStatus(),
                "Status must be defaulted server-side to OPEN");

        // 3. Owner MUST be the authenticated caller (clientUserA), NOT clientUserB
        assertEquals(clientUserA.getId(), createdCase.getOwner().getId(),
                "Owner must be the authenticated principal");

        // 4. AssignedAnalyst MUST be null initially, NOT analystBob
        assertNull(createdCase.getAssignedAnalyst(),
                "Assigned analyst must not be settable via creation request");
    }

    @Test
    @DisplayName("SEC-AUTHZ-10: POST /api/cases restricted to CLIENT role; MANAGER and ANALYST receive 403 Forbidden")
    void postCasesRestrictedToClient() throws Exception {
        CreateCaseRequestDto requestDto = new CreateCaseRequestDto("New Manager Case", "PHISHING", "MEDIUM");
        String json = objectMapper.writeValueAsString(requestDto);

        // MANAGER attempting to POST /api/cases -> 403 Forbidden
        mockMvc.perform(post("/api/cases")
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isForbidden());

        // ANALYST attempting to POST /api/cases -> 403 Forbidden
        mockMvc.perform(post("/api/cases")
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("SEC-AUTHZ-11: Category and Severity validation allow-list rejects invalid or malicious values with 400 Bad Request")
    void categoryAndSeverityValidationAllowList() throws Exception {
        // Disallowed category (e.g. SQLi / arbitrary string)
        CreateCaseRequestDto invalidCategory = new CreateCaseRequestDto("Test Title", "MALICIOUS_CATEGORY", "HIGH");
        mockMvc.perform(post("/api/cases")
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidCategory)))
                .andExpect(status().isBadRequest());

        // Disallowed severity
        CreateCaseRequestDto invalidSeverity = new CreateCaseRequestDto("Test Title", "PHISHING", "EXTREME_CRITICAL");
        mockMvc.perform(post("/api/cases")
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidSeverity)))
                .andExpect(status().isBadRequest());

        // Valid allow-listed category and severity
        CreateCaseRequestDto validCase = new CreateCaseRequestDto("Valid Incident", "RANSOMWARE", "CRITICAL");
        mockMvc.perform(post("/api/cases")
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validCase)))
                .andExpect(status().isCreated());
    }
}
