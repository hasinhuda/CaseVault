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
    private com.casevault.repository.CaseNoteRepository caseNoteRepository;

    @Autowired
    private com.casevault.repository.RemediationActionRepository remediationActionRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private com.casevault.repository.ReportRepository reportRepository;

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
        reportRepository.deleteAll();
        remediationActionRepository.deleteAll();
        caseNoteRepository.deleteAll();
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
                UUID.randomUUID().toString(),
                caseA1AssignedToBob,
                "ransomware_note.txt",
                UUID.randomUUID().toString(),
                "text/plain",
                1024L,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                1,
                clientUserA,
                now
        ));

        evidenceB1 = evidenceRepository.save(new Evidence(
                UUID.randomUUID().toString(),
                caseB1,
                "confidential_dump.csv",
                UUID.randomUUID().toString(),
                "text/plain",
                2048L,
                "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
                1,
                clientUserB,
                now
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

    @org.junit.jupiter.api.io.TempDir
    java.nio.file.Path tempStorageDir;

    private com.casevault.service.DefaultCaseAccessService getDirectCaseAccessService() {
        com.casevault.service.EvidenceStorageService tempEvidenceStore = new com.casevault.service.EvidenceStorageService(
                tempStorageDir.resolve("evidence").toString(),
                tempStorageDir.resolve("keyset.json").toString()
        );
        return new com.casevault.service.DefaultCaseAccessService(
                caseRepository,
                evidenceRepository,
                organisationRepository,
                userRepository,
                caseNoteRepository,
                remediationActionRepository,
                new com.casevault.security.AccessPolicy(),
                new com.casevault.service.EvidenceValidator(new com.casevault.service.StubAntivirusScanner()),
                tempEvidenceStore,
                new com.casevault.service.LoggingAuditEventRecorder()
        );
    }

    private CaseVaultUserPrincipal principalFor(User user) {
        return new CaseVaultUserPrincipal(user, Instant.now());
    }

    private static final byte[] SYNTHETIC_TEXT_BYTES = "2026-11-10 14:00:00 Incident Report Case #49281".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @Test
    @DisplayName("SEC-EVID-AUTHZ-01: CLIENT own organisation can upload, list, and download; CLIENT from other organisation receives 404")
    void clientOwnOrgEvidenceLifecycleAndCrossTenantIsolation() {
        com.casevault.service.DefaultCaseAccessService service = getDirectCaseAccessService();
        CaseVaultUserPrincipal clientPrincipalA = principalFor(clientUserA);
        CaseVaultUserPrincipal clientPrincipalB = principalFor(clientUserB);

        // 1. Client User A uploads to own organisation Case A1 -> OK
        org.springframework.mock.web.MockMultipartFile validFile = new org.springframework.mock.web.MockMultipartFile(
                "file", "network_dump.txt", "text/plain", SYNTHETIC_TEXT_BYTES
        );
        com.casevault.dto.EvidenceResponseDto uploadedA = service.uploadEvidence(caseA1AssignedToBob.getId(), validFile, clientPrincipalA);
        org.junit.jupiter.api.Assertions.assertNotNull(uploadedA);
        org.junit.jupiter.api.Assertions.assertEquals("network_dump.txt", uploadedA.getOriginalName());

        // 2. Client User A lists evidence of Case A1 -> OK (contains uploaded evidence)
        java.util.List<com.casevault.dto.EvidenceResponseDto> listA = service.listEvidence(caseA1AssignedToBob.getId(), clientPrincipalA);
        org.junit.jupiter.api.Assertions.assertTrue(listA.stream().anyMatch(e -> e.getId().equals(uploadedA.getId())));

        // 3. Client User A downloads evidence from Case A1 -> OK (payload matches plaintext)
        com.casevault.service.EvidenceDownload downloadA = service.openEvidence(caseA1AssignedToBob.getId(), uploadedA.getId(), clientPrincipalA);
        org.junit.jupiter.api.Assertions.assertArrayEquals(SYNTHETIC_TEXT_BYTES, downloadA.content());

        // 4. Cross-tenant attempt: Client User B attempts upload to Case A1 -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.uploadEvidence(caseA1AssignedToBob.getId(), validFile, clientPrincipalB));

        // 5. Cross-tenant attempt: Client User B attempts list evidence of Case A1 -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.listEvidence(caseA1AssignedToBob.getId(), clientPrincipalB));

        // 6. Cross-tenant attempt: Client User B attempts download of evidence from Case A1 -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.openEvidence(caseA1AssignedToBob.getId(), uploadedA.getId(), clientPrincipalB));

        // 7. Cross-tenant attempt: Client User A attempts upload to Case B1 -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.uploadEvidence(caseB1.getId(), validFile, clientPrincipalA));

        // 8. Cross-tenant attempt: Client User A attempts list evidence of Case B1 -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.listEvidence(caseB1.getId(), clientPrincipalA));
    }

    @Test
    @DisplayName("SEC-EVID-AUTHZ-02: Assigned ANALYST can upload, list, and download; unassigned ANALYST receives 404")
    void analystAssignedCaseEvidenceLifecycleAndUnassignedBoundary() {
        com.casevault.service.DefaultCaseAccessService service = getDirectCaseAccessService();
        CaseVaultUserPrincipal analystPrincipalBob = principalFor(analystBob);

        // 1. Assigned Analyst Bob uploads evidence to assigned Case A1 -> OK
        org.springframework.mock.web.MockMultipartFile analystFile = new org.springframework.mock.web.MockMultipartFile(
                "file", "analyst_notes.txt", "text/plain", SYNTHETIC_TEXT_BYTES
        );
        com.casevault.dto.EvidenceResponseDto uploaded = service.uploadEvidence(caseA1AssignedToBob.getId(), analystFile, analystPrincipalBob);
        org.junit.jupiter.api.Assertions.assertNotNull(uploaded);

        // 2. Assigned Analyst Bob lists evidence of Case A1 -> OK
        java.util.List<com.casevault.dto.EvidenceResponseDto> list = service.listEvidence(caseA1AssignedToBob.getId(), analystPrincipalBob);
        org.junit.jupiter.api.Assertions.assertTrue(list.stream().anyMatch(e -> e.getId().equals(uploaded.getId())));

        // 3. Assigned Analyst Bob downloads evidence of Case A1 -> OK
        com.casevault.service.EvidenceDownload download = service.openEvidence(caseA1AssignedToBob.getId(), uploaded.getId(), analystPrincipalBob);
        org.junit.jupiter.api.Assertions.assertArrayEquals(SYNTHETIC_TEXT_BYTES, download.content());

        // 4. Unassigned Analyst Bob attempts upload to Case A2 (unassigned) -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.uploadEvidence(caseA2Unassigned.getId(), analystFile, analystPrincipalBob));

        // 5. Unassigned Analyst Bob attempts list evidence of Case A2 -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.listEvidence(caseA2Unassigned.getId(), analystPrincipalBob));

        // 6. Unassigned Analyst Bob attempts download from Case A2 -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.openEvidence(caseA2Unassigned.getId(), UUID.randomUUID().toString(), analystPrincipalBob));

        // 7. Unassigned Analyst Bob attempts upload to Case B1 -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.uploadEvidence(caseB1.getId(), analystFile, analystPrincipalBob));
    }

    @Test
    @DisplayName("SEC-EVID-AUTHZ-03: Internal consultancy MANAGER (ORG_INTERNAL) can view and download any case; client MANAGER restricted to own organisation")
    void managerInternalConsultancyVsClientManagerBoundaries() {
        com.casevault.service.DefaultCaseAccessService service = getDirectCaseAccessService();
        CaseVaultUserPrincipal internalManagerPrincipal = principalFor(managerAlice);
        CaseVaultUserPrincipal clientManagerPrincipal = principalFor(clientManagerA);

        // First upload evidence to Case A1 and Case B1
        org.springframework.mock.web.MockMultipartFile fileA = new org.springframework.mock.web.MockMultipartFile(
                "file", "ev_a1.txt", "text/plain", SYNTHETIC_TEXT_BYTES
        );
        org.springframework.mock.web.MockMultipartFile fileB = new org.springframework.mock.web.MockMultipartFile(
                "file", "ev_b1.txt", "text/plain", SYNTHETIC_TEXT_BYTES
        );
        com.casevault.dto.EvidenceResponseDto uploadedA = service.uploadEvidence(caseA1AssignedToBob.getId(), fileA, principalFor(clientUserA));
        com.casevault.dto.EvidenceResponseDto uploadedB = service.uploadEvidence(caseB1.getId(), fileB, principalFor(clientUserB));

        // 1. Internal consultancy manager Alice (ORG_INTERNAL) can view/list Case A1 and Case B1
        java.util.List<com.casevault.dto.EvidenceResponseDto> listA = service.listEvidence(caseA1AssignedToBob.getId(), internalManagerPrincipal);
        org.junit.jupiter.api.Assertions.assertTrue(listA.stream().anyMatch(e -> e.getId().equals(uploadedA.getId())));

        java.util.List<com.casevault.dto.EvidenceResponseDto> listB = service.listEvidence(caseB1.getId(), internalManagerPrincipal);
        org.junit.jupiter.api.Assertions.assertTrue(listB.stream().anyMatch(e -> e.getId().equals(uploadedB.getId())));

        // 2. Internal consultancy manager Alice can download evidence from Case A1 and Case B1
        com.casevault.service.EvidenceDownload dlA = service.openEvidence(caseA1AssignedToBob.getId(), uploadedA.getId(), internalManagerPrincipal);
        org.junit.jupiter.api.Assertions.assertArrayEquals(SYNTHETIC_TEXT_BYTES, dlA.content());

        com.casevault.service.EvidenceDownload dlB = service.openEvidence(caseB1.getId(), uploadedB.getId(), internalManagerPrincipal);
        org.junit.jupiter.api.Assertions.assertArrayEquals(SYNTHETIC_TEXT_BYTES, dlB.content());

        // 3. Client manager (Org A) can view/download own org Case A1
        java.util.List<com.casevault.dto.EvidenceResponseDto> clientMgrListA = service.listEvidence(caseA1AssignedToBob.getId(), clientManagerPrincipal);
        org.junit.jupiter.api.Assertions.assertTrue(clientMgrListA.stream().anyMatch(e -> e.getId().equals(uploadedA.getId())));

        com.casevault.service.EvidenceDownload clientMgrDlA = service.openEvidence(caseA1AssignedToBob.getId(), uploadedA.getId(), clientManagerPrincipal);
        org.junit.jupiter.api.Assertions.assertArrayEquals(SYNTHETIC_TEXT_BYTES, clientMgrDlA.content());

        // 4. Client manager (Org A) CANNOT view or download foreign Org B Case B1 -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.listEvidence(caseB1.getId(), clientManagerPrincipal));

        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.openEvidence(caseB1.getId(), uploadedB.getId(), clientManagerPrincipal));
    }

    @Test
    @DisplayName("SEC-EVID-AUTHZ-04: AUDITOR_ADMIN has strict zero-access to evidence and receives 404 on upload, list, and download (SR-07)")
    void auditorAdminZeroAccessToEvidence() {
        com.casevault.service.DefaultCaseAccessService service = getDirectCaseAccessService();
        CaseVaultUserPrincipal auditorPrincipal = principalFor(auditorUser);

        // Upload evidence to Case A1 using authorized client
        org.springframework.mock.web.MockMultipartFile file = new org.springframework.mock.web.MockMultipartFile(
                "file", "audit_target.txt", "text/plain", SYNTHETIC_TEXT_BYTES
        );
        com.casevault.dto.EvidenceResponseDto uploaded = service.uploadEvidence(caseA1AssignedToBob.getId(), file, principalFor(clientUserA));

        // 1. AUDITOR_ADMIN attempting upload -> 404
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.uploadEvidence(caseA1AssignedToBob.getId(), file, auditorPrincipal));

        // 2. AUDITOR_ADMIN attempting list -> 404
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.listEvidence(caseA1AssignedToBob.getId(), auditorPrincipal));

        // 3. AUDITOR_ADMIN attempting download -> 404
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.openEvidence(caseA1AssignedToBob.getId(), uploaded.getId(), auditorPrincipal));

        // 4. AUDITOR_ADMIN attempting getEvidenceById -> 404
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.getEvidenceById(uploaded.getId(), auditorPrincipal));
    }

    @Test
    @DisplayName("SEC-EVID-AUTHZ-05: Evidence of case B requested under case A returns 404; unknown IDs return 404")
    void crossCaseEvidenceMismatchAndUnknownIdsReturn404() {
        com.casevault.service.DefaultCaseAccessService service = getDirectCaseAccessService();
        CaseVaultUserPrincipal clientPrincipalA = principalFor(clientUserA);
        CaseVaultUserPrincipal internalManagerPrincipal = principalFor(managerAlice);

        org.springframework.mock.web.MockMultipartFile fileA = new org.springframework.mock.web.MockMultipartFile(
                "file", "ev_a.txt", "text/plain", SYNTHETIC_TEXT_BYTES
        );
        org.springframework.mock.web.MockMultipartFile fileB = new org.springframework.mock.web.MockMultipartFile(
                "file", "ev_b.txt", "text/plain", SYNTHETIC_TEXT_BYTES
        );
        com.casevault.dto.EvidenceResponseDto uploadedA = service.uploadEvidence(caseA1AssignedToBob.getId(), fileA, clientPrincipalA);
        com.casevault.dto.EvidenceResponseDto uploadedB = service.uploadEvidence(caseB1.getId(), fileB, principalFor(clientUserB));

        // 1. Evidence B requested under Case A1 by manager (who has access to both cases) -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.openEvidence(caseA1AssignedToBob.getId(), uploadedB.getId(), internalManagerPrincipal));

        // 2. Evidence A requested under Case B1 by manager -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.openEvidence(caseB1.getId(), uploadedA.getId(), internalManagerPrincipal));

        // 3. Unknown case ID with valid evidence ID -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.openEvidence(UUID.randomUUID().toString(), uploadedA.getId(), internalManagerPrincipal));

        // 4. Valid case ID with unknown evidence ID -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.openEvidence(caseA1AssignedToBob.getId(), UUID.randomUUID().toString(), internalManagerPrincipal));

        // 5. Unknown case ID and unknown evidence ID -> 404 Not Found
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class,
                () -> service.openEvidence(UUID.randomUUID().toString(), UUID.randomUUID().toString(), internalManagerPrincipal));
    }

    @Test
    @DisplayName("SEC-EVID-AUTHZ-06: Upload to a CLOSED case is rejected with 400 Bad Request")
    void uploadToClosedCaseRejected() {
        com.casevault.service.DefaultCaseAccessService service = getDirectCaseAccessService();
        CaseVaultUserPrincipal clientPrincipalA = principalFor(clientUserA);

        // Create a case in CLOSED state
        Case closedCase = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgA, "Closed Incident Case", "MALWARE", "LOW", "CLOSED", clientUserA, analystBob, Instant.now()
        ));

        org.springframework.mock.web.MockMultipartFile file = new org.springframework.mock.web.MockMultipartFile(
                "file", "late_evidence.txt", "text/plain", SYNTHETIC_TEXT_BYTES
        );

        // Uploading to a CLOSED case must throw BadRequestException
        com.casevault.exception.BadRequestException ex = org.junit.jupiter.api.Assertions.assertThrows(
                com.casevault.exception.BadRequestException.class,
                () -> service.uploadEvidence(closedCase.getId(), file, clientPrincipalA)
        );
        org.junit.jupiter.api.Assertions.assertTrue(ex.getMessage().contains("Evidence cannot be uploaded to a closed case."));
    }

    @Test
    @DisplayName("SEC-EVID-AUTHZ-07: Mass assignment prevention: organisationId, uploader, and caseId form parameters are ignored")
    void massAssignmentAttributesIgnored() throws Exception {
        // Upload via MockMvc with attacker-supplied organisationId, uploader, and caseId in multipart form params
        org.springframework.mock.web.MockMultipartFile uploadFile = new org.springframework.mock.web.MockMultipartFile(
                "file", "mass_assignment_probe.txt", "text/plain", SYNTHETIC_TEXT_BYTES
        );

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart("/cases/{id}/evidence", caseA1AssignedToBob.getId())
                        .file(uploadFile)
                        .param("organisationId", orgB.getId())
                        .param("uploadedBy", clientUserB.getId())
                        .param("uploaderId", clientUserB.getId())
                        .param("uploader", clientUserB.getId())
                        .param("caseId", caseB1.getId())
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        // Verify in database that saved entity strictly bound authenticated principal and target path variable
        java.util.List<Evidence> savedList = evidenceRepository.findByACaseId(caseA1AssignedToBob.getId());
        Evidence probe = savedList.stream()
                .filter(e -> "mass_assignment_probe.txt".equals(e.getOriginalName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Uploaded evidence must exist in Case A1 records"));

        org.junit.jupiter.api.Assertions.assertEquals(caseA1AssignedToBob.getId(), probe.getCase().getId(), "Case ID must match path variable");
        org.junit.jupiter.api.Assertions.assertEquals(orgA.getId(), probe.getCase().getOrganisation().getId(), "Organisation must remain Org A");
        org.junit.jupiter.api.Assertions.assertEquals(clientUserA.getId(), probe.getUploadedBy().getId(), "Uploader must be authenticated principal Client A");
        org.junit.jupiter.api.Assertions.assertNotEquals(clientUserB.getId(), probe.getUploadedBy().getId(), "Attacker uploader ID must be ignored");
        org.junit.jupiter.api.Assertions.assertNotEquals(orgB.getId(), probe.getCase().getOrganisation().getId(), "Attacker org ID must be ignored");
    }

    @Test
    @DisplayName("SEC-EVID-AUTHZ-08: Role upload authorization enforcement (FR-08): only CLIENT and assigned ANALYST may upload; MANAGER and AUDITOR_ADMIN cannot upload")
    void uploadRolePermissionEnforcement() {
        com.casevault.service.DefaultCaseAccessService service = getDirectCaseAccessService();
        org.springframework.mock.web.MockMultipartFile file = new org.springframework.mock.web.MockMultipartFile(
                "file", "role_test.txt", "text/plain", SYNTHETIC_TEXT_BYTES
        );

        // 1. CLIENT (own org) may upload -> OK
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                () -> service.uploadEvidence(caseA1AssignedToBob.getId(), file, principalFor(clientUserA))
        );

        // 2. ANALYST (assigned to case) may upload -> OK
        org.junit.jupiter.api.Assertions.assertDoesNotThrow(
                () -> service.uploadEvidence(caseA1AssignedToBob.getId(), file, principalFor(analystBob))
        );

        // 3. MANAGER (even internal ORG_INTERNAL) cannot upload evidence per FR-08 -> 404
        org.junit.jupiter.api.Assertions.assertThrows(
                com.casevault.exception.ResourceNotFoundException.class,
                () -> service.uploadEvidence(caseA1AssignedToBob.getId(), file, principalFor(managerAlice))
        );

        // 4. MANAGER of client org cannot upload evidence -> 404
        org.junit.jupiter.api.Assertions.assertThrows(
                com.casevault.exception.ResourceNotFoundException.class,
                () -> service.uploadEvidence(caseA1AssignedToBob.getId(), file, principalFor(clientManagerA))
        );

        // 5. AUDITOR_ADMIN cannot upload evidence -> 404
        org.junit.jupiter.api.Assertions.assertThrows(
                com.casevault.exception.ResourceNotFoundException.class,
                () -> service.uploadEvidence(caseA1AssignedToBob.getId(), file, principalFor(auditorUser))
        );
    }

    // ---- Phase 7A: report role x operation matrix (ADDED; no existing test changed) ----

    private com.casevault.service.DefaultReportService reportService() {
        return new com.casevault.service.DefaultReportService(reportRepository, caseRepository, userRepository,
                new com.casevault.security.AccessPolicy(), new com.casevault.service.LoggingAuditEventRecorder());
    }

    private void assertReportNotFound(org.junit.jupiter.api.function.Executable call, String what) {
        org.junit.jupiter.api.Assertions.assertThrows(com.casevault.exception.ResourceNotFoundException.class, call, what);
    }

    @Test
    @DisplayName("SEC-REPORT-AUTHZ-01: role x operation matrix for report create, update, submit, approve, list and get (404, never 403)")
    void reportRoleOperationMatrix() {
        com.casevault.service.DefaultReportService svc = reportService();
        Instant now = Instant.now();
        User analystEve = createUser("analyst_eve_" + UUID.randomUUID().toString().substring(0, 8), orgInternal, Role.ANALYST, now);
        String caseId = caseA1AssignedToBob.getId();
        com.casevault.dto.ReportRequestDto body = new com.casevault.dto.ReportRequestDto("Matrix report body");

        // create: only the assigned analyst
        for (User denied : new User[]{analystEve, managerAlice, clientManagerA, clientUserA, clientUserB, auditorUser}) {
            assertReportNotFound(() -> svc.createDraft(caseId, body, principalFor(denied)), "create by " + denied.getRole());
        }
        assertReportNotFound(() -> svc.createDraft(caseA2Unassigned.getId(), body, principalFor(analystBob)), "create on unassigned case");
        com.casevault.dto.ReportResponseDto draft = svc.createDraft(caseId, body, principalFor(analystBob));
        assertEquals("DRAFT", draft.status());
        String reportId = draft.id();

        // get/list of a DRAFT: analyst (assigned) and managers in scope only
        for (User allowed : new User[]{analystBob, managerAlice, clientManagerA}) {
            assertEquals(reportId, svc.get(caseId, reportId, principalFor(allowed)).id());
            assertEquals(1, svc.list(caseId, principalFor(allowed)).size());
        }
        for (User denied : new User[]{clientUserA, analystEve, clientUserB, auditorUser}) {
            assertReportNotFound(() -> svc.get(caseId, reportId, principalFor(denied)), "get draft by " + denied.getRole());
        }
        assertEquals(0, svc.list(caseId, principalFor(clientUserA)).size(), "client list hides drafts");
        for (User denied : new User[]{clientUserB, analystEve, auditorUser}) {
            assertReportNotFound(() -> svc.list(caseId, principalFor(denied)), "list by " + denied.getRole());
        }

        // update: author only
        for (User denied : new User[]{analystEve, managerAlice, clientManagerA, clientUserA, clientUserB, auditorUser}) {
            assertReportNotFound(() -> svc.updateDraft(caseId, reportId, body, principalFor(denied)), "update by " + denied.getRole());
        }
        assertEquals("DRAFT", svc.updateDraft(caseId, reportId, new com.casevault.dto.ReportRequestDto("Edited"), principalFor(analystBob)).status());

        // submit: author only
        for (User denied : new User[]{analystEve, managerAlice, clientManagerA, clientUserA, clientUserB, auditorUser}) {
            assertReportNotFound(() -> svc.submit(caseId, reportId, principalFor(denied)), "submit by " + denied.getRole());
        }
        assertEquals("SUBMITTED", svc.submit(caseId, reportId, principalFor(analystBob)).status());

        // approve: managers who can see the case only
        for (User denied : new User[]{analystBob, analystEve, clientUserA, clientUserB, auditorUser}) {
            assertReportNotFound(() -> svc.approve(caseId, reportId, principalFor(denied)), "approve by " + denied.getRole());
        }
        // a MANAGER of another organisation cannot see the case (client-org manager of org A on case B1)
        assertReportNotFound(() -> svc.approve(caseB1.getId(), reportId, principalFor(clientManagerA)), "manager of other org");
        com.casevault.dto.ReportResponseDto approved = svc.approve(caseId, reportId, principalFor(managerAlice));
        assertEquals("APPROVED", approved.status());
        assertEquals(managerAlice.getId(), approved.approvedById());

        // after approval the CLIENT of the case organisation sees it; other tenants and the auditor still do not
        assertEquals(reportId, svc.get(caseId, reportId, principalFor(clientUserA)).id());
        assertEquals(1, svc.list(caseId, principalFor(clientUserA)).size());
        assertReportNotFound(() -> svc.get(caseId, reportId, principalFor(clientUserB)), "other tenant");
        assertReportNotFound(() -> svc.get(caseId, reportId, principalFor(auditorUser)), "auditor");
        assertReportNotFound(() -> svc.list(caseId, principalFor(auditorUser)), "auditor list");
    }
}
