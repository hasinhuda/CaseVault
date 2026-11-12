package com.casevault.cases;

import com.casevault.dto.AssignAnalystRequestDto;
import com.casevault.dto.CreateCaseNoteRequestDto;
import com.casevault.dto.CreateRemediationActionRequestDto;
import com.casevault.dto.UpdateCaseStatusRequestDto;
import com.casevault.dto.UpdateRemediationActionStatusRequestDto;
import com.casevault.model.Case;
import com.casevault.model.CaseNote;
import com.casevault.model.Organisation;
import com.casevault.model.RemediationAction;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseNoteRepository;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.RemediationActionRepository;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class CaseWorkflowSecurityTest {

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

    @Autowired
    private ObjectMapper objectMapper;

    private Organisation orgInternal;
    private Organisation orgA;
    private Organisation orgB;

    private User managerAlice;     // Internal Consultancy Manager (ORG_INTERNAL)
    private User analystBob;        // Internal Consultancy Analyst (ORG_INTERNAL)
    private User analystDave;       // Another Internal Analyst
    private User clientUserA;       // Client Org A User
    private User clientUserB;       // Client Org B User
    private User clientManagerA;    // Client Org A Manager (Non-internal)
    private User auditorUser;       // System Auditor

    private Case caseA;
    private Case caseB;

    @org.springframework.beans.factory.annotation.Autowired
    private org.springframework.jdbc.core.JdbcTemplate cleanupJdbc;

    @BeforeEach
    void setUp() {
        // F-008: FK-safe cleanup (reports, actions, notes, evidence, cases); other classes may have committed rows
        com.casevault.support.TestDatabaseCleaner.deleteCasesAndDependents(cleanupJdbc);
        evidenceRepository.deleteAll();
        remediationActionRepository.deleteAll();
        caseNoteRepository.deleteAll();
        caseRepository.deleteAll();

        Instant now = Instant.now();

        orgInternal = organisationRepository.findByCode("ORG_INTERNAL")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Internal Consultancy", "ORG_INTERNAL", now)));
        orgA = organisationRepository.findByCode("ORG_WF_A")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Workflow Client Org A", "ORG_WF_A", now)));
        orgB = organisationRepository.findByCode("ORG_WF_B")
                .orElseGet(() -> organisationRepository.save(new Organisation(UUID.randomUUID().toString(), "Workflow Client Org B", "ORG_WF_B", now)));

        managerAlice = createUser("wf_manager_alice", orgInternal, Role.MANAGER, now);
        analystBob = createUser("wf_analyst_bob", orgInternal, Role.ANALYST, now);
        analystDave = createUser("wf_analyst_dave", orgInternal, Role.ANALYST, now);
        clientUserA = createUser("wf_client_a", orgA, Role.CLIENT, now);
        clientUserB = createUser("wf_client_b", orgB, Role.CLIENT, now);
        clientManagerA = createUser("wf_client_mgr_a", orgA, Role.MANAGER, now);
        auditorUser = createUser("wf_auditor", null, Role.AUDITOR_ADMIN, now);

        caseA = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgA, "Case A Investigation", "RANSOMWARE", "HIGH", "OPEN", clientUserA, null, now
        ));

        caseB = caseRepository.save(new Case(
                UUID.randomUUID().toString(), orgB, "Case B Security Breach", "DATA_EXFILTRATION", "CRITICAL", "OPEN", clientUserB, null, now
        ));
    }

    private User createUser(String username, Organisation org, Role role, Instant now) {
        String randomSuffix = UUID.randomUUID().toString().substring(0, 8);
        return userRepository.save(new User(
                UUID.randomUUID().toString(),
                org,
                username + "_" + randomSuffix,
                "$argon2id$v=19$m=65536,t=3,p=1$fakeHashForWorkflowTests",
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
    @DisplayName("SEC-CASE-01: FSM Lifecycle transitions - valid transitions succeed; invalid transitions return 400")
    void testFsmStateTransitions() throws Exception {
        // 1. OPEN -> ASSIGNED (Manager assigns analyst)
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("ASSIGNED"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("ASSIGNED")));

        // Assign Bob to caseA
        caseA.setAssignedAnalyst(analystBob);
        caseA.setStatus("ASSIGNED");
        caseRepository.save(caseA);

        // 2. ASSIGNED -> IN_PROGRESS (Analyst advances)
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("IN_PROGRESS"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("IN_PROGRESS")));

        // 3. IN_PROGRESS -> PENDING_REVIEW (Analyst submits for review)
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("PENDING_REVIEW"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("PENDING_REVIEW")));

        // 4. Invalid transition: PENDING_REVIEW -> OPEN (not allowed) -> HTTP 400
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("OPEN"))))
                .andExpect(status().isBadRequest());

        // 5. Valid transition: PENDING_REVIEW -> CLOSED (Manager approves)
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("CLOSED"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("CLOSED")));

        // 6. CLOSED is a terminal state: CLOSED -> IN_PROGRESS -> HTTP 400
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("IN_PROGRESS"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("SEC-CASE-02: Role-based status transition restrictions")
    void testRoleBasedStatusTransitions() throws Exception {
        // CLIENT cannot change status -> 403
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("IN_PROGRESS"))))
                .andExpect(status().isForbidden());

        // Assign caseA to Bob
        caseA.setAssignedAnalyst(analystBob);
        caseA.setStatus("PENDING_REVIEW");
        caseRepository.save(caseA);

        // Assigned ANALYST cannot approve/close case (PENDING_REVIEW -> CLOSED is MANAGER-only) -> 403
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("CLOSED"))))
                .andExpect(status().isForbidden());

        // Unassigned ANALYST Dave cannot access caseA -> 404 (BOLA defense)
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(analystDave)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("CLOSED"))))
                .andExpect(status().isNotFound());

        // AUDITOR_ADMIN attempting status update -> 404 (SR-07)
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(auditorUser)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("CLOSED"))))
                .andExpect(status().isNotFound());

        // Non-internal Client Manager A cannot transition caseB (cross-tenant) -> 404
        mockMvc.perform(put("/api/cases/{id}/status", caseB.getId())
                        .with(authentication(authFor(clientManagerA)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("IN_PROGRESS"))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("SEC-CASE-03: Analyst assignment authorization rules")
    void testAnalystAssignmentSecurity() throws Exception {
        // 1. Internal MANAGER assigns analystBob -> 200, status advances to ASSIGNED
        mockMvc.perform(post("/api/cases/{id}/assign", caseA.getId())
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new AssignAnalystRequestDto(analystBob.getId()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assignedAnalystId", is(analystBob.getId())))
                .andExpect(jsonPath("$.status", is("ASSIGNED")));

        // 2. Non-manager CLIENT attempting to assign -> 403
        mockMvc.perform(post("/api/cases/{id}/assign", caseA.getId())
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new AssignAnalystRequestDto(analystDave.getId()))))
                .andExpect(status().isForbidden());

        // 3. ANALYST attempting self-assignment or assignment -> 403
        mockMvc.perform(post("/api/cases/{id}/assign", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new AssignAnalystRequestDto(analystBob.getId()))))
                .andExpect(status().isForbidden());

        // 4. Target user is not an analyst (e.g. assigning a CLIENT user) -> 400 Bad Request
        mockMvc.perform(post("/api/cases/{id}/assign", caseA.getId())
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new AssignAnalystRequestDto(clientUserA.getId()))))
                .andExpect(status().isBadRequest());

        // 5. Cross-tenant non-internal manager attempting assignment on foreign case -> 404
        mockMvc.perform(post("/api/cases/{id}/assign", caseB.getId())
                        .with(authentication(authFor(clientManagerA)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new AssignAnalystRequestDto(analystBob.getId()))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("SEC-CASE-04: Investigation notes permissions & cross-tenant IDOR defense")
    void testCaseNotesSecurity() throws Exception {
        // Assign caseA to Bob
        caseA.setAssignedAnalyst(analystBob);
        caseRepository.save(caseA);

        // 1. Assigned ANALYST Bob adds note -> 201 Created
        mockMvc.perform(post("/api/cases/{id}/notes", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateCaseNoteRequestDto("Identified suspicious C2 beaconing on port 8443."))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.body", is("Identified suspicious C2 beaconing on port 8443.")))
                .andExpect(jsonPath("$.authorUsername", is(analystBob.getUsername())));

        // 2. Internal MANAGER Alice adds note -> 201 Created
        mockMvc.perform(post("/api/cases/{id}/notes", caseA.getId())
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateCaseNoteRequestDto("Confirmed triage priority."))))
                .andExpect(status().isCreated());

        // 3. CLIENT cannot add notes -> 403 Forbidden
        mockMvc.perform(post("/api/cases/{id}/notes", caseA.getId())
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateCaseNoteRequestDto("Client note attempt"))))
                .andExpect(status().isForbidden());

        // 4. CLIENT can read notes of own case -> 200 OK (2 notes)
        mockMvc.perform(get("/api/cases/{id}/notes", caseA.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)));

        // 5. Cross-tenant clientUserB reading notes on caseA -> 404 Not Found
        mockMvc.perform(get("/api/cases/{id}/notes", caseA.getId())
                        .with(authentication(authFor(clientUserB))))
                .andExpect(status().isNotFound());

        // 6. Cross-tenant clientUserB adding note on caseA -> 404 Not Found
        mockMvc.perform(post("/api/cases/{id}/notes", caseA.getId())
                        .with(authentication(authFor(clientUserB)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateCaseNoteRequestDto("Cross-tenant note injection"))))
                .andExpect(status().isNotFound());

        // 7. AUDITOR_ADMIN has zero access to notes -> 404 Not Found (SR-07)
        mockMvc.perform(get("/api/cases/{id}/notes", caseA.getId())
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isNotFound());

        // 8. Note validation: blank note -> 400 Bad Request
        mockMvc.perform(post("/api/cases/{id}/notes", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateCaseNoteRequestDto("   "))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("SEC-CASE-05: Remediation actions permissions & cross-tenant IDOR defense")
    void testRemediationActionsSecurity() throws Exception {
        // Assign caseA to Bob
        caseA.setAssignedAnalyst(analystBob);
        caseRepository.save(caseA);

        // 1. Assigned ANALYST Bob adds action -> 201 Created
        String responseJson = mockMvc.perform(post("/api/cases/{id}/actions", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateRemediationActionRequestDto("Isolate host 10.0.1.25"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status", is("OPEN")))
                .andExpect(jsonPath("$.description", is("Isolate host 10.0.1.25")))
                .andReturn().getResponse().getContentAsString();

        String actionId = objectMapper.readTree(responseJson).get("id").asText();

        // 2. Manager Alice updates action status to IN_PROGRESS -> 200 OK
        mockMvc.perform(put("/api/cases/{id}/actions/{actionId}/status", caseA.getId(), actionId)
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateRemediationActionStatusRequestDto("IN_PROGRESS"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("IN_PROGRESS")));

        // 3. CLIENT cannot create remediation action -> 403 Forbidden
        mockMvc.perform(post("/api/cases/{id}/actions", caseA.getId())
                        .with(authentication(authFor(clientUserA)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateRemediationActionRequestDto("Client action attempt"))))
                .andExpect(status().isForbidden());

        // 4. CLIENT can read actions of own case -> 200 OK
        mockMvc.perform(get("/api/cases/{id}/actions", caseA.getId())
                        .with(authentication(authFor(clientUserA))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)));

        // 5. Cross-tenant clientUserB reading actions on caseA -> 404 Not Found
        mockMvc.perform(get("/api/cases/{id}/actions", caseA.getId())
                        .with(authentication(authFor(clientUserB))))
                .andExpect(status().isNotFound());

        // 6. Action status validation: invalid status -> 400 Bad Request
        mockMvc.perform(put("/api/cases/{id}/actions/{actionId}/status", caseA.getId(), actionId)
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateRemediationActionStatusRequestDto("INVALID_STATUS"))))
                .andExpect(status().isBadRequest());

        // 7. AUDITOR_ADMIN has zero access to actions -> 404 Not Found (SR-07)
        mockMvc.perform(get("/api/cases/{id}/actions", caseA.getId())
                        .with(authentication(authFor(auditorUser))))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("SEC-CASE-06: Mass-assignment protection - server overrides client claims")
    void testMassAssignmentProtection() throws Exception {
        caseA.setAssignedAnalyst(analystBob);
        caseRepository.save(caseA);

        // Attacker attempts to pass forged organisationId, owner, role, or id in note creation payload
        Map<String, Object> maliciousPayload = new HashMap<>();
        maliciousPayload.put("body", "Legitimate note content");
        maliciousPayload.put("organisationId", orgB.getId());
        maliciousPayload.put("authorId", managerAlice.getId());
        maliciousPayload.put("createdAt", "2000-01-01T00:00:00Z");

        mockMvc.perform(post("/api/cases/{id}/notes", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(maliciousPayload)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.authorUsername", is(analystBob.getUsername())))
                .andExpect(jsonPath("$.authorId", is(analystBob.getId())));
    }

    @Test
    @DisplayName("FUNC-CASE-01: Full case investigation lifecycle workflow")
    void testCompleteInvestigativeLifecycle() throws Exception {
        // Step 1: Case is OPEN
        assertEquals("OPEN", caseA.getStatus());

        // Step 2: Manager Alice assigns Analyst Bob -> status transitions to ASSIGNED
        mockMvc.perform(post("/api/cases/{id}/assign", caseA.getId())
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new AssignAnalystRequestDto(analystBob.getId()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("ASSIGNED")))
                .andExpect(jsonPath("$.assignedAnalystId", is(analystBob.getId())));

        // Step 3: Analyst Bob advances status to IN_PROGRESS
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("IN_PROGRESS"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("IN_PROGRESS")));

        // Step 4: Analyst Bob appends initial forensic findings note
        mockMvc.perform(post("/api/cases/{id}/notes", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateCaseNoteRequestDto("Identified anomalous PowerShell execution."))))
                .andExpect(status().isCreated());

        // Step 5: Analyst Bob logs a remediation action
        String actionJson = mockMvc.perform(post("/api/cases/{id}/actions", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateRemediationActionRequestDto("Revoke Active Directory Kerberos tickets."))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        String actionId = objectMapper.readTree(actionJson).get("id").asText();

        // Step 6: Analyst completes remediation and submits case for review
        mockMvc.perform(put("/api/cases/{id}/actions/{actionId}/status", caseA.getId(), actionId)
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateRemediationActionStatusRequestDto("COMPLETED"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("COMPLETED")));

        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(analystBob)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("PENDING_REVIEW"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("PENDING_REVIEW")));

        // Step 7: Manager Alice reviews and approves case closure
        mockMvc.perform(put("/api/cases/{id}/status", caseA.getId())
                        .with(authentication(authFor(managerAlice)))
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateCaseStatusRequestDto("CLOSED"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("CLOSED")));

        // Verify final state in database
        Case finalCase = caseRepository.findById(caseA.getId()).orElseThrow();
        assertEquals("CLOSED", finalCase.getStatus());
        assertNotNull(finalCase.getAssignedAnalyst());
        assertEquals(analystBob.getId(), finalCase.getAssignedAnalyst().getId());
    }
}

