package com.casevault.service;

import com.casevault.dto.AssignAnalystRequestDto;
import com.casevault.dto.CaseNoteResponseDto;
import com.casevault.dto.CaseResponseDto;
import com.casevault.dto.CreateCaseNoteRequestDto;
import com.casevault.dto.CreateCaseRequestDto;
import com.casevault.dto.CreateRemediationActionRequestDto;
import com.casevault.dto.EvidenceResponseDto;
import com.casevault.dto.RemediationActionResponseDto;
import com.casevault.dto.SearchCasesRequestDto;
import com.casevault.dto.UpdateCaseStatusRequestDto;
import com.casevault.dto.UpdateRemediationActionStatusRequestDto;
import com.casevault.dto.UserSummaryDto;
import com.casevault.security.CaseVaultUserPrincipal;
import org.springframework.data.domain.Page;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

/**
 * Service interface enforcing tenant isolation, role boundaries, and lifecycle workflow
 * for Case, Evidence, CaseNote, and RemediationAction domain objects.
 * Implements ADR 0003, FR-04..FR-07, FR-10, and requirements SR-01, SR-02, SR-07, SR-10.
 */
public interface CaseAccessService {

    /**
     * Retrieves a Case by ID, enforcing tenant isolation and role-based access rules.
     * Unauthorized or cross-tenant access throws ResourceNotFoundException (HTTP 404).
     */
    CaseResponseDto getCaseById(String caseId, CaseVaultUserPrincipal principal);

    /**
     * Lists cases accessible to the authenticated principal according to role and organisation scope.
     */
    List<CaseResponseDto> listCases(CaseVaultUserPrincipal principal);

    /**
     * Searches and filters cases with criteria, sorting, and pagination (FR-10).
     */
    Page<CaseResponseDto> searchCases(SearchCasesRequestDto criteria, CaseVaultUserPrincipal principal);

    /**
     * Creates a new case for the principal's organisation (FR-04, SR-01).
     * Restricted strictly to CLIENT role.
     */
    CaseResponseDto createCase(CreateCaseRequestDto requestDto, CaseVaultUserPrincipal principal);

    /**
     * Updates the status of a case according to strict FSM lifecycle rules (FR-06).
     */
    CaseResponseDto transitionCaseStatus(String caseId, UpdateCaseStatusRequestDto dto, CaseVaultUserPrincipal principal);

    /**
     * Assigns a primary investigator analyst to a case (FR-05).
     * Only permitted for MANAGER role.
     */
    CaseResponseDto designateAnalyst(String caseId, AssignAnalystRequestDto dto, CaseVaultUserPrincipal principal);

    /**
     * Appends an immutable chronological case note (FR-07).
     */
    CaseNoteResponseDto appendCaseNote(String caseId, CreateCaseNoteRequestDto dto, CaseVaultUserPrincipal principal);

    /**
     * Retrieves chronological case notes for an accessible case (FR-07).
     */
    List<CaseNoteResponseDto> getCaseNotes(String caseId, CaseVaultUserPrincipal principal);

    /**
     * Creates a remediation action item for an accessible case (FR-07).
     */
    RemediationActionResponseDto createRemediationAction(String caseId, CreateRemediationActionRequestDto dto, CaseVaultUserPrincipal principal);

    /**
     * Updates the status of a remediation action (FR-07).
     */
    RemediationActionResponseDto transitionRemediationActionStatus(String caseId, String actionId,
                                                                 UpdateRemediationActionStatusRequestDto dto,
                                                                 CaseVaultUserPrincipal principal);

    /**
     * Retrieves remediation actions for an accessible case (FR-07).
     */
    List<RemediationActionResponseDto> getRemediationActions(String caseId, CaseVaultUserPrincipal principal);

    /**
     * Lists all active analysts available for case assignment.
     */
    List<UserSummaryDto> listAvailableAnalysts(CaseVaultUserPrincipal principal);

    /**
     * Retrieves Evidence metadata by ID, enforcing tenant isolation inherited from the parent case.
     */
    EvidenceResponseDto getEvidenceById(String evidenceId, CaseVaultUserPrincipal principal);

    EvidenceResponseDto uploadEvidence(String caseId, MultipartFile file, CaseVaultUserPrincipal principal);

    List<EvidenceResponseDto> listEvidence(String caseId, CaseVaultUserPrincipal principal);

    EvidenceDownload openEvidence(String caseId, String evidenceId, CaseVaultUserPrincipal principal);
}
