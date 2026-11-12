package com.casevault.service;

import com.casevault.dto.ReportRequestDto;
import com.casevault.dto.ReportResponseDto;
import com.casevault.security.CaseVaultUserPrincipal;

import java.util.List;

/**
 * Incident report workflow (FR-11, FR-12, SR-02, SR-06). Every method is tenant aware and enforced server side.
 * Unauthorised or cross-tenant access throws ResourceNotFoundException (HTTP 404, never 403); an invalid
 * transition or invalid body throws BadRequestException (HTTP 400).
 */
public interface ReportService {

    /** Only the ANALYST assigned to the case; not on a closed case. */
    ReportResponseDto createDraft(String caseId, ReportRequestDto request, CaseVaultUserPrincipal principal);

    /** Only the author, only while DRAFT; not on a closed case. */
    ReportResponseDto updateDraft(String caseId, String reportId, ReportRequestDto request,
                                  CaseVaultUserPrincipal principal);

    /** Only the author, DRAFT to SUBMITTED; not on a closed case. */
    ReportResponseDto submit(String caseId, String reportId, CaseVaultUserPrincipal principal);

    /** Only a MANAGER who can see the case, never the author, SUBMITTED to APPROVED. */
    ReportResponseDto approve(String caseId, String reportId, CaseVaultUserPrincipal principal);

    /** ANALYST and MANAGER see all states; CLIENT sees APPROVED only; AUDITOR_ADMIN gets 404. */
    List<ReportResponseDto> list(String caseId, CaseVaultUserPrincipal principal);

    ReportResponseDto get(String caseId, String reportId, CaseVaultUserPrincipal principal);
}
