package com.casevault.controller;

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
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.CaseAccessService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * REST API endpoints for Case, Workflow, Note, RemediationAction, and Evidence operations.
 * Implements requirements SR-01, SR-02, SR-07: delegates access control to CaseAccessService.
 * Controllers never access repositories directly.
 */
@RestController
@RequestMapping("/api")
public class CaseApiController {

    private final CaseAccessService caseAccessService;

    public CaseApiController(CaseAccessService caseAccessService) {
        this.caseAccessService = caseAccessService;
    }

    /**
     * Minimal read endpoint: GET case list
     */
    @GetMapping("/cases")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<CaseResponseDto>> listCases(
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        List<CaseResponseDto> cases = caseAccessService.listCases(principal);
        return ResponseEntity.ok(cases);
    }

    /**
     * Search and filter endpoint: GET /api/cases/search (FR-10, SR-10)
     */
    @GetMapping("/cases/search")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Page<CaseResponseDto>> searchCases(
            @ModelAttribute SearchCasesRequestDto searchRequest,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        Page<CaseResponseDto> page = caseAccessService.searchCases(searchRequest, principal);
        return ResponseEntity.ok(page);
    }

    /**
     * Minimal read endpoint: GET case by ID
     */
    @GetMapping("/cases/{id}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<CaseResponseDto> getCaseById(
            @PathVariable("id") String id,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        CaseResponseDto caseDto = caseAccessService.getCaseById(id, principal);
        return ResponseEntity.ok(caseDto);
    }

    /**
     * Status transition endpoint: PUT /api/cases/{id}/status (FR-06)
     */
    @PutMapping("/cases/{id}/status")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<CaseResponseDto> updateStatus(
            @PathVariable("id") String id,
            @Valid @RequestBody UpdateCaseStatusRequestDto dto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        CaseResponseDto updated = caseAccessService.transitionCaseStatus(id, dto, principal);
        return ResponseEntity.ok(updated);
    }

    /**
     * Analyst assignment endpoint: POST /api/cases/{id}/assign (FR-05)
     */
    @PostMapping("/cases/{id}/assign")
    @PreAuthorize("hasRole('MANAGER')")
    public ResponseEntity<CaseResponseDto> assignAnalyst(
            @PathVariable("id") String id,
            @Valid @RequestBody AssignAnalystRequestDto dto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        CaseResponseDto updated = caseAccessService.designateAnalyst(id, dto, principal);
        return ResponseEntity.ok(updated);
    }

    /**
     * Case notes: POST /api/cases/{id}/notes (FR-07)
     */
    @PostMapping("/cases/{id}/notes")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<CaseNoteResponseDto> addNote(
            @PathVariable("id") String id,
            @Valid @RequestBody CreateCaseNoteRequestDto dto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        CaseNoteResponseDto note = caseAccessService.appendCaseNote(id, dto, principal);
        return ResponseEntity.status(HttpStatus.CREATED).body(note);
    }

    /**
     * Case notes: GET /api/cases/{id}/notes (FR-07)
     */
    @GetMapping("/cases/{id}/notes")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<CaseNoteResponseDto>> getNotes(
            @PathVariable("id") String id,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        List<CaseNoteResponseDto> notes = caseAccessService.getCaseNotes(id, principal);
        return ResponseEntity.ok(notes);
    }

    /**
     * Remediation actions: POST /api/cases/{id}/actions (FR-07)
     */
    @PostMapping("/cases/{id}/actions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<RemediationActionResponseDto> addAction(
            @PathVariable("id") String id,
            @Valid @RequestBody CreateRemediationActionRequestDto dto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        RemediationActionResponseDto action = caseAccessService.createRemediationAction(id, dto, principal);
        return ResponseEntity.status(HttpStatus.CREATED).body(action);
    }

    /**
     * Remediation actions: GET /api/cases/{id}/actions (FR-07)
     */
    @GetMapping("/cases/{id}/actions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<RemediationActionResponseDto>> getActions(
            @PathVariable("id") String id,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        List<RemediationActionResponseDto> actions = caseAccessService.getRemediationActions(id, principal);
        return ResponseEntity.ok(actions);
    }

    /**
     * Remediation actions: PUT /api/cases/{id}/actions/{actionId}/status (FR-07)
     */
    @PutMapping("/cases/{id}/actions/{actionId}/status")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<RemediationActionResponseDto> updateActionStatus(
            @PathVariable("id") String id,
            @PathVariable("actionId") String actionId,
            @Valid @RequestBody UpdateRemediationActionStatusRequestDto dto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        RemediationActionResponseDto updated = caseAccessService.transitionRemediationActionStatus(id, actionId, dto, principal);
        return ResponseEntity.ok(updated);
    }

    /**
     * Minimal read endpoint: GET evidence metadata by ID
     */
    @GetMapping("/evidence/{id}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<EvidenceResponseDto> getEvidenceById(
            @PathVariable("id") String id,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        EvidenceResponseDto evidenceDto = caseAccessService.getEvidenceById(id, principal);
        return ResponseEntity.ok(evidenceDto);
    }

    /**
     * Minimal write endpoint for testing mass-assignment prevention (SR-01).
     * Restricts case creation strictly to CLIENT role per FR-04 and product role specification.
     */
    @PostMapping("/cases")
    @PreAuthorize("hasRole('CLIENT')")
    public ResponseEntity<CaseResponseDto> createCase(
            @Valid @RequestBody CreateCaseRequestDto requestDto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        CaseResponseDto created = caseAccessService.createCase(requestDto, principal);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }
}
