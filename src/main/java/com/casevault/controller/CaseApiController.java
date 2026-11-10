package com.casevault.controller;

import com.casevault.dto.CaseResponseDto;
import com.casevault.dto.CreateCaseRequestDto;
import com.casevault.dto.EvidenceResponseDto;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.CaseAccessService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Minimal REST API endpoints for Case and Evidence operations.
 * Implements requirement SR-01, SR-02, SR-07: delegates access control to CaseAccessService.
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

