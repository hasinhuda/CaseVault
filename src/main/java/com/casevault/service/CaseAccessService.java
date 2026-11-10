package com.casevault.service;

import com.casevault.dto.CaseResponseDto;
import com.casevault.dto.CreateCaseRequestDto;
import com.casevault.dto.EvidenceResponseDto;
import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.Case;
import com.casevault.model.Evidence;
import com.casevault.model.Organisation;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.EvidenceRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.AccessPolicy;
import com.casevault.security.CaseVaultUserPrincipal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service enforcing tenant isolation and role boundaries for Case and Evidence domain objects.
 * Implements ADR 0003 and requirements SR-01, SR-02, SR-07.
 */
@Service
@Transactional(readOnly = true)
public class CaseAccessService {

    private final CaseRepository caseRepository;
    private final EvidenceRepository evidenceRepository;
    private final OrganisationRepository organisationRepository;
    private final UserRepository userRepository;
    private final AccessPolicy accessPolicy;

    public CaseAccessService(CaseRepository caseRepository,
                             EvidenceRepository evidenceRepository,
                             OrganisationRepository organisationRepository,
                             UserRepository userRepository,
                             AccessPolicy accessPolicy) {
        this.caseRepository = caseRepository;
        this.evidenceRepository = evidenceRepository;
        this.organisationRepository = organisationRepository;
        this.userRepository = userRepository;
        this.accessPolicy = accessPolicy;
    }

    /**
     * Retrieves a Case by ID, enforcing tenant isolation and role-based access rules.
     * Any unauthorized or cross-tenant access returns HTTP 404 (ResourceNotFoundException) to prevent IDOR/enumeration.
     */
    @PreAuthorize("isAuthenticated()")
    public CaseResponseDto getCaseById(String caseId, CaseVaultUserPrincipal principal) {
        if (principal == null || principal.getRole() == Role.AUDITOR_ADMIN) {
            // SR-07: AUDITOR_ADMIN has zero access to case content -> uniform 404
            throw new ResourceNotFoundException("Case not found");
        }

        Case aCase = caseRepository.findById(caseId)
                .orElseThrow(() -> new ResourceNotFoundException("Case not found"));

        if (!accessPolicy.canReadCase(principal, aCase)) {
            // SR-02: Uniform 404 for cross-tenant or unauthorized case access
            throw new ResourceNotFoundException("Case not found");
        }

        return CaseResponseDto.fromEntity(aCase);
    }

    /**
     * Lists cases accessible to the authenticated principal according to role and organisation scope.
     * AUDITOR_ADMIN receives an empty list (or can be rejected/404 per policy; empty list avoids metadata leakage).
     */
    @PreAuthorize("isAuthenticated()")
    public List<CaseResponseDto> listCases(CaseVaultUserPrincipal principal) {
        if (principal == null || principal.getRole() == Role.AUDITOR_ADMIN) {
            return Collections.emptyList();
        }

        String orgId = principal.getOrganisationId();
        if (orgId == null) {
            return Collections.emptyList();
        }

        Role role = principal.getRole();
        List<Case> cases;

        switch (role) {
            case CLIENT:
                // Scoped strictly to own organisation's cases
                cases = caseRepository.findByOrganisationId(orgId);
                break;

            case MANAGER:
                // Internal staff manager (ORG_INTERNAL) accesses all cases; otherwise own organisation
                if (AccessPolicy.INTERNAL_ORG_CODE.equals(principal.getOrganisationCode())) {
                    cases = caseRepository.findAll();
                } else {
                    cases = caseRepository.findByOrganisationId(orgId);
                }
                break;

            case ANALYST:
                // Scoped strictly to cases assigned to this analyst regardless of case organisation
                cases = caseRepository.findByAssignedAnalystId(principal.getUserId());
                break;

            default:
                cases = Collections.emptyList();
                break;
        }

        return cases.stream()
                .filter(c -> accessPolicy.canReadCase(principal, c))
                .map(CaseResponseDto::fromEntity)
                .collect(Collectors.toList());
    }

    /**
     * Retrieves Evidence metadata by ID, enforcing tenant isolation inherited from the parent case.
     * Any unauthorized or cross-tenant access returns HTTP 404 (ResourceNotFoundException).
     */
    @PreAuthorize("isAuthenticated()")
    public EvidenceResponseDto getEvidenceById(String evidenceId, CaseVaultUserPrincipal principal) {
        if (principal == null || principal.getRole() == Role.AUDITOR_ADMIN) {
            // SR-07: AUDITOR_ADMIN has zero access to evidence content -> uniform 404
            throw new ResourceNotFoundException("Evidence not found");
        }

        Evidence evidence = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new ResourceNotFoundException("Evidence not found"));

        if (!accessPolicy.canReadEvidence(principal, evidence)) {
            // SR-02: Uniform 404 for cross-tenant or unauthorized evidence access
            throw new ResourceNotFoundException("Evidence not found");
        }

        return EvidenceResponseDto.fromEntity(evidence);
    }

    /**
     * Creates a new case for the principal's organisation.
     * Restricts case creation strictly to CLIENT role per system requirements (FR-04).
     * Protects against mass-assignment: organisationId, owner, role, status, and assignedAnalyst
     * are strictly populated from the server session context and business rules, NEVER from the DTO.
     */
    @Transactional
    @PreAuthorize("hasRole('CLIENT')")
    public CaseResponseDto createCase(CreateCaseRequestDto requestDto, CaseVaultUserPrincipal principal) {
        if (principal == null || principal.getOrganisationId() == null) {
            throw new ResourceNotFoundException("Organisation not found");
        }

        Organisation org = organisationRepository.findById(principal.getOrganisationId())
                .orElseThrow(() -> new ResourceNotFoundException("Organisation not found"));

        User owner = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Instant now = Instant.now();
        // Server forces default status, server-derived owner, server-derived org, null analyst
        Case newCase = new Case(
                UUID.randomUUID().toString(),
                org,
                requestDto.getTitle(),
                requestDto.getCategory(),
                requestDto.getSeverity(),
                "OPEN",
                owner,
                null,
                now
        );

        Case saved = caseRepository.save(newCase);
        return CaseResponseDto.fromEntity(saved);
    }
}

