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
import com.casevault.exception.BadRequestException;
import com.casevault.exception.InvalidStatusTransitionException;
import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.Case;
import com.casevault.model.CaseNote;
import com.casevault.model.Evidence;
import com.casevault.model.Organisation;
import com.casevault.model.RemediationAction;
import com.casevault.model.Role;
import com.casevault.model.User;
import com.casevault.repository.CaseNoteRepository;
import com.casevault.repository.CaseRepository;
import com.casevault.repository.EvidenceRepository;
import com.casevault.repository.OrganisationRepository;
import com.casevault.repository.RemediationActionRepository;
import com.casevault.repository.UserRepository;
import com.casevault.security.AccessPolicy;
import com.casevault.security.CaseVaultUserPrincipal;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Default implementation of CaseAccessService enforcing tenant isolation, role boundaries,
 * and lifecycle workflow for Case, Evidence, CaseNote, and RemediationAction domain objects.
 * Implements ADR 0003, FR-04..FR-07, FR-10, and requirements SR-01, SR-02, SR-07, SR-10.
 */
@Service
@Transactional(readOnly = true)
public class DefaultCaseAccessService implements CaseAccessService {

    private final CaseRepository caseRepository;
    private final EvidenceRepository evidenceRepository;
    private final OrganisationRepository organisationRepository;
    private final UserRepository userRepository;
    private final CaseNoteRepository caseNoteRepository;
    private final RemediationActionRepository remediationActionRepository;
    private final AccessPolicy accessPolicy;
    private final EvidenceValidator evidenceValidator;
    private final EvidenceStore evidenceStorageService;
    private final AuditEventRecorder auditEventRecorder;

    public DefaultCaseAccessService(CaseRepository caseRepository,
                                   EvidenceRepository evidenceRepository,
                                   OrganisationRepository organisationRepository,
                                   UserRepository userRepository,
                                   CaseNoteRepository caseNoteRepository,
                                   RemediationActionRepository remediationActionRepository,
                                   AccessPolicy accessPolicy,
                                   EvidenceValidator evidenceValidator,
                                   EvidenceStore evidenceStorageService,
                                   AuditEventRecorder auditEventRecorder) {
        this.caseRepository = caseRepository;
        this.evidenceRepository = evidenceRepository;
        this.organisationRepository = organisationRepository;
        this.userRepository = userRepository;
        this.caseNoteRepository = caseNoteRepository;
        this.remediationActionRepository = remediationActionRepository;
        this.accessPolicy = accessPolicy;
        this.evidenceValidator = evidenceValidator;
        this.evidenceStorageService = evidenceStorageService;
        this.auditEventRecorder = auditEventRecorder;
    }

    private static boolean isValidTransition(String from, String to) {
        if (from == null || to == null) {
            return false;
        }
        return switch (from) {
            case "OPEN" -> "ASSIGNED".equals(to) || "IN_PROGRESS".equals(to);
            case "ASSIGNED" -> "IN_PROGRESS".equals(to);
            case "IN_PROGRESS" -> "PENDING_REVIEW".equals(to);
            case "PENDING_REVIEW" -> "IN_PROGRESS".equals(to) || "CLOSED".equals(to);
            default -> false;
        };
    }

    /**
     * Escapes SQL LIKE special wildcard characters (%, _, \) to prevent query injection
     * or costly wildcard searches (SR-10).
     */
    public static String escapeLikeWildcards(String input) {
        if (input == null) {
            return "";
        }
        return input
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");
    }

    @Override
    @PreAuthorize("isAuthenticated()")
    public CaseResponseDto getCaseById(String caseId, CaseVaultUserPrincipal principal) {
        return CaseResponseDto.fromEntity(getAccessibleCaseEntity(caseId, principal));
    }

    @Override
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
                cases = caseRepository.findByOrganisationId(orgId);
                break;

            case MANAGER:
                if (AccessPolicy.INTERNAL_ORG_CODE.equals(principal.getOrganisationCode())) {
                    cases = caseRepository.findAll();
                } else {
                    cases = caseRepository.findByOrganisationId(orgId);
                }
                break;

            case ANALYST:
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

    @Override
    @PreAuthorize("isAuthenticated()")
    public Page<CaseResponseDto> searchCases(SearchCasesRequestDto request, CaseVaultUserPrincipal principal) {
        if (principal == null || principal.getRole() == Role.AUDITOR_ADMIN) {
            return Page.empty();
        }

        Specification<Case> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            Role role = principal.getRole();
            if (role == Role.CLIENT) {
                predicates.add(cb.equal(root.get("organisation").get("id"), principal.getOrganisationId()));
            } else if (role == Role.ANALYST) {
                predicates.add(cb.equal(root.get("assignedAnalyst").get("id"), principal.getUserId()));
            } else if (role == Role.MANAGER) {
                if (!AccessPolicy.INTERNAL_ORG_CODE.equals(principal.getOrganisationCode())) {
                    predicates.add(cb.equal(root.get("organisation").get("id"), principal.getOrganisationId()));
                }
            } else {
                return cb.disjunction();
            }

            if (request != null) {
                if (request.getStatus() != null && !request.getStatus().isBlank()) {
                    predicates.add(cb.equal(root.get("status"), request.getStatus().trim()));
                }
                if (request.getSeverity() != null && !request.getSeverity().isBlank()) {
                    predicates.add(cb.equal(root.get("severity"), request.getSeverity().trim()));
                }
                if (request.getCategory() != null && !request.getCategory().isBlank()) {
                    predicates.add(cb.equal(root.get("category"), request.getCategory().trim()));
                }
                if (request.getQ() != null && !request.getQ().isBlank()) {
                    String escapedQ = escapeLikeWildcards(request.getQ().trim());
                    predicates.add(cb.like(cb.lower(root.get("title")), cb.lower(cb.literal("%" + escapedQ + "%")), '\\'));
                }
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        int pageNum = (request != null) ? request.getPage() : 0;
        int pageSize = (request != null) ? request.getSize() : 10;
        String sortField = (request != null) ? request.getSort() : "createdAt";
        String dir = (request != null) ? request.getDirection() : "desc";

        Sort.Direction direction = ("asc".equals(dir) || "ASC".equals(dir)) ? Sort.Direction.ASC : Sort.Direction.DESC;
        Sort sort = Sort.by(direction, sortField);
        Pageable pageable = PageRequest.of(pageNum, pageSize, sort);

        Page<Case> page = caseRepository.findAll(spec, pageable);
        return page.map(CaseResponseDto::fromEntity);
    }

    @Override
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
        auditEventRecorder.record(AuditEventType.CASE_CREATED, principal.getUserId(), saved.getId(), "CREATED");
        return CaseResponseDto.fromEntity(saved);
    }

    @Override
    @Transactional
    @PreAuthorize("isAuthenticated()")
    public CaseResponseDto transitionCaseStatus(String caseId, UpdateCaseStatusRequestDto dto, CaseVaultUserPrincipal principal) {
        Case aCase = getAccessibleCaseEntity(caseId, principal);

        Role role = principal.getRole();
        if (role == Role.CLIENT) {
            throw new AccessDeniedException("Clients are not authorized to update case status");
        }

        String currentStatus = aCase.getStatus();
        String targetStatus = dto.getStatus();

        if (Objects.equals(currentStatus, targetStatus)) {
            return CaseResponseDto.fromEntity(aCase);
        }

        if (!isValidTransition(currentStatus, targetStatus)) {
            throw new InvalidStatusTransitionException("Illegal status transition from " + currentStatus + " to " + targetStatus);
        }

        if (role == Role.ANALYST) {
            boolean allowedAnalystTransition =
                    ("ASSIGNED".equals(currentStatus) && "IN_PROGRESS".equals(targetStatus)) ||
                    ("IN_PROGRESS".equals(currentStatus) && "PENDING_REVIEW".equals(targetStatus));
            if (!allowedAnalystTransition) {
                throw new AccessDeniedException("Analysts are not permitted to execute transition: " + currentStatus + " -> " + targetStatus);
            }
        }

        aCase.setStatus(targetStatus);
        Case saved = caseRepository.save(aCase);
        auditEventRecorder.record(AuditEventType.CASE_UPDATED, principal.getUserId(), caseId, "STATUS_CHANGED");
        return CaseResponseDto.fromEntity(saved);
    }

    @Override
    @Transactional
    @PreAuthorize("isAuthenticated()")
    public CaseResponseDto designateAnalyst(String caseId, AssignAnalystRequestDto dto, CaseVaultUserPrincipal principal) {
        Case aCase = getAccessibleCaseEntity(caseId, principal);

        if (principal.getRole() != Role.MANAGER) {
            throw new AccessDeniedException("Only managers can assign analysts to cases");
        }

        User targetUser = userRepository.findById(dto.getAnalystId())
                .orElseThrow(() -> new BadRequestException("Selected analyst user does not exist"));

        if (!targetUser.isEnabled() || targetUser.getRole() != Role.ANALYST) {
            throw new BadRequestException("Target user must be an active analyst");
        }

        aCase.setAssignedAnalyst(targetUser);
        if ("OPEN".equals(aCase.getStatus())) {
            aCase.setStatus("ASSIGNED");
        }

        Case saved = caseRepository.save(aCase);
        auditEventRecorder.record(AuditEventType.CASE_ASSIGNED, principal.getUserId(), caseId, "ASSIGNED");
        return CaseResponseDto.fromEntity(saved);
    }

    @Override
    @Transactional
    @PreAuthorize("isAuthenticated()")
    public CaseNoteResponseDto appendCaseNote(String caseId, CreateCaseNoteRequestDto dto, CaseVaultUserPrincipal principal) {
        Case aCase = getAccessibleCaseEntity(caseId, principal);

        Role role = principal.getRole();
        if (role == Role.CLIENT) {
            throw new AccessDeniedException("Clients are not permitted to append case notes");
        }

        User author = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        CaseNote note = new CaseNote(
                UUID.randomUUID().toString(),
                aCase,
                author,
                dto.getBody(),
                Instant.now()
        );

        CaseNote saved = caseNoteRepository.save(note);
        auditEventRecorder.record(AuditEventType.CASE_UPDATED, principal.getUserId(), caseId, "UPDATED");
        return CaseNoteResponseDto.fromEntity(saved);
    }

    @Override
    @PreAuthorize("isAuthenticated()")
    public List<CaseNoteResponseDto> getCaseNotes(String caseId, CaseVaultUserPrincipal principal) {
        getAccessibleCaseEntity(caseId, principal);

        return caseNoteRepository.findByCaseEntityIdOrderByCreatedAtAsc(caseId).stream()
                .map(CaseNoteResponseDto::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    @PreAuthorize("isAuthenticated()")
    public RemediationActionResponseDto createRemediationAction(String caseId, CreateRemediationActionRequestDto dto, CaseVaultUserPrincipal principal) {
        Case aCase = getAccessibleCaseEntity(caseId, principal);

        Role role = principal.getRole();
        if (role == Role.CLIENT) {
            throw new AccessDeniedException("Clients are not permitted to create remediation actions");
        }

        User creator = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        RemediationAction action = new RemediationAction(
                UUID.randomUUID().toString(),
                aCase,
                dto.getDescription(),
                "OPEN",
                creator,
                Instant.now()
        );

        RemediationAction saved = remediationActionRepository.save(action);
        auditEventRecorder.record(AuditEventType.CASE_UPDATED, principal.getUserId(), caseId, "UPDATED");
        return RemediationActionResponseDto.fromEntity(saved);
    }

    @Override
    @Transactional
    @PreAuthorize("isAuthenticated()")
    public RemediationActionResponseDto transitionRemediationActionStatus(String caseId, String actionId,
                                                                         UpdateRemediationActionStatusRequestDto dto,
                                                                         CaseVaultUserPrincipal principal) {
        getAccessibleCaseEntity(caseId, principal);

        Role role = principal.getRole();
        if (role == Role.CLIENT) {
            throw new AccessDeniedException("Clients are not permitted to modify remediation actions");
        }

        RemediationAction action = remediationActionRepository.findById(actionId)
                .orElseThrow(() -> new ResourceNotFoundException("Remediation action not found"));

        if (action.getCaseEntity() == null || !Objects.equals(action.getCaseEntity().getId(), caseId)) {
            throw new ResourceNotFoundException("Remediation action not found");
        }

        action.setStatus(dto.getStatus());
        RemediationAction saved = remediationActionRepository.save(action);
        auditEventRecorder.record(AuditEventType.CASE_UPDATED, principal.getUserId(), caseId, "UPDATED");
        return RemediationActionResponseDto.fromEntity(saved);
    }

    @Override
    @PreAuthorize("isAuthenticated()")
    public List<RemediationActionResponseDto> getRemediationActions(String caseId, CaseVaultUserPrincipal principal) {
        getAccessibleCaseEntity(caseId, principal);

        return remediationActionRepository.findByCaseEntityIdOrderByCreatedAtAsc(caseId).stream()
                .map(RemediationActionResponseDto::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @PreAuthorize("hasRole('MANAGER')")
    public List<UserSummaryDto> listAvailableAnalysts(CaseVaultUserPrincipal principal) {
        if (principal == null || principal.getRole() != Role.MANAGER) {
            return Collections.emptyList();
        }
        return userRepository.findByRoleAndEnabledTrue(Role.ANALYST).stream()
                .map(UserSummaryDto::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @PreAuthorize("isAuthenticated()")
    public EvidenceResponseDto getEvidenceById(String evidenceId, CaseVaultUserPrincipal principal) {
        if (principal == null || principal.getRole() == Role.AUDITOR_ADMIN) {
            throw maskedNotFound("Evidence not found", principal, null);
        }

        Evidence evidence = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new ResourceNotFoundException("Evidence not found"));

        if (!accessPolicy.canReadEvidence(principal, evidence)) {
            throw maskedNotFound("Evidence not found", principal, evidence.getCase().getId());
        }

        return EvidenceResponseDto.fromEntity(evidence);
    }

    @Override
    @Transactional
    @PreAuthorize("isAuthenticated()")
    public EvidenceResponseDto uploadEvidence(String caseId, MultipartFile file, CaseVaultUserPrincipal principal) {
        Case aCase = getAccessibleCaseEntity(caseId, principal);
        if (principal.getRole() != Role.CLIENT && principal.getRole() != Role.ANALYST) {
            throw maskedNotFound("Case not found", principal, caseId);
        }
        if (principal.getRole() == Role.ANALYST
                && (aCase.getAssignedAnalyst() == null || !Objects.equals(principal.getUserId(), aCase.getAssignedAnalyst().getId()))) {
            throw maskedNotFound("Case not found", principal, caseId);
        }
        if ("CLOSED".equals(aCase.getStatus())) {
            throw new BadRequestException("Evidence cannot be uploaded to a closed case.");
        }
        EvidenceValidator.ValidatedEvidence validated;
        try {
            validated = evidenceValidator.validate(file);
        } catch (BadRequestException exception) {
            auditEventRecorder.record(AuditEventType.EVIDENCE_REJECTED, principal.getUserId(), caseId, "VALIDATION_REJECTED");
            throw exception;
        }
        User uploader = userRepository.findById(principal.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        String evidenceId = UUID.randomUUID().toString();
        byte[] aad = associatedData(caseId, evidenceId);
        evidenceStorageService.encryptAndStore(validated.storedName(), validated.content(), aad);
        try {
            Evidence saved = evidenceRepository.save(new Evidence(evidenceId, aCase, validated.originalName(),
                    validated.storedName(), validated.detectedMimeType(), validated.sizeBytes(), validated.sha256Hex(),
                    1, uploader, Instant.now()));
            auditEventRecorder.record(AuditEventType.EVIDENCE_UPLOADED, principal.getUserId(), caseId, "ACCEPTED");
            return EvidenceResponseDto.fromEntity(saved);
        } catch (org.springframework.dao.DataAccessException exception) {
            evidenceStorageService.discardQuietly(validated.storedName());
            throw exception;
        }
    }

    @Override
    @PreAuthorize("isAuthenticated()")
    public List<EvidenceResponseDto> listEvidence(String caseId, CaseVaultUserPrincipal principal) {
        getAccessibleCaseEntity(caseId, principal);
        return evidenceRepository.findByACaseId(caseId).stream().map(EvidenceResponseDto::fromEntity).collect(Collectors.toList());
    }

    @Override
    @PreAuthorize("isAuthenticated()")
    public EvidenceDownload openEvidence(String caseId, String evidenceId, CaseVaultUserPrincipal principal) {
        Case aCase = getAccessibleCaseEntity(caseId, principal);
        Evidence evidence = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new ResourceNotFoundException("Evidence not found"));
        if (!Objects.equals(evidence.getCase().getId(), aCase.getId()) || !accessPolicy.canReadEvidence(principal, evidence)) {
            throw maskedNotFound("Evidence not found", principal, caseId);
        }
        byte[] plaintext;
        try {
            plaintext = evidenceStorageService.decryptAndRetrieve(evidence.getStoredName(), associatedData(caseId, evidenceId));
        } catch (EvidenceFileNotFoundException ex) {
            auditEventRecorder.record(AuditEventType.EVIDENCE_REJECTED, principal.getUserId(), caseId, "FILE_NOT_FOUND");
            throw new ResourceNotFoundException("Evidence not found");
        } catch (EvidenceIntegrityException ex) {
            auditEventRecorder.record(AuditEventType.EVIDENCE_REJECTED, principal.getUserId(), caseId, "INTEGRITY_FAILED");
            throw new ResourceNotFoundException("Evidence not found");
        }

        if (!EvidenceValidator.computeSha256Hex(plaintext).equals(evidence.getSha256Hex())) {
            auditEventRecorder.record(AuditEventType.EVIDENCE_REJECTED, principal.getUserId(), caseId, "INTEGRITY_FAILED");
            throw new ResourceNotFoundException("Evidence not found");
        }
        auditEventRecorder.record(AuditEventType.EVIDENCE_DOWNLOADED, principal.getUserId(), caseId, "INTEGRITY_VERIFIED");
        return new EvidenceDownload(evidence.getOriginalName(), plaintext);
    }

    private static byte[] associatedData(String caseId, String evidenceId) {
        return (caseId + ":" + evidenceId).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Records ACCESS_DENIED (NOT_VISIBLE) for an object that is masked as 404, and returns the unchanged 404
     * exception so the HTTP response stays exactly as before. Truly nonexistent objects are not recorded.
     */
    private ResourceNotFoundException maskedNotFound(String message, CaseVaultUserPrincipal principal, String caseId) {
        auditEventRecorder.record(AuditEventType.ACCESS_DENIED,
                principal == null ? null : principal.getUserId(), caseId, "NOT_VISIBLE");
        return new ResourceNotFoundException(message);
    }

    private Case getAccessibleCaseEntity(String caseId, CaseVaultUserPrincipal principal) {
        if (principal == null || principal.getRole() == Role.AUDITOR_ADMIN) {
            throw maskedNotFound("Case not found", principal, caseId);
        }

        Case aCase = caseRepository.findById(caseId)
                .orElseThrow(() -> new ResourceNotFoundException("Case not found"));

        if (!accessPolicy.canReadCase(principal, aCase)) {
            throw maskedNotFound("Case not found", principal, caseId);
        }

        return aCase;
    }
}
