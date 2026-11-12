package com.casevault.controller;

import com.casevault.dto.AssignAnalystRequestDto;
import com.casevault.dto.CaseNoteResponseDto;
import com.casevault.dto.CaseResponseDto;
import com.casevault.dto.CreateCaseNoteRequestDto;
import com.casevault.dto.CreateCaseRequestDto;
import com.casevault.dto.CreateRemediationActionRequestDto;
import com.casevault.dto.RemediationActionResponseDto;
import com.casevault.dto.SearchCasesRequestDto;
import com.casevault.dto.UpdateCaseStatusRequestDto;
import com.casevault.dto.UpdateRemediationActionStatusRequestDto;
import com.casevault.dto.UserSummaryDto;
import com.casevault.exception.ResourceNotFoundException;
import com.casevault.model.Role;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.CaseAccessService;
import com.casevault.service.EvidenceDownload;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.nio.charset.StandardCharsets;

/**
 * Server-rendered Thymeleaf Web Controller for Case Management UI shell.
 * Implements FR-04..FR-07, FR-10 and security requirements SR-01, SR-02, SR-07, SR-08.
 * Repositories are never accessed directly; all queries delegate to CaseAccessService.
 */
@Controller
@RequestMapping("/cases")
public class CaseWebController {

    private final CaseAccessService caseAccessService;

    public CaseWebController(CaseAccessService caseAccessService) {
        this.caseAccessService = caseAccessService;
    }

    /**
     * Case list view with search, filtering, and capped pagination.
     * AUDITOR_ADMIN accessing /cases returns HTTP 404 (SR-07).
     */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public String listCases(
            @ModelAttribute("searchRequest") SearchCasesRequestDto searchRequest,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal,
            Model model) {

        if (principal == null || principal.getRole() == Role.AUDITOR_ADMIN) {
            throw new ResourceNotFoundException("Not found");
        }

        Page<CaseResponseDto> casesPage = caseAccessService.searchCases(searchRequest, principal);

        addCommonPrincipalAttributes(model, principal);
        model.addAttribute("casesPage", casesPage);
        return "cases/list";
    }

    /**
     * Incident creation form view (CLIENT only per FR-04).
     */
    @GetMapping("/new")
    @PreAuthorize("isAuthenticated()")
    public String newCaseForm(
            @AuthenticationPrincipal CaseVaultUserPrincipal principal,
            Model model) {

        if (principal == null || principal.getRole() == Role.AUDITOR_ADMIN) {
            throw new ResourceNotFoundException("Not found");
        }
        if (principal.getRole() != Role.CLIENT) {
            throw new AccessDeniedException("Only clients can create incidents");
        }

        addCommonPrincipalAttributes(model, principal);
        if (!model.containsAttribute("createCaseRequestDto")) {
            model.addAttribute("createCaseRequestDto", new CreateCaseRequestDto());
        }
        return "cases/create";
    }

    /**
     * Handles case creation form submission (CLIENT only).
     */
    @PostMapping
    @PreAuthorize("isAuthenticated()")
    public String createCase(
            @Valid @ModelAttribute("createCaseRequestDto") CreateCaseRequestDto requestDto,
            BindingResult bindingResult,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal,
            Model model,
            RedirectAttributes redirectAttributes) {

        if (principal == null || principal.getRole() == Role.AUDITOR_ADMIN) {
            throw new ResourceNotFoundException("Not found");
        }
        if (principal.getRole() != Role.CLIENT) {
            throw new AccessDeniedException("Only clients can create incidents");
        }

        if (bindingResult.hasErrors()) {
            addCommonPrincipalAttributes(model, principal);
            model.addAttribute("errorMessage", "Validation failed. Please correct form fields.");
            return "cases/create";
        }

        CaseResponseDto created = caseAccessService.createCase(requestDto, principal);
        redirectAttributes.addFlashAttribute("successMessage", "Case created successfully: " + created.getTitle());
        return "redirect:/cases/" + created.getId();
    }

    /**
     * Case detail view (tabs: Overview, Notes, Actions; right sidebar: metadata, assignment, status).
     * AUDITOR_ADMIN or cross-tenant access returns HTTP 404 (SR-02, SR-07).
     */
    @GetMapping("/{id}")
    @PreAuthorize("isAuthenticated()")
    public String caseDetail(
            @PathVariable("id") String id,
            @RequestParam(value = "tab", required = false, defaultValue = "overview") String tab,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal,
            Model model) {

        if (principal == null) {
            throw new ResourceNotFoundException("Not found");
        }
        // AUDITOR_ADMIN is answered with 404 (and one ACCESS_DENIED / NOT_VISIBLE audit event) by the service.

        CaseResponseDto caseItem = caseAccessService.getCaseById(id, principal);
        List<CaseNoteResponseDto> notes = caseAccessService.getCaseNotes(id, principal);
        List<RemediationActionResponseDto> actions = caseAccessService.getRemediationActions(id, principal);
        List<com.casevault.dto.EvidenceResponseDto> evidence = caseAccessService.listEvidence(id, principal);

        Role role = principal.getRole();
        boolean isAssignedAnalyst = role == Role.ANALYST
                && Objects.equals(principal.getUserId(), caseItem.getAssignedAnalystId());
        boolean isManager = role == Role.MANAGER;

        boolean canAddNotes = isManager || isAssignedAnalyst;
        boolean canAddActions = isManager || isAssignedAnalyst;

        List<String> allowedNextStatuses = calculateAllowedNextStatuses(caseItem.getStatus(), role, isAssignedAnalyst);
        boolean canChangeStatus = !allowedNextStatuses.isEmpty();

        List<UserSummaryDto> availableAnalysts = Collections.emptyList();
        if (isManager) {
            availableAnalysts = caseAccessService.listAvailableAnalysts(principal);
        }

        addCommonPrincipalAttributes(model, principal);
        model.addAttribute("caseItem", caseItem);
        model.addAttribute("notes", notes);
        model.addAttribute("actions", actions);
        model.addAttribute("evidence", evidence);
        model.addAttribute("activeTab", tab);
        model.addAttribute("canAddNotes", canAddNotes);
        model.addAttribute("canAddActions", canAddActions);
        model.addAttribute("canChangeStatus", canChangeStatus);
        model.addAttribute("allowedNextStatuses", allowedNextStatuses);
        model.addAttribute("availableAnalysts", availableAnalysts);

        return "cases/detail";
    }

    /**
     * Form submission: Assign analyst to case (MANAGER only).
     */
    @PostMapping("/{id}/assign")
    // Visibility first, then the role: the service answers 404 for a case the caller may not see (including
    // AUDITOR_ADMIN, SR-07) and 403 only for a visible case when the caller is not a MANAGER.
    @PreAuthorize("isAuthenticated()")
    public String assignAnalyst(
            @PathVariable("id") String id,
            @Valid @ModelAttribute AssignAnalystRequestDto dto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal,
            RedirectAttributes redirectAttributes) {

        caseAccessService.designateAnalyst(id, dto, principal);
        redirectAttributes.addFlashAttribute("successMessage", "Investigator assigned successfully.");
        return "redirect:/cases/" + id + "?tab=overview";
    }

    /**
     * Form submission: Status transition (MANAGER or assigned ANALYST).
     */
    @PostMapping("/{id}/status")
    @PreAuthorize("isAuthenticated()")
    public String updateStatus(
            @PathVariable("id") String id,
            @Valid @ModelAttribute UpdateCaseStatusRequestDto dto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal,
            RedirectAttributes redirectAttributes) {

        caseAccessService.transitionCaseStatus(id, dto, principal);
        redirectAttributes.addFlashAttribute("successMessage", "Case status transitioned to " + dto.getStatus());
        return "redirect:/cases/" + id + "?tab=overview";
    }

    /**
     * Form submission: Append case note (MANAGER or assigned ANALYST).
     */
    @PostMapping("/{id}/notes")
    @PreAuthorize("isAuthenticated()")
    public String addNote(
            @PathVariable("id") String id,
            @Valid @ModelAttribute CreateCaseNoteRequestDto dto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal,
            RedirectAttributes redirectAttributes) {

        caseAccessService.appendCaseNote(id, dto, principal);
        redirectAttributes.addFlashAttribute("successMessage", "Investigation note appended.");
        return "redirect:/cases/" + id + "?tab=notes";
    }

    /**
     * Form submission: Log remediation action (MANAGER or assigned ANALYST).
     */
    @PostMapping("/{id}/actions")
    @PreAuthorize("isAuthenticated()")
    public String addAction(
            @PathVariable("id") String id,
            @Valid @ModelAttribute CreateRemediationActionRequestDto dto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal,
            RedirectAttributes redirectAttributes) {

        caseAccessService.createRemediationAction(id, dto, principal);
        redirectAttributes.addFlashAttribute("successMessage", "Remediation action recorded.");
        return "redirect:/cases/" + id + "?tab=actions";
    }

    /**
     * Form submission: Update remediation action status (MANAGER or assigned ANALYST).
     */
    @PostMapping("/{id}/actions/{actionId}/status")
    @PreAuthorize("isAuthenticated()")
    public String updateActionStatus(
            @PathVariable("id") String id,
            @PathVariable("actionId") String actionId,
            @Valid @ModelAttribute UpdateRemediationActionStatusRequestDto dto,
            @AuthenticationPrincipal CaseVaultUserPrincipal principal,
            RedirectAttributes redirectAttributes) {

        caseAccessService.transitionRemediationActionStatus(id, actionId, dto, principal);
        redirectAttributes.addFlashAttribute("successMessage", "Action status updated to " + dto.getStatus());
        return "redirect:/cases/" + id + "?tab=actions";
    }

    @PostMapping(path = "/{id}/evidence", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("isAuthenticated()")
    public String uploadEvidence(@PathVariable("id") String id,
                                 @RequestPart("file") MultipartFile file,
                                 @AuthenticationPrincipal CaseVaultUserPrincipal principal,
                                 RedirectAttributes redirectAttributes) {
        caseAccessService.uploadEvidence(id, file, principal);
        redirectAttributes.addFlashAttribute("successMessage", "Evidence uploaded successfully.");
        return "redirect:/cases/" + id + "?tab=evidence";
    }

    @GetMapping("/{caseId}/evidence/{evidenceId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<byte[]> downloadEvidence(@PathVariable String caseId,
                                                   @PathVariable String evidenceId,
                                                   @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        EvidenceDownload download = caseAccessService.openEvidence(caseId, evidenceId, principal);
        String safeFilename = sanitizeHeaderFilename(download.originalName());
        ContentDisposition disposition = ContentDisposition.attachment()
                .filename(safeFilename, StandardCharsets.UTF_8).build();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
                .header("X-Content-Type-Options", "nosniff")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(download.content());
    }

    private static String sanitizeHeaderFilename(String filename) {
        if (filename == null || filename.isBlank()) {
            return "evidence.bin";
        }
        return filename.replace("\r", "").replace("\n", "").replace("\"", "");
    }

    private void addCommonPrincipalAttributes(Model model, CaseVaultUserPrincipal principal) {
        if (principal != null) {
            model.addAttribute("username", principal.getUsername());
            model.addAttribute("role", principal.getRole().name());
            model.addAttribute("organisationId", principal.getOrganisationId());
            model.addAttribute("organisationCode", principal.getOrganisationCode());
        }
    }

    private List<String> calculateAllowedNextStatuses(String currentStatus, Role role, boolean isAssignedAnalyst) {
        if (currentStatus == null || role == null) {
            return Collections.emptyList();
        }

        List<String> next = new ArrayList<>();
        if (role == Role.MANAGER) {
            switch (currentStatus) {
                case "OPEN":
                    next.addAll(List.of("ASSIGNED", "IN_PROGRESS"));
                    break;
                case "ASSIGNED":
                    next.add("IN_PROGRESS");
                    break;
                case "IN_PROGRESS":
                    next.add("PENDING_REVIEW");
                    break;
                case "PENDING_REVIEW":
                    next.addAll(List.of("IN_PROGRESS", "CLOSED"));
                    break;
                default:
                    break;
            }
        } else if (role == Role.ANALYST && isAssignedAnalyst) {
            switch (currentStatus) {
                case "ASSIGNED":
                    next.add("IN_PROGRESS");
                    break;
                case "IN_PROGRESS":
                    next.add("PENDING_REVIEW");
                    break;
                default:
                    break;
            }
        }
        return next;
    }
}

