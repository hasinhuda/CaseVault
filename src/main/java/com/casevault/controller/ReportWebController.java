package com.casevault.controller;

import com.casevault.dto.ReportRequestDto;
import com.casevault.dto.ReportResponseDto;
import com.casevault.exception.BadRequestException;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.ReportService;
import org.springframework.http.HttpStatus;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

/**
 * Report pages (Phase 7C, FR-11, FR-12). The controller calls {@link ReportService} only. The single client input
 * is the {@code body} form field; case and report ids come from the path and every other parameter is ignored, so
 * status, author, approver, case and organisation can never be set from a request. Authorisation (404 for anything
 * not permitted, never 403), four-eyes and the state machine are enforced in the service, not here.
 *
 * <p>Failures: a rejected body or an invalid transition renders the page again with HTTP 400 and a fixed message;
 * a concurrent change (optimistic lock) renders it with HTTP 409. Successes redirect (post-redirect-get).
 */
@Controller
@RequestMapping("/cases/{caseId}/reports")
public class ReportWebController {

    private static final String INVALID_INPUT = "The report could not be saved. The text must be 1 to 10000 characters, "
            + "and may contain only printable characters, line breaks and tabs.";
    private static final String CONFLICT = "This report was changed by someone else in the meantime "
            + "(for example it was already approved). Reload the page and check its current state.";

    private final ReportService reportService;

    public ReportWebController(ReportService reportService) {
        this.reportService = reportService;
    }

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ModelAndView list(@PathVariable("caseId") String caseId,
                             @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        return listView(caseId, principal, null, null, HttpStatus.OK);
    }

    @GetMapping("/{reportId}")
    @PreAuthorize("isAuthenticated()")
    public ModelAndView detail(@PathVariable("caseId") String caseId, @PathVariable("reportId") String reportId,
                               @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        return detailView(caseId, reportId, principal, null, null, HttpStatus.OK);
    }

    @PostMapping
    @PreAuthorize("isAuthenticated()")
    public Object create(@PathVariable("caseId") String caseId,
                         @RequestParam(value = "body", required = false) String body,
                         @AuthenticationPrincipal CaseVaultUserPrincipal principal, RedirectAttributes redirect) {
        ReportResponseDto created;
        try {
            created = reportService.createDraft(caseId, new ReportRequestDto(body), principal);
        } catch (BadRequestException rejected) {
            return listView(caseId, principal, rejected.getMessage(), body, HttpStatus.BAD_REQUEST);
        }
        redirect.addFlashAttribute("successMessage", "Draft report created.");
        return "redirect:/cases/" + caseId + "/reports/" + created.id();
    }

    @PostMapping("/{reportId}/update")
    @PreAuthorize("isAuthenticated()")
    public Object update(@PathVariable("caseId") String caseId, @PathVariable("reportId") String reportId,
                         @RequestParam(value = "body", required = false) String body,
                         @AuthenticationPrincipal CaseVaultUserPrincipal principal, RedirectAttributes redirect) {
        try {
            reportService.updateDraft(caseId, reportId, new ReportRequestDto(body), principal);
        } catch (BadRequestException rejected) {
            return detailView(caseId, reportId, principal, rejected.getMessage(), body, HttpStatus.BAD_REQUEST);
        } catch (ObjectOptimisticLockingFailureException conflict) {
            return detailView(caseId, reportId, principal, CONFLICT, null, HttpStatus.CONFLICT);
        }
        redirect.addFlashAttribute("successMessage", "Draft saved.");
        return "redirect:/cases/" + caseId + "/reports/" + reportId;
    }

    @PostMapping("/{reportId}/submit")
    @PreAuthorize("isAuthenticated()")
    public Object submit(@PathVariable("caseId") String caseId, @PathVariable("reportId") String reportId,
                         @AuthenticationPrincipal CaseVaultUserPrincipal principal, RedirectAttributes redirect) {
        return transition(caseId, reportId, principal, redirect, "Report submitted for approval.",
                () -> reportService.submit(caseId, reportId, principal));
    }

    @PostMapping("/{reportId}/approve")
    @PreAuthorize("isAuthenticated()")
    public Object approve(@PathVariable("caseId") String caseId, @PathVariable("reportId") String reportId,
                          @AuthenticationPrincipal CaseVaultUserPrincipal principal, RedirectAttributes redirect) {
        return transition(caseId, reportId, principal, redirect, "Report approved.",
                () -> reportService.approve(caseId, reportId, principal));
    }

    private Object transition(String caseId, String reportId, CaseVaultUserPrincipal principal,
                              RedirectAttributes redirect, String success, Supplier<ReportResponseDto> action) {
        try {
            action.get();
        } catch (BadRequestException rejected) {
            return detailView(caseId, reportId, principal, rejected.getMessage(), null, HttpStatus.BAD_REQUEST);
        } catch (ObjectOptimisticLockingFailureException conflict) {
            return detailView(caseId, reportId, principal, CONFLICT, null, HttpStatus.CONFLICT);
        }
        redirect.addFlashAttribute("successMessage", success);
        return "redirect:/cases/" + caseId + "/reports/" + reportId;
    }

    private ModelAndView listView(String caseId, CaseVaultUserPrincipal principal, String error, String draftBody,
                                  HttpStatus status) {
        ModelAndView mav = new ModelAndView("reports/list");
        mav.setStatus(status);
        mav.addObject("caseId", caseId);
        // The service returns oldest first; the page shows the newest report first.
        List<ReportResponseDto> newestFirst = new ArrayList<>(reportService.list(caseId, principal));
        Collections.reverse(newestFirst);
        mav.addObject("reports", newestFirst);
        mav.addObject("errorMessage", error == null ? null : fixedMessage(error));
        mav.addObject("draftBody", draftBody == null ? "" : draftBody);
        addPrincipal(mav, principal);
        return mav;
    }

    private ModelAndView detailView(String caseId, String reportId, CaseVaultUserPrincipal principal, String error,
                                    String draftBody, HttpStatus status) {
        ReportResponseDto report = reportService.get(caseId, reportId, principal);
        ModelAndView mav = new ModelAndView("reports/detail");
        mav.setStatus(status);
        mav.addObject("caseId", caseId);
        mav.addObject("report", report);
        mav.addObject("errorMessage", error == null ? null : fixedMessage(error));
        mav.addObject("draftBody", draftBody == null ? report.body() : draftBody);
        mav.addObject("isAuthor", report.authorId().equals(principal.getUserId()));
        addPrincipal(mav, principal);
        return mav;
    }

    /** Messages come from fixed texts of this class or the service; anything else is replaced by a generic text. */
    private static String fixedMessage(String message) {
        if (message == null || message.isBlank()) {
            return INVALID_INPUT;
        }
        return message.startsWith("Report body") || message.startsWith("Only a ")
                || message.startsWith("The author") || message.startsWith("Reports cannot")
                || message.equals(CONFLICT) ? message : INVALID_INPUT;
    }

    private static void addPrincipal(ModelAndView mav, CaseVaultUserPrincipal principal) {
        mav.addObject("username", principal.getUsername());
        mav.addObject("role", principal.getRole().name());
        mav.addObject("userId", principal.getUserId());
        mav.addObject("organisationId", principal.getOrganisationId());
        mav.addObject("organisationCode", principal.getOrganisationCode());
    }
}
