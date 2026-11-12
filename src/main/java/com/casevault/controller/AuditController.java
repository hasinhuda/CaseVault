package com.casevault.controller;

import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AuditQueryService;
import com.casevault.service.AuditQueryService.AuditPageView;
import com.casevault.service.AuditQueryService.VerifyOutcome;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Auditor view of the audit log (Phase 6C). Only AUDITOR_ADMIN may use it; every other authenticated role gets
 * HTTP 404 from {@link AuditQueryService} (server-side check, never only the hidden menu link). The controller
 * talks to the service only. All request parameters are plain strings that the service validates, so a bad value
 * is a friendly message and never a binding error or a 500. A "sort" parameter is not read at all.
 */
@Controller
@RequestMapping("/audit")
public class AuditController {

    private final AuditQueryService auditQueryService;

    public AuditController(AuditQueryService auditQueryService) {
        this.auditQueryService = auditQueryService;
    }

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public String list(@RequestParam(value = "eventType", required = false) String eventType,
                       @RequestParam(value = "userId", required = false) String userId,
                       @RequestParam(value = "from", required = false) String from,
                       @RequestParam(value = "to", required = false) String to,
                       @RequestParam(value = "page", required = false) String page,
                       @RequestParam(value = "size", required = false) String size,
                       @AuthenticationPrincipal CaseVaultUserPrincipal principal,
                       Model model) {
        AuditPageView view = auditQueryService.view(principal, eventType, userId, from, to, page, size);
        model.addAttribute("username", principal.getUsername());
        model.addAttribute("role", principal.getRole().name());
        model.addAttribute("organisationId", principal.getOrganisationId());
        model.addAttribute("organisationCode", principal.getOrganisationCode());
        model.addAttribute("audit", view);
        return "audit/list";
    }

    @PostMapping("/verify")
    @PreAuthorize("isAuthenticated()")
    public String verify(@AuthenticationPrincipal CaseVaultUserPrincipal principal,
                         RedirectAttributes redirectAttributes) {
        VerifyOutcome outcome = auditQueryService.verifyChain(principal);
        if (outcome == VerifyOutcome.ALREADY_RUNNING) {
            redirectAttributes.addFlashAttribute("verifyBusy",
                    "A verification is already running. Please wait for it to finish and reload the page.");
        } else {
            redirectAttributes.addFlashAttribute("verifyDone", true);
        }
        return "redirect:/audit";
    }
}
