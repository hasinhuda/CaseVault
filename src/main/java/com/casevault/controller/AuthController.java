package com.casevault.controller;

import com.casevault.model.Role;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AdminUserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    @GetMapping("/login")
    public String login(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "logout", required = false) String logout,
            @RequestParam(value = "expired", required = false) String expired,
            @RequestParam(value = "disabled", required = false) String disabled,
            Model model) {

        if (error != null) {
            model.addAttribute("errorMessage", "Invalid username or password");
        } else if (expired != null) {
            model.addAttribute("errorMessage", "Your session has expired. Please log in again.");
        } else if (disabled != null) {
            model.addAttribute("errorMessage", "Account is deactivated or disabled. Contact administrator.");
        }

        if (logout != null) {
            model.addAttribute("infoMessage", "You have been successfully logged out.");
        }

        return "login";
    }

    private final AdminUserService adminUserService;

    public AuthController(AdminUserService adminUserService) {
        this.adminUserService = adminUserService;
    }

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal CaseVaultUserPrincipal principal, Model model) {
        if (principal != null) {
            model.addAttribute("username", principal.getUsername());
            model.addAttribute("role", principal.getRole().name());
            model.addAttribute("organisationId", principal.getOrganisationId() != null ? principal.getOrganisationId() : "N/A");
            model.addAttribute("organisationCode", principal.getOrganisationCode());
            if (principal.getRole() == Role.AUDITOR_ADMIN) {
                addAuditorStatus(principal, model);
            }
        }
        return "dashboard";
    }

    /**
     * Phase 9B: the auditor dashboard shows only values backed by the same health service as the Health page.
     * Fixed words only (HEALTHY, DEGRADED, DOWN, UNKNOWN) plus the audit chain state text; no path, version, host or
     * exception text. If the check throws, the page still renders with UNKNOWN.
     */
    private void addAuditorStatus(CaseVaultUserPrincipal principal, Model model) {
        String health;
        String chain;
        try {
            AdminUserService.HealthView view = adminUserService.health(principal);
            if (!view.databaseReachable()) {
                health = "DOWN";
            } else if (!view.evidenceStorageWritable()) {
                health = "DEGRADED";
            } else {
                health = "HEALTHY";
            }
            chain = view.chainState() == null ? "UNKNOWN" : view.chainState();
        } catch (RuntimeException e) {
            health = "UNKNOWN";
            chain = "UNKNOWN";
        }
        model.addAttribute("systemHealth", health);
        model.addAttribute("auditChainState", chain);
    }
}

