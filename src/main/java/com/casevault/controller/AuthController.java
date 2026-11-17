package com.casevault.controller;

import com.casevault.dto.ChangePasswordRequestDto;
import com.casevault.model.Role;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AdminUserService;
import com.casevault.service.UserAccountService;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AuthController {

    private final AdminUserService adminUserService;
    private final UserAccountService userAccountService;

    public AuthController(AdminUserService adminUserService, UserAccountService userAccountService) {
        this.adminUserService = adminUserService;
        this.userAccountService = userAccountService;
    }

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

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal CaseVaultUserPrincipal principal, Model model) {
        if (principal != null) {
            addPrincipal(model, principal);
            if (principal.getRole() == Role.AUDITOR_ADMIN) {
                addAuditorStatus(principal, model);
            }
        }
        return "dashboard";
    }

    @GetMapping("/account/credentials")
    public String changePasswordForm(Model model, @AuthenticationPrincipal CaseVaultUserPrincipal principal) {
        if (!model.containsAttribute("changePasswordRequestDto")) {
            model.addAttribute("changePasswordRequestDto", new ChangePasswordRequestDto());
        }
        addPrincipal(model, principal);
        return "account/credentials";
    }

    @PostMapping("/account/credentials")
    public String changePassword(@Valid @ModelAttribute("changePasswordRequestDto") ChangePasswordRequestDto form,
                                 BindingResult bindingResult,
                                 @AuthenticationPrincipal CaseVaultUserPrincipal principal,
                                 Model model,
                                 RedirectAttributes redirect) {
        if (principal == null) {
            return "redirect:/login";
        }
        if (bindingResult.hasErrors()) {
            addPrincipal(model, principal);
            return "account/credentials";
        }

        try {
            userAccountService.changePassword(principal, form);
            redirect.addFlashAttribute("successMessage", "Your password has been changed successfully.");
            return "redirect:/dashboard";
        } catch (IllegalArgumentException e) {
            model.addAttribute("errorMessage", e.getMessage());
            addPrincipal(model, principal);
            return "account/credentials";
        }
    }

    private void addPrincipal(Model model, CaseVaultUserPrincipal principal) {
        if (principal != null) {
            model.addAttribute("username", principal.getUsername());
            model.addAttribute("role", principal.getRole().name());
            model.addAttribute("organisationId", principal.getOrganisationId() != null ? principal.getOrganisationId() : "N/A");
            model.addAttribute("organisationCode", principal.getOrganisationCode());
        }
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

