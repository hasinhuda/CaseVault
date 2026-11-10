package com.casevault.controller;

import com.casevault.security.CaseVaultUserPrincipal;
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

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal CaseVaultUserPrincipal principal, Model model) {
        if (principal != null) {
            model.addAttribute("username", principal.getUsername());
            model.addAttribute("role", principal.getRole().name());
            model.addAttribute("organisationId", principal.getOrganisationId() != null ? principal.getOrganisationId() : "N/A");
            model.addAttribute("organisationCode", principal.getOrganisationCode());
        }
        return "dashboard";
    }
}

