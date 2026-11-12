package com.casevault.controller;

import com.casevault.exception.AdminActionRefusedException;
import com.casevault.security.CaseVaultUserPrincipal;
import com.casevault.service.AdminUserService;
import com.casevault.service.AdminUserService.ActionResult;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Admin pages (Phase 7B): user list, disable/enable, session revocation and a minimal health page. AUDITOR_ADMIN
 * only: the service answers every other role with 404. The controller calls the service interface only and binds
 * nothing but path ids and paging strings; the actor always comes from the authenticated principal.
 */
@Controller
@RequestMapping("/admin")
public class AdminController {

    private final AdminUserService adminUserService;

    public AdminController(AdminUserService adminUserService) {
        this.adminUserService = adminUserService;
    }

    @GetMapping("/users")
    @PreAuthorize("isAuthenticated()")
    public String users(@RequestParam(value = "page", required = false) String page,
                        @RequestParam(value = "size", required = false) String size,
                        @AuthenticationPrincipal CaseVaultUserPrincipal principal, Model model) {
        model.addAttribute("users", adminUserService.listUsers(principal, page, size));
        addPrincipal(model, principal);
        return "admin/users";
    }

    @GetMapping("/users/{id}/disable-confirm")
    @PreAuthorize("isAuthenticated()")
    public String disableConfirm(@PathVariable("id") String id,
                                 @AuthenticationPrincipal CaseVaultUserPrincipal principal, Model model) {
        model.addAttribute("target", adminUserService.getUser(principal, id));
        addPrincipal(model, principal);
        return "admin/disable-confirm";
    }

    @PostMapping("/users/{id}/disable")
    @PreAuthorize("isAuthenticated()")
    public String disable(@PathVariable("id") String id, @AuthenticationPrincipal CaseVaultUserPrincipal principal,
                          RedirectAttributes redirect) {
        return act(redirect, () -> adminUserService.disable(principal, id) == ActionResult.DONE
                ? "Account disabled. Active sessions of that user are ended." : "The account was already disabled.");
    }

    @PostMapping("/users/{id}/enable")
    @PreAuthorize("isAuthenticated()")
    public String enable(@PathVariable("id") String id, @AuthenticationPrincipal CaseVaultUserPrincipal principal,
                         RedirectAttributes redirect) {
        return act(redirect, () -> adminUserService.enable(principal, id) == ActionResult.DONE
                ? "Account enabled." : "The account was already enabled.");
    }

    @PostMapping("/users/{id}/revoke-sessions")
    @PreAuthorize("isAuthenticated()")
    public String revoke(@PathVariable("id") String id, @AuthenticationPrincipal CaseVaultUserPrincipal principal,
                         RedirectAttributes redirect) {
        return act(redirect, () -> {
            adminUserService.revokeSessions(principal, id);
            return "Sessions revoked. The user must sign in again.";
        });
    }

    @GetMapping("/health")
    @PreAuthorize("isAuthenticated()")
    public String health(@AuthenticationPrincipal CaseVaultUserPrincipal principal, Model model) {
        model.addAttribute("health", adminUserService.health(principal));
        addPrincipal(model, principal);
        return "admin/health";
    }

    private String act(RedirectAttributes redirect, java.util.function.Supplier<String> action) {
        try {
            redirect.addFlashAttribute("successMessage", action.get());
        } catch (AdminActionRefusedException refused) {
            redirect.addFlashAttribute("errorMessage", refused.getMessage());
        }
        return "redirect:/admin/users";
    }

    private static void addPrincipal(Model model, CaseVaultUserPrincipal principal) {
        model.addAttribute("username", principal.getUsername());
        model.addAttribute("role", principal.getRole().name());
        model.addAttribute("organisationId", principal.getOrganisationId());
        model.addAttribute("organisationCode", principal.getOrganisationCode());
    }
}
