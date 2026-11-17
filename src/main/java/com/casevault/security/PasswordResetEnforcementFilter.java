package com.casevault.security;

import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

public class PasswordResetEnforcementFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public PasswordResetEnforcementFilter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof CaseVaultUserPrincipal principal) {

            String uri = request.getRequestURI();
            String path = uri != null ? uri : "";

            if (!isExemptPath(path)) {
                boolean resetRequired = principal.isPasswordResetRequired();
                if (!resetRequired) {
                    Optional<User> userOptional = userRepository.findById(principal.getUserId());
                    if (userOptional.isPresent() && userOptional.get().isPasswordResetRequired()) {
                        resetRequired = true;
                    }
                }

                if (resetRequired) {
                    if (path.startsWith("/api/")) {
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        response.setContentType("application/json");
                        response.getWriter().write("{\"error\":\"Password change required\",\"code\":\"PASSWORD_CHANGE_REQUIRED\"}");
                    } else {
                        redirectStrategy.sendRedirect(request, response, "/account/credentials");
                    }
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isExemptPath(String path) {
        return path.equals("/account/credentials")
                || path.equals("/logout")
                || path.equals("/login")
                || path.equals("/error")
                || path.startsWith("/css/")
                || path.startsWith("/js/")
                || path.startsWith("/images/");
    }
}
