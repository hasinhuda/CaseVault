package com.casevault.security;

import com.casevault.model.User;
import com.casevault.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

public class UserStatusEnforcementFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(UserStatusEnforcementFilter.class);
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final UserRepository userRepository;

    public UserStatusEnforcementFilter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof CaseVaultUserPrincipal principal) {

            Optional<User> userOptional = userRepository.findById(principal.getUserId());

            if (userOptional.isEmpty() || !userOptional.get().isEnabled()) {
                logger.warn("Revoking active session for deactivated user");

                HttpSession session = request.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
                SecurityContextHolder.clearContext();

                String uri = request.getRequestURI();
                if (uri != null && uri.startsWith("/api/")) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Account disabled\",\"code\":\"ACCOUNT_DISABLED\"}");
                } else {
                    redirectStrategy.sendRedirect(request, response, "/login?disabled=true");
                }
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
