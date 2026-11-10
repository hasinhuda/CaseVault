package com.casevault.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

public class SessionAbsoluteTimeoutFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(SessionAbsoluteTimeoutFilter.class);
    public static final String SESSION_START_TIME_KEY = "CASEVAULT_SESSION_START_TIME";
    public static final long DEFAULT_MAX_ABSOLUTE_TIMEOUT_MS = Duration.ofHours(8).toMillis();

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final long maxAbsoluteTimeoutMs;

    public SessionAbsoluteTimeoutFilter() {
        this(DEFAULT_MAX_ABSOLUTE_TIMEOUT_MS);
    }

    public SessionAbsoluteTimeoutFilter(long maxAbsoluteTimeoutMs) {
        this.maxAbsoluteTimeoutMs = maxAbsoluteTimeoutMs;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);

        if (session != null && SecurityContextHolder.getContext().getAuthentication() != null
                && SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {

            Long startTime = (Long) session.getAttribute(SESSION_START_TIME_KEY);
            long now = System.currentTimeMillis();

            if (startTime == null) {
                session.setAttribute(SESSION_START_TIME_KEY, now);
            } else {
                long elapsed = now - startTime;
                if (elapsed >= maxAbsoluteTimeoutMs) {
                    logger.warn("Session absolute timeout reached. Invalidating session.");
                    session.invalidate();
                    SecurityContextHolder.clearContext();

                    String uri = request.getRequestURI();
                    if (uri != null && uri.startsWith("/api/")) {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.setContentType("application/json");
                        response.getWriter().write("{\"error\":\"Session expired\",\"code\":\"SESSION_ABSOLUTE_TIMEOUT\"}");
                    } else {
                        redirectStrategy.sendRedirect(request, response, "/login?expired=true");
                    }
                    return;
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
