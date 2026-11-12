package com.casevault.ratelimit;

import com.casevault.security.CaseVaultUserPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * In-process rate limiting (Phase 8A). Runs in the security chain before the username/password filter, so
 * {@code POST /login} is counted before credentials are checked and the answer never depends on the username.
 *
 * <ul>
 *   <li>{@code POST /login}: per client address, every attempt counts (success or failure).</li>
 *   <li>HTTP Basic requests to {@code /api/**}: per client address.</li>
 *   <li>Authenticated users, key = user id: case search ({@code GET /cases}, {@code /api/cases},
 *       {@code /api/cases/search} with query parameters), evidence upload, report writes.</li>
 * </ul>
 * A limited request is answered here with HTTP 429 and never reaches a controller. It writes no audit row (an
 * attacker would flood the table); one WARN line per limiter and window carries the limiter name and a
 * correlation id and nothing else. The client address is {@code getRemoteAddr()}; X-Forwarded-For is only read
 * when explicitly enabled for a known reverse proxy.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(RateLimitFilter.class);
    private static final Pattern ADDRESS_CHARS = Pattern.compile("[0-9a-fA-F:.]{1,45}");
    private static final String API_TEXT = "Too many requests. Please try again later.";

    private final RateLimiter limiter;
    private final RateLimitSettings settings;
    private final LongSupplier nowMillis;
    private final BlockedPageRenderer renderer;
    private final Map<LimiterName, Long> lastWarnedWindow = new ConcurrentHashMap<>();

    public RateLimitFilter(RateLimiter limiter, RateLimitSettings settings, Clock clock,
                           BlockedPageRenderer renderer) {
        this.limiter = limiter;
        this.settings = settings;
        this.nowMillis = clock::millis;
        this.renderer = renderer;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!settings.enabled()) {
            chain.doFilter(request, response);
            return;
        }
        LimiterName name = null;
        String key = null;
        String path = request.getRequestURI().substring(request.getContextPath().length());
        String method = request.getMethod();

        if ("POST".equals(method) && "/login".equals(path)) {
            name = LimiterName.LOGIN;
            key = clientAddress(request);
        } else if (path.startsWith("/api/") && isBasicAuthorization(request)) {
            name = LimiterName.API_BASIC;
            key = clientAddress(request);
        } else {
            String userId = authenticatedUserId();
            if (userId != null) {
                name = userLimiter(method, path, request);
                key = userId;
            }
        }
        if (name == null) {
            chain.doFilter(request, response);
            return;
        }
        RateLimiter.Decision decision = limiter.tryAcquire(name, key);
        if (decision.allowed()) {
            chain.doFilter(request, response);
            return;
        }
        block(request, response, name, decision.retryAfterSeconds(), path.startsWith("/api/"));
    }

    private static LimiterName userLimiter(String method, String path, HttpServletRequest request) {
        if ("GET".equals(method) && ("/cases".equals(path) || "/api/cases".equals(path) || "/api/cases/search".equals(path))
                && !new ServletWebRequest(request).getParameterMap().isEmpty()) {
            return LimiterName.SEARCH;
        }
        if (!"POST".equals(method)) {
            return null;
        }
        // Segment comparison instead of regular expressions: no backtracking on attacker-controlled paths.
        String[] parts = path.split("/", -1);
        boolean caseScoped = parts.length >= 4 && parts[0].isEmpty() && "cases".equals(parts[1]) && !parts[2].isEmpty();
        if (caseScoped && parts.length == 4 && "evidence".equals(parts[3])) {
            return LimiterName.UPLOAD;
        }
        if (caseScoped && "reports".equals(parts[3])) {
            if (parts.length == 4) {
                return LimiterName.REPORT_WRITE;
            }
            if (parts.length == 6 && !parts[4].isEmpty()
                    && ("update".equals(parts[5]) || "submit".equals(parts[5]) || "approve".equals(parts[5]))) {
                return LimiterName.REPORT_WRITE;
            }
        }
        return null;
    }

    private static String authenticatedUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && authentication.getPrincipal() instanceof CaseVaultUserPrincipal principal) {
            return principal.getUserId();
        }
        return null;
    }

    private static boolean isBasicAuthorization(HttpServletRequest request) {
        String header = new ServletWebRequest(request).getHeader("Authorization");
        return header != null && header.regionMatches(true, 0, "Basic ", 0, 6);
    }

    /** getRemoteAddr(), unless the proxy flag is on: then the last X-Forwarded-For entry (added by the proxy). */
    private String clientAddress(HttpServletRequest request) {
        if (settings.trustForwardedFor()) {
            String lastEntry = null;
            String[] headers = new ServletWebRequest(request).getHeaderValues("X-Forwarded-For");
            for (String line : headers == null ? new String[0] : headers) {
                String[] parts = line.split(",");
                lastEntry = parts[parts.length - 1].trim();
            }
            if (lastEntry != null && ADDRESS_CHARS.matcher(lastEntry).matches()) {
                return lastEntry;
            }
        }
        String remote = request.getRemoteAddr();
        return remote == null ? "unknown" : remote;
    }

    private void block(HttpServletRequest request, HttpServletResponse response, LimiterName name,
                       long retryAfterSeconds, boolean api) throws IOException {
        // Fresh id for this 429; the response header is replaced so header, page and log line carry the same id.
        UUID correlationId = UUID.randomUUID();
        if (firstInWindow(name)) {
            LOGGER.warn("Rate limit exceeded limiter={} correlationId={}", fixedLabel(name), correlationId);
        }
        response.setStatus(429);
        response.setHeader("Retry-After", Long.toString(retryAfterSeconds));
        response.setHeader(com.casevault.web.CorrelationIdFilter.HEADER, correlationId.toString());
        response.setHeader("Cache-Control", "no-store");
        if (api) {
            response.setContentType("text/plain;charset=UTF-8");
            response.getOutputStream().write(API_TEXT.getBytes(StandardCharsets.UTF_8));
        } else {
            renderer.render(request, response, correlationId.toString(), retryAfterSeconds);
        }
    }

    /** Fixed text per limiter (never derived from request data) for the log line. */
    private static String fixedLabel(LimiterName name) {
        return switch (name) {
            case LOGIN -> "login";
            case API_BASIC -> "api-basic";
            case SEARCH -> "search";
            case UPLOAD -> "upload";
            case REPORT_WRITE -> "report-write";
        };
    }

    /** True for the first limited request of a limiter in the current window (one WARN line per window). */
    private boolean firstInWindow(LimiterName name) {
        long windowMillis = settings.rule(name).windowSeconds() * 1000L;
        long windowIndex = nowMillis.getAsLong() / windowMillis;
        boolean[] first = new boolean[1];
        lastWarnedWindow.compute(name, (k, previous) -> {
            first[0] = previous == null || previous != windowIndex;
            return windowIndex;
        });
        return first[0];
    }
}
