package com.casevault.ratelimit;

import com.casevault.web.SignedInState;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.ViewResolver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;

/**
 * Renders the {@code rate-limited} Thymeleaf template (th:text only, base layout head) from inside the security
 * filter chain, where no controller runs. If rendering fails, a fixed plain-text body is written instead; nothing
 * about the cause is revealed.
 */
public class ThymeleafBlockedPageRenderer implements BlockedPageRenderer {

    /** Looks up the view; only this lookup is kept, not the resolver object itself. */
    @FunctionalInterface
    private interface ViewLookup {
        View lookup(String name);
    }

    private static final String VIEW_NAME = "rate-limited";
    private static final String FALLBACK = "Too many requests. Please try again later.";

    private final ViewLookup viewLookup;

    public ThymeleafBlockedPageRenderer(ViewResolver viewResolver) {
        this.viewLookup = name -> {
            try {
                return viewResolver.resolveViewName(name, Locale.ENGLISH);
            } catch (Exception e) {
                throw new IllegalStateException("The blocked page view could not be resolved");
            }
        };
    }

    @Override
    public void render(HttpServletRequest request, HttpServletResponse response, String correlationId,
                       long retryAfterSeconds) throws IOException {
        try {
            View view = viewLookup.lookup(VIEW_NAME);
            if (view != null) {
                response.setContentType("text/html;charset=UTF-8");
                // Phase 9B: only the link on the page depends on this flag (Dashboard or Back to sign in).
                renderView(view, Map.of("correlationId", correlationId, "retryAfterSeconds", retryAfterSeconds,
                        "signedIn", SignedInState.isSignedIn()), request, response);
                return;
            }
        } catch (IOException | RuntimeException e) {
            if (response.isCommitted()) {
                return;
            }
            response.resetBuffer();
        }
        response.setContentType("text/plain;charset=UTF-8");
        response.getOutputStream().write(FALLBACK.getBytes(StandardCharsets.UTF_8));
    }

    private static void renderView(View view, Map<String, Object> model, HttpServletRequest request,
                                   HttpServletResponse response) throws IOException {
        try {
            view.render(model, request, response);
        } catch (IOException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("The blocked page could not be rendered");
        }
    }
}
