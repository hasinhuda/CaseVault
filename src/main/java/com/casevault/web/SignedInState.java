package com.casevault.web;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Phase 9B: whether the current request belongs to a signed-in user. Used only to choose a link on the error and
 * 429 pages (Dashboard or Back to login); it never decides access. Anonymous authentication counts as NOT signed in.
 * Reads the SecurityContext, so it works in a controller advice and inside a servlet filter alike.
 */
public final class SignedInState {

    private SignedInState() {
    }

    public static boolean isSignedIn() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null
                && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
    }
}
