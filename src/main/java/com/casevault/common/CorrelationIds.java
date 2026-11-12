package com.casevault.common;

import org.slf4j.MDC;

import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Correlation id helpers. An id is always rebuilt from the two 64-bit halves of a parsed UUID, so the text that is
 * logged or shown can only ever be a canonical lower-case UUID, never client-supplied characters (no CR/LF, no
 * markup, no length games).
 */
public final class CorrelationIds {

    public static final String MDC_KEY = "correlationId";
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private CorrelationIds() {
    }

    /** A strictly formed UUID text becomes the canonical id; anything else (including null) becomes a new UUID. */
    public static String sanitiseOrNew(Object candidate) {
        if (candidate instanceof String text && text.length() == 36 && UUID_PATTERN.matcher(text).matches()) {
            // Rebuild the id from the two parsed 64-bit halves: only canonical UUID text can come out.
            UUID parsed = UUID.fromString(text);
            return new UUID(parsed.getMostSignificantBits(), parsed.getLeastSignificantBits()).toString();
        }
        return UUID.randomUUID().toString();
    }

    /** The id of the current request thread (MDC), or a new UUID when there is none. */
    public static String currentOrNew() {
        return sanitiseOrNew(MDC.get(MDC_KEY));
    }
}
