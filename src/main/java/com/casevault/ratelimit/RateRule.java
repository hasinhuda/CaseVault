package com.casevault.ratelimit;

/** Immutable limit: at most {@code limit} requests per {@code windowSeconds}. Values below 1 are raised to 1. */
public record RateRule(int limit, int windowSeconds) {

    public RateRule {
        limit = Math.max(1, limit);
        windowSeconds = Math.max(1, windowSeconds);
    }
}
