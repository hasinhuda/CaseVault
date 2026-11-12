package com.casevault.ratelimit;

/** Read-only view of the limiter configuration (casevault.ratelimit.*). */
public interface RateLimitSettings {

    boolean enabled();

    /** Only for a known reverse proxy that appends the real client address (Phase 12). Default false. */
    boolean trustForwardedFor();

    int maxTrackedKeys();

    RateRule rule(LimiterName name);
}
