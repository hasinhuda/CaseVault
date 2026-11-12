package com.casevault.ratelimit;

/** Decides whether one more request for a key is allowed. In-process, per node. */
public interface RateLimiter {

    /** Outcome of one attempt. {@code retryAfterSeconds} is at least 1 when the attempt is denied, 0 otherwise. */
    record Decision(boolean allowed, long retryAfterSeconds) {
    }

    /** Counts the attempt (allowed or not) and returns the decision. */
    Decision tryAcquire(LimiterName name, String key);
}
