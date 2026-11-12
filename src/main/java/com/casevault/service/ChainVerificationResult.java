package com.casevault.service;

/**
 * Outcome of {@link AuditLogService#verifyChain()}.
 *
 * @param valid                 true when every checked event matched
 * @param firstBrokenSequenceNo the first sequence number at which verification failed (for a gap: the missing
 *                              sequence number); null when valid
 * @param breakKind             kind of the first break; null when valid
 * @param eventsVerified        number of events that verified correctly before the first break (or in total)
 */
public record ChainVerificationResult(boolean valid, Long firstBrokenSequenceNo, BreakKind breakKind,
                                      long eventsVerified) {

    /** Kinds of chain break that verification can distinguish. */
    public enum BreakKind {
        HMAC_MISMATCH,
        LINK_MISMATCH,
        SEQUENCE_GAP
    }

    static ChainVerificationResult ok(long eventsVerified) {
        return new ChainVerificationResult(true, null, null, eventsVerified);
    }

    static ChainVerificationResult broken(long sequenceNo, BreakKind kind, long eventsVerified) {
        return new ChainVerificationResult(false, sequenceNo, kind, eventsVerified);
    }
}
