package com.casevault.service;

/**
 * Whitelist of reason codes that may be stored in the audit log. Free text is never stored: any value that is
 * not on this list is mapped to {@link #UNSPECIFIED}.
 */
public enum AuditReasonCode {
    ACCEPTED,
    VALIDATION_REJECTED,
    INTEGRITY_VERIFIED,
    INTEGRITY_FAILED,
    FILE_NOT_FOUND,
    SUCCESS,
    BAD_CREDENTIALS,
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    NOT_PERMITTED,
    NOT_VISIBLE,
    CREATED,
    UPDATED,
    ASSIGNED,
    STATUS_CHANGED,
    DRAFT_SUBMITTED,
    APPROVED,
    REJECTED,
    DISABLED_BY_ADMIN,
    SESSIONS_REVOKED,
    ENABLED_BY_ADMIN,
    ADMIN_REFUSED,
    CHAIN_VALID,
    CHAIN_INVALID,
    REPORT_CREATED,
    REPORT_SUBMITTED,
    REPORT_APPROVED,
    UNSPECIFIED;

    /** Maps a raw string to a whitelisted code by exact name; anything else (including null) is UNSPECIFIED. */
    public static AuditReasonCode fromString(String raw) {
        if (raw == null) {
            return UNSPECIFIED;
        }
        for (AuditReasonCode code : values()) {
            if (code.name().equals(raw)) {
                return code;
            }
        }
        return UNSPECIFIED;
    }
}
