package com.casevault.service;

/** Closed set of audit event types. Existing constants must never be removed or renamed (stored values). */
public enum AuditEventType {
    EVIDENCE_UPLOADED,
    EVIDENCE_DOWNLOADED,
    EVIDENCE_REJECTED,
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    ACCOUNT_LOCKED,
    LOGOUT,
    ACCESS_DENIED,
    CASE_CREATED,
    CASE_UPDATED,
    CASE_ASSIGNED,
    REPORT_TRANSITION,
    ADMIN_ACCOUNT_DISABLED,
    ADMIN_ACCOUNT_ENABLED,
    ADMIN_SESSION_REVOKED,
    AUDIT_CHAIN_VERIFIED
}
