package com.casevault.model;

/**
 * Finite state machine lifecycle statuses for a forensic case.
 * Enforces FR-06: OPEN -> ASSIGNED -> IN_PROGRESS -> PENDING_REVIEW -> CLOSED.
 */
public enum CaseStatus {
    OPEN,
    ASSIGNED,
    IN_PROGRESS,
    PENDING_REVIEW,
    CLOSED
}

