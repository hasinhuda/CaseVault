package com.casevault.service;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * {@link AuditEventRecorder} backed by the HMAC chain. Active only with {@code casevault.audit.recorder=chained};
 * the default remains the Phase 5 logging recorder until the wiring step (Phase 6B).
 *
 * <p>Failure mode: FAIL-CLOSED. If the event cannot be appended the exception propagates to the caller, so a
 * security-relevant action is never silently left unaudited. See docs/adr/0005-audit-chain.md.
 */
@Component
@ConditionalOnProperty(name = "casevault.audit.recorder", havingValue = "chained")
public class ChainedAuditEventRecorder implements AuditEventRecorder {

    private final AuditAppender auditLogService;

    public ChainedAuditEventRecorder(AuditAppender auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Override
    public void record(AuditEventType eventType, String userId, String caseId, String reasonCode) {
        auditLogService.recordEvent(eventType, parseUuid(userId), parseUuid(caseId), reasonCode);
    }

    /** Only well-formed UUIDs are stored; anything else becomes null so free text can never enter the log. */
    private static UUID parseUuid(String raw) {
        if (raw == null) {
            return null;
        }
        try {
            return UUID.fromString(raw);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
