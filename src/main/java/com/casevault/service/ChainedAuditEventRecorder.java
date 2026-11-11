package com.casevault.service;

import com.casevault.exception.AuditAppendFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

/**
 * {@link AuditEventRecorder} backed by the HMAC chain; the default (select the Phase 5 placeholder with
 * {@code casevault.audit.recorder=logging}).
 *
 * <p>Ordering: when called inside a transaction the event is appended only AFTER that transaction completed.
 * <ul>
 *   <li>Outcome events (uploaded, downloaded, case created or changed, login success, logout) are appended after
 *       COMMIT, so an event never describes something that did not happen. If the append fails, the business change
 *       stays committed, an ERROR line with a correlation id (and nothing else) is logged and
 *       {@link AuditAppendFailedException} reaches the caller (safe error page, fail-closed toward the user).</li>
 *   <li>Attempt events (login failure, account locked, access denied, evidence rejected) describe something that
 *       happened even though the surrounding transaction rolled back, so they are appended after completion
 *       whatever the outcome. A failed append is logged (ERROR, correlation id only); the user already receives
 *       the error or denial response.</li>
 * </ul>
 * Residual risk: a committed action can be unaudited if the append fails (see docs/adr/0005-audit-chain.md).
 */
@Component
@ConditionalOnProperty(name = "casevault.audit.recorder", havingValue = "chained", matchIfMissing = true)
public class ChainedAuditEventRecorder implements AuditEventRecorder {

    private static final Logger LOGGER = LoggerFactory.getLogger(ChainedAuditEventRecorder.class);

    private static final Set<AuditEventType> ATTEMPT_EVENTS = EnumSet.of(
            AuditEventType.LOGIN_FAILURE,
            AuditEventType.ACCOUNT_LOCKED,
            AuditEventType.ACCESS_DENIED,
            AuditEventType.EVIDENCE_REJECTED);

    private final AuditAppender auditLogService;

    public ChainedAuditEventRecorder(AuditAppender auditLogService) {
        this.auditLogService = auditLogService;
    }

    @Override
    public void record(AuditEventType eventType, String userId, String caseId, String reasonCode) {
        UUID user = parseUuid(userId);
        UUID caseUuid = parseUuid(caseId);
        boolean attempt = ATTEMPT_EVENTS.contains(eventType);

        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    if (!attempt) {
                        appendFailClosed(eventType, user, caseUuid, reasonCode);
                    }
                }

                @Override
                public void afterCompletion(int status) {
                    if (attempt) {
                        appendFailOpen(eventType, user, caseUuid, reasonCode);
                    }
                }
            });
            return;
        }

        if (attempt) {
            appendFailOpen(eventType, user, caseUuid, reasonCode);
        } else {
            appendFailClosed(eventType, user, caseUuid, reasonCode);
        }
    }

    private void appendFailClosed(AuditEventType eventType, UUID user, UUID caseUuid, String reasonCode) {
        try {
            auditLogService.recordEvent(eventType, user, caseUuid, reasonCode);
        } catch (RuntimeException e) {
            throw new AuditAppendFailedException(logFailure());
        }
    }

    private void appendFailOpen(AuditEventType eventType, UUID user, UUID caseUuid, String reasonCode) {
        try {
            auditLogService.recordEvent(eventType, user, caseUuid, reasonCode);
        } catch (RuntimeException e) {
            logFailure();
        }
    }

    /** Logs an ERROR line with a fresh correlation id only (never the exception, which could carry data). */
    private static String logFailure() {
        String correlationId = UUID.randomUUID().toString();
        LOGGER.error("Audit append failed correlationId={}", correlationId);
        return correlationId;
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
