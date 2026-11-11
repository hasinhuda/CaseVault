package com.casevault.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Logs metadata only; this is deliberately not the Phase 6 cryptographic audit log. */
@Component
@ConditionalOnProperty(name = "casevault.audit.recorder", havingValue = "logging", matchIfMissing = true)
public class LoggingAuditEventRecorder implements AuditEventRecorder {
    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingAuditEventRecorder.class);

    @Override
    public void record(AuditEventType eventType, String userId, String caseId, String reasonCode) {
        String eventLiteral = mapEventType(eventType);
        String safeUserId = sanitizeHexId(userId);
        String safeCaseId = sanitizeHexId(caseId);
        String reasonLiteral = mapReasonCode(reasonCode);
        LOGGER.info("audit-placeholder eventType={} userId={} caseId={} reasonCode={}",
                eventLiteral, safeUserId, safeCaseId, reasonLiteral);
    }

    private static String mapEventType(AuditEventType eventType) {
        if (eventType == null) {
            return "UNKNOWN";
        }
        // Enum constant names are a closed, code-defined set, so they are safe to log.
        return eventType.name();
    }

    private static String mapReasonCode(String reasonCode) {
        if ("ACCEPTED".equals(reasonCode)) {
            return "ACCEPTED";
        }
        if ("VALIDATION_REJECTED".equals(reasonCode)) {
            return "VALIDATION_REJECTED";
        }
        if ("INTEGRITY_VERIFIED".equals(reasonCode)) {
            return "INTEGRITY_VERIFIED";
        }
        if ("INTEGRITY_FAILED".equals(reasonCode)) {
            return "INTEGRITY_FAILED";
        }
        if ("FILE_NOT_FOUND".equals(reasonCode)) {
            return "FILE_NOT_FOUND";
        }
        return "UNSPECIFIED";
    }

    private static String sanitizeHexId(String rawId) {
        if (rawId == null) {
            return "00000000-0000-0000-0000-000000000000";
        }
        StringBuilder sb = new StringBuilder(36);
        for (int i = 0; i < rawId.length() && sb.length() < 36; i++) {
            char c = rawId.charAt(i);
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-') {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
