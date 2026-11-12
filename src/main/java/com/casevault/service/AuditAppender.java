package com.casevault.service;

import com.casevault.model.AuditEvent;

import java.util.UUID;

/** The single append operation of the audit chain; implemented by {@link AuditLogService}. */
public interface AuditAppender {

    AuditEvent recordEvent(AuditEventType eventType, UUID userId, UUID caseId, String reasonCode);
}
