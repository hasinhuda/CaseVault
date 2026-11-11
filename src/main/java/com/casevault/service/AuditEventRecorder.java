package com.casevault.service;

public interface AuditEventRecorder {
    void record(AuditEventType eventType, String userId, String caseId, String reasonCode);
}
