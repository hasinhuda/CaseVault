package com.casevault.service;

import com.casevault.model.AuditEvent;
import org.springframework.data.domain.Page;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/** Read and verify operations of the audit log, implemented by {@link AuditLogService}; used by the auditor view. */
public interface AuditLogReader {

    Page<AuditEvent> searchEvents(AuditEventType eventType, UUID userId, Instant fromInclusive,
                                  Instant toExclusive, int page, int size);

    ChainVerificationResult verifyChain();

    Optional<AuditLogService.ChainHead> currentHead();
}
