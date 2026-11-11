package com.casevault.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import org.hibernate.annotations.Immutable;
import org.springframework.data.domain.Persistable;

import java.time.Instant;
import java.util.UUID;

/**
 * One row of the append-only audit chain. The entity is {@link Immutable} (Hibernate never issues UPDATE) and
 * reports itself as new until persisted, so Spring Data can only INSERT it and never merges over an existing row.
 */
@Entity
@Immutable
@Table(name = "audit_events")
public class AuditEvent implements Persistable<UUID> {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "sequence_no", nullable = false, updatable = false, unique = true)
    private long sequenceNo;

    @Column(name = "event_type", length = 64, nullable = false, updatable = false)
    private String eventType;

    @Column(name = "user_id", updatable = false)
    private UUID userId;

    @Column(name = "case_id", updatable = false)
    private UUID caseId;

    @Column(name = "reason_code", length = 64, nullable = false, updatable = false)
    private String reasonCode;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    @Column(name = "prev_hash", length = 64, nullable = false, updatable = false)
    private String prevHash;

    @Column(name = "hmac", length = 64, nullable = false, updatable = false)
    private String hmac;

    @Transient
    private boolean newEntity = true;

    protected AuditEvent() {
    }

    public AuditEvent(UUID id, long sequenceNo, String eventType, UUID userId, UUID caseId,
                      String reasonCode, Instant occurredAt, String prevHash, String hmac) {
        this.id = id;
        this.sequenceNo = sequenceNo;
        this.eventType = eventType;
        this.userId = userId;
        this.caseId = caseId;
        this.reasonCode = reasonCode;
        this.occurredAt = occurredAt;
        this.prevHash = prevHash;
        this.hmac = hmac;
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return newEntity;
    }

    @PostLoad
    @PostPersist
    void markNotNew() {
        this.newEntity = false;
    }

    public long getSequenceNo() {
        return sequenceNo;
    }

    public String getEventType() {
        return eventType;
    }

    public UUID getUserId() {
        return userId;
    }

    public UUID getCaseId() {
        return caseId;
    }

    public String getReasonCode() {
        return reasonCode;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public String getPrevHash() {
        return prevHash;
    }

    public String getHmac() {
        return hmac;
    }
}
