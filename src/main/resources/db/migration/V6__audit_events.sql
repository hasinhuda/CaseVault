-- CaseVault tamper-evident audit log (Phase 6A, FR-13, SR-13, SR-14).
-- H2 and PostgreSQL compatible. Intentionally no foreign keys: audit rows must never block, or be
-- cascaded by, deletes elsewhere. The application only ever INSERTs into this table.
CREATE TABLE audit_events (
    id          UUID                     NOT NULL,
    sequence_no BIGINT                   NOT NULL,
    event_type  VARCHAR(64)              NOT NULL,
    user_id     UUID                     NULL,
    case_id     UUID                     NULL,
    reason_code VARCHAR(64)              NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    prev_hash   VARCHAR(64)              NOT NULL,
    hmac        VARCHAR(64)              NOT NULL,
    CONSTRAINT pk_audit_events PRIMARY KEY (id),
    CONSTRAINT uq_audit_events_sequence_no UNIQUE (sequence_no)
);
