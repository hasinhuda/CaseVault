-- CaseVault Evidence Storage Schema Migration (Phase 5)
-- Adds storage metadata, plaintext SHA-256 integrity hash, and encryption version columns (FR-08, SR-12)

ALTER TABLE evidence ADD COLUMN stored_name VARCHAR(64) NOT NULL;
ALTER TABLE evidence ADD CONSTRAINT uq_evidence_stored_name UNIQUE (stored_name);
ALTER TABLE evidence ADD COLUMN content_type VARCHAR(100) NOT NULL;
ALTER TABLE evidence ADD COLUMN size_bytes BIGINT NOT NULL;
ALTER TABLE evidence ADD COLUMN sha256_hex VARCHAR(64) NOT NULL;
ALTER TABLE evidence ADD COLUMN encryption_version INT NOT NULL DEFAULT 1;

