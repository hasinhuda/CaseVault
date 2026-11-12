-- CaseVault User Status Trace Migration (Phase 7B)
-- The audit table stores only the acting admin; these columns keep the target account traceable.
-- status_changed_by is a plain user id (no foreign key) so it never blocks user maintenance.

ALTER TABLE users ADD COLUMN status_changed_at TIMESTAMP NULL;
ALTER TABLE users ADD COLUMN status_changed_by VARCHAR(36) NULL;
