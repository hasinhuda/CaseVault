-- CaseVault Report Version Migration (Phase 7C)
-- Optimistic locking: a concurrent second change of the same report fails instead of overwriting the first.

ALTER TABLE reports ADD COLUMN version BIGINT NOT NULL DEFAULT 0;
