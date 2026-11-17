-- CaseVault Password Reset Required Migration
-- Adds password_reset_required flag to users table.
-- When true, the user is required to change their password upon login.

ALTER TABLE users ADD COLUMN password_reset_required BOOLEAN DEFAULT FALSE NOT NULL;
