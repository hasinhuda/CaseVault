-- CaseVault baseline migration
CREATE TABLE schema_baseline (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    initialized_at TIMESTAMP NOT NULL
);
