-- CaseVault Authentication & Tenancy Schema Migration
CREATE TABLE organisations (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    code VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE users (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    organisation_id VARCHAR(36) NULL,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMP NULL,
    password_updated_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_users_organisation FOREIGN KEY (organisation_id) REFERENCES organisations (id)
);

CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_org ON users (organisation_id);

