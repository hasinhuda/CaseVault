-- CaseVault Reports Migration (Phase 7A)
-- Incident reports with a DRAFT -> SUBMITTED -> APPROVED workflow (FR-11, FR-12, SR-06).
-- Ids follow the existing convention (VARCHAR(36) text UUIDs) so foreign keys match cases(id) and users(id).
-- The body is plain text, limited to 10000 characters (also checked in the service).

CREATE TABLE reports (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    case_id VARCHAR(36) NOT NULL,
    author_id VARCHAR(36) NOT NULL,
    body VARCHAR(10000) NOT NULL,
    status VARCHAR(20) NOT NULL,
    approved_by VARCHAR(36),
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    submitted_at TIMESTAMP,
    approved_at TIMESTAMP,
    CONSTRAINT fk_reports_case FOREIGN KEY (case_id) REFERENCES cases (id),
    CONSTRAINT fk_reports_author FOREIGN KEY (author_id) REFERENCES users (id),
    CONSTRAINT fk_reports_approved_by FOREIGN KEY (approved_by) REFERENCES users (id),
    CONSTRAINT chk_reports_status CHECK (status IN ('DRAFT', 'SUBMITTED', 'APPROVED'))
);

CREATE INDEX idx_reports_case ON reports (case_id);
CREATE INDEX idx_reports_author ON reports (author_id);
