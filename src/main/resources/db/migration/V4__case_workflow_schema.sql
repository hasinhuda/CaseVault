-- CaseVault Case Workflow Schema Migration (Phase 4)
-- Adds case_notes and remediation_actions tables supporting FR-06 and FR-07

CREATE TABLE case_notes (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    case_id VARCHAR(36) NOT NULL,
    author_id VARCHAR(36) NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_case_notes_case FOREIGN KEY (case_id) REFERENCES cases (id),
    CONSTRAINT fk_case_notes_author FOREIGN KEY (author_id) REFERENCES users (id)
);

CREATE INDEX idx_case_notes_case ON case_notes (case_id);
CREATE INDEX idx_case_notes_author ON case_notes (author_id);

CREATE TABLE remediation_actions (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    case_id VARCHAR(36) NOT NULL,
    description VARCHAR(500) NOT NULL,
    status VARCHAR(50) NOT NULL,
    created_by VARCHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_remediation_actions_case FOREIGN KEY (case_id) REFERENCES cases (id),
    CONSTRAINT fk_remediation_actions_created_by FOREIGN KEY (created_by) REFERENCES users (id)
);

CREATE INDEX idx_remediation_actions_case ON remediation_actions (case_id);
CREATE INDEX idx_remediation_actions_created_by ON remediation_actions (created_by);

