-- CaseVault Cases & Evidence Schema Migration
CREATE TABLE cases (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    organisation_id VARCHAR(36) NOT NULL,
    title VARCHAR(200) NOT NULL,
    category VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) NOT NULL,
    owner_user_id VARCHAR(36) NOT NULL,
    assigned_analyst_id VARCHAR(36) NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_cases_organisation FOREIGN KEY (organisation_id) REFERENCES organisations (id),
    CONSTRAINT fk_cases_owner FOREIGN KEY (owner_user_id) REFERENCES users (id),
    CONSTRAINT fk_cases_assigned_analyst FOREIGN KEY (assigned_analyst_id) REFERENCES users (id)
);

CREATE INDEX idx_cases_org ON cases (organisation_id);
CREATE INDEX idx_cases_assigned_analyst ON cases (assigned_analyst_id);
CREATE INDEX idx_cases_owner ON cases (owner_user_id);

CREATE TABLE evidence (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    case_id VARCHAR(36) NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    uploaded_by VARCHAR(36) NOT NULL,
    created_at TIMESTAMP NOT NULL,
    CONSTRAINT fk_evidence_case FOREIGN KEY (case_id) REFERENCES cases (id),
    CONSTRAINT fk_evidence_uploaded_by FOREIGN KEY (uploaded_by) REFERENCES users (id)
);

CREATE INDEX idx_evidence_case ON evidence (case_id);
CREATE INDEX idx_evidence_uploaded_by ON evidence (uploaded_by);

