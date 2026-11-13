# Data Privacy & Retention Policy: CaseVault

> **Status: design only (TARGET, not built in this submission).** The retention schedules, shredding, purge, erasure and report-redaction rules below describe intended behaviour. **No purge, deletion, erasure or redaction code exists**, there is no scheduled job, and `EVIDENCE_PURGED` is not an audit event type in the code. What is built: audit rows hold identifiers only (no names, titles or file content), log lines carry no secrets or content (SEC-LOG-01..03), passwords are stored only as Argon2id hashes, and evidence files are encrypted at rest. See [known-limitations.md](assurance/known-limitations.md).

## 1. Regulatory Context & Privacy Principles
CaseVault processes sensitive incident response data, forensic evidence, and client operational telemetry. The platform adheres to **Data Protection by Design and by Default** (aligned with GDPR Article 5 and international forensic data standards).

### Core Privacy Principles:
1. **Purpose Limitation (GDPR Art. 5(1)(b))**: Data collected during an incident investigation is processed solely for containment, root cause analysis, remediation, and reporting.
2. **Data Minimisation (GDPR Art. 5(1)(c))**: System stores only evidence artifacts, attributes, and user records strictly necessary for incident resolution.
3. **Storage Limitation (GDPR Art. 5(1)(e))**: Strict chronological retention thresholds govern the lifecycle of all stored records.
4. **Integrity & Confidentiality (GDPR Art. 5(1)(f))**: Cryptographic encryption at rest (Google Tink AES-256-GCM) and HMAC tamper-evidence protect personal and corporate data against unauthorized access.

---

## 2. Data Classification & Retention Schedules (TARGET - not built)

| Data Category | Specific Elements | Retention Period | Post-Retention Action | Compliance Rationale |
|---|---|---|---|---|
| **Active Case Records** | Title, description, severity, status, timestamps, notes | Duration of case investigation + 180 days post-closure | Archive or Pseudonymise | Operational reference and incident review |
| **Digital Evidence Artifacts** | Encrypted binary files, packet traces, forensic dumps | 90 days after case resolution (or custom SLA) | Cryptographic shredding & deletion | Minimise liability for sensitive client evidence |
| **Evidence Metadata** | File name, SHA-256 hash, upload timestamp, size, author | 3 years post-closure | Permanent deletion | Chain of custody and legal dispute defense |
| **Final Incident Reports** | Sanitised executive summaries and technical reports | 5 years post-closure | Archival under restricted access | Compliance audit and regulatory reporting |
| **Cryptographic Audit Logs** | Sequence number, event type, actor ID, payload, HMAC hash | 7 years | Tamper-evident deep archive | Regulatory audit and non-repudiation |
| **Authentication & Session Logs** | User ID, login timestamp, IP address, lockout state | 90 days | Automatic purge | Security forensics and brute-force detection |
| **Disabled User Accounts** | Username, email, role, disabled timestamp | 1 year after deactivation | Hard delete from database | Identity lifecycle and record consistency |

---

## 3. Cryptographic Shredding & Secure Deletion (TARGET - not built)
When an evidence artifact reaches the end of its retention schedule:
1. **Ciphertext Shredding**: The encrypted file on disk is overwritten with random bytes and unlinked (`rm`).
2. **Key Erasure**: If tenant-specific sub-keys are employed, key deletion renders any historical disk snapshots permanently unrecoverable.
3. **Database Purge**: Corresponding database foreign keys and row pointers are deleted or marked purged.
4. **Audit Logging**: (TARGET; `EVIDENCE_PURGED` is not defined in the code) An immutable audit record `EVIDENCE_PURGED` is appended to the HMAC chain recording the deletion event, authorizer ID, and timestamp.

---

## 4. Report Sanitisation & Data Minimisation Rules (TARGET - not built; reports are plain text with escaped output only)
Before an incident report is generated or exported to client stakeholders:
- **PII Scrubbing**: Analyst notes containing personal phone numbers, home addresses, or unrelated third-party identities are scrubbed or pseudonymized.
- **Credential Masking**: Password strings, session tokens, or API secrets discovered during forensics must be masked (e.g. `AKIA****************`) in report drafts.
- **Redaction of Sensitive Network Topology**: Internal IP spaces and sensitive host names not relevant to the root-cause narrative are redacted.

---

## 5. Compliance & Standards Mapping
- **Regulatory**: GDPR Articles 5, 17 (Right to Erasure), 25 (Data Protection by Design), 32 (Security of Processing)
- **OWASP Top 10**:
  - OWASP Top 10:2025 [VERIFY MANUALLY]: A04 (Insecure Design), A09 (Security Logging and Monitoring Failures)
  - OWASP Top 10:2021: A04:2021, A09:2021
- **CWE**:
  - CWE-226: Sensitive Information in Resource Not Removed Before Reuse
  - CWE-404: Improper Resource Shutdown or Release
- **ASVS 5.0**:
  - V8 Data Protection (V8.1.1, V8.3.1, V8.3.2 [VERIFY MANUALLY])
