# System Requirements Specification: CaseVault

## 1. Scope & System Overview
CaseVault is a secure, hardened, multi-tenant case-management and digital evidence platform engineered for a fictional incident-response consultancy and its client organisations.

The system supports four distinct operational roles with strict separation of duties:
- **CLIENT**: Belongs to an external client organisation. Can view only their own organisation's cases, upload evidence artifacts, and view approved final incident reports. Strictly prohibited from accessing other tenants' data or draft reports.
- **ANALYST**: Consultancy investigator assigned to specific cases within a tenant. Authors investigation notes, logs containment/remediation actions, uploads evidence, and compiles draft incident reports.
- **MANAGER**: Consultancy supervisor. Assigns cases to analysts, manages case lifecycle status, and reviews and approves incident reports. Under the Four-Eyes principle, a manager cannot approve a report they authored.
- **AUDITOR_ADMIN**: Platform administrator and security auditor. Inspects security events, system health telemetry, account activity, and verifies cryptographic audit log integrity; manages user lifecycles (disable/revoke accounts). Strictly prohibited from viewing case details or evidence artifacts.

---

## 2. Requirements Totals Summary
- **Total Functional Requirements (FR)**: 15 (FR-01 through FR-15)
- **Total Security Requirements (SR)**: 20 (SR-01 through SR-20)
- **Combined Requirements**: 35
- **Standards Baseline**: CWE 4.14, OWASP Top 10:2025 [VERIFY MANUALLY] / OWASP Top 10:2021, OWASP ASVS 5.0 [VERIFY MANUALLY].

---

## 3. Functional Requirements (FR)

### FR-01: User Authentication & Session Establishment
- **Description**: The system must authenticate users via username and password, issuing a secure, stateful HTTP session upon successful authentication. Unauthenticated requests to protected endpoints must redirect to `/login`.
- **Primary Roles**: All Roles (`CLIENT`, `ANALYST`, `MANAGER`, `AUDITOR_ADMIN`).
- **Rationale**: Establishes verifiable user identity prior to granting access to sensitive forensic cases and administrative capabilities.
- **Verification Method**: Automated integration tests asserting redirection to login for anonymous requests, successful session establishment upon valid credentials, and rejection of invalid credentials.
- **Standards Mapping**: CWE-287, OWASP Top 10:2025 A07 [VERIFY MANUALLY] / A07:2021, ASVS 5.0 V2.1 [VERIFY MANUALLY].

### FR-02: Organisation Multi-Tenancy & Tenant Segmentation
- **Description**: The system must associate every non-administrative user and case entity with exactly one organisation (tenant). Data queries must be partitioned by organisation identifier.
- **Primary Roles**: All Roles.
- **Rationale**: Guarantees complete data compartmentalisation between competing consultancy clients.
- **Verification Method**: Automated integration tests asserting that users cannot query, view, or modify cases or evidence belonging to an organisation other than their own.
- **Standards Mapping**: CWE-284, OWASP Top 10:2025 A01 [VERIFY MANUALLY] / A01:2021, ASVS 5.0 V4.1 [VERIFY MANUALLY].

### FR-03: Role-Based Access Control (RBAC)
- **Description**: The system must restrict UI views, navigation links, and controller actions according to the authenticated user's assigned role (`CLIENT`, `ANALYST`, `MANAGER`, `AUDITOR_ADMIN`).
- **Primary Roles**: All Roles.
- **Rationale**: Enforces least privilege across client representatives, investigators, managers, and system auditors.
- **Verification Method**: Role matrix tests invoking all application URL endpoints with each role principal, asserting expected HTTP response codes (200, 403, or 404).
- **Standards Mapping**: CWE-285, OWASP Top 10:2025 A01 [VERIFY MANUALLY] / A01:2021, ASVS 5.0 V4.1 [VERIFY MANUALLY].

### FR-04: Case Creation & Metadata Management
- **Description**: Users with permitted roles must be able to create new cases by specifying title, description, incident category (e.g. `RANSOMWARE`, `DATA_EXFILTRATION`, `PHISHING`, `INSIDER_THREAT`), severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and initial client reference.
- **Primary Roles**: `CLIENT`, `MANAGER`.
- **Rationale**: Captures structured initial incident details required to initiate containment and investigation workflows.
- **Verification Method**: Automated tests creating cases via form submission and validating persistence of all metadata fields.
- **Standards Mapping**: CWE-20, OWASP Top 10:2025 A04 [VERIFY MANUALLY] / A04:2021, ASVS 5.0 V5.1 [VERIFY MANUALLY].

### FR-05: Case Assignment & Investigator Triage
- **Description**: Managers must be able to assign one primary analyst and optional secondary analysts to an open case within the tenant organisation.
- **Primary Roles**: `MANAGER`.
- **Rationale**: Ensures clear ownership of investigation tasks and prevents unauthorized unassigned access.
- **Verification Method**: Integration tests verifying that managers can assign analysts, while non-managers attempting assignment receive an authorization denial.
- **Standards Mapping**: CWE-284, OWASP Top 10:2025 A01 [VERIFY MANUALLY] / A01:2021, ASVS 5.0 V4.1 [VERIFY MANUALLY].

### FR-06: Strict Case Lifecycle State Transitions
- **Description**: Cases must transition through a finite state machine: `OPEN` -> `ASSIGNED` -> `IN_PROGRESS` -> `PENDING_REVIEW` -> `CLOSED`. Illegal status transitions must be rejected server-side.
- **Primary Roles**: `MANAGER`, `ANALYST`.
- **Rationale**: Guarantees forensic process rigor and prevents premature closure or reopening without oversight.
- **Verification Method**: State machine unit and integration tests executing valid and invalid state transitions, verifying database state and audit event emission.
- **Standards Mapping**: CWE-840, OWASP Top 10:2025 A04 [VERIFY MANUALLY] / A04:2021, ASVS 5.0 V11.1 [VERIFY MANUALLY].

### FR-07: Chronological Notes & Remediation Action Tracking
- **Description**: Assigned analysts and managers must be able to append immutable, chronological investigation notes and structured remediation actions (with title, target date, and completion status) to an active case.
- **Primary Roles**: `ANALYST`, `MANAGER`.
- **Rationale**: Documents investigative findings, evidence correlations, and incident containment milestones for client transparency.
- **Verification Method**: Integration tests appending notes and verifying author attribution, creation timestamp, and immutability.
- **Standards Mapping**: CWE-284, OWASP Top 10:2025 A04 [VERIFY MANUALLY] / A04:2021, ASVS 5.0 V8.1 [VERIFY MANUALLY].

### FR-08: Evidence Artifact Upload & Integrity Hashing
- **Description**: Authorized users must be able to upload digital evidence artifacts to a case. The system must compute the SHA-256 cryptographic checksum of the stream, record file metadata (original filename, size, MIME type, upload timestamp, uploader ID), and store the encrypted payload.
- **Primary Roles**: `CLIENT`, `ANALYST`.
- **Rationale**: Preserves chain of custody and proves evidentiary integrity from the point of ingestion.
- **Verification Method**: Upload integration tests asserting SHA-256 hash calculation, metadata record creation, and successful ciphertext storage.
- **Standards Mapping**: CWE-353, OWASP Top 10:2025 A08 [VERIFY MANUALLY] / A08:2021, ASVS 5.0 V12.1 [VERIFY MANUALLY].

### FR-09: Secure Evidence Download & Streaming Decryption
- **Description**: Authorized case participants must be able to download stored evidence artifacts. The system must decrypt the ciphertext in-memory and stream it to the client with secure headers (`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`).
- **Primary Roles**: `CLIENT`, `ANALYST`, `MANAGER`.
- **Rationale**: Allows authorized forensic review without leaving decrypted artifacts on the server disk or exposing them via public URLs.
- **Verification Method**: Download integration tests comparing downloaded bytes and SHA-256 hash against the pre-upload original.
- **Standards Mapping**: CWE-311, OWASP Top 10:2025 A02 [VERIFY MANUALLY] / A02:2021, ASVS 5.0 V12.1 [VERIFY MANUALLY].

### FR-10: Tenant-Scoped Case Search & Parameter Filtering
- **Description**: The system must provide search and filter capabilities across accessible cases by keyword, status, severity, category, and date range. Search queries must strictly scope results to the caller's tenant.
- **Primary Roles**: All Roles (within role permissions).
- **Rationale**: Facilitates rapid retrieval of relevant incidents during active investigation without cross-tenant leakage.
- **Verification Method**: Automated search tests executing wildcard and cross-tenant queries, asserting zero results outside caller tenant.
- **Standards Mapping**: CWE-200, OWASP Top 10:2025 A01 [VERIFY MANUALLY] / A01:2021, ASVS 5.0 V4.1 [VERIFY MANUALLY].

### FR-11: Incident Report Drafting
- **Description**: Analysts must be able to draft formal incident reports compiling executive summaries, chronological case notes, evidence exhibits, containment timelines, and remediation recommendations.
- **Primary Roles**: `ANALYST`.
- **Rationale**: Prepares formal deliverables for client executives, legal teams, and regulatory reporting bodies.
- **Verification Method**: Workflow tests asserting report draft creation, linking to case entities, and restriction of unapproved drafts from client view.
- **Standards Mapping**: CWE-284, OWASP Top 10:2025 A01 [VERIFY MANUALLY] / A01:2021, ASVS 5.0 V4.1 [VERIFY MANUALLY].

### FR-12: Two-Person Report Review & Approval (Four-Eyes Principle)
- **Description**: Incident reports must be reviewed and approved by a user with the `MANAGER` role before being released to client users. The approving manager must be a distinct user from the drafting author.
- **Primary Roles**: `MANAGER`.
- **Rationale**: Eliminates unilateral approval, accidental release of incorrect findings, or fraudulent reporting.
- **Verification Method**: Automated workflow tests asserting that self-approval attempts fail, and approval by an independent manager succeeds, transitioning the report to `APPROVED`.
- **Standards Mapping**: CWE-284, OWASP Top 10:2025 A04 [VERIFY MANUALLY] / A04:2021, ASVS 5.0 V4.1 [VERIFY MANUALLY].

### FR-13: Cryptographic Audit Trail Chaining
- **Description**: The system must log every authentication attempt, case status change, evidence operation, and administrative action into an append-only, HMAC-SHA256 chained audit log.
- **Primary Roles**: System-wide, viewable by `AUDITOR_ADMIN`.
- **Rationale**: Ensures legal accountability, non-repudiation, and tamper-detection for all system state modifications.
- **Verification Method**: Automated audit suite testing sequential entry creation, HMAC verification, and tamper detection when database rows are altered.
- **Standards Mapping**: CWE-353, OWASP Top 10:2025 A08 [VERIFY MANUALLY] / A08:2021, ASVS 5.0 V7.4 [VERIFY MANUALLY].

### FR-14: Account Disabling & Session Revocation
- **Description**: Users with the `AUDITOR_ADMIN` role must be able to disable or revoke user accounts. Disabling an account must immediately invalidate any active session upon their subsequent request.
- **Primary Roles**: `AUDITOR_ADMIN`.
- **Rationale**: Provides rapid containment when an account is suspected of compromise.
- **Verification Method**: Integration test where an admin disables a user account, asserting that existing sessions are terminated and subsequent requests are rejected.
- **Standards Mapping**: CWE-613, OWASP Top 10:2025 A07 [VERIFY MANUALLY] / A07:2021, ASVS 5.0 V3.4 [VERIFY MANUALLY].

### FR-15: System Health Telemetry & Actuator Isolation
- **Description**: The system must expose health and database connectivity telemetry for monitoring, sanitised so that no sensitive environment variables, internal paths, or credentials are exposed.
- **Primary Roles**: `AUDITOR_ADMIN`, Monitoring infrastructure.
- **Rationale**: Ensures operational visibility into system availability while guarding infrastructure secrets.
- **Verification Method**: Actuator endpoint integration tests verifying HTTP 200 on `/actuator/health` and denial of unauthenticated access to sensitive actuator endpoints.
- **Standards Mapping**: CWE-200, OWASP Top 10:2025 A05 [VERIFY MANUALLY] / A05:2021, ASVS 5.0 V14.4 [VERIFY MANUALLY].
- **Clarification (Phase 9E, as built; the text above is kept as history):** the application sends the CSP as two headers (`default-src 'self'; frame-ancestors 'none'; object-src 'none'` and `base-uri 'self'; form-action 'self'; script-src 'self'; style-src 'self'`). It does **not** use per-request nonces: no template has an inline script or style, so `script-src 'self'` is sufficient and stricter than a nonce policy that would allow inline code. See [headers-and-rate-limit.md](assurance/headers-and-rate-limit.md).

---

## 4. Security Requirements (SR)

### SR-01: Server-Side Request Re-Validation & Re-Authorization
- **Description**: Every incoming HTTP request and service-layer invocation must re-validate the caller's identity, role, and organisation membership. The server must never trust client-supplied hidden fields, query parameters, UI disabled states, or client role declarations.
- **Rationale**: Prevents authorization bypass via manipulated API requests or client-side tampering.
- **Verification Method**: Automated integration tests attempting direct controller invocation with altered or stripped session credentials.
- **Standards Mapping**: CWE-285, OWASP Top 10:2025 A01 [VERIFY MANUALLY] / A01:2021, ASVS 5.0 V4.1 [VERIFY MANUALLY].

### SR-02: Cross-Tenant Isolation & Uniform HTTP 404 Masking
- **Description**: Any request targeting a case, evidence artifact, note, or report that belongs to a different organisation or is unauthorized must return HTTP `404 Not Found` (never HTTP `403 Forbidden`).
- **Rationale**: Eliminates tenant enumeration and resource existence disclosure via response status differentiation (BOLA/IDOR defense).
- **Verification Method**: Automated cross-tenant tests requesting foreign UUIDs asserting that HTTP 404 is uniformly returned.
- **Standards Mapping**: CWE-200, CWE-284, CWE-639, OWASP Top 10:2025 A01 [VERIFY MANUALLY] / A01:2021, ASVS 5.0 V4.1 [VERIFY MANUALLY].
- **Clarification (Phase 8C, decision F-003 by the project owner; the text above is unchanged)**: "Unauthorized" in this requirement means an object the caller cannot see (another organisation, or a role without access to the object): that always returns HTTP `404`. A forbidden action on an object the caller CAN see (for example a client adding a note to their own case, or a non-manager assigning an analyst) returns HTTP `403`. Both cases write exactly one `ACCESS_DENIED` audit event. Tests: SEC-HDR-404-01..03, SEC-AUTHZ-10, SEC-AUDIT-WIRE-08.

### SR-03: Argon2id Password Hashing
- **Description**: Passwords must be hashed using Argon2id via Spring Security `Argon2PasswordEncoder` backed by BouncyCastle (`bcprov-jdk18on`) with minimum parameters: memory 65,536 KiB (64 MiB), 3 iterations, parallelism 1, 16-byte random salt, 32-byte hash output.
- **Rationale**: Protects stored credentials against offline GPU/ASIC brute-force dictionary attacks in the event of database compromise.
- **Verification Method**: Unit tests asserting password hash format, parameter verification, and comparison matching.
- **Standards Mapping**: CWE-328, CWE-916, OWASP Top 10:2025 A02 [VERIFY MANUALLY] / A02:2021, ASVS 5.0 V2.4 [VERIFY MANUALLY].

### SR-04: Credential Lockout & Anti-Enumeration Timing Equalization
- **Description**: The system must lock user accounts after 5 consecutive failed login attempts for a duration of 15 minutes. Authentication failure responses must return generic error messages (*"Invalid username or password"*). For non-existent usernames, a dummy Argon2id verification must be executed to equalize response timing.
- **Rationale**: Neutralizes credential stuffing, automated brute force, and username enumeration.
- **Verification Method**: Automated suite executing brute-force cycles, asserting uniform HTTP 401 error responses, identical message strings, and comparable timing profiles.
- **Implementation note (docs honesty fix):** a failed browser login is answered with a 302 redirect to `/login?error=true` (a generic message), not an HTTP 401; `/api/**` without credentials answers 401. A locked or disabled account gets the same generic message (no separate lockout message). Tests: `AuthenticationLockoutSecurityTest`, SEC-RATE-WEB-01.
- **Standards Mapping**: CWE-307, CWE-204, OWASP Top 10:2025 A07 [VERIFY MANUALLY] / A07:2021, ASVS 5.0 V2.2 [VERIFY MANUALLY].

### SR-05: Secure Session Lifecycle & Strict Cookie Flags
- **Description**: Session identifiers must be rotated upon authentication (session fixation mitigation). Session cookies must be issued with `HttpOnly`, `SameSite=Strict`, and `Secure` (in HTTPS profile). Idle timeout must occur at 15 minutes and absolute timeout at 8 hours.
- **Rationale**: Protects against session hijacking, XSS-driven token exfiltration, and Cross-Site Request Forgery (CSRF).
- **Verification Method**: Automated integration test `TEST-BASE-005` verifying cookie header attributes and session invalidation after timeout.
- **Standards Mapping**: CWE-384, CWE-614, CWE-1004, OWASP Top 10:2025 A07 [VERIFY MANUALLY] / A07:2021, ASVS 5.0 V3.3 [VERIFY MANUALLY].

### SR-06: Four-Eyes Principle for Incident Report Approval
- **Description**: The user who authored or drafted an incident report is strictly prohibited from approving that report. Approval requires a distinct user holding the `MANAGER` role.
- **Rationale**: Eliminates unilateral tampering, accidental release of unverified claims, and single-operator fraud.
- **Verification Method**: Workflow integration test validating that self-approval attempts throw `SelfApprovalException` and return HTTP 400/422.
- **Implementation note (docs honesty fix):** there is no `SelfApprovalException`. `DefaultReportService.approve` throws `BadRequestException("The author of a report cannot approve it")` (HTTP 400) and records `ACCESS_DENIED`. Only ANALYSTs can author reports and only MANAGERs can approve, so the self-approval branch cannot be reached through the UI with the bootstrap roles; the rule is checked in the service regardless of roles. Tests: SEC-REPORT-WEB-05 (see `docs/assurance/report-tests.md`).
- **Standards Mapping**: CWE-284, OWASP Top 10:2025 A01 [VERIFY MANUALLY] / A01:2021, ASVS 5.0 V4.1 [VERIFY MANUALLY].

### SR-07: Strict Auditor-Admin Content Boundary
- **Description**: Users holding the `AUDITOR_ADMIN` role are strictly restricted to security audit logs, user management, and health telemetry. Any attempt to access case or evidence endpoints (`/cases/**`, `/evidence/**`) must return HTTP 404.
- **Rationale**: Enforces separation of duties and prevents surveillance or abuse of client evidence by operational administrators.
- **Verification Method**: Role operation matrix test verifying access denial to `/cases/**` and `/evidence/**` by `AUDITOR_ADMIN`.
- **Standards Mapping**: CWE-284, OWASP Top 10:2025 A01 [VERIFY MANUALLY] / A01:2021, ASVS 5.0 V4.1 [VERIFY MANUALLY].

### SR-08: Context-Aware Output Encoding (XSS Prevention)
- **Description**: All dynamic data rendered in Thymeleaf templates must utilize HTML context-aware encoding via `th:text`. Unescaped HTML rendering (`th:utext`), raw JavaScript interpolation, inline event handlers, and `innerHTML` are strictly forbidden.
- **Rationale**: Neutralizes stored and reflected Cross-Site Scripting (XSS).
- **Verification Method**: Template AST scanner and integration test injecting polyglot XSS payloads (`<script>`, `onerror=`, `javascript:`) asserting HTML entity escaping in the response.
- **Standards Mapping**: CWE-79, OWASP Top 10:2025 A03 [VERIFY MANUALLY] / A03:2021, ASVS 5.0 V5.3 [VERIFY MANUALLY].

### SR-09: Content Security Policy & HTTP Defensive Headers
- **Description**: System must emit a strict CSP with per-request cryptographic nonces for permitted scripts, `frame-ancestors 'none'`, `object-src 'none'`, alongside `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`.
- **Rationale**: Defense-in-depth against XSS execution, clickjacking, MIME confusion, and unauthorized browser feature abuse.
- **Verification Method**: Integration test `TEST-BASE-002` verifying HTTP headers across public and protected endpoints.
- **Standards Mapping**: CWE-1021, CWE-693, OWASP Top 10:2025 A05 [VERIFY MANUALLY] / A05:2021, ASVS 5.0 V14.4 [VERIFY MANUALLY].
- **Clarification (Phase 9E, as built; the text above is kept as history):** the application sends the CSP as two headers (`default-src 'self'; frame-ancestors 'none'; object-src 'none'` and `base-uri 'self'; form-action 'self'; script-src 'self'; style-src 'self'`). It does **not** use per-request nonces: no template has an inline script or style, so `script-src 'self'` is sufficient and stricter than a nonce policy that would allow inline code. See [headers-and-rate-limit.md](assurance/headers-and-rate-limit.md).

### SR-10: Parameterised Queries & Wildcard Escaping (SQLi Prevention)
- **Description**: All database queries must use Spring Data JPA parameterised queries or prepared statements. Dynamic search queries must escape SQL `LIKE` wildcard meta-characters (`%`, `_`, `\`).
- **Rationale**: Prevents SQL injection and database denial-of-service via expensive wildcard searches.
- **Verification Method**: SpotBugs / FindSecBugs static analysis and integration tests targeting search parameters.
- **Standards Mapping**: CWE-89, OWASP Top 10:2025 A03 [VERIFY MANUALLY] / A03:2021, ASVS 5.0 V5.3 [VERIFY MANUALLY].

### SR-11: Strict File Upload Validation & MIME Verification
- **Description**: Evidence uploads must be validated via Apache Tika content inspection (magic bytes), rejecting mismatches between file extension, declared Content-Type, and actual binary format. Executable extensions (`.exe`, `.sh`, `.bat`, `.ps1`, `.jar`, `.php`, `.jsp`) and SVG files are blocked. Antivirus inspection is integrated as a documented stub. Synthetic files only.
- **Rationale**: Prevents web shell execution, polyglot file uploads, and arbitrary code execution on the server.
- **Verification Method**: Upload test suite testing renamed executable binaries, polyglot headers, and valid document formats.
- **Standards Mapping**: CWE-434, CWE-350, OWASP Top 10:2025 A04 [VERIFY MANUALLY] / A04:2021, ASVS 5.0 V12.1 [VERIFY MANUALLY].

### SR-12: Evidence Envelope Encryption at Rest (Google Tink)
- **Description**: Evidence binaries stored on disk must be encrypted using Google Tink envelope encryption with AES-256-GCM. Decryption keys are stored outside the storage directory in `.local-data/` or `secrets/` (git-ignored).
- **Rationale**: Protects sensitive client evidence artifacts against offline disk inspection and unauthorized volume snapshots.
- **Verification Method**: Test reading raw stored file bytes from disk to prove ciphertext is non-plaintext before deciphering.
- **Implementation note (docs honesty fix):** implemented as AES-256-GCM authenticated encryption (AEAD) through Google Tink (`AeadKeyTemplates.AES256_GCM`), not as an envelope scheme: there is no key-encryption key or key hierarchy. The Tink keyset is stored as cleartext JSON (`CleartextKeysetHandle`) at `casevault.storage.keyset-path` (default `.local-data/keys/evidence-keyset.json`, git-ignored, owner-only permissions on POSIX systems only). That is a documented residual risk. See [evidence-upload-tests.md](assurance/evidence-upload-tests.md) and [known-limitations.md](assurance/known-limitations.md).
- **Standards Mapping**: CWE-311, CWE-327, OWASP Top 10:2025 A02 [VERIFY MANUALLY] / A02:2021, ASVS 5.0 V6.2 [VERIFY MANUALLY].

### SR-13: Cryptographic Tamper-Evident Audit Chaining (HMAC-SHA256)
- **Description**: Each audit event must compute an HMAC-SHA256 incorporating the previous record's hash, current event payload, event type, actor ID, and millisecond-truncated timestamp. Chain breaks or record alterations must be cryptographically detectable.
- **Rationale**: Ensures non-repudiation and detects retroactive modification or deletion by insiders.
- **Verification Method**: Audit integrity verification test asserting failure if any historical database record or hash is modified.
- **Standards Mapping**: CWE-353, CWE-365, OWASP Top 10:2025 A08 [VERIFY MANUALLY] / A08:2021, ASVS 5.0 V7.4 [VERIFY MANUALLY].

### SR-14: Audit Concurrency Locking & Determinism
- **Description**: Audit log append operations must acquire an explicit exclusive database transaction lock during sequence generation, releasing the lock only upon commit. Timestamps are truncated to milliseconds for reproducible verification across environments.
- **Rationale**: Prevents race conditions, fork anomalies, and sequence corruption during high concurrency.
- **Verification Method**: Multi-threaded concurrency test executing 50 parallel event writes repeatedly, validating continuous HMAC chain integrity.
- **Standards Mapping**: CWE-362, CWE-662, OWASP Top 10:2025 A04 [VERIFY MANUALLY] / A04:2021, ASVS 5.0 V7.4 [VERIFY MANUALLY].

### SR-15: Safe Error Handling & UUID Correlation IDs
- **Description**: System exceptions and HTTP 4xx/5xx responses must never reveal stack traces, database schema names, class names, or SQL statements. A random UUID correlation ID must be returned to the client and logged internally.
- **Rationale**: Prevents information leakage that facilitates exploit payload formulation.
- **Verification Method**: Error simulation tests (triggering DB constraints, 404, 500) verifying response HTML/JSON contains only correlation IDs and sanitized messages.
- **Standards Mapping**: CWE-209, CWE-497, OWASP Top 10:2025 A05 [VERIFY MANUALLY] / A05:2021, ASVS 5.0 V7.1 [VERIFY MANUALLY].

### SR-16: Zero-Secret Repository & Dynamic First-Run Bootstrap
- **Description**: No passwords, API keys, certificates, private keys, or encryption keysets may exist in Git or source code. First-run bootstrap must generate credentials dynamically into git-ignored local storage (`.local-data/` or `secrets/`).
- **Rationale**: Prevents permanent credential compromise through repository cloning, commit history leaks, or public repository exposure.
- **Verification Method**: Gitleaks CI action and pre-commit regex gate scanning repository tree.
- **Standards Mapping**: CWE-798, CWE-259, OWASP Top 10:2025 A07 [VERIFY MANUALLY] / A07:2021, ASVS 5.0 V14.1 [VERIFY MANUALLY].

### SR-17: Dependency Vulnerability Scanning & Convergence
- **Description**: All direct and transitive dependencies must converge via Maven Enforcer. CI must run Trivy and Dependency Review rejecting any high or critical known CVEs.
- **Rationale**: Neutralizes known vulnerabilities and supply chain dependency tampering.
- **Verification Method**: Maven Enforcer rule execution and Trivy container/dependency scan in CI.
- **Standards Mapping**: CWE-1395, OWASP Top 10:2025 A06 [VERIFY MANUALLY] / A06:2021, ASVS 5.0 V14.2 [VERIFY MANUALLY].

### SR-18: Hardened Non-Root Container Execution
- **Description**: Container image must run under a dedicated unprivileged user (`UID 10001: GID 10001`), with multi-stage build, minimal runtime JRE base, and upgraded OS packages.
- **Rationale**: Restricts container breakout capabilities and reduces Linux host attack surface.
- **Verification Method**: Hadolint Dockerfile linting and Trivy container scan.
- **Implementation note (docs honesty fix):** built: multi-stage `Dockerfile`, digest-pinned base images, `USER 10001:10001`, OS package upgrade; Hadolint and Trivy run in CI. **TARGET (not built in this submission):** read-only root filesystem, dropped capabilities and resource limits (no compose or runtime configuration exists).
- **Standards Mapping**: CWE-250, OWASP Top 10:2025 A05 [VERIFY MANUALLY] / A05:2021, ASVS 5.0 V14.3 [VERIFY MANUALLY].

### SR-19: Synthetic Data & Antivirus Stub Isolation
- **Description**: All test fixtures and sample data must be strictly synthetic. Real malware binaries, live exploits, and EICAR strings are strictly prohibited. Malware scanning logic is implemented as a deterministic mock stub.
- **Rationale**: Prevents accidental contagion, anti-malware false alarms in educational/CI environments, and external network dependencies.
- **Verification Method**: Test suite verification asserting that test evidence fixtures contain benign synthetic strings.
- **Standards Mapping**: ASVS 5.0 V10.2 [VERIFY MANUALLY], CWE-506 [VERIFY MANUALLY].

### SR-20: Data Minimisation & Retention Enforcement
- **Description**: Case evidence, session records, and closed case data must observe strict retention schedules. Expired evidence files must undergo cryptographic shredding and secure deletion.
- **Rationale**: Complies with privacy-by-design standards (GDPR Art 5) and reduces data breach liability.
- **Verification Method**: Scheduled purge job automated tests verifying deletion of records past retention threshold.
- **Implementation note (docs honesty fix):** **TARGET (not built in this submission) - design only.** No retention schedule, purge job, evidence shredding, deletion or erasure code exists in `src/main`; `EVIDENCE_PURGED` is not an audit event type; the verification method above has no test. What exists is data minimisation in the audit log (ids only) and log hygiene (SEC-LOG-01..03). See [privacy-retention.md](privacy-retention.md) and [known-limitations.md](assurance/known-limitations.md).
- **Standards Mapping**: CWE-226, OWASP Top 10:2025 A04 [VERIFY MANUALLY] / A04:2021, ASVS 5.0 V8.3 [VERIFY MANUALLY].
