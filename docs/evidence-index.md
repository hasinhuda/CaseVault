# Evidence Index

This index maps architectural, security, and functional requirements to verified artifacts, tests, and CI jobs within the CaseVault repository.

## Phase 0: Baseline Quality & Security Gates

| Requirement ID | Description | Source / Config | Automated Test / Gate | CI Verification | Status |
|---|---|---|---|---|---|
| SEC-001 | Java 21 LTS baseline & Enforcer | [pom.xml](../pom.xml) | Maven Enforcer plugin | CI `build-test-coverage` | Verified |
| SEC-002 | Dependency convergence & duplication ban | [pom.xml](../pom.xml) | Maven Enforcer plugin | CI `build-test-coverage` | Verified |
| SEC-003 | Code coverage quality gate (bundle >= 70%) | [pom.xml](../pom.xml) | JaCoCo check rule | CI `build-test-coverage` | Verified |
| SEC-004 | Static analysis / AST security scanning | [pom.xml](../pom.xml) | SpotBugs + FindSecBugs | CI `build-test-coverage` | Verified |
| SEC-005 | Software Bill of Materials (SBOM) generation | [pom.xml](../pom.xml) | CycloneDX plugin | CI `dependency-review-sbom` | Verified |
| SEC-006 | Secret detection in Git history | [.github/workflows/ci.yml](../.github/workflows/ci.yml) | Gitleaks action | CI `gitleaks` | Verified |
| SEC-007 | Container image vulnerability & Dockerfile lint | [Dockerfile](../Dockerfile) | Hadolint & Trivy | CI `container-build-lint-scan` | Verified |
| SEC-008 | Baseline application health & context loading | [CaseVaultApplicationTests.java](../src/test/java/com/casevault/CaseVaultApplicationTests.java) | JUnit 5 / SpringBootTest | CI `build-test-coverage` | Verified |
| SEC-009 | Session cookie security & strict headers | [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java), [HealthEndpointTest.java](../src/test/java/com/casevault/HealthEndpointTest.java) | `TEST-BASE-002`, `TEST-BASE-005` | CI `build-test-coverage` | Verified |

## Phase 1: Requirements, Threat Modeling & Architecture

| Requirement ID | Description | Specification Artifact | Validation / Verification Method | Status |
|---|---|---|---|---|
| REQ-001 | System Requirements Specification (15 FRs, 20 SRs) | [requirements.md](requirements.md) | Peer review & verification matrix mapping | Documented |
| REQ-002 | Misuse Cases (11 Scenarios covering brief) | [misuse-cases.md](misuse-cases.md) | Threat actor attack path review | Documented |
| REQ-003 | Comprehensive Threat Model (STRIDE, Assets, Boundaries) | [threat-model.md](threat-model.md) | STRIDE boundary evaluation & CVSS risk scoring | Documented |
| REQ-004 | Component Architecture & Trust Boundaries | [architecture.md](architecture.md) | Architecture review & ArchUnit boundary rules | Documented |
| REQ-005 | Data Flow Specification & Sequence Diagrams | [data-flow.md](data-flow.md) | DFD trust boundary crossing analysis | Documented |
| REQ-006 | Privacy & Data Retention Policy (Minimisation, Purging) | [privacy-retention.md](privacy-retention.md) | GDPR Art. 5 schedule audit & purge routines | Documented |
| ADR-001 | Technology Stack Selection | [0001-stack.md](adr/0001-stack.md) | Maven Enforcer & build verification | Accepted |
| ADR-002 | Authentication, Password Hashing & Session Management | [0002-auth.md](adr/0002-auth.md) | Argon2id tests & session cookie tests | Accepted |
| ADR-003 | Multi-Tenant Data Isolation & Authorization Model | [0003-tenant-isolation.md](adr/0003-tenant-isolation.md) | Cross-tenant 404 tests | Accepted |
| ADR-004 | Digital Evidence Storage & Envelope Encryption | [0004-evidence-encryption.md](adr/0004-evidence-encryption.md) | Google Tink AEAD & Tika MIME validation tests | Accepted |
| ADR-005 | Cryptographic Audit Trail Chaining & Concurrency | [0005-audit-chain.md](adr/0005-audit-chain.md) | Planned for Phase 6: HMAC-SHA256 chain verification & concurrency tests (no such tests exist yet) | Accepted (verification pending) |

## Phase 2: Authentication, Password Policy & Session Lifecycle

| Requirement ID | Description | Source / Config | Automated Test / Gate | CI Verification | Status |
|---|---|---|---|---|---|
| SEC-AUTH-01 | Argon2id password hashing parameters (64MB, 3 iter, 1 lane, 16-byte salt, 32-byte hash) | [PasswordEncoderConfig.java](../src/main/java/com/casevault/security/PasswordEncoderConfig.java) | [Argon2idSecurityTest.java](../src/test/java/com/casevault/auth/Argon2idSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-02 | Password policy enforcement (min 12 chars, complexity, dictionary rejection) | [PasswordPolicyValidator.java](../src/main/java/com/casevault/security/PasswordPolicyValidator.java) | [PasswordPolicySecurityTest.java](../src/test/java/com/casevault/auth/PasswordPolicySecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-03 | Account lockout after 5 consecutive failures for 15 minutes | [CaseVaultAuthenticationProvider.java](../src/main/java/com/casevault/security/CaseVaultAuthenticationProvider.java) | [AuthenticationLockoutSecurityTest.java](../src/test/java/com/casevault/auth/AuthenticationLockoutSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-04 | Generic error message identical for unknown user and wrong password | [CaseVaultAuthenticationProvider.java](../src/main/java/com/casevault/security/CaseVaultAuthenticationProvider.java) | [AuthenticationLockoutSecurityTest.java](../src/test/java/com/casevault/auth/AuthenticationLockoutSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-05 | Constant-ish timing defense (dummy Argon2id evaluation for unknown usernames) | [CaseVaultAuthenticationProvider.java](../src/main/java/com/casevault/security/CaseVaultAuthenticationProvider.java) | [AuthenticationLockoutSecurityTest.java](../src/test/java/com/casevault/auth/AuthenticationLockoutSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-06 | Session fixation protection & session ID rotation upon login | [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-07 | Logout invalidation, SecurityContext clearing & cookie deletion | [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-08 | Server-side session idle timeout (15 minutes) | [application.properties](../src/main/resources/application.properties) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-09 | Server-side session absolute timeout (8 hours maximum duration) | [SessionAbsoluteTimeoutFilter.java](../src/main/java/com/casevault/security/SessionAbsoluteTimeoutFilter.java) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-10 | Disabled accounts cannot authenticate | [CaseVaultAuthenticationProvider.java](../src/main/java/com/casevault/security/CaseVaultAuthenticationProvider.java) | [AuthenticationLockoutSecurityTest.java](../src/test/java/com/casevault/auth/AuthenticationLockoutSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-11 | Disabled account's existing active sessions terminate on next request | [UserStatusEnforcementFilter.java](../src/main/java/com/casevault/security/UserStatusEnforcementFilter.java) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-12 | CSRF protection enforced on state-changing requests | [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-13 | Session cookie policy (HttpOnly, SameSite=Strict, Secure in prod-like profile) | [application-prod-like.properties](../src/main/resources/application-prod-like.properties) | [ProfileConfigurationSecurityTest.java](../src/test/java/com/casevault/auth/ProfileConfigurationSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-14 | First-run bootstrap generates synthetic users and writes zero secrets to Git | [DataBootstrapService.java](../src/main/java/com/casevault/bootstrap/DataBootstrapService.java) | [DataBootstrapSecurityTest.java](../src/test/java/com/casevault/auth/DataBootstrapSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTH-15 | Prod-like profile strictly disables bootstrap generation and prints zero credentials | [DataBootstrapService.java](../src/main/java/com/casevault/bootstrap/DataBootstrapService.java) | [BootstrapProdProfileSecurityTest.java](../src/test/java/com/casevault/auth/BootstrapProdProfileSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-DB-001 | Flyway V1, V2, and V3 migrations execute successfully on real PostgreSQL container | [V3__cases_and_evidence_schema.sql](../src/main/resources/db/migration/V3__cases_and_evidence_schema.sql) | [PostgresFlywayMigrationTest.java](../src/test/java/com/casevault/db/PostgresFlywayMigrationTest.java) | CI `build-test-coverage` | Verified |
| SEC-DB-002 | PostgreSQL schema integrity (foreign keys, unique constraints, CRUD operations) | [V3__cases_and_evidence_schema.sql](../src/main/resources/db/migration/V3__cases_and_evidence_schema.sql) | [PostgresFlywayMigrationTest.java](../src/test/java/com/casevault/db/PostgresFlywayMigrationTest.java) | CI `build-test-coverage` | Verified |

## Phase 3: Multi-Tenant Authorization & IDOR/BOLA Defense

| Requirement ID | Description | Source / Config | Automated Test / Gate | CI Verification | Status |
|---|---|---|---|---|---|
| SEC-AUTHZ-01 | CLIENT confined strictly to own organisation cases; foreign case access returns HTTP 404 | [CaseAccessService.java](../src/main/java/com/casevault/service/CaseAccessService.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-02 | ANALYST can access assigned cases across all client orgs; unassigned/unauthorized cases return HTTP 404 | [CaseAccessService.java](../src/main/java/com/casevault/service/CaseAccessService.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-03 | Internal staff manager (ORG_INTERNAL) accesses all client cases; client org manager restricted to own org | [CaseAccessService.java](../src/main/java/com/casevault/service/CaseAccessService.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-04 | AUDITOR_ADMIN has strict zero-access to case content (returns HTTP 404 on get; empty list on list) | [AccessPolicy.java](../src/main/java/com/casevault/security/AccessPolicy.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-05 | Case listings strictly scoped to caller's tenant and role assignment without leaking records | [CaseAccessService.java](../src/main/java/com/casevault/service/CaseAccessService.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-06 | Evidence metadata queries inherit case tenant scoping; foreign access returns HTTP 404 | [CaseAccessService.java](../src/main/java/com/casevault/service/CaseAccessService.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-07 | Nonexistent UUID guessing returns HTTP 404 indistinguishable from unauthorized tenant access | [CaseAccessService.java](../src/main/java/com/casevault/service/CaseAccessService.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-08 | Unauthenticated requests to protected API endpoints return HTTP 401 Unauthorized | [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-09 | Mass assignment protection: DTOs do not bind organisationId, role, status, owner, or assignedAnalyst | [CreateCaseRequestDto.java](../src/main/java/com/casevault/dto/CreateCaseRequestDto.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-10 | Case creation restricted strictly to CLIENT role (FR-04); other roles receive HTTP 403 Forbidden | [CaseApiController.java](../src/main/java/com/casevault/controller/CaseApiController.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-11 | Category and Severity input validation: regex allow-lists reject unexpected values with HTTP 400 | [CreateCaseRequestDto.java](../src/main/java/com/casevault/dto/CreateCaseRequestDto.java) | [AuthorisationOperationMatrixTest.java](../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-ARCH-01 | Controllers must not access repositories directly; all access must route through service layer | [CaseApiController.java](../src/main/java/com/casevault/controller/CaseApiController.java) | [ArchitectureTest.java](../src/test/java/com/casevault/ArchitectureTest.java) | CI `build-test-coverage` | Verified |
| SEC-AUTHZ-ARCH-02 | Repositories only accessible by service and security/bootstrap components | [CaseRepository.java](../src/main/java/com/casevault/repository/CaseRepository.java) | [ArchitectureTest.java](../src/test/java/com/casevault/ArchitectureTest.java) | CI `build-test-coverage` | Verified |

## Phase 4: Case Workflow & UI Shell

| Requirement ID | Description | Source / Config | Automated Test / Gate | CI Verification | Status |
|---|---|---|---|---|---|
| SEC-CASE-01 | FSM lifecycle transitions: valid succeed, invalid return HTTP 400 (FR-06) | [DefaultCaseAccessService.java](../src/main/java/com/casevault/service/DefaultCaseAccessService.java) | [CaseWorkflowSecurityTest.java](../src/test/java/com/casevault/cases/CaseWorkflowSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-02 | Role-based status transition restrictions (FR-06, SR-01) | [DefaultCaseAccessService.java](../src/main/java/com/casevault/service/DefaultCaseAccessService.java) | [CaseWorkflowSecurityTest.java](../src/test/java/com/casevault/cases/CaseWorkflowSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-03 | Analyst assignment authorization: MANAGER only, target must be ANALYST (FR-05) | [DefaultCaseAccessService.java](../src/main/java/com/casevault/service/DefaultCaseAccessService.java) | [CaseWorkflowSecurityTest.java](../src/test/java/com/casevault/cases/CaseWorkflowSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-04 | Investigation notes permissions and cross-tenant IDOR defense (FR-07, SR-02) | [DefaultCaseAccessService.java](../src/main/java/com/casevault/service/DefaultCaseAccessService.java) | [CaseWorkflowSecurityTest.java](../src/test/java/com/casevault/cases/CaseWorkflowSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-05 | Remediation actions permissions and cross-tenant IDOR defense (FR-07, SR-02) | [DefaultCaseAccessService.java](../src/main/java/com/casevault/service/DefaultCaseAccessService.java) | [CaseWorkflowSecurityTest.java](../src/test/java/com/casevault/cases/CaseWorkflowSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-06 | Mass assignment protection: server overrides client claims (SR-01) | [DefaultCaseAccessService.java](../src/main/java/com/casevault/service/DefaultCaseAccessService.java) | [CaseWorkflowSecurityTest.java](../src/test/java/com/casevault/cases/CaseWorkflowSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-07 | LIKE wildcard escaping in q query parameter (SR-10) | [DefaultCaseAccessService.java](../src/main/java/com/casevault/service/DefaultCaseAccessService.java) | [CaseSearchAndUiSecurityTest.java](../src/test/java/com/casevault/cases/CaseSearchAndUiSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-08 | SQL injection safety across search parameters (SR-10) | [DefaultCaseAccessService.java](../src/main/java/com/casevault/service/DefaultCaseAccessService.java) | [CaseSearchAndUiSecurityTest.java](../src/test/java/com/casevault/cases/CaseSearchAndUiSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-09 | Capped pagination limit (max 50) and sort field allow-list (FR-10) | [SearchCasesRequestDto.java](../src/main/java/com/casevault/dto/SearchCasesRequestDto.java) | [CaseSearchAndUiSecurityTest.java](../src/test/java/com/casevault/cases/CaseSearchAndUiSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-10 | Strict tenant boundaries in case search (SR-02) | [DefaultCaseAccessService.java](../src/main/java/com/casevault/service/DefaultCaseAccessService.java) | [CaseSearchAndUiSecurityTest.java](../src/test/java/com/casevault/cases/CaseSearchAndUiSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-11 | AUDITOR_ADMIN web route boundary: returns 404 on /cases/** (SR-07) | [CaseWebController.java](../src/main/java/com/casevault/controller/CaseWebController.java) | [CaseSearchAndUiSecurityTest.java](../src/test/java/com/casevault/cases/CaseSearchAndUiSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-12 | Context-aware HTML output encoding / XSS prevention (SR-08) | Thymeleaf templates (`th:text` only) | [CaseSearchAndUiSecurityTest.java](../src/test/java/com/casevault/cases/CaseSearchAndUiSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-CASE-13 | Template scanner: zero th:utext, innerHTML, inline scripts/styles (SR-08, SR-09) | All `.html` templates | [CaseSearchAndUiSecurityTest.java](../src/test/java/com/casevault/cases/CaseSearchAndUiSecurityTest.java) | CI `build-test-coverage` | Verified |
| FUNC-CASE-01 | Full case investigation lifecycle workflow (FR-04..FR-07) | [DefaultCaseAccessService.java](../src/main/java/com/casevault/service/DefaultCaseAccessService.java) | [CaseWorkflowSecurityTest.java](../src/test/java/com/casevault/cases/CaseWorkflowSecurityTest.java) | CI `build-test-coverage` | Verified |
| FUNC-CASE-02 | Client incident reporting workflow through web UI (FR-04) | [CaseWebController.java](../src/main/java/com/casevault/controller/CaseWebController.java) | [CaseSearchAndUiSecurityTest.java](../src/test/java/com/casevault/cases/CaseSearchAndUiSecurityTest.java) | CI `build-test-coverage` | Verified |
| SEC-SA-02 | SpotBugs EI_EXPOSE_REP2 exclusion on controllers justified (Spring DI false positive) | [spotbugs-exclude.xml](../spotbugs-exclude.xml) | [static-analysis-exclusions.md](assurance/static-analysis-exclusions.md) | CI `build-test-coverage` | Verified |


## Phase 5: Evidence Upload, Storage & Secure Download

| Requirement | Evidence / tests |
|---|---|
| FR-08 | `EvidenceValidatorTest` SEC-EV-VAL-001..013, SEC-EVID-UNI-01..02, SEC-EVID-HARDEN-01..02; `AuthorisationOperationMatrixTest` SEC-EVID-AUTHZ-01, SEC-EVID-AUTHZ-02, SEC-EVID-AUTHZ-06, SEC-EVID-AUTHZ-07, SEC-EVID-AUTHZ-08; `CaseSearchAndUiSecurityTest` SEC-EVID-HARDEN-03; `EvidenceWebSecurityTest` SEC-EVID-WEB-01..08; `EvidenceFailureOrderTest` SEC-EVID-FAIL-01..02; `EvidenceUiSecurityTest` SEC-EVID-UI-01; `EvidenceLogSecurityTest` SEC-EVID-LOG-01..02; `ArchitectureTest` SEC-EVID-ARCH-01..03 |
| FR-09 | `AuthorisationOperationMatrixTest` SEC-EVID-AUTHZ-01, SEC-EVID-AUTHZ-02, SEC-EVID-AUTHZ-03, SEC-EVID-AUTHZ-04, SEC-EVID-AUTHZ-05; `EvidenceWebSecurityTest` SEC-EVID-WEB-03..04, SEC-EVID-DL-01..05; `EvidenceUiSecurityTest` SEC-EVID-UI-01; `EvidenceLogSecurityTest` SEC-EVID-LOG-03..05 |
| SR-01 | `AuthorisationOperationMatrixTest` SEC-EVID-AUTHZ-01..08; `EvidenceWebSecurityTest` SEC-EVID-WEB-01..04; `EvidenceUiSecurityTest` SEC-EVID-UI-01..03; `ArchitectureTest` SEC-EVID-ARCH-01..03 |
| SR-02 | `AuthorisationOperationMatrixTest` SEC-EVID-AUTHZ-01, SEC-EVID-AUTHZ-03, SEC-EVID-AUTHZ-05; `EvidenceWebSecurityTest` SEC-EVID-WEB-03..04; `EvidenceUiSecurityTest` SEC-EVID-UI-01..03 |
| SR-07 | `AuthorisationOperationMatrixTest` SEC-EVID-AUTHZ-04; `EvidenceWebSecurityTest` SEC-EVID-WEB-03; `EvidenceUiSecurityTest` SEC-EVID-UI-03 |
| SR-08 | `CaseSearchAndUiSecurityTest` SEC-EVID-HARDEN-03; `EvidenceWebSecurityTest` SEC-EVID-WEB-05..06, SEC-EVID-DL-02..04; `EvidenceUiSecurityTest` SEC-EVID-UI-02, SEC-EVID-UI-04; `EvidenceLogSecurityTest` SEC-EVID-LOG-02 |
| SR-11 | `EvidenceValidatorTest` SEC-EV-VAL-002..010, SEC-EVID-UNI-01..02, SEC-EVID-HARDEN-01..02; `EvidenceWebSecurityTest` SEC-EVID-WEB-05..07; `EvidenceFailureOrderTest` SEC-EVID-FAIL-01..02 |
| SR-12 | `EvidenceStorageServiceTest` (encryption, ciphertext round-trip, tampering detection); `AuthorisationOperationMatrixTest` SEC-EVID-AUTHZ-01..05; `EvidenceWebSecurityTest` SEC-EVID-DL-01..05; `EvidenceFailureOrderTest` SEC-EVID-FAIL-01..02; `EvidenceLogSecurityTest` SEC-EVID-LOG-04..05 |

All Phase 5 evidence requirements (Groups A through G) verified. Phase 6 cryptographic audit log chaining pending.

All Phase 5 evidence requirements (Groups A through G) verified. Phase 6 cryptographic audit log chaining pending.

## Verification Execution Summary

- Local Build & Gate Command: `.\mvnw.cmd -B verify`
- Target Environments: Java 21 LTS (OpenJDK Temurin), PostgreSQL 16+ via Testcontainers, H2 (in-memory test profile)

## Phase 6A: Tamper-Evident Audit Chain (backend only, DRAFT)

| Requirement | Evidence / tests |
|---|---|
| FR-13 | `AuditChainTest` SEC-AUDIT-01..14; `AuditConcurrencyTest` SEC-AUDIT-15; `PostgresAuditChainTest` SEC-AUDIT-16..17. Service only: NOT yet wired into application flows (Phase 6B). Details: [audit-tests.md](assurance/audit-tests.md) |
| SR-13 | `AuditChainTest` SEC-AUDIT-01, SEC-AUDIT-03..09; `ArchitectureTest` SEC-AUDIT-ARCH-01..05. Tail truncation is detectable only with an external anchor (SEC-AUDIT-08) |
| SR-14 | `AuditConcurrencyTest` SEC-AUDIT-15 (8 threads x 25 appends, repeated 10 times); `AuditChainTest` SEC-AUDIT-11 and `PostgresAuditChainTest` SEC-AUDIT-16 (millisecond precision) |

## Phase 6B: Audit Log Wiring (DRAFT)

| Requirement | Evidence / tests |
|---|---|
| FR-13 | `AuditWiringTest` SEC-AUDIT-WIRE-01..11 (login, lockout, logout, access denied, case and evidence events recorded; chain valid after a mixed scenario). Admin and report events are NOT wired yet (Phase 7); no auditor UI yet (Phase 6C). Details: [audit-tests.md](assurance/audit-tests.md) |
| SR-13 | `AuditWiringTest` SEC-AUDIT-WIRE-11 (chain verifies after real application events); `ArchitectureTest` SEC-AUDIT-ARCH-06 |
| SR-15 | `AuditWiringTest` SEC-AUDIT-WIRE-12 (append failure shows the safe error page with a correlation id, no stack trace or exception text) |
| SR-02 | `AuditWiringTest` SEC-AUDIT-WIRE-07 (cross-tenant request stays HTTP 404 and is recorded once as ACCESS_DENIED) |

## Phase 6C: Findings Log and Auditor Audit View (DRAFT)

| Requirement ID | Description | Source / Config | Automated Test / Gate | CI Verification | Status |
|---|---|---|---|---|---|
| FINDINGS-001 | Findings log; F-001 (authentication provider ran twice per login) with retest reference | [findings-log.md](assurance/findings-log.md) | SEC-AUDIT-WIRE-04 ([AuditWiringTest.java](../src/test/java/com/casevault/audit/AuditWiringTest.java)) | CI `build-test-coverage` | Verified (retest passes) |
| FR-13-UI | Auditor-only paged audit list with filters, fixed newest-first sort, size cap 50 | [AuditController.java](../src/main/java/com/casevault/controller/AuditController.java), [AuditQueryService.java](../src/main/java/com/casevault/service/AuditQueryService.java), [audit/list.html](../src/main/resources/templates/audit/list.html) | SEC-AUDIT-UI-02, -03, -07, -08, -09, -10 ([AuditUiTest.java](../src/test/java/com/casevault/audit/AuditUiTest.java)); SEC-AUDIT-UI-15 (PostgreSQL) | CI `build-test-coverage` | Verified |
| SR-07-UI | Auditor sees ids only and still has no case or evidence content | [audit-chain ADR, 6C](adr/0005-audit-chain.md) | SEC-AUDIT-UI-06 | CI `build-test-coverage` | Verified |
| SR-13-UI | Chain verification on demand: badge, one run at a time, AUDIT_CHAIN_VERIFIED event, CSRF on POST | [AuditQueryService.java](../src/main/java/com/casevault/service/AuditQueryService.java) | SEC-AUDIT-UI-01, -04, -11, -12, -13 | CI `build-test-coverage` | Verified |
| SR-08-UI | Audit template: th:text only, no inline script/style/handler, CSP unchanged | [audit/list.html](../src/main/resources/templates/audit/list.html) | SEC-AUDIT-UI-14, SEC-CASE-13, SEC-EVID-UI-04 | CI `build-test-coverage` | Verified |
| ARCH-AUDIT-07 | Only AuditQueryService reads the audit log through AuditLogReader | [ArchitectureTest.java](../src/test/java/com/casevault/ArchitectureTest.java) | SEC-AUDIT-ARCH-07 | CI `build-test-coverage` | Verified |

## Phase 7A: Reports Backend (DRAFT)

| Requirement ID | Description | Source / Config | Automated Test / Gate | CI Verification | Status |
|---|---|---|---|---|---|
| FR-11 | Analyst drafts reports linked to a case; unapproved drafts hidden from clients (service layer only, no endpoint yet) | [DefaultReportService.java](../src/main/java/com/casevault/service/DefaultReportService.java), [V8__reports.sql](../src/main/resources/db/migration/V8__reports.sql) | SEC-REPORT-AUTHZ-01, SEC-REPORT-03, SEC-REPORT-05 | CI `build-test-coverage` | Verified at service level; HTTP and UI in 7C |
| FR-12 / SR-06 | Four-eyes: the author cannot approve; a different manager can | [DefaultReportService.java](../src/main/java/com/casevault/service/DefaultReportService.java) | SEC-REPORT-01, SEC-REPORT-02 | CI `build-test-coverage` | Verified at service level |
| SR-02 (reports) | Cross-tenant, unauthorised and wrong-case report access is 404; auditor gets 404 | [DefaultReportService.java](../src/main/java/com/casevault/service/DefaultReportService.java) | SEC-REPORT-AUTHZ-01, SEC-REPORT-03, SEC-REPORT-04 | CI `build-test-coverage` | Verified at service level |
| REPORT-BODY | Plain-text body, length and control-character limits, no mass assignment | [ADR 0006](adr/0006-report-workflow-plain-text.md), [ReportRequestDto.java](../src/main/java/com/casevault/dto/ReportRequestDto.java) | SEC-REPORT-05, SEC-REPORT-07 | CI `build-test-coverage` | Verified (output escaping is tested in 7C) |
| FR-13 (reports) | REPORT_TRANSITION wired: one event per transition, actor and case id, no body | [DefaultReportService.java](../src/main/java/com/casevault/service/DefaultReportService.java) | SEC-REPORT-08, SEC-REPORT-09 | CI `build-test-coverage` | Verified |
| DB-REPORTS | Flyway V8 on H2 and real PostgreSQL | [V8__reports.sql](../src/main/resources/db/migration/V8__reports.sql) | SEC-DB-001 ([PostgresFlywayMigrationTest.java](../src/test/java/com/casevault/db/PostgresFlywayMigrationTest.java)) | CI `build-test-coverage` | Verified |
| ARCH-REPORT | Controllers cannot reach the report repository or implementation | [ArchitectureTest.java](../src/test/java/com/casevault/ArchitectureTest.java) | SEC-REPORT-ARCH-01, -02, -03 | CI `build-test-coverage` | Verified |
| TEST-REPORT-DOC | Report attack-to-test table | [report-tests.md](assurance/report-tests.md) | n/a | n/a | Documentation |

## Phase 7B: Admin Functions and Health (DRAFT)

| Requirement ID | Description | Source / Config | Automated Test / Gate | CI Verification | Status |
|---|---|---|---|---|---|
| FR-14 | Admin disables or enables accounts and revokes sessions; the session dies on the next request | [DefaultAdminUserService.java](../src/main/java/com/casevault/service/DefaultAdminUserService.java), [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java) | SEC-ADMIN-09, SEC-ADMIN-10, SEC-ADMIN-11 ([AdminHttpTest.java](../src/test/java/com/casevault/admin/AdminHttpTest.java)) | CI `build-test-coverage` | Verified over HTTP |
| FR-14 (safety) | No self-disable, no self-revoke, last active admin protected, concurrent double disable safe | [DefaultAdminUserService.java](../src/main/java/com/casevault/service/DefaultAdminUserService.java) | SEC-ADMIN-06, SEC-ADMIN-07, SEC-ADMIN-08 | CI `build-test-coverage` | Verified |
| SR-07 (admin) | Only AUDITOR_ADMIN reaches admin pages; others 404; CSRF on every POST; auditor still has no case content | [AdminController.java](../src/main/java/com/casevault/controller/AdminController.java) | SEC-ADMIN-03, -04, -12, SEC-ADMIN-AUTHZ-01 | CI `build-test-coverage` | Verified |
| FR-13 (admin) | ADMIN_ACCOUNT_DISABLED, ADMIN_ACCOUNT_ENABLED, ADMIN_SESSION_REVOKED wired; actor only; refusals as ACCESS_DENIED / ADMIN_REFUSED | [DefaultAdminUserService.java](../src/main/java/com/casevault/service/DefaultAdminUserService.java) | SEC-ADMIN-14 | CI `build-test-coverage` | Verified |
| FR-15 | Minimal health page: database, evidence storage, last audit verification, head sequence; no paths, versions or secrets | [admin/health.html](../src/main/resources/templates/admin/health.html) | SEC-ADMIN-01, SEC-ADMIN-02, HealthEndpointTest (unchanged) | CI `build-test-coverage` | Verified (minimal set) |
| DB-USERTRACE | users.status_changed_at / status_changed_by (V9) so the disabled account is traceable | [V9__user_status_trace.sql](../src/main/resources/db/migration/V9__user_status_trace.sql) | SEC-ADMIN-14, SEC-DB-001 | CI `build-test-coverage` | Verified |
| SR-08-ADMIN | Admin templates: th:text only, no inline script/style/handler, CSP unchanged | [templates/admin](../src/main/resources/templates/admin) | SEC-ADMIN-15, SEC-CASE-13, SEC-EVID-UI-04 | CI `build-test-coverage` | Verified |
| ARCH-ADMIN | Controllers use only the AdminUserService interface | [ArchitectureTest.java](../src/test/java/com/casevault/ArchitectureTest.java) | SEC-ADMIN-ARCH-01 | CI `build-test-coverage` | Verified |
| TEST-ADMIN-DOC | Admin attack-to-test table | [admin-tests.md](assurance/admin-tests.md) | n/a | n/a | Documentation |
