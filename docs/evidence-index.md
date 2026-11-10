# Evidence Index

This index maps architectural, security, and functional requirements to verified artifacts, tests, and CI jobs within the CaseVault repository.

## Phase 0: Baseline Quality & Security Gates

| Requirement ID | Description | Source / Config | Automated Test / Gate | CI Verification | Status |
|---|---|---|---|---|---|
| SEC-001 | Java 21 LTS baseline & Enforcer | [pom.xml](../pom.xml) | Maven Enforcer plugin | CI `build-and-test` | Verified |
| SEC-002 | Dependency convergence & duplication ban | [pom.xml](../pom.xml) | Maven Enforcer plugin | CI `build-and-test` | Verified |
| SEC-003 | Code coverage quality gate (bundle >= 70%) | [pom.xml](../pom.xml) | JaCoCo check rule | CI `build-and-test` | Verified |
| SEC-004 | Static analysis / AST security scanning | [pom.xml](../pom.xml) | SpotBugs + FindSecBugs | CI `build-and-test` | Verified |
| SEC-005 | Software Bill of Materials (SBOM) generation | [pom.xml](../pom.xml) | CycloneDX plugin | CI `sbom` | Verified |
| SEC-006 | Secret detection in Git history | [.github/workflows/ci.yml](../.github/workflows/ci.yml) | Gitleaks action | CI `gitleaks` | Verified |
| SEC-007 | Container image vulnerability & Dockerfile lint | [Dockerfile](../Dockerfile) | Hadolint & Trivy | CI `container-scan` | Verified |
| SEC-008 | Baseline application health & context loading | [CaseVaultApplicationTests.java](../src/test/java/com/casevault/CaseVaultApplicationTests.java) | JUnit 5 / SpringBootTest | CI `build-and-test` | Verified |
| SEC-009 | Session cookie security & strict headers | [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java), [HealthEndpointTest.java](../src/test/java/com/casevault/HealthEndpointTest.java) | `TEST-BASE-002`, `TEST-BASE-005` | CI `build-and-test` | Verified |

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
| ADR-005 | Cryptographic Audit Trail Chaining & Concurrency | [0005-audit-chain.md](adr/0005-audit-chain.md) | HMAC-SHA256 chain verification & concurrency tests | Accepted |

## Phase 2: Authentication, Password Policy & Session Lifecycle

| Requirement ID | Description | Source / Config | Automated Test / Gate | CI Verification | Status |
|---|---|---|---|---|---|
| SEC-AUTH-01 | Argon2id password hashing parameters (64MB, 3 iter, 1 lane, 16-byte salt, 32-byte hash) | [PasswordEncoderConfig.java](../src/main/java/com/casevault/security/PasswordEncoderConfig.java) | [Argon2idSecurityTest.java](../src/test/java/com/casevault/auth/Argon2idSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-02 | Password policy enforcement (min 12 chars, complexity, dictionary rejection) | [PasswordPolicyValidator.java](../src/main/java/com/casevault/security/PasswordPolicyValidator.java) | [PasswordPolicySecurityTest.java](../src/test/java/com/casevault/auth/PasswordPolicySecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-03 | Account lockout after 5 consecutive failures for 15 minutes | [CaseVaultAuthenticationProvider.java](../src/main/java/com/casevault/security/CaseVaultAuthenticationProvider.java) | [AuthenticationLockoutSecurityTest.java](../src/test/java/com/casevault/auth/AuthenticationLockoutSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-04 | Generic error message identical for unknown user and wrong password | [CaseVaultAuthenticationProvider.java](../src/main/java/com/casevault/security/CaseVaultAuthenticationProvider.java) | [AuthenticationLockoutSecurityTest.java](../src/test/java/com/casevault/auth/AuthenticationLockoutSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-05 | Constant-ish timing defense (dummy Argon2id evaluation for unknown usernames) | [CaseVaultAuthenticationProvider.java](../src/main/java/com/casevault/security/CaseVaultAuthenticationProvider.java) | [AuthenticationLockoutSecurityTest.java](../src/test/java/com/casevault/auth/AuthenticationLockoutSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-06 | Session fixation protection & session ID rotation upon login | [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-07 | Logout invalidation, SecurityContext clearing & cookie deletion | [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-08 | Server-side session idle timeout (15 minutes) | [application.properties](../src/main/resources/application.properties) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-09 | Server-side session absolute timeout (8 hours maximum duration) | [SessionAbsoluteTimeoutFilter.java](../src/main/java/com/casevault/security/SessionAbsoluteTimeoutFilter.java) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-10 | Disabled accounts cannot authenticate | [CaseVaultAuthenticationProvider.java](../src/main/java/com/casevault/security/CaseVaultAuthenticationProvider.java) | [AuthenticationLockoutSecurityTest.java](../src/test/java/com/casevault/auth/AuthenticationLockoutSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-11 | Disabled account's existing active sessions terminate on next request | [UserStatusEnforcementFilter.java](../src/main/java/com/casevault/security/UserStatusEnforcementFilter.java) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-12 | CSRF protection enforced on state-changing requests | [SecurityConfig.java](../src/main/java/com/casevault/config/SecurityConfig.java) | [SessionLifecycleSecurityTest.java](../src/test/java/com/casevault/auth/SessionLifecycleSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-13 | Session cookie policy (HttpOnly, SameSite=Strict, Secure in prod-like profile) | [application-prod-like.properties](../src/main/resources/application-prod-like.properties) | [ProfileConfigurationSecurityTest.java](../src/test/java/com/casevault/auth/ProfileConfigurationSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-14 | First-run bootstrap generates synthetic users and writes zero secrets to Git | [DataBootstrapService.java](../src/main/java/com/casevault/bootstrap/DataBootstrapService.java) | [DataBootstrapSecurityTest.java](../src/test/java/com/casevault/auth/DataBootstrapSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-AUTH-15 | Prod-like profile strictly disables bootstrap generation and prints zero credentials | [DataBootstrapService.java](../src/main/java/com/casevault/bootstrap/DataBootstrapService.java) | [BootstrapProdProfileSecurityTest.java](../src/test/java/com/casevault/auth/BootstrapProdProfileSecurityTest.java) | CI `build-and-test` | Verified |
| SEC-DB-001 | Flyway V1 and V2 migrations execute successfully on real PostgreSQL container | [V2__auth_schema.sql](../src/main/resources/db/migration/V2__auth_schema.sql) | [PostgresFlywayMigrationTest.java](../src/test/java/com/casevault/db/PostgresFlywayMigrationTest.java) | CI `build-and-test` | Verified |
| SEC-DB-002 | PostgreSQL schema integrity (foreign keys, unique constraints, CRUD operations) | [V2__auth_schema.sql](../src/main/resources/db/migration/V2__auth_schema.sql) | [PostgresFlywayMigrationTest.java](../src/test/java/com/casevault/db/PostgresFlywayMigrationTest.java) | CI `build-and-test` | Verified |

## Verification Execution Summary

- Local Build & Gate Command: `.\mvnw.cmd -B verify`
- Target Environments: Java 21 LTS (OpenJDK Temurin), PostgreSQL 16+ via Testcontainers, H2 (in-memory test profile)
