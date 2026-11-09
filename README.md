# CaseVault

CaseVault is a secure case-management and evidence-handling platform designed for incident-response consultancies.

## Architectural & Security Overview

- **Multi-Tenant Isolation**: Organisation-scoped data model; server-side re-validation on every request. Cross-tenant or unauthorized case/evidence access yields HTTP 404.
- **Role-Based Access Control**:
  - `CLIENT`: Own organisation's cases, evidence uploads, approved reports.
  - `ANALYST`: Assigned cases, investigation notes, remediation actions, draft reports.
  - `MANAGER`: Case assignment, status updates, report approval (four-eyes principle: cannot approve own reports).
  - `AUDITOR_ADMIN`: Security events, account activity, system health, account revocation. Strictly no access to case or evidence content.
- **Defensive Engineering**:
  - Strict Content Security Policy (CSP) with per-request nonce.
  - Argon2id password hashing via Spring Security and BouncyCastle.
  - Google Tink envelope encryption at rest for sensitive evidence artifacts.
  - Cryptographic tamper-evident audit logging using JDK HMAC-SHA256 chains.
  - Safe error handling: correlation IDs only, no stack traces or internal schema details exposed.
  - Content sanitization and strict context-aware output encoding (Thymeleaf `th:text`).

## Prerequisites

- Java 21 LTS (OpenJDK Temurin 21 recommended)
- Maven 3.9+ (or included Maven wrapper `mvnw` / `mvnw.cmd`)
- Docker (for Testcontainers PostgreSQL tests and container verification)

## Building & Verifying

Run the full verification suite including unit/integration tests, Enforcer checks, JaCoCo coverage, and SpotBugs/FindSecBugs static analysis:

```powershell
.\mvnw.cmd -B verify
```

On Linux / macOS:
```bash
./mvnw -B verify
```

## Documentation

- [Evidence Index](docs/evidence-index.md)
- [AI Assistance Declaration](docs/ai-declaration.md)
- [Backlog & Known Issues](docs/issues-backlog.md)
- [Architecture Decision Records](docs/adr/)
- [Security Assurance Documents](docs/assurance/)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
