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
  - Strict Content Security Policy (CSP) delivered as two headers (`default-src 'self'` and `script-src 'self'`, no `unsafe-inline`, no `unsafe-eval`). There is no per-request nonce: the templates contain no inline script or style, so none is needed.
  - Argon2id password hashing via Spring Security and BouncyCastle.
  - Evidence files are encrypted at rest with AES-256-GCM (AEAD) through Google Tink. The Tink keyset is stored as cleartext JSON in a git-ignored folder beside the data (documented residual risk; there is no key hierarchy and no secret manager).
  - Cryptographic tamper-evident audit logging using JDK HMAC-SHA256 chains.
  - Safe error handling: correlation IDs only, no stack traces or internal schema details exposed.
  - Output escaping on every page (Thymeleaf `th:text`, no `th:utext`). There is no content sanitisation or redaction of report or note text.

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

## Testing

Result of a fresh `.\mvnw.cmd -B verify` on 2026-11-13 (this is the only place in the documentation that states the current total): **354 tests, 0 failures, 0 skipped**, SpotBugs `BugInstance size is 0`. Other documents quote older totals and label them with their phase. The manual browser tests in [docs/assurance/manual-browser-tests.md](docs/assurance/manual-browser-tests.md) have **not** been executed yet. What is not built or only partly built is listed in [docs/assurance/known-limitations.md](docs/assurance/known-limitations.md).

## Running locally

Start the application with the `local` profile (HTTP on port 8080, in-memory H2 database, session cookie without `Secure` so that it works over plain http):

```powershell
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=local"
```

Then open `http://localhost:8080/login`. On every start the `local` profile creates synthetic accounts with **random passwords** (only in this profile) and prints them once in the console banner `[CASEVAULT FIRST-RUN BOOTSTRAP]`; they are also written to `.local-data/bootstrap-credentials.txt` (git-ignored). Besides the four normal accounts (`admin_auditor`, `manager_alice`, `analyst_bob`, `client_charlie`) the local profile creates DEMO data for browser tests: a second client organisation "Demo Client Org B" with the user `demo_client_b` and one DEMO case, and a second administrator `demo_admin_2`. The default and `prod-like` profiles never create demo data, and the `prod-like` profile creates no accounts at all. Stopping and starting the application resets the in-memory database (and generates new passwords). A step-by-step browser test guide is in [docs/assurance/manual-browser-tests.md](docs/assurance/manual-browser-tests.md).

## Run with Docker (hardened)

A hardened stack (nginx with TLS, the application, PostgreSQL; read-only containers, all capabilities dropped, only `127.0.0.1:8443` published) is described in [docs/assurance/deployment-hardening.md](docs/assurance/deployment-hardening.md). It uses its own compose project `casevault-rebuild` and the names `cvr-*`; the scripts refuse any other project. Requires Docker, PowerShell and openssl (Git for Windows includes it). From the repository root:

```powershell
scripts\deploy-init.ps1                  # creates the database password and a self-signed certificate in .local-data\deploy\ (git-ignored)
scripts\deploy-up.ps1 -Build -FirstRun   # builds the image and starts the stack; the four accounts are created ONCE
scripts\deploy-status.ps1                # state and hardening settings
```

Open `https://localhost:8443/login` (self-signed certificate: the browser warns). The initial passwords are written only to a file inside the Docker volume `cvr_firstrun` and are never printed or logged. **After the first login the first-run override must be removed and the credentials file deleted** (the opt-in flag needs the credentials-file path on every start, so the override must not stay in use):

```powershell
scripts\deploy-up.ps1 -FinishFirstRun    # restarts WITHOUT the override and deletes the credentials file
scripts\deploy-down.ps1                  # stops and removes the containers, keeps the data
scripts\deploy-down.ps1 -RemoveData      # also deletes the data volumes of this project (cvr_*)
```

`scripts\deploy-verify.ps1` repeats the recorded checks and writes scrubbed evidence to `docs/evidence/deploy/`. There is no backup, restore or rollback procedure yet (see [known limitations](docs/assurance/known-limitations.md)).

## Documentation

- [Evidence Index](docs/evidence-index.md)
- [AI Assistance Declaration](docs/ai-declaration.md)
- [Backlog & Known Issues](docs/issues-backlog.md)
- [Architecture Decision Records](docs/adr/)
- [Security Assurance Documents](docs/assurance/)
- [Known Limitations](docs/assurance/known-limitations.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
