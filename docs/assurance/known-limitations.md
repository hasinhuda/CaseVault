# Known limitations (DRAFT)

One consolidated, plain-language list of what CaseVault does **not** do, does only in part, or does by design choice. It is based on `docs/assurance/brief-audit.md` (2026-11-13) and the code. Nothing here is a promise to fix; each item says where the detail lives. If a statement in another document sounds stronger than this page, this page is the one to trust.

## (a) Not implemented

| Item | What the repository contains | Consequence | Detail |
|---|---|---|---|
| Production-grade TLS | The Docker stack (`deploy/compose.yaml`, Phase 12B) terminates TLS 1.2/1.3 in nginx with a **self-signed** localhost certificate; the application itself still serves plain HTTP on an internal port (TLS ends at nginx). Outside that stack (`local` or default profile) everything is plain HTTP | No certificate from a certificate authority, no certificate management or renewal, no mutual TLS, no TLS between nginx and the application; browsers show a warning. Only run on one machine and not in a browser by the author (**NOT VERIFIED** in Chrome or Edge) | `assurance/deployment-hardening.md`, `docs/evidence/deploy/05-tls.txt` |
| Hardening beyond one host | The compose stack sets read-only root filesystems, all capabilities dropped, `no-new-privileges`, memory and process limits, non-root users and an internal database network (evidence `02-inspect.txt`). Not built: image signing, an image scan of the compose images, a secret manager, resource tuning under load, orchestration (Kubernetes), WAF, log shipping | The stack was run on one Docker Desktop machine only; behaviour under load and on a Linux host is not verified | `assurance/deployment-hardening.md` section 5 |
| Runbooks, backup, restore, rollback | Start, status, stop and the first-run steps are scripted and documented (`scripts/`, `deployment-hardening.md`, README); **no backup, restore or rollback** procedure exists or was demonstrated | No documented way to recover or roll back a deployment; no backup design (database backups are not addressed) | `brief-audit.md` D14 |
| Retention, deletion, erasure | Design text only (`privacy-retention.md`). No purge job, no deletion or erasure code, no `EVIDENCE_PURGED` event | Data is kept indefinitely; no right-to-erasure path | `requirements.md` SR-20 note, `issues-backlog.md` |
| DAST results | A ZAP job exists in CI but runs only if the repository variable `CASEVAULT_ENABLE_DAST` is `true`; `.zap/rules.tsv` has comments only; no ZAP report is stored | No dynamic-scan evidence; if enabled, it can only scan unauthenticated pages | `brief-audit.md` D7 |
| Executed manual browser tests | 57 cases written (`manual-browser-tests.md`); all result cells and the screenshot folder are empty | Browser behaviour (cookies, headers over a real browser, keyboard focus, zoom) is not confirmed by a human | `manual-browser-tests.md` |
| Secure code review document | None | The required review activity has no written evidence | `brief-audit.md` D4 |
| Stored SAST / SCA / secret-scan outputs | Tools run in CI (SpotBugs, CodeQL, Trivy, Gitleaks, CycloneDX); only Trivy findings of 2026-11-10 and the SpotBugs exclusions are interpreted in the repo | Current scan results are not in the repository | `trivy.md`, `static-analysis-exclusions.md` |
| Tagged release | `git tag -l` is empty at the time of the audit (CI listens for `v*` tags) | No release artefact for submission yet | `brief-audit.md` F3 |
| MFA, password change/reset, user creation screen | Not built | Accounts come from first-run bootstrap only | `issues-backlog.md` |
| Production database secret handling | Phase 12A removed the default database password: prod-like fails fast at start-up without one and reads it from `POSTGRES_PASSWORD`, `SPRING_DATASOURCE_PASSWORD` or a secret file `spring.datasource.password` (configtree). There is still no secret manager and no rotation | The password lives in an environment variable or a file on the host | `adr/0009-deployment-configuration.md`, `brief-audit.md` B9 |

## (b) Implemented, with limits

| Item | Limit |
|---|---|
| Antivirus | A deterministic synthetic **stub** (`StubAntivirusScanner`); no real malware scanning (project hard rule: synthetic data only). Validation is by extension allow-list, content type (Apache Tika), executable magic bytes and size |
| Initial accounts in a deployed stack | Opt-in only (`casevault.bootstrap.initial-accounts-enabled=true` plus a credentials file path): the four standard accounts get random passwords written to that one file (owner-only where supported), never printed or logged | There is no password change feature, so those passwords stay until one is built; the file must be deleted after the first login; the accounts are the synthetic standard ones | `adr/0009-deployment-configuration.md`, `InitialAccountsOptInTest` |
| Docker stack operation | `cvr-app` used 58% of its 640 MiB limit in the recorded run (77% in an earlier run); the three volumes `cvr_pgdata`, `cvr_evidence`, `cvr_keys` belong together (evidence cannot be decrypted without the keyset); secret files appear world-readable inside the container on Docker Desktop; initial passwords stay valid until a password-change feature exists | Single node, no backup, no failover; a restart ends all sessions and clears the rate limiter | `assurance/deployment-hardening.md` |
| Client address behind a proxy | Prod-like believes `X-Forwarded-For` only from internal proxy addresses (Tomcat remote IP handling) and takes the right-most address that is not a proxy | Safe only if the proxy OVERWRITES the header and the application port is not published; with a proxy that appends and a client on a private address the left-most entry would be believed. Tested through the real nginx of the Docker stack in Phase 12B (`docs/evidence/deploy/08-rate-limit.txt`): spoofed headers did not help and a client with another source address had its own budget | `adr/0009-deployment-configuration.md`, `ProxyHeadersHttpTest` |
| Sessions and rate limiter | In memory and per node; lost on restart; session registry and limiter state are not shared between nodes |
| Audit log | HMAC-SHA256 chain with a PostgreSQL immutability trigger. Deleting the newest rows (tail truncation) is detectable only by comparing the head with a copy kept elsewhere; the HMAC key is a file next to the application; reads of cases, reports and the audit log are not audited; a business action can commit without its audit row if the append fails |
| Keys | The Tink keyset (evidence encryption) is stored as **cleartext JSON** and the audit HMAC key as a file, both in git-ignored `.local-data/`; owner-only permissions are set on POSIX systems and are best effort on Windows. No key rotation, no key hierarchy, no secret manager. Evidence is encrypted with AES-256-GCM (AEAD) via Tink; case notes, reports and the database itself are not encrypted by the application |
| Uploads | Maximum 10 MB, held in memory while encrypting; single-node local filesystem storage |
| HTTP Basic on `/api` | Enabled; each request records a login audit row (rate limited) |
| Oversize upload status | Answered with HTTP **400** and the heading "Payload Too Large", not 413 (finding F-012, open; pinned by SEC-EV-ERR-001/002) |
| Reports | A report is a free-text plain-text body (DRAFT -> SUBMITTED -> APPROVED, four-eyes). Nothing is compiled from case data; no PII scrubbing or redaction; no export or download; no version history; no return-to-draft step |
| Remediation actions and notes | Actions have a description and status only (no title or target date); CLIENT cannot read notes or actions (open product question) |
| Cookie flags and headers | Verified as response headers with a test client, not in a real browser and not over TLS. The CSP is sent as two headers; there is no nonce (`script-src 'self'`; templates have no inline script or style) |
| Dependencies | Two Spring MVC CVEs are accepted in `.trivyignore` with reason, evidence and review date 2026-12-01; the SBOM is a CI artifact only |
| Test evidence | The suite (total in the README) was run locally; CI results are not stored in the repository; the coverage gate is 70% |
| Local profile and demo data | The `local` profile is for a developer machine (HTTP, in-memory database, demo accounts with random passwords printed once); it must not be used for a shared system |
| "Last active administrator" rule | Reachable only by two administrators disabling each other at the same moment (test SEC-ADMIN-08); not reachable by clicking one step at a time |

## (c) Design decisions

| Decision | Why | Detail |
|---|---|---|
| The auditor/administrator can **never** read case or evidence content (404), and there is no break-glass path | Separation of duties (SR-07): the role sees events, accounts and health, not content. This is stricter than "does not automatically gain access" | `requirements.md` SR-07, `AccessPolicy` |
| 404 for objects the caller cannot see, 403 for forbidden actions on objects the caller can see | Hides existence of foreign objects; accepted as finding F-003 | `adr/0003-tenant-isolation.md` addendum, `findings-log.md` |
| A MANAGER of `ORG_INTERNAL` sees the cases of every tenant; an ANALYST sees only assigned cases; a CLIENT sees only its own organisation | The consultancy staff model of the scenario | `AccessPolicy`, `authorisation-tests.md` |
| Clients see APPROVED reports only; the author of a report cannot approve it | Four-eyes principle (SR-06, FR-12) | `report-tests.md` |
| Synthetic data only; antivirus is a stub | Project hard rule 1 | `AGENTS.md`, SR-19 |
| Demo data exists only in the `local` profile, with random passwords | Lets tenant isolation and two administrators be shown in a browser without fixed secrets | `adr/0008-local-demo-data.md` |
