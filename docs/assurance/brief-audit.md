# Brief compliance audit (CYS22301, Case Vault) - DRAFT

Read-only, adversarial audit of the repository at commit `4a5c426` (branch `main`, 2026-11-13) against the assessment brief CYS22301 (Case Vault scenario, as summarised in the audit request) and against the project's phase plan. Nothing was fixed or added. A status is **DONE** only where the file, test or workflow was opened and confirmed in this audit; otherwise **PARTIAL**, **NOT DONE** or **UNCONFIRMED**. Test IDs were confirmed to exist in `src/test` by search; for tests I did not re-read line by line I rely on the behaviour documented in the matching `docs/assurance/*.md` file and say so. No secret value is printed here.

Important limits of this audit:
- The manual browser tests (`manual-browser-tests.md`, MAN-01..57) have **not been executed by a human**: every result cell is empty and `docs/evidence/screenshots/` holds only `.gitkeep`. That is reported as a gap, not as evidence.
- I cannot see GitHub (no network): CI run results, repository variables (for example `CASEVAULT_ENABLE_DAST`), branch protection and whether the repository is public are **UNCONFIRMED**.
- Risk column = risk to the marking rubric if the gap stays (HIGH / MED / LOW).

## Verification commands run in this audit

| Command | Result |
|---|---|
| `.\mvnw.cmd -B verify` | `Tests run: 354, Failures: 0, Errors: 0, Skipped: 0`; `BugInstance size is 0`; `BUILD SUCCESS` (JaCoCo, Enforcer, ArchUnit inside verify green) |
| `git tag -l` | empty: **no tags** |
| `git log --oneline \| wc -l` | 49 commits, 1 author, branch `main`, remote `origin` = `https://github.com/hasinhuda/CaseVault.git` |
| `git ls-files \| grep -c -E "secrets/\|\.env$\|\.pem\|\.key$\|keyset\|admin_initial_password\|\.local-data"` | 0 matches |
| `git ls-files \| grep -c -E "^target/\|\.class$\|\.jar$"` | 1 (`.mvn/wrapper/maven-wrapper.jar`, the standard Maven wrapper; no build output tracked) |
| `git ls-files` (total) | 236 tracked files |
| Link check over 35 markdown files (throw-away Node script outside the repo) | 339 relative links, **0 broken**; 1 text hit for an absolute-path pattern: `AGENTS.md:31`, which only quotes the rule (`C:\Users\...` as an example) |
| Test-ID check: every token in the "Automated Test / Gate" column of `docs/evidence-index.md` (147 rows) searched in `src/test` | 81 distinct IDs, **0 missing** (for ranges such as `SEC-X-01..05` only the first ID was searched) |
| `Get-ChildItem`/`git ls-files` search for compose, nginx, runbook, SBOM, lock file, code-review, rollback, restore, DAST report, viva, outline, exported diagram | **no match** (the only hits were unrelated Java file names) |
| No Docker command was run by me. `verify` itself starts Testcontainers PostgreSQL as part of the Postgres tests; I did not touch any other container. | - |

---

## Section A - Minimum functional requirements

| ID | Brief requirement | Status | Evidence (confirmed) | Gap | Risk |
|---|---|---|---|---|---|
| A1 | Authenticate securely and terminate sessions | DONE | `CaseVaultAuthenticationProvider` (Argon2id via `PasswordEncoderConfig`: 64 MiB, 3 iterations, parallelism 1; lockout after 5 failures for 15 min; generic message; dummy-hash timing equalisation), `SecurityConfig` (form login, POST `/logout`, session id change on login, 15 min idle, concurrent-session cap 3), `SessionAbsoluteTimeoutFilter` (8 h). Tests: `Argon2idSecurityTest`, `AuthenticationLockoutSecurityTest`, `SessionLifecycleSecurityTest`, SEC-COOKIE-01..05, SEC-SESSION-01..06, SEC-SESSURL-01..04, SEC-AUTH-06/12..15 | No MFA, no password change or reset screen (`issues-backlog.md`); cookie `Secure` verified as a header only, not over TLS and not in a browser (manual tests not executed) | LOW |
| A2 | Create and view incident cases | DONE | `CaseWebController` (`/cases`, `/cases/new`, `/cases/{id}`), `CaseApiController`; SEC-CASE-01..13 (`CaseWorkflowSecurityTest`, `CaseSearchAndUiSecurityTest`) | Only CLIENT can create cases (by design); no edit-case screen | LOW |
| A3 | Assign category, severity, status and owner | DONE | Create form sets category and severity; status finite-state machine in `DefaultCaseAccessService.isValidTransition`; assignment `designateAnalyst`; owner = reporting client, assigned analyst separate. SEC-CASE-01/02/03/06 | "Owner" has two meanings (reporter and assigned analyst); no assignment history | LOW |
| A4 | Add investigation notes and remediation actions | DONE | `appendCaseNote`, `createRemediationAction`, `transitionRemediationActionStatus`; SEC-CASE-04/05 | FR-07 also asks for action title and target date: not built (`issues-backlog.md` item 3); CLIENT cannot read notes (open question, item 4); notes/actions views are not audited | LOW |
| A5 | Upload and retrieve authorised, non-malicious evidence files | PARTIAL | `EvidenceValidator` (10 MB, extension allow-list, double-extension and Unicode tricks, executable magic bytes, Apache Tika content check, UUID stored name), `EvidenceStorageService` (Tink AES-256-GCM), authorised download with `nosniff`, `attachment`, `no-store`. SEC-EV-VAL-002..010, SEC-EVID-HARDEN-01..03, SEC-EVID-WEB-01..08, SEC-EVID-AUTHZ-01..08, SEC-EVID-DL-01..05 | "Non-malicious" rests on `StubAntivirusScanner`, a documented synthetic stub (hard rule 1), so no real malware scanning; whole file held in memory; single-node local filesystem | MED |
| A6 | Search or filter cases without exposing unauthorised records | DONE | `searchCases` tenant-scoped; LIKE wildcard escaping, page cap 50, sort allow-list; rate limit 60/min. SEC-CASE-07..10, SEC-RATE-WEB-08 | Title search plus filters only (no search in notes) | LOW |
| A7 | Generate a sanitised case summary or remediation report | PARTIAL | `DefaultReportService`, `ReportWebController`, plain-text body, DRAFT -> SUBMITTED -> APPROVED, four-eyes, client sees APPROVED only, output via `th:text`. SEC-REPORT-01..10, SEC-REPORT-WEB-01..13 | Report is a free-text box: nothing is **generated or compiled** from case data (FR-11 asks for a compilation of notes, exhibits and timeline); no PII scrubbing, credential masking or redaction although `privacy-retention.md` section 4 describes them; no export or download; no versioning (`issues-backlog.md` 7A/7C). "Sanitised" currently means HTML-escaped output only | MED |
| A8 | Record security-relevant events in a protected audit log | DONE | `AuditLogService` (HMAC-SHA256 chain, append lock, ms truncation), `ChainedAuditEventRecorder`, PostgreSQL immutability trigger (`db/migration-postgresql/V7`), auditor view with verification. SEC-AUDIT-01..17, SEC-AUDIT-WIRE-01..14, SEC-AUDIT-UI-01..15, `PostgresAuditChainTest` | Tail truncation is detectable only by comparing the head manually; HMAC key is a file next to the app; case/report/audit **reads** are not audited; a business action can commit without its audit row if the append fails (`issues-backlog.md` 6A-6C) | LOW |
| A9 | Administrator function to disable accounts or revoke access | DONE | `AdminController`, `DefaultAdminUserService` (disable, enable, revoke sessions, self-protection, last-admin rule), `UserStatusEnforcementFilter`. SEC-ADMIN-01..15 | No user creation or password reset UI; the "last active administrator" refusal is unreachable one step at a time (only the concurrency test SEC-ADMIN-08 reaches it); whether an admin can clear a lockout early is UNCONFIRMED (not opened) | LOW |
| A10 | Four roles: client, analyst, case manager, auditor/administrator | DONE | `Role` enum CLIENT, ANALYST, MANAGER, AUDITOR_ADMIN; `AccessPolicy.canReadCase` per role (client = own organisation, analyst = assigned cases only, manager = all in ORG_INTERNAL else own organisation); `SEC-AUTHZ-01..11`, `AuthorisationOperationMatrixTest` | Manager of ORG_INTERNAL sees every tenant by design (insider-risk note in C11) | LOW |
| A11 | Auditor/administrator reviews security events, account activity and system health WITHOUT automatically gaining access to evidence content | DONE | `AccessPolicy.canReadCase` returns false for AUDITOR_ADMIN before any organisation check; services answer 404 and audit `ACCESS_DENIED/NOT_VISIBLE`; `/cases` and `/cases/new` throw not-found for the auditor; audit page shows ids only; user list has no hashes or case data; health page has no paths or versions. SEC-CASE-11, SEC-EVID-AUTHZ-04, SEC-EVID-WEB-03, SEC-REPORT-WEB-02, SEC-AUDIT-UI-02/06, SEC-ADMIN-01/12, SEC-HDR-404-01/02, DEMO-LOCAL-02 | Stricter than the brief: there is **no** break-glass or approval path for the auditor to read content at all (a design choice to state in the report). The auditor still sees user ids, usernames, roles and case ids | LOW |

## Section B - Security requirements

| ID | Requirement | Status | Evidence | Gap | Risk |
|---|---|---|---|---|---|
| B1 | Secure authentication, password handling, session management | DONE | See A1; `PasswordPolicyValidator`, SEC-AUTH-13 (cookie flags), `HstsProfileTest` | No MFA or reset flow; no breached-password check | LOW |
| B2 | Role-based and tenant-aware authorisation | DONE | `AccessPolicy`, service-layer checks, `@PreAuthorize("isAuthenticated()")` plus role checks inside services, ArchUnit SEC-AUTHZ-ARCH-01/02, SEC-ADMIN-ARCH-01, SEC-AUDIT-ARCH-01..07 | Rules live in services, not in annotations, so each new endpoint relies on discipline (mitigated by tests) | LOW |
| B3 | IDOR / BOLA protection | DONE | Uniform 404 masking and `ACCESS_DENIED` audit: SEC-AUTHZ-*, SEC-EVID-AUTHZ-05, SEC-REPORT-WEB-04, SEC-ADMIN-13, SEC-CASE-06 (mass assignment), SEC-EVID-WEB-04 | Browser-level confirmation (MAN-20, MAN-22) not executed | LOW |
| B4 | Server-side validation and safe output encoding | DONE | Bean-validation DTOs, `ReportRequestDto` rules, `th:text` only; `TemplateScannerTest` SEC-TPL-01..03, SEC-CASE-13, SEC-EVID-UI-04, UI-A11Y-STRUCT | The scanner is pattern based (documented) | LOW |
| B5 | Injection, XSS, CSRF | DONE | JPA parameters and LIKE escaping (SEC-CASE-07/08, SEC-AUDIT-UI-09); escaped output (SEC-CASE-12, SEC-REPORT-WEB tests); CSRF tokens on every POST (SEC-AUTH-12, SEC-EVID-WEB-01, SEC-ADMIN-04); CSP `script-src 'self'` | HTTP Basic is still enabled on `/api/**` (one LOGIN_SUCCESS audit row per request, rate limited) | LOW |
| B6 | Secure file upload validation, storage, retrieval | PARTIAL | See A5 | AV stub; 10 MB in memory; oversize answered 400 "Payload Too Large" (finding F-012, open) | MED |
| B7a | Protection of sensitive data **in transit** | NOT DONE | HSTS header exists only behind `casevault.security.hsts-enabled=true` (prod-like), tested as a header (SEC-HDR-03, `HstsProfileTest`) | No TLS configuration anywhere: no `server.ssl.*`, no nginx, no compose, no certificates. `application-prod-like.properties` says "Strict HTTPS" and uses port 8443 but contains no SSL setting, so it would serve plain HTTP. Docker image exposes 8080 over HTTP. `Secure` cookies cannot work over that HTTP. Deferred to "Phase 12" in several docs | HIGH |
| B7b | Protection of sensitive data **at rest** | PARTIAL | Evidence files: Tink AES-256-GCM (`EvidenceStorageService`); passwords Argon2id; audit HMAC | The Tink keyset is stored as **cleartext JSON** (`CleartextKeysetHandle`) beside the data; case notes, reports, titles and the database itself are not encrypted; no key rotation or secret manager; Postgres disk/backups unencrypted unless the platform does it | MED |
| B8 | Safe error handling | DONE | `GlobalExceptionHandler`, `CorrelationErrorAttributes`, `server.error.*=never`; SEC-ERR-01..11, SEC-HDR-404-01..03, F-002/F-006 fixed | Our own exception texts (for example "Illegal status transition ...") are shown on 4xx pages | LOW |
| B9 | Secrets and configuration management | PARTIAL | Keys and bootstrap passwords generated at first run into git-ignored `.local-data/`; 0 secret-pattern matches in tracked files; Gitleaks job in CI; bootstrap off in prod-like (SEC-AUTH-14/15); F-013 | `application-prod-like.properties:10` has a **default database password** `${POSTGRES_PASSWORD:casevault}`; no Gitleaks result or config file in the repo; no secret manager; audit key and Tink keyset are plain files | MED |
| B10 | Dependency and supply-chain security | PARTIAL | Dependabot (maven, actions, docker), Enforcer + dependency convergence, JaCoCo gate, SpotBugs/FindSecBugs gate, Trivy container scan (`--exit-code 1 --ignore-unfixed --severity CRITICAL,HIGH`) in CI, CycloneDX SBOM at `package`, `dependency-review-action` on pull requests, all `uses:` pinned by 40-character SHA, Docker base images pinned by digest, `.trivyignore` with reason/evidence/review date for 2 CVEs (review 2026-12-01) | SBOM exists only as a CI artifact (not committed, not interpreted); Trivy assessment (`trivy.md`) covers only the 2026-11-10 findings; no later scan result is documented; no signing, provenance or attestation; two accepted CVEs remain | MED |
| B11 | Security logging, monitoring, accountable admin activity | PARTIAL | Audit chain records admin actions (SEC-ADMIN-14), login events, evidence events; log hygiene SEC-LOG-01..03, SEC-EVID-LOG-01..05; correlation id in every log line | No monitoring, alerting or log shipping; no review procedure for the audit log; failure recovery not designed | MED |
| B12 | Rate limiting and abuse controls | DONE | `RateLimitFilter` (login 10/min per address, API Basic, search, upload, report writes), lockout 5/15 min; SEC-RATE-01..06, SEC-RATE-WEB-01..14, UI-RATE-01/02 | In-memory and per node; address-based; no distributed or proxy-level limiting (`headers-and-rate-limit.md`) | LOW |
| B13 | Data minimisation, retention, privacy-aware design | NOT DONE | Data minimisation is partly real: audit rows hold ids only; DTOs are narrow; logs carry no content; `privacy-retention.md` states a policy | **No retention or deletion mechanism exists**: a search of `src/main` finds no purge, delete or shredding code; `EVIDENCE_PURGED` is not an `AuditEventType`; SR-20's verification ("scheduled purge job automated tests") has no test; `issues-backlog.md` says "Retention and deletion workflows are not yet implemented"; no account/data erasure although GDPR Art. 17 is cited | HIGH |
| B14 | Secure deployment and platform hardening | PARTIAL | `Dockerfile`: multi-stage, digest-pinned bases, non-root `USER 10001:10001`, apt upgrade, Hadolint and Trivy in CI | No compose, nginx, TLS, read-only root filesystem, capability drop, resource limits or `HEALTHCHECK`; default profile runs H2 in memory; no deployment instructions | HIGH |
| B15 | No custom cryptographic algorithms | DONE | Libraries and places: Spring Security `Argon2PasswordEncoder` with BouncyCastle 1.86 (`PasswordEncoderConfig`); Google Tink `Aead`/AES-256-GCM (`EvidenceStorageService`); JDK `javax.crypto.Mac` HmacSHA256 (`AuditLogService`, key from `AuditKeyProvider`); JDK `MessageDigest` SHA-256 for file hashes and `MessageDigest.isEqual` (`EvidenceValidator`, `AuditLogService`); JDK `SecureRandom` (bootstrap passwords, audit key). No hand-written cipher, hash or random generator found by search | Terminology: documents call the Tink use "envelope encryption"; the code uses one AEAD keyset directly (see H) | LOW |

## Section C - Threat list coverage (11 threats)

`docs/threat-model.md` section 6 has one analysis per threat (headings 1-11) and `docs/misuse-cases.md` has MUC-01..MUC-11 in the same order.

| ID | Threat | In threat-model / misuse cases | Control (confirmed) | Test(s) | Status | Gap | Risk |
|---|---|---|---|---|---|---|---|
| C1 | Cross-organisation access | yes / MUC-01 | `AccessPolicy`, tenant-scoped queries, 404 masking | SEC-AUTHZ-*, SEC-CASE-10, SEC-EVID-WEB-04, SEC-REPORT-WEB-AUTHZ-01, DEMO-LOCAL-02 | DONE | Manual cross-tenant check (MAN-22) not executed | LOW |
| C2 | Privilege escalation from a low-privilege account | yes / MUC-02 | role checks in services, `@PreAuthorize` | `AuthorisationOperationMatrixTest`, SEC-CASE-02/03, SEC-ADMIN-03, SEC-AUDIT-UI-02, SEC-EVID-WEB-03 | DONE | - | LOW |
| C3 | Manipulation of case identifiers / API requests | yes / MUC-03 | ownership checks on every id, mass-assignment ignored | SEC-EVID-AUTHZ-05/07, SEC-REPORT-WEB-04/08, SEC-ADMIN-13, SEC-CASE-06 | DONE | - | LOW |
| C4 | Injection into notes, searches, reports | yes / MUC-04 | `th:text`, JPA, LIKE escaping, CSP | SEC-CASE-07/08/12/13, SEC-REPORT-WEB tests, SEC-AUDIT-UI-09, SEC-TPL-01..03 | DONE | - | LOW |
| C5 | Disguised / unauthorised upload | yes / MUC-05 | validator, Tika, magic bytes, encrypted storage, `attachment` | SEC-EV-VAL-002..010, SEC-EVID-HARDEN-01..03, SEC-EVID-WEB-06 | PARTIAL | No real malware scanning (stub) | MED |
| C6 | Credential, token, secret exposure | yes / MUC-06 | git-ignored `.local-data`, bootstrap local-only, log hygiene | SEC-AUTH-14/15, SEC-LOG-01..03, DEMO-LOCAL-04 | PARTIAL | No automated test that the repository holds no secret (only Gitleaks in CI, result unseen); cleartext Tink keyset on disk; default DB password in prod-like config | MED |
| C7 | Vulnerable third-party dependencies | yes / MUC-07 | Trivy gate, Dependabot, dependency-review, SBOM, pinned SHAs | none in `src/test`; CI only (`trivy.md` documents the 2026-11-10 fixes) | PARTIAL | No test and no current scan result in the repo; CI result unseen | MED |
| C8 | Tampering / deletion / excess access to audit records | yes / MUC-08 | HMAC chain, append-only repository (ArchUnit), PostgreSQL trigger, auditor-only view | SEC-AUDIT-01..17, SEC-AUDIT-ARCH-01..07, SEC-AUDIT-UI-11/12, `PostgresAuditChainTest` | DONE | Tail truncation and key-next-to-app are documented residual risks; trigger can be dropped by the table owner | LOW |
| C9 | Leakage through logs, exceptions, backups, deployment configuration | yes / MUC-09 | safe errors, log hygiene, encrypted evidence files | SEC-ERR-01..11, SEC-LOG-01..03, SEC-EVID-LOG-01..05 | PARTIAL | **Backups: no backup design, no encrypted-backup control, no test**; the "backups contain only ciphertext" argument covers evidence files only, not the database; deployment configuration has a default DB password | MED |
| C10 | Automated login, enumeration, resource exhaustion | yes / MUC-10 | lockout, generic error, timing equalisation, rate limits, 10 MB cap | `AuthenticationLockoutSecurityTest`, SEC-RATE-*, SEC-RATE-WEB-*, SEC-ERR tests | PARTIAL | Argon2 memory pressure under concurrency is a documented risk (`issues-backlog.md` item 1); limiter is per node; no edge/proxy limits | MED |
| C11 | Authorised insider misuse | yes / MUC-11 | four-eyes in the service, auditor content ban, audited admin actions | SEC-REPORT-WEB-05, SEC-ADMIN-12/14, SEC-AUDIT-UI-06 | DONE | Auditor/manager reads are not audited; ORG_INTERNAL managers see all tenants by design | LOW |

Threats with no control or no test: none lacks a control; **no automated test** exists for C7 (supply chain) and the C6 "no secret in git" claim; C9's backup leg has **neither control nor test**.

## Section D - Required assurance activities

"Interpreted" = a document explains what the result means, not only raw tool output.

| ID | Activity | Status | Evidence | Interpreted? | Gap | Risk |
|---|---|---|---|---|---|---|
| D1 | Security requirements and misuse/abuse cases | DONE | `docs/requirements.md` (15 FR, 20 SR, counts match headings), `docs/misuse-cases.md` (MUC-01..11) | yes | some verification methods name tests/jobs that do not exist (confirmed for SR-20 purge job and SR-06 `SelfApprovalException`; the other SRs were not all re-checked) | MED |
| D2 | Architecture / data-flow diagram **with trust boundaries** | PARTIAL | `docs/architecture.md` (Mermaid with Perimeter/Application/Storage zones), `docs/data-flow.md` (5 Mermaid blocks, Trust Boundary 1-3), `docs/threat-model.md` (TB-1..TB-4 in ASCII plus Mermaid attack paths). Diagrams are Mermaid source inside Markdown; no exported image file exists | yes | Diagrams show a TLS gateway/reverse proxy and a read-only container that are **not built**; no as-built versus target-state labelling | MED |
| D3 | Risk-based threat model | PARTIAL | `docs/threat-model.md`: assets, actors, STRIDE per boundary, 11 scenarios, controls matrix P1-P3 | yes | No likelihood/impact or risk rating anywhere (search finds none); prioritisation is by label only | MED |
| D4 | Secure code review | NOT DONE | No `docs/assurance/code-review.md` or review log; only tool-based checks and the author's own findings | no | The brief's required review activity has no evidence | HIGH |
| D5 | Automated functional and security tests | DONE | `354 tests, 0 failures, 0 skipped`; JaCoCo gate (70% bundle), ArchUnit rules, Postgres Testcontainers tests, real-HTTP tests | yes (`docs/assurance/*.md`) | CI result and Linux order-independence only validated locally in reverse order (F-008); coverage gate is 70% | LOW |
| D6 | SAST | PARTIAL | SpotBugs + FindSecBugs in `verify` (`BugInstance size is 0`), exclusions justified in `static-analysis-exclusions.md`; CodeQL job in CI (`codeql-sast`) | partly (exclusions only) | No CodeQL result or interpretation in the repo; one FindSecBugs warning was fixed in Phase 9E, not recorded as a finding | MED |
| D7 | DAST | PARTIAL | Job `dast-zap` in `ci.yml`, runs only if repository variable `CASEVAULT_ENABLE_DAST == 'true'` (value UNCONFIRMED); `.zap/rules.tsv` contains comments only | no | **No DAST result exists** in the repo or docs; the job starts the default-profile container with no accounts known, so it can only scan unauthenticated pages (login, error) | HIGH |
| D8 | Software composition / dependency analysis | PARTIAL | Trivy in CI + `docs/assurance/trivy.md` (18 findings, 16 fixed by upgrades, 2 accepted), Dependabot, dependency-review, SBOM generation | yes (Trivy only) | Trivy document is dated 2026-11-10 and names `app/app.jar` while CI scans the image `casevault:latest`; SBOM not retained or interpreted; no later scan documented | MED |
| D9 | Secrets scanning | PARTIAL | Gitleaks job (`gitleaks/gitleaks-action`) in CI; local pattern check (0 matches) | no | No result, no configuration/allow-list file, run unseen -> result UNCONFIRMED | MED |
| D10 | Manual testing of authentication, authorisation, input handling | PARTIAL | `docs/assurance/manual-browser-tests.md` (57 cases MAN-01..57) | no | **Not executed**: all Result, Screenshot and notes cells are empty; screenshot folder empty | HIGH |
| D11 | Remediation and retesting of significant findings | DONE | `findings-log.md` F-001..F-013: every row has a Fix and a Retest entry (checked: none empty). F-001 double provider run, F-002 500 on unknown URL, F-004/F-005 auditor 404 and audit, F-006 echoed class names, F-007 session cap dead, F-008 CI order dependence, F-009 false HEALTHY, F-010 jsessionid, F-011 accessibility, F-013 credentials-dir: fixed with named tests. Trivy fixes: commit `9cecc9b` and `trivy.md` | yes | F-012 (400 vs 413) open by decision; F-003 is a documented decision; F-010's original row still reads "NOT fixed" with the fix recorded only in a later line (see H) | LOW |
| D12 | Secure build and deployment workflow | PARTIAL | `ci.yml`: runs on every branch push, PR, tags `v*`, weekly schedule and manual dispatch; `permissions: contents: read`; pinned action SHAs; verify, CodeQL, SBOM, Gitleaks, Hadolint, Trivy | yes (headers in file) | No deploy or release job, no image publishing, no signing/provenance, **no tag exists** so the `v*` trigger was never used | MED |
| D13a | Platform hardening: Dockerfile | PARTIAL | `Dockerfile` opened: digest-pinned bases, multi-stage, apt upgrade, non-root | yes (`trivy.md`, hadolint comment) | No `HEALTHCHECK`; image runs the default profile (H2 in memory, session cookie `Secure` over plain HTTP) | MED |
| D13b | docker-compose | NOT DONE | file does not exist | - | no multi-service deployment (app + PostgreSQL + proxy) | HIGH |
| D13c | nginx reverse proxy | NOT DONE | file does not exist | - | referenced as "Phase 12" in docs | HIGH |
| D13d | TLS | NOT DONE | no certificate, no `server.ssl.*`, no proxy config | - | see B7a | HIGH |
| D13e | Read-only root filesystem | NOT DONE | no compose/Kubernetes runtime setting; `threat-model.md:85` claims it | - | unsupported claim | MED |
| D13f | Dropped capabilities / no-new-privileges | NOT DONE | no runtime configuration exists | - | - | MED |
| D13g | Non-root container user | DONE | `Dockerfile`: `USER 10001:10001`, `useradd -s /bin/false` | yes | verified in the file only; not verified in a running container | LOW |
| D14a | Logging | DONE | correlation id in every log line; log hygiene tests | yes | - | LOW |
| D14b | Monitoring / alerting | NOT DONE | only `/actuator/health` and the Health page | - | no alerting, no log review process | MED |
| D14c | Runbooks | NOT DONE | no runbook file | - | - | HIGH |
| D14d | Backup and restore (documented AND demonstrated) | NOT DONE | none | - | no backup procedure, no restore demonstration | HIGH |
| D14e | Rollback (documented AND demonstrated) | NOT DONE | none | - | the word appears in no deployment document | HIGH |

## Section E - Brief acceptance criteria

| ID | Criterion | Status | Evidence / gap |
|---|---|---|---|
| E1 | Principal workflow reliable | DONE | Automated end-to-end tests of the workflow pass (`354 tests, 0 failures, 0 skipped`); not exercised by a human in a browser (MAN cases empty); CI result unseen |
| E2 | Ordinary users cannot access other organisations, cases or admin functions | DONE | A2/A10/B2/B3 tests; admin routes 404 for non-auditors (SEC-ADMIN-03); manual confirmation missing |
| E3 | Consistent server-side controls | DONE | Service-layer authorisation, ArchUnit boundaries, status-code decision F-003 documented |
| E4 | Traceable remediation of significant vulnerabilities | DONE | F-001..F-013 with fix and retest, Trivy fixes in `trivy.md`; no deliberate-vulnerability remediation demo (Phase 14) |
| E5 | Documented, reproducible build/deploy instructions | PARTIAL | README documents `verify` and the `local` run command; Docker build/run, PostgreSQL setup, TLS and deployment are not documented |
| E6 | No exposed secrets and no known critical dependency vulnerabilities (SBOM/CI/Trivy documented) | UNCONFIRMED | 0 secret-pattern matches and no tracked key files; but no current Trivy/Gitleaks/SBOM result is stored in the repo and the CI run is unseen; two accepted CVEs documented |
| E7 | Useful logs without credentials | DONE | SEC-LOG-01..03, SEC-EVID-LOG-01..05, DEMO-LOCAL-04 |
| E8 | Honest remaining weaknesses and residual risk | PARTIAL | `issues-backlog.md` and `headers-and-rate-limit.md` are candid, but there is no single consolidated limitations section and several documents overclaim (section H) |
| E9 | Demonstrable and defensible in a viva | PARTIAL | Strong test and finding trail; but no tag, no executed manual evidence, no deployment to demonstrate, no viva notes |

## Section F - Submission checklist

| ID | Item | Status | Evidence / gap | Risk |
|---|---|---|---|---|
| F1 | Report (or outline) | NOT DONE | No outline or draft in the repo (`AGENTS.md` forbids writing the final report; an outline is still absent) | MED |
| F2 | Repository URL / archive | DONE | `origin` = `https://github.com/hasinhuda/CaseVault.git`; visibility UNCONFIRMED | LOW |
| F3 | **Tagged release** | NOT DONE | `git tag -l` is empty; CI listens to `v*` tags but none was created | HIGH |
| F4 | Source and configuration | DONE | 236 tracked files; configs under `src/main/resources` | LOW |
| F5 | Threat model | DONE | `docs/threat-model.md` | LOW |
| F6 | Architecture / data-flow diagrams | PARTIAL | Mermaid source only (D2) | MED |
| F7 | Dependency and build manifests (pom, lock/SBOM) | PARTIAL | `pom.xml`, wrapper; Maven has no lock file; SBOM only as CI artifact | MED |
| F8 | Tests | DONE | `src/test`, 8+ packages | LOW |
| F9 | SAST / DAST / SCA / secrets evidence | PARTIAL | SpotBugs and Trivy documented; CodeQL, Gitleaks, SBOM, DAST: no stored result | HIGH |
| F10 | Remediation and retest evidence | DONE | `findings-log.md` | LOW |
| F11 | CI/CD configuration | DONE | `.github/workflows/ci.yml`, `dependabot.yml` | LOW |
| F12 | Deployment / hardening / runbook | NOT DONE | Only the Dockerfile exists | HIGH |
| F13 | Presentation materials | NOT DONE | none in the repo | MED |
| F14 | Evidence index linking claims to commit, issues, tool outputs, test IDs | PARTIAL | `docs/evidence-index.md`: 147 rows, 339 links over all docs with **0 broken**, 81 cited test IDs **all exist** in `src/test`. But it contains **no commit hashes, issue links or CI-run/tool-output links** (search finds none); CI column only says `CI build-test-coverage` | MED |
| F15 | Licence and third-party / provenance declaration | PARTIAL | `LICENSE` is a placeholder ("CaseVault License Placeholder ... All rights reserved"); no NOTICE/third-party file (SBOM would be the source) | MED |
| F16 | AI-assistance declaration complete | PARTIAL | `docs/ai-declaration.md` has a table with tool and verification up to Phase 4, then dated one-line entries that omit the tool/model column; several entries say "[DRAFT]" | MED |
| F17 | Issue / decision records | DONE | ADR 0001-0008 (index complete), `issues-backlog.md`, `findings-log.md`; GitHub issues not checked | LOW |
| F18 | Meaningful commit history | DONE | 49 commits, Conventional Commit subjects, merge commits per phase; largest commit 45 files (Phase 4), one "WIP checkpoint" commit (`8b06c89`) | LOW |
| F19 | No absolute paths or `file:///` links in docs | DONE | 0 in links; 1 text hit in `AGENTS.md:31` (quotes the rule) | LOW |
| F20 | No secrets, no `.local-data`, no build artefacts committed | DONE | 0 secret-pattern matches; `.local-data/` exists on disk but is git-ignored; only the standard `maven-wrapper.jar` is tracked | LOW |

## Section G - Phase plan

No phase-plan file exists in the repo (search of `docs/`, `README.md`, `AGENTS.md`, `CONTRIBUTING.md` for "Phase 10"-"Phase 15" finds only forward references to "Phase 12 reverse proxy/TLS"). The plan given in the audit request was used.

| ID | Phase | Status | Evidence | Gap | Risk |
|---|---|---|---|---|---|
| G0-9 | Phases 0-9E (baseline to UI/doc fixes) | DONE | `git log`: phase branches and merge commits 0 to 9E; the 354-test suite | Subject lines only were read for the history | LOW |
| G10 | Phase 10 secure code review | NOT DONE | no review document or log | D4 | HIGH |
| G11 | Phase 11 SAST/SCA/secrets/SBOM/container scan with interpretation per tool | PARTIAL | Tools run in CI (SpotBugs, CodeQL, Trivy, Gitleaks, CycloneDX, Hadolint); interpretation only for Trivy and SpotBugs exclusions | no CodeQL/Gitleaks/SBOM interpretation; no stored results | MED |
| G12 | Phase 12 hardened Docker + nginx TLS + runbooks + demonstrated rollback/restore | NOT DONE | only the Dockerfile (non-root, pinned digests) | compose, nginx, TLS, runbooks, backup/restore, rollback all absent | HIGH |
| G13 | Phase 13 DAST + manual testing | PARTIAL | ZAP job scaffold (gated, no result); manual guide written | nothing executed | HIGH |
| G14 | Phase 14 deliberate-vulnerability remediation demo (optional) | NOT DONE | no evidence branch | optional | LOW |
| G15 | Phase 15 evidence index, runbook, viva notes, report outline | PARTIAL | evidence index exists; runbook, viva notes, outline do not | - | MED |

## Section H - Consistency and honesty checks

### H1 Numbers

| Item | Documents say | Repo shows | Verdict |
|---|---|---|---|
| FR / SR counts | 15 FR, 20 SR, 35 total (`requirements.md`) | 15 `### FR-` and 20 `### SR-` headings, 0 NFR | match |
| ADR numbers | 0001-0008 | 8 files, index lists 8 | match |
| Finding IDs | F-001..F-013 | sequential, plus "F-003 (update)" row | match; two later "update" notes sit below the table (see H3) |
| Test count | `ai-declaration.md` shows 123 -> 319 over time; `evidence-index.md` mentions 319 | current suite `354 tests, 0 failures, 0 skipped` | **mismatch**: no document states the current total; older counts in `docs/assurance/*.md` are historical and labelled with their phase |
| `docs/assurance/README.md` index | lists 2 documents | 13 files in the folder | **stale** |
| MUC / threat count | 11 mandatory threats | 11 `###` sections, MUC-01..11 | match |

### H2 Claims not backed by code (file:line)

| Claim | Where | Reality |
|---|---|---|
| "Mandatory TLS 1.3" | `docs/threat-model.md:76` | no TLS configuration exists |
| "read-only root where possible (SR-18)" | `docs/threat-model.md:85` | no runtime setting; Dockerfile only |
| Reverse proxy / TLS gateway as a component | `docs/architecture.md:17`, `docs/data-flow.md:17`, `docs/threat-model.md:8,47` | not built (target state) |
| "Prod-like profile (Strict HTTPS ...)" on port 8443 | `src/main/resources/application-prod-like.properties:1` | no SSL settings; plain HTTP |
| Google Tink "envelope encryption" | `README.md:16`, `docs/architecture.md:75`, `docs/requirements.md:202-203`, `docs/threat-model.md:52,265`, `docs/data-flow.md:89` | one AEAD keyset used directly; keyset stored in cleartext JSON; no key hierarchy |
| "Content sanitization" | `README.md:19` | output escaping only; no sanitisation or redaction of content |
| Retention schedules, cryptographic shredding, `EVIDENCE_PURGED`, PII scrubbing, scheduled purge job | `docs/privacy-retention.md:16-41`, `docs/requirements.md:251-253` (SR-20) | not implemented (no code, no event type, no test); `issues-backlog.md` admits it |
| SR-06 verification "`SelfApprovalException` ... HTTP 400/422" | `docs/requirements.md:168` | no such exception exists; self-approval is a `BadRequestException` (400), and unreachable through the UI with the bootstrap roles |
| SR-04 verification "uniform HTTP 401" | `docs/requirements.md:156` | failed browser login is a 302 to `/login?error=true` |
| Immediate mitigation "IP rate limiting at reverse proxy ingress" | `docs/issues-backlog.md:13` | now application-level limiter; no proxy |
| Trivy target `app/app.jar` | `docs/assurance/trivy.md:4,11` | CI scans the image `casevault:latest` |
| `AGENTS.md:24` "per-request nonce" | owner's instruction file | code has no nonce (README, SECURITY, architecture, threat model and misuse cases were corrected in Phase 9E; `AGENTS.md` was left for the owner) |

### H3 Findings and known limitations

| Finding | Status | Mentioned as limitation? |
|---|---|---|
| F-001..F-002, F-004..F-009, F-011, F-013 | fixed with test | not needed |
| F-003 | decision accepted (404 invisible, 403 forbidden on visible) | yes: requirements clarification, ADR 0003 addendum, backlog |
| F-010 | fixed (cookie-only session tracking) but its table row still says "NOT fixed"; the fix is described in a later "F-010 update" line placed under the Lessons list | row and update contradict each other for a reader of the table |
| F-012 | open by decision (400 vs 413) | yes: finding row only; not in `issues-backlog.md` |

Open limitations also recorded only in `issues-backlog.md`/assurance docs, not in a single place: audit tail truncation, in-memory sessions/limiter, AV stub, 10 MB in-memory uploads, single-node storage, no retention.

---

## 1. Scorecard

| Section | DONE | PARTIAL | NOT DONE | UNCONFIRMED | Rows |
|---|---|---|---|---|---|
| A Functional requirements | 9 | 2 | 0 | 0 | 11 |
| B Security requirements | 8 | 6 | 2 | 0 | 16 |
| C Threat coverage | 6 | 5 | 0 | 0 | 11 |
| D Assurance activities | 5 | 9 | 10 | 0 | 24 |
| E Acceptance criteria | 5 | 3 | 0 | 1 | 9 |
| F Submission checklist | 10 | 6 | 4 | 0 | 20 |
| G Phase plan | 1 | 3 | 3 | 0 | 7 |
| **Total** | **44** | **34** | **19** | **1** | **98** |

Counts are over the numbered rows of sections A-G (sub-rows such as D13a-g and D14a-e are counted separately). Section H has no status column.

## 2. Top 10 gaps (ranked by risk to the marking rubric)

Rubric weights: requirements/architecture 15%, implementation 20%, assurance 20%, supply chain/DevSecOps/deployment 10%, report 15%, viva 20%.

| Rank | Gap | Rubric areas hit |
|---|---|---|
| 1 | **No manual testing evidence**: 57 manual cases written, none executed; no screenshots (D10, F9, E9) | assurance 20%, viva 20% |
| 2 | **No tagged release** (`git tag -l` empty) (F3) | submission, supply chain 10%, viva |
| 3 | **No transport security or deployment package**: no TLS, nginx, compose, read-only fs, capability drop, `HEALTHCHECK`; prod-like says "Strict HTTPS" without SSL settings (B7a, B14, D13b-f, G12) | implementation 20%, deployment 10%, viva |
| 4 | **No runbook, backup/restore or rollback**, documented or demonstrated (D14c-e, F12) | deployment 10%, assurance, viva |
| 5 | **Retention and deletion not implemented** although specified in `privacy-retention.md` and SR-20; no erasure path (B13) | requirements 15%, implementation 20% |
| 6 | **No secure code review evidence** (D4, G10) | assurance 20% |
| 7 | **DAST has no result and is disabled by default**; scans only unauthenticated pages when enabled (D7) | assurance 20%, DevSecOps 10% |
| 8 | **Documents overclaim** (TLS 1.3, read-only root, "envelope" encryption, content sanitization, SR-06/SR-20 verification methods, `AGENTS.md` nonce) (H2) | report 15%, viva 20% |
| 9 | **SCA/SAST/secrets results not stored or interpreted** (CodeQL, Gitleaks, SBOM; Trivy only to 2026-11-10); evidence index has no commit/CI-run/tool-output links (D6, D8, D9, F14) | assurance 20%, supply chain 10% |
| 10 | **Report feature is thin and presentation/outline missing**: no compiled or sanitised case summary, no export (A7); no report outline, presentation, viva notes (F1, F13); placeholder LICENCE, incomplete AI declaration (F15, F16) | implementation 20%, report 15%, viva 20% |

## 3. Must fix before submission vs can be disclosed as a limitation

**Must fix (or the marking risk is high):**
1. Execute the manual browser tests (at least areas a, b, c, d, e, g, h, j, k), fill results, add screenshots, record defects.
2. Create and push a tagged release (after the above), and make sure CI runs on it.
3. Make the documents match the code: remove or reword the TLS 1.3, read-only root, "envelope", "content sanitization", prod-like "Strict HTTPS", SR-06/SR-04 verification texts and the retention claims, or implement what they promise.
4. Provide at least a minimal deployment package that is honest about its scope: TLS termination (nginx or Tomcat SSL) with a documented certificate approach, compose with PostgreSQL, non-default DB password, runbook, a demonstrated backup/restore and rollback.
5. Add a secure code review document (even a focused, evidenced review of authentication, authorisation, upload and audit code) with findings and retests.
6. Store and interpret the SAST/SCA/secrets/SBOM outputs (CodeQL, Gitleaks, Trivy current run, CycloneDX) and, if DAST is claimed, one executed ZAP run with an authenticated or at least interpreted result; otherwise state clearly that DAST was not performed.
7. Fix the findings-log presentation (F-010 row vs update), refresh `docs/assurance/README.md`, and state the current test total in one place.

**Can be disclosed as limitations (already honestly documented, keep them visible in the report):** antivirus stub (hard rule 1), in-memory sessions/limiter/per-node state, audit tail truncation and file-based keys, 10 MB in-memory uploads and local storage, 400 versus 413 on oversize (F-012), no MFA/password reset/user creation UI, HTTP Basic on `/api`, retention/deletion if it is clearly described as design-only, no deliberate-vulnerability demo (Phase 14, optional), auditor and manager reads not audited.

## 4. Commands run and results

See the table at the top of this document. In addition: file reads of `ci.yml`, `Dockerfile`, `.trivyignore`, `.zap/rules.tsv`, `pom.xml`, the `application*.properties`, `DataBootstrapService`, `AccessPolicy`, `EvidenceValidator`, `DefaultReportService`, `DefaultAdminUserService`, `GlobalExceptionHandler`, `SecurityConfig` and the documents named above. Things I could not do: view GitHub Actions results or repository variables, confirm repository visibility, run the application in a browser, run DAST or any Docker start/stop command.
