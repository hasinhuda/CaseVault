# Issues & Technical Debt Backlog

This backlog tracks identified technical debt, deferred security enhancements, and upcoming architectural milestones.

## Phase 2 Authentication & Performance Notes

1. **Argon2id Memory Cost (64 MiB) vs. Constrained JVM Heap (384 MB)**:
   - **Current Configuration**: Argon2id password hashing enforces `memory = 65,536 KiB` (64 MiB) per verification operation (matching OWASP Cryptographic Storage recommendations and Hard Rule 10).
   - **Risk Analysis**: In environments where JVM maximum heap is constrained to 384 MB (e.g. small container instances), concurrent login attempts can place significant pressure on heap memory:
     - 4 concurrent Argon2id computations allocate `4 * 64 MB = 256 MB` off-heap / native memory buffer.
     - Under a burst of simultaneous login requests or automated brute-force attacks, memory pressure could lead to `OutOfMemoryError` or heavy GC pauses if JVM heap + native memory exceeds container cgroup limits.
   - **Mitigation & Architectural Roadmap**:
     - *Immediate*: Account lockout after 5 failures and IP rate limiting at reverse proxy ingress mitigate automated concurrent flood attacks.
     - *Container Sizing*: Production container specifications must provision at least 1 GB RAM (e.g., `-Xmx512m` plus native off-heap buffer margin) to support concurrent legitimate authentications safely.
     - *Alternative/Scale*: If deployed in severely constrained environments (< 512 MB total RAM), parameter tuning to `memory = 32,768 KiB` (32 MiB) with 4 iterations should be evaluated and documented via an ADR amendment.

## Phase 3 Authorisation Technical Debt

2. **Spring Security Deprecated AntPathRequestMatcher in SecurityConfig**:
   - **Current Configuration**: `SecurityConfig` employs `AntPathRequestMatcher.antMatcher("/api/**")` within `DelegatingAuthenticationEntryPoint` to route unauthenticated API requests to `HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)`.
   - **Status**: In Spring Security 6.5.x, `AntPathRequestMatcher` is marked `@Deprecated(forRemoval = true)`. The emerging replacement is `PathPatternRequestMatcher` (`org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.withDefaults().matcher("/api/**")`).
   - **Deferred Action**: To avoid regressions or behavioral mismatches during Phase 3 authorisation baseline stabilization, `AntPathRequestMatcher` is intentionally retained. Migration to `PathPatternRequestMatcher` is scheduled for refactoring alongside Spring Boot 3.5.x patch upgrades before Phase 6 production hardening.

## Phase 4 Case Workflow & UI Technical Debt

3. **`remediation_actions` Schema Missing `title` and `target_date` Columns (FR-07)**:
   - **Current State**: FR-07 specifies "title, target date, and completion status" for remediation actions. The V4 migration only has `description`, `status`, and `created_at`. The `title` and `target_date` columns are absent.
   - **Impact**: Minimal for the current workflow phase; `description` serves as a combined title/description field. A future migration should add `title VARCHAR(200)` and `target_date TIMESTAMP NULL` if the full FR-07 specification is required.
   - **Deferred Action**: Add columns via a new Flyway migration (V5 or later) when the full remediation tracking UI is implemented.

4. **CLIENT Read Access to Notes and Remediation Actions (FR-07 Clarification)**:
   - **Current State**: FR-07 states notes and actions are authored by ANALYST and MANAGER. Whether CLIENTs may _read_ notes and actions on their own cases is not explicitly stated. The current implementation blocks CLIENT from reading notes and actions (they can only see the case overview).
   - **Deferred Action**: VERIFY MANUALLY with product owner whether CLIENT should have read-only access to case notes and remediation actions. If yes, update `CaseWebController` to show read-only tabs.
# Evidence backlog (DRAFT)

- Antivirus scanning is a deterministic synthetic-only stub; integrate an approved scanner before production use.
- AES-GCM processing holds evidence in memory and is limited to 10 MB; use streaming encryption for larger files.
- Storage is local single-node filesystem storage; production needs resilient managed storage.
- Retention and deletion workflows are not yet implemented.
- The cryptographic audit chain remains pending for Phase 6; the current recorder logs minimal metadata only.

## Phase 6A audit chain backlog (DRAFT)

- Wire `ChainedAuditEventRecorder` (`casevault.audit.recorder=chained`) into login, cases, evidence and admin flows, decide record ordering relative to business commits, and add the AUDITOR_ADMIN verification view (Phase 6B).
- Move the audit HMAC key out of the database's trust domain (secret manager or HSM); today it is a file beside the application.
- Add an external anchoring job (periodic export of `currentHead()`); otherwise tail truncation is undetectable.
- Create a production database role limited to INSERT and SELECT on `audit_events`; the PostgreSQL trigger can be dropped by the table owner.
- Multi-node deployments: the append lock is in-process; design retry and ordering on unique `sequence_no` violations.
- Windows key-file permissions are best effort: VERIFY MANUALLY.

## Phase 6B audit wiring backlog (DRAFT)

- Login-failure flooding grows `audit_events` without bound until Phase 8 rate limiting; there is no retention or archival for audit rows yet.
- ADMIN_ACCOUNT_DISABLED, ADMIN_SESSION_REVOKED and REPORT_TRANSITION are defined event types but not wired (Phase 7); session revocation in `UserStatusEnforcementFilter` is not audited yet.
- The AUDITOR_ADMIN audit view and chain verification page is Phase 6C.
- A committed action can be unaudited if the append fails after commit (no retry queue or outbox).
- HTTP Basic requests on `/api` record one LOGIN_SUCCESS per request; consider disabling Basic or sampling before production.

## Phase 6C auditor view backlog (DRAFT)

- Viewing the audit list is not audited (only chain verification is); decide whether auditor reads must be recorded.
- The page shows ids only (user id, case id), no usernames, by design; resolving an id to a person needs a separate, audited admin function (Phase 7).
- The last chain verification result is in memory: lost on restart and not shared between nodes. Persist it or recompute on demand.
- There is no export of the head anchor (sequence and HMAC); the page only shows the first 12 hex characters, so tail truncation is still detected only by manual comparison.
- Audit pages need `Cache-Control: no-store` (Phase 8).
- Contrast ratio and keyboard behaviour of the new page were not measured with a tool: VERIFY MANUALLY.
- The auditor dashboard card still contains static text ("Audit Log Integrity: ACTIVE") that is not computed from a verification; replace it with the real status.

## Phase 7A reports backlog (DRAFT)

- No reject or return-to-draft step: a SUBMITTED report can only be approved; a manager cannot send it back.
- No report versioning or history: an edit replaces the body, and the earlier text is lost.
- HTTP endpoints and UI come in 7C, so end-to-end HTTP tests for reports (status codes, CSRF, output escaping of a body such as a script tag) are still missing.
- Client download or export of approved reports is not built.
- Two managers approving the same report at the same moment: no optimistic locking or version column; the second call sees APPROVED and gets 400 only if it runs after the first commit.
- Unicode bidirectional and other invisible formatting characters are accepted in report bodies.
- Report body edits (drafts) are not audited; only create, submit and approve are.
- Approval of a submitted report on a CLOSED case is allowed by assumption; confirm with the product owner.

## Phase 7B admin backlog (DRAFT)

- No admin password reset and no user creation UI.
- Viewing the admin pages (user list, health) is not audited; only the actions are.
- The session registry is in memory and per node: sessions on other nodes are not revoked, and a restart empties it (a disabled user is still stopped by the status filter on the next request).
- The in-process admin lock covers one node; the database row lock on the active admins is the multi-node backstop and is untested on PostgreSQL.
- Revoke-sessions leaves no trace on the target account (the audit row names only the actor); only enable and disable set users.status_changed_*.
- The health page is a minimal set (database, evidence storage writable, last audit verification, head sequence). "Writable" is a permission check and writes nothing.
- A refused admin action is shown as a flash message; there is no rate limit on admin actions (Phase 8).
- Admin pages need Cache-Control no-store (Phase 8), like the audit pages.

## Phase 7C reports backlog (DRAFT)

- Unlimited concurrent sessions per user: a cap such as 3 is a Phase 8 candidate.
- No reject or return-to-draft step for reports.
- No report history or versions: an edit replaces the body (the new version column is a lock counter, not a history).
- No report export or download.
- Viewing reports is not audited (only create, submit and approve).
- The concurrent-approval test runs on H2; the PostgreSQL behaviour of the same versioned update is not tested.
- Concurrent edits or submits of one report are protected by the same lock but have no concurrent test.
- Contrast and keyboard behaviour of the report pages were not measured with a tool: VERIFY MANUALLY.

## Phase 8A rate-limit backlog (DRAFT)

- Rate-limit events are not in the audit chain (deliberate, to avoid audit flooding); only one WARN log line per limiter and window exists.
- Limiter state is per node and in memory, lost on restart; there is no distributed limiter.
- The limits are defaults, not tuned against real traffic.
- No CAPTCHA and no progressive delay after repeated limited attempts.
- Address-based login limiting can affect legitimate users behind one shared NAT; a trusted reverse proxy (Phase 12) and the forwarded-for setting must be reviewed together.
- Fixed-window counting allows up to twice the limit around a window boundary; a token bucket is a possible refinement.
- An attacker rotating more distinct keys than the cap (10000) can reset other keys' counters.
- User-based limits cover authenticated requests only; other unauthenticated URLs are not limited.
- Reading endpoints (report and case detail, downloads) are not limited.


## Phase 8B headers and errors backlog (DRAFT)

- Closed by tests SEC-HDR-01 and SEC-HDR-04: "audit pages need Cache-Control no-store" (Phase 6C) and "admin pages need Cache-Control no-store" (Phase 7B). The old rows stay as history.
- DECISION F-003: forbidden actions on a visible case return 403 while SR-02 says 404; keep and reword SR-02, or switch the routes to 404 and rewrite the pinned Phase 3/4 tests.
- The case list, the new-case form and case creation by AUDITOR_ADMIN are 404 without an ACCESS_DENIED audit event (no object is targeted); decide whether they should be audited.
- The CSP is sent as two headers to keep the original value unchanged; merge them when TEST-BASE-002 may be updated. Check the CSP in a real browser console: VERIFY MANUALLY.
- Referrer-Policy stays strict-origin-when-cross-origin (SR-09 text); no-referrer is possible and stricter.
- Permissions-Policy denies only camera, microphone and geolocation; extend it (payment, usb, sensors) when its assertion may be updated.
- Static CSS is served no-store; add a cache lifetime with a content hash in the file name if load time matters.
- HSTS needs TLS; verify it behind the reverse proxy in Phase 12, and consider preload only after that.
- A real oversize upload over HTTP is not tested; the container may drop the connection.
- The 429 page and the 500 page after a failed audit append use their own id instead of the request id (header, page and log line agree with each other).


## Phase 8C session, log and scanner backlog (DRAFT)

- Addressed by Phase 8C (new line; the Phase 2 line above stays as history): "Unlimited concurrent sessions per user" is now capped by `casevault.session.max-per-user` (default 3, oldest session expires), tests SEC-SESSION-01..06. The registry is in memory and per node; a cluster needs a shared registry.
- Decision F-003 accepted (policy clarified): 404 for invisible objects, 403 for forbidden actions on visible ones. The Phase 8B backlog line "DECISION F-003" is closed by this line.
- The two Content-Security-Policy headers were NOT merged: `RateLimitHttpTest` pins the exact original value and only `TEST-BASE-002` may be changed. Merge them when that assertion may be updated, then update `HealthEndpointTest`, `RateLimitHttpTest`, `HeaderAuditTest` and `HstsProfileTest` together.
- Log hygiene was proven for the listed flows and marker strings only; a periodic review of new log statements is still needed (ArchUnit has no rule against logging request parameters).
- Cookie flags were checked as headers on a local server, not in a real browser and not over TLS: VERIFY MANUALLY with the browser steps in the phase report, and again behind the Phase 12 reverse proxy.
- Session cap is per user and counts registered sessions; consider an idle-session sweep if users hit the cap because of forgotten browser tabs.
