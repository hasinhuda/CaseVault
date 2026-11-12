# Headers and Rate Limiting (DRAFT)

This file collects the Phase 8 evidence. Section 1 (Phase 8A, rate limiting) is written; Phase 8B will add the headers and error-page section. Design: [ADR 0007](../adr/0007-rate-limiting.md).

## 1. Rate limiting (Phase 8A)

### Limits
| Endpoint | Key | Default limit | Configuration property |
|---|---|---|---|
| `POST /login` | client address | 10 per 60 s | `casevault.ratelimit.login-limit`, `login-window-seconds` |
| HTTP Basic requests to `/api/**` | client address | 60 per 60 s | `api-basic-limit`, `api-basic-window-seconds` |
| Case search with query parameters (`GET /cases`, `/api/cases`, `/api/cases/search`) | authenticated user id | 60 per 60 s | `search-limit`, `search-window-seconds` |
| Evidence upload (`POST /cases/{id}/evidence`) | authenticated user id | 10 per 60 s | `upload-limit`, `upload-window-seconds` |
| Report writes (create, update, submit, approve) | authenticated user id | 30 per 60 s | `report-write-limit`, `report-write-window-seconds` |
| all | switch | on | `casevault.ratelimit.enabled` |
| all | forwarded address | off | `casevault.ratelimit.trust-forwarded-for` (only behind a known reverse proxy) |
| all | tracked keys | 10000 | `casevault.ratelimit.max-tracked-keys` |

### Attack to test to result
Results from `.\mvnw.cmd -B verify`: 279 tests, 0 failures, 0 skipped, SpotBugs BugInstance size 0, JaCoCo checks met. Classes: [InMemoryRateLimiterTest.java](../../src/test/java/com/casevault/ratelimit/InMemoryRateLimiterTest.java) (unit), [RateLimitHttpTest.java](../../src/test/java/com/casevault/ratelimit/RateLimitHttpTest.java), [RateLimitForwardedForTest.java](../../src/test/java/com/casevault/ratelimit/RateLimitForwardedForTest.java), [RateLimitDisabledTest.java](../../src/test/java/com/casevault/ratelimit/RateLimitDisabledTest.java) (all through the real filter chain, with a mutable clock, no sleeping).

| Attack or property | Test ID | Result |
|---|---|---|
| Credential stuffing at `/login`: the 11th attempt from one address is 429; known and unknown usernames get the same status, headers and page (apart from the correlation id); limited attempts do not raise the failed-login counter; another address is unaffected; after the window it works again | SEC-RATE-WEB-01 | PASS |
| Successful logins count too; legitimate use within the limit is not affected | SEC-RATE-WEB-02 | PASS |
| 429 page: HTML, `Retry-After` 1..60, correlation id, `no-store`, CSP and other headers unchanged, no script, no address, username, password, class name or stack trace | SEC-RATE-WEB-03 | PASS |
| Spoofed `X-Forwarded-For` does not bypass the login limit (flag false) | SEC-RATE-WEB-04 | PASS |
| Flag true: the last forwarded entry is the key (different clients behind one proxy are separate, the same client is limited, client-controlled earlier entries do not change the key); malformed values fall back to the remote address | SEC-RATE-WEB-12, SEC-RATE-WEB-13 | PASS |
| No audit row for limited requests; exactly one WARN line per limiter and window with limiter label and correlation id only | SEC-RATE-WEB-05 | PASS |
| 50 parallel logins with a limit of 10: exactly 10 processed, 40 get 429 | SEC-RATE-WEB-06 | PASS |
| HTTP Basic on `/api`: 429 with fixed text and `Retry-After` after 3 attempts (test configuration); another address unaffected | SEC-RATE-WEB-07 | PASS |
| Search flood per user (HTML and API share the counter); other user and plain lists unaffected; limited request did not run the controller and wrote no audit row | SEC-RATE-WEB-08 | PASS |
| Upload flood per user: the third upload (test limit 2) is 429, no new evidence row, no new file in the evidence directory, no EVIDENCE_UPLOADED row; another user unaffected | SEC-RATE-WEB-09 | PASS |
| Report-write flood per user: create, submit and update after the limit are 429 and change nothing (no new report row, status and body unchanged, no extra audit row); another user unaffected; reading is not limited | SEC-RATE-WEB-10 | PASS |
| Rate-limited template has no th:utext, inline script, style or handler | SEC-RATE-WEB-11 | PASS |
| `enabled=false` switches the limiter off | SEC-RATE-WEB-14 | PASS |
| Window logic and Retry-After, key and limiter independence, degenerate configuration | SEC-RATE-01, SEC-RATE-02, SEC-RATE-06 | PASS |
| Memory bound: rotating 20 times the cap of keys never exceeds the cap (also with 8 parallel threads); expired windows are purged first | SEC-RATE-03, SEC-RATE-04 | PASS |
| 50 parallel attempts with limit 10 admit exactly 10 (20 rounds, unit level) | SEC-RATE-05 | PASS |
| Controllers, services, repositories and models do not depend on the limiter; limiter internals are used only inside the package and by the security configuration | SEC-RATE-ARCH-01, SEC-RATE-ARCH-02 | PASS |

### Existing tests given a higher login limit
`AdminHttpTest`, `AuditWiringTest`, `ReportWebTest` and `SessionLifecycleSecurityTest` perform many real logins from the same address inside one Spring context (the limiter state lives as long as the cached context), so each has `@TestPropertySource(properties = "casevault.ratelimit.login-limit=100000")`. Only the login limit is raised, the limiter stays enabled, and no assertion was changed. All other test classes run with the defaults.

### Honest limits
- In-process, per node, lost on restart. A second node has separate counters; there is no distributed limiter.
- Address based: users behind one shared NAT share the login budget. A spoofing-proof address needs a trusted proxy (Phase 12); the forwarded-for handling assumes exactly one trusted proxy that appends the client address and is only tested, not deployed.
- Fixed window: up to twice the limit can pass around a window boundary.
- An attacker rotating more distinct keys than the cap can reset other keys' counters.
- Rate-limit events are not in the audit chain, only one WARN line per limiter and window.
- Limits are defaults, not tuned; there is no CAPTCHA and no progressive delay.
- User-based limits apply to authenticated requests; unauthenticated floods of other URLs are not limited.
- Not tested: behaviour behind a real reverse proxy; the limits of two nodes together; the contrast and keyboard behaviour of the 429 page (VERIFY MANUALLY).


## 2. Browser security headers, caching and safe errors (Phase 8B)

Results from `.\mvnw.cmd -B verify`: 297 tests, 0 failures, 0 skipped, SpotBugs BugInstance size 0, JaCoCo checks met. Classes: [HeaderAuditTest.java](../../src/test/java/com/casevault/web/HeaderAuditTest.java), [HstsProfileTest.java](../../src/test/java/com/casevault/web/HstsProfileTest.java), [CorrelationIdTest.java](../../src/test/java/com/casevault/web/CorrelationIdTest.java), [ErrorHandlingHttpTest.java](../../src/test/java/com/casevault/web/ErrorHandlingHttpTest.java) (real HTTP to the embedded server), [StatusConsistencyTest.java](../../src/test/java/com/casevault/web/StatusConsistencyTest.java).

### Header audit: before and after
The first run of `HeaderAuditTest` recorded the headers of 16 page types before any change. Missing then: `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, the CSP directives `base-uri`, `form-action`, `script-src`, `style-src`, and `X-Correlation-ID` on every response. Also seen: an unknown URL answered HTTP 500 (finding F-002). Already correct: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cache-Control: no-store` on every dynamic page (Spring Security default).

Headers now, identical on every page type (login, dashboard, case list, case detail, evidence tab, report list, report detail, redirect with state, audit list, admin users, admin health, 404 page, 429 page, evidence download, actuator health, static CSS):

| Header | Value (asserted exactly in SEC-HDR-01) |
|---|---|
| Content-Security-Policy (header 1, unchanged) | `default-src 'self'; frame-ancestors 'none'; object-src 'none'` |
| Content-Security-Policy (header 2, new) | `base-uri 'self'; form-action 'self'; script-src 'self'; style-src 'self'` |
| X-Content-Type-Options | `nosniff` |
| X-Frame-Options | `DENY` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=()` |
| Cross-Origin-Opener-Policy | `same-origin` |
| Cross-Origin-Resource-Policy | `same-origin` |
| Strict-Transport-Security | absent on the local profile (also for a request marked secure); `max-age=31536000 ; includeSubDomains` with the prod-like profile on an https request |
| Cache-Control | `no-cache, no-store, max-age=0, must-revalidate` (Spring Security default) on every page, redirect, error page and the static CSS; `no-store` on the 429 page and the evidence download |
| X-Correlation-ID | a UUID on every response |

Decisions: the CSP is sent as TWO headers. Browsers enforce every CSP header they receive (the result is the intersection, nothing weaker), and the original value stays byte for byte identical, so the existing assertion TEST-BASE-002 and the 8A test still hold unchanged. `script-src` and `style-src` allow only `'self'`; no `'unsafe-inline'` and no `'unsafe-eval'`, so no nonce is needed (the templates contain no inline script or style; the scanners enforce it). `Referrer-Policy` stays `strict-origin-when-cross-origin` as written in SR-09; `no-referrer` would also work in this single-origin application but would deviate from that requirement text. `Permissions-Policy` was not extended because the existing assertion fixes its exact value; it already denies camera, microphone and geolocation. The static CSS is not cached today (Spring Security's no-store applies); that is simple and safe, only slower.

### Safe errors and the correlation id
- `CorrelationIdFilter` runs before the security chain. The client header `X-Correlation-ID` is used only when it is a strictly formed UUID (rebuilt from the parsed value, echoed in canonical lower case); anything else is replaced. The id is in the request, in the logging context (log pattern `[cid=...]`) and in the response header before the application runs.
- Error pages (`error.html`, base layout head, `th:text` only) are rendered for 400, 403, 404, 405, 409, 500 and every other status by the same template, either by `GlobalExceptionHandler` or by the Boot `/error` mechanism (`CorrelationErrorAttributes` adds the id and a fixed text per status). `server.error.include-message/stacktrace/exception/binding-errors` are off, the Whitelabel page is off.
- Two responses use their own fresh id instead of the request id, set consistently in header, page and log line: the 429 page (8A) and the 500 page after a failed audit append (6B), because their ERROR/WARN log line is written before the response exists.

### Attack to test to result
| Attack or property | Test ID | Result |
|---|---|---|
| Missing or weak security headers on any page type, including error, 429, download, static and actuator responses | SEC-HDR-01 | PASS |
| HSTS: absent on the local profile (http and secure-marked requests), present with the prod-like profile on https, absent on plain http | SEC-HDR-03, SEC-HDR-02 | PASS |
| Authenticated pages cached by browsers or proxies: audit, admin, dashboard, login redirect and logout redirect are no-store (closes the backlog item "audit pages need Cache-Control no-store") | SEC-HDR-04, SEC-HDR-01 | PASS |
| Unknown URL, wrong method, missing static file: safe 404/405 pages with the same id in header and page | SEC-ERR-01 | PASS |
| `page=abc`, type mismatch, malformed UUID: safe 400/404 pages without class names or echoed input | SEC-ERR-02 | PASS |
| Malformed multipart body: safe 400 page | SEC-ERR-03 | PASS |
| CSRF failure stays 403 and uses the safe page with a correlation id | SEC-ERR-04 | PASS |
| Unexpected runtime exception: safe 500 page, no exception text, id in header = page = ERROR log context | SEC-ERR-05 | PASS |
| Database exception: safe 500 page without SQL or constraint names | SEC-ERR-06 | PASS |
| Exception while rendering a template: safe 500 page via /error | SEC-ERR-07 | PASS |
| API clients get JSON errors with the correlation id and no stack trace | SEC-ERR-08 | PASS |
| Unauthenticated request for an unknown URL still redirects to the login page | SEC-ERR-09 | PASS |
| Log forging and header injection through X-Correlation-ID (CR/LF, long junk, script text, wrong shapes): replaced by a fresh UUID; a valid UUID is echoed | SEC-ERR-10 | PASS |
| Every response carries a correlation id, one id per request, page = header = log context | SEC-ERR-11 | PASS |
| 404 for objects the caller may not see and 403 for forbidden actions on visible cases, each with exactly one ACCESS_DENIED audit event (as pinned by Phase 3/4 tests); CSRF 403 for every route and role; unauthenticated behaviour unchanged | SEC-HDR-404-01, -02, -03 | PASS |

Every error test in SEC-ERR-01..09 asserts the absence of: "Whitelabel", "Exception", "at com.", "org.springframework", "java.lang", "SQL", SQL keywords, file paths, the secret text thrown by the test-only controller, and the echoed input.

### Honest limits
- Headers are verified through MockMvc and a local embedded server, not in a real browser. CSP behaviour (blocked inline content, console reports) is not verified in a browser console: VERIFY MANUALLY.
- HSTS is only honoured by browsers over https; the header was verified on a request marked secure, not over a real TLS connection (TLS comes with the Phase 12 reverse proxy).
- The error page for an oversized upload is covered by the existing MockMvc test (GlobalExceptionHandlerUploadTest); a real oversize upload over HTTP was not tested because the container may close the connection before answering.
- Two CSP headers are unusual; a later change can merge them when TEST-BASE-002 is updated.
- Finding F-003 (403 for forbidden actions on visible cases versus the wording of SR-02) is a decision, not a fix; see [findings-log.md](findings-log.md).
- The test-only fault controller and the failing template live in `src/test` and are not part of the application.
