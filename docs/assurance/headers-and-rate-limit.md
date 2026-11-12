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
