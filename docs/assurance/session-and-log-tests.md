# Session cookie, session cap, log hygiene and template scanner (Phase 8C, DRAFT)

Requirement ids used: SR-05 (session lifecycle and cookie flags), SR-15 (safe errors, correlation id), SR-08 and SR-09 (output encoding, CSP; scanner). The requirements file has no separate logging requirement; the log rules come from hard rule 7 of `AGENTS.md` ("logs never contain passwords, tokens or file contents"). Test results are from the final `.\mvnw.cmd -B verify` of this phase (see the phase report for counts).

## 1. Session cookie (SEC-COOKIE-01..05)

Tested over REAL HTTP against the embedded server, once with the `local` profile and once with the `prod-like` profile (its PostgreSQL datasource replaced by H2, cookie properties unchanged). The cookies are handled by hand so the raw `Set-Cookie` header is inspected. Classes: [AbstractSessionCookieHttpTest.java](../../src/test/java/com/casevault/web/AbstractSessionCookieHttpTest.java), [SessionCookieLocalHttpTest.java](../../src/test/java/com/casevault/web/SessionCookieLocalHttpTest.java), [SessionCookieProdLikeHttpTest.java](../../src/test/java/com/casevault/web/SessionCookieProdLikeHttpTest.java).

| Attribute | `local` (http) | `prod-like` | Test |
|---|---|---|---|
| Name | `JSESSIONID` (only cookie ever set) | same | SEC-COOKIE-03 |
| HttpOnly | present | present | SEC-COOKIE-01 |
| SameSite | `Strict` | `Strict` | SEC-COOKIE-01 |
| Secure | absent on purpose (a browser would not send it over http) | present | SEC-COOKIE-01 |
| Path | `/` | `/` | SEC-COOKIE-01 |
| Max-Age / Expires / Domain | absent (session cookie, host only) | absent | SEC-COOKIE-01 |
| Remember-me cookie | none | none | SEC-COOKIE-03 |
| Id changes on login | yes; the pre-login id gives no access | yes | SEC-COOKIE-02 |
| Logout | server session invalid, cookie cleared (empty value, Max-Age=0), old id gives no access | same | SEC-COOKIE-04 |
| Id in URL, `Location` or body | never | never | SEC-COOKIE-05 |

No configuration change was needed: the prod-like flags were already correct, so there is no finding for the cookie flags. Note that the default `application.properties` has `Secure=true`; only the `local` profile switches it off.

## 2. Concurrent session cap (SEC-SESSION-01..06)

`casevault.session.max-per-user` (default 3) feeds `maximumSessions` in [SecurityConfig.java](../../src/main/java/com/casevault/config/SecurityConfig.java). When a user logs in beyond the cap, the OLDEST session is expired; the new login always succeeds. The expired session is redirected to `/login?expired=true` (HTTP 401 for `/api/**`). Classes: [SessionCapTest.java](../../src/test/java/com/casevault/auth/SessionCapTest.java), [SessionCapConfiguredTest.java](../../src/test/java/com/casevault/auth/SessionCapConfiguredTest.java) (cap set to 1 by a test property).

| Test | Property proven |
|---|---|
| SEC-SESSION-01 | default 3; the 4th login expires the 1st, sessions 2, 3, 4 keep working |
| SEC-SESSION-02 | expired session: 401 on `/api/**`, redirect to `/login?expired=true` on pages |
| SEC-SESSION-03 | other users are not affected |
| SEC-SESSION-04 | admin revoke-sessions still ends all sessions of a user, the user can log in again |
| SEC-SESSION-05 | disabling an account still ends its session |
| SEC-SESSION-06 | the value comes from the property (cap 1: the 2nd login expires the 1st) |

Finding F-007: the first run of these tests showed the cap doing nothing, because `CaseVaultUserPrincipal` had no `equals`/`hashCode` and the session registry keys sessions by principal. Fixed in the principal class. No existing test class needed a higher cap: with the default of 3 the whole existing suite stayed green without any change (checked by a full test run before the new tests were added).

## 3. Log hygiene (SEC-LOG-01..03)

[LogHygieneHttpTest.java](../../src/test/java/com/casevault/web/LogHygieneHttpTest.java): a Logback appender on the root logger captures everything written at the configured levels while real HTTP flows run (embedded server, real logins, CSRF tokens, session cookies).

| Flow | What was checked in the captured log | Result |
|---|---|---|
| Login success; wrong password (known user); unknown user; lockout after repeated failures; logout | no password (right or wrong), no user name (marker string), no session id, no CSRF token | PASS (SEC-LOG-01) |
| API call with HTTP Basic (good and bad credentials) | no `Authorization` value, neither the base64 text nor the decoded password | PASS |
| Case create (form); audit append failure on case create | the flow runs (the failing append gives the safe 500 page); the markers above stay out of the log. Case titles are not asserted. | PASS |
| Evidence upload (valid), upload rejected (wrong type), download | no file name, no file content | PASS |
| Report create, submit, approve | no report body text | PASS |
| Admin revoke, disable, enable | no user name, no session id | PASS |
| Rate limit 429, 404, 405, 500 | no request-derived text, no SQL | PASS |
| Whole capture | no `$argon2` / `argon2id` text, no audit HMAC key (text, base64, hex), no Tink keyset values, no SQL keywords (`select `, `insert into`, `update users`, `delete from`, `from users`, `values (`) | PASS |
| Injection: CR/LF plus fake log text in a login form field, in file names (encoded, escaped and with a real line feed) and in request headers (`X-Correlation-ID`, and a raw socket request with a real line break in a header) | the marker text never reaches the log at all, so no forged line exists; no message of the application or Spring contains a line break | PASS (SEC-LOG-02) |
| Configuration | root level not DEBUG/TRACE (effective level INFO or higher for Hibernate SQL, bind and JDBC loggers), `spring.jpa.show-sql` not true, no `logging.level.*` set to DEBUG/TRACE/ALL, no SQL or bind logger entry in `application.properties`, `application-prod-like.properties` or `application-local.properties` | PASS (SEC-LOG-03) |

Not asserted on purpose: the text of an unexpected exception (the test-only 500 and the injected audit failure) appears in the server log together with its stack trace. That is useful for diagnosis and never reaches the user (SEC-ERR-05, SEC-AUDIT-WIRE-12). Tomcat writes its own fixed two-line message when it rejects a malformed header; the line-break check therefore skips the `org.apache.coyote`, `org.apache.tomcat` and `org.apache.catalina` loggers (the injected marker is still asserted absent from them).

## 4. Template scanner (SEC-TPL-01..03)

[TemplateScannerTest.java](../../src/test/java/com/casevault/web/TemplateScannerTest.java) ADDS to the older scanners; none was relaxed. Rules (whole-file patterns, so multi-line tags are covered): `th:utext`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function`, `localStorage`, `sessionStorage`, inline event handlers (also `th:on*`), `javascript:` URLs, `<script>` without `src`, `th:inline="javascript"`, `style=` / `th:style=` attributes, `<style>` blocks, and external resources (`src`, `href`, `action`, `data`, CSS `url(...)` and `@import` with `http://`, `https://` or `//`). SEC-TPL-01 scans every `.html`, `.css`, `.js` and `.svg` file in `src/main/resources/templates` and `static`; SEC-TPL-02 proves every rule fires on an in-memory sample; SEC-TPL-03 proves variants (upper case, multi-line, prefixed) are caught and a clean sample is not flagged.

## 5. Other 8C changes

- Deprecated matcher: `AntPathRequestMatcher` in `SecurityConfig` was replaced by `PathPatternRequestMatcher` (class verified in the Spring Security 6.5.11 jar before use). It was the only use in the code; `RateLimitFilter` uses plain string checks. The whole suite stayed green with no assertion change.
- Decision F-003: kept the as-built policy (404 for objects the caller cannot see, 403 for forbidden actions on visible objects). SR-02 got an appended clarifying bullet and ADR 0003 an addendum.
- Merging the two CSP headers (optional step 7) was NOT done: see the phase report. `RateLimitHttpTest` pins the exact original CSP value (SEC-RATE-WEB), and only `TEST-BASE-002` may be changed, so a merge cannot be done without rewriting that assertion.

## Attack to test to result

| Attack or property | Test ID | Result |
|---|---|---|
| Script reads the session cookie (XSS) | SEC-COOKIE-01 (HttpOnly) | PASS |
| Cross-site request carries the session cookie | SEC-COOKIE-01 (SameSite=Strict) | PASS |
| Cookie sent over plain http on the production profile | SEC-COOKIE-01 (Secure on prod-like) | PASS (header only; a real TLS connection is not tested) |
| Session fixation | SEC-COOKIE-02, SEC-AUTH-06 | PASS |
| Stolen session reused after logout | SEC-COOKIE-04 | PASS |
| Session id leaked in URL, redirect or page | SEC-COOKIE-05 | PASS |
| Persistent login cookie | SEC-COOKIE-03 | PASS |
| One account used by an unbounded number of sessions | SEC-SESSION-01..03, 06 | PASS |
| Secrets in logs | SEC-LOG-01 | PASS |
| Log forging with CR/LF | SEC-LOG-02 | PASS |
| Verbose logging or SQL logging in production configuration | SEC-LOG-03 | PASS |
| Inline script, inline style, DOM-injection API, CDN resource added to a template | SEC-TPL-01..03 | PASS |

## Honest limits

- MockMvc and the JDK HTTP client are not a real browser: cookie behaviour in Chrome, Firefox or Edge is VERIFY MANUALLY (see the browser steps in the phase report).
- The `Secure` flag is verified as a header; browsers only honour it over https (TLS arrives with the Phase 12 reverse proxy).
- The session registry is in memory and per node: the cap is per application instance and is lost on restart. A cluster would need a shared registry.
- The cap counts sessions the registry knows. Sessions end through the container's session events or expiry; a session that is only idle still counts until it times out (15 minutes idle, 8 hours absolute).
- The log capture covers the flows listed above at the configured levels. It does not prove that no other flow, or a DEBUG level switched on by an operator, logs a secret. The marker approach proves absence of the marker values used in the test only.
- The scanner is pattern based: it can miss obfuscated code and can flag harmless text. It guards against accidental regressions, not against a determined developer.

## Session id never in a URL (F-010, added after Phase 9B)

| Test ID | What it proves (real HTTP, no cookie jar for signed-out requests) |
|---|---|
| SEC-SESSURL-01 | `GET /login` with no cookie: no `;jsessionid` in body or Location; plain form action and stylesheet link |
| SEC-SESSURL-02 | Signed-out CSRF 403 page: no `;jsessionid` anywhere; exact `/login` and `/css/app.css` links |
| SEC-SESSURL-03 | Redirect of a signed-out request to a protected page goes to the plain `/login` |
| SEC-SESSURL-04 | Successful login redirects to the plain `/dashboard`; cookie still HttpOnly and SameSite=Strict; signed-in page works with plain links |

Setting: `server.servlet.session.tracking-modes=cookie`. Limit: a real browser check is VERIFY MANUALLY.
