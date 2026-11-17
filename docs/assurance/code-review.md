# Secure code review (Stage A) - DRAFT

A hostile review of `src/main` done by reading the code, not the documentation. Date: 2026-11-13. Reviewer: the AI assistant working with the author (see `docs/ai-declaration.md`; tool/model name: [tool/model to be completed by the author]). Method: read the classes listed below line by line, ask for every entry point "who may call this, what is checked, what happens with a hostile value", and for each suspicion write a test first. Three suspicions were real defects: each got a failing test, a minimal fix and a passing test (section 3). The rest are either fine or recorded as accepted risks (section 2, `known-limitations.md`). Standards identifiers (CWE, OWASP Top 10 2025) are suggestions and marked VERIFY MANUALLY.

## 1. What was checked, area by area

| Area | Classes read | Checked | Result |
|---|---|---|---|
| Authentication and passwords | `CaseVaultAuthenticationProvider`, `PasswordEncoderConfig`, `PasswordPolicyValidator`, `UserRepository`, `User`, `CaseVaultUserPrincipal` | Argon2id parameters (64 MiB, 3 iterations, 1 lane), generic error text, dummy hash for unknown users, disabled and locked paths, atomic counter updates | Fine, except CR-04 (lockout decision uses a stale counter under parallel guesses) |
| Sessions | `SecurityConfig`, `SessionAbsoluteTimeoutFilter`, `UserStatusEnforcementFilter`, `application*.properties` | session id change on login, cookie flags, 15 min idle, 8 h absolute, cap per user, cookie-only tracking, status re-check per request | Fine |
| Authorisation and tenancy | `AccessPolicy`, `DefaultCaseAccessService` (every public method), `DefaultReportService`, `AdminController`, `DefaultAdminUserService`, `AuditController`, `AuditQueryService` | each entry point passes through `getAccessibleCaseEntity`/`visibleCase`/`requireAdmin`; auditor refused first; role checks after visibility (404 before 403) | Fine. Observations CR-07, CR-08 |
| IDOR/BOLA | `CaseApiController`, `CaseWebController`, `ReportWebController`, `openEvidence`, `getEvidenceById`, report `reportOfCase`, remediation action `caseId` check | every id from a URL is combined with a visibility check; evidence, report and action ids are checked against the case in the path | Fine |
| Mass assignment and validation | all `*RequestDto`, `SearchCasesRequestDto`, `GlobalExceptionHandler` | DTOs carry only the fields that may be set; patterns for status, category, severity; sort allow-list; page size cap 50; length limits | Fine |
| Output encoding, templates | `TemplateScannerTest` rules and the templates (read in Phase 9A/9C) | `th:text` only, no inline script or style, view names are constants | Fine (pattern based; see section 5) |
| CSRF | `SecurityConfig` | CSRF is on for every state-changing request; no `ignoringRequestMatchers`; logout is POST | Fine |
| Evidence upload and download | `EvidenceValidator`, `EvidenceStorageService`, `CaseWebController.downloadEvidence` | extension allow-list, double-extension and Unicode tricks, executable magic bytes, Tika content type, 10 MB cap, UUID storage name checked by regex and `normalize().startsWith`, AAD binds case and evidence id, header filename sanitised, `attachment` + `nosniff` + `no-store`; no archive formats are allowed so there is nothing to expand | Fine. Observations CR-05, CR-11 |
| Audit log | `AuditLogService`, `ChainedAuditEventRecorder`, `AuditKeyProvider`, `AuditEventRepository`, `AuditQueryService` | only `AuditLogService` saves events; canonical encoding is length-prefixed; reason codes are a whitelist; constant-time comparison; append under lock in its own transaction; key created owner-only; verification lock | Fine (tail truncation and key next to the app are documented limits) |
| Rate limiter | `RateLimitFilter`, `InMemoryRateLimiter`, `RateLimitProperties`, `RateLimitConfig` | key choice, forwarded-for handling, map growth cap and eviction, which requests are counted | **CR-01, CR-02 (real, fixed)**; growth is bounded (10 000 keys) |
| Admin functions | `DefaultAdminUserService`, `AdminController` | self-disable and self-revoke refused, last-admin rule under an in-process lock plus row locks, acting admin re-checked inside the transaction, id shape check | Fine |
| Error handling and logging | `GlobalExceptionHandler`, `CorrelationErrorAttributes`, `CorrelationIdFilter`, `CorrelationIds`, every `logger.` call (listed by search) | no request bodies, passwords, tokens or file names are logged; client correlation ids are rebuilt from a parsed UUID (no log injection); `server.error.*=never` | Fine. Our own exception texts reach 4xx pages (known) |
| Configuration | `application*.properties`, `DataBootstrapService`, `ProdLikeConfigurationCheck`, `RateLimitConfig` | demo data only in `local`; prod-like needs the explicit opt-in and a credentials file path; no default database password; forwarded-for flag cannot be combined with the native strategy | Fine. CR-06, CR-10; **CR-03 (real, fixed)** in `management.endpoint.health.show-details` |
| HTTP Basic on `/api` | `SecurityConfig`, `RateLimitFilter` | Basic is still enabled; lockout and Argon2 apply; **limiter covered only `/api/**`** | **CR-02 (real, fixed)** |
| Cryptography | `PasswordEncoderConfig`, `EvidenceStorageService`, `AuditLogService`, `AuditKeyProvider`, `DataBootstrapService` | libraries only (Spring Security Argon2 with BouncyCastle, Tink AES-256-GCM, JDK HmacSHA256 and SHA-256, `SecureRandom`); constant-time `MessageDigest.isEqual`; no home-made primitive | Fine. CR-05 (key file permissions order) |
| Concurrency | `AuditLogService.append`, `DefaultReportService` (`@Version`), `DefaultAdminUserService` locks, case status updates | audit append serialised, report approval has optimistic locking, admin rules serialised; **case status and notes have no version column** | CR-12 |
| Resource exhaustion | `listCases`, upload path, rate-limiter map, Argon2 | uploads capped at 10 MB (multipart) and held in memory; search page size capped; limiter map capped; `/api/cases` returns every case without paging | CR-07 |

Reviewed with no issue found: tenant filter in `searchCases` (no path to another organisation, `cb.disjunction()` for unknown roles), LIKE escaping, evidence storage path handling, the four-eyes check, status transition table (server side, not trusting the UI), correlation id handling, session registry equality (`CaseVaultUserPrincipal.equals`), `UserStatusEnforcementFilter` for disabled users, bootstrap password generation (`SecureRandom`, policy check, no fixed value), `ProdLikeConfigurationCheck`, HSTS only behind the profile flag.

Not read in depth in this review (so no claim): JPA entity classes other than `Case`, `Report` and `User` fields mentioned, the response DTOs (only searched for password hash use: none are serialised), the Thymeleaf templates themselves (covered by the scanner tests and the Phase 9 reviews), `LoggingAuditEventRecorder`, `StubAntivirusScanner`.

## 2. Findings (12, by risk)

CWE and OWASP entries are suggestions: VERIFY MANUALLY.

| CR-ID | File:line | Description | Attack scenario (input -> impact) | CWE / OWASP Top 10 2025 | Severity and reason | Status |
|---|---|---|---|---|---|---|
| CR-01 | `ratelimit/RateLimitFilter.java:67` (before the fix) | The limiter compared the raw request URI with `"/login"`. The container and Spring route a percent-encoded spelling (`/%6Cogin`) to the same login handler. | `POST /%6Cogin` with a guessed password, any number of times: 6 of 6 attempts were processed as logins and never limited (`[302,302,302,302,302,302]`). Credential stuffing across many accounts is not throttled per address; only the per-account lockout (5) remains. The same raw-path comparison covered search, upload and report limits. | CWE-307 (VERIFY MANUALLY) / Authentication failures (VERIFY MANUALLY) | **Medium**: defeats a documented control (SR-04 abuse limit) with one character; needs no privilege. Lockout per account and Argon2 cost remain. | **Fixed**, F-019, test CR-01 |
| CR-02 | `ratelimit/RateLimitFilter.java:70` (before) | The "Basic header" limiter only applied below `/api/`. HTTP Basic is accepted on every URL. | `GET /dashboard` with `Authorization: Basic ...` and a different password each time: 6 of 6 answered 401, none limited. Password spraying across usernames at full speed (also CPU load: Argon2, 64 MiB each). | CWE-307, CWE-770 (VERIFY MANUALLY) / Authentication failures (VERIFY MANUALLY) | **Medium**: same effect as CR-01 through a second door. | **Fixed**, F-020, test CR-02 |
| CR-03 | `application.properties:6` (before) | `management.endpoint.health.show-details=when-authorized`: with no roles configured every signed-in user counts as authorised. | A CLIENT calls `GET /actuator/health`: the response included `components.db.details.database="H2"` (PostgreSQL in production), the validation query and `diskSpace` total and free bytes. | CWE-200 (VERIFY MANUALLY) / Security misconfiguration (VERIFY MANUALLY) | **Low-Medium**: information disclosure to any account, helps fingerprinting and timing attacks; no data. | **Fixed**, F-021, test CR-03 |
| CR-04 | `security/CaseVaultAuthenticationProvider.java:78-96` | The lock decision uses `user.getFailedLoginAttempts() + 1` read before the check; the counter update itself is atomic. Parallel wrong guesses all read the old value, are all verified, and only then increment. | 50 parallel guesses against one account from many addresses: all 50 are compared with the real password before the lock is set (a lock appears on the next request). The per-address limiter (10/min) does not stop a distributed attacker. | CWE-362/CWE-367 (VERIFY MANUALLY) / Authentication failures (VERIFY MANUALLY) | **Low-Medium**: bounded by the number of parallel requests the server accepts, Argon2 cost and the limiter; lockout still triggers. A strict fix (increment first, then verify) changes the provider flow and many existing assertions. | **Accepted risk** (reasoning in `known-limitations.md`); proposed fix: reserve an attempt with one atomic UPDATE before verifying |
| CR-05 | `service/EvidenceStorageService.java:99-101` | The Tink keyset file is written first and restricted to owner-only afterwards (the audit key file is created owner-only from the start). Failure to restrict is silently ignored. | On a shared POSIX host another local user could read the keyset in the instant between write and chmod, and always on a platform without POSIX permissions. In the Docker stack the directory is 0700 and owned by the application user. | CWE-732 (VERIFY MANUALLY) / Security misconfiguration (VERIFY MANUALLY) | **Low**: needs local access to the host; directory permissions protect it in the shipped stack. A test could only run on POSIX systems (a skipped test would break the zero-skip rule). | **Accepted risk** |
| CR-06 | `bootstrap/DataBootstrapService.java` (`saveCredentialsToLocalFile`) | The local-profile credentials file is written with default permissions (the Phase 12A opt-in file is owner-only). | Another user on the same developer machine reads `.local-data/bootstrap-credentials.txt` (synthetic accounts of the local profile only). | CWE-732 (VERIFY MANUALLY) | **Low**: local profile, synthetic data. | **Accepted risk** |
| CR-07 | `service/DefaultCaseAccessService.java:130-169` | `listCases` returns every visible case without paging; an ORG_INTERNAL manager triggers `findAll()`. | `GET /api/cases` as the internal manager with a very large table loads all rows into memory. | CWE-770 (VERIFY MANUALLY) | **Low**: needs a large data set and an authorised manager; synthetic data. | **Accepted risk** |
| CR-08 | `service/DefaultCaseAccessService.java:325-420` | Notes and remediation actions can still be added or changed on a CLOSED case (evidence and reports cannot). | An analyst adds a note after closure; the case history is changed after sign-off (every change is audited). | CWE-841 (VERIFY MANUALLY) | **Low**: policy gap, not an access-control bypass; audited. | **Accepted risk** (product decision) |
| CR-09 | `model/Case.java`, `CaseNote.java`, `Evidence.java`, `RemediationAction.java` | Entities keep defensive copies of related `User` objects including the password hash. | A future accidental serialisation or log of an entity would expose Argon2 hashes. Today only DTOs are serialised and no log statement prints an entity (checked by searching all `logger.` calls). | CWE-200 (VERIFY MANUALLY) | **Low**: defence in depth. | **Accepted risk** |
| CR-10 | `bootstrap/DataBootstrapService.java:run` | If both profiles `local` and `prod-like` are active and the opt-in flag is true, the `local` branch runs (demo data, credentials printed). | A misconfigured deployment starts with `local,prod-like` and the flag: demo accounts exist. | CWE-1188 (VERIFY MANUALLY) / Security misconfiguration | **Low**: needs two deliberate wrong settings; the shipped compose file sets only `prod-like`. | **Accepted risk** |
| CR-11 | `service/DefaultCaseAccessService.java:476-487` | The encrypted file is written before the database row; cleanup only runs if the save throws inside the method, not if the commit fails later. | A commit failure leaves an orphaned ciphertext file (no plaintext, not referenced). | CWE-459 (VERIFY MANUALLY) | **Low**: storage hygiene only. | **Accepted risk** |
| CR-12 | `model/Case.java` | No version column on `Case` (`Report` has one): two concurrent status transitions or a transition racing with an upload are last-writer-wins. | A manager closes a case while an analyst moves it to review: one of the two changes wins; both were individually valid. | CWE-362 (VERIFY MANUALLY) | **Low**: no invalid state is reachable (each change is validated against the state it read); audited. | **Accepted risk** |

## 3. Fixes (failing test first)

Tests are in `src/test/java/com/casevault/review/`. Each was run before the fix and failed with the output below, then passed after the fix. Command: `.\mvnw.cmd -B test "-Dtest=RateLimitBypassHttpTest,ActuatorHealthDetailsTest"`.

| Test ID | Before the fix (red) | After the fix (green) |
|---|---|---|
| CR-01 `encodedLoginPathIsStillRateLimited` (`RateLimitBypassHttpTest`, real HTTP, login limit 3) | `statuses [302, 302, 302, 302, 302, 302] ==> expected: <429> but was: <302>` | attempts 1-3 are 302 (processed), attempt 4 and 6 are 429 |
| CR-02 `basicHeaderOutsideApiIsRateLimited` (same class) | `statuses [401, 401, 401, 401, 401, 401] ==> expected: <429> but was: <401>` | attempt 4 and 6 are 429 |
| CR-03 `signedInUserSeesNoHealthDetails` (`ActuatorHealthDetailsTest`) | `expected: <{"status":"UP"}> but was: <{"status":"UP","components":{"db":{"status":"UP","details":{"database":"H2","validationQuery":"isValid()"}},"diskSpace":{"status":"UP","details":{"total":...,"free":...` | body is exactly `{"status":"UP"}` |

Related existing tests re-run and green after the change: `RateLimitHttpTest` (11), `RateLimitForwardedForTest`, `RateLimitDisabledTest`, `RateLimitPageLinksTest`, `HealthEndpointTest`, `ProxyHeadersHttpTest`. The full suite was run afterwards (section 6).

Before and after:

```java
// CR-01 and CR-02, RateLimitFilter.doFilterInternal
// before
String path = request.getRequestURI().substring(request.getContextPath().length());
...
} else if (path.startsWith("/api/") && isBasicAuthorization(request)) {

// after: the decoded, normalised path the application really routes; Basic is an attempt on any URL
String path = requestPath(request);   // servletPath + pathInfo, falls back to the URI only if both are empty
...
} else if (isBasicAuthorization(request)) {
```

```properties
# CR-03, application.properties
# before
management.endpoint.health.show-details=when-authorized
# after
management.endpoint.health.show-details=never
```

Findings log entries: F-019, F-020, F-021. Accepted risks CR-04..CR-12 are listed in `known-limitations.md` (section b).

## 4. What this review cannot find

- Anything in code that was not read (list in section 1), and logic errors in code that looks correct line by line: the review is one reader, not a proof.
- Problems that appear only at run time or in combination with infrastructure (nginx, Docker, database privileges, real browsers): see `deployment-hardening.md`, `dast.md` and the unexecuted `manual-browser-tests.md`.
- Vulnerabilities in third-party libraries (see the tool documents), and weaknesses of the Java, Tomcat or PostgreSQL versions in use beyond what Trivy reported.
- Business-logic questions that need the product owner (who may read notes, should closed cases be immutable).
- Timing and side channels, memory-safety of the JVM, supply-chain compromise of the build.
- Whether the tests would catch a future regression in every area (coverage is 70% line-based by gate, not a measure of security).
- Race conditions that need many parallel requests (CR-04 was reasoned from the code, not reproduced under load).

## 5. Pattern-based checks to be aware of

`TemplateScannerTest` is regular-expression based and the Thymeleaf output rules are conventions; a future template that bypasses `th:text` would be caught only if it matches one of the listed patterns. The ArchUnit rules protect layering (controllers do not touch repositories or the audit repository) but not every misuse.

## 6. Verification of this stage

Recorded in the stage report and in `docs/evidence-index.md` (Stage A rows): `.\mvnw.cmd -B verify` in default order and with `-Dsurefire.runOrder=reversealphabetical`.
