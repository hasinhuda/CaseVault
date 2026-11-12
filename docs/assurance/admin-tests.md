# Admin Tests (Phase 7B, DRAFT)

Pages: `GET /admin/users`, `GET /admin/users/{id}/disable-confirm`, `POST /admin/users/{id}/disable`, `POST /admin/users/{id}/enable`, `POST /admin/users/{id}/revoke-sessions`, `GET /admin/health`. All are AUDITOR_ADMIN only (FR-14, FR-15, SR-07 in [requirements.md](../requirements.md)).

Session mechanism: Spring Security's `SessionRegistry` (`SessionRegistryImpl`, in memory, per node, lost on restart), enabled with unlimited sessions per user in `SecurityConfig` (the `ProviderManager` setting is untouched). Revoking calls `expireNow()` on the user's registered sessions; the framework's concurrent-session filter then refuses the next request of that session (redirect to `/login?expired=true`, 401 for `/api/**`). Disabling a user also expires the sessions, and the existing `UserStatusEnforcementFilter` independently rejects a disabled user on the next request. No new dependency.

Refusals: a refused action (self-disable, self-revoke, last active admin) changes nothing and is recorded as `ACCESS_DENIED` with the reason code `ADMIN_REFUSED`. A disable of an already disabled account (or enable of an enabled one) is a no-op with a message and writes no event. Actions write `ADMIN_ACCOUNT_DISABLED` (`DISABLED_BY_ADMIN`), `ADMIN_ACCOUNT_ENABLED` (`ENABLED_BY_ADMIN`) and `ADMIN_SESSION_REVOKED` (`SESSIONS_REVOKED`) with the acting admin's UUID and no case id, appended after commit.

Results from `.\mvnw.cmd -B verify`: 242 tests, 0 failures, 0 skipped, SpotBugs BugInstance size 0, JaCoCo checks met. Classes: [AdminHttpTest.java](../../src/test/java/com/casevault/admin/AdminHttpTest.java) (real filter chain, real logins through `/login`), [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java), [ArchitectureTest.java](../../src/test/java/com/casevault/ArchitectureTest.java), [PostgresFlywayMigrationTest.java](../../src/test/java/com/casevault/db/PostgresFlywayMigrationTest.java).

| Attack or property | Test ID | Result |
|---|---|---|
| Health page shows database and storage checks and "Not verified yet" before any verification; no storage path, "jdbc", "H2", "PostgreSQL", exception text, host name or secret words in the page | SEC-ADMIN-01 | PASS |
| Health shows a verification done earlier, never verifies on page load (a row tampered after the verification does not change the page until the next verification) | SEC-ADMIN-02 | PASS |
| CLIENT, ANALYST, MANAGER get 404 on every admin route and POST with no state change and no ADMIN event; the auditor is served | SEC-ADMIN-03, SEC-ADMIN-AUTHZ-01 | PASS |
| Unauthenticated requests behave like `/cases`; every POST without CSRF is 403, also for the admin | SEC-ADMIN-04 | PASS |
| "Users" and "Health" links only for the auditor; forms carry CSRF tokens; skip link; no script | SEC-ADMIN-05 | PASS |
| Self-disable and self-revoke blocked, nothing changed, own session keeps working, two ADMIN_REFUSED rows | SEC-ADMIN-06 | PASS |
| After one admin disabled the other, the disabled admin cannot act (status filter, and the service alone); one active admin remains | SEC-ADMIN-07 | PASS |
| Two admins disabling each other concurrently (8 rounds): exactly one stays active, no 5xx | SEC-ADMIN-08 | PASS |
| Disabled user cannot log in; can again after enable | SEC-ADMIN-09 | PASS |
| Logged-in session of a disabled user is rejected on the next request (browser redirect, API 401); admin session unaffected | SEC-ADMIN-10 | PASS |
| Revoke: two sessions of the user rejected on the next request, account still enabled, new login works | SEC-ADMIN-11 | PASS |
| User list has no password hash, session id, JSESSIONID or case title; admin gets 404 on case pages and API | SEC-ADMIN-12 | PASS |
| Paging cap 50, bad page and size values, sort parameters ignored (username order); unknown, malformed and SQL-looking ids are 404 for confirm, disable, enable, revoke | SEC-ADMIN-13 | PASS |
| One audit row per action with the admin's UUID; no-ops write nothing; no username, password or long session id in rows or logs; `users.status_changed_by/at` set on the target; chain valid | SEC-ADMIN-14 | PASS |
| Admin templates have no th:utext, inline script, style or handler | SEC-ADMIN-15 | PASS |
| Controllers cannot use `DefaultAdminUserService`, `UserRepository` or `SessionRegistry` | SEC-ADMIN-ARCH-01 | PASS |
| Flyway V9 applies on real PostgreSQL after V1-V8 | SEC-DB-001 | PASS |

Not tested (and not claimed): the "last active admin" count branch itself is unreachable sequentially (an acting admin is always one of at least two active admins), so it is proven only through the concurrency test SEC-ADMIN-08 and the actor check of SEC-ADMIN-07; multi-node behaviour (registry and lock are per node); keyboard focus and contrast of the new pages (VERIFY MANUALLY); revoke-sessions leaves no trace on the target account (only the audit row of the actor).

Test housekeeping: `AdminHttpTest` temporarily disables other active admins left in the shared in-memory database and restores them afterwards. Existing tests changed: `PostgresFlywayMigrationTest` now expects 9 migrations and asserts V9 (assertions added, none removed).
