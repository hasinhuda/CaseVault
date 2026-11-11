# Audit chain tests (Phase 6A, DRAFT)

Scope: backend only. The audit log is built and tested as a service; it is NOT yet wired into login, cases, evidence or admin flows (Phase 6B). Requirement ids: FR-13, SR-13, SR-14 (see [requirements.md](../requirements.md)). Results come from `.\mvnw.cmd -B verify`: 180 tests, 0 failures, 0 skipped, SpotBugs BugInstance size 0.

| Attack / property | Test ID | Test class | Result |
|---|---|---|---|
| Five appended events verify; genesis link and sequence 1..5 | SEC-AUDIT-01 | [AuditChainTest.java](../../src/test/java/com/casevault/audit/AuditChainTest.java) | PASS |
| Paged verification, empty chain, invalid page size | SEC-AUDIT-02 | AuditChainTest | PASS |
| Row field edited (reason_code) | SEC-AUDIT-03 | AuditChainTest | PASS (exact sequence reported, HMAC_MISMATCH) |
| prev_hash edited | SEC-AUDIT-04 | AuditChainTest | PASS (LINK_MISMATCH) |
| Middle row deleted | SEC-AUDIT-05 | AuditChainTest | PASS (SEQUENCE_GAP at the missing number) |
| Two rows swap sequence numbers | SEC-AUDIT-06 | AuditChainTest | PASS (detected at first swapped position) |
| Row forged without the key | SEC-AUDIT-07 | AuditChainTest | PASS (HMAC_MISMATCH) |
| Tail truncation and truncate-then-append | SEC-AUDIT-08 | AuditChainTest | PASS, with a documented limitation: `verifyChain()` alone does NOT detect it; only an externally kept `currentHead()` copy does |
| Verification with a different key | SEC-AUDIT-09 | AuditChainTest | PASS (invalid at sequence 1) |
| Reason whitelist, no extra columns, null event type rejected | SEC-AUDIT-10 | AuditChainTest | PASS |
| Millisecond precision and verification after DB round trip (H2) | SEC-AUDIT-11 | AuditChainTest | PASS |
| Recorder keeps only well-formed UUIDs | SEC-AUDIT-12 | AuditChainTest | PASS |
| Recorder is fail-closed | SEC-AUDIT-13 | AuditChainTest | PASS |
| Key created lazily, reused, owner-only on POSIX, invalid key rejected | SEC-AUDIT-14 | AuditChainTest | PASS (the permission assertion only runs where POSIX exists; on Windows VERIFY MANUALLY) |
| 8 threads x 25 appends: sequence 1..200, no gap or duplicate, valid chain, repeated 10 times | SEC-AUDIT-15 | [AuditConcurrencyTest.java](../../src/test/java/com/casevault/audit/AuditConcurrencyTest.java) | PASS x10 |
| Millisecond round trip and verification on real PostgreSQL | SEC-AUDIT-16 | [PostgresAuditChainTest.java](../../src/test/java/com/casevault/db/PostgresAuditChainTest.java) | PASS |
| PostgreSQL trigger rejects UPDATE, DELETE, TRUNCATE | SEC-AUDIT-17 | PostgresAuditChainTest | PASS |
| Only `AuditLogService` touches the audit repository | SEC-AUDIT-ARCH-01 | [ArchitectureTest.java](../../src/test/java/com/casevault/ArchitectureTest.java) | PASS |
| Controllers cannot touch the audit repository | SEC-AUDIT-ARCH-02 | ArchitectureTest | PASS |
| Audit repository declares no delete or update method | SEC-AUDIT-ARCH-03 | ArchitectureTest | PASS |
| Audit repository is not a `CrudRepository` | SEC-AUDIT-ARCH-04 | ArchitectureTest | PASS |
| Audit entity has no setters | SEC-AUDIT-ARCH-05 | ArchitectureTest | PASS |

Not covered: key and database in different trust domains, multi-node appends, an external anchoring job, a database role limited to INSERT and SELECT, and wiring into application flows (Phase 6B).

## Phase 6B wiring tests (H2, real Spring context)

Results from `.\mvnw.cmd -B verify`: 195 tests, 0 failures, 0 skipped, SpotBugs BugInstance size 0. Class: [AuditWiringTest.java](../../src/test/java/com/casevault/audit/AuditWiringTest.java).

| Property | Test ID | Result |
|---|---|---|
| Successful login: exactly one LOGIN_SUCCESS with the user's UUID | SEC-AUDIT-WIRE-01 | PASS |
| Wrong password, existing user: LOGIN_FAILURE with that UUID | SEC-AUDIT-WIRE-02 | PASS |
| Unknown username: LOGIN_FAILURE with null user_id | SEC-AUDIT-WIRE-03 | PASS |
| Five failures: five LOGIN_FAILURE plus one ACCOUNT_LOCKED; correct password while locked is LOGIN_FAILURE (also proves the double-invocation fix) | SEC-AUDIT-WIRE-04 | PASS |
| Logout writes LOGOUT; logout without a session writes nothing | SEC-AUDIT-WIRE-05 | PASS |
| No typed username, password or (distinctive) session id in audit columns or captured log lines | SEC-AUDIT-WIRE-06 | PASS (rotated session id checked only when 16+ characters, because Spring's mock sessions use short counter ids) |
| Cross-tenant case request: HTTP 404 and exactly one ACCESS_DENIED NOT_VISIBLE; nonexistent id and unauthenticated request write no row | SEC-AUDIT-WIRE-07 | PASS |
| HTTP 403 AccessDeniedException: exactly one ACCESS_DENIED NOT_PERMITTED | SEC-AUDIT-WIRE-08 | PASS |
| Case create, assign, status change (and no event for an unchanged status) and note: one row each with the actor | SEC-AUDIT-WIRE-09 | PASS |
| Evidence upload, rejected upload, download, tampered file, missing file: one row each | SEC-AUDIT-WIRE-10 | PASS |
| Mixed scenario: chain valid, sequence 1..5 without gap, no file name, hash or stored name in rows, only allowed columns | SEC-AUDIT-WIRE-11 | PASS |
| Append failure after commit: case stays committed, HTTP 500 safe error (JSON and HTML) with correlation id, ERROR log with the same id and no exception or message. Proves only the case-creation path; the same recorder code serves all outcome events | SEC-AUDIT-WIRE-12 | PASS |
| Outcome events appended only after commit and dropped on rollback; attempt events survive rollback | SEC-AUDIT-WIRE-13 | PASS |
| Chained recorder is the default bean | SEC-AUDIT-WIRE-14 | PASS |
| Controllers, security and config use the recorder interface only | SEC-AUDIT-ARCH-06 | PASS |

Not wired and therefore not tested: ADMIN_ACCOUNT_DISABLED, ADMIN_SESSION_REVOKED, REPORT_TRANSITION (Phase 7). The logging recorder as a selectable alternative is exercised by `EvidenceLogSecurityTest`, which selects it with `@TestPropertySource`.

Existing test changed: `PostgresFlywayMigrationTest` (SEC-DB-001) now expects 7 applied migrations (V6 and the PostgreSQL-only V7 added). No assertion was removed or relaxed.
