# ADR 0005: Cryptographic Audit Trail Chaining & Concurrency Control

## Status
Accepted

## Context
CaseVault manages security incidents, evidentiary records, and chain-of-custody data. Audit records must be immutable, tamper-evident, and verifiable to withstand forensic scrutiny, legal disputes, and insider threats (including rogue administrators or compromised database operators attempting retroactive alteration or deletion).
Per stack constraints and Hard Rule 10, custom cryptographic algorithms are prohibited. The solution must use standard JDK cryptographic primitives, operate reliably under concurrent write loads, and ensure deterministic verification across different environments and database engines.

## Decision
1. **JDK HMAC-SHA256 Chaining**:
   - Every audit record computes an HMAC-SHA256 signature binding:
     - `sequenceNumber`: Monotonically increasing sequential `BIGINT`
     - `previousHash`: The HMAC-SHA256 hash of the immediately preceding audit record (genesis block uses a fixed constant seed: `GENESIS-CASEVAULT-AUDIT-ROOT`)
     - `eventType`: Standardized enum (e.g. `USER_LOGIN_SUCCESS`, `CASE_CREATED`, `EVIDENCE_UPLOADED`, `REPORT_APPROVED`)
     - `actorId`: UUID of the authenticated principal (or `SYSTEM` for background jobs)
     - `tenantId`: Organization UUID (or null for platform-wide events)
     - `payload`: Canonicalized JSON string or delimited string of event attributes
     - `timestamp`: Millisecond-truncated UTC ISO-8601 instant
   - Signature computation uses JDK `javax.crypto.Mac` with algorithm `HmacSHA256`.
2. **Deterministic Millisecond Truncation**:
   - Timestamps must be explicitly truncated to milliseconds (`Instant.now().truncatedTo(ChronoUnit.MILLIS)`) before serializing into the hash input and persisting into the PostgreSQL `TIMESTAMP WITH TIME ZONE` column.
   - This eliminates sub-millisecond precision discrepancies between Java `Instant` (nanoseconds) and database storage engines, guaranteeing that cryptographic re-verification produces identical hashes across all platforms.
3. **Explicit Transaction Append Lock & Concurrency Control**:
   - Concurrent writes to the audit log could cause sequence forks or broken hash pointers.
   - To guarantee monotonic serial execution, the append operation executes inside a dedicated database transaction holding an exclusive lock on the sequence table / audit head row (e.g., `SELECT ... FOR UPDATE` or PostgreSQL advisory lock).
   - The append lock is released only after the transaction commits successfully.
4. **Key Management & Storage**:
   - The HMAC signing key is loaded from `.local-data/audit.key` or `secrets/audit.key` (git-ignored).
   - If not present at startup, a cryptographically secure 256-bit random key is generated using `SecureRandom` and persisted with restricted permissions.
5. **Auditor-Admin Role Boundary**:
   - Users with the `AUDITOR_ADMIN` role can execute the verification routine and view the audit log timeline.
   - `AUDITOR_ADMIN` users have zero access to case or evidence content (queries return HTTP 404).
   - Direct database updates or deletions of audit rows are prohibited by database-level table privileges (append-only table where possible).

## Consequences
- **Positive**:
   - Any historical modification, insertion, or deletion of audit rows immediately invalidates the cryptographic chain from that record forward.
   - Millisecond truncation ensures deterministic re-verification without precision loss across H2, PostgreSQL, and backups.
   - Exclusive append locking prevents race conditions and chain forking during concurrent requests.
   - Adheres strictly to standard JDK HMAC-SHA256 (zero custom crypto).
- **Negative / Trade-offs**:
   - Database serialization lock limits audit write throughput to the rate of sequential database commits (acceptable for incident-response consultancy scale; batching or asynchronous queued writer can be introduced if throughput demands exceed baseline).
   - Loss of the HMAC signing key prevents appending new verifiable entries or verifying existing records with that key.

## Compliance & Standards Mapping
- **OWASP Top 10**:
  - OWASP Top 10:2025 [VERIFY MANUALLY]: A08 (Software and Data Integrity Failures), A09 (Security Logging and Monitoring Failures)
  - OWASP Top 10:2021: A08:2021 (Software and Data Integrity Failures), A09:2021 (Security Logging and Monitoring Failures)
- **CWE**:
  - CWE-353: Missing Support for Integrity Check
  - CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
  - CWE-365: Race Condition in Switch
  - CWE-778: Insufficient Logging
- **ASVS 5.0**:
  - V7 Log and Audit Verification (V7.4.1, V7.4.2 [VERIFY MANUALLY])
  - V8 Data Protection (V8.3.1 [VERIFY MANUALLY])

## Phase 6A Implementation (as built, backend only)
Status: the audit chain is implemented and tested as a service. It is NOT yet wired into login, cases, evidence or admin flows (Phase 6B). By default the application still uses the Phase 5 `LoggingAuditEventRecorder`; `casevault.audit.recorder=chained` selects `ChainedAuditEventRecorder`.

Deviations from the decision text above (the as-built behaviour wins):
- **Lock**: an in-process fair `ReentrantLock` in `AuditLogService`, not `SELECT ... FOR UPDATE` or an advisory lock. The append runs in a `TransactionTemplate` with `PROPAGATION_REQUIRES_NEW`, so the row commits before the lock is released even if the caller already runs inside a transaction. The `UNIQUE (sequence_no)` constraint is the database-level backstop: a second node racing for the same number fails with a constraint violation instead of forking the chain.
- **Key**: `.local-data/keys/audit-hmac.key` (property `casevault.audit.key-path`), 32 random bytes from `SecureRandom`, Base64 text, generated lazily on first use (never at startup). On POSIX it is created with owner read/write only. On Windows permissions are best effort: VERIFY MANUALLY. The key is never logged.
- **Genesis**: the first event uses `prev_hash` = 64 times `0` (hex). The text seed mentioned above is not used.
- **Stored data**: only the columns `id, sequence_no, event_type, user_id, case_id, reason_code, occurred_at, prev_hash, hmac`. There is no free-text payload and no tenant id; `user_id` is a UUID or null. Reason codes come from the whitelist enum `AuditReasonCode`; anything else is stored as `UNSPECIFIED`.

### Canonical serialisation (HMAC input)
Fixed field order, every field self-delimiting, so two different events cannot produce the same byte string. `str(s)` = int32 big-endian UTF-8 byte length followed by the bytes; `opt(s)` = byte `0`, or byte `1` followed by `str(s)`.
1. `str("CVAUDIT1")` format tag
2. int64 big-endian `sequence_no`
3. `str(event_type)`
4. `opt(user_id)` canonical lower-case UUID text
5. `opt(case_id)`
6. `str(reason_code)`
7. int64 big-endian `occurred_at` as epoch milliseconds (`Instant.now().truncatedTo(ChronoUnit.MILLIS)`)
8. `str(prev_hash)`

HMAC = `javax.crypto.Mac` `HmacSHA256` over those bytes, stored as 64 lower-case hex characters. Comparisons use `MessageDigest.isEqual`. Sub-millisecond digits of a stored timestamp are ignored by verification (only epoch milliseconds are signed).

### Verification
`verifyChain()` reads in keyset pages (default 500) and checks, in order: sequence continuity (the missing number is reported as `SEQUENCE_GAP`), the `prev_hash` link (`LINK_MISMATCH`), the recomputed HMAC (`HMAC_MISMATCH`). It returns the first break. It detects changed fields, forged rows (no key), deleted or re-ordered rows inside the chain, and a different key.

### Recorder failure mode: FAIL-CLOSED
`ChainedAuditEventRecorder` lets an append failure propagate to the caller. Reason: an action that cannot be recorded must not silently proceed as if audited. Cost: an audit-store outage becomes an availability problem. Phase 6B must decide the exact ordering; today evidence flows record after their own commit, so a failed append could leave an unaudited, already committed action.

### Residual risks
1. **Key beside the database**: anyone who can read the key file and write the database can recompute a valid chain. Production needs the key in a separate trust domain (secret manager or HSM). Not done.
2. **Single-node lock**: the lock is in-process. Multiple nodes rely on the unique `sequence_no` constraint (fail, not fork); retry behaviour is not designed.
3. **Tail truncation**: deleting the newest rows, or deleting them and appending new events, leaves a chain that `verifyChain()` accepts. It is detectable only by comparing `currentHead()` with an externally stored copy (an anchor). No anchoring job exists yet. Test SEC-AUDIT-08 demonstrates both the limitation and the anchor detection.
4. **DB-level immutability**: implemented for PostgreSQL only, as Flyway migration `db/migration-postgresql/V7__audit_events_immutable.sql`, loaded via `spring.flyway.locations=classpath:db/migration,classpath:db/migration-{vendor}`. A trigger rejects UPDATE, DELETE and TRUNCATE (test SEC-AUDIT-17 on a real PostgreSQL container). H2 (test/dev) has no trigger. The table owner or a superuser can still drop the trigger; in production the application role should additionally lose write rights (`REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM <app_role>`). That role setup is NOT in the repository and is not tested.
5. **Windows key permissions** are best effort only (VERIFY MANUALLY).
