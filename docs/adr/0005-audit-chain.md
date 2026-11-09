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
