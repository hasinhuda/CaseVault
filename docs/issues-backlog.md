# Issues & Technical Debt Backlog

This backlog tracks identified technical debt, deferred security enhancements, and upcoming architectural milestones.

## Phase 0 Baseline Identified Items

1. **Testcontainers PostgreSQL Integration (Phase 1+)**: Baseline Phase 0 runs H2 for unit and health verification. Full Testcontainers PostgreSQL harness to be implemented alongside Flyway baseline migrations in Phase 1.
2. **Coverage Threshold Evolution (Phase 2+)**: JaCoCo overall bundle coverage threshold is set to 70% in baseline; specific package coverage gates (service and security >= 85%) will be introduced as business logic and security components are added.
3. **Argon2id & Tink Integration (Phase 1/2)**: Argon2id password hashing and Google Tink envelope encryption modules to be integrated during user management and evidence storage phases.
4. **Audit HMAC Tamper-Evidence Chain (Phase 2)**: Transaction-locked HMAC-SHA256 audit chaining mechanism with deterministic millisecond timestamp formatting.
