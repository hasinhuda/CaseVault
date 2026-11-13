# Architecture Decision Records (ADRs)

This directory documents key architectural, security, and cryptographic decisions for the CaseVault platform in lightweight ADR format.

## Record Index

| ADR ID | Title | Status | Date | Primary Focus |
|---|---|---|---|---|
| [0001](0001-stack.md) | Technology Stack Selection | Accepted | 2026-11-09 | Java 21 LTS, Spring Boot 3.5.16, PostgreSQL, Flyway, Testcontainers, Maven Enforcer, SpotBugs, JaCoCo |
| [0002](0002-auth.md) | Authentication, Password Hashing & Session Management | Accepted | 2026-11-09 | Argon2id, account lockout, uniform timing, session fixation rotation, cookie flags |
| [0003](0003-tenant-isolation.md) | Multi-Tenant Data Isolation & Authorization Model | Accepted | 2026-11-09 | Shared DB discriminator, server-side AccessPolicy, HTTP 404 masking, Four-Eyes principle |
| [0004](0004-evidence-encryption.md) | Digital Evidence Storage & Encryption at Rest (Tink AES-256-GCM AEAD; see the implementation note in the ADR) | Accepted | 2026-11-09 | Google Tink AES-256-GCM, off-web-root storage, Apache Tika MIME validation, streaming decryption |
| [0005](0005-audit-chain.md) | Cryptographic Audit Trail Chaining & Concurrency Control | Accepted | 2026-11-09 | JDK HMAC-SHA256 chaining, millisecond timestamp truncation, exclusive append locking |
| [0006](0006-report-workflow-plain-text.md) | Report Workflow and Plain-Text Report Bodies | Accepted (DRAFT) | 2026-11-12 | DRAFT/SUBMITTED/APPROVED, four-eyes in the service, plain-text body, 404 masking, REPORT_TRANSITION audit |
| [0007](0007-rate-limiting.md) | In-Process Rate Limiting | Accepted (DRAFT) | 2026-11-12 | Self-written fixed-window limiter, bounded memory, login/search/upload/report-write limits, 429 page, no audit row per limited request |
| [0008](0008-local-demo-data.md) | Demo Data Only in the Local Profile | Accepted (DRAFT) | 2026-11-13 | Second client organisation, DEMO case and second administrator, random passwords, never in default or prod-like |
