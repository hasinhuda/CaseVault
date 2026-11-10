# AI Assistance Declaration

This document transparently tracks all AI tooling and assistant usage during the engineering of CaseVault, detailing the date, tool, scope of assistance, and verification method.

| Date | Tool | What | Verified By |
| ---- | ---- | ---- | ----------- |
| 2026-11-09 | Antigravity (Gemini 3.8 Flash) | Phase 0 baseline repository scaffolding, Maven pom configuration, quality gates, GitHub Actions workflows, initial health tests | Maven verify build, unit tests, secret checks, manual review |
| 2026-11-09 | Antigravity (Gemini 3.8 Flash) | Phase 1 requirements (15 FRs, 20 SRs), 11 misuse cases, comprehensive STRIDE threat model, architecture and data flow Mermaid diagrams with trust boundaries, privacy/retention policy, and ADRs (stack, auth, tenant isolation, evidence encryption, audit chain) | Manual consistency review, Maven verify build, secret scan, standards mapping validation |
| 2026-11-10 | Antigravity (Gemini 3.8 Flash) | Phase 2 authentication sub-system: Flyway auth migration, Argon2id password hashing with BouncyCastle (bcprov 1.80 verified on Central), password policy validator (min 12, complexity, common password rejection), 5-failure lockout, timing equalization, server-side session management (15m idle, 8h absolute timeout), session fixation rotation, immediate disabled session revocation filter, CSRF, silent/disabled bootstrap in test/prod-like profiles with console-only output in local profile, Testcontainers PostgreSQL Flyway verification, open-in-view=false enforcement, and SEC-AUTH-01..15 + SEC-DB-01..02 test suites | Maven verify build, 25 automated tests (Skipped: 0), SpotBugs + FindSecBugs, JaCoCo, secret checks |
