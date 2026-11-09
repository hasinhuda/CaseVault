# AI Assistance Declaration

This document transparently tracks all AI tooling and assistant usage during the engineering of CaseVault, detailing the date, tool, scope of assistance, and verification method.

| Date | Tool | What | Verified By |
| ---- | ---- | ---- | ----------- |
| 2026-11-09 | Antigravity (Gemini 3.8 Flash) | Phase 0 baseline repository scaffolding, Maven pom configuration, quality gates, GitHub Actions workflows, initial health tests | Maven verify build, unit tests, secret checks, manual review |
| 2026-11-09 | Antigravity (Gemini 3.8 Flash) | Phase 1 requirements (15 FRs, 20 SRs), 11 misuse cases, comprehensive STRIDE threat model, architecture and data flow Mermaid diagrams with trust boundaries, privacy/retention policy, and ADRs (stack, auth, tenant isolation, evidence encryption, audit chain) | Manual consistency review, Maven verify build, secret scan, standards mapping validation |
