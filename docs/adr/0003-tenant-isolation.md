# ADR 0003: Multi-Tenant Data Isolation & Authorization Model

## Status
Accepted

## Context
CaseVault hosts cases and evidence for competing client organisations. Cross-tenant leakage constitutes a catastrophic breach of confidentiality. The platform must prevent Broken Object-Level Authorization (BOLA/IDOR), horizontal privilege escalation, and entity enumeration.

## Decision
1. **Shared Database, Discriminator Column Architecture**:
   - Multi-tenancy uses a shared schema with an explicit `organisation_id` foreign key on all tenant-owned entities (`Case`, `Evidence`, `Note`, `IncidentReport`, `User`).
2. **Server-Side Request Authorization & Validation**:
   - Every request is re-validated and re-authorized server-side. No client-supplied hidden fields, parameters, or claims are trusted.
   - Central `AccessPolicy` and service-layer authorization methods verify that `caller.organisationId == targetEntity.organisationId`.
3. **HTTP 404 Masking Policy**:
   - Any attempt to access, view, or modify a case, evidence, note, or report belonging to a different tenant or for which the user lacks authorization must return **HTTP 404 Not Found** (never HTTP 403 Forbidden).
   - This masks the existence of the foreign resource and defeats UUID / ID enumeration.
4. **Role Segregation & Four-Eyes Principle**:
   - `CLIENT`: Confined strictly to own organisation's cases and approved reports.
   - `ANALYST`: Confined to assigned cases within own organisation.
   - `MANAGER`: Can assign cases and approve reports, but cannot approve reports they authored (Four-Eyes Principle).
   - `AUDITOR_ADMIN`: Restricted strictly to system telemetry, user lifecycle, and audit logs. Access to case and evidence content returns HTTP 404.

## Consequences
- **Positive**:
  - Consistent and fail-closed tenant boundary.
  - Zero metadata leakage or confirmation of foreign record existence.
  - Robust separation of duties between investigative and administrative roles.
- **Negative / Trade-offs**:
  - Requires developers to consistently route queries through tenant-scoped service methods rather than raw unconscripted repository calls. Enforced via ArchUnit rules.

## Compliance & Standards Mapping
- **OWASP Top 10**:
  - OWASP Top 10:2025 [VERIFY MANUALLY]: A01 (Broken Access Control - BOLA / IDOR)
  - OWASP Top 10:2021: A01:2021 (Broken Access Control)
- **CWE**:
  - CWE-200 (Exposure of Sensitive Information)
  - CWE-284 (Improper Access Control)
  - CWE-639 (Authorization Bypass Through User-Controlled Key / IDOR)
- **ASVS 5.0**:
  - V4 Access Control (V4.1.1, V4.1.2, V4.1.3 [VERIFY MANUALLY])

