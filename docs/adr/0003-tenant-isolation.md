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

---

## Amendment: Staff Scope & Consultancy Multi-Tenancy (Phase 3)

### Context & Gap Analysis
In the initial tenant model, `AccessPolicy` required `caller.organisationId == targetEntity.organisationId` uniformly across all roles. Because internal consultancy staff (analysts and managers) reside in the internal consultancy organisation (`code = ORG_INTERNAL`), this strict restriction prevented consultancy investigators from accessing the client-organisation cases they were contracted to investigate and manage.

### Amended Decision
1. **CLIENT Scope**:
   - Confined strictly to cases and evidence where `case.organisation_id == caller.organisationId`.
2. **ANALYST Scope**:
   - Confined strictly to cases where `case.assigned_analyst_id == caller.userId`, irrespective of the case's client organization. Unassigned cases, even within the same consultancy or client organization, return HTTP 404.
3. **MANAGER Scope**:
   - If the caller belongs to the internal staff consultancy organization (identified deterministically by organisation code `ORG_INTERNAL` via server configuration, never from client input), the manager can view and manage all client cases across the tenancy.
   - If a manager belongs to a client organisation, they remain strictly restricted to their own organisation's cases (`case.organisation_id == caller.organisationId`) and receive HTTP 404 for any other organization's cases.
4. **AUDITOR_ADMIN Scope**:
   - Retains strict zero-access to case and evidence content (returns HTTP 404).
5. **Case Creation Restriction (FR-04)**:
   - Case creation (`POST /api/cases`) is restricted strictly to users with the `CLIENT` role. Managers and analysts do not create cases on behalf of clients via this endpoint.

### Threat Model Note: Privileged Organisation Code `ORG_INTERNAL` (Phase 4)

The internal consultancy organisation is identified deterministically by organisation code `ORG_INTERNAL`, which is bootstrapped by `DataBootstrapService` and verified in `AccessPolicy` via the constant `INTERNAL_ORG_CODE`. This code grants MANAGER users scoped to the internal organisation full cross-tenant case visibility.

**Spoofing Prevention**: The `organisations` table (`V2__auth_schema.sql`) declares `code VARCHAR(50) NOT NULL UNIQUE`, enforcing a database-level uniqueness constraint. An attacker cannot create a second organisation with code `ORG_INTERNAL` because the `INSERT` would violate the `UNIQUE` constraint. Additionally:
- Organisation records are created exclusively by `DataBootstrapService` (server-side, not via any user-facing API endpoint).
- No API endpoint exposes organisation creation or code modification.
- The organisation code is never accepted from client input; it is resolved server-side from the authenticated principal's persisted organisation record.

## Addendum (Phase 8C): status codes for unauthorised access

Decision F-003 by the project owner, recorded in [findings-log.md](../assurance/findings-log.md): an object the caller cannot see (another organisation, or a role that has no access to it, for example AUDITOR_ADMIN on case content) returns HTTP 404. A forbidden action on an object the caller CAN see returns HTTP 403. Both write one ACCESS_DENIED audit event. The reason for 404 is to hide whether an object exists; for a visible object there is nothing left to hide, and 403 tells the user the truth. The wording of SR-02 in [requirements.md](../requirements.md) was clarified by an appended bullet; the original text is unchanged. The behaviour is pinned by SEC-HDR-404-01..03.
