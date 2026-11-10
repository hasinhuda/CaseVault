# Authorization & Tenant Isolation Assurance

## 1. Scope & Security Objectives
This document provides assurance evidence for the tenant-aware, role-based authorization model implemented in CaseVault Phase 3 (`phase-3-authz`), as defined in [ADR 0003](../adr/0003-tenant-isolation.md) and security requirements `SR-01`, `SR-02`, and `SR-07` in [requirements.md](../requirements.md).

---

## 2. Security Claims to Test ID Mapping

| Security Claim / Requirement | Architectural Rule | Test ID | Verification Artifact | Result |
| :--- | :--- | :--- | :--- | :--- |
| **SR-01: Server-Side Re-Validation & Re-Authorization** | Client hidden fields, URL parameters, or claimed roles are never trusted. Every request re-validates principal credentials server-side. | `SEC-AUTHZ-01`, `SEC-AUTHZ-02`, `SEC-AUTHZ-03`, `SEC-AUTHZ-03B`, `SEC-AUTHZ-05` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SR-01: Mass Assignment Prevention** | DTOs do not bind `organisationId`, `role`, `status`, `owner`, or `assignedAnalyst`. Server derives identity and defaults. | `SEC-AUTHZ-09` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SR-01 / FR-04: Case Creation Role Restriction** | Case creation (`POST /api/cases`) is restricted strictly to users with the `CLIENT` role. Non-client roles receive HTTP 403 Forbidden. | `SEC-AUTHZ-10` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SR-01 / FR-04: Allow-List Input Validation** | Category and severity inputs are validated against strict regex allow-lists; invalid values return HTTP 400 Bad Request. | `SEC-AUTHZ-11` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SR-02: Cross-Tenant Isolation & Uniform HTTP 404 Masking** | Access attempts targeting records belonging to another tenant return HTTP 404 Not Found (never 403 Forbidden). | `SEC-AUTHZ-01`, `SEC-AUTHZ-03B`, `SEC-AUTHZ-06` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SR-02: Staff Scope - Consultancy Manager Access** | Internal consultancy managers (`ORG_INTERNAL`) have tenancy-wide investigation scope and can access client-organisation cases. | `SEC-AUTHZ-03` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SR-02: Staff Scope - Assigned Analyst Access** | Analysts can access client-organisation cases assigned to them, regardless of organisation; unassigned cases return HTTP 404. | `SEC-AUTHZ-02` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SR-02: Anti-Enumeration & IDOR Protection** | Non-existent UUID queries and cross-tenant queries produce identical HTTP 404 responses without resource existence disclosure. | `SEC-AUTHZ-07` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SR-02: Tenant Scoping on Queries** | Case listing endpoints strictly filter by the caller's organization and analyst assignment without leaking foreign records. | `SEC-AUTHZ-03`, `SEC-AUTHZ-03B`, `SEC-AUTHZ-05` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SR-02: Evidence Tenant Isolation** | Access to evidence inherits case tenant scoping. Unauthorized access returns HTTP 404. | `SEC-AUTHZ-06` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SR-07: Strict Auditor-Admin Content Boundary** | Users with `AUDITOR_ADMIN` role have zero access to case or evidence content; queries return HTTP 404 or empty lists. | `SEC-AUTHZ-04`, `SEC-AUTHZ-06` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |
| **SEC-AUTHZ-ARCH-01: Architectural Isolation** | Controllers must not access repositories directly. All access must be routed through `CaseAccessService`. | `SEC-AUTHZ-ARCH-01` | [ArchitectureTest.java](../../src/test/java/com/casevault/ArchitectureTest.java) | PASS |
| **SEC-AUTHZ-ARCH-02: Repository Boundary Enforcement** | Repositories may only be accessed by service and security/bootstrap components. | `SEC-AUTHZ-ARCH-02` | [ArchitectureTest.java](../../src/test/java/com/casevault/ArchitectureTest.java) | PASS |
| **Unauthenticated API Access** | Unauthenticated requests to protected `/api/**` endpoints return HTTP 401 Unauthorized. | `SEC-AUTHZ-08` | [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java) | PASS |

---

## 3. Role Operation Matrix

| Role | Operation | Permitted Scope | Unpermitted Access Status |
| :--- | :--- | :--- | :--- |
| **CLIENT** | `GET /api/cases/{id}` | Own organisation's cases only | HTTP 404 (cross-tenant or foreign case) |
| **CLIENT** | `GET /api/cases` | Own organisation's cases only | Filtered (0 cross-tenant records returned) |
| **CLIENT** | `GET /api/evidence/{id}` | Evidence attached to own organisation's cases | HTTP 404 (cross-tenant or foreign evidence) |
| **CLIENT** | `POST /api/cases` | Create case within own organisation (FR-04) | HTTP 400 (validation failure) / Server sets org |
| **ANALYST** | `GET /api/cases/{id}` | Cases explicitly assigned to this analyst (any org) | HTTP 404 (unassigned cases, cross-tenant unassigned) |
| **ANALYST** | `GET /api/cases` | Cases explicitly assigned to this analyst (any org) | Filtered (unassigned cases omitted) |
| **ANALYST** | `GET /api/evidence/{id}` | Evidence attached to assigned cases | HTTP 404 (unassigned case evidence) |
| **ANALYST** | `POST /api/cases` | None (Restricted to CLIENT per FR-04) | HTTP 403 Forbidden |
| **MANAGER (ORG_INTERNAL)** | `GET /api/cases/{id}` | All cases across all client organisations | HTTP 404 (non-existent UUID only) |
| **MANAGER (ORG_INTERNAL)** | `GET /api/cases` | All cases across all client organisations | Full tenancy scope (all client cases) |
| **MANAGER (ORG_INTERNAL)** | `GET /api/evidence/{id}` | All evidence across all client cases | HTTP 404 (non-existent UUID only) |
| **MANAGER (Client Org)** | `GET /api/cases/{id}` | Own client organisation's cases only | HTTP 404 (cross-tenant cases) |
| **MANAGER (Client Org)** | `GET /api/cases` | Own client organisation's cases only | Filtered (cross-tenant cases omitted) |
| **MANAGER (Client Org)** | `GET /api/evidence/{id}` | Evidence attached to own organisation cases | HTTP 404 (cross-tenant evidence) |
| **MANAGER (Any)** | `POST /api/cases` | None (Restricted to CLIENT per FR-04) | HTTP 403 Forbidden |
| **AUDITOR_ADMIN** | `GET /api/cases/{id}` | None (Strict zero content access) | HTTP 404 |
| **AUDITOR_ADMIN** | `GET /api/cases` | None (Strict zero content access) | Empty list `[]` (HTTP 200 with 0 items) |
| **AUDITOR_ADMIN** | `GET /api/evidence/{id}` | None (Strict zero content access) | HTTP 404 |
| **AUDITOR_ADMIN** | `POST /api/cases` | None (Strict zero content access) | HTTP 403 Forbidden |

---

## 4. Residual Risk & Manual Verification Notes
- **Standards Mapping**: OWASP Top 10:2025 A01 [VERIFY MANUALLY], CWE-284, CWE-285, CWE-639, ASVS 5.0 V4.1 [VERIFY MANUALLY].
- **UI & Workflow Scope**: Full case status transition workflows, four-eyes report approval rules (SR-06), and Thymeleaf UI views are deferred to Phase 4. Minimal REST endpoints implemented in Phase 3 serve to prove and gate backend authorization logic.
