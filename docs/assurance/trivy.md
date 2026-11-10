# Trivy Container & Dependency Scan Assessment

**Date**: 2026-11-10  
**Target**: `app/app.jar` (Container image scan in CI)  
**Scanner Configuration**: Trivy (`--exit-code 1 --ignore-unfixed --severity CRITICAL,HIGH`)

---

## 1. Executive Summary

During CI container vulnerability scanning of `app/app.jar`, Trivy reported 14 high and critical severity findings (HIGH: 7, CRITICAL: 7) across four dependency groups:
- **Jackson** (`com.fasterxml.jackson.core:*`): 5 findings (all Denial of Service: regex backtracking, unbounded StringBuilder growth, unbounded numeric parsing, unbounded cache growth, quadratic forward-reference completion)
- **Apache Tomcat** (`org.apache.tomcat.embed:*`): 6 findings (5 CRITICAL + 1 HIGH: security constraint bypass, DIGEST and FORM authentication bypass, HTTP/2 no-authority bypass, misleading security logs, rewrite valve control flow)
- **PostgreSQL JDBC Driver** (`org.postgresql:postgresql`): 1 finding (1 HIGH: SCRAM-SHA-256-PLUS downgrade, man-in-the-middle)
- **Spring Web MVC** (`spring-webmvc` 6.2.19): 2 findings (CVE-2026-47884 CRITICAL; CVE-2026-47890 severity VERIFY MANUALLY)

**Total Findings**: 14 (HIGH: 7, CRITICAL: 7)

Of these 14 findings:
- **12 findings** were resolved directly via library version upgrades in [pom.xml](../../pom.xml).
- **2 findings** (affecting `spring-webmvc`) currently lack a backport in the Spring Framework 6.2.x series. Source search (grep) confirms the vulnerable code paths are completely unused in CaseVault; these have been accepted and documented in [.trivyignore](../../.trivyignore) pending future major framework upgrades.

---

## 2. Findings Analysis & Action per Library

| Component | Findings Count & Details | Vulnerability Class | Assessment & Exploitability | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| **Jackson** (`com.fasterxml.jackson.core:*`) | 5 findings (all Denial of Service: regex backtracking, unbounded StringBuilder growth, unbounded numeric parsing, unbounded cache growth, quadratic forward-reference completion) | Denial of service<br>(CWE: VERIFY MANUALLY) | **True positive** in the library. Upgraded to prevent potential denial of service via untrusted payload inputs. | Upgraded Jackson BOM by overriding `<jackson-bom.version>2.21.8</jackson-bom.version>` in `pom.xml`. Resolved version confirmed with mvnw dependency:tree. |
| **Apache Tomcat** (`org.apache.tomcat.embed:*`) | 6 findings (5 CRITICAL + 1 HIGH: security constraint bypass, DIGEST and FORM authentication bypass, HTTP/2 no-authority bypass, misleading security logs, rewrite valve control flow) | Authentication / access-control bypass<br>(CWE: VERIFY MANUALLY) | **True positive** in the library. Embedded web server flaws patched proactively to protect ingress endpoints. | Upgraded embedded Tomcat by overriding `<tomcat.version>10.1.61</tomcat.version>` in `pom.xml`. Resolved version confirmed with mvnw dependency:tree. |
| **PostgreSQL JDBC** (`org.postgresql:postgresql`) | 1 finding (1 HIGH: SCRAM-SHA-256-PLUS downgrade, man-in-the-middle) | Protocol downgrade<br>(CWE: VERIFY MANUALLY) | **True positive** in the library. Driver flaw could allow MITM connection downgrade during authentication. | Upgraded JDBC driver by overriding `<postgresql.version>42.7.14</postgresql.version>` in `pom.xml`. Resolved version confirmed with mvnw dependency:tree. |
| **Spring Web MVC** (`org.springframework:spring-webmvc:6.2.19`) | 2 findings (CVE-2026-47884 CRITICAL; CVE-2026-47890 severity VERIFY MANUALLY) | CVE-2026-47884: Remote code execution via improper path limitation in XsltView (CWE: VERIFY MANUALLY)<br><br>CVE-2026-47890: Stream corruption in Server-Sent Events (SSE) with views; Trivy title also names spring-webflux (CWE: VERIFY MANUALLY) | **True positive in the library, not reachable from CaseVault code**. CaseVault uses Thymeleaf for HTML rendering and JSON REST endpoints; it does not employ XSLT views (`XsltView`) or Server-Sent Events (`SseEmitter`, `ResponseBodyEmitter`, `text/event-stream`). | Documented and accepted in `.trivyignore` with source search (grep) evidence. Target fix requires Spring Framework 7.0.9+ (Spring Boot 4.x). |

---

## 3. Vulnerability Class and OWASP Mappings

- **Vulnerability Classifications**:
  - Jackson: Denial of service (CWE: VERIFY MANUALLY)
  - Apache Tomcat: Authentication / access-control bypass (CWE: VERIFY MANUALLY)
  - PostgreSQL JDBC: Protocol downgrade (CWE: VERIFY MANUALLY)
  - Spring Web MVC:
    - CVE-2026-47884: Remote code execution via improper path limitation in XsltView (CWE: VERIFY MANUALLY)
    - CVE-2026-47890: Stream corruption in Server-Sent Events (SSE) with views; Trivy title also names spring-webflux (CWE: VERIFY MANUALLY)
- **OWASP Top 10 Mapping**:
  - OWASP Top 10:2025 category for vulnerable components: VERIFY MANUALLY

---

## 4. Evidence of Non-Exploitability for Ignored CVEs

Per project governance rules in `AGENTS.md`, any CVE recorded in `.trivyignore` must include reproducible code evidence that the vulnerable capability is unused.

A source search (grep) across the repository confirms zero references to `XsltView`, `SseEmitter`, `ResponseBodyEmitter`, or `text/event-stream`:

```powershell
Get-ChildItem src -Recurse -Include *.java,*.html,*.xml,*.properties | Select-String -Pattern "XsltView|SseEmitter|ResponseBodyEmitter|text/event-stream"
```

*Result*: 0 matches found.

### Ignored CVE Entry Details

1. **CVE-2026-47884**:
   - *Severity*: CRITICAL
   - *Reason*: spring-webmvc 6.2.19, Remote code execution via improper path limitation in XsltView; fixed only in Spring Framework 7.0.9.
   - *Evidence*: `XsltView` is absent from all source files and templates.
   - *Fix Requirement*: Spring Framework 7.0.9 or later (requires Spring Boot 4.x, currently forbidden by `AGENTS.md`).
   - *Review Date*: 2026-12-01.

2. **CVE-2026-47890**:
   - *Severity*: VERIFY MANUALLY
   - *Reason*: spring-webmvc 6.2.19, Stream corruption in Server-Sent Events (SSE) with views; Trivy title also names spring-webflux; fixed only in Spring Framework 7.0.9.
   - *Evidence*: Neither `SseEmitter` nor SSE content types are used.
   - *Fix Requirement*: Spring Framework 7.0.9 or later.
   - *Review Date*: 2026-12-01.

---

## 5. Residual Risk Assessment

- **Upgraded Components (Tomcat, Jackson, PostgreSQL)**: Residual risk is low. All components were updated to vetted patch releases without introducing API incompatibilities or breaking Maven Enforcer convergence rules.
- **Ignored Spring MVC CVEs**: Residual risk is negligible while the vulnerable classes remain unreferenced. The `.trivyignore` exception is bounded by an explicit expiration review date (2026-12-01). If future case-management features require real-time streaming, SSE alternatives (e.g. WebSockets or polled JSON APIs) must be used instead.

---

## 6. What Trivy CANNOT Find (Scanner Limitations)

Software Composition Analysis (SCA) tools such as Trivy analyze binaries, packages, and manifest files against databases of published vulnerabilities (NVD, GitHub Advisories). They **cannot** verify the security posture of custom application code or system logic.

Specifically, Trivy cannot detect:
1. **Broken Object Level Authorization (BOLA / IDOR)**: Accessing another organization's case or evidence by manipulating case IDs or file IDs in HTTP paths.
2. **Broken Object Property Level Authorization (BOPLA)**: Updating unpermitted fields (e.g., client users attempting to self-assign cases or approve reports).
3. **Cross-Tenant Isolation Breaches**: Queries failing to enforce tenant filters or returning `403` instead of the required `404` for unauthorized cross-tenant objects.
4. **Business Logic & Workflow Flaws**: Circumvention of multi-step approval workflows (such as a Manager approving their own report draft, or unauthorized status transitions).
5. **Session & Cookie Misconfigurations at Runtime**: Absence of dynamic cryptographic nonces in Content Security Policy headers or missing `HttpOnly`/`SameSite=Strict`/`Secure` flags in production deployments.
6. **Audit Trail Tampering or Concurrency Gaps**: Broken HMAC chains, race conditions during audit record appending, or uncommitted transactions holding append locks.

These risks must be covered by dedicated unit/integration tests (`HealthEndpointTest`, `ArchitectureTest`, `CaseVaultApplicationTests`, with role-based access control tests planned for a later phase), SpotBugs/FindSecBugs AST analysis, and security code reviews.
