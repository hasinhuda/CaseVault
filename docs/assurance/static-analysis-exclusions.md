# Static Analysis Assurance & Exclusions Record

## 1. Scope
This document records verified justifications for static analysis filter configurations in `spotbugs-exclude.xml`, ensuring transparent security assurance in accordance with Hard Rule 9.

---

## 2. Excluded Bug Patterns

### 2.1 FindSecBugs: `SPRING_ENDPOINT`

| Attribute | Detail |
|---|---|
| **Plugin / Rule** | FindSecBugs: `SPRING_ENDPOINT` |
| **Category** | Informational / Security Warning |
| **Affected Components** | [AuthController.java](../../src/main/java/com/casevault/controller/AuthController.java) |
| **Exclusion Filter** | [spotbugs-exclude.xml](../../spotbugs-exclude.xml) |

#### Justification & Security Evidence:
- **Rule Purpose**: FindSecBugs flags every `@GetMapping`, `@PostMapping`, or `@RequestMapping` method in Spring MVC controllers as a broad informational alert, notifying developers that an endpoint is exposed to network requests.
- **Endpoint Analysis**:
  1. `GET /login`: Must be unauthenticated by design to serve the HTML sign-in form, CSRF token, and authentication error/logout messages.
  2. `GET /dashboard`: Protected by Spring Security filter chain (`SecurityConfig.java`) enforcing `anyRequest().authenticated()`. Unauthenticated requests to `/dashboard` are intercepted by `DelegatingAuthenticationEntryPoint` and redirected to `/login`.
- **Automated Verification**:
  - `TEST-BASE-003` / `SessionLifecycleSecurityTest`: Integration tests assert that unauthenticated requests to protected endpoints return HTTP 401 or redirect to `/login`.
  - `SEC-AUTH-12`: Asserts that CSRF tokens are required on state-changing POST requests.
- **Conclusion**: The exclusion of `SPRING_ENDPOINT` suppresses an informational scanner reminder without weakening any authorization, authentication, or input-validation gate.

---

### 2.2 SpotBugs: `EI_EXPOSE_REP2` on Spring Controllers

| Attribute | Detail |
|---|---|
| **Plugin / Rule** | SpotBugs: `EI_EXPOSE_REP2` |
| **Category** | Malicious Code Vulnerability (False Positive) |
| **Affected Components** | `com.casevault.controller.*` ([CaseApiController.java](../../src/main/java/com/casevault/controller/CaseApiController.java), [CaseWebController.java](../../src/main/java/com/casevault/controller/CaseWebController.java)) |
| **Exclusion Filter** | [spotbugs-exclude.xml](../../spotbugs-exclude.xml) |

#### Justification & Security Evidence:
- **Rule Purpose**: SpotBugs flags constructors that store references to non-primitive objects into internal fields, warning that external code could retain a reference to mutate internal state (`May expose internal representation by incorporating reference to mutable object`).
- **Spring Framework Architecture**:
  1. Controllers and services (`CaseAccessService`) are singleton beans managed entirely by the Spring IoC container application context.
  2. Spring enforces constructor-based dependency injection as the recommended design pattern. The injected service bean is held in `private final` fields and is never exposed through getters or public mutators.
  3. External callers (HTTP clients) communicate with controllers via serialized DTOs over HTTP/JSON and Thymeleaf HTML rendering; callers never receive, access, or modify the underlying Java service reference.
- **Automated Verification**:
  - `SEC-AUTHZ-ARCH-01`: ArchUnit test asserts that controllers never access repositories directly, strictly routing through `CaseAccessService`.
  - Full suite of 54 integration tests verifies strict tenant isolation, role boundaries, and DTO encapsulation across all REST and web endpoints.
- **Conclusion**: Scoping `EI_EXPOSE_REP2` exclusion strictly to `com.casevault.controller.*` eliminates a well-known Spring dependency injection false positive without relaxing any domain, entity, or cryptographic encapsulation.


