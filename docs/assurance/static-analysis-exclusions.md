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

