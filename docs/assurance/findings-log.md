# Findings Log (DRAFT)

Defects and weaknesses found by tests or review. **Add rows only; never rewrite or delete an existing row.** CWE and OWASP numbers are deliberately not filled in unless verified: write VERIFY MANUALLY.

| ID | Found in | Finding | Impact | Fix | Retest | CWE / OWASP |
|---|---|---|---|---|---|---|
| F-001 | Phase 6B (audit wiring tests) | The authentication provider ran twice per login request. `SecurityConfig` registered it on `HttpSecurity` and Spring Boot also put the same bean into the global authentication manager, so a failed login was handled by the child manager and again by its parent. | The failed-login counter rose by 2 per failed attempt, so accounts locked after about 3 failures instead of 5, and each failure was audited twice. Found by the Phase 6B wiring tests because the Phase 2 lockout tests called the provider directly and never went through `/login`. | `SecurityConfig` now uses a `ProviderManager` without a parent: [SecurityConfig.java](../../src/main/java/com/casevault/config/SecurityConfig.java). | SEC-AUDIT-WIRE-04 in [AuditWiringTest.java](../../src/test/java/com/casevault/audit/AuditWiringTest.java) drives the real `/login` endpoint (five failures give five LOGIN_FAILURE rows plus one ACCOUNT_LOCKED). | VERIFY MANUALLY |

## Lessons

- **F-001:** controls must be tested through the real entry point, not only the component. A unit-level call to the provider passed while the assembled HTTP path behaved differently.
