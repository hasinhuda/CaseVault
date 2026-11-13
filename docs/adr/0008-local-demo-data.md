# ADR 0008: Demo data exists only in the local profile

## Status
Accepted (Phase 9E, DRAFT)

## Context
Browser tests need two things the four bootstrap accounts cannot show: tenant isolation between two client organisations, and two administrators (there is no user-creation screen). The project forbids fixed passwords and secrets in the repository (SR-16).

## Decision
1. `DataBootstrapService` creates the demo data in the same first-run pass as the four normal accounts and only when the `local` profile is active: organisation "Demo Client Org B" (`ORG_DEMO_B`), user `demo_client_b` (CLIENT), one case titled "DEMO case of Demo Client Org B (synthetic demo data)", and a second AUDITOR_ADMIN `demo_admin_2`.
2. The existing guards apply unchanged: nothing runs in `prod-like`; nothing runs when any user already exists.
3. Passwords are generated per start with the same generator and password policy as the other accounts and are shown the same way (console banner and the git-ignored credentials file). No fixed or guessable password exists in code, tests or documents.
4. The bootstrap now honours `casevault.bootstrap.credentials-dir` (default `.local-data`, unchanged for a normal start). Before, the property was read but ignored, so tests running the local profile wrote to the developer's real credentials file.

## Why this is safe
- The default (test) profile and `prod-like` never create the data (tests DEMO-ABSENT-01 and DEMO-ABSENT-02); the existing guard tests (`DataBootstrapSecurityTest`, `BootstrapProdProfileSecurityTest`, `ProfileConfigurationSecurityTest`) are unchanged and green.
- The local profile is for a developer machine (HTTP, in-memory database). It must never be used for a shared or production system; `prod-like` is the profile for that.
- The data is synthetic, clearly named, and removed by restarting the application (in-memory database).
- Test DEMO-LOCAL-04 checks that the passwords are policy-valid, distinct, stored only as Argon2id hashes and absent from log lines.

## Consequences
- A test class that activates the `local` profile must use its own in-memory database so that demo data never lands in the database shared by the other test classes (done for `SessionCookieLocalHttpTest`).
- The "last active administrator" message is still not reachable by one-step-at-a-time clicking, even with two administrators (the self-disable rule fires first); it remains covered by SEC-ADMIN-08.

Related finding: F-013 (Phase 9E) - the bootstrap used to ignore `casevault.bootstrap.credentials-dir` and always wrote to `.local-data`; it is now honoured, see [findings-log.md](../assurance/findings-log.md).
