# Contributing to CaseVault

## Workflow & Git Policy

1. All development occurs on dedicated branch names matching `phase-<n>-<topic>`. Direct commits or force-pushes to `main` are strictly prohibited.
2. Every pull request must pass all CI checks before review and merging.
3. Commit messages follow Conventional Commits conventions (e.g., `feat: ...`, `fix: ...`, `docs: ...`, `chore: ...`, `test: ...`).

## Pre-Commit Verification Gate

Before creating a commit, ensure:
1. `.\mvnw.cmd -B verify` completes cleanly with zero errors, zero failing tests, zero skipped PostgreSQL tests in CI, and all quality gates passing (Enforcer, JaCoCo, SpotBugs/FindSecBugs, CycloneDX).
2. The secret leak check passes cleanly:
   ```powershell
   git ls-files | Select-String -Pattern "secrets/|\.env$|\.pem|\.key$|keyset|admin_initial_password|\.local-data"
   ```
   No uncommitted or staged secrets may exist in the repository.

## Quality Standards

- Maintain documentation integrity: do not claim features exist until verified by code and passing automated tests in the repository.
- Never weaken, bypass, or delete quality gates, security linters, or existing tests.
- Repository-relative links only in all markdown documentation.
