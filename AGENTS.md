# AGENTS.md: CaseVault-style secure case-management platform (rebuild)

## Product
A secure web platform for a fictional incident-response consultancy to manage cases and evidence.
Roles: CLIENT (own organisation's cases, uploads evidence, sees approved reports), ANALYST (assigned cases: notes,
remediation actions, report drafts), MANAGER (assigns analysts, changes status, approves reports written by someone else),
AUDITOR_ADMIN (security events, account activity, system health, disables accounts; NO access to case or evidence content).
Users only access records of their own organisation and permitted role.
Minimum functions: secure login/logout; create/view cases; category, severity, status, owner; notes and remediation
actions; evidence upload/download; search/filter without leaking records; sanitised report; protected audit log;
admin disable/revoke accounts.

## Stack (fixed)
Java 21, Spring Boot 3.5.x (use the NEWEST 3.5.x patch that exists on Maven Central; verify, never guess), Spring Security,
Thymeleaf, Spring Data JPA, PostgreSQL + Flyway, H2 for fast tests, Testcontainers for Postgres tests, Maven wrapper.
Do NOT use Spring Boot 4.x. Crypto: NO custom algorithms. Argon2id password hashing (Spring Security Argon2PasswordEncoder
with BouncyCastle), Google Tink for encryption at rest, JDK HMAC-SHA256 for the audit chain, Apache Tika for file-type detection.

## Hard rules
1. Synthetic data only. No real malware, no EICAR, no testing against third-party systems. Antivirus is a documented stub.
2. Every request is re-validated and re-authorised server-side. Never trust the UI, hidden fields or client role/org values.
3. Cross-tenant or unauthorised object access returns 404 (not 403) for case/evidence objects.
4. Output encoded by default (th:text only). Forbidden: th:utext, innerHTML, inline scripts/handlers, localStorage for secrets.
5. Strict CSP (two headers, script-src 'self', no nonce), X-Content-Type-Options nosniff, X-Frame-Options DENY, Referrer-Policy, Permissions-Policy.
6. Session cookie HttpOnly, SameSite=Strict, Secure (disabled only in the local http profile; prove Secure by test).
7. No secrets in code, logs, git or client. Generate keys and the initial admin password at first run into secrets/ or
   .local-data/ (git-ignored). Logs never contain passwords, tokens or file contents.
8. Safe errors: no stack traces, class names or SQL to users. Return a correlation ID.
9. Never weaken, skip or delete a test or a quality gate (Enforcer, JaCoCo, SpotBugs/FindSecBugs, ArchUnit) to get green.
10. Never invent versions, CVE ids, ASVS or OWASP numbers, or citations. If unsure write VERIFY MANUALLY.
11. Use repository-relative links only. Never write absolute paths such as C:\Users\... or file:/// links.
12. Do NOT write the final 2,500-word student report. Only produce notes, evidence and drafts clearly marked DRAFT.

## Lessons learned (do these from day one)
- Always run `.\mvnw.cmd -B verify` (not just test). Report BUILD result, test counts, skipped count.
- mvnw must be executable in git: `git update-index --chmod=+x mvnw`.
- Pin every GitHub Action by full commit SHA that you VERIFIED from the action's repository. Never guess a SHA.
- Keep Maven Enforcer (Java/Maven version, BanDuplicatePomDependencyVersions, DependencyConvergence). Fix convergence
  properly (newer BOM patch or explicit management), never by disabling the rule.
- Run Trivy (pinned image digest) with --exit-code 1 --ignore-unfixed --severity CRITICAL,HIGH from the first CI.
  Fix by upgrading; override <tomcat.version>/<jackson-bom.version> when the BOM lags; ignore a CVE only in .trivyignore
  with: reason, evidence (grep showing the feature is unused), fix requirement, review date.
- Dockerfile: pin base image digest; in the runtime stage upgrade apt packages that Trivy flags; run as non-root;
  Hadolint with documented ignores (for example DL3008) and a reason.
- Audit log: append inside an explicit transaction while holding the append lock; release the lock only after commit;
  truncate timestamps to milliseconds so the HMAC chain re-verifies deterministically. Add a concurrency test and run it
  repeatedly.
- CI must run on pushes to every branch, pull requests and manual dispatch, plus a weekly schedule.
- Postgres tests need Docker; in CI make sure they actually run (Skipped must be 0).
- Windows/PowerShell is my shell: give PowerShell commands, not bash-only ones.
- Docs: no coursework wording that claims something is done unless it is verified in the repo.

## Git policy
- Work only on a branch named phase-<n>-<topic>. Never commit or push to main. Never force-push. Never create tags or releases.
  Never change repository settings, secrets or variables.
- Commit ONLY after `.\mvnw.cmd -B verify` is green and the secret check passes. Small commits, conventional messages.
- Push the branch and open a Pull Request. I merge.
- Secret check before every commit:
  git ls-files | Select-String -Pattern "secrets/|\.env$|\.pem|\.key$|keyset|admin_initial_password|\.local-data"
  (harmless .env.example or key-generation scripts are fine; anything else: stop and tell me).

## Phase report format (end of every phase)
Goal, files changed (table), tests added with IDs, verify result and counts, security claims mapped to evidence,
anything uncertain (VERIFY MANUALLY), docs updated (evidence-index, ai-declaration line), and the commit hash.