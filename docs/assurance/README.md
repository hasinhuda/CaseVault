# Security Assurance Evidence

This directory stores threat models, security architecture reviews, testing plans, static analysis justifications, OWASP Top 10 and compliance mappings (e.g. ASVS) for CaseVault.
All claims must be backed by reproducible test evidence or source artifacts. Start with [known-limitations.md](known-limitations.md) for what is not built or only partly built.

## Document Index

Overview and honesty documents:
- [known-limitations.md](known-limitations.md): consolidated list of what is not implemented, implemented with limits, and design decisions.
- [brief-audit.md](brief-audit.md): read-only audit of the repository against the assessment brief and the phase plan (scorecard, top gaps, must-fix list).
- [findings-log.md](findings-log.md): findings F-001 onwards with fix and retest (add-only).

Tool evidence:
- [static-analysis-exclusions.md](static-analysis-exclusions.md): Static analysis rules and SpotBugs/FindSecBugs exclusion rationale.
- [trivy.md](trivy.md): Analysis of CI container/dependency scan findings, upgrade resolutions, and accepted non-exploitable CVE exemptions (scan dates: 2026-11-10).

Test result documents (by area; each lists test IDs and the verify result of its phase, so test totals inside them are historical):
- [authorisation-tests.md](authorisation-tests.md): tenant isolation, roles, case workflow, search, output encoding.
- [evidence-upload-tests.md](evidence-upload-tests.md): upload validation, encrypted storage, download, evidence authorisation and logging.
- [audit-tests.md](audit-tests.md): audit chain, wiring, auditor view.
- [admin-tests.md](admin-tests.md): account disable/enable, session revocation, health page.
- [report-tests.md](report-tests.md): report workflow, four-eyes, plain-text output.
- [headers-and-rate-limit.md](headers-and-rate-limit.md): security headers, safe errors, rate limiting.
- [session-and-log-tests.md](session-and-log-tests.md): cookie flags, session cap, session id never in a URL, log hygiene, template scanner.

User interface and manual testing:
- [ui-inventory.md](ui-inventory.md): UI inventory, accessibility audit and the Phase 9B/9C results.
- [manual-browser-tests.md](manual-browser-tests.md): 57 manual browser test cases for a human tester; **not executed yet** (all result cells are empty).
