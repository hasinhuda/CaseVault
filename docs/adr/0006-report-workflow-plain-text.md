# ADR 0006: Report Workflow and Plain-Text Report Bodies

## Status
Accepted (Phase 7A, DRAFT until reviewed). Related: FR-11, FR-12, SR-02, SR-06 in [requirements.md](../requirements.md); [ADR 0003](0003-tenant-isolation.md); [ADR 0005](0005-audit-chain.md).

## Decision: the report body is plain text only
- The body is stored as received text and will be rendered only with `th:text` (HTML-escaped by Thymeleaf) in Phase 7C. There is no HTML subset, no Markdown and no sanitiser library.
- Why: a sanitiser is a large attack surface and a new dependency, and the product needs only paragraphs of text. Escaping on output is the one control that is easy to test and hard to get wrong.
- Input is never trusted but also not rewritten: a body such as `<script>alert(1)</script>` is stored as is (test SEC-REPORT-05) and must be escaped on output. The output-escaping test belongs to Phase 7C, when a page exists; nothing in 7A claims it.
- Validation in `DefaultReportService.validateBody`: required, not blank, at most 10000 characters (also a `VARCHAR(10000)` column), control characters rejected except newline and tab. CRLF is normalised to LF first because browsers submit CRLF; a lone carriage return is rejected.
- Not covered: Unicode bidirectional or other invisible formatting characters are accepted (backlog).

## Workflow and rules (as built)
- DRAFT -> SUBMITTED -> APPROVED. There is no reject or return-to-draft step.
- `createDraft`: only the ANALYST assigned to the case. `updateDraft` and `submit`: only the author. `approve`: only a MANAGER who can read the case, and never the author (four-eyes, checked in the service by comparing user ids, independent of roles).
- Reads follow case visibility (`AccessPolicy.canReadCase`): ANALYST (assigned) and MANAGER (in scope) see all states; CLIENT of the case organisation sees APPROVED only (other states are 404 and absent from the list); AUDITOR_ADMIN gets 404.
- Unauthorised or cross-tenant access is 404, never 403, and is audited as `ACCESS_DENIED` / `NOT_VISIBLE` when the object exists. A report id must belong to the case id in the path (otherwise 404). Invalid body or invalid transition is 400.
- Assumption: creating, editing and submitting on a CLOSED case is rejected (400); approving an already submitted report on a closed case is allowed.
- Only the body is client input. Status, author, approver, case and organisation have no setter and are not fields of `ReportRequestDto`.
- Audit: `REPORT_TRANSITION` with reason `REPORT_CREATED`, `REPORT_SUBMITTED` or `REPORT_APPROVED`, user id of the actor, case id, never the body. Recorded through `AuditEventRecorder`, so it is appended after commit (6B ordering); a self-approval attempt is recorded as `ACCESS_DENIED` / `NOT_PERMITTED`. Editing a draft is not a transition and writes no event.
- Schema: Flyway `V8__reports.sql` (V7 is the PostgreSQL-only audit trigger). Ids are `VARCHAR(36)` text UUIDs like every other table, so the foreign keys match `cases` and `users`.

## Consequences
- No HTTP endpoint or page exists yet (Phase 7C); today the service bean is the only entry point and the tests call it with a real authentication in the security context.
- No report history or versioning: an edit replaces the body.
