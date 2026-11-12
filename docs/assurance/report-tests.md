# Report Tests (Phase 7A, DRAFT)

Phase 7A section (backend only; the HTTP endpoints and pages came in Phase 7C, see the last section): every test calls the security-proxied `ReportService` bean (or, in the matrix test, the service built directly with the logging recorder) with a real authentication. End-to-end HTTP tests for reports are still missing.

Results from `.\mvnw.cmd -B verify`: 225 tests, 0 failures, 0 skipped, SpotBugs BugInstance size 0, JaCoCo checks met. Classes: [ReportServiceTest.java](../../src/test/java/com/casevault/reports/ReportServiceTest.java), [AuthorisationOperationMatrixTest.java](../../src/test/java/com/casevault/authz/AuthorisationOperationMatrixTest.java), [ArchitectureTest.java](../../src/test/java/com/casevault/ArchitectureTest.java), [PostgresFlywayMigrationTest.java](../../src/test/java/com/casevault/db/PostgresFlywayMigrationTest.java).

| Attack or property | Test ID | Result |
|---|---|---|
| Role x operation matrix (assigned and unassigned analyst, internal manager, client-org manager, own-org client, other-org client, auditor) for create, update, submit, approve, list, get; always 404 when not permitted | SEC-REPORT-AUTHZ-01 | PASS |
| Author approves own report: 400 and one ACCESS_DENIED NOT_PERMITTED; a different manager approves | SEC-REPORT-01 | PASS |
| Skip SUBMITTED, approve twice, edit after SUBMITTED or APPROVED, submit twice: 400; body unchanged | SEC-REPORT-02 | PASS |
| CLIENT sees DRAFT or SUBMITTED reports: 404 on get, absent from list; APPROVED visible; other tenant and auditor 404 | SEC-REPORT-03 | PASS |
| Report of case B under case A for get, update, submit, approve: 404; random report or case id: 404 | SEC-REPORT-04 | PASS |
| Empty, blank, null, over-length, NUL, BEL, ESC, DEL, lone CR, C1 control characters: 400 and nothing stored; 10000 characters, newline and tab accepted; CRLF normalised; script-like text stored unchanged | SEC-REPORT-05 | PASS |
| Closed case: create, edit, submit rejected (400); approve of an already submitted report allowed (documented assumption) | SEC-REPORT-06 | PASS |
| Mass assignment: status, author, approver, case, organisation and id in JSON input are ignored; the input object has one field | SEC-REPORT-07 | PASS |
| Audit: one REPORT_TRANSITION per transition with actor and case id, an unauthorised attempt gives ACCESS_DENIED, no event for an invalid transition or an edit, no report body in any audit column or log line, `verifyChain()` valid | SEC-REPORT-08 | PASS |
| Rejected operations (rolled back) write no REPORT_TRANSITION | SEC-REPORT-09 | PASS |
| No authentication in the security context: the service refuses; a null principal is 404 | SEC-REPORT-10 | PASS |
| Controllers never touch `ReportRepository` or `DefaultReportService`; only services access the repository | SEC-REPORT-ARCH-01, -02, -03 | PASS |
| Flyway V8 applies on real PostgreSQL after V1-V7 (Hibernate schema validation also passes) | SEC-DB-001 | PASS |

Not tested in 7A (the items now covered by HTTP tests are listed in the Phase 7C section below; what is still untested is listed there too) (and not claimed): escaping of a report body in a rendered page (Phase 7C), HTTP status codes and CSRF for report endpoints (Phase 7C), concurrent approval of the same report by two managers (no optimistic locking exists; backlog), Unicode bidirectional characters in bodies.

Existing tests changed: `PostgresFlywayMigrationTest` now expects 8 applied migrations and asserts V8 (assertions added, none removed); `AuthorisationOperationMatrixTest.setUp` now also deletes reports before cases because of the new foreign key (one line added, nothing relaxed).

## Phase 7C: report pages over HTTP

Results from `.\mvnw.cmd -B verify`: 256 tests, 0 failures, 0 skipped, SpotBugs BugInstance size 0, JaCoCo checks met. Class: [ReportWebTest.java](../../src/test/java/com/casevault/reports/ReportWebTest.java) (real filter chain, real logins through `/login`, H2, chained audit log). Routes: `GET /cases/{caseId}/reports`, `GET /cases/{caseId}/reports/{reportId}`, `POST /cases/{caseId}/reports`, `POST /cases/{caseId}/reports/{reportId}/update`, `.../submit`, `.../approve`.

| Attack or property | Test ID | Result |
|---|---|---|
| Role matrix over HTTP (assigned and unassigned analyst, internal manager, client-org manager, own and other client, auditor) for list, detail, create, update, submit, approve: 404 when not permitted; DRAFT absent from the client list; POST without CSRF is 403 | SEC-REPORT-WEB-01, SEC-REPORT-WEB-AUTHZ-01 | PASS |
| Unauthenticated requests behave like `/cases`; Reports tab link present for analyst and client, absent for the auditor (who gets 404 on the case page and on the reports route) | SEC-REPORT-WEB-02 | PASS |
| Report text with a script tag and an image tag with an onerror attribute is shown escaped on the detail page (analyst, manager, client), on the rejected create form and on the rejected edit form; no raw script or image element, no tag with an onerror attribute; line breaks kept as text for CSS `white-space: pre-wrap` | SEC-REPORT-WEB-03 | PASS |
| Report of case B under case A, random, malformed and SQL-looking ids, unknown cases: 404 on every route; nothing changes | SEC-REPORT-WEB-04 | PASS |
| Four-eyes over HTTP: the author gets a 400 message and no state change, no Approve button; another manager approves; the client sees APPROVED only (SUBMITTED is 404) | SEC-REPORT-WEB-05 | PASS |
| Wrong-state transitions (approve a draft, submit twice, edit after submit, approve twice): friendly 400, no stack trace, nothing changed | SEC-REPORT-WEB-06 | PASS |
| Empty, blank, over-length, NUL, ESC, lone CR, DEL and missing body: friendly 400, nothing stored; the form states the 10000 limit, has maxlength and a label, and no script | SEC-REPORT-WEB-07 | PASS |
| Mass assignment: status, authorId, approvedBy, approvedById, caseId, organisationId, id and version form fields are ignored on create, update, submit | SEC-REPORT-WEB-08 | PASS |
| Audit over HTTP: exactly one REPORT_TRANSITION per successful create, submit and approve with actor and case id; no event for edit or a refused transition; a refused attempt is one ACCESS_DENIED; no body text in audit columns or log lines; chain valid | SEC-REPORT-WEB-09 | PASS |
| Two managers approving the same SUBMITTED report at once (3 rounds, both requests held until both read SUBMITTED): exactly one redirect and one HTTP 409 with a friendly message, one REPORT_APPROVED event, `approved_by` is the winner | SEC-REPORT-WEB-10 | PASS |
| Audit append fails after the commit: HTTP 500 safe error page with a correlation id, no exception text, the change stays committed (SUBMITTED), ERROR log line with the correlation id and without the outage text. It proves the submit path; the other transitions use the same recorder code | SEC-REPORT-WEB-11 | PASS |
| The list shows the newest report first; friendly empty state | SEC-REPORT-WEB-13 | PASS |
| Report templates have no th:utext, inline script, style or handler | SEC-REPORT-WEB-12 | PASS |
| The report web controller depends on `ReportService` and DTOs only (no repository, report, case or user entity); earlier controller rules unchanged | SEC-REPORT-ARCH-04 (new), SEC-REPORT-ARCH-01..03 | PASS |
| Flyway V10 (version column) applies on real PostgreSQL after V1-V9 | SEC-DB-001 | PASS |

Optimistic locking: `reports.version` (V10) is mapped with `@Version`. The losing request gets HTTP 409 and the page is shown again with the current state. The same applies to concurrent edits and submits of one report (the mechanism is shared; only approval has a concurrent test).

Not tested (and not claimed): contrast ratios and keyboard focus of the new pages (VERIFY MANUALLY); behaviour with JavaScript disabled beyond "the pages contain no script element"; concurrent edit or submit of one report; the concurrency test runs on H2 (PostgreSQL locking behaviour of the same update is not tested); report export or download (not built); viewing reports is not audited; Unicode bidirectional characters in bodies are accepted.
