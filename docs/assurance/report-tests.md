# Report Tests (Phase 7A, DRAFT)

Backend only: there are no report HTTP endpoints or pages yet (Phase 7C), so every test calls the security-proxied `ReportService` bean (or, in the matrix test, the service built directly with the logging recorder) with a real authentication. End-to-end HTTP tests for reports are still missing.

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

Not tested (and not claimed): escaping of a report body in a rendered page (Phase 7C), HTTP status codes and CSRF for report endpoints (Phase 7C), concurrent approval of the same report by two managers (no optimistic locking exists; backlog), Unicode bidirectional characters in bodies.

Existing tests changed: `PostgresFlywayMigrationTest` now expects 8 applied migrations and asserts V8 (assertions added, none removed); `AuthorisationOperationMatrixTest.setUp` now also deletes reports before cases because of the new foreign key (one line added, nothing relaxed).
