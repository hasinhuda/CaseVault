# Evidence upload assurance (DRAFT)

| Attack or assurance claim | Test ID | Result |
|---|---|---|
| Allowed extension case variants cannot bypass checks | SEC-EVID-UNI-01 | PASS |
| Unicode look-alike extension or normalised dangerous name | SEC-EVID-UNI-02 | PASS |
| Empty, oversized, dangerous extension, executable magic and MIME mismatch | SEC-EV-VAL-002 through SEC-EV-VAL-010 | PASS |
| Plaintext hashing and AV-stub handling | SEC-EV-VAL-011 through SEC-EV-VAL-013 | PASS |
| Unicode FORMAT, LINE_SEPARATOR, look-alike dots, and disallowed trailing punctuation in filename | SEC-EVID-HARDEN-01 | PASS |
| Trailing whitespace is trimmed safely and non-ASCII Bengali script base name is permitted | SEC-EVID-HARDEN-02 | PASS |
| Rejected extension with HTML script tags is context-escaped in error response | SEC-EVID-HARDEN-03 | PASS |
| CLIENT own organisation upload, list, download OK; CLIENT other organisation returns 404 | SEC-EVID-AUTHZ-01 | PASS |
| Assigned ANALYST upload, list, download OK; unassigned ANALYST returns 404 | SEC-EVID-AUTHZ-02 | PASS |
| Internal consultancy MANAGER (ORG_INTERNAL) can view/download any case; client MANAGER restricted to own org | SEC-EVID-AUTHZ-03 | PASS |
| AUDITOR_ADMIN zero-access boundary: 404 on upload, list, download, and getEvidenceById | SEC-EVID-AUTHZ-04 | PASS |
| Cross-case evidence mismatch (Evidence of Case B under Case A) and unknown IDs return 404 | SEC-EVID-AUTHZ-05 | PASS |
| Upload to a CLOSED case rejected with 400 Bad Request | SEC-EVID-AUTHZ-06 | PASS |
| Form mass-assignment prevention: organisationId, uploader, and caseId parameters ignored | SEC-EVID-AUTHZ-07 | PASS |
| Role upload authorization enforcement (FR-08): only CLIENT and assigned ANALYST may upload; MANAGER and AUDITOR_ADMIN cannot | SEC-EVID-AUTHZ-08 | PASS |

Note: Phase 6 cryptographic audit log chaining and verification pending. Groups B through G tests pending.
