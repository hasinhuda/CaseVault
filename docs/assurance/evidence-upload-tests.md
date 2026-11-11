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
| Upload without CSRF token returns 403 Forbidden | SEC-EVID-WEB-01 | PASS |
| Unauthenticated upload returns 401 Unauthorized | SEC-EVID-WEB-02 | PASS |
| MANAGER and AUDITOR_ADMIN upload returns HTTP 404 with safe body masking | SEC-EVID-WEB-03 | PASS |
| Cross-tenant upload, list, download over HTTP returns HTTP 404 | SEC-EVID-WEB-04 | PASS |
| Oversize file upload returns safe error page with correlation ID and no stack trace | SEC-EVID-WEB-05 | PASS |
| Content validation failures (fake PNG with text, MZ in PDF, ELF bytes, double extensions .pdf.exe / .exe.pdf, empty file) return safe error and record EVIDENCE_REJECTED audit placeholder | SEC-EVID-WEB-06 | PASS |
| Valid PDF, PNG, and TXT files uploaded over HTTP return 302 and record EVIDENCE_UPLOADED audit placeholder | SEC-EVID-WEB-07 | PASS |
| Mass-assignment over HTTP ignores injected organisationId, uploader, and caseId form fields | SEC-EVID-WEB-08 | PASS |
| Download responses include required defensive headers (Content-Disposition attachment, application/octet-stream, nosniff, no-store) | SEC-EVID-DL-01 | PASS |
| Stored display name with CR, LF or quotes cannot inject headers or split response | SEC-EVID-DL-02 | PASS |
| Tampered stored ciphertext returns safe 404 error page, releases no plaintext, and records INTEGRITY_FAILED audit placeholder | SEC-EVID-DL-03 | PASS |
| Deleted or missing stored file returns safe 404 error page and records FILE_NOT_FOUND audit placeholder | SEC-EVID-DL-04 | PASS |
| Hash mismatch between plaintext and DB sha256 records exactly ONE INTEGRITY_FAILED audit placeholder event | SEC-EVID-DL-05 | PASS |
| Database save failure triggers cleanup of written encrypted file (no orphan file) and 0 DB rows remain | SEC-EVID-FAIL-01 | PASS |
| File storage write failure aborts operation and leaves no database row | SEC-EVID-FAIL-02 | PASS |
| Evidence tab renders for CLIENT, ANALYST and MANAGER with role-appropriate controls | SEC-EVID-UI-01 | PASS |
| Stored display name with script tags is HTML-escaped (`&lt;script&gt;` present, no raw `<script>`) in Evidence tab | SEC-EVID-UI-02 | PASS |
| Evidence tab is hidden from AUDITOR_ADMIN and direct request returns HTTP 404 | SEC-EVID-UI-03 | PASS |
| Template scanner security gate confirms zero `th:utext` or unsafe inline handlers across all templates | SEC-EVID-UI-04 | PASS |
| Upload accepted audit placeholder log contains only event type, UUIDs and fixed reason code with no secrets or filenames | SEC-EVID-LOG-01 | PASS |
| Upload rejected with CRLF filename prevents log injection and does not create second line | SEC-EVID-LOG-02 | PASS |
| Download verified audit placeholder log contains only metadata and no keys or filenames | SEC-EVID-LOG-03 | PASS |
| Integrity failure audit placeholder log records INTEGRITY_FAILED with zero plaintext leakage | SEC-EVID-LOG-04 | PASS |
| Missing file audit placeholder log records FILE_NOT_FOUND without leaking path | SEC-EVID-LOG-05 | PASS |
| Evidence storage boundary is service-only | SEC-EVID-ARCH-01 | PASS |
| EvidenceRepository is accessed only by service classes | SEC-EVID-ARCH-02 | PASS |
| Controllers must not access EvidenceRepository or storage classes directly | SEC-EVID-ARCH-03 | PASS |

### Multipart & Audit Notes
- `SEC-EVID-WEB-05` exercises the validator's 10MB rule through MockMvc. The servlet multipart limit (`spring.servlet.multipart.max-file-size=10MB`, `max-request-size=11MB`) is covered separately by `GlobalExceptionHandlerUploadTest`.
- **Known Limitation**: An oversize upload stopped early by the servlet multipart container limit (`MaxUploadSizeExceededException`) is handled at the servlet/filter boundary before controller or service invocation, and therefore does NOT produce an audit placeholder event.
- **Audit Implementation Note**: Phase 6 cryptographic audit log chaining and verification pending. All audit events recorded in Phase 5 are metadata placeholders (`LoggingAuditEventRecorder`).
