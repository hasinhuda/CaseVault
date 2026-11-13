# Manual browser test guide (Phase 9D) - DRAFT

Guide for the human tester. Windows 11, PowerShell, Chrome or Edge. **Nothing in this document has been executed by the author: every Result, Screenshot and Tester notes cell is blank on purpose.** Expected results were read from the code, templates and configuration (repository state of Phase 9C); where the code does not settle a point it is marked `UNCONFIRMED - check while testing` and the tester records what really happens.

Rules for the tester: use synthetic data only (hard rule 1), never type a real password of yours, never paste a password, token or session id into this file, a screenshot or a chat. Use placeholders such as `<bootstrap password from the console log>`.

## 0. Preparation

### 0.1 Start the application

The README (section "Running locally", added in Phase 9E) documents this command. It is derived from the `spring-boot-maven-plugin` in `pom.xml` and the `local` profile (`application-local.properties`: HTTP, port 8080, cookie `Secure` off, in-memory H2). The author has not run it; if it fails, record the console error. `UNCONFIRMED - check while testing`.

Open PowerShell in the repository root (the folder that contains `pom.xml`) and run:

```powershell
.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=local"
```

Wait until the console shows the banner `[CASEVAULT FIRST-RUN BOOTSTRAP] Initial Credentials Generated`, then open `http://localhost:8080/login`.

Why the `local` profile: bootstrap passwords are printed and saved **only** in the `local` profile (`DataBootstrapService`); without it the four accounts exist but nobody knows their passwords. Also, the default `application.properties` sets the session cookie `Secure=true`; over plain `http` that may stop the login form from working (see MAN-09, `UNCONFIRMED`).

### 0.2 The four accounts and their passwords

| Role | Username | Organisation |
|---|---|---|
| AUDITOR_ADMIN | `admin_auditor` | none |
| MANAGER | `manager_alice` | ORG_INTERNAL |
| ANALYST | `analyst_bob` | ORG_INTERNAL |
| CLIENT | `client_charlie` | ORG_ACME |
| CLIENT (demo, local profile only) | `demo_client_b` | ORG_DEMO_B "Demo Client Org B" (owns the DEMO case) |
| AUDITOR_ADMIN (demo, local profile only, second administrator) | `demo_admin_2` | none |

There is no user creation screen (`docs/issues-backlog.md`). In the `local` profile two more DEMO accounts exist (below); no other account can be created. Passwords are random and **new on every start** (the database is in memory and is empty after a restart).

Read a password without displaying it (it goes to the clipboard, then paste it into the browser field with Ctrl+V):

```powershell
$u = 'client_charlie'; (Select-String -Path .\.local-data\bootstrap-credentials.txt -Pattern "^$u=").Line -replace '^[^=]*=' | Set-Clipboard
```

After pasting, empty the clipboard: `Set-Clipboard -Value ' '`. The file `.local-data\bootstrap-credentials.txt` is git-ignored; never copy it into the repository.

### 0.3 Browser basics

| Task | How |
|---|---|
| Incognito / InPrivate window | Ctrl+Shift+N (Chrome) or Ctrl+Shift+N (Edge InPrivate) |
| Hard reload | Ctrl+Shift+R (or Ctrl+F5) |
| Open DevTools | F12 |
| Clear the session cookie | F12 -> Application -> Storage -> Cookies -> `http://localhost:8080` -> right-click `JSESSIONID` -> Delete |
| View page source | Ctrl+U (or type `view-source:http://localhost:8080/login`) |
| Zoom | Ctrl+Plus / Ctrl+Minus, Ctrl+0 resets |
| Narrow width | F12 -> Toggle device toolbar (Ctrl+Shift+M) -> width 375 |

### 0.4 Reset local data

The repository documents no reset procedure. The `local` profile uses an in-memory H2 database, so **stopping the app (Ctrl+C) and starting it again** empties cases, reports, audit log and users, and creates the four accounts again with **new passwords** (re-read them). Encrypted evidence files and keys stay in `.local-data\` (git-ignored); the repository does not document deleting them, so do not delete them. Restart also ends every session and clears the login lockout and rate-limit counters (in memory).

### 0.5 Test files (outside the repository)

Create harmless files in a scratch folder (nothing here is real malware):

```powershell
$dir = Join-Path $env:TEMP 'casevault-manual'; New-Item -ItemType Directory -Force $dir | Out-Null
Set-Content "$dir\ok-evidence.txt" 'synthetic evidence text for manual test'
Set-Content "$dir\fake.exe" 'this is only text with an exe name'
Set-Content "$dir\disguised.png" 'this is only text with a png name'
$f = [IO.File]::Create("$dir\too-big.txt"); $f.SetLength(11MB); $f.Close()
Get-FileHash "$dir\ok-evidence.txt" -Algorithm SHA256
```

### 0.6 Suggested order (the lockout and rate-limit tests disturb later tests)

1. MAN-01..08, MAN-10..11, MAN-13..14, then workflow areas e, f, g, h, i, k.
2. Do **MAN-12 (session cap)** with `analyst_bob` when nothing else is open.
3. Do **MAN-06 (lockout)** and **MAN-48 (429 page)** last. After MAN-06 the locked account stays locked for 15 minutes (`CaseVaultAuthenticationProvider.LOCK_DURATION`); restart the app to continue (see 0.4). The login rate limiter is shared by all login attempts from your computer: allow 60 seconds between login-heavy tests.

## 1. Test cases

Column "Link" gives the requirement (SR/FR ids from `docs/requirements.md`), finding (`docs/assurance/findings-log.md`) or the automated test that covers the same behaviour. Screenshot names follow section 2. **Result, Screenshot (if taken) and Tester notes are for the tester.**

### Area a - Login and logout

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-01 | FR-01; SEC-AUTH-06, SEC-COOKIE-02 | App running, fresh browser, `client_charlie` | 1. Open `http://localhost:8080/login`.<br>2. Enter username `client_charlie` and the password (clipboard).<br>3. Click **Sign In**. | Redirect to `/dashboard`. Header shows `[ORG_ACME]`, `client_charlie` and role badge `CLIENT`. Page title "Security Operations Dashboard", card "Client Incident Portal" with buttons "View Organization Cases" and "Submit New Incident". Sidebar is not shown on the dashboard (top navigation: Dashboard, Cases). | MAN-01_client-dashboard.png | | |
| MAN-02 | FR-01 | `analyst_bob` | As MAN-01 with `analyst_bob`. | `/dashboard`; badge `ANALYST`; card "Investigator Workspace" with button "My Assigned Investigations". | MAN-02_analyst-dashboard.png | | |
| MAN-03 | FR-01 | `manager_alice` | As MAN-01 with `manager_alice`. | `/dashboard`; badge `MANAGER`; card "Consultancy Supervision & Triage" with button "Manage Cases & Assignments". | MAN-03_manager-dashboard.png | | |
| MAN-04 | FR-01, SR-07 | `admin_auditor` | As MAN-01 with `admin_auditor`. | `/dashboard`; badge `AUDITOR_ADMIN`; card "Security Audit Telemetry & Governance (SR-07)"; navigation shows Audit log, Users, Health and a non-link "Cases (Restricted)". | MAN-04_auditor-dashboard.png | | |
| MAN-05 | SR-04 | Signed out | 1. Open `/login`.<br>2. Enter `client_charlie` and a wrong password; click **Sign In**.<br>3. Repeat with username `nobody_x` and any password. | Both times the URL is `/login?error=true` and the red message is exactly "Invalid username or password" (same text for known and unknown user). The fields are empty again. | MAN-05_wrong-password.png | | |
| MAN-06 | SR-04; automated: `AuthenticationLockoutSecurityTest` (its test ids are not listed in docs/assurance - VERIFY MANUALLY) | `client_charlie` not locked. **Do this test last (0.6).** | 1. Enter `client_charlie` with a wrong password 5 times in a row (5 separate submissions; keep inside one minute to stay under the 10-per-minute login limit).<br>2. Enter the **correct** password. | Every attempt, including the 5th and the one with the correct password, shows the same "Invalid username or password"; there is **no separate lockout message** (by design, anti-enumeration). The account stays locked for 15 minutes. As `admin_auditor`, `Users` page shows `Locked` in the Locked column for `client_charlie` (check this). | MAN-06_lockout-generic-message.png | | |
| MAN-07 | FR-01 | Signed in as any role | 1. Click **Sign Out** in the header.<br>2. Press the browser Back button.<br>3. Open `http://localhost:8080/dashboard`. | After step 1: URL `/login?logout=true`, blue message "You have been successfully logged out.". After steps 2-3: no protected page content is shown; you land on `/login`. (Responses carry `Cache-Control: no-store`; whether Back shows a cached copy is `UNCONFIRMED - check while testing`.) | MAN-07_logout.png | | |
| MAN-08 | SEC-COOKIE-02 | Signed out | 1. Open `/login`, press Ctrl+Shift+R.<br>2. Log in as `analyst_bob`.<br>3. Sign out, hard reload `/login`, log in again. | Both logins reach `/dashboard`. In DevTools -> Application -> Cookies the `JSESSIONID` **value changed** between the login page and after login (do not screenshot the value). | MAN-08_fresh-login.png | | |
| MAN-09 | F-010; SEC-ERR (CSRF 403 page); UI-ERR-02 | Signed out | **A. Provoke on purpose.** 1. Open `/login` (do not submit).<br>2. F12 -> Application -> Cookies -> delete `JSESSIONID`.<br>3. Enter valid credentials and click **Sign In**.<br>4. Click the link on the error page.<br>**B. If the 403 appears by itself**, record: the time (to the second), the page text, the correlation id on the page, the status in DevTools -> Network (request `login`), whether `JSESSIONID` existed before submitting, how long the login page had been open, whether the app was restarted after the page was opened, and the profile used to start the app. | A: page "HTTP 403", heading "Forbidden", text "This request was refused.", an "Incident Correlation ID" (a UUID), and a link **Back to login** (no "Return to Dashboard"). The link goes to `/login`; logging in then works. The page source has no `;jsessionid`. B: record only; **cause `UNCONFIRMED`**. Candidate causes to check: stale CSRF token because the session cookie was cleared, expired (idle timeout 15 minutes) or lost by an app restart; an app started without the `local` profile (cookie `Secure` over http, `UNCONFIRMED`). A login-limit block is a different page ("HTTP 429"). | MAN-09_login-403.png | | |

### Area b - Session cookie and `;jsessionid`

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-10 | SR-05; SEC-COOKIE-01, SEC-COOKIE-03 | Signed in (any role), local profile | 1. F12 -> Application -> Cookies -> `http://localhost:8080`.<br>2. Look at the `JSESSIONID` row (columns Path, Expires, HttpOnly, Secure, SameSite). | Exactly one cookie, `JSESSIONID`. Path `/`. Expires "Session". **HttpOnly checked. SameSite `Strict`. Secure NOT checked** (local http profile; `Secure` is expected only on prod-like). No remember-me cookie, no other cookie. Hide the Value column before the screenshot. | MAN-10_cookie-flags.png | | |
| MAN-11 | F-010; SEC-SESSURL-01..04 | Signed out | 1. Open `view-source:http://localhost:8080/login` and search (Ctrl+F) for `jsessionid`.<br>2. Repeat for the 403 page from MAN-09 (right-click -> View page source).<br>3. Look at the address bar after login and after navigating. | No match for `jsessionid` (any case) in either page source; no `;jsessionid=` in any address bar, link or redirect. Stylesheet link is `/css/app.css`; form action is `/login`. | MAN-11_no-jsessionid.png | | |

### Area c - Concurrent session cap

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-12 | SR-05; SEC-SESSION-01, SEC-SESSION-02; F-007; configured `casevault.session.max-per-user=3` | `analyst_bob`; four separate browser contexts (cookies are shared inside one context): **(1)** Chrome normal window, **(2)** Chrome Incognito window, **(3)** Edge normal window (or Firefox), **(4)** a second Chrome profile (Profile menu -> Add) or Edge InPrivate | 1. Log in as `analyst_bob` in context 1, then 2, then 3, then 4, in this order.<br>2. In each context reload `/dashboard` (F5).<br>3. In context 1 click any sidebar or header link. | Contexts 2, 3 and 4 still show the dashboard. Context 1 (the **oldest**) is redirected to `/login?expired=true` with the red message "Your session has expired. Please log in again.". The 4th login itself was not refused. Signing in again in context 1 works (it then expires the next-oldest). | MAN-12_session-cap-expired.png | | |

### Area d - Security headers

Use F12 -> Network, reload the page, click the document request, tab **Headers** -> **Response Headers**. Cross-check: `HeaderAuditTest` (SEC-HDR-01), `SecurityConfig`.

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-13 | SR-09; SEC-HDR-01 | Signed out | 1. Open DevTools -> Network, then load `http://localhost:8080/login`.<br>2. Select request `login` and read the response headers.<br>3. Select `app.css` and read its headers. | `Content-Security-Policy` is sent **twice** (DevTools may show them joined): (1) `default-src 'self'; frame-ancestors 'none'; object-src 'none'` and (2) `base-uri 'self'; form-action 'self'; script-src 'self'; style-src 'self'`. No `unsafe-inline`, no `unsafe-eval`. Also: `X-Content-Type-Options: nosniff`; `X-Frame-Options: DENY`; `Referrer-Policy: strict-origin-when-cross-origin`; `Permissions-Policy` containing `camera=()`, `microphone=()`, `geolocation=()`; `Cross-Origin-Opener-Policy: same-origin`; `Cross-Origin-Resource-Policy: same-origin`; `X-Correlation-ID` = a UUID; `Cache-Control` containing `no-store` (also on `app.css`). **`Strict-Transport-Security` absent** (http profile). The README and `docs/requirements.md` (clarification under SR-09) now state that there is no nonce: confirm that no `nonce-` appears in either CSP header. | MAN-13_headers-login.png | | |
| MAN-14 | SR-09; SEC-HDR-01 | Signed in as `analyst_bob` | Repeat MAN-13 for `dashboard`, then for one error page (open `/no-such-page`). | Same header set as MAN-13 on `/dashboard` and on the 404 page; each response has its own `X-Correlation-ID`; the 404 page shows the same id as the header. | MAN-14_headers-dashboard.png | | |

### Area e - Case workflow per role

Use one case through the whole area. Role steps are in order; keep `client_charlie` and `manager_alice` in separate browser contexts (normal and Incognito) to avoid signing out and in.

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-15 | FR-04; SEC-CASE-12 | `client_charlie` | 1. Sidebar -> **Report Incident** (`/cases/new`).<br>2. Title `Manual test case 1`, category Ransomware, severity High.<br>3. Click **Submit Incident Report**. | Redirect to `/cases/<uuid>`. Green message "Case created successfully: Manual test case 1". Status badge OPEN, severity HIGH. Tabs: Overview, Investigation Notes (0), Remediation Actions (0), Evidence (0), Reports. No assignment or status form (client). The case appears in **Cases**. | MAN-15_case-created.png | | |
| MAN-16 | FR-05; SEC-CASE-03 | `manager_alice`; case from MAN-15 | 1. **Cases** -> open the case (an internal manager sees all cases).<br>2. In "Analyst Triage Assignment" choose `analyst_bob`, click **Assign Investigator**. | Message "Investigator assigned successfully."; status OPEN -> ASSIGNED; "Assigned Lead Investigator" shows `analyst_bob`. | MAN-16_assigned.png | | |
| MAN-17 | FR-06; SEC-CASE-01, SEC-CASE-02 | `analyst_bob`; case assigned | 1. **Cases**: the case is listed (before assignment it was not).<br>2. Open it; in "Lifecycle Transition (FR-06)" choose IN_PROGRESS, click **Transition Status**.<br>3. Repeat with PENDING_REVIEW.<br>4. Notes tab: add a note ("Add Note"); Actions tab: add an action ("Record Action"), then set its status and click **Update**. | Messages: "Case status transitioned to IN_PROGRESS", then "... to PENDING_REVIEW"; "Investigation note appended."; "Remediation action recorded."; "Action status updated to ...". At PENDING_REVIEW the analyst has **no** status form any more. | MAN-17_analyst-workflow.png | | |
| MAN-18 | FR-06; SEC-CASE-02 | `manager_alice` | 1. Open the case (PENDING_REVIEW). In "Next Allowed State" note the options.<br>2. Choose CLOSED and click **Transition Status**. | Options offered are exactly IN_PROGRESS and CLOSED. After CLOSED: message "Case status transitioned to CLOSED" and no further transitions. | MAN-18_manager-closed.png | | |
| MAN-19 | F-003; SEC-HDR-404-01; SEC-AUTHZ (see `authorisation-tests.md`) | `analyst_bob` (repeat with `manager_alice`) | Open `http://localhost:8080/cases/new`. | **403**: page "HTTP 403", heading "Forbidden", text "Only clients can create incidents", correlation id, link **Return to Dashboard**. (Visible object / forbidden action = 403, F-003.) | MAN-19_forbidden-403.png | | |
| MAN-20 | SR-02, SR-07; F-003; SEC-CASE-11, SEC-EVID-AUTHZ-02 | (a) `admin_auditor`; (b) `analyst_bob` with a case NOT assigned to him (create a second case as `client_charlie` and do not assign it); (c) any signed-in user | (a) Open `/cases`.<br>(b) Open `http://localhost:8080/cases/<uuid of the unassigned case>` (copy the UUID from the client's case page, "Forensic Case Reference ID").<br>(c) Open `/cases/00000000-0000-4000-8000-000000000000`. | All three show **404**: "HTTP 404", heading "Not Found", short message (exact wording `UNCONFIRMED - check while testing`), correlation id, **Return to Dashboard**. (b) and (c) look the same: an invisible object and a missing object are indistinguishable. | MAN-20_not-found-404.png | | |
| MAN-21 | FR-06; SEC-CASE-01 (optional) | `manager_alice`, a case at IN_PROGRESS (create one) | 1. DevTools -> Elements; in the "Next Allowed State" `<select>` change one `<option value="...">` to `CLOSED` (this edits only your own browser).<br>2. Submit. | Server refuses: **400** error page "Bad Request" with a message like "Illegal status transition from IN_PROGRESS to CLOSED"; status unchanged. | MAN-21_illegal-transition.png | | |
| MAN-22 | SR-02; F-003; DEMO-LOCAL-02; SEC-AUTHZ-01..11, SEC-EVID-AUTHZ-01 | Local profile (demo data): organisation A = ORG_ACME (`client_charlie`), organisation B = "Demo Client Org B" (`demo_client_b`, one case titled "DEMO case of Demo Client Org B (synthetic demo data)"); `admin_auditor` | 1. Context 1: sign in as `demo_client_b`, **Cases**: the DEMO case is listed. Open it and copy the UUID from "Forensic Case Reference ID".<br>2. Context 2: sign in as `client_charlie`, **Cases**: the DEMO case is **not** listed.<br>3. As `client_charlie` open `http://localhost:8080/cases/<UUID of the DEMO case>` and then `...?tab=evidence`; also open `http://localhost:8080/cases/00000000-0000-4000-8000-000000000000`.<br>4. As `client_charlie` create a case, copy its UUID; as `demo_client_b` open `/cases/<that UUID>`.<br>5. As `admin_auditor`: **Audit log** -> Event type `ACCESS_DENIED` -> **Filter**. | Step 3 and 4: **404** (never 403) - "HTTP 404", heading "Not Found", correlation id, **Return to Dashboard**; the page for the foreign case looks the same as for the all-zero UUID (existence is not revealed). Step 5: one new `ACCESS_DENIED` row per masked access, with the Case id of the foreign case (reason code expected `NOT_VISIBLE`, `UNCONFIRMED - check while testing`); no case title anywhere in the audit log. | MAN-22_cross-tenant-404.png | | |

### Area f - Evidence

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-23 | SR-11, FR-08; SEC-EVID-WEB (see `evidence-upload-tests.md`) | `client_charlie`, own case, files from 0.5 | 1. Case -> **Evidence** tab.<br>2. "Evidence file": choose `ok-evidence.txt`.<br>3. Click **Upload encrypted evidence**. | Message "Evidence uploaded successfully."; list shows `ok-evidence.txt`, its size in bytes, `SHA-256:` followed by 12 hex characters, "Uploaded by: client_charlie", a time, and a **Download** button. The first 12 characters equal the start of `Get-FileHash` output from 0.5. | MAN-23_upload-ok.png | | |
| MAN-24 | SR-11; SEC-EV-VAL-002 through SEC-EV-VAL-010 | as MAN-23 | Upload `fake.exe`. | **400** page "Bad Request" with message `File extension 'exe' is not permitted.`; nothing added to the list. | MAN-24_blocked-type.png | | |
| MAN-25 | SR-11 | as MAN-23 | Upload `disguised.png` (text content named .png). | **400** page; message names a MIME mismatch (expected like `MIME type mismatch: extension '.png' does not match detected content type 'text/plain'`; exact wording `UNCONFIRMED - check while testing`); nothing added. | MAN-25_mime-mismatch.png | | |
| MAN-26 | SR-11; SEC-EVID-WEB-05 (validator rule); the servlet multipart limit is covered by `GlobalExceptionHandler` tests per evidence-upload-tests.md | as MAN-23 | Upload `too-big.txt` (11 MB; limit 10 MB). | Error page with heading "Payload Too Large", text "File upload exceeds the maximum allowed size of 10MB.", and HTTP status **400** in DevTools -> Network (the code answers 400, not 413). Nothing added. | MAN-26_oversize.png | | |
| MAN-27 | FR-09; SEC-EVID-DL-01..05 | `client_charlie` (then `analyst_bob` on an assigned case) | 1. Click **Download** for `ok-evidence.txt`.<br>2. In PowerShell: `Get-FileHash "$env:USERPROFILE\Downloads\ok-evidence.txt" -Algorithm SHA256`. | The browser downloads (does not display) a file with the original name. Its SHA-256 equals the one from 0.5 and starts with the 12 characters shown on the page. DevTools: `Content-Disposition: attachment...`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`. | MAN-27_download.png | | |
| MAN-28 | FR-13; SEC-EVID-WEB-06, SEC-EVID-WEB-07 (audit events), SEC-AUDIT-UI-06 | `admin_auditor` after MAN-23, 24, 27 | **Audit log** -> filter "Event type" `EVIDENCE_UPLOADED`, **Filter**; repeat for `EVIDENCE_REJECTED` and `EVIDENCE_DOWNLOADED`. | Rows with columns Sequence, Time (UTC), Event type, User id, Case id, Reason code. Uploaded: `ACCEPTED`. Rejected (MAN-24, 25): `VALIDATION_REJECTED`. Downloaded: `INTEGRITY_VERIFIED`. **No file name, no file content, no username, no hash** anywhere on the page. Whether the oversize upload (MAN-26) leaves a row is `UNCONFIRMED - check while testing` (it is refused by the multipart limit before the controller). | MAN-28_audit-evidence.png | | |
| MAN-29 | FR-08; SEC-EVID-WEB-03 | `manager_alice`, then `admin_auditor` | Open the case's Evidence tab as the manager; try `/cases/<uuid>?tab=evidence` as the auditor. | Manager: sees the list and **Download**, but **no "Upload Evidence" form**. Auditor: 404 (as MAN-20 a). | MAN-29_no-upload-for-manager.png | | |

### Area g - Reports

Use the assigned case from MAN-16 (reopen it by creating a new case and assigning it if MAN-18 closed it, because reports cannot be created on a closed case).

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-30 | FR-11; SEC-REPORT-WEB-01..08 (see report-tests.md) | `analyst_bob`, assigned case not closed | 1. Case -> **Reports** tab.<br>2. In "New draft report" type `Draft body line 1` + Enter + `line 2`, click **Create draft**. | Message "Draft report created."; detail page "Incident report" with progress "1. Draft - Current step", badge "Draft", "Edit draft" card with **Save draft**, and **Submit for approval**. Line break kept. | MAN-30_draft.png | | |
| MAN-31 | FR-12; SEC-REPORT-WEB-05 | `analyst_bob` | Click **Submit for approval**. | Message "Report submitted for approval."; badge "Submitted"; stepper "2. Submitted - Current step"; edit form and Submit button gone. | MAN-31_submitted.png | | |
| MAN-32 | FR-12, SR-06; SEC-REPORT-WEB-05 | `manager_alice` (a user who is **not** the author) | Open the case -> Reports -> the report -> **Approve report**. | Message "Report approved."; badge "Approved"; "Approved (UTC)" time shown. | MAN-32_approved.png | | |
| MAN-33 | SR-06; SEC-REPORT-WEB-05 | `analyst_bob` viewing his own SUBMITTED report (create another one) | Look for an approve control on the report page. | No **Approve report** button for the analyst (the button exists only for a MANAGER who is not the author). A real self-approval attempt **cannot be made through the UI with the bootstrap users** (only analysts write reports, only managers approve); the author rule (`The author of a report cannot approve it`) is covered by the automated tests only. `UNCONFIRMED - check while testing` if you can craft a POST yourself. | MAN-33_no-approve-for-author.png | | |
| MAN-34 | FR-12, SR-02; SEC-REPORT-WEB-05, SEC-REPORT-WEB-AUTHZ-01 | `client_charlie`; one SUBMITTED and one APPROVED report on the client's case | Case -> **Reports**. Then open the SUBMITTED report by typing its URL `/cases/<case>/reports/<report-uuid>` (copy it from the analyst's address bar). | List shows **only the Approved** report. Before any approval: "No reports to show" and "Approved reports appear here once a manager has approved them." The SUBMITTED report URL gives **404**. | MAN-34_client-reports.png | | |
| MAN-35 | SR-08; SEC-CASE-12; the escaped-report-text row in report-tests.md | `analyst_bob` then `manager_alice` | 1. Create a draft whose text is exactly `<script>alert(1)</script> <b>bold?</b> <img src=x onerror=alert(2)>`.<br>2. View it as analyst and as manager; open DevTools -> Console and Elements. | The text is displayed **literally**, tags visible as characters. No alert dialog. "bold?" is not bold. No broken image. In Elements the text is an escaped text node. The edit textarea also shows it literally. | MAN-35_report-xss.png | | |
| MAN-36 | SR-08; SEC-CASE-12 | `client_charlie` for the title; `manager_alice` for the note | 1. Create a case with title `<b>title</b><script>alert(3)</script>`.<br>2. As the manager add the note `<img src=x onerror=alert(4)>`. | Title (list, case page, browser tab title) and note shown literally; no dialog; no console CSP violation caused by page content. | MAN-36_title-note-xss.png | | |

### Area h - Auditor pages

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-37 | FR-13; SEC-AUDIT-UI-01..10 | `admin_auditor` | 1. **Audit log**.<br>2. Look at "Chain status", head line, and the table.<br>3. Filter by Event type `LOGIN_SUCCESS`, then **Clear**. | Heading "Audit Log"; chain badge "Not verified yet" until verified; "Head: sequence N, HMAC starts with ...". Table columns as MAN-28. No usernames, case titles, notes, file names or hashes. Newest first. | MAN-37_audit-list.png | | |
| MAN-38 | FR-13, SR-13; SEC-AUDIT-UI-11, SEC-AUDIT-UI-12 | `admin_auditor` | Click **Verify chain now**. | Redirect to `/audit`; badge "Chain valid" with "N events verified at <time>". A new row `AUDIT_CHAIN_VERIFIED` appears. | MAN-38_chain-valid.png | | |
| MAN-39 | FR-14; SEC-ADMIN-09, SEC-ADMIN-10 | `admin_auditor`; `client_charlie` signed in in another context | 1. **Users**; in the `client_charlie` row click **Disable**.<br>2. On "Disable account" check Account/Role/Organisation/Status, click **Confirm disable**.<br>3. In the other context click any link.<br>4. Try to log in as `client_charlie`.<br>5. Back as auditor click **Enable** on that row. | Step 2: green "Account disabled. Active sessions of that user are ended.", row badge "Disabled". Step 3: redirect to `/login?disabled=true` with "Account is deactivated or disabled. Contact administrator.". Step 4: generic "Invalid username or password". Step 5: "Account enabled."; login works again. | MAN-39_disable-enable.png | | |
| MAN-40 | FR-14; SEC-ADMIN-11 | `admin_auditor`; `analyst_bob` signed in elsewhere | Users -> **Revoke sessions** on the `analyst_bob` row. In the other context click a link. | Green "Sessions revoked. The user must sign in again."; the other context goes to `/login?expired=true`; `analyst_bob` can log in again; the account is still Enabled. | MAN-40_revoke.png | | |
| MAN-41 | FR-14; SEC-ADMIN-06, SEC-ADMIN-07, SEC-ADMIN-08; DEMO-LOCAL-03 | Local profile (demo data). Context 1: `admin_auditor`; context 2: `demo_admin_2` (second AUDITOR_ADMIN, created only in the local profile) | 1. Context 1: **Users** -> row `demo_admin_2` -> **Disable** -> **Confirm disable**.<br>2. Context 2: click any link.<br>3. Context 1: on the `admin_auditor` row click **Disable** -> **Confirm disable**.<br>4. Context 1: click **Revoke sessions** on your own row.<br>5. Try to log in as `demo_admin_2`.<br>6. Context 1: **Enable** `demo_admin_2` again (restores the demo state). | Step 1: green "Account disabled. Active sessions of that user are ended.". Step 2: redirect to `/login?disabled=true` with "Account is deactivated or disabled. Contact administrator.". Step 3: red "You cannot disable your own account." (self-disable is checked first). Step 4: red "You cannot revoke your own sessions with this action.". Step 5: generic "Invalid username or password". Throughout, exactly one administrator (`admin_auditor`) stays Enabled, so the system is never left without an administrator. The message "The last active administrator cannot be disabled." is **not reachable by clicking one step at a time** (the actor is always another active administrator, so at least two are active); it only matters when two administrators disable each other at the same moment (automated concurrency test SEC-ADMIN-08). Optional: click **Confirm disable** in both contexts within about a second - expected: not both succeed; the exact page the loser sees is `UNCONFIRMED - check while testing`. | MAN-41_two-admins.png | | |
| MAN-42 | FR-15; SEC-ADMIN-01 | `admin_auditor` | 1. **Health**.<br>2. View source and search for `jdbc`, `H2`, `.local-data`, `C:\`, `Spring`, `Java`, `version`. | Table rows: "Database reachable" Yes, "Evidence storage writable" Yes, "Audit chain (last verification)" (Not verified yet / Chain valid), "Audit head sequence" (number or "No events"). Text "The chain is not verified when this page loads" with a link to the audit log. **No** paths, versions, host names or exception text. | MAN-42_health.png | | |

### Area i - Auditor dashboard status (F-009)

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-43 | F-009; UI-DASH-01..05 (`DashboardStatusTest`) | `admin_auditor`, healthy system | 1. Open `/dashboard`: read the three cards.<br>2. Run **Verify chain now** on `/audit`, return to `/dashboard`.<br>3. View source: search `ENFORCED`, `Telemetry Online`. | Card "Audit Log Integrity (last verification)" shows "Not verified yet", after step 2 "Chain valid". Card "Access Boundary (control description)" is plain text, no status word. Card "System Health (checked when this page loaded)" shows **HEALTHY** with a link to the Health page. The old constants are gone. | MAN-43_dashboard-health.png | | |
| MAN-44 | F-009 | - | A non-HEALTHY state (DEGRADED, DOWN, UNKNOWN): the repository documents **no safe way** to produce one by hand. Record "covered by automated `DashboardStatusTest` only". Do not stop the database or change folder permissions on your own initiative. | Not applicable manually. | - | | |

### Area j - Error pages and rate limit

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-45 | UI-ERR-01; SEC-ERR-01 | Signed out (no `JSESSIONID`) | Open `http://localhost:8080/css/no-such-file.css`. (An unknown path such as `/no-such-page` only redirects a signed-out visitor to `/login`; `/css/**` is public.) | "HTTP 404", "Not Found", "The requested page or item was not found.", correlation id, and a link **Back to login**. **No** "Return to Dashboard". The link goes to `/login` with no `;jsessionid`. | MAN-45_404-signed-out.png | | |
| MAN-46 | UI-ERR-03; SEC-ERR-01, SEC-HDR-404-01 | Signed in as `analyst_bob` | Open `/no-such-page-test`. | "HTTP 404", the same safe text, correlation id, and a link **Return to Dashboard** (to `/dashboard`). **No** "Back to login". The id in the page equals the `X-Correlation-ID` response header (Network tab). | MAN-46_404-signed-in.png | | |
| MAN-47 | UI-ERR-02, UI-ERR-04 | Signed out, then signed in | Signed out: reproduce MAN-09 A (delete `JSESSIONID`, submit the login form). Signed in: open `/cases/new` as `analyst_bob` (MAN-19). | Signed out: 403 page with **Back to login**. Signed in: 403 page with **Return to Dashboard**. Never both links. | MAN-47_403-both.png | | |
| MAN-48 | SR-15; SEC-RATE-WEB-01, SEC-RATE-WEB-03; UI-RATE-01 (signed-out 429); configured `casevault.ratelimit.login-limit=10` per 60 s | Signed out, no login attempts in the last 60 seconds. **Do this last (0.6).** | 1. Open `/login`, F12 -> Network.<br>2. Submit the form with username `nobody_x` and any password 11 times quickly (unknown user, so no real account is locked).<br>3. Look at the 11th response. | Attempts 1-10 return to `/login?error=true`. The 11th shows "HTTP 429", "Too many requests", "Try again in about N seconds." (N between 1 and 60), a correlation id, and a link **Back to login**; response header `Retry-After: N`; status 429. After about a minute the login form works again. A **signed-in** 429 page (link "Return to Dashboard") needs 61 searches in a minute (`search-limit=60`) and is covered by automated UI-RATE-02 only. | MAN-48_429.png | | |

### Area k - Accessibility

| ID | Link | Preconditions | Steps | Expected result | Screenshot | Result | Tester notes |
|---|---|---|---|---|---|---|---|
| MAN-49 | F-011; UI-A11Y-FOCUS-01 | Signed out, mouse not used | 1. Open `/login` (the username field has `autofocus`).<br>2. Press Shift+Tab once, then Tab through the page with Tab / Shift+Tab; submit with Enter in the password field. | A "Skip to login form" link appears at the top left when focused; Enter on it moves to the form. Every focus stop shows a **visible teal ring (about 3 px)**. Order: username, password, Sign In. Enter submits; error message appears as text. | MAN-49_keyboard-login.png | | |
| MAN-50 | F-011; UI-A11Y-NAV-01 | Signed in as `client_charlie` with at least 2 cases | On `/cases` use only the keyboard: Tab through skip link, brand link, Sign Out, sidebar links, filter fields, Filter, Clear, case title links, **View** buttons, pagination. Operate a filter (Space/Enter on the select, type in the field). | All stops have the visible ring, including on the dark header and sidebar. Order follows the page. Current sidebar item "Cases" is marked (DevTools -> Elements: `aria-current="page"`). Filtering works without a mouse. | MAN-50_keyboard-cases.png | | |
| MAN-51 | F-011 | `analyst_bob` on an assigned case | Keyboard only on case detail: tabs (Overview, Notes, Actions, Evidence, Reports), add a note, change the case status, change an action's status. | All controls reachable and operable with Tab, Enter, Space; the open tab has `aria-current="page"`; every select/field has a visible label or a name in the Accessibility pane. | MAN-51_keyboard-case-detail.png | | |
| MAN-52 | F-011 | `admin_auditor` | Keyboard only on `/admin/users`: reach **Disable**, **Revoke sessions**, open the confirm page, **Cancel**. | Ring visible on each; the confirm page has **Confirm disable** and **Cancel**; nothing needs the mouse. | MAN-52_keyboard-users.png | | |
| MAN-53 | F-011 | Any signed-in page | 1. Reload the page, press Tab once.<br>2. Press Enter on the skip link.<br>3. Press Tab. | "Skip to main content" appears at the top; after Enter the next Tab lands on the first control **inside** the main area (not in the sidebar). `UNCONFIRMED - check while testing`: on older Safari focus may not move because `<main>` has no `tabindex`. | MAN-53_skip-link.png | | |
| MAN-54 | F-011 | `client_charlie`, `/cases` and a case page | Zoom to 200% (Ctrl+Plus). | No overlapping or cut-off text; every button still reachable; page does not need sideways scrolling except inside the table container. `UNCONFIRMED - check while testing`. | MAN-54_zoom-200.png | | |
| MAN-55 | F-011 | Same pages | DevTools device toolbar, width 375 px. | Content readable and operable. The fixed 240 px sidebar (`.app-sidebar`) has no narrow-width rule, so it may squeeze the content: **record what happens** (`UNCONFIRMED - check while testing`). | MAN-55_narrow-375.png | | |
| MAN-56 | F-011; UI-A11Y-ACTIONS-01 | `/cases` as client (2+ cases) and `/admin/users` as auditor | F12 -> Elements; click a **View** link; open the **Accessibility** pane (right side, may be under ">>") -> Computed Properties -> **Name**. Repeat for **Disable**, **Enable**, **Revoke sessions** on two different users, **Download** on an evidence row, and the action **Update** button. | Names are distinct per row and contain the target: `View case <title>`, `Disable user <username>`, `Enable user <username>`, `Revoke sessions of user <username>`, `Download evidence <file name>`, `Update status of action: <description>`. | MAN-56_accessible-names.png | | |
| MAN-57 | F-011; UI-A11Y-CONTRAST-01 | Pages with badges and alerts | Visually check: case severity/status badges (HIGH and PENDING_REVIEW amber text, LOW and CLOSED green text), success message, an input border, secondary button border. | Text readable without strain; input and secondary-button borders clearly visible. (The measured ratios are in `ui-inventory.md` section 11; this is only a visual spot check.) | MAN-57_contrast-visual.png | | |

Total cases: 57 (a: 9, b: 2, c: 1, d: 2, e: 8, f: 7, g: 7, h: 6, i: 2, j: 4, k: 9). Cases MAN-22, MAN-44 and parts of MAN-33, MAN-41 and MAN-48 are "cannot be run by hand"; they are listed so the tester records that fact.

## 2. Screenshot convention

- Folder: `docs/evidence/screenshots/` (the folder is kept in git with a `.gitkeep`).
- File name: `MAN-xx_<short-description>.png`, as in the Screenshot column.
- Show the **browser address bar with the full URL** and, when the test is about it, the relevant DevTools panel (Application -> Cookies, Network -> Headers, Accessibility pane).
- Include the date and time if possible (Windows taskbar clock visible, or the correlation id and time on the page).
- **Do not** capture or leave readable: passwords (the clipboard method in 0.2 avoids typing them; password fields show dots), the `JSESSIONID` value (hide the Value column), bootstrap credentials file or console banner. Blur anything sensitive before saving. Do not commit files you have not looked at.
- One screenshot per test case at least; for FAIL results also capture the page text and the correlation id.

## 3. Results

### 3.1 Results summary (tester fills in)

| Area | Cases | PASS | FAIL | Not run | Notes |
|---|---|---|---|---|---|
| a Login and logout | 9 | | | | |
| b Cookie and `;jsessionid` | 2 | | | | |
| c Session cap | 1 | | | | |
| d Security headers | 2 | | | | |
| e Case workflow | 8 | | | | |
| f Evidence | 7 | | | | |
| g Reports | 7 | | | | |
| h Auditor pages | 6 | | | | |
| i Auditor dashboard status | 2 | | | | |
| j Error pages and rate limit | 4 | | | | |
| k Accessibility | 9 | | | | |
| **Total** | **57** | | | | |

Tester name: ______________  Date: ______________  Browser and version: ______________  Windows build: ______________  App started with: ______________  Commit tested (`git rev-parse --short HEAD`): ______________

### 3.2 Defects found (tester fills in)

| ID | Description | Severity | Linked finding / test case | Status |
|---|---|---|---|---|
| DEF-01 | | | | |
| DEF-02 | | | | |
| DEF-03 | | | | |

## 4. How this evidence is used

The automated tests (`docs/evidence-index.md`) show that the server behaves correctly for the requests the tests send. This guide covers what they cannot: what a real browser stores, sends and shows (cookies in DevTools, headers, keyboard focus, zoom, screen-reader names). Completed rows and their screenshots may be cited in the report and the viva as the tester's own observations, together with the date, browser and commit in 3.1. A row without a recorded result, or marked `UNCONFIRMED`, must not be presented as verified. Defects found are logged in 3.2 and in `findings-log.md` before they are discussed.
