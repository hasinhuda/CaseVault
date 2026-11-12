# UI inventory (Phase 9A) - DRAFT

Read-only inventory of the current CaseVault web UI, made by reading `src/main/resources/templates`, `src/main/resources/static`
and the controllers. No source file was changed. No browser was used: everything below comes from reading HTML, CSS and Java,
so anything about real rendering is marked VERIFY MANUALLY. Later UI phases (9B-9D) must keep: strict CSP (no inline style,
script or handler, no `style=""`), `th:text` only, CSRF token on every POST form, reports and notes as plain text, no external
CDN, font or script.

## 1. Files

| Kind | Count | Files |
|---|---|---|
| Thymeleaf templates | 14 (13 pages + 1 fragment file) | `layout.html` (fragments), `login.html`, `dashboard.html`, `error.html`, `rate-limited.html`, `cases/list.html`, `cases/create.html`, `cases/detail.html`, `reports/list.html`, `reports/detail.html`, `audit/list.html`, `admin/users.html`, `admin/disable-confirm.html`, `admin/health.html` |
| Static files | 1 | `static/css/app.css` (860 lines; no JavaScript, no images, no fonts) |
| Other | 1 | `templates/.gitkeep` |

## 2. Pages, URLs, roles, forms

CSS: every page uses only `/css/app.css`. "Role" is what the server allows; the UI hides links, but the server re-checks (404 for objects the caller may not see).

| Template | URL(s) and controller method | Who reaches it | Forms (method, CSRF) |
|---|---|---|---|
| `login.html` | `GET /login` `AuthController.login`; `POST /login` (Spring Security) | Everyone (permitAll) | 1 POST login, CSRF yes |
| `dashboard.html` | `GET /dashboard` `AuthController.dashboard` | Any signed-in user; content differs per role | 1 POST logout (own copy of header), CSRF yes |
| `cases/list.html` | `GET /cases` `CaseWebController.listCases` | CLIENT, ANALYST, MANAGER. AUDITOR_ADMIN gets 404 | 1 GET filter form |
| `cases/create.html` | `GET /cases/new` `newCaseForm`; `POST /cases` `createCase` | CLIENT only (others: 404 for auditor, 403 for analyst/manager) | 1 POST, CSRF yes |
| `cases/detail.html` | `GET /cases/{id}?tab=overview/notes/actions/evidence` `caseDetail`; POSTs `/cases/{id}/assign`, `/status`, `/notes`, `/actions`, `/actions/{actionId}/status`, `/evidence` (multipart) | Users who may see that case (tenant and role); otherwise 404 | 6 POST (assign, status, note, action, action status, evidence upload), CSRF yes in all 6 |
| `reports/list.html` | `GET /cases/{caseId}/reports` `ReportWebController.list`; `POST /cases/{caseId}/reports` `create` | Case-visible users; CLIENT sees approved reports only; "New draft" form shown to ANALYST | 1 POST, CSRF yes |
| `reports/detail.html` | `GET /cases/{caseId}/reports/{reportId}`; POSTs `.../update`, `.../submit`, `.../approve` | As above; submit/update: author ANALYST; approve: MANAGER who is not the author | 3 POST, CSRF yes |
| `audit/list.html` | `GET /audit` `AuditController`; `POST /audit/verify` | AUDITOR_ADMIN only (service answers 404 to others) | 1 GET filter, 1 POST verify, CSRF yes |
| `admin/users.html` | `GET /admin/users`; POSTs `/admin/users/{id}/enable`, `/revoke-sessions` | AUDITOR_ADMIN only (404 to others) | 2 POST per row, CSRF yes |
| `admin/disable-confirm.html` | `GET /admin/users/{id}/disable-confirm`; `POST /admin/users/{id}/disable` | AUDITOR_ADMIN only | 1 POST, CSRF yes |
| `admin/health.html` | `GET /admin/health` | AUDITOR_ADMIN only | none |
| `error.html` | Rendered by `GlobalExceptionHandler` (400/403/404/405/409/415/500 ...) and by Boot `/error` (permitAll) | Everyone, including signed-out visitors | none |
| `rate-limited.html` | Rendered by `RateLimitFilter` (via `ThymeleafBlockedPageRenderer`) on HTTP 429 | Everyone | none |
| `layout.html` | Not routable; fragments `htmlhead(pageTitle)`, `appheader`, `appsidebar(activeMenu)`, `appfooter` | - | 1 POST logout (in `appheader`), CSRF yes |

POST forms: 18 in templates (17 pages plus the fragment; the dashboard duplicates the logout form). CSRF hidden field present: 18 of 18 (counted per file: `method="post"` vs `_csrf`).

## 3. Layout and fragments

| Page | head | header | sidebar | footer | Notes |
|---|---|---|---|---|---|
| `cases/*`, `reports/*`, `audit/list`, `admin/*` | fragment `htmlhead` | fragment `appheader` | fragment `appsidebar(x)` | fragment `appfooter` | Uses the shared shell |
| `dashboard.html` | **own copy** (hard-coded title) | **own copy** with a top `nav` | **none** (top nav instead) | **own copy**, different text | Duplicates markup; different navigation pattern; no org code in header |
| `login.html` | **own copy** | none | none | none | Acceptable for a login page, but title format differs (`CaseVault - Secure Login` vs `X - CaseVault`) |
| `error.html`, `rate-limited.html` | fragment `htmlhead` | none | none | none | Centered card on dark background, no header or footer |

Flash messages are not a fragment: each page repeats its own `successMessage`/`errorMessage` block (cases/list, cases/detail, reports/list, reports/detail, admin/users; `cases/create` has only the error block; `login` has its own pair; `audit/list` has none for flash, only validation errors). The `role="status"` / `role="alert"` and `aria-live` attributes differ between copies (for example `aria-live="polite"` on an alert in cases, `assertive` in reports, none in admin/users error).

Pages that duplicate markup instead of using a fragment: `dashboard.html` (header, nav, footer), `login.html` (head), and the repeated skip link, flash blocks and "case sections" tab nav (copied in `cases/detail.html`, `reports/list.html`, `reports/detail.html`).

## 4. Navigation audit

Visible navigation per role, taken from `layout.html` (sidebar) and `dashboard.html` (top nav). Brand link `CaseVault` goes to `/dashboard` on all signed-in pages.

| Role | Sidebar (all pages except dashboard) | Dashboard top nav | Missing / odd |
|---|---|---|---|
| CLIENT | Dashboard, Cases, Report Incident | Dashboard, Cases (no "Report Incident" in nav; button in page body) | Dashboard and other pages show different menus |
| ANALYST | Dashboard, Cases | Dashboard, Cases | No link to reports except inside a case |
| MANAGER | Dashboard, Cases | Dashboard, Cases | Same as analyst |
| AUDITOR_ADMIN | Dashboard, "Cases (Quarantined)" (plain span), Audit log, Users, Health | Dashboard, "Cases (Restricted)" (plain span), Audit log, Users, Health | Two different labels for the same restriction; `aria-disabled` on a span has no effect |
| Unauthenticated | none (login page only) | - | Login page has no link elsewhere (fine) |

Back links: `cases/detail` ("Back to Cases"), `reports/list` ("Back to case"), `reports/detail` ("Back to reports"), `cases/create` ("Cancel"), `admin/disable-confirm` ("Cancel"), `admin/users` empty state ("Show the first page"), `audit/list` empty state. The sidebar and brand link give a way home on every signed-in page.

Dead ends: **0 pages without any link out**. Weak spots:

| Page | What the visitor sees | Link offered | Problem |
|---|---|---|---|
| `error.html` (403, 404, 400, 405, 409, 500), signed in | Card with HTTP status, message, correlation id | "Return to Dashboard" only | No header, no sign-out, no link back to the previous place (case, list) |
| `error.html`, **signed out** | Same card | "Return to Dashboard" (`/dashboard`) | No "Back to login" or "Home". The link works only indirectly: `/dashboard` redirects a visitor to `/login`. Label is misleading. A signed-out visitor reaches this page only through `/error`, a missing `/css/**` file, or a CSRF/403 on a POST |
| `rate-limited.html` (429) | HTTP 429, wait seconds, correlation id | "Back to sign in" (`/login`) | Good for signed-out. For a signed-in user the link also goes to `/login`, which does not redirect an authenticated user to the dashboard (the login page is simply shown). Missing: a link to the dashboard |
| 401 on `/api/**` | JSON, no page | - | Not a UI page |

Signed-out requests to any other protected URL get a 302 to `/login` (`LoginUrlAuthenticationEntryPoint`), so a signed-out visitor normally never sees a 403 or 404 page. VERIFY MANUALLY in a browser: the exact page shown for a signed-out CSRF failure.

## 5. Accessibility audit (reading HTML and CSS)

### 5.1 Structure

| Check | Result | Where |
|---|---|---|
| `lang` attribute | Present (`en`) on all 13 pages and layout | - |
| `<title>` | Present on all pages. Formats differ: `X - CaseVault` (fragment), `CaseVault - Secure Login`, `CaseVault - Security Operations Dashboard` | `login.html`, `dashboard.html` |
| One `h1` per page | Yes, exactly one on each page (counted) | - |
| Skipped heading levels | `h1` then `h3` with no `h2`: `cases/list.html` (empty state), `admin/users.html` (empty state). `audit/list.html`/`reports/list.html` have an `h2` first, so they are fine | `cases/list.html:137`, `admin/users.html:77` |
| `<main>` landmark | Present on all pages except `login.html` (uses `div#login-main`) | `login.html` |
| Landmark names | Two navigations on case pages (sidebar `nav` without label inside `aside[aria-label]`, tabs `nav[aria-label="Case Sections"]`); dashboard nav is "Main Navigation" | - |
| Current page in nav | `aria-current="page"` only on the Reports tab (`reports/*`). Sidebar active link and case tabs use a CSS class only, so a screen reader does not hear the current page | `layout.html`, `cases/detail.html` |
| Skip link | Present everywhere (`.skip-link`), visible on focus | - |

### 5.2 Forms and controls

| Check | Result |
|---|---|
| Inputs without `<label for>` | None found. All inputs, selects and textareas have a label. The per-action status `select` has a label whose class is `skip-link` (`cases/detail.html:150`): it is hidden by being moved off-screen (`top:-40px`), which works only by accident; it should use `.sr-only` |
| Placeholders as the only label | None |
| Required fields | `required` attribute is used; no visible "required" marker and no error text next to the field (errors are one banner at the top) |
| Icon-only buttons or links | None found (all controls have text). Arrows `&larr;` are followed by words |
| Repeated identical link text | Case list: each row has two links ("title" and "View"); user table: "Disable", "Revoke sessions" with no user name in the accessible name. A screen reader user cannot tell rows apart from the button alone |
| Tables | All data tables have `<th scope="col">`; `caption.sr-only` on audit, users, health, report list; **no caption on the cases list table**. Health table uses `<th scope="row">` correctly |
| `autofocus` | Only on the login username field (acceptable) |
| Live regions | `role="alert"` plus `aria-live` is used; the mix of `polite`/`assertive` is inconsistent (see section 3) |
| Mouse-only interactions | None: there is no JavaScript at all and no hover-only content. Tabs are plain links; "Disable" goes through a confirmation page |

### 5.3 Focus

`app.css` has no `outline: none` or `outline: 0` (searched). It styles `a:focus, button:focus, input:focus, select:focus, textarea:focus` with a 2px teal outline and 2px offset (lines 69-72). There is **no `:focus-visible`** rule, so the ring also shows after a mouse click (cosmetic). `.form-control:focus` only changes the border colour on top of that. On the dark header and sidebar the teal ring has a contrast of 3.49:1 against navy (enough for a focus indicator at 3:1, but not generous).

### 5.4 Colour contrast

Formula (WCAG relative luminance): each sRGB channel `c` is divided by 255, then `c <= 0.03928 ? c/12.92 : ((c+0.055)/1.055)^2.4`; `L = 0.2126 R + 0.7152 G + 0.0722 B`; ratio = `(L_lighter + 0.05) / (L_darker + 0.05)`. Thresholds: 4.5:1 for normal text, 3:1 for large text (18pt, or 14pt bold) and for UI component boundaries. Values were computed with a throwaway script (not in the repository) from the hex values in `app.css`; the numbers below are the script output.

| Use | Foreground | Background | Ratio | Result |
|---|---|---|---|---|
| Body text | `#0F1B2D` | `#F4F6F8` | 15.95 | pass |
| Card text | `#0F1B2D` | `#FFFFFF` | 17.28 | pass |
| Secondary text (subtitle, labels) | `#475569` | `#FFFFFF` | 7.58 | pass |
| Muted text (`--text-muted`, timeline meta, metadata label) | `#64748B` | `#FFFFFF` | 4.76 | pass (close) |
| Muted text on timeline body | `#64748B` | `#F8FAFC` | 4.55 | pass (close) |
| Link in tables (`.table-link`) | `#0E7C86` | `#FFFFFF` | 4.95 | pass |
| Tab link (inactive / active) | `#475569` / `#0E7C86` | `#FFFFFF` | 7.58 / 4.95 | pass |
| Button primary | `#FFFFFF` | `#0E7C86` | 4.95 | pass |
| Button primary hover | `#FFFFFF` | `#095961` | 8.04 | pass |
| Button secondary | `#0F1B2D` | `#FFFFFF` | 17.28 | pass |
| Button danger / hover | `#FFFFFF` | `#C0392B` / `#A93226` | 5.44 / 6.62 | pass |
| Header nav link / header text | `#CBD5E1` / `#F8FAFC` | `#0F1B2D` | 11.64 / 16.52 | pass |
| Role badge in header | `#F8FAFC` | `#334155` | 9.90 | pass |
| Footer, sidebar heading, org tag | `#94A3B8` | `#0F1B2D` | 6.74 | pass |
| Sidebar link / active | `#CBD5E1` / `#FFFFFF` | `#0F1B2D` / `#1E293B` | 11.64 / 14.63 | pass |
| Alert danger | `#C0392B` | `#FDEDEC` | 4.79 | pass |
| Alert info / badge in_progress | `#0E7C86` | `#E8F8F5` | 4.52 | pass (barely) |
| **Alert success** | `#1E8449` | `#EAFAF1` | **4.37** | **fail (< 4.5), body-size text** |
| **Badge severity LOW / status CLOSED** | `#1E8449` | `#EAFAF1` | **4.37** | **fail (< 4.5), 0.75rem bold** |
| Badge severity MEDIUM | `#B45309` | `#FEF3C7` | 4.51 | pass (barely) |
| **Badge severity HIGH / status PENDING_REVIEW** | `#D68910` | `#FEF9E7` | **2.68** | **fail (< 3 even for large text), 0.75rem bold** |
| Badge severity CRITICAL | `#C0392B` | `#FDEDEC` | 4.79 | pass |
| Badge status OPEN / ASSIGNED | `#475569` / `#0369A1` | `#F1F5F9` / `#E0F2FE` | 6.92 / 5.17 | pass |
| Table header | `#475569` | `#F8FAFC` | 7.24 | pass |
| Metric value (2rem bold, large text) | `#0E7C86` | `#FFFFFF` | 4.95 | pass |
| Report/audit `status-badge` (ok / bad / warn) | `#0F1B2D` | `#EAFAF1` / `#FDEDEC` / `#FEF9E7` | 16.00 / 15.23 / 16.39 | pass (this is the pattern to reuse) |
| Skip link | `#F8FAFC` | `#0F1B2D` | 16.52 | pass |
| Focus ring (teal) on white / on navy | `#0E7C86` | `#FFFFFF` / `#0F1B2D` | 4.95 / 3.49 | pass for 3:1 |
| **Form control and secondary button border** | `#E2E8F0` | `#FFFFFF` | **1.23** | **fail** the 3:1 expected for the boundary of an input (inputs have only a very pale border) |

Colour is never the only signal for severity and status: every badge carries its text (LOW, HIGH, ...), and report states carry a text label.

## 6. Consistency issues

| Area | Finding | Where |
|---|---|---|
| Undefined CSS class | `text-muted` is used in 10 places but **not defined** in `app.css` (only the variable `--text-muted` exists), so the text is not muted | `dashboard.html`, `audit/list.html`, `reports/list.html`, `reports/detail.html` |
| Style outside its scope | `.badge-role` is styled only under `.user-profile`; the same class in the note timeline (`cases/detail.html:100`) is unstyled | `app.css:133`, `cases/detail.html` |
| Dead CSS | `.badge-open`, `.badge-assigned`, `.badge-in_progress`, `.badge-pending_review`, `.badge-closed`, `.badge-low/medium/high/critical` (old badge set) are not used; templates use `badge-status-*` and `badge-severity-*` | `app.css:201-210` |
| Two badge systems | Case severity/status: `.badge badge-status-*`, `.badge-severity-*` (text and colour). Audit, users, health, reports: `.status-badge status-ok/bad/warn/neutral`. Report status (Draft/Submitted/Approved) and case status look different; case action status reuses `badge-status-closed` for COMPLETED | `cases/*`, `reports/*`, `admin/*` |
| Status wording | Cases show `IN PROGRESS` (badge) but filter options and select options show `IN_PROGRESS`; action select shows raw enum values; case detail transition select shows raw `st` | `cases/list.html`, `cases/detail.html` |
| Button classes | Mostly `btn btn-primary/secondary/danger`; `btn-sm` used inconsistently (primary page actions are full size in the header, forms use `btn-sm`); Cancel is `btn-secondary ml-8` using a margin utility; "Sign Out" is `btn-secondary btn-sm` | all |
| Date format | All timestamps are printed as raw `Instant` (`2026-11-12T10:15:30.123Z`) with no formatting. Labels differ: some say "(UTC)", case pages do not | `cases/list`, `cases/detail`, `reports/*`, `audit/list`, `admin/users` |
| Empty states | Four styles: heading + text + button (cases list, audit, users), text only (notes, actions, evidence), heading + text by role (reports), none (health). Wording: "No incident cases found", "No audit events found", "No users on this page", "No reports to show" | - |
| Flash/error messages | Success flash exists on cases, reports, admin; none on audit verify (result is shown in the chain-status block). The generic `error.html` uses `alert-danger`; login uses alert-danger/alert-info | - |
| Labels and copy | Requirement ids are visible to users: "(FR-04)", "(FR-06)", "(SR-07)", "(SR-15)" in headings and subtitles. "Cases (Quarantined)" vs "Cases (Restricted)". Mixed vocabulary: "Tenant", "Organisation", "Organization" | `cases/create`, `cases/detail`, `dashboard`, `error`, `layout`, `admin/users` |
| Hard-coded status text | The auditor dashboard shows "ACTIVE", "ENFORCED", "HEALTHY" as constants. They are not computed, so "System Health: HEALTHY" stays even if the database is down (the real checks are on `/admin/health`) | `dashboard.html:71-85` |
| Markup nit | A raw `&` in text (headings and a button label) is tolerated by browsers but should be `&amp;` | `dashboard.html:66`, `dashboard.html:112`, `dashboard.html:115` |
| Pagination text | "Page 1 of 1 (N total records)" differs between cases ("total records"), audit ("events"), users ("users") | - |

## 7. Security-relevant UI checks (read-only)

Searched `src/main/resources/templates` and `static` for each item.

| Check | Result |
|---|---|
| `th:utext` | none found |
| `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(` | none found (there is no JavaScript at all) |
| Inline `<script>` or `<script>` without `src` | none found |
| Inline event handlers (`onclick=` etc.) | none found |
| `style=` attributes, `<style>` blocks | none found |
| External URL (`http://`, `https://`, `//cdn`) in a resource, form action or CSS `url()`/`@import` | none found (the only `http` text is the Thymeleaf XML namespace `http://www.thymeleaf.org`, which is not loaded) |
| `localStorage` / `sessionStorage` | none found |
| POST form without a CSRF hidden field | none found (18 of 18 have one) |
| `target="_blank"` without `rel` | none found (no `target` attributes) |
| Report and note output | rendered only with `th:text`; `white-space: pre-wrap` in CSS keeps line breaks, so plain text is kept |
| Textarea content | `th:text` inside `<textarea>` (the draft body), escaped |
| Related automated checks | `TemplateScannerTest` (SEC-TPL-01..03) scans all templates and static files for the rules above; older template tests also exist |

Other observation (not a template issue, not changed): `error.html` shows `ex.getMessage()` for 403/404/400 raised by our own exceptions (for example the role transition text from `DefaultCaseAccessService`). The text is written by us and contains no user data, but it names internal rules; review in 9B.

## 8. Prioritised list of proposed changes

Severity order inside each group: security-relevant, accessibility, consistency. "New test needed" means no existing test covers it.

| # | Tag | Change | File(s) it would touch | Test that would cover it |
|---|---|---|---|---|
| 1 | 9B | Auditor dashboard shows constant "ACTIVE / ENFORCED / HEALTHY" as if checked. Replace with a link to `/admin/health` or real values; no claim of health that is not measured | `dashboard.html`, `AuthController` (if real values) | New test needed (dashboard for AUDITOR_ADMIN contains no constant health claim); existing dashboard tests must stay green |
| 2 | 9B | Error page: give signed-out visitors a "Back to sign in" link, signed-in users "Dashboard" plus a sign-out; do not label `/dashboard` as the home for a signed-out visitor. Needs a model flag for "authenticated" | `error.html`, (maybe `CorrelationErrorAttributes`/`GlobalExceptionHandler` for the flag) | New test needed; existing SEC-ERR tests must stay green |
| 3 | 9B | Rate-limit page: add link to the dashboard when signed in | `rate-limited.html`, `ThymeleafBlockedPageRenderer` | New test needed; existing RateLimitHttpTest must stay green |
| 4 | 9B | Use the shared shell on the dashboard (head, header, sidebar, footer); remove the duplicated header and the second navigation pattern; one label for the restricted cases entry | `dashboard.html`, `layout.html` | Existing dashboard/role tests; new test needed for the single navigation |
| 5 | 9B | Shared fragment for flash messages (one markup, one set of ARIA attributes) and for the "case sections" tab nav | `layout.html`, `cases/*`, `reports/*`, `admin/users.html` | `TemplateScannerTest` (SEC-TPL-01); new test needed for flash markup |
| 6 | 9C | Fix failing contrast: severity HIGH and status PENDING_REVIEW (2.68:1), alert-success, severity LOW and status CLOSED (4.37:1); darken text colours, keep the text label | `static/css/app.css` | New test needed (CSS contrast check from colour tokens); no existing test |
| 7 | 9C | Input and secondary-button border darker than `#E2E8F0` (1.23:1) so the boundary is visible | `static/css/app.css` | New test needed |
| 8 | 9C | Define `.text-muted`, scope `.badge-role` globally, delete dead badge CSS | `static/css/app.css` | `TemplateScannerTest` still passes; new test needed (every used class is defined) |
| 9 | 9C | `aria-current="page"` on active sidebar link and active case tab; `<main>` landmark on login; caption on the case table; `.sr-only` instead of `.skip-link` for the hidden status label | `layout.html`, `cases/detail.html`, `cases/list.html`, `login.html` | New test needed (template parse test for these attributes) |
| 10 | 9C | Accessible names for repeated row actions (include the case title or user name in `aria-label`, text from `th:text` only) | `cases/list.html`, `admin/users.html` | New test needed |
| 11 | 9C | `:focus-visible` styling, a thicker ring on the dark header and sidebar; keep every outline | `static/css/app.css` | New test needed (CSS has no `outline: none`) |
| 12 | 9C | Heading order: `h2` in the empty states of the cases list and users | `cases/list.html`, `admin/users.html` | New test needed |
| 13 | 9D | One badge system for statuses (case, action, report); one empty-state pattern; one date format shown with "UTC" | `app.css`, `cases/*`, `reports/*`, `admin/*`, DTO or a Thymeleaf formatter | New test needed |
| 14 | 9D | Remove requirement ids from visible headings (FR-04, FR-06, SR-07, SR-15); one spelling of Organisation | `cases/create.html`, `cases/detail.html`, `dashboard.html`, `error.html` | New test needed; existing tests that assert these strings must be checked first (VERIFY MANUALLY with grep before editing) |
| 15 | later | Review which of our own exception messages are shown on the error page | `GlobalExceptionHandler`, `DefaultCaseAccessService` | Existing SEC-ERR tests plus a new one |
| 16 | later | Browser check of focus ring, zoom to 200 percent, narrow width, screen reader reading order | none | VERIFY MANUALLY (no browser used in 9A) |

## 9. What this document could not verify

- Real rendering in a browser (layout at narrow width, zoom, the position of the off-screen labels, the focus ring on each background).
- The exact page a signed-out visitor sees for a failed CSRF POST (code path read, not exercised).
- Screen reader output (only the HTML was read).
- Contrast values come from the CSS hex values; hover/active state combinations not listed were not computed, and colours set by the browser (placeholder, disabled controls) are the browser defaults.

## 10. Phase 9B result (DRAFT)

| Item | Inventory finding | Change | Test |
|---|---|---|---|
| B1 error page | Section 4: error page has no "Back to login" for a signed-out visitor | `error.html`: signed-out sees "Back to login" (`/login`), signed-in sees "Return to Dashboard" (`/dashboard`); the flag `signedIn` comes from `SignedInState` (Security context, anonymous counts as signed out) via `GlobalExceptionHandler.errorView()` and `CorrelationErrorAttributes` | UI-ERR-01..05 (`ErrorPageLinksHttpTest`), UI-NAV-02 (`UiConsistencyTest`) |
| B1 429 page | Section 4: link to `/login` for everyone | `rate-limited.html`: same rule; `ThymeleafBlockedPageRenderer` passes `signedIn` | UI-RATE-01, UI-RATE-02 (`RateLimitPageLinksTest`) |
| B2 dashboard | Section 6 "Hard-coded status text", proposed change 1 | Auditor dashboard shows the health service result (HEALTHY, DEGRADED, DOWN, UNKNOWN) and the real audit chain state; the access-boundary card is a description only (finding F-009) | UI-DASH-01..05 (`DashboardStatusTest`) |
| B3 `.text-muted` | Section 6 "Undefined CSS class", proposed change 8 (first part) | `.text-muted` added to `app.css` with `var(--text-muted)`; the dashboard header label that used it on the dark background now uses the existing `layout-header-org` class (`#94A3B8` on navy, 6.74:1) so it does not turn dark grey | UI-CSS-01 (`UiConsistencyTest`) |
| B3 label | Section 4: "Quarantined" vs "Restricted" | One wording, "Cases (Restricted)", in `layout.html` and `dashboard.html` (reason: it states the rule plainly; "Quarantined" suggests infected or isolated data) | UI-NAV-01 (`UiConsistencyTest`), UI-DASH-05 |

Not done in 9B (still open in section 8): dead CSS removal, `.badge-role` scope, contrast fixes, ARIA, focus, shared dashboard shell. New observation: F-010 (`;jsessionid` in links of the signed-out CSRF error page), not fixed, owner decision needed.
