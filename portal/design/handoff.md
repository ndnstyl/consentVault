# Front-end handoff: ConsentVault Cloud portal

Status: written against the low-fidelity wireframes and the live site tokens. **Hi-fi review is pending**: when
web-designer delivers screens, ui-ux reviews them against this file and lists every divergence, then this file is
re-issued. Build target: `/Users/oxfloors/debwe/portal/` (Next.js static export, same design system as consentvault.ai).

Companion files in this folder: `ia.md` (routes), `flows.md`, `roles.md`, `copy-rules.md`, `accessibility.md`,
`contract-gaps.md`, `ux-audit.md`, `wireframes/*.html` (every state), `wireframes/README.md`.

**Copy of record.** The visible text in each wireframe state is the approved copy for that state, with example values
(names, dates, counts) replaced by data. Strings that appear in no wireframe are given below.

**Endpoint rule.** An element whose source is marked **gap** must not be built against a guessed route. Build it behind
a feature flag named for the gap row (for example `gap_B3_credentials_list`) that renders the element's "Not available"
partial state until the contract lands.

---

## G. Global behavior (applies to every screen)

G-1 **Session.** WorkOS AuthKit hosted page -> HttpOnly session cookie (8 h) -> vault-minted tenant token
(contracts/auth.md). The portal never stores a token in localStorage. On 401 from any call: go to 01 with
`?return=<route>`; restore unsaved form fields from sessionStorage after sign-in.

G-2 **Organization.** Selected once per session (03); never in the URL. A `storage` event from another tab that
changes the organization shows the "switched in another tab" banner (22) and blocks writes until reload or switch back.

G-3 **Copy check.** A build test scans all rendered strings (not API identifiers or code blocks) and fails on any match
of: `\bcompliant\b`, `non-compliant`, `in compliance`, `compliance status`, `valid consent` (outside the allowlisted
cover sentence), `consent is valid`, `\bprov(e|es|en)\b`, `\bproof\b`, `\blawful\b`, `legally sufficient` (outside the
attestation), `permitted to`, `allowed to (contact|call|text|email|dial)`, `safe to`, `cleared to`, `OK to contact`,
`guarantee`, `hold(s)? up in court`, `court-ready`, `qualifies`, `satisfied`, `meets (the )?TCPA`,
`something went wrong`, and the characters U+2014 and U+2013. Allowlist: the three fixed strings in copy-rules.md
section 2, "Not legal advice", "not a legal test".

G-4 **Five states.** Every async region implements: loading (skeleton, `aria-busy`), empty (named, with the next
action), partial (banner naming what is missing, missing values read "Not available"), error (copy-rules.md section 4
formula, `role="alert"`), success. A region never renders 0 for a count the API did not return.

G-5 **Organization status banner** (slot under the top bar, every page):
- `trial`: "Acme Lending is in trial. Records are test data until you choose a plan." [Choose a plan]
- `past_due`: wireframe 05 "Past due".
- `suspended`: wireframe 05 "Suspended". Also disables: Build evidence package (14, 13), Issue a credential (09).
- `offboarding`: wireframe 20 "Offboarding in progress" summary line. [Open settings]
- `closed`: full-page state: "Acme Lending is closed. Its records were exported on <date> and its key was destroyed on
  <date>." [Switch organization] [Sign out]

G-6 **Role gating.** Navigation hides items per roles.md. A deep link to a hidden screen renders the role-refusal state
(22) with the person's role named. Server 403 `role_not_allowed` renders the same state.

G-7 **Polling.** Only these poll: first event (06) every 5 s for 15 min; export status (14) every 3 s until
ready or failed, then stop; checkout confirmation (04) every 5 s for 2 min; redrive progress (15) every 5 s for 5 min.
Polling pauses when the tab is hidden. Each has a deadline after which it shows its named "still waiting" error.

G-8 **Writes.** Every write button shows a busy label ("Saving", "Issuing", "Revoking") and is disabled while in
flight; double submits are impossible. Destructive or irreversible writes (revoke, erasure, redrive, offboarding,
policy approval) use an alert dialog with a reason field where the contract records a reason; the reason is required.

G-9 **Personal data.** Contact points appear only on 13 and 14 for admin and compliance viewer. They are never put in
a URL, page title, log, analytics event, or error report. The 13 input clears on route change.

G-10 **Time.** Show in the viewer's zone with the zone named; `<time datetime>` carries UTC.

Global acceptance criteria:
1. G-AC1: For every route in ia.md, a Playwright run with each role fixture shows only the navigation items in roles.md.
2. G-AC2: Visiting a hidden route renders a heading "This page is for admins" (or the role-specific text) and a button
   that navigates to a page the role may open.
3. G-AC3: With the org fixture set to `suspended`, the "Build evidence package" and "Issue a credential" buttons are
   disabled with visible reason text, and the banner text matches wireframe 05 "Suspended".
4. G-AC4: The copy check in G-3 passes on every route and state fixture.
5. G-AC5: No request URL captured during flows F5 and F10 contains the test contact point.
6. G-AC6: axe-core reports 0 violations on every route and state fixture at 375px and 1440px, light and dark.
7. G-AC7: At 375px, `document.documentElement.scrollWidth <= 375` on every route and state fixture.
8. G-AC8: A 401 on any call navigates to `/sign-in?return=` the current route.

---

## Screen specs

Format per screen: route · roles · purpose · states (trigger) · components · data · extra copy · keyboard and focus ·
ARIA · acceptance criteria.

### 01 Sign in (WorkOS hosted)
- Route: `/sign-in` redirects to WorkOS; `/auth/callback` finishes. Roles: everyone.
- Purpose: sign in with passkey, Google or Microsoft. No password field exists anywhere.
- States: default (WorkOS page); loading (callback in progress); empty: no organization (session has zero memberships);
  partial: second factor missing (token's authentication-method claim lacks a passkey or second factor, per the spec's
  sign-in requirement); error (WorkOS unreachable, 15 s timeout); session expired (arrived with `?reason=expired`);
  success (redirect to `return`, to 03 when 2+ orgs, else `/`).
- Components: WorkOS hosted page with branding; portal `CenteredCard`, `StateBlock`.
- Data: WorkOS AuthKit (hosted). Membership lookup: **gap B1**.
- WorkOS branding settings (web-designer to finalize): logo = `Mark` + wordmark from `site/src/components/Logo.tsx`;
  primary color `#2A3845`; button text white; accent `#C6B25D` for focus is **not** allowed (fails 3:1); page
  background `#F7F4EA`; font Montserrat for heading, Geist for body; sign-in methods: passkey, Google, Microsoft;
  passwords and magic links off.
- Keyboard: callback page focuses its heading. ARIA: callback status in `role="status"`.
- AC: 01-1 No `input[type=password]` exists on any portal route. 01-2 A callback fixture with a token lacking a second
  factor renders "Your sign-in needs a second factor". 01-3 A callback fixture with zero memberships renders "Your
  account is not a member of any organization" with "Sign out". 01-4 `?reason=expired` renders the expired banner.

### 02 Accept an invitation
- Route `/invite?token=`. Roles: invitee.
- States: default (token valid); loading; empty (no token param); partial: wrong account (signed in, email differs);
  error: `invite_expired`, `invite_used`, `invite_withdrawn` (each its own block, wireframe text); success (membership
  created).
- Components: `CenteredCard`, `KeyValueList`, `StateBlock`.
- Data: **gap C1** (lookup and accept). Invitation email is SES (billing.md step 1).
- Extra copy (invitation email, plain text and HTML, no personal data beyond the invitee's own address): Subject
  "You are invited to Acme Lending on ConsentVault". Body: "<Inviter> invited you to join <Org> on ConsentVault as
  <Role>. This link works once and expires on <date, time, zone>. [Accept invitation]. If you were not expecting this,
  ignore this email; nothing happens unless you sign in."
- Focus: heading on load; on error, the error heading.
- AC: 02-1 No token renders "This link has no invitation in it". 02-2 Each of the three error names renders its own
  heading. 02-3 Success shows the role name and a "Choose a plan" button for admins, "Go to overview" for other roles.

### 03 Choose an organization
- Route `/choose-org`. Shown only when 2+ memberships; with 1, skip to `/`.
- States: default; loading; empty (memberships removed between sign-in and load); partial (one org's status failed:
  row shows "Not available" and its Open is disabled); error; success (redirect).
- Data: **gap B1**. Components: `DataTable` (collapses to cards), `StatusChip`.
- AC: 03-1 With 1 membership fixture, `/choose-org` redirects to `/`. 03-2 Selecting an org sets it for the session and
  lands on `/`; the URL never contains the org id.

### 04 Choose a plan and check out
- Routes `/start/plan`, `/billing/return?result=success|cancel`. Roles: admin; others see "Only an admin can choose a
  plan".
- States: default (plans); loading (creating session, then browser leaves for Stripe); empty (no plans); partial:
  payment confirming (returned with success, org not yet `active`; poll G-7); error: session create failed, or
  `result=cancel`; success (org `active`).
- Data: `POST /v1/billing/checkout` (billing.md). Plans: **gap B23**. Status poll: **gap B2**. Return URLs: **gap C8**.
- Plan card values come from Stripe price metadata `included_events`, `included_gate_checks`, `orgs_brands`; never
  hard coded.
- AC: 04-1 "Choose Growth" calls checkout once and navigates to the returned Stripe URL. 04-2 `result=cancel` renders
  "Checkout was cancelled" and "Nothing was charged". 04-3 A success return with org still `trial` renders the
  confirming state and a "Start setup" button.

### 05 Overview
- Route `/`. Roles: all (tiles trimmed per roles.md).
- States: default; loading; empty: new organization (setup checklist, triggered when any of brand, source, wording,
  credential, first event is missing); partial (any tile source failed: that tile "Not available"); error (org read
  failed); past due; suspended; success: setup done (first time after the first event, then default).
- Components: `SetupChecklist`, `Tile` x4, `StatusBanner`.
- Data: brands `GET /v1/brands`; sources `GET /v1/sources`; wording **gap B5**; credentials **gap B3**; first event
  **gap B19**; policy **gap B7**; unsealed and dead counts **gap B21**; usage **gap B22**; org status **gap B2**.
- Checklist order and button: first not-done item becomes the single primary button.
- AC: 05-1 New-org fixture shows 5 checklist items with "Done" or "To do" text and exactly one primary button, labelled
  for the first not-done item. 05-2 A failed usage call renders "Not available" in the usage tile and never "0".
  05-3 The undelivered tile links to `/systems/<id>` of the system with the most dead deliveries.

### 06 First test event
- Route `/setup/first-event`. Roles: admin, developer.
- States: default (all prerequisites done, waiting); loading; empty: prerequisites missing (lists them, primary =
  first missing); partial: event received, seal pending; error: refusal table (always visible below the command) and
  "No event arrived in 15 minutes"; success: recorded and sealed.
- Components: `Stepper`, `CodeSnippet` (copy button; values filled from the chosen credential, source, brand and
  wording fingerprint; site-key and server-token variants in tabs), `LiveStatus`.
- Data: prerequisites as 05; arrival **gap B19**; refusals from contracts/capture.md and the core's `docs/api.md`.
- The snippet body uses the core's field names: `contact, event_type, channels, purposes, checked, brand_ids,
  disclosure_sha256, source_id` (`/Users/oxfloors/debwe/docs/api.md` lines 22-37; capture.md).
- AC: 06-1 Copy button puts the exact snippet text on the clipboard. 06-2 With no wording fixture, the page shows
  "Two steps come first" (or the count that applies) and a "Register your consent wording" button. 06-3 When the
  arrival fixture flips to an unsealed event, the status region text becomes "Event received at ..." within one poll.
  06-4 After 15 minutes with no event (fake timers), "No event arrived in 15 minutes" renders.

### 07 Brands
- Route `/brands`. Roles: admin W, developer R.
- States: default; loading; empty; partial (counts failed); error (list failed; create failed `brand_exists`); add
  dialog; success.
- Data: `GET /v1/brands`, `POST /v1/brands` (admin.md). Count per brand **gap**, error name **gap D**.
- Focus: dialog opens on Brand name; after success, focus the banner.
- AC: 07-1 Adding a brand calls POST once and the new row appears without reload. 07-2 `brand_exists` keeps the
  dialog open with the error inside it and the field value kept.

### 08 Capture sources
- Routes `/sources`, `/sources/[source_id]`. Roles: admin W, developer W (proposed).
- States: default; loading; empty; blocked: no brand; partial (last event times failed); error (list; create
  `invalid_origin`); add dialog; success (offers "Issue a credential for <source>").
- Form rules: site-key sources require 1+ origin, each `scheme://host[:port]` with no path; server sources hide the
  origins field. At least one brand.
- Data: `GET /v1/sources`, `POST /v1/sources` (admin.md); schema **gap B20**; last event **gap B19**.
- AC: 08-1 Entering `https://acme.com/form` shows the origin error before submit. 08-2 With zero brands, the page shows
  "Add a brand first" and no add-source button.

### 09 Credentials
- Routes `/credentials`, `/credentials/new`. Roles: admin W; developer W (capture and evidence read only, proposed).
- States: default; loading; empty; partial; error (list; issue `private_key_refused`); wizard step 1; step 2 key;
  step 3 shown once; revoke dialog; suspended; success.
- Rules: gate check scope disabled with reason when no policy is in force (`policy_required`); the secret or client id
  is shown once; Done enables only after "I stored this secret" is ticked; closing early asks "Close without storing?
  This secret will not be shown again." [Go back] [Close anyway]. Revoke requires a reason. Client-side check refuses
  text containing `PRIVATE KEY` before sending.
- Data: `POST /v1/credentials`, `DELETE /v1/credentials/{id}` (admin.md); scopes per auth.md; list **gap B3**; issue
  answer **gap B4**; `capture_verified` issuer **gap C6** (not offered in the portal).
- Focus: step change moves focus to the step heading; reveal dialog focuses the copy button.
- AC: 09-1 With no policy fixture, the gate-check option is disabled and its reason text is visible. 09-2 The reveal
  Done button is disabled until the checkbox is ticked. 09-3 Revoke without a reason cannot submit. 09-4 Pasting a
  block containing "PRIVATE KEY" shows the refusal and sends no request.

### 10 Wording
- Routes `/wording`, `/wording/new`, `/wording/[sha256]`. Roles: admin W; viewer and developer R.
- States: default; loading; empty; partial; error (list; `disclosure_exists`); form; detail; success.
- Rules: textarea value is sent byte for byte (no trimming, no smart-quote conversion; `spellcheck` allowed, autocorrect
  off). At least one channel, one purpose, one brand. "Replaces" lists registered versions. No edit route exists.
- Data: `POST /v1/disclosures` (admin.md); list and detail **gap B5**; purposes **gap B6**.
- AC: 10-1 Text with leading and trailing spaces is sent unchanged (request body assertion). 10-2 The detail page has
  no edit control. 10-3 `disclosure_exists` shows a link to the existing version.

### 11 Policies
- Routes `/policies`, `/policies/new`, `/policies/[version]`, `/policies/[version]/approve`. Roles: admin W; others R.
- States: default; loading; empty (no policy in force); partial; error (list; `policy_superseded` on approve); draft
  editor; approve with attestation; read only; success.
- Editor: matrix rows are the evidence statuses (consent record found, stop on record, no record, record incomplete,
  records not available); columns are channels; each cell a select Proceed or Hold labelled
  "<row>, <channel>". Purpose dimension: one matrix per purpose, tabs (pending **gap B10** confirms the shape).
- Approve: rules repeated read-only; attestation text and version from **gap B9**; checkbox required; approver from
  session; "On approval" line states what retires.
- Data: `POST /v1/policies`, `POST /v1/policies/{version}:approve` (admin.md); reads **gap B7**; templates **gap B8**.
- Focus: approve page lands on its heading; the checkbox is the first control after the attestation text.
- AC: 11-1 Approve button disabled until the attestation box is ticked; the reason "Approve turns on after the box is
  ticked" is visible. 11-2 The approve request carries no name field (identity comes from the session).
  11-3 Approved and retired versions render no editable control. 11-4 Each matrix select has an accessible name
  containing both the evidence status and the channel.

### 12 Documentation checklists
- Routes `/checklists`, `/checklists/[version]`. Roles: admin W; others R.
- States: default; loading; empty (offers the PEWC example); partial; error; editor and approve; success.
- PEWC example: element names from the spec's documentation-checklist requirement; regulation quotes come from the
  rule reference list, never typed by the build.
- Data: `POST /v1/checklists`, `POST /v1/checklists/{version}:approve` (admin.md); reads **gap B11**.
- AC: 12-1 The approve checkbox label contains "documentation completeness" or "not a legal test". 12-2 An element
  row can be added and removed by keyboard alone.

### 13 Evidence lookup
- Route `/evidence`. Roles: admin, compliance viewer.
- States: default (search only); loading; empty (`found: false`); partial (deliveries or gate checks failed);
  seal pending (any event without a seal); later grant did not lift a stop (a `reviews` row with
  `contact_control_unverified`); error (`unavailable:*` or invalid contact); erasure dialog; success.
- Sections and their data (all from one `POST /v1/proof {contact}` unless noted; field schema **gap B24**):
  status table from `permissions` plus policy action per row; notice text fixed; timeline from `timeline` with
  wording label from `disclosures`; seal chip per event; checklist result **gap B12**; chain chip from `chain.head`
  and `chain.anchors`; gate checks table from the cloud addition "gate decisions for that contact"; deliveries from
  `POST /v1/deliveries:query {contact, system_id}` once per connected system (suppression-sync.md).
- Actions: "Build evidence package" posts to 14's endpoint and navigates there; "Request erasure" (admin) opens the
  dialog, posts `POST /v1/contacts:erase` (admin.md); status **gap C5**; `legal_hold_active` renders the hold refusal.
- Empty copy never implies another organization: always "in <your org>".
- Focus: after results load, focus the "Records for ..." heading; on error, the alert.
- AC: 13-1 The contact is sent in the POST body and the URL is unchanged after search. 13-2 `found:false` renders
  "No records for <contact> in <org>" and the notice. 13-3 Every evidence status chip has visible text from the label
  dictionary. 13-4 The notice string appears exactly once under the status table. 13-5 A failing deliveries call
  renders the partial banner and the rest of the page. 13-6 Navigating away and back leaves the input empty.

### 14 Evidence packages
- Routes `/exports`, `/exports/[export_id]`. Roles: admin, compliance viewer.
- States: default; building; empty; partial: large history (progress, **gap B18**); error (`failed`, link used or
  expired); suspended; success: ready.
- Data: `POST /v1/exports` -> 202 `{export_id}`; `GET /v1/exports/{export_id}` -> `status, download_url, sha256,
  signature, expires_at` (proof-export.md). List **gap B18**; until then the list holds this session's exports only.
- Download: the link is one-time; after click, the row shows "Downloaded <time>" and offers "Get a new link"
  (**gap B18**).
- AC: 14-1 Polling stops at `ready` or `failed`. 14-2 Ready shows sha256 with a copy button and the expiry time.
  14-3 A `failed` fixture never shows a download button.

### 15 Connected systems and deliveries
- Routes `/systems`, `/systems/new`, `/systems/[system_id]`. Roles: admin W; developer W (proposed); viewer R.
- States: default; loading; empty; partial (counts "Not available"); error (list; test push non-2xx or timeout);
  connect dialog; detail; redrive dialog; success.
- Connect form: name, kind (`crm, dialer, sms, email, ai_agent, webhook`), https endpoint, signature (Ed25519 or HMAC),
  contact form (plaintext or fingerprint), retry window (default 24 h). After create, run a test push and show the
  public key or one-time HMAC secret for the receiver.
- Test push answer copy: 2xx "Test push accepted: <code> in <ms> ms"; 4xx "Dialer answered <code>. It did not accept
  the push." + per-code next action (401/403 signature, 404 address, 410 gone); 5xx "Dialer answered <code>. It had an
  error."; timeout "Dialer did not answer within 10 seconds."
- Data: `POST/PATCH /v1/systems`, `POST /v1/deliveries:redrive {system_id}` (admin.md);
  `POST /v1/deliveries:query` (suppression-sync.md); list, detail, dead list, test push **gaps B14, B15, B16**.
- AC: 15-1 A non-https endpoint cannot submit. 15-2 Redrive needs a reason and posts once with the system id.
  15-3 Dead rows show fingerprints, never contact points. 15-4 A failed count call renders "Not available".

### 16 Retention
- Route `/retention`. Roles: admin W; viewer R.
- States: default; loading; empty (platform minimum only); partial; error (`below_platform_minimum`); success.
- Input `min` = platform minimum; the save confirms "Applies to records written from now on".
- Data: `PUT /v1/retention` (admin.md); read **gap B13**.
- AC: 16-1 A value below the minimum shows the inline error before submit. 16-2 Success text names the time from which
  it applies.

### 17 Members
- Route `/members`. Roles: admin.
- States: default; loading; empty: only you; partial; error (`email_send_failed`, `last_admin`); invite dialog;
  success.
- Data: `GET /v1/members`, `POST /v1/members` (admin.md); role change, remove, withdraw **gap C2**; invites **gap B26**;
  developer role **gap A5** (until it lands, the dialog offers two roles).
- AC: 17-1 Each role option shows its one-line description. 17-2 The only admin row has no remove or demote control.

### 18 Audit log
- Route `/audit`. Roles: admin (viewer pending ruling).
- States: default; loading; empty (filters match nothing, offers "Clear filters"); partial (names failed: show
  sign-in id); error; success.
- Data: `GET /v1/audit` (admin.md); filters and paging **gap B25**. Filters live in the URL query (no personal data).
- AC: 18-1 Changing a filter updates the URL query and the rows. 18-2 No personal field is rendered (fixture with
  contact-like strings in `target` is masked).

### 19 Billing
- Route `/billing`. Roles: admin.
- States: default; loading (opening Stripe); empty (trial, no subscription); partial (usage failed); error (portal
  session failed); past due; success (returned from Stripe).
- Data: `POST /v1/billing/portal` (billing.md); status and usage **gap B22**.
- AC: 19-1 "Manage billing on Stripe" posts once and navigates to the returned URL. 19-2 Usage failure renders
  "Not available" for both counts.

### 20 Settings and offboarding
- Route `/settings`. Roles: admin W (request); viewer and developer R (identity only, no offboarding card).
- States: default; loading; empty (no offboarding); partial (key status failed); error (request failed); request
  dialog (type the org name); offboarding in progress (steps with dates); success.
- Data: org and key status **gap B2**; request **gap C3**; progress **gap C4**. Operator endpoints
  (`PATCH /v1/orgs/{id}/status`, `POST /v1/orgs/{id}/offboard`) are not called by the portal.
- AC: 20-1 Send request stays disabled until the typed name matches exactly. 20-2 The steps list states the final export
  comes first and the wait is at least 30 days.

### 21 Rule references
- Route `/references`. Roles: all.
- States: default; loading; empty (jurisdiction has none); partial; error; success.
- Data: `GET /v1/rule-references` (admin.md). Shows citation and official link only, no summary (data-model.md line
  287). External links open in a new tab and say so in their text.
- AC: 21-1 The banner "Citations and official links only. Not legal advice." is present. 21-2 Every row has a
  last-reviewed date or "Not available".

### 22 Global states
- Behavior in section G. AC: covered by G-AC1 to G-AC8 plus 22-1: the session warning dialog appears at 7 h 58 min
  (fake timers) and "Sign in again" preserves a filled form.

---

## Component inventory

Existing (adapt from the site; file paths under `/Users/oxfloors/brain/projects/consentVault/site/src/`):

| Component | Source | Change |
|---|---|---|
| `Logo`, `Mark` | `components/Logo.tsx` | wrap in home link |
| Button | `styles/globals.css` lines 75-84 | add `size="sm"` 36px; disabled and busy states |
| Field | `styles/sections.css` lines 294-297 | new focus ring and `--field-edge` border; error and hint slots |
| Checkbox | `styles/sections.css` lines 299-300 | reuse for attestation and "stored" boxes |
| Card | `styles/globals.css` line 96 | none |
| Table base | `styles/sections.css` line 347 | add card collapse |
| Skip link | `styles/globals.css` lines 52-53 | none |

New (props and states):

| Component | Props | States |
|---|---|---|
| `AppShell` | `org, role, nav[], banner?` | menu open or closed under 760px |
| `OrgSwitcher` | `memberships[], current` | 1 org (hidden), many, loading, error |
| `StatusBanner` | `kind: trial, past_due, suspended, offboarding, info, warn`, `title, body, action?` | |
| `StateBlock` | `kind: empty, error`, `title, cause?, next, actions[]` | |
| `Skeleton` | `rows, variant: table, tiles, text` | reduced motion static |
| `DataTable` | `columns[], rows[], collapseBelow=760, caption` | loading, empty, partial cells |
| `StatusChip` | `value` (label dictionary key), `icon` | every dictionary value |
| `EvidenceStatusChip`, `PolicyActionChip` | `status`, `action` | per copy-rules.md section 3 |
| `SealChip` | `sealedAt?` | sealed, pending |
| `Tile` | `label, value?, sub, href?` | value missing renders "Not available" |
| `SetupChecklist` | `items[{label, done, href}]` | |
| `Stepper` | `steps[], current` | |
| `CodeSnippet` | `tabs[{label, code}]` | copied confirmation |
| `CopyField` | `value, label` | copied |
| `SecretReveal` | `secret, onDone` | unticked, ticked, close-confirm |
| `ConfirmDialog` | `title, body, reasonRequired, confirmLabel, destructive` | busy, error inside |
| `AttestationPanel` | `text, version, approverName` | unticked, ticked, busy |
| `PolicyMatrix` | `rules, editable, purposes[]` | read only, editable |
| `Timeline` | `events[]` | |
| `LiveStatus` | `message, pollMs, deadlineMs` | waiting, done, deadline passed |
| `FilterBar` | `filters[]` | |
| `Pager` | `cursorPrev?, cursorNext?` | |
| `ContactInput` | `onSubmit` | invalid phone, invalid email |
| `Toast` | `message` | |

## Not in scope (portal launch)

- Operator console (separate surface, operator-only functions).
- EBR records and DNC scrub upload: write endpoints exist (`POST /v1/ebr-records`, `POST /v1/dnc-scrubs`), no reads.
- Legal hold management (`POST /v1/legal-holds`, release): no list endpoint; holds appear only as refusal reasons.
- Operator access approval by the client (gap C7). Until built, emergency notices arrive by email.
- Inbound signal browsing (gap B17).
- Website-started self-serve sign-up (designed for in the invite path, switched on later).
- Named CRM or dialer connectors (generic signed webhook only at launch).
- Client-supplied keys.

## Open questions (each with a recommended answer)

1. May a new admin set up and send a test event before checkout completes? Recommended: yes, while the organization is
   in trial, with the trial banner saying records are test data.
2. Final attestation wording (copy-rules.md section 2, item 3). Recommended: keep the draft; it follows the custodian
   principle and the "counsel recommended, not required" ruling.
3. Add a developer role? Recommended: yes, as roles.md defines it, so engineers never see personal records.
4. Should the compliance viewer read the audit log? Recommended: yes, read only.
5. Does approving a new policy retire the one in force at once? Recommended: yes, one policy in force at a time.
6. Does an invitation bind to the invited email address? Recommended: yes; a different signed-in address gets the
   "wrong account" state.
7. Who issues the credential that may claim a verified contact point? Recommended: the operator only, never the portal.
