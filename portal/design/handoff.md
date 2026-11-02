# Front-end handoff: ConsentVault Cloud portal

Status: written against the low-fidelity wireframes and the live site tokens. **Hi-fi review is pending**: when
web-designer delivers screens, ui-ux reviews them against this file and lists every divergence, then this file is
re-issued. Build target: `portal/` (Next.js static export, same design system as consentvault.ai).

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
  disclosure_sha256, source_id` (`docs/api.md` lines 22-37; capture.md).
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

Existing (adapt from the site; file paths under the marketing site's `src/`):

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

---

## Additions 2026-10-30: Records, Setup walkthrough, Confirmation messages

Written against low-fidelity wireframes 23, 24, 25 (hi-fi pending, same review rule as the rest of this file). Contracts
are **proposed**: `contracts/records.md`, `contracts/confirmations.md`, and contract-gaps.md section F. Until accepted,
build behind flags `gap_records`, `gap_setup`, `gap_confirmations`; a flagged region renders its partial state.

### 23 Records
- Route `/records`. Filters live in the query string (`channel, status, purpose, has_stop, source_id, date_field, from,
  to, trial, sort`) so a filtered view can be bookmarked; a contact point is never in the URL. Roles: admin, compliance
  viewer (masked, reveal on request), developer (fingerprints, rows not links, no search, reveal or export).
- States and triggers: loading (first fetch); empty: no records yet (`total: 0` with no filters); empty: no match (`items:
  []` with filters); partial: `partial` contains `contact_mask` (contact column "Not available", banner), summary failed
  (tiles "Not available", chart replaced by the named banner), `total: null` ("Showing 1 to 50. Total not available.");
  error: list failed; error: `audit_unavailable` (no rows shown); reveal confirm (first reveal in a session); revealed;
  search found; search no record; developer view; export dialog, building, ready, failed, `export_too_large`;
  suspended (export disabled with reason); role refused (developer deep link to an export).
- Components: `AppShell`, `Tile` x3, new `BarChart`, new `ShareBar`, `FilterBar`, new `ContactSearch` (from
  `ContactInput`), new `RevealToggle`, `DataTable` (card collapse under 760px), `EvidenceStatusChip`, `Pager`,
  `ConfirmDialog`, new `ExportDialog`, `LiveStatus` (export progress), `StatusBanner`.
- Data: tiles `GET /v1/records/summary` (`total`, `new_in_range`, `with_stop`); chart `new_per_day` with `tz` = viewer's
  zone; share bars `by_channel` (Call = voice plus artificial_voice summed per status); table `GET /v1/records`;
  confirmation column `record.confirmation`; reveal `POST /v1/records:reveal` with the current page's `record_id`s;
  search `POST /v1/records:search`; export `POST /v1/records/exports` then poll `GET /v1/records/exports/{id}` every 3 s.
  All fetched, not realtime; "as of" time shown under the tiles.
- Name and Company columns (admin, compliance viewer) from `record.person`: "Not captured" when never sent, "Not
  available" when `partial` names `person`. Developers get neither column. Neither is filterable or searchable.
- Table cells: Email, Text, Call show one chip per channel: with a purpose filter, that purpose's status; without, the
  counts "Consent record found (2)" and "Stop on record (1)" side by side, stop first. Never a policy action.
- Reveal: toggle off on every new session. While on, each page fetch is followed by one reveal call; the banner shows the
  audit time. Turning it off clears revealed values from memory and the DOM.
- Keyboard and focus: tab order is tiles' links, chart table disclosure, filters left to right, Clear filters, search
  input, Find, reveal switch, Export, table rows (the contact cell is the link), pager. Changing a filter keeps focus on
  that control and announces "312 records" through a polite live region. After search, focus moves to the result banner.
- ARIA: chart is `role="img"` with an `aria-label` naming range and peak, and a `<details>` table; share bars `role="img"`
  with all four percentages in the label and the same numbers in visible text; reveal is `role="switch"`; patterns, not
  shade alone, separate statuses.
- AC: 23-1 With the records fixture, the URL after any filter change contains no `@` and no run of 7 or more digits.
  23-2 A summary failure renders "Not available" in each tile and never "0". 23-3 `partial: ["contact_mask"]` renders
  "Not available" in every contact cell and still renders every stop chip. 23-4 An `audit_unavailable` list answer renders
  no table rows. 23-5 Turning on reveal calls `POST /v1/records:reveal` once with exactly the visible page's ids; turning
  it off removes every full contact point from the DOM. 23-6 Developer fixture: no search box, no reveal switch, no export
  button, contact cells contain a fingerprint and are not links. 23-7 Search sends the contact in the body; the URL is
  unchanged. 23-8 A row link goes to `/evidence?record=<record_id>`. 23-9 Export with "Full" selected and an empty reason
  shows the inline error and sends nothing. 23-10 At 375px, `document.documentElement.scrollWidth` equals the viewport
  width. 23-11 Each status chip carries its text label; the share bars carry three visible percentages (found, stop, no
record) and no "Record incomplete" anywhere on the screen. 23-12 Developer fixture: no Name or
Company column and no name or company string anywhere in the DOM. 23-13 `partial: ["person"]` renders "Not available"
in Name and Company and still renders every row. 23-14 An erased fixture row reads "Erased" in Contact, Name and
Company and keeps its stop chip. 23-15 A search for "555-01" shows the inline invalid-contact error and sends no request.
23-16 A 429 from search or reveal shows the rate-limit banner with the wait time and leaves masked values in place.
23-17 A list fixture with names writes nothing to the DOM for a developer. (Name and company now read with the display
key; screen 13 opened by record id shows the masked contact and a "Show full contact point" button that calls reveal.)

### 24 Setup walkthrough
- Route `/setup`, `/setup?step=<brand|source|wording|credential|first_event|policy|system|confirmations>`. Roles: admin,
  developer; compliance viewer gets the role refusal with a link to the overview.
- States and triggers: empty (welcome: no step done, reached from 02 success); loading; default (resumed at
  `current_step`, "Welcome back" when any step is done); step success; step error (the step endpoint's named error, form
  kept); waiting (step 5 polling); partial (a step in `partial`: "Not available", Check again, other steps usable);
  blocked (`blocked_reason: org_suspended` or a prerequisite); developer view (admin steps "Waiting on an admin"); skip
  dialog; error (setup read failed); role refused; success (complete, skipped steps listed with "Turn on").
- Components: new `SetupRail` (`steps[], current, onSelect`; under 760px a select), the existing step components in a
  `mode="setup"` prop that hides the page heading and shows Back, Skip for now (optional steps only), primary, Leave
  setup. Step 6 opens the policy editor in setup mode and returns to `/setup?step=system` after approval.
- Data: `GET /v1/setup` on load and after every step write (contracts/setup.md); each step writes through its own
  screen's endpoint (07, 08, 10, 09, 06, 11, 15, 25); skip `POST /v1/setup/steps/{step}:skip`.
- Screen 05 change: `SetupChecklist` reads `GET /v1/setup` and lists the same 8 steps (optional ones marked); its primary
  button reads "Resume setup: <step label>" and opens `/setup?step=<current_step>`. AC 05-1 becomes "8 items".
- Keyboard and focus: on step change, focus moves to the step heading (`h2`); the rail is an ordered list of links with
  `aria-current="step"`; the live status in step 5 is `aria-live="polite"`.
- AC: 24-1 Loading `/setup` with a fixture where steps 1 and 2 are done opens step 3. 24-2 Reloading after step 3
  succeeds opens step 4 (no client storage involved: clearing storage gives the same result). 24-3 Skip appears only on
  steps 7 and 8. 24-4 Developer fixture shows "Waiting on an admin" on steps 3, 6 and 8 and no form on them. 24-5 A
  `partial: ["credential"]` fixture shows "Not available" on step 4 and never "Done". 24-6 Compliance viewer gets the role
  refusal with a link to `/`. 24-7 Overview checklist and setup rail show the same status for every step on one fixture.

### 25 Confirmation messages
- Route `/confirmations`, `/confirmations/[source_id]/[channel]` (edit). Roles per roles.md additions.
- States and triggers: loading; empty (no sending account); default; texts off (`texting_registration.status:
  not_marked`, text toggles `aria-disabled` with the reason as visible text); registration dialog; edit with preview;
  saved; replies to read; partial (any `counts` field null, opt-out check failed); alarm (opt-out check added stops);
  error (settings read failed); sending account failing; suspended; developer read-only; role refused.
- Components: `Tile` x4, new `Toggle` (`role="switch"`), `DataTable`, new `TemplateEditor` (editable fields plus locked
  fixed parts rendered from `:preview`), new `MessagePreview` (email and text, characters and segments), `ConfirmDialog`
  (registration statement, record a stop with reason), `StatusBanner`.
- Data: tiles and toggles `GET /v1/confirmations/settings` and `/rules`; preview `POST /v1/confirmations:preview` on
  field change (debounced 400 ms); activity `GET /v1/confirmations/sends?limit=5`; replies
  `GET /v1/confirmations/replies?state=to_read`; all fetched.
- Screen 13 change: the timeline adds contact log entries (Confirmation sent, Not sent: reason, Reply, Stop from a reply)
  from `contact_log`, each with its seal chip and "Show the exact text" (A, V).
- Keyboard and focus: toggles operate with Space; a disabled toggle stays focusable and its reason is its description
  (`aria-describedby`). Dialog focus starts on the first field and returns to the opener.
- Revised 2026-10-30 (compliance gate and design review). Added states: connect text provider (four steps, waiting
  for test reply, test reply arrived, no test reply in 15 minutes), wording link host, withdraw registration, disconnect
  account, undelivered sends, replies unread over 24 hours, inbound signature alarm,
  public email stop page. Text messages are fixed text (no editor for text). The registration dialog shows all four fixed
  texts and needs both boxes ticked. Activity filter offers Sent, Sent delivered, Retrying, Undelivered, Not sent.
- AC: 25-8 With the text account `awaiting_test_reply`, every text toggle is `aria-disabled` with "no test reply has
  reached ConsentVault". 25-9 The text preview contains "Msg frequency varies. Msg & data rates may apply." and the
  agreement time with zone, and no input field. 25-10 No email preview contains "reply STOP". 25-11 The stop page shows
  two buttons, "Stop email" and "Stop everything". 25-12 The record-a-stop dialog names texts, calls and AI-voice calls
  and says email is not affected. 25-13 Every link in a preview uses the organization's link host, never a ConsentVault
  host. 25-14 A replies fixture with one reply older than 24 hours renders the alarm banner. 25-15 A disconnect answered
  `inbound_still_pointed_here` renders the named error and the account stays connected. 25-16 A START refused fixture
  shows the cause in plain words and the contact-us reply, never "sign up again". 25-17 With `provider_replies.stop`
  true, the activity row reads "Opt-out reply sent by Twilio". Twilio is the first provider in the connect picker. 25-18 The Twilio connect form asks for an API key SID and secret for sending and the auth token labelled "signature checks only". 25-19 No copy anywhere says ConsentVault reads Twilio's opt-out settings or list.
- AC: 25-1 With `not_marked`, every text toggle has `aria-disabled="true"` and the visible reason. 25-2 Mark complete is
  disabled until the statement box is ticked. 25-3 The template editor offers only subject and opening line; the fixed
  parts render read only from the preview and have no input. 25-4 A null `counts.to_read` renders "Not
  available". 25-5 A provider-refusal fixture (Twilio 21610) renders the alarm banner naming the count and records a stop. 25-6 Developer fixture shows no
  reply text. 25-7 Record a stop needs a reason before the button enables.

### Component inventory additions

| Component | Props | States |
|---|---|---|
| `BarChart` | `series[{date,count}], label, tableCaption` | loading, failed (named banner), reduced motion static |
| `ShareBar` | `channel, counts{found,stop,incomplete,none}` | missing (Not available) |
| `ContactSearch` | `onFind` | invalid phone, invalid email, found, none |
| `RevealToggle` | `on, onChange` | off, confirming, on, failed (returns to off) |
| `ExportDialog` | `count, onBuild` | reason required for full, building, ready, failed, too large |
| `SetupRail` | `steps[], current` | each step status; select under 760px |
| `Toggle` | `checked, disabled, reason` | on, off, disabled with reason |
| `TemplateEditor` | `template, fixedParts` | editing, invalid, saving |
| `MessagePreview` | `channel, rendered` | loading, failed |

### Not in scope (these additions)
- Loading earlier website signups recorded before the vault existed (they would carry today's receipt time).
- Model reading of replies: replies that are not a keyword always go to a person.
- Quiet hours for confirmations (they go out within minutes of the person's own submission or not at all).
- A people view joining several contact points into one person, beyond the linked-record count.
- Search or filter by name or company (both are encrypted per contact).
- A START reply turning texts back on (recorded, changes nothing).

### Owner rulings 2026-10-30 (applied above and in both contracts)
8. Confirmations send from the customer's own email domain and texting number, never ConsentVault's.
9. A stop word in a reply to a text stops texts, calls and AI-voice calls; email keeps its own consent. Not a setting.
   (Compliance gate 2026-10-30 overrides the earlier "texts only" ruling.)
10. Texts link to the full wording page and never include the wording. Email carries it in full.
11. Records show name and company when captured, encrypted under the contact's own key and erased with it; developers
    never see them. Capture gains two optional fields (records.md section 9).
12. Confirmations cost nothing extra: each recorded confirmation counts as one normal event; message cost sits on the
    customer's own accounts.

### Superseded open questions (kept for the record)
8. Who sends confirmation messages? Recommended: the organization's own connected email and text accounts, so messages
   leave under its identity and its texting registration; launch with Amazon SES or Postmark, and Twilio.
9. What does a STOP reply stop by default? Recommended: texts only, all purposes, matching the site's wording "Reply
   STOP to opt out of texts"; the organization can widen it.
10. Should a confirmation text carry the full wording or a link to it? Recommended: a link to the agreed-wording page;
    the full wording runs to about seven text segments. Email always carries it in full.
11. Should the vault hold names and company for the Records list? Recommended: no; it keeps contact points only and the
    owner reads names in the CRM.
12. How are confirmation messages charged? Recommended: counted as usage, included up to a plan amount.

---

## Build handoff list (Records, Setup walkthrough, Confirmation messages), in build order

Contracts of record: the cloud contracts for records, confirmations and setup, with amendments in the auth and
billing contracts and the contracts index. Migration numbers are the next
free ones at build time; renumber if taken. Every migration ships with its down file.

### 1. Migrations
1. `migrations/0029_records.sql`: tables `record` (never rebuilt, never deleted; one active row per
   fingerprint), `record_index` (derived, rebuildable), `record_display` (name and company under the display key, never
   hashed), `org_display_key` (wrapped by the org key), `org_alarm` (every feature's alarms); owner-rights functions `record_upsert`, `record_index_refresh`,
   `record_display_write`, `record_index_set_confirmation`, `record_index_rebuild`, modelled on `sync_advance_state`
   (`0004_sync.sql` line 201); redefinition of `consentvault.erase_contact(text)` (defined in `0014_erasure_holds.sql`
   line 213) to delete the display row, null `mask_ct` and set `record.erased_at`. Rebuild the security manifest with
   `scripts/build_security_manifest.py` and pass `--check` in the same change. (records.md 8, 9)
2. `migrations/0030_confirmations.sql`: `confirmation_send_intent` (unique on organization,
   fingerprint, channel and basis event), `confirmation_send`, `confirmation_send_status`, `confirmation_reply`,
   `confirmation_settings`, `confirmation_rule`, `confirmation_template`, `sending_account`, `confirmation_connect_test`, `confirmation_inbound_seen`
   (unique on organization, provider and provider message id), and the dated area code to single time zone table.
   (confirmations.md)
3. `migrations/0031_setup.sql`: `setup_step_skip`. (setup.md)
4. Later, before any message is called sealed: a migration adding `basis_event_id` and `message_sha256` to `contact_log`
   and joining it to the chain (core change C3).

### 2. Core changes (this open-source repository), in order
1. **K1** display key: `src/consentvault/tenancy/keys_adapter.py` (`new_display_key`, `display_key`, loader scope
   `worker:display_key`), `src/consentvault/tenancy/key_rotation.py` (`display_key` in `CENSUS_KINDS`, re-wrap beside the
   fingerprint secret), organization creation.
2. **P1** `src/consentvault/tenancy/pipeline.py`: `parse_capture` strips and validates `display` before the unknown-field
   check; the stored and hashed body is the canonical JSON of the rest (records.md section 9).
3. **R1** `src/consentvault/ledger.py`: `record_tenant_event` takes `display`, and beside `enqueue_event_pushes` calls the
   records functions (Python wrappers in new `src/consentvault/records.py`) and `enqueue_confirmation_intents` (new
   `src/consentvault/confirm/intents.py`), all in the event's transaction; `src/consentvault/capture.py`
   `tenant_capture` passes `display` through.
4. **C4** `src/consentvault/gate.py`: `record_tenant_contact` (fingerprint plus `contact_ct` by `encrypt_field`, bound by
   `field_aad`; the confirmations service's `capture_verified` token; no `INSERT ... RETURNING`).
5. **C2** `src/consentvault/release.py`: both `quiet_broken` queries ignore rows with `recorded_by = 'confirmations'`.
6. Confirmations service writes stops through `record_tenant_event` and START through `tenant_capture` with
   `checked: true`, in process inside `org_transaction`, never through the capture pipeline (confirmations.md section 7).
7. **S1** `src/consentvault/stopwords.py`: `start` only for a message that is exactly START, UNSTOP or YES; a start word
   with other words is `needs_review` (confirmations.md section 10).
8. **C3** contact log sealing: the migration in 1.4, `src/consentvault/seal.py`, `src/consentvault/proof.py`.

### 3. Cloud contract changes outside the new files
1. Capture: proof-export.md, capture.md, members.md and admin.md carry their 2026-10-30 amendments (applied in those files).
2. `POST /v1/proof` and `POST /v1/exports` accept `{record_id}`; by record id the proof returns the masked contact only.
3. `GET /v1/audit` items gain an optional `detail` object; new audit actions from records.md, confirmations.md, setup.md.
4. auth.md: portal scope `records_read`; developer and compliance viewer rows as amended.
5. billing.md: `contact_log` rows with `recorded_by = 'confirmations'` count as events; skips and retries do not.
6. admin.md: one operator-issued `capture_verified` credential per organization for the confirmations service.
7. `GET /v1/health`: confirmation counts (contract-gaps.md row F7).

### 4. Endpoints, in build order
1. Setup: `GET /v1/setup`, `POST /v1/setup/steps/{step}:skip`, `POST /v1/setup/steps/{step}:unskip`.
2. Records: `GET /v1/records`, `GET /v1/records/summary`, `POST /v1/records:search`, `POST /v1/records:reveal`,
   `POST /v1/records/exports`, `GET /v1/records/exports`, `GET /v1/records/exports/{export_id}`,
   `POST /v1/records/exports/{export_id}:link`.
3. Confirmations, configuration: `GET` and `PUT /v1/confirmations/settings`, `POST /v1/confirmations/sending-accounts`,
   `POST /v1/confirmations/sending-accounts/{id}:check`, `DELETE /v1/confirmations/sending-accounts/{id}`,
   `POST /v1/confirmations/link-host`, `POST /v1/confirmations/link-host:verify`,
   `POST /v1/confirmations/texting-registration`, `POST /v1/confirmations/texting-registration:withdraw`,
   `GET /v1/confirmations/rules`, `PUT /v1/confirmations/rules/{source_id}/{channel}`, `GET /v1/confirmations/templates`,
   `GET /v1/confirmations/templates/{template_id}`, `POST /v1/confirmations/templates`, `POST /v1/confirmations:preview`.
4. Confirmations, inbound before outbound (a stop must be catchable before anything is sent):
   `POST /v1/confirmations/inbound/{inbound_key}` (Twilio; Telnyx out of scope until built), then the sender worker, then
   `POST /v1/confirmations:test`.
5. Confirmations, reads and actions: `GET /v1/confirmations/sends`, `GET /v1/confirmations/replies`,
   `POST /v1/confirmations/replies/{reply_id}:mark`.
6. Public pages on the organization's link host: `GET /c/r/{token}`, `GET` and `POST /c/stop/{token}`.

### 5. Portal screens
Screen 24 setup walkthrough and the screen 05 checklist change; screen 23 records and the screen 13 changes (open by record
id, masked heading, "Show full contact point", contact log entries in the timeline); screen 25 confirmation messages;
navigation changes in ia.md.

### 6. Owner finding carried into the build
The published Terms say "To rejoin, sign up again as you did the first time or text START". The core does not let a
new web-form sign-up lift a stop (`docs/api.md`, the paragraph on `contact_control_unverified`), so
only the START half is true. The Terms page wording is the owner's to change.
