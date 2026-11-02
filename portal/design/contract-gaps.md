# Contract gaps

Every portal element must name its endpoint. Where no contract under
the cloud contracts defines one, it is listed here instead of invented.
"Suggested" is a shape for the API owner to accept or replace; the portal build must not call any row here until the
contract carries it. Each row names the screens that wait on it.

## A. Conflicts between existing documents (resolve first)

| # | Conflict | Where | Screens | Recommendation |
|---|---|---|---|---|
| A1 | Org status values: `active, suspended, offboarding, closed` vs `trial, active, past_due, suspended, closed` | data-model.md line 44 vs spec (organization lifecycle requirement) and billing.md | 04, 05, 14, 19, 20 | One enum: `trial, active, past_due, suspended, offboarding, closed`. |
| A2 | Proof is `GET /v1/proof` vs `POST /v1/proof {contact}` | contracts/README.md vs proof-export.md | 13 | POST. The contact must never be in a URL. |
| A3 | `POST /v1/rule-sets` and `POST /v1/policies` both listed; model says policy replaces rule set | admin.md vs data-model.md line 280 | 11 | Drop rule-sets from admin.md. |
| A4 | Org creation at `POST /v1/orgs` vs `POST /v1/admin/orgs` | admin.md vs billing.md | operator only | Pick one. |
| A5 | Member roles: `admin, compliance_viewer` only; brief asks for `developer` | admin.md, data-model.md line 48 | 17, roles.md | Add `developer` (roles.md defines it). |
| A6 | `POST /v1/oauth/token` scope `admin` "portal only" vs portal tokens minted from WorkOS sessions | auth.md | all | Confirm the portal never holds an `admin`-scoped machine token. |

## B. Missing reads (the portal cannot list what it cannot read)

| # | Missing | Screens | Suggested |
|---|---|---|---|
| B1 | Current session: memberships, roles, org status | 01, 03, all | `GET /v1/session` -> `{user, memberships:[{org_id, name, role, status}]}`; `POST /v1/session/org {org_id}` |
| B2 | Current organization: name, status, region, key status and version, plan | 05, 19, 20 | `GET /v1/org` (admin full; others name and status) |
| B3 | Credential list | 09 | `GET /v1/credentials` -> id, name, kind, scope, source_id, algorithm, created_at, revoked_at, last_used_at |
| B4 | Credential issue answer shape (client id, site key id, one-time secret) | 09 | Define the 201 body; secret returned once. |
| B5 | Wording list and one version | 10, 13 | `GET /v1/disclosures`, `GET /v1/disclosures/{sha256}` |
| B6 | Configured purpose list | 06, 10 | `GET /v1/purposes` (capture refuses unknown purposes with `UnknownPurposeError`) |
| B7 | Policy list, one version with rules, status | 05, 09, 11 | `GET /v1/policies`, `GET /v1/policies/{version}` |
| B8 | Policy templates | 11 | `GET /v1/policy-templates` |
| B9 | Attestation text and version | 11 | `GET /v1/attestations/current` -> `{version, text, sha256}` |
| B10 | Policy rules schema (evidence status x channel x purpose -> action; unavailable action; checklist reference) | 11 | Define `policy.rules` JSON. |
| B11 | Checklist list, one version, element schema | 12 | `GET /v1/checklists`, `GET /v1/checklists/{version}` |
| B12 | Checklist results per record | 13 | Add `doc_check_results` to the proof answer. |
| B13 | Retention: value in force, platform minimum, history | 16 | `GET /v1/retention` |
| B14 | Connected systems list and detail (config without secrets, state) | 15 | `GET /v1/systems`, `GET /v1/systems/{id}` |
| B15 | Per-system delivery summary and dead list (fingerprints, not contacts) | 05, 15 | `GET /v1/systems/{id}/deliveries?status=dead` |
| B16 | Test push route and answer (status, latency, error) | 15 | `POST /v1/systems/{id}:test` |
| B17 | Inbound signal list per system | 15 (not in scope at launch) | `GET /v1/systems/{id}/signals` |
| B18 | Export list and progress count; new link for a ready package | 14 | `GET /v1/exports`; `progress {done, total}` on the status answer; `POST /v1/exports/{id}:link` |
| B19 | Latest event per source (time, seq, sealed or not; no personal fields) | 06, 08 | `GET /v1/sources` fields `last_event_at`, `last_event_seq`, `last_event_sealed` |
| B20 | Source field schema (kind, brands, allowed origins), edit and retire | 08 | Define the body for `POST /v1/sources`; `PATCH /v1/sources/{id}` |
| B21 | Health counts: events unsealed past 1 hour, dead deliveries, last chain verification | 05, 13 | `GET /v1/health` (counts, never personal data) |
| B22 | Usage this period vs plan inclusions | 05, 19 | `GET /v1/billing` -> plan, status, included, used, last_reported_at |
| B23 | Plan list for checkout (Stripe price metadata) | 04 | `GET /v1/billing/plans` |
| B24 | Proof answer field schema for the cloud (gate decisions, deliveries, seal status per event, review rows) | 13 | Document on top of the core's keys: `timeline, permissions, disclosures, contact_log, reviews, chain{head,events,path,anchors}` (`src/consentvault/proof.py` lines 171-186). |
| B25 | Audit filters and paging, action name list | 18 | `GET /v1/audit?action=&actor=&from=&to=&cursor=` |
| B26 | Pending invitations | 17 | `GET /v1/members?include=invites` |

## C. Missing writes and actions

| # | Missing | Screens | Suggested |
|---|---|---|---|
| C1 | Invitation lookup and accept, with reasons expired, used, withdrawn, wrong account | 02 | `GET /v1/invites/{token}`, `POST /v1/invites/{token}:accept` |
| C2 | Change a member's role, remove a member, withdraw an invite | 17 | `PATCH /v1/members/{id}`, `DELETE /v1/members/{id}`, `DELETE /v1/invites/{id}` |
| C3 | Client-side offboarding request (only operator endpoints exist) | 20 | `POST /v1/offboarding-requests {reason}` |
| C4 | Offboarding progress read | 20 | part of `GET /v1/org` |
| C5 | Erasure request status (needs operator confirmation) | 13 | `GET /v1/erasures/{id}` |
| C6 | Who may issue a `capture_verified` credential (auth.md says "issued separately") | 09 | Operator only; say so in auth.md. |
| C7 | Client approval of an operator access request | not in scope | `POST /v1/operator-access/{id}:approve` |
| C8 | Stripe return URLs (checkout success and cancel, Customer Portal return) | 04, 19 | Fix them in billing.md. |

## D. Missing error names (the portal shows the name; it needs to know it)

`brand_exists`, `invalid_origin`, `private_key_refused`, `policy_required` (gate credential without an approved
policy), `disclosure_exists`, `policy_superseded`, `below_platform_minimum`, `last_admin`, `email_send_failed`,
`stripe_unavailable`, `org_suspended` (exports and credentials paused), `legal_hold_active`, `role_not_allowed`,
`invite_expired`, `invite_used`, `invite_withdrawn`, `invite_wrong_account`. Plus one rule: every admin endpoint answers
the README's `{"error", "detail"}` shape.

## E. Conventions not stated

Pagination (cursor), sort order, time zone of timestamps (assume UTC ISO 8601), and maximum list sizes for every list
endpoint.

## F. Additions 2026-10-30

Two new contracts are proposed in full: `contracts/records.md` and `contracts/confirmations.md`
(the cloud contracts). They need the README index rows and error names
listed at their ends. The rows below are the gaps that remain outside those two files.

| # | Missing | Screens | Suggested |
|---|---|---|---|
| F1 | **Moved to contracts/setup.md.** Setup progress read, resumable across devices | 05, 24 | `GET /v1/setup` (A, D, V) -> `{steps: [{step: "brand"|"source"|"wording"|"credential"|"first_event"|"policy"|"system"|"confirmations", status: "done"|"to_do"|"skipped"|"blocked", required: bool, evidence: {kind, id, at}|null, blocked_reason|null, skipped_by|null, skipped_at|null, roles: ["admin"|"developer"]}], current_step, complete: bool, partial: [steps not readable]}`. Done is derived from facts (brand exists, source exists, wording registered, active capture credential, first event recorded, policy approved, system with 2xx test push, a confirmation rule on); never a client flag. |
| F2 | **Moved to contracts/setup.md.** Skip and un-skip an optional step | 24, 05 | `POST /v1/setup/steps/{step}:skip {reason?}`, `:unskip`; only `system` and `confirmations` are skippable (`validation_failed` otherwise); audited `setup.step_skipped`. |
| F3 | Proof and export keyed by record id | 13, 23 | `POST /v1/proof {record_id}` and `POST /v1/exports {record_id}` (records.md section 9). |
| F4 | Audit item `detail` object | 18, 23 | additive field on `GET /v1/audit` items (records.md section 6). |
| F5 | Contact log entries sealed in the chain | 13, 25 | core change C3 in confirmations.md section 10 (new migration, `seal.py`, `proof.py`); until then messages are recorded in `contact_log`, not sealed. |
| F6 | Withdrawn 2026-10-30. Portal times use the viewer's zone; message times use the recipient's zone (texts from the area code; email from the record or a linked phone, else UTC named), confirmations.md sections 5 and 6. | 23, 25 | none |
| F7 | Health counts for the overview | 05 | `GET /v1/health` adds `confirmations: {failed_24h, dead_24h, replies_to_read, provider_refusal_stops_24h}` (each null when unreadable). |
| F8 | Developer access to `GET /v1/records` | 23 | auth.md developer row: records list and summary with fingerprints only. |
| F9 | Withdrawn 2026-10-30: no time zone is captured; it is derived at send time from the record's area code (confirmations.md section 5). | 25 | none |
| F10 | START lifting a text stop | 25, 13 | No new core path. The START grant meets `_judge` in `src/consentvault/release.py` as written: `session_ref` set from the provider message id (the `has_session` branch), reply and stop-page stops recorded with releasable methods `keyword`, `written`, `checkbox` (the `RELEASABLE_STOP_METHODS` branch; tuple at line 37), `contact_verification: inbound_keyword`. One core change remains, C2 in confirmations.md section 10: the quiet-window query (lines 123 to 128 and 316 to 321) ignores every contact log row with `recorded_by = 'confirmations'` (opt-out, HELP and START replies); until then a deployment with `CONSENTVAULT_RELEASE_REQUIRE_NO_CONTACT_SINCE_STOP` on refuses START with `contact_since_stop`. Also: the published Terms promise that signing up again rejoins texts, which the core refuses (`docs/api.md` line 50); owner finding. |
| F11 | Fixed text versioning for confirmation, opt-out, HELP and START texts | 25 | `fixed_text_version` on settings; a change turns text rules off until registration is re-marked. |
| F12 | Area code to single time zone table | 25 | vault-owned reference table, dated, in `0030_confirmations.sql`; used for texts only (quiet hours); a number whose area code spans zones is unknown and its text is skipped. Email never uses it for sending hours (confirmations.md section 5). |
| F13 | Tenant contact-log writer | 13, 25 | core change C4 in confirmations.md section 10: a writer in `src/consentvault/gate.py` storing fingerprint plus ciphertext; `record_contact` is refused in multi mode by `migrations/0002_tenancy.sql` lines 566 to 587. |
| F14 | Name and company display table | 23 | `migrations/0029_records.sql` (records.md section 9); never in the evidence object or the chain. |
| F15 | Records index written under capture tokens | 23 | owner-rights SQL functions in `0029_records.sql` (records.md section 8); a capture token cannot read `event` or `current_permission` (`0002_tenancy.sql` lines 851 to 853). |
| F16 | Display key | 23 | core change K1 (records.md sections 8, 9). |
| F17 | Capture body without `display` | 23 | core change P1 in `pipeline.py` (records.md section 9). |
