# Information architecture and route map

Host: `app.consentvault.ai` (Cloudflare Pages, static export, same design system as consentvault.ai).
Every authenticated route works inside exactly one organization at a time. The organization is part of the session,
never part of the URL, so a shared link never leaks which organizations exist.

## Navigation model

- **Top bar**: wordmark (link to Overview), organization switcher (only when the person belongs to 2 or more),
  person menu (name, role, sign out). Help link sits in the same place on every page (WCAG 3.2.6).
- **Side navigation**, four groups. Items a role cannot use are **hidden**, not disabled; deep links to them show
  the "not allowed for your role" state (wireframe 22).
- At widths under 760px the side navigation becomes a "Menu" button that opens a full-height panel.
- **Status banner slot** sits under the top bar on every page and shows organization status (trial, past due,
  suspended, offboarding) with the action that resolves it.

```
Start
  Overview ............................ /
  First test event .................... /setup/first-event
Evidence
  Evidence lookup ..................... /evidence
  Evidence packages ................... /exports
Configuration
  Brands .............................. /brands
  Capture sources ..................... /sources
  Credentials ......................... /credentials
  Wording ............................. /wording
  Policies ............................ /policies
  Documentation checklists ............ /checklists
  Connected systems ................... /systems
  Retention ........................... /retention
Organization
  Members ............................. /members
  Audit log ........................... /audit
  Billing ............................. /billing
  Settings ............................ /settings
  Rule references ..................... /references
```

## Route map (one job per route)

| # | Route | Wireframe | Job |
|---|---|---|---|
| 01 | `/sign-in` then WorkOS, then `/auth/callback` | wireframes/01-sign-in.html | Get a person signed in with a passkey, Google or Microsoft; no password anywhere. |
| 02 | `/invite?token=` | 02-invite.html | Turn a single-use invite link into a membership with a role. |
| 03 | `/choose-org` | 03-choose-org.html | Let a person in several organizations pick which one's records to work in. |
| 04 | `/start/plan`, `/billing/return?result=` | 04-plan.html | Send the first admin to Stripe checkout and land them on a clear outcome. |
| 05 | `/` | 05-overview.html | Show setup progress, policy in force, health and usage, with the next action. |
| 06 | `/setup/first-event` | 06-first-event.html | Take an admin or developer from credential to one recorded test event and confirm it arrived. |
| 07 | `/brands` | 07-brands.html | List and add the business names wording may name as the seller. |
| 08 | `/sources`, `/sources/[source_id]` | 08-sources.html | List and add the forms, CRMs and integrations that send consents. |
| 09 | `/credentials`, `/credentials/new` | 09-credentials.html | Issue, rotate and revoke machine credentials. |
| 10 | `/wording`, `/wording/new`, `/wording/[sha256]` | 10-wording.html | Register exact consent text and keep its version chain. |
| 11 | `/policies`, `/policies/new`, `/policies/[version]`, `/policies/[version]/approve` | 11-policies.html | Draft the evidence-to-action rules and approve them with a recorded attestation. |
| 12 | `/checklists`, `/checklists/[version]` | 12-checklists.html | Define documentation checklists that mark each record's elements present or missing. |
| 13 | `/evidence` | 13-evidence-lookup.html | Show everything held for one contact point, and start an export or erasure request. |
| 14 | `/exports`, `/exports/[export_id]` | 14-exports.html | Build, track and download a signed, offline-checkable evidence package. |
| 15 | `/systems`, `/systems/new`, `/systems/[system_id]` | 15-systems.html | Connect systems that must receive stops, see deliveries, redrive failures. |
| 16 | `/retention` | 16-retention.html | Show and raise how long evidence written from now on is kept. |
| 17 | `/members` | 17-members.html | Invite people with a role, change roles, remove people. |
| 18 | `/audit` | 18-audit.html | Show every privileged action: who, what, when, why. |
| 19 | `/billing` | 19-billing.html | Show plan, status and usage; open Stripe's hosted billing page. |
| 20 | `/settings` | 20-settings.html | Show organization identity and key status; request offboarding. |
| 21 | `/references` | 21-references.html | List dated rule citations and official links, for reading only. |
| 22 | any | 22-global-states.html | Role refusal, not found, offline, session ending, organization switched in another tab. |

Screen count: 21 screens plus 1 global-states sheet.

## Entry points

- Invitation email (SES, single-use link, 7-day expiry) -> 02.
- Bookmark or typed address -> 01 if signed out, else the last route.
- Security and delivery-failure emails deep link to 15 (system detail) or 18 (audit). Emails never carry personal data.
- Stripe returns -> `/billing/return?result=success|cancel` (from checkout) and `/billing` (from Customer Portal).

## Not in the portal at launch

Operator console (separate surface), EBR record and DNC scrub upload, legal hold management, operator access approval,
inbound signal browsing. Reasons and the endpoints each would need: handoff.md "Not in scope" and contract-gaps.md.
