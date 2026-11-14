# User flows

Every step has its failure branch. Screen numbers refer to ia.md. Where a step depends on an endpoint no contract
defines, the step is marked **(gap)** and listed in contract-gaps.md.

## F1. Invite to first test event, under 30 minutes (spec: new client to first recorded test event)

Time budget: email to sign-in 3 min; checkout 5 min; brand and source 3 min (often already created by the operator);
wording 5 min; credential 4 min; send and confirm 5 min. Total about 25 minutes.

```mermaid
flowchart TD
  A[Invite email, single-use link, 7 days] --> B[02 Invite page: org, role, expiry]
  B -->|token missing| B1[Error: link has no invitation. Next: open from email]
  B -->|expired / used / withdrawn| B2[Named error. Next: ask for new invite]
  B --> C[01 WorkOS hosted sign-in: passkey, Google, Microsoft]
  C -->|no second factor in token| C1[Error: sign-in needs a second factor. Next: add passkey or 2-step]
  C -->|WorkOS unreachable| C2[Error: sign-in did not finish. Next: retry]
  C -->|signed in as other address| C3[Partial: wrong account. Next: sign out and switch]
  C --> D[Membership created as admin. Success state on 02]
  D --> E[04 Choose plan]
  E -->|checkout session fails| E1[Error: checkout could not start. Nothing charged. Retry]
  E --> F[Stripe hosted checkout]
  F -->|cancel| F1[Return: checkout cancelled. Nothing charged. Choose plan or set up first]
  F -->|paid| G[Return: waiting for Stripe confirmation. Partial state; may start setup]
  G --> H[05 Overview, setup checklist]
  H --> I{Brand exists?}
  I -->|no| I1[07 Add brand] --> J
  I -->|yes| J{Source exists?}
  J -->|no| J1[08 Add source, origins] --> K
  J -->|yes| K[10 Register exact wording]
  K -->|409 already registered| K2[Use existing version]
  K --> L[09 Issue capture credential]
  L -->|private key pasted| L1[Refused; treat key as exposed]
  L --> M[Secret or client id shown once; confirm stored]
  M --> N[06 Copy command, send test event with a number you control]
  N --> O{Event arrives within 15 min? gap: latest event per source}
  O -->|refused by capture| O1[Error table maps 4xx/5xx to next action]
  O -->|nothing in 15 min| O2[Error: no event arrived. Keep waiting or open credentials]
  O -->|yes, unsealed| P[Partial: received, seal pending]
  P --> Q[Success: recorded and sealed. Link to evidence lookup]
```

Decision for Mike recorded in handoff.md open questions: whether setup may proceed before checkout completes in `trial`.
The flow above allows it, because billing.md lets a trial org exist with test data only.

## F2. Issue a credential (screen 09)

```mermaid
flowchart TD
  A[Credentials list] --> B[Issue: choose scope]
  B --> B1{Scope = gate check?}
  B1 -->|no policy in force| B2[Option disabled with reason and link to draft policy]
  B1 -->|policy in force| C
  B -->|capture or evidence read| C[Choose kind: site key, public key, signed webhook secret]
  C --> D{Kind}
  D -->|site key| E[Pick source; origins come from the source]
  D -->|public key| F[Paste public key, pick pinned algorithm]
  F -->|private key detected| F1[Refused, named; advise rotation]
  D -->|signed webhook| G[Pick source]
  E --> H[POST /v1/credentials]
  F --> H
  G --> H
  H -->|org suspended| H1[Paused banner; existing credentials keep working]
  H -->|error| H2[Named error, form kept]
  H --> I[Reveal once: copy, tick I stored it, Done]
  I -->|close without tick| I1[Confirm: secret will not be shown again]
  I --> J[List with new row; success banner; next: send test event]
  J --> K[Rotate = issue new, switch system, revoke old]
  K --> L[Revoke dialog with reason; immediate effect]
  L -->|error| L1[Named error; credential still active, said plainly]
```

## F3. Register consent wording (screen 10)

```mermaid
flowchart TD
  A[Wording list] --> B[Register form: exact text, label, channels, purposes, brands, replaces, shown from]
  B --> C{Client checks}
  C -->|no channel or brand| C1[Inline error on the field; focus moves there]
  C --> D[POST /v1/disclosures]
  D -->|409 same text exists| D1[Error with link to the existing version]
  D -->|unknown purpose| D2[Named error; purpose list gap]
  D -->|503| D3[Not registered; form kept; retry]
  D --> E[Detail page: fingerprint with copy button; success banner]
  E --> F[Wording is never edited. New version replaces old and links both ways]
```

## F4. Draft and approve a policy with attestation (screen 11)

```mermaid
flowchart TD
  A[Policies list] --> B{Policy in force?}
  B -->|none| B1[Empty state: gate returns evidence status only; credentials for gate wait]
  B --> C[Draft: start from in-force version, template gap, or blank]
  C --> D[Matrix: evidence status x channel -> proceed or hold; unavailable row; checklist select]
  D --> E[Save draft POST /v1/policies]
  E -->|error| E1[Named error; matrix kept]
  E --> F[Review and approve page]
  F --> G[Plain-words summary + attestation text, versioned, gap: read endpoint]
  G --> H{Attestation box ticked?}
  H -->|no| H1[Approve stays disabled with visible reason]
  H -->|yes| I[POST /v1/policies/version:approve; approver from session]
  I -->|another version approved meanwhile| I1[Error: superseded; open newer version]
  I -->|role not admin| I2[Role refusal]
  I --> J[Success: in force, recorded, cannot be changed; next: issue gate check credential]
```

## F5. Evidence lookup and evidence export (screens 13, 14)

```mermaid
flowchart TD
  A[Evidence lookup: enter phone or email] --> B{Client format check}
  B -->|incomplete| B1[Inline error naming the format]
  B --> C[POST /v1/proof contact in body]
  C -->|key_unavailable or 503| C1[Error: records could not be read. Never shows a status it could not read]
  C -->|found false| C2[Empty: no records in this organization. Never hints at other orgs]
  C -->|deliveries query fails| C3[Partial: rest shown, deliveries Not available]
  C --> D[Status by channel and purpose + policy action + notice; timeline; gate checks; deliveries]
  D -->|event unsealed| D1[Seal pending banner]
  D -->|review row present| D2[Later grant did not lift stop banner]
  D --> E[Build evidence package POST /v1/exports]
  E -->|org suspended| E1[Paused banner; link to billing]
  E --> F[Poll GET /v1/exports/id every 3 s, building]
  F -->|failed| F1[Named cause; start again resumes]
  F --> G[Ready: download once within 15 min; sha256; how to check offline]
  G -->|link used or expired| G1[Get a new link gap]
```

## F6. Suppression deliveries and redrive (screen 15)

```mermaid
flowchart TD
  A[Alert email: deliveries to Dialer undelivered] --> B[15 System detail]
  A2[Overview tile: undelivered stops] --> B
  B -->|list fails| B1[Error; pushes keep running]
  B -->|counts fail| B2[Partial: Not available, never zero]
  B --> C[Dead list: time, fingerprint, channel, last answer, attempts]
  C --> D[Send a test push to confirm the system is fixed gap: route]
  D -->|non-2xx or timeout| D1[Named answer: code and time; next action per code]
  D -->|2xx| E[Redrive dialog with reason]
  E --> F[POST /v1/deliveries:redrive system_id]
  F -->|error| F1[Named error; nothing re-queued]
  F --> G[Success: N re-queued, sent in order; rows update to acknowledged]
```

## F7. Invite a member (screen 17)

```mermaid
flowchart TD
  A[Members] --> B[Invite: email, role with plain description]
  B -->|invalid email| B1[Inline error]
  B --> C[POST /v1/members]
  C -->|already a member| C1[Named error; open member]
  C -->|email send failed| C2[No invite created; retry]
  C --> D[Success: invited row with expiry; withdraw gap]
  D --> E[Invitee follows F1 steps A to D, then lands on Overview with their role]
```

## F8. Billing through Stripe's portal (screen 19)

```mermaid
flowchart TD
  A[Billing page: plan, status, usage gap] --> B[Manage billing on Stripe]
  B --> C[POST /v1/billing/portal]
  C -->|error| C1[Stripe page could not be opened; retry; nothing changed]
  C --> D[Stripe Customer Portal: invoices, payment method, cancel]
  D --> E[Return to /billing: changes can take a minute]
  E --> F{Webhook state}
  F -->|invoice.payment_failed| F1[Past due banner everywhere; capture continues]
  F -->|subscription.deleted| F2[Suspended banner; exports and new credentials paused; offboarding not started]
```

## F9. Offboarding request (screen 20)

```mermaid
flowchart TD
  A[Settings: what leaving does, in order] --> B[Request offboarding dialog: reason, type org name]
  B -->|name mismatch| B1[Inline error]
  B --> C[Client request endpoint gap]
  C -->|error| C1[Not sent; nothing changed]
  C --> D[Success: operator will contact admin to confirm dates]
  D --> E[Operator runs POST /v1/orgs/id/offboard]
  E --> F[Progress: final export delivered, credentials revoked, key destruction scheduled, destruction record]
  F -->|legal hold active| F1[Key destruction delayed for the held scope; shown with hold date]
```

## F10. Erasure request for one person (screen 13)

```mermaid
flowchart TD
  A[Evidence lookup result] --> B[Request erasure dialog: what is kept, what is lost, reason]
  B --> C[POST /v1/contacts:erase]
  C -->|legal hold| C1[Refused, hold named]
  C -->|error| C2[Not sent]
  C --> D[Pending operator confirmation gap: status read]
  D --> E[Done: contact unreadable; stop kept; chain verifies]
```

## Additions 2026-10-30

## F11. Work the records list (screen 23)

```mermaid
flowchart TD
  A[Nav: Records, or Overview tile, or a link with filters] --> B[GET /v1/records + GET /v1/records/summary, same filters]
  B -->|audit row not written| B1[Error: list not shown, audit_unavailable. Try again]
  B -->|list fails| B2[Error: named cause. Capture unaffected. Try again]
  B -->|summary fails| B3[Partial: tiles or chart Not available, list shown]
  B -->|display key fails| B4[Partial: contact column Not available, statuses and stops shown]
  B -->|no records at all| B5[Empty: no records yet. Send a test event]
  B --> C[Tiles, chart, channel share, table, pager]
  C --> D{What next}
  D -->|change a filter| E[URL query updates, back button restores, focus stays on the control] --> B
  E -->|no match| E1[Empty: filters named, Clear filters]
  D -->|Find exact contact| F[POST /v1/records:search contact in body, URL unchanged]
  F -->|invalid| F1[Inline: not a complete phone number or email]
  F -->|none| F2[Empty: no record for that exact contact in this org. Back to list]
  F --> G[One row]
  D -->|open a row| H[13 /evidence?record=id; POST /v1/proof record_id]
  H -->|back| C
  D -->|Show full contact points| I[First time this session: confirm dialog, optional reason]
  I --> J[POST /v1/records:reveal page ids]
  J -->|audit_unavailable or key_unavailable| J1[Error banner, masks stay, toggle returns to off]
  J -->|rate_limited| J2[Banner: wait N seconds, masks stay]
  J --> K[Full contact points on this page; banner with audit time; each later page reveals again]
  D -->|Export this list| L[Dialog: masked, full with reason, or fingerprints]
  L --> M[POST /v1/records/exports]
  M -->|export_too_large| M1[Error with count; change filters]
  M -->|org_suspended| M2[Paused banner, link to billing]
  M --> N[Poll every 3 s: building N of M] -->|failed| N1[Named cause; export again]
  N --> O[Ready: download once in 15 min, fingerprint, kept 24 h]
  O -->|link used or expired| O1[Get a new link while kept; after 24 h build again]
```

## F12. First-run walkthrough, invitation to first system (screen 24, ties to 05)

```mermaid
flowchart TD
  A[02 invitation accepted] --> B{Role and setup state, GET /v1/setup}
  B -->|compliance viewer| B1[05 Overview, setup progress read only]
  B -->|setup already done| B2[05 Overview]
  B -->|setup read fails| B3[05 Overview with the error; Setup link retries]
  B --> C[24 Welcome: 8 steps, time estimate, trial note]
  C --> D[Step = first not done and not skipped]
  D --> E{Step kind}
  E -->|admin-only step, developer signed in| E1[Waiting on an admin; go to the next step this role can do]
  E -->|depends on an unfinished step| E2[Names the step it needs; button opens it]
  E -->|org suspended and step creates a credential or system| E3[Paused, link to billing; earlier steps stay done]
  E --> F[Step form, same component and endpoint as its own screen]
  F -->|write fails| F1[Named error, form kept, step stays To do]
  F --> G[Step done: success line; Continue to next]
  G --> H{Step 5 test event}
  H -->|no event in 15 min| H1[Named: no event arrived; keep waiting, check credential, or leave and return]
  H -->|received, seal pending| H2[Partial: received; continue allowed]
  H --> I[Step 6 policy: template or blank, approve with attestation, returns to setup]
  I -->|policy_superseded| I1[Open newer version]
  I --> J[Step 7 connect a system, optional]
  J -->|skip| J1[Skip dialog, optional reason; POST skip; shown Skipped on 05]
  J -->|test push fails| J2[Named answer; system saved, step stays To do until a test push answers 2xx]
  J --> K[Step 8 confirmations, optional, opens 25 in setup mode]
  K --> L[Setup complete: Records, or turn on skipped steps]
  D -.->|leave at any point| M[05 shows the same steps; Resume setup opens the first open step]
```

Done is read from the server, never from the browser: a step is done when its fact exists (a brand, a source, a
registered wording, an active capture credential, a recorded event, an approved policy, a connected system with a 2xx
test push, a confirmation rule on). Skips are stored server side with who and when, so another admin or device sees the
same progress.

## F13. A new consent triggers a confirmation (screen 25, evidence on 13). Revised 2026-10-30

```mermaid
flowchart TD
  A[Grant recorded from source S] --> B[Same transaction: one send intent per enabled rule, unique per contact, channel and consent event]
  B -->|duplicate| B0[Nothing new]
  B --> C[Worker locks the intent]
  C --> D{Checks in order: channel in grant, contact kind, sending brand named in grant, arrived within delay, texts only: quiet hours in recipient zone and zone known (email has no sending hours), no stop, no recent confirmation, texting registration and test reply and link host, org active, test-event option}
  D -->|any fails| D1[Skip recorded with its name; never delayed into the next window]
  D --> E[Send from the organization's own domain or number]
  E -->|retryable error| E1[Retry at 1, 2, 4, 8, 16, 32, 57 min; each try re-checks stop, registration, org status, and quiet hours for texts]
  E1 -->|a re-check fails| D1
  E1 -->|still failing after about 2 hours| E2[Dead: recorded, listed under Undelivered, never retried]
  E -->|non-retryable refusal| E3[Failed with provider code; a text opt-out answer also records the stop, F14]
  E --> F[Sent: exact text sealed in the chain; counts as one event; delivery report updates status]
```

## F14. Replies, stop links and START (screen 25, 23, 13). Revised 2026-10-30

```mermaid
flowchart TD
  A[Person texts the organization's number] --> B[Provider posts to the inbound address]
  B -->|signature fails| B1[401; 5 in 10 min raises the signature alarm on 25]
  B -->|vault cannot record| B2[503 so the provider retries; a provider refusal of the next send is the backstop]
  B --> C{Classify: a stop word anywhere wins}
  C -->|core classifier: stop, or a stop word inside a longer message| D[Stop, method keyword: the org's channels among texts, calls, AI-voice calls; email kept; pushed to connected systems]
  D --> D1{Admin answered Yes: does Twilio reply to STOP, HELP and START itself?}
  D1 -->|no| D2[One opt-out reply within 5 min, any hour; dead after 5 min alarms]
  D1 -->|yes| D3[None from us]
  C -->|HELP| E[One reply: brand, help contact, how to stop, rates line]
  C -->|START| G{Stop on record?}
  G -->|no| G3[Recorded, nothing changes, no reply]
  G -->|yes| G0[Grant for texts only: prior purposes and wording, inbound_keyword, session_ref from the provider message id]
  G0 --> G4{Core release rule decides}
  G4 -->|released| G1[Texts on again; calls stay stopped; reply unless Twilio answers START]
  G4 -->|refused: staff, system or import stop, no earlier grant, contact since stop| G2[Stop kept; reply: contact us at help contact; to read with the cause]
  C -->|other| F[To read; count on 25 and overview]
  F -->|unread 24 h| F1[Alarm row on 25 and overview; no email]
  F --> F2{Admin decides, reason required}
  F2 -->|stop| D
  F2 -->|not a stop| F3[Marked, audited]
  H[Email stop link on the organization's domain] --> I[Page: Stop email, or Stop everything]
  I -->|email| J[Revoke email]
  I -->|everything| K[Revoke email, texts, calls, AI-voice calls]
  I -->|already stopped| I1[Already stopped; nothing new]
  I -->|vault down| I2[Not recorded, try again; buttons kept]
  L[Provider refuses a send: number opted out at the provider, Twilio 21610] --> L2[Stop recorded, recorded_by provider_refusal; alarm on 25]
```

## F15. Turn texts on (screen 25). Revised 2026-10-30

```mermaid
flowchart TD
  A[25 Texts off] --> B[Connect a text provider: Twilio]
  B -->|provider_not_supported, refused or unreachable| B1[Named error with provider code; nothing saved]
  B --> C[Point the number's incoming webhook at the inbound address; vault sets it when it can, else shows field and value]
  C --> D[Vault reads whether the provider sends its own opt-out reply]
  D --> E[Admin texts the number from a phone they hold]
  E -->|nothing in 15 min| E1[Named: no test text arrived; show the webhook step again]
  E --> F[Test reply arrived; account connected]
  F --> G[Wording link host on the organization's domain: CNAME and TXT, check]
  G -->|link_host_dns_missing| G1[Named record missing; check again]
  G --> H[Sender details: name, postal address, help contact]
  H --> I[Mark texting registration: approved box and filed-samples box, the four fixed texts shown]
  I -->|a box unticked| I1[Mark complete disabled with reason]
  I --> J[Text toggles available per source]
  J --> K[On. Next new consent naming texts and the sending brand gets one, inside quiet hours only]
  K -.->|withdraw, disconnect, fixed text changes, link host failing| L[Texts off at once; queued texts recorded as not sent]
```
