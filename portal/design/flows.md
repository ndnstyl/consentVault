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
