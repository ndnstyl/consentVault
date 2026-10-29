# Copy rules

The portal shows records as evidence and the client's own policy outcome. It never states a legal conclusion
(spec: foundational principle; requirements on no legal conclusions, evidence-not-proof, and separate evidence status
and policy action). No em dashes and no en dashes anywhere.

## 1. Banned in any portal string

Matched case-insensitively by the copy check (acceptance criterion G-3 in handoff.md, which holds the exact patterns).
"Not legal advice" and "not a legal test" are disclaimers and are allowed.

| Banned | Why | Say instead |
|---|---|---|
| compliant, compliance status, non-compliant, in compliance | legal conclusion | "what the records show", "documentation completeness" |
| valid consent, consent is valid, invalid consent | legal conclusion | "consent record found", "no record" |
| prove, proves, proven, proof (as a claim) | storage does not establish consent | "records", "evidence", "verified (integrity)" |
| lawful, legally sufficient, permitted to / allowed to (contact, call, text, email, dial) | legal conclusion | "your policy: proceed", "your policy: hold" |
| PEWC satisfied, EBR qualifies, meets TCPA | legal conclusion | "checklist: 5 of 5 elements present", "relationship dates on record" |
| safe to call, cleared to text, OK to contact | legal conclusion | "your policy: proceed" |
| guaranteed, holds up in court, court-ready, litigation-proof | claim the site already refuses | "checkable offline by anyone" |
| Something went wrong (alone) | unnamed failure | cause plus next action, section 4 |

The noun "proof" is not used in labels. The contract's `/v1/proof` is labelled **Evidence lookup**, and the export is an
**evidence package**.

## 2. The only three strings allowed to contain a banned word

They are fixed, versioned, and allowlisted by exact match. Changing one is a copy change with Mike's sign-off.

1. Gate notice (contracts/gate.md), shown under every evidence status:
   "Evidence status and the outcome of your organization's approved policy. Not a legal determination."
2. Package cover sentence (contracts/proof-export.md), shown on screen 14:
   "Its cover page states that the records are evidence for an investigation or dispute, and that storing a record does
   not by itself establish valid consent."
3. Attestation text, version 1 (screen 11). **Draft; needs Mike's ruling on final wording:**
   "I am an admin of [Organization]. [Organization] is responsible for whether this policy is legally sufficient for its
   marketing. ConsentVault recommends that [Organization]'s counsel review it before approval. ConsentVault applies this
   policy as written and does not decide whether any communication is permitted by law."

## 3. Label dictionary (API value to screen words)

| API value | Screen label | Chip icon |
|---|---|---|
| `consent_record_found` | Consent record found | filled diamond |
| `stop_on_record` | Stop on record | diamond with bar |
| `no_record` | No record | hollow diamond |
| `record_incomplete:<elements>` | Record incomplete: missing <element names> | half diamond |
| `unavailable:<cause>` | Not available: <cause in plain words, table in section 5> | warning triangle |
| `policy_action: proceed` | Your policy: proceed | arrow |
| `policy_action: hold` | Your policy: hold | pause bars |
| `policy_action: null` + `no_policy_configured` | No policy in force | dash |
| push `state: denied` | Suppress | |
| push `state: permitted` | Release suppression | |
| delivery `sent` / `acknowledged` / `failed` / `dead` / `superseded` | Sending / Acknowledged / Retrying / Undelivered (dead) / Replaced by a newer change | |
| signal `applied_as_event` / `no_change` / `ignored_stale` / `conflict_stop_wins` | Recorded / No change / Older than our record / Stop on record kept | |
| event `grant` / `revoke` / `suppress` / `release` | Grant / Stop (revoke) / Stop (suppress) / Stop lifted | |
| org `trial` / `active` / `past_due` / `suspended` / `offboarding` / `closed` | Trial / Active / Past due / Suspended / Offboarding / Closed | |

Every chip carries the icon and the word. Color is never the only signal.

## 4. Error copy formula

`<What did not happen, in past tense>` + `Cause: <plain cause> (<http status> <error name>)` + `Next: <one action>` +
a button that does that action. Also say what was **not** changed when that is true ("Nothing was charged",
"Nothing was changed", "Pushes keep running while this page is down").

## 5. Cause dictionary for `unavailable:<cause>` and portal errors

| Name | Plain cause |
|---|---|
| `key_unavailable` | your organization's encryption key did not answer |
| `database_unreachable:*` | the records database did not answer |
| `service_unavailable` | the service did not answer |
| `stripe_unavailable` | Stripe did not answer |
| `email_send_failed` | the email service did not accept the message |
| `org_not_active` | your organization is not active |
| `invalid_contact:phone` / `invalid_contact:email` | that is not a complete phone number / email address |
| any unknown name | "the service answered <status> <name>", shown raw, never hidden |

## 6. Numbers

- Unknown is not zero. A count the API did not return reads **Not available**, never 0 and never a dash alone.
- Dates: "Nov 3, 2026, 9:12 AM ET" in the viewer's time zone with the zone named; machine times in a `<time datetime>`.
- Contact points: shown in full only on screen 13 to roles that may read them; elsewhere masked "(555) ***-0100" or as
  a fingerprint.

## 7. Voice

Plain, specific, short. Second person. Verbs first on buttons ("Issue a credential", "Redrive now"). No exclamation
marks, no "Oops", no "Great job".
