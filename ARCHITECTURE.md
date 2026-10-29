# ConsentVault.AI architecture

ConsentVault.AI is a consent vault: a tamper-evident record of who agreed to be contacted, how, on which channels,
under which exact wording, and who later said stop. It is built to answer one question under scrutiny:
*"Prove this person agreed to this contact, and that they had not withdrawn it."*

This document describes the design.

## Principles

1. **Append-only.** Events are inserted, never updated or deleted. A database trigger refuses UPDATE/DELETE.
2. **Chained and anchored.** Every event row carries `prev_hash` and `row_hash`. `row_hash` is the sha256 of
   `prev_hash` followed by the canonical JSON of three digests: `contact_commit` (sha256 of the contact's own random salt followed by the contact point),
   `subject_commit` (sha256 of the same salt followed by the subject key) and `content_sha256` (sha256 of the canonical JSON of **every**
   evidence column, hash version 1). Because each link carries its own commitments, a reader can recompute the
   chain, and which links belong to one person, without seeing anyone else's data. A column added later gets a
   new `hash_version` in a new migration; old rows verify under their own version forever. The head of the chain
   is anchored outside the database (`consentvault anchor`), and `verify_chain` fails when a row up to an anchor is missing.
   An exported bundle carries the whole chain path from seq 1 (other people's links as commitments only), and its
   `verify.py` takes the anchors from outside (`--anchor` or `--anchors`), so a path cut at the front or the tail fails.
3. **Sealed outside.** Each event's digest is timestamped by an RFC 3161 authority (configurable; required, no default).
   Only the 32-byte digest leaves the host. Seals live **in the database** (`seal` table, token bytes included).
   See docs/evidence-model.md for what a seal covers.
   `verify-seals` also fails an event that has stayed unsealed longer than a configured delay (default one hour).
4. **The wording is evidence.** The exact disclosure text the person saw is stored once by sha256
   (`disclosure` table), registered by an operator with its channels and purposes, and every grant references
   it by hash. The capture surface sends only the hash of what it rendered at submit time; the vault refuses a
   grant whose hash it does not hold or whose channels and purposes exceed the wording's.
5. **Fail closed.** If the vault cannot answer, the answer to "may I contact?" is no, with a named reason.
6. **Two roles.** The owner role (migrations only) owns the schema. The runtime role is a member of the group
   role `consentvault_app`: SELECT and INSERT (SELECT only on `contact_salt`), two SECURITY DEFINER functions with a
   pinned search path (stamp `seal.verified_at`; mint a contact's salt), no ownership, no TRUNCATE, no way to disable a trigger.
7. **A stop is lifted only by a contact whose control was verified.** A release of a consumer's own stop needs a grant
   whose `contact_verification` is `otp` or `inbound_keyword`; a plain web-form grant is refused with cause
   `contact_control_unverified` and a pending `review` row. The release insert trigger enforces the same rule.
7. **Arrival order decides.** Permission is decided by `seq`. `received_at` is the vault server's own clock (a
   database trigger refuses any other value); the capture edge's receipt time is stored apart as
   `edge_received_at`, evidence only. `captured_at` is evidence and is refused when it is later than `received_at`
   plus five minutes.
8. **Errors are raised as typed exceptions with a non-zero exit.**
9. **No vendor in the core.** CRMs, SMS and email providers plug in through small adapter interfaces.
   The core knows contact points, channels, purposes and events, nothing else.
10. **White label.** No brand, company, person, phone number, domain or path is hardcoded. All of it is config.

## Data model (relational database; supported versions in docs/deployment.md)

Schema `consentvault`. One clean, ordered set of migrations in `migrations/` (`0001_init.sql`, ...), each with a matching
`down/` file. Fresh install = apply in order.

| Table | Purpose |
|---|---|
| `contact_salt` | `contact_norm` PK, `salt` (32 random bytes), `created_at`. Insert-once and append-only; minted on a contact's first event by the owner-defined `mint_contact_salt` function (32 bytes drawn in the database, under the ledger lock); the runtime role has SELECT only and cannot insert. A trigger refuses an event whose `contact_salt` is not its contact's. |
| `disclosure` | `sha256` PK, `body` text, `label`, `locale`, `channels[]`, `purposes[]` (lower-case, no `*`), `first_seen_at`. Immutable; registered by an operator, never by a client. |
| `event` | the chained ledger: `event_id`, `subject_key` (stable person key), `contact_kind` (`phone`/`email`), `contact_norm` (E.164 or lowercased email), `contact_salt` (the contact's own random 32 bytes, hex, copied from the append-only `contact_salt` table), `contact_commit` (sha256 of `contact_salt` followed by `contact_norm`), `event_type` (`grant`, `revoke`, `suppress`, `release`), `channels` (voice, artificial_voice, sms, email), `purposes` (lower-case; `*` only on a stop), `disclosure_sha256`, `method` (checkbox, verbal, written, keyword, staff, import), `origin` (consumer, staff, regulatory, import), `captured_at`, `received_at` (the vault's clock), `edge_received_at` (the edge's claimed receipt time), `page_url`, `client_ip`, `user_agent`, `session_ref`, `bot_check`, `payload_sha256`, `source` (capture surface id), `recorded_by`, `release_of_event_id` / `release_outcome` (`released` or `refused`) / `release_cause` (release events only), `contact_verification` (`none`, `otp`, `inbound_keyword`; consumer grants only), `hash_version`, `prev_hash`, `row_hash`. |
| `seal` | `event_id`, `hash_version`, `columns[]`, `digest`, `tsa_url`, `token` (DER bytes), `gen_time`, `verified_at`. |
| `chain_head` | anchors: (`seq`, `row_hash`, `sink`, `anchored_at`) written by `consentvault anchor`, also written to a file or webhook sink. Append-only. |
| `contact_log` | outbound attempts recorded by integrators (`record_contact`), used by the release rule. |
| `review` | human review queue: the release rule opens a pending `release` row when it refuses a grant with cause `contact_control_unverified`; integrators may add `stop_message` rows for ambiguous stop messages. |

Views: `current_permission` (per contact point x channel x purpose: allowed / denied + reason, latest event wins
by `seq`, suppressions outrank grants unless released by the release rule, a `*` stop denies every purpose), `chain_breaks`,
`unsealed_events`. Roles: the owner owns everything; group role `consentvault_app` has SELECT on tables and views,
INSERT on the ledger tables other than `contact_salt`, and EXECUTE on `consentvault.mark_seal_verified(seal_id)`, the one permitted update, and on `consentvault.mint_contact_salt(contact_norm)`.

## Modules (Python package `consentvault`, Python 3.11+, one database-driver dependency; the system timestamp tool for RFC 3161)

| Module | Job |
|---|---|
| `consentvault.config` | load `consentvault.toml` / env (`CONSENTVAULT_DSN`, `CONSENTVAULT_OWNER_DSN`, `CONSENTVAULT_PURPOSES`, `CONSENTVAULT_ANCHOR_SINK`, `CONSENTVAULT_TSA_URL`, ...). No defaults that name anyone. |
| `consentvault.normalize` | phone to E.164 (default region from config), email normalisation, subject key. |
| `consentvault.db` | connection helper, migrate runner (`consentvault migrate`, owner role), refuses altered or missing applied migrations and pending files numbered at or below the highest applied (sha256 ledger). |
| `consentvault.ledger` | `record_event(...)` the only writer (lower-cases and validates purposes, refuses a grant beyond its disclosure and a `captured_at` past `received_at` + 5 min); canonical serialisation; hash versions; `verify_chain()` (recompute, then check every anchor). |
| `consentvault.anchor` | `anchor()`: write the head to `chain_head` and a file or webhook sink. |
| `consentvault.disclosure` | register a disclosure body with its channels and purposes (operator only); resolve hash. |
| `consentvault.seal` | RFC 3161 request/verify via the system timestamp tool; `seal_pending()`, `verify(event_id)`, `verify_all()` (signing time vs `received_at`, delay limit, monotonic against `seq`). |
| `consentvault.stopwords` | multilingual stop-keyword classifier with confusable-character folding and near-miss list; returns `stop` / `start` / `not_stop` / `needs_review` (`start` only for a message that is just START, UNSTOP or YES). |
| `consentvault.gate` | `may_contact(contact, channel, purpose) -> Decision(allowed, reason)`; fail closed on any error. The API's permission endpoint calls it. |
| `consentvault.release` | a later consumer grant releases the consumer's **own** earlier stop for the named channels only; never staff, regulatory or imported stops; requires a held disclosure, a session ref, a grant whose contact point the integrator verified (`otp` or `inbound_keyword`; otherwise cause `contact_control_unverified` and a pending review row), and (if configured) no contact logged between the stop and the grant (vault times only); refuses, with cause `stop_after_grant`, when any stop for the contact arrived after the grant; runs under the ledger lock; every decision about a consumer grant is a `release` event. The view ranks a release at the position of the grant it decides, and a database trigger accepts a release row only for an earlier consumer grant of the same contact point, and a `released` row only when that grant was verified. `capture` through the API or the command line calls it automatically after every consumer grant. |
| `consentvault.proof` | lookup by phone/email/subject key: full timeline (grants **and** stops), current permission, seals status, chain proof. |
| `consentvault.evidence` | export a self-verifying evidence bundle (JSON with every event row for the subject in full + DER tokens + disclosure bodies + `verify.py` that needs only Python and the system timestamp tool), byte-identical to what `proof` shows. `verify.py` requires `--cafile` from outside the bundle (no trust root is bundled) and at least one `--anchor seq:row_hash` (or `--anchors FILE`) taken from the anchor sink, requires the chain path to start at seq 1 with the genesis previous hash and to reach every supplied anchor with the same hash, fails any bundled anchor not on the path, recomputes every chain-path link from its own commitments, recomputes which links carry the subject's salted commitments and fails a flag that differs or a belonging link whose event is missing (other people's links carry only commitments no guessed contact point can be tested against), fails an event with no seal, and prints each seal's signing time beside `captured_at` and `received_at`. It embeds the source of `ledger.canonical_dumps` and the seal column lists, and accepts exactly the digest `seal.digest` computes; a test pins the two together. |
| `consentvault.adapters` | `CrmAdapter`, `MessagingAdapter` protocols + `webhook` example and `null` adapter. |
| `consentvault.api` | optional stdlib HTTP server: `POST /v1/events` (HMAC-signed; hashes only, never wording; a grant claiming a verified contact point must be signed with the separate verified-grant secret), `GET /v1/permission`, `GET /v1/proof`. |
| `consentvault.cli` | `consentvault migrate | disclosure register | capture | revoke | may-contact | seal | verify-seals | verify-chain | proof | export | anchor | classify | serve`. |

## Capture edge (`edge/`)

An edge worker (TypeScript, no dependencies) and an embeddable `consent-checkbox.js`. The widget renders a
disclosure, computes its sha256 in the browser, and posts `{contact, checked, disclosure_sha256, page_url, session}`;
it never sends the wording, and the operator registers the same wording in the vault beforehand.
The worker adds receipt time, IP, user agent, a bot-check result, and the payload hash, signs the forward with
HMAC, and posts it to `POST /v1/events`. Unchecked boxes never become grants. The exact field contract between
the worker and the API is in `docs/api.md`; `tests/test_e2e_edge.py` runs the worker's code against a live API.

## Out of scope for the core

CRM-specific do-not-call flag sync, dialers, outreach cadences, reporting dashboards. These are adapters or
separate projects.
