<p>
  <a href="../README.md"><picture>
    <source media="(prefers-color-scheme: dark)" srcset="../.github/assets/logo-dark.svg">
    <img alt="ConsentVault.AI" src="../.github/assets/logo-light.svg" height="36">
  </picture></a>
</p>

# Evidence model

This page says what ConsentVault.AI records, why each piece is there, and what it does and does not prove.
It is not legal advice. Which evidence a court or regulator will accept is a question for your own
lawyer in your own jurisdiction.

## What is recorded for every event

| Field | Why it is there |
|---|---|
| `contact_norm`, `contact_kind` | which phone number or email the event is about, in one canonical form |
| `contact_salt`, `contact_commit` | `contact_salt` is the contact's own random 32-byte salt (64 hex characters). It is minted once, on the contact's first event, by the owner-defined function `mint_contact_salt`, which draws the 32 bytes inside the database under the ledger lock and writes them to the append-only `contact_salt` table (the runtime role cannot insert into that table, so it can neither choose nor pre-plant a salt); every row for that contact copies it, the row hash covers it, and a database trigger refuses a row whose salt is not the contact's. `contact_commit` is sha256 of `contact_salt` followed by `contact_norm`. Every chain link carries the commitment, never the salt, so no one can test a guessed phone number or email against another person's link, while every link of one contact still shares one commitment |
| `event_type` | `grant`, `revoke`, `suppress` or `release` |
| `contact_verification` | `none`, `otp` or `inbound_keyword`: how the integrator established that the person who ticked the box controls the contact point. Part of the row hash. Only a consumer grant may carry anything but `none`. The vault records what the integrator says it verified; it cannot see the code check itself |
| `channels`, `purposes` | exactly what was agreed to or withdrawn |
| `disclosure_sha256` | the hash of the wording the person saw; the wording itself is stored once, by hash |
| `method`, `origin` | how it was given (checkbox, verbal, keyword...) and by whom (consumer, staff, import...) |
| `captured_at`, `received_at`, `edge_received_at` | when the capture surface says it happened (evidence only, never used to order events, and refused if later than `received_at` plus five minutes); when the vault received it, read from the vault server's own clock (a database trigger refuses any other value); and when the capture edge says it received it (evidence only) |
| `page_url`, `session_ref` | where the person was, and a per-visit reference |
| `client_ip`, `user_agent` | what the server observed about the connection |
| `bot_check` | the result of any bot check the capture surface ran |
| `payload_sha256` | the hash of the exact payload received |
| `release_of_event_id`, `release_outcome`, `release_cause` | release events only: which grant was decided, the outcome, and the reason for a refusal |
| `prev_hash`, `row_hash` | the chain: `row_hash` is the sha256 of `prev_hash` followed by the canonical JSON of the row's `contact_commit`, the sha256 of its `contact_salt` followed by its `subject_key` (`subject_commit`; salted too, because a default subject key is derived from the contact point), and the sha256 of the canonical JSON of every evidence column (`content_sha256`, ledger hash version 1) |

## Five layers of protection

1. **A role that can only append.** The runtime role holds SELECT and INSERT (on the salt table, SELECT only; salts come from the minting function). It owns nothing, so it cannot
   UPDATE, DELETE, TRUNCATE, alter the schema or switch a trigger off. Only the owner role can, and it is used
   for migrations only. A database trigger refuses UPDATE and DELETE for everyone else as a second line.
2. **Hash chain.** `row_hash = sha256(prev_hash || canonical({contact_commit, content_sha256, subject_commit}))`,
   where `content_sha256` covers every evidence column. Changing, removing or inserting a row in the middle
   breaks every hash after it. `consentvault verify-chain` recomputes it, and also checks that each row's
   `contact_commit` is the sha256 of its `contact_salt` followed by its `contact_norm`. When the anchor sink is a webhook, `verify-chain` prints
   `sink_not_checked`: a webhook cannot be read back, so only the anchors in the database were compared.
3. **Anchors.** A chain whose last rows were deleted still verifies, so `consentvault anchor` writes the head
   (`seq`, `row_hash`, time) to the `chain_head` table and to a sink outside the database. `verify-chain`
   fails when any row up to an anchor is missing or different. An anchor taken from before the deletion is what
   proves the deletion happened; keep the sink somewhere the database host cannot rewrite.
4. **RFC 3161 timestamps.** The digest of each event is sent to an RFC 3161 timestamp authority; the signed
   token is stored in the `seal` table. This is what stops the owner of the database from rewriting the whole
   chain: the authority's signature fixes the digest at a time. Only 32 bytes leave your host. Verification
   also reads the signing time from the token and fails a seal that precedes the event's `received_at`, that
   comes later than the configured limit (default 24 hours), or that runs backwards against `seq`. It also fails
   any event that has stayed unsealed longer than a configured delay (default one hour) after the vault received it.
5. **Exported bundle.** `consentvault export` writes the events, disclosure wording, seal tokens and a standalone
   `verify.py` that needs only Python and openssl. A reviewer can check it without trusting you or consentvault,
   given two things the bundle cannot supply for itself: the timestamp authority's root certificate and the anchors.

## Seals

Each seal stores its column list. Covered columns are never altered; new evidence gets a new hash version, and old
rows verify under their own version. A change to a covered column fails verification.
The seal digest is the sha256 of the canonical JSON (sorted keys, no spaces, ASCII only) of exactly the columns
the seal's hash version names. The exported `verify.py` recomputes that one digest with a copy of the same
canonicalization function and accepts no other form, so a seal that digests anything else reads as failed.

## What the exported bundle proves, and how a reviewer runs it

`python3 verify.py --cafile <root.pem> --anchor <seq>:<row_hash>` (repeat `--anchor`, or give `--anchors <file>`).
The verifier needs two things from outside the bundle, and fails without either:

- **The timestamp authority's root certificate** (`--cafile`). The bundle carries no trust root and `verify.py` refuses a
  `--cafile` that sits inside its own directory, so a bundle cannot vouch for itself.
- **At least one anchor** (`--anchor seq:row_hash`, repeatable, or `--anchors FILE` in the format the anchor sink writes:
  one JSON record per line with `seq` and `row_hash`). Get it from the anchor sink yourself: read the sink file from
  its append-only storage, or ask the webhook receiver's operator for its record, never from whoever exported the
  bundle and never from the bundle. `verify.py` refuses an `--anchors` file inside its own directory.

The verifier:

- requires the chain path to start at seq 1 with the all-zero genesis previous hash and run without a gap to the stated
  head, so nothing can be cut from the front or the middle (links of other people carry commitments only);
- recomputes every event's row hash and the chain links, checks the chain ends at the stated head, and recomputes
  every chain-path link from the commitments the link itself carries (`prev_hash`, `contact_commit`,
  `subject_commit`, `content_sha256`), so a link's commitments cannot be changed without breaking the chain;
- checks each event's `contact_commit` is the sha256 of its `contact_salt` followed by its `contact_norm`, and that its link's `subject_commit` is the same for its `subject_key`, and that its link carries the same
  commitments and content hash as the event;
- fails any event without a seal: an event with no RFC 3161 timestamp is not proven, and a missing seal is a
  failure, not a skip;
- runs `openssl ts -verify` on every seal, reads the authority's signing time out of the token, prints it beside
  that event's `captured_at` and `received_at`, and fails a signing time before `received_at` or later than
  `--max-delay` (default 24 hours);
- recomputes which links belong to this subject: a link belongs when its `contact_commit` equals the sha256 of a
  bundled `contact_salt` followed by a `contact_norm` of the subject (or the query), or its `subject_commit`
  equals the sha256 of a bundled salt followed by a `subject_key`. It fails when any link's `subject` flag differs
  from that result, and fails when a link marked as this subject's has no event with full content in the bundle.
  The bundle carries salts only for the subject's own contacts, so other people's links appear as commitments
  nobody can test a guessed contact point against. Hiding a stop therefore leaves a belonging link with no
  content, or a flag that disagrees with its commitments, and the check fails;
- fails when the path does not reach every anchor you supplied with the same hash, which is what a cut tail looks
  like, and fails any anchor the bundle itself carries that is not on the path with a matching hash. The bundle's
  own anchors prove nothing alone: whoever builds the bundle can leave them out.

What the verifier proves: every link of the chain path recomputes, so a link's commitments cannot be altered; any
link that carries the subject's salted commitments is flagged as theirs and has its full event in the bundle, so a
stop cannot be dropped from the bundle (or its link unflagged) without a failed check; and every event has a valid
RFC 3161 timestamp. With the anchors you supply, it also proves the path runs from the first event of the ledger to
at least the latest anchor you hold. What it cannot prove: events after your newest anchor (anchor often; anything
later than the newest anchor you hold can still be cut), and that the bundle holds every contact point of the
subject: a contact the vault never linked to the subject's contacts or subject key has a different salt and
cannot be found from the bundle. A bundle for a contact with no record proves nothing about absence: the verifier
still requires the anchors but skips the chain checks, because there is no salt to test commitments against.

## The wording is part of the record

An operator registers each wording in the vault (`consentvault disclosure register`), together with the channels and
purposes it covers. The capture surface hashes the text that is on the visitor's screen at submit time and
sends only that hash; wording itself is never accepted from a client. The vault refuses a grant whose
disclosure hash it does not hold, and a grant that names a channel or purpose its wording does not cover.
This avoids the classic gap where the record points to whatever the "current" copy of the wording is today,
which may differ from what the person saw, and it stops a grant being stretched to a channel the person was
never asked about. A registered wording and its scope never change.

## Stops are evidence too

Revocations and suppressions are events in the same chain. The permission answer is decided by the order the
vault received events (`seq`), never by the time a caller says something happened: a grant that claims to be
newer cannot get ahead of a stop that arrived after it. A stop outranks a grant. A person's own later grant can
release their own earlier stop for the channels it names, but only when the grant's `contact_verification` is `otp` or
`inbound_keyword`; a stop recorded by staff, a regulator or an import
is never released that way, and a release never lifts a stop that arrived after the grant it decides: the
permission view ranks a release at the position of its grant, and the release rule refuses such a decision with
the cause `stop_after_grant`. A release row is accepted only for an earlier consumer grant of the same contact
point. The release rule runs automatically after every consumer grant recorded through the API or `consentvault capture`.
A web form alone shows that a box was ticked, not who owns the number or address, so a grant with
`contact_verification` of `none` never lifts a stop: the release rule writes a `refused` release with the cause
`contact_control_unverified` and opens a pending `release` row in `review` for a person to look at, and the release
insert trigger refuses a `released` row for such a grant even from a hand-written insert. Running the one-time code
or reading the inbound START message is the integrator's job; the vault takes the integrator's word, recorded in a
hashed column, so a false claim is on the integrator's record. The capture edge always sends `none`, and the HTTP
API accepts another value only on a request signed with the separate verified-grant secret.
Every release decision about a consumer grant is itself an event, written with explicit columns
(`release_of_event_id`, `release_outcome` of `released` or `refused`, and `release_cause` for a refusal) that
are part of the row hash.

Purposes are lower-cased and must be on the configured list, so a stop written `Marketing` stops `marketing`.
A stop for the purpose `*` stops every purpose on its channels, including purposes never granted; only a
release naming a specific purpose lifts it, for that purpose.

## What this does not prove

- Who physically ticked the box. IP address and user agent are corroboration, not identity. `otp` and
  `inbound_keyword` record that the integrator checked control of the contact point; the vault cannot see or
  repeat that check, and an integrator holding the verified-grant secret (or the database insert right) can claim it falsely.
- A grant that never arrives at the vault, or a stop that was never sent to it.
- That the capture surface told the truth. If it is compromised, the vault records what it was told.
- That your wording satisfies any particular law. That is for your own legal review.
- Anything about systems outside the vault. A CRM flag can still be wrong; adapters push changes but cannot
  enforce them.

---

[Back to the README](../README.md) · [Architecture](../ARCHITECTURE.md)
