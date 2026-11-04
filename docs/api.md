<p>
  <a href="../README.md"><picture>
    <source media="(prefers-color-scheme: dark)" srcset="../.github/assets/logo-dark.svg">
    <img alt="ConsentVault.AI" src="../.github/assets/logo-light.svg" height="36">
  </picture></a>
</p>

# HTTP API

`consentvault serve` runs a small API on the standard library. Put it behind your own TLS-terminating proxy, or behind the
capture edge (`edge/`), never directly on the public internet. A request whose `Host` header is not on the allowlist is
refused with 421 on every route except the capture routes below, which store it.

## Capture: every request is stored whole, then answered with a receipt

Every path under `/v1/events` and `/v1/capture/`, with any method, any headers, any body, any content type and any size, is
written to the raw post store before anything reads it. Nothing about the request is checked first: not its signature, its
credential, its origin, its host, its size, its shape or its content. What the vault learned about it (the signature result, a
replay, the host, the origin header, an edge's site key, bot-check answer and client address) is stored as a fact beside the
post; no fact ever decides whether a post is stored, linked, shown or exported.

Answers:

- `201` `{"stored": true, "post_id", "received_at", "body_sha256", "body_bytes", "unusual_size", "receipt": {...}}`. The same
  answer is given for a post that is garbage, unauthenticated, unticked, duplicated or a replay, and it never contains a
  judgment of the post. `body_sha256` and `body_bytes` cover every byte received. The receipt
  (`org_id`, `post_id`, `seq`, `row_hash`, `received_at`, `body_sha256`, `signature`) is signed with the platform receipt key and
  verifies offline (`consentvault.rawpost.verify_post_receipt`). `unusual_size` is true above the unusual-size level; nothing
  is cut or refused for size.
- `202` `{"stored": false, "queued": true, "queue_id", "body_sha256", "body_bytes", "edge_received_at"}` from the capture edge
  when the vault is unreachable and the request is waiting in the edge's durable store; the stored post carries the facts
  `queued_at_edge` and `delivered_from_queue_at` and the same `body_sha256`.
- `503` `{"stored": false, "error": "store_unavailable", ...}`: the one answer that says nothing was stored, given only when the
  vault could not write. It raises an alarm every time.
- `503` `{"stored": "unknown", "error": "store_unknown", "request_id", "body_sha256"}` from the edge or gateway when the vault
  did not answer, so it is not known whether it stored the request. Resending it (the same signed request, or the same
  `X-ConsentVault-Request-Id`) is safe: a request is acted on once. The vault keeps the identity of every request it has acted
  on for good (the edge's request id, else the request id header, else the signature) and derives no consent event from a request
  it has already seen or whose signed time is not fresh. Identity is never the body: the same stop sent twice is two requests.
- `204` to a browser permission check (`OPTIONS` with `Access-Control-Request-Method`) from any origin, with the origin echoed.
  It is stored as a post labelled `preflight`. Every capture answer carries the same permission headers so a browser can read it.

The body is kept exactly as received (encrypted at rest under a per-post key wrapped by the organisation key, large bodies
whole in the write-once evidence store), together with the method, the path, the query string and every header name and value
in the order presented. A single-company vault run without a key provider or an evidence store keeps the bytes as sent in the
row itself and says so (`encryption = none` on the row): configure custody to encrypt at rest.

### What is read from the stored post

After the answer, the vault reads the stored bytes with the form's field map (one per capture source, versioned, never edited)
and copies out, exactly as the sender wrote it: the consent box value, the decision time, the wording, the wording hash, the
contact point and the written-consent elements. A JSON `true` is copied as `true`, `"on"` as `"on"`; a missing field reads
`not_sent`; a field named twice gives every occurrence in byte order; a form with no map reads `unmapped`, and an unreadable
body reads `body_unreadable`. Nothing is defaulted, corrected, filled in from the arrival time, or replaced by registered
wording. The decision time sent and the arrival time are kept side by side. A missing box, missing wording, unmapped form,
unreadable body or unusual size raises an operator alarm; the post is stored in every case.

### The signed event form (`POST /v1/events`)

For a client that sends the vault's own event fields, signed: `X-ConsentVault-Timestamp` (unix seconds) and
`X-ConsentVault-Signature` (hex HMAC-SHA256 of `<timestamp>.<raw body>` with the shared `CONSENTVAULT_API_SECRET`; a leading
`sha256=` is accepted). A post that is signed, fresh, not a replay and carries the fields below is also written as a ledger
event, so the permission answer keeps working; whatever the vault cannot turn into an event is stored as the fact
`event_not_derived` with the reason, and the post is untouched.

| Field | Meaning |
|---|---|
| `contact` | phone number or email |
| `event_type` | `grant`, `revoke` or `suppress` |
| `channels`, `purposes` | lists of names; purposes are lower-cased and checked against the configured list; a stop may send `["*"]` |
| `checked` | the consent box exactly as sent; only `true` makes a grant event |
| `disclosure_sha256` | hash of wording an operator registered (`consentvault disclosure register`) |
| `captured_at`, `edge_received_at` | ISO 8601 with a time zone, kept as evidence; never used to order events |
| `payload_sha256`, `page_url`, `client_ip`, `user_agent`, `session_ref`, `bot_check`, `source`, `recorded_by`, `subject_key` | recorded as sent |
| `contact_verification`, `inbound_message` | how a verified contact point was confirmed; only a request signed with the verified-grant secret (`CONSENTVAULT_API_VERIFIED_SECRET`) may claim it |

Any other field, including `disclosure_text`, is stored in the post as sent and used for nothing else. Events are ordered by
arrival (`seq`), not by `captured_at`.

A consumer grant from the person lifts their own earlier stop, for the channels its disclosure names: a form grant sent after
the stop takes effect with no one-time code and no review step. A claim of `inbound_keyword`, or any `inbound_message`, on
a grant is stored and makes no event: a text is never consent. A revoke or suppress always records, whatever text came
with it.

## `GET /v1/permission`

`?contact=&channel=&purpose=` with `Authorization: Bearer <CONSENTVAULT_API_TOKEN>`. The answer is the contact gate's
(`consentvault may-contact`): `{"allowed", "reason", "basis_event_ids"}`. Every denial is named: no consent on record
is `no_consent_on_record`, a stop is `stopped:revoke` or `stopped:suppress`, a bad contact, channel or purpose
is `invalid_contact:...`, `invalid_channel:...` or `invalid_purpose`. Any error at all, a database that cannot
be reached or a query that fails, answers `503` with `allowed: false` and `reason: "database_unreachable:<error
class>"`; a caller that reads only `allowed` is never told yes by a failure.

## `GET /v1/proof`

`?contact=` with the bearer token. Answers the same structure as `consentvault proof`.

## A START text restores nothing: wiring it to a re-engagement form

ConsentVault never treats a text as consent. A START (or UNSTOP, YES, or any other inbound text) is stored exactly as it was
received, as its own post, and writes no consent event and lifts no stop. A person who stopped gets back on the list only by
consenting again on a form.

To give people a way back, wire it in your own messaging automation:

1. Build a re-engagement form on your own site: the person types their number, ticks the consent box (left as it is by default
   unticked) and submits. Send it through the capture widget or the signed API like any other capture, so the new post carries
   the full proof: address, device, browser, the exact consent language shown, the box as left and the time.
2. Set your messaging provider (or your own automation) to answer an inbound START with a link to that form.
3. The consent the person gives on that form is a grant from them after their stop, and it takes effect when the vault
   receives it.

Whether a prior express written consent or an established business relationship stands is for your own counsel; ConsentVault
records what was sent and never decides it.

---

[Back to the README](../README.md) · [Architecture](../ARCHITECTURE.md)
