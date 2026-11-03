<p>
  <a href="../README.md"><picture>
    <source media="(prefers-color-scheme: dark)" srcset="../.github/assets/logo-dark.svg">
    <img alt="ConsentVault.AI" src="../.github/assets/logo-light.svg" height="36">
  </picture></a>
</p>

# HTTP API

`consentvault serve` runs a small API on the standard library. No CORS headers are ever sent, and a request whose
`Host` header is not on the allowlist is refused with 421. Put it behind your own TLS-terminating proxy, or
behind the capture edge (`edge/`), never directly on the public internet.

## `POST /v1/events`: signed event intake

Headers: `X-ConsentVault-Timestamp` (unix seconds, within 300 seconds of the vault's clock) and `X-ConsentVault-Signature`
(hex HMAC-SHA256 of `<timestamp>.<raw body>` with the shared `CONSENTVAULT_API_SECRET`; a leading `sha256=` is
accepted). Replays are refused within the window by a single running process.

Body: one JSON object. Unknown fields are stored as sent and labelled.

| Field | Required | Meaning |
|---|---|---|
| `contact` | yes | phone number or email |
| `event_type` | yes | `grant`, `revoke`, `suppress` or `release` |
| `channels` | yes | list of `voice`, `artificial_voice`, `sms`, `email` |
| `purposes` | yes | list of strings, lower-cased by the vault; a purpose not on the configured purpose list is stored as sent and labelled. A stop (`revoke` or `suppress`) may send `["*"]` to stop every purpose on its channels |
| `checked` | grants | the box value as sent. Every submission is recorded exactly as sent, ticked or not. An unticked box is recorded as the person's 'no', never as a consent. |
| `disclosure_sha256` | grants | sha256 of the wording the person saw. The capture surface sends the wording on the screen at submit time, and the vault stores it as sent, with its hash. A wording the vault has not seen before is stored as a new version on first sight, never refused. Where the wording names fewer channels than the post claims, both are kept as sent and shown side by side. |
| `edge_received_at` | no | ISO 8601 with a timezone: when the capture edge says it received the submission. Stored as evidence only; the vault sets `received_at` from its own clock and refuses a `received_at` field |
| `payload_sha256` | no | 64 lowercase hex: sha256 of the body the person's browser sent to the edge. Recorded as is; when absent the vault hashes the body it received |
| `captured_at` | no | ISO 8601 with a timezone. Evidence of when the capture surface says it happened; it never orders events. A value later than the vault's own receipt time is stored as sent and labelled |
| `method`, `origin` | no | default `checkbox` and `consumer` |
| `contact_verification` | no | `none` (default), `otp` or `inbound_keyword`: how you verified that the person controls the contact point. Only a consumer grant may carry `otp` or `inbound_keyword`, and only a request signed with the verified-grant secret (`CONSENTVAULT_API_VERIFIED_SECRET`, or `verified_secret` under `[api]`) may claim it: a request signed with the ordinary secret (the capture edge's) is refused with 403 `verification_key_required`, and with no verified-grant secret configured every such claim is refused. The vault records that you verified it; sending and checking the one-time code is your job and the vault cannot see it |
| `inbound_message` | with `inbound_keyword` | the message the contact point sent. It is stored as sent; a message that is not a START word is stored and labelled, never refused |
| `page_url`, `client_ip`, `user_agent`, `session_ref`, `bot_check`, `source`, `recorded_by`, `subject_key` | no | recorded as sent |

The capture surface sends the wording on the screen at submit time, and the vault stores it as sent, with its hash. A wording the vault has not seen before is stored as a new version on first sight, never refused. Where the wording names fewer channels than the post claims, both are kept as sent and shown side by side.

Every field of every post is stored as sent, including fields the vault does not recognise, a claimed time that is later than the vault's clock, a purpose not on your list, a failed bot check and an inbound message that is not a START word. Each is labelled for what it is; none is refused.

Events are ordered by arrival (`seq`), not by `captured_at`: the permission answer is decided by the order the
vault received them.

Answers: 201 `{"ok": true, "event_id", "seq", "row_hash"}`, plus `release` (the proof-of-control row kept beside a later
consent) after a consumer grant; if that row cannot be written the grant stays recorded and the answer carries
`release_error`; 400 for a malformed body; 401 for every authentication failure (unsigned, bad or stale signature, non-finite timestamp, a request already
accepted), with one body that does not say which; the reason is in the server log; 413 body too large; 422 a named vault refusal (`error` carries its class name).

A stop and a later consent are both kept, in the order they arrived, with every fact that shows who sent each: the contact point, the words, the times, and any proof the integrator gives that the person controls the contact point. The record shows the person's own later consent beside their stop, and what verifies it; it never ranks, releases or refuses either one, and no staff member, operator or customer can lift a stop.

`release` events are written by the vault, not through this endpoint's fields: a release needs
`release_of_event_id`, `release_outcome` and `release_cause`, which this endpoint does not accept. They are
written for every consumer grant received here and by `consentvault capture`, and they rank and refuse nothing.

## `GET /v1/permission`

`?contact=&channel=&purpose=` with `Authorization: Bearer <CONSENTVAULT_API_TOKEN>`. The answer is the contact gate's
(`consentvault may-contact`): `{"allowed", "reason", "basis_event_ids"}`. Every answer names its basis: nothing on file
is `no_consent_on_record`, a stop is `stopped:revoke` or `stopped:suppress`, a bad contact, channel or purpose
is `invalid_contact:...`, `invalid_channel:...` or `invalid_purpose`. If the vault cannot answer, it says so with the reason. The answer is the record as it stands, not a yes or a no. Any error at all, a database that cannot
be reached or a query that fails, answers `503` with `reason: "database_unreachable:<error
class>"`, which means the vault did not answer; it is never read as 'no consent'.

## `GET /v1/proof`

`?contact=` with the bearer token. Answers the same structure as `consentvault proof`.

---

[Back to the README](../README.md) · [Architecture](../ARCHITECTURE.md)
