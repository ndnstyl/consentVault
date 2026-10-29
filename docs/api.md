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

Body: one JSON object. Unknown fields are refused with 400 `unknown_fields`.

| Field | Required | Meaning |
|---|---|---|
| `contact` | yes | phone number or email |
| `event_type` | yes | `grant`, `revoke`, `suppress` or `release` |
| `channels` | yes | list of `voice`, `artificial_voice`, `sms`, `email` |
| `purposes` | yes | list of strings, lower-cased by the vault and checked against the configured purpose list (422 `UnknownPurposeError`). A stop (`revoke` or `suppress`) may send `["*"]` to stop every purpose on its channels; `*` is refused on anything else |
| `checked` | grants | must be exactly `true`; anything else is refused with 422 `UncheckedConsentError` and nothing is recorded |
| `disclosure_sha256` | grants | sha256 of the wording the person saw. The vault accepts only a hash an operator already registered (`consentvault disclosure register`); an unknown hash is 422 `UnknownDisclosureError` and nothing is recorded |
| `edge_received_at` | no | ISO 8601 with a timezone: when the capture edge says it received the submission. Stored as evidence only; the vault sets `received_at` from its own clock and refuses a `received_at` field |
| `payload_sha256` | no | 64 lowercase hex: sha256 of the body the person's browser sent to the edge. Recorded as is; when absent the vault hashes the body it received |
| `captured_at` | no | ISO 8601 with a timezone. Evidence of when the capture surface says it happened; it never orders events. A value later than the vault's own receipt time plus five minutes is refused with 422 `ClockSkewError` |
| `method`, `origin` | no | default `checkbox` and `consumer` |
| `contact_verification` | no | `none` (default), `otp` or `inbound_keyword`: how you verified that the person controls the contact point. Only a consumer grant may carry `otp` or `inbound_keyword`, and only a request signed with the verified-grant secret (`CONSENTVAULT_API_VERIFIED_SECRET`, or `verified_secret` under `[api]`) may claim it: a request signed with the ordinary secret (the capture edge's) is refused with 403 `verification_key_required`, and with no verified-grant secret configured every such claim is refused. The vault records that you verified it; sending and checking the one-time code is your job and the vault cannot see it |
| `inbound_message` | with `inbound_keyword` | the message the contact point sent. It must read as a START-type message (`START`, `UNSTOP`, `YES`, with filler words only); anything else is refused with 422 `InvalidEventError` |
| `page_url`, `client_ip`, `user_agent`, `session_ref`, `bot_check`, `source`, `recorded_by`, `subject_key` | no | recorded as sent |

Wording is never accepted on the wire: a body that carries `disclosure_text` is refused with 400
`disclosure_text_refused`. A grant may name only channels and purposes that its registered wording names; a
grant beyond them is refused with 422 `GrantScopeError`.

Events are ordered by arrival (`seq`), not by `captured_at`: the permission answer is decided by the order the
vault received them.

Answers: 201 `{"ok": true, "event_id", "seq", "row_hash"}`, plus `release` (`released_channels` and `refusals`) after a
consumer grant, because the release rule runs automatically once the grant is recorded; if that decision cannot be
written the grant stays recorded and the answer carries `release_error`; 400 for a malformed body; 401 unsigned, bad or stale
signature; 409 replay; 413 body too large; 422 a named vault refusal (`error` carries its class name).

A consumer grant lifts the contact's own earlier stop only when its `contact_verification` is `otp` or `inbound_keyword`. A
plain web-form grant (`none`) is answered with `release.refusals` of `contact_control_unverified`, the stop stays in
force, and a pending `release` row appears in `review`.

`release` events are written by the vault's release rule, not through this endpoint's fields: a release needs
`release_of_event_id`, `release_outcome` and `release_cause`, which this endpoint does not accept. The rule is
applied to every consumer grant received here and by `consentvault capture`.

## `GET /v1/permission`

`?contact=&channel=&purpose=` with `Authorization: Bearer <CONSENTVAULT_API_TOKEN>`. The answer is the contact gate's
(`consentvault may-contact`): `{"allowed", "reason", "basis_event_ids"}`. Every denial is named: no consent on record
is `no_consent_on_record`, a stop is `stopped:revoke` or `stopped:suppress`, a bad contact, channel or purpose
is `invalid_contact:...`, `invalid_channel:...` or `invalid_purpose`. Any error at all, a database that cannot
be reached or a query that fails, answers `503` with `allowed: false` and `reason: "database_unreachable:<error
class>"`; a caller that reads only `allowed` is never told yes by a failure.

## `GET /v1/proof`

`?contact=` with the bearer token. Answers the same structure as `consentvault proof`.

---

[Back to the README](../README.md) · [Architecture](../ARCHITECTURE.md)
