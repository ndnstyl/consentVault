# ConsentVault.AI capture edge

A dependency-free Cloudflare Worker plus an embeddable checkbox widget. The widget shows a disclosure,
hashes the exact text on screen at submit time, and posts to the worker. The worker adds what only the
server knows (receipt time, client IP, user agent, optional Turnstile result, payload hash), signs the
body and forwards it to the vault's `POST /v1/events`.

Cloudflare and Turnstile are used here only as the deploy target of this directory. The vault itself
knows neither.

## What the worker does

1. Accepts `POST /consent` only from origins listed in `ALLOWED_ORIGINS` (comma separated, exact match).
2. Refuses anything that is not a valid shape. An unchecked box is refused with 422 and never forwarded.
3. Accepts only the wording's hash, `disclosure_sha256`: the sha256 of the text the visitor had on screen at
   submit time. The worker never accepts wording itself (a request carrying `disclosure_text` is refused with
   400) and never substitutes a server-side copy. The operator registers the wording in the vault beforehand
   with `consentvault disclosure register`; the vault refuses a grant whose hash it does not hold.
4. Adds `edge_received_at` (its own receipt time, kept as evidence only; the vault stamps `received_at` itself), `client_ip` (from `CF-Connecting-IP`), `user_agent`, `bot_check`
   (`none` or `turnstile:pass`; a failed check is refused) and `payload_sha256` (sha256 of the received body).
5. Signs `timestamp + "." + body` with HMAC-SHA256 (`X-ConsentVault-Timestamp`, `X-ConsentVault-Signature`) and posts to
   `VAULT_URL/v1/events`. A vault refusal or outage is returned as 502 with `recorded: false`.

## Deploy

1. Copy `wrangler.toml.example` to `wrangler.toml` and edit `ALLOWED_ORIGINS` and `VAULT_URL`.
2. Set the secret `SIGNING_SECRET` (the same value as the vault's `CONSENTVAULT_API_SECRET`) using the Cloudflare CLI's
   secret command. Optionally set `TURNSTILE_SECRET`.
3. Deploy the worker with the Cloudflare CLI's deploy command.

## Widget

```html
<script src="consent-checkbox.js"></script>
<consentvault-consent
  data-endpoint="https://edge.example.com/consent"
  data-channels="sms,email"
  data-purposes="marketing"
  data-disclosure="I agree to be contacted about my account."></consentvault-consent>
<script>
  document.querySelector("consentvault-consent").submit("+15555550100");
</script>
```

The widget posts only the sha256 of the text shown; register the same text in the vault first
(`consentvault disclosure register --body-file wording.txt ...`; the command trims leading and trailing whitespace, as the
widget does before hashing) or every submission is refused. Use
`data-template="id"` to read the disclosure from a `<template>` instead. `submit(contact)` rejects on
every failure and never reports success unless the worker answered `recorded: true`.

## Test

```
npm test        # node --test; Node 24 runs the TypeScript directly
```
