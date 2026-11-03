# ConsentVault.AI capture edge

A dependency-free Cloudflare Worker plus an embeddable checkbox widget. The widget shows a disclosure,
sends the exact text on screen at submit time with its sha256, and posts to the worker. The worker adds what only the
server knows (receipt time, client IP, user agent, optional Turnstile result, payload hash), signs the
body and forwards it to the vault's `POST /v1/events`.

Cloudflare and Turnstile are used here only as the deploy target of this directory. The vault itself
knows neither.

## What the worker does

1. Accepts `POST /consent` only from origins listed in `ALLOWED_ORIGINS` (comma separated, exact match).
2. Keeps every field of a submission as sent, in whatever shape it arrives. Every submission is recorded exactly as sent, ticked or not. An unticked box is recorded as the person's 'no', never as a consent.
3. Forwards the wording the visitor had on screen at submit time, as sent, with its sha256, and never substitutes a
   server-side copy. The vault stores it as sent, with its hash. A wording the vault has not seen before is stored as a new version on first sight, never refused. Where the wording names fewer channels than the post claims, both are kept as sent and shown side by side.
4. Adds `edge_received_at` (its own receipt time, kept as evidence only; the vault stamps `received_at` itself), `client_ip` (from `CF-Connecting-IP`), `user_agent`, `bot_check`
   (`none`, `turnstile:pass` or the failed result, each stored as sent) and `payload_sha256` (sha256 of the received body).
5. Signs `timestamp + "." + body` with HMAC-SHA256 (`X-ConsentVault-Timestamp`, `X-ConsentVault-Signature`) and posts to
   `VAULT_URL/v1/events`. A vault outage is returned as 502 with `recorded: false`.

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

The widget posts the text shown with its sha256. You may register the same text in the vault ahead of time
(`consentvault disclosure register --body-file wording.txt ...`; the command trims leading and trailing whitespace, as the
widget does before hashing); a text the vault has not seen is stored on first sight, never refused. Use
`data-template="id"` to read the disclosure from a `<template>` instead. `submit(contact)` rejects on
every failure and never reports success unless the worker answered `recorded: true`.

## Test

```
npm test        # node --test; Node 24 runs the TypeScript directly
```

## Portal Worker (sign-in and the dashboard's door)

`src/portal.ts` is the dashboard's one public door: `/auth/*` is sign-in (`src/auth.ts`), `/v1/*` is the gateway with
session cookies (`src/gateway.ts`, `src/session.ts`), and every other path is the dashboard's static export. The browser
holds one opaque `__Host-` cookie (HttpOnly, Secure, SameSite=Lax); the identity token, refresh token, chosen organization
and the vault's short tenant token stay in the Worker's key-value store. The flow is written down in
the cloud session contract. Configuration: `wrangler.portal.toml.example`.
`npm test` runs the unit tests, including auth, the cookie gateway and the portal router. The dashboard against the real
API (stub sign-in issuer, no WorkOS) is described in `portal/app/README.md`.

## Logging

The edge Workers log nothing. An evidence download link is a single-use credential in the query string, so any proxy
or load balancer placed in front of the vault must log the path only, with the query string removed.
