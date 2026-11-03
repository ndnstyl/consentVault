# ConsentVault.AI capture edge

A dependency-free Cloudflare Worker plus an embeddable checkbox widget. The widget shows a disclosure and, at
submit, posts the box exactly as it is, the moment of the choice with its offset, and the text on screen with its
hash. The worker adds what only the server knows (receipt time, client address, Turnstile answer) and forwards the
browser's own request, signed, to the vault, which stores it whole.

Cloudflare and Turnstile are used here only as the deploy target of this directory. The vault itself
knows neither.

## What the worker does

1. Accepts every request on its hostname: any path, any method, any body, any size, any origin. It checks nothing before
   it stores.
2. Forwards the browser's own request to the vault in one signed envelope: the method, path and query, every header as
   the runtime presented it (the runtime lower-cases names and joins repeated values, and the record says so), and the
   exact bytes of the body with their SHA-256 and byte count. The worker never builds, trims, sorts or sets a field of
   the post; it sets no box value.
3. Adds what only a server knows as facts in the envelope: its own arrival time, the client address headers (each
   labelled by who sets it), `request.cf`, the site key's state, whether the origin is on the key's list, the rate count,
   and the bot-check provider's answer exactly as given. A failed check, a missing key or an unlisted origin changes
   nothing about what is stored.
4. Signs `timestamp + "." + envelope` with HMAC-SHA256 (`X-ConsentVault-Timestamp`, `X-ConsentVault-Signature`) and posts to
   `VAULT_URL/v1/events`, then answers the browser with the vault's receipt: `201` with the fingerprint of the whole body.
5. Answers a browser permission check (`OPTIONS` with `Access-Control-Request-Method`) for any origin with `204` and
   forwards it to be stored as a labelled preflight.
6. When the vault cannot be reached and the edge has a durable store (`BODY_STORE`, `CAPTURE_QUEUE`), it keeps the body
   there and answers `202 {"queued": true, ...}` with the body's fingerprint; the queue delivers in arrival order with
   the facts `queued_at_edge` and `delivered_from_queue_at`. When it can store nowhere it answers `503 store_unavailable`
   and says nothing was stored; that is the only answer that does.

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
