# Suppression sync (for the API, admin and deployment lanes)

## 1. The hook (wired at the integration pass)

`ledger.record_tenant_event` calls `enqueue_event_pushes` itself, inside the transaction that inserts the event and
right after the INSERT, so every tenant event (capture, release, signal) queues its pushes or rolls back with them.
The result is on the returned event as `event.pushes`. A signal passes `source_system_id=` to the writer, so the system
that sent it is never pushed its own signal back. No caller invokes the hook by hand any more.

It raises `OutboxTransactionError` outside a transaction, `OutboxError` when a push cannot be queued (the event then
rolls back). An event that does not move a person's state (a second stop, a grant behind a stop) queues nothing.

## 2. Routes (API lane registers one line each)

`from consentvault.sync.routes import SyncRoutes, Request` (see the module docstring): `POST /v1/signals`,
`POST /v1/deliveries:query`, `GET /v1/systems/{id}/deliveries`, `POST /v1/deliveries:redrive`, `GET /v1/redrives/{id}`.

## 3. Worker (deployment lane)

`SyncWorker(crypto, custody, transport, alarms).run_once(worker_role_conn, connect=db.connect_factory(cfg))` or `.run_loop(...)`; with `db_auth = "iam"` every connection logs in with a fresh RDS IAM token. Runs as
`consentvault_worker`; one organisation per transaction through `dispatch_orgs('sync')`. `transport` is
`connectors.webhook.EgressTransport(egress_url, EGRESS_SECRET)`. `custody` is the providers `KeyProvider`
(`wrap`/`unwrap`). `alarms` is any object with `raise_alarm(Alarm)`; the default logs at ERROR.

## 4. Seams with the admin lane

- `connected_system.credentials_ct` = `custody.wrap(str(org_id), 32 raw bytes)` (HMAC secret or Ed25519 seed). The worker
  opens it with `custody.unwrap`.
- A system's signals arrive on a `capture` credential. Binding it: `sync.systems.bind_signal_credential(conn, system_id,
  credential_id)` (admin or developer token); the admin lane calls it from `POST /v1/systems` and `PATCH
  /v1/systems/{id}` when the body carries `signal_credential_id`. Unbound credentials get `role_not_allowed` on
  `/v1/signals`.
- Signature header: `X-ConsentVault-Signature: hmac-sha256=<hex>` or `ed25519=<hex>` over the exact body bytes; also
  `X-ConsentVault-Delivery` (outbox id) and `Idempotency-Key`.
