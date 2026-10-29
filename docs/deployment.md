<p>
  <a href="../README.md"><picture>
    <source media="(prefers-color-scheme: dark)" srcset="../.github/assets/logo-dark.svg">
    <img alt="ConsentVault.AI" src="../.github/assets/logo-light.svg" height="36">
  </picture></a>
</p>

# Deployment

## Requirements

- PostgreSQL 15 or newer (a dedicated database; consentvault uses its own `consentvault` schema).
- Python 3.11 or newer, and the `openssl` command line tool (used for timestamp requests and verification).
- A timestamp authority URL you trust (RFC 3161). Only a 32-byte digest is sent.

## Database roles

ConsentVault.AI uses two kinds of database role, and the split is part of the protection:

| Role | What it is | Used by |
|---|---|---|
| owner | any role without superuser rights that runs `consentvault migrate`; it owns the `consentvault` schema and everything in it | `consentvault migrate` only (`CONSENTVAULT_OWNER_DSN`) |
| runtime | a login role that is a **member of the group role `consentvault_app`**; it holds `SELECT` and `INSERT` on the ledger tables and the views, `EXECUTE` on one function that stamps `seal.verified_at`, and nothing else | every other command and the API (`CONSENTVAULT_DSN`) |

The migration creates the group role `consentvault_app` (no login) if it does not exist and grants it exactly that.
The runtime role owns nothing, has no `UPDATE`, `DELETE` or `TRUNCATE`, cannot alter the schema and cannot
disable triggers, because all of that needs ownership. Create it yourself:

```
CREATE ROLE consentvault_runtime LOGIN PASSWORD '...' IN ROLE consentvault_app;
```

Do not run the API or the daily jobs as the owner or as a superuser: a superuser can switch the append-only
triggers off, which is the thing the split exists to prevent. The migration is run from a separate step with
the owner's connection string; the long-running processes never see it. `docker-compose.yml` follows this: the
`db` service creates the roles on first start (`docker/initdb/10-roles.sh`), the `migrate` service holds the
owner password, and the `vault` service holds only the runtime password.

## Settings

Environment wins over `consentvault.toml`.

| Setting | Env | Meaning |
|---|---|---|
| `dsn` | `CONSENTVAULT_DSN` | connection string for the runtime role |
| `owner_dsn` | `CONSENTVAULT_OWNER_DSN` | connection string for the owner role; `migrate` only |
| `purposes` | `CONSENTVAULT_PURPOSES` | the purposes consent may name (list, or comma separated); anything else is refused. `*` is reserved for stop-all |
| `anchor_sink` | `CONSENTVAULT_ANCHOR_SINK` | where `consentvault anchor` writes the chain head: a file path or an http(s) webhook URL |
| `seal_max_delay_seconds` | `CONSENTVAULT_SEAL_MAX_DELAY_SECONDS` | longest a seal's signing time may come after the event was received (default 86400) |
| `unsealed_grace_seconds` | `CONSENTVAULT_UNSEALED_GRACE_SECONDS` | longest an event may stay unsealed before `verify-seals` fails it (default 3600) |
| `default_region` | `CONSENTVAULT_DEFAULT_REGION` | region for phone numbers written without a country code |
| `tsa_url` | `CONSENTVAULT_TSA_URL` | timestamp authority (required; no default) |
| `migrations_dir` | `CONSENTVAULT_MIGRATIONS` | override the migrations directory |
| `[api] secret` | `CONSENTVAULT_API_SECRET` | HMAC secret that signs writes to the API |
| `[api] token` | `CONSENTVAULT_API_TOKEN` | bearer token for read endpoints |
| `[api] verified_secret` | `CONSENTVAULT_API_VERIFIED_SECRET` | optional second signing secret; only a request signed with it may claim a verified contact point |
| `[api] allowed_hosts` | `CONSENTVAULT_API_HOSTS` | accepted `Host` header values |
| — | `CONSENTVAULT_RELEASE_REQUIRE_NO_CONTACT_SINCE_STOP` | when `1`, a later grant releases an earlier stop only if no contact was logged between them |
| — | `CONSENTVAULT_OPENSSL` | path to the `openssl` binary used for timestamp requests and verification |
| — | `CONSENTVAULT_TSA_CAFILE` | CA bundle used to verify timestamp tokens (default: the system bundle) |

A missing required setting is a named error, not a default.

## Docker

`docker-compose.yml` runs PostgreSQL and the vault API. Set the three database passwords and the secrets in
your shell or an env file that is not committed (see the README quickstart for the full list), then:

```
docker compose up -d --build db
docker compose run --rm migrate      # as the owner role
docker compose up -d vault           # as the runtime role
```

The API binds to the loopback interface of the host. Put your own TLS-terminating reverse proxy in front of
it if it must be reachable from elsewhere, and add the proxy's public host name to the allowed hosts.

## Without Docker

```
pip install .
CONSENTVAULT_OWNER_DSN=postgresql://owner@db/consentvault consentvault migrate
consentvault serve --host 127.0.0.1 --port 8080     # CONSENTVAULT_DSN is the runtime role
```

Run `serve` under a process supervisor (systemd or similar) so it restarts and its logs are kept.

## Daily jobs

Schedule these once a day and alert on a non-zero exit:

```
consentvault seal            # timestamp new events
consentvault verify-seals    # re-verify every stored seal
consentvault anchor          # write the chain head to chain_head and the external sink
consentvault verify-chain    # recompute the hash chain and check every anchor
```

Exit codes: 0 fine, 2 an error was raised, 3 the chain or a seal is broken.

`consentvault anchor` is what makes a deleted tail visible: a chain with its last rows cut off is still a valid
chain, until an anchor says those rows existed. Run it often (hourly is cheap), and point `anchor_sink` at
something the database host cannot rewrite: a webhook on another host, or a file on append-only storage.
`verify-chain` checks every row in `chain_head`, and every record of a file sink, against the ledger and
fails when an anchored row is missing or changed. A webhook receiver is your own record; compare it by hand
or with your own script. When the sink is a webhook, `verify-chain` prints `sink_not_checked`.

### Verified-grant secret

A grant that claims the person's control of the contact point was verified (`contact_verification` of `otp` or
`inbound_keyword`) is the only kind that can lift a stop. Set `CONSENTVAULT_API_VERIFIED_SECRET` (or
`verified_secret` under `[api]`) to a second secret and give it only to the server-side integrator that sends or
checks the one-time codes or reads inbound START messages. Never give it to the capture edge. Without it, the API
refuses every such claim; `consentvault capture --verification otp|inbound_keyword` records one directly for the
command-line integrator.

`verify-seals` fails a seal whose signing time precedes the event's `received_at`, or comes more than
`seal_max_delay_seconds` after it, or runs backwards against `seq` (a later event stamped earlier than an
earlier one), and fails any event still unsealed `unsealed_grace_seconds` after it was received. Run
`consentvault seal` shortly after events arrive so the delay stays small.

## The capture edge

The field contract between the worker and the vault API is in [api.md](api.md).

`edge/` holds an optional worker and widget that sit between a public web page and the vault, so the vault
API itself never faces the public internet. See `edge/README.md`. Its signing secret must equal the vault's
`CONSENTVAULT_API_SECRET`.

## Backups and upgrades

- Back up the database like any system of record, and keep at least one copy off the host. Seal tokens live in
  the database, so a restore keeps them.
- Apply upgrades with `consentvault migrate` as the owner role. It refuses to run if an already-applied migration
  file has changed or is missing, or if a pending file is numbered at or below the highest one applied.
- Export an evidence bundle (`consentvault export`) before any major change, as an independent copy. A reviewer
  verifies it with `verify.py --cafile <the authority's root certificate> --anchors <the sink's file>` (or one
  `--anchor <seq>:<row_hash>` per head), both obtained themselves: the bundle carries no trust root, and the
  anchors must come from the anchor sink, read independently of whoever exports the bundle. A file sink on
  append-only storage can be handed to the reviewer as is; for a webhook sink, the receiver's operator supplies its
  record. A reviewer with no anchor cannot run the verifier at all.

---

[Back to the README](../README.md) · [Architecture](../ARCHITECTURE.md)
