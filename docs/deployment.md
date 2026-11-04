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

ConsentVault.AI splits the database into roles, and the split is part of the protection:

| Role | What it is | Used by |
|---|---|---|
| owner (`consentvault_owner`) | **NOLOGIN.** Owns the database, the `consentvault` schema and every table, sequence and owner-rights function. Never a superuser, never `BYPASSRLS`. Nobody connects as it | nothing connects as it |
| migrator (`consentvault_migrator`) | a login role that is a member of the owner, with the owner as its default role (`ALTER ROLE consentvault_migrator SET role = 'consentvault_owner'`), so every migration runs as the owner | `consentvault migrate` only (`CONSENTVAULT_OWNER_DSN`) |
| operator console (`consentvault_operator_login`, a member of `consentvault_console`) | holds only the grants the operator console and the operator jobs need (migration `0019`), owns nothing, bound by row-level security; it cannot alter a table, replace a function or switch a trigger off | the operator console and `consentvault erasure-resume` (`CONSENTVAULT_OPERATOR_DSN`) |
| runtime | a login role that is a **member of the group role `consentvault_app`**; it holds `SELECT` and `INSERT` on the ledger tables and the views and `EXECUTE` on the tenant functions, and nothing else | every other command and the API (`CONSENTVAULT_DSN`) |
| worker (`consentvault_worker` group) | background jobs with per-organisation worker tokens, and the replay-guard sweep | the sync worker and `consentvault replay-sweep` (`CONSENTVAULT_DSN` set to the worker login) |

The runtime and console roles own nothing, have no `TRUNCATE`, cannot alter the schema and cannot disable triggers,
because all of that needs ownership. A superuser makes the roles once (the reference stack does it in
`docker/initdb/10-roles.sh`):

```
CREATE ROLE consentvault_app NOLOGIN;
CREATE ROLE consentvault_worker NOLOGIN;
CREATE ROLE consentvault_operator NOLOGIN BYPASSRLS;   -- owns the narrow cross-organisation lookups; nobody logs in as it
CREATE ROLE consentvault_console NOLOGIN;
CREATE ROLE consentvault_integrity NOLOGIN;            -- the seal, verify and anchor jobs in multi-tenant mode (0048)
CREATE ROLE consentvault_records_jobs NOLOGIN;         -- the records export worker in multi-tenant mode (0050); sign-in by AWS token only
CREATE ROLE consentvault_isolation_self_test NOLOGIN;  -- the nightly isolation self-test (0059): canary tokens and reads only
CREATE ROLE consentvault_restore_drill NOLOGIN;        -- the restore drill (0059): appends its drill record only
CREATE ROLE consentvault_owner NOLOGIN IN ROLE consentvault_operator;
CREATE ROLE consentvault_migrator LOGIN PASSWORD '...' IN ROLE consentvault_owner;
ALTER ROLE consentvault_migrator SET role = 'consentvault_owner';
CREATE ROLE consentvault_operator_login LOGIN PASSWORD '...' IN ROLE consentvault_console;
CREATE ROLE consentvault_runtime LOGIN PASSWORD '...' IN ROLE consentvault_app;
ALTER DATABASE consentvault OWNER TO consentvault_owner;
```

### Who can switch a trigger off

The append-only ledgers, the legal holds and the request states are triggers. Normally a table's owner can disable or
drop its triggers, so the trigger guard takes that away: `docker/initdb/20-trigger-guard.sql` installs two event
triggers (and a third, below) that refuse `ALTER TABLE ... DISABLE TRIGGER` (any form, and `ENABLE REPLICA`, which stops a trigger in a normal
session) and any drop of a trigger on a `consentvault` table, **for every role that is not a superuser**: the migrator
acting as the owner, the operator console and the runtime roles alike. Only a superuser can disable a vault trigger,
which is also the only role that may run a down migration. Run the file once per database **as a superuser** (Docker
does it at first start; on a managed database, as the master user, whose `rds_superuser` membership is the only other
break-glass). Its functions live in the schema `consentvault_guard`, owned by that superuser, so the schema owner can
neither replace nor drop them. The multi-tenant API refuses to start (`require_multi_tenant()`) while the guard is
missing or disabled, while the owner can log in, while anything in the schema is owned by another role, or while
`consentvault_console` or any of its members is a superuser, the owner or a member of it, or a member of a `BYPASSRLS`
role. A member is a role that can act as the console: one that holds an `INHERIT` or `SET` membership in it, directly
or through other such memberships (migration `0026`). An admin-only membership, which lets a role grant the console but
not act as it, does not count; PostgreSQL 16 and later give exactly that to the role that creates a role, so the master
user on a managed database, which creates the console roles, is not a member. Nothing is exempt by role name: a master
that holds an `INHERIT` or `SET` membership in the console or in a console login is a violation like any other role.
On PostgreSQL 15, which records no such options, every membership counts. It also refuses when its own login is any of those.

A vault table's partitions and inheritance children are guarded in any schema. The guard records each child as
`CREATE TABLE ... PARTITION OF` made it in the vault schema, and a fifth event trigger refuses, for the same roles, a
child made or moved outside the vault schema, a child renamed, detached or un-inherited, and a table attached to a vault
table by `ALTER TABLE ... INHERIT` or `ATTACH PARTITION`; the disable and guard-change checks follow a child to its
vault table. The security manifest names every child outside the vault schema, so the API refuses to start on one.

A third event trigger refuses, for the same roles, the ways around a guard that do not disable it: replacing a guard
function's body or attributes (`CREATE OR REPLACE FUNCTION`, `ALTER FUNCTION`), replacing or renaming a guarded trigger
(`CREATE OR REPLACE TRIGGER`, `ALTER TRIGGER`), renaming the `consentvault` schema, and moving or renaming a guarded table
(`ALTER TABLE ... SET SCHEMA` / `RENAME`). Which objects are guards is pinned: `consentvault_guard.pin` holds a SHA-256 of
each guard function (every trigger function of a vault table, every vault function those call, and the start check) and
of each guarded trigger. Pinning is a superuser's only (`consentvault_guard.pin_guards()`, insert-only, not executable
by `PUBLIC`): the migrator cannot pin a trigger it has just added. After every migration run the superuser (the master
user on a managed database) runs `SELECT consentvault_guard.pin_guards()`; a reviewed break-glass change is re-pinned
with `SELECT consentvault_guard.repin()`. The API refuses to start while any pinned guard differs from its pin, is gone,
or a guard is not pinned. A database whose guard was installed before pinning: run the file again as a superuser, then
`consentvault migrate`, then pin.

Row-level security is a guard too: a restrictive policy, a dropped tenant policy or row security switched off on a table
a guard reads (the holds table, the key tables, the erasure tables) would blind the guard without touching it. A fourth
event trigger (`consentvault_refuse_policy_change`, with the drop guard) refuses, for the same roles, `CREATE`, `ALTER`
and `DROP POLICY` and `ALTER TABLE ... ENABLE / DISABLE / FORCE / NO FORCE ROW LEVEL SECURITY` on every table a guard
trigger is on and every vault table a guard function names; their flags and a SHA-256 of their policies are pinned in
`consentvault_guard.table_pin` and reported like the other pins.
A later migration that changes a pinned guard, a policy or the row security of such a table runs as the superuser
(the master user), then the superuser re-pins with `SELECT consentvault_guard.repin()`.

### The security manifest

`src/consentvault/data/security_manifest.sha256` ships with each build: a SHA-256 of every object of the guarded security
surface as a clean apply of the shipped migrations leaves it in multi mode (every function in `consentvault` and
`consentvault_guard` with its body, `SECURITY DEFINER` or `INVOKER` and `search_path`; every trigger; row security and
every policy on every table; table, column and function grants; the schemas; the guard's event triggers), with the
schema owner's and the superuser's names normalised, and partitions made month by month after the migration
collapsed into one entry per parent. It also covers every column (type, default), constraint, index and rule. `scripts/build_security_manifest.py` builds it; the checkpoint fails
while the committed file is stale. At start the multi-tenant API reads the same surface from the live database's system
catalogs and refuses to serve on any drift, naming every object added, changed or removed, and on a PostgreSQL major
version other than the manifest's. A pin records what a superuser blessed; the manifest records what shipped, so even a
pinned change that did not ship refuses.

### The migration login exists only during a migration run

The migrator acts with the owner's rights, so it is the one login that could change the schema between runs. In a
multi-tenant deployment it exists only while a migration runs: the operator gives it `LOGIN` (or creates it) for the
run, runs `consentvault migrate`, runs `SELECT consentvault_guard.pin_guards()` as the superuser, and then removes it
(`ALTER ROLE consentvault_migrator NOLOGIN`, or `DROP ROLE`). The ops bootstrap for the managed service already removes
it after the run. The multi-tenant API refuses to start while any login role that is a member of the schema owner (other
than a superuser or the master user) can still log in, and names it.

Do not run the API, the operator console or the daily jobs as the owner, the migrator or a superuser. The migration runs
from a separate step with the migrator's connection string; the long-running processes never see it.
`docker-compose.yml` follows this: the `db` service creates the roles and the guard on first start, the `migrate` service
holds the migrator password, and the `vault` service holds only the runtime password.

### Upgrading a database made before migration 0019

Before 0019 the owner was a login role and the operator console connected as it. As a superuser (or the master user),
before `consentvault migrate`:

```
CREATE ROLE consentvault_console NOLOGIN;
CREATE ROLE consentvault_migrator LOGIN PASSWORD '...' IN ROLE consentvault_owner;
ALTER ROLE consentvault_migrator SET role = 'consentvault_owner';
CREATE ROLE consentvault_operator_login LOGIN PASSWORD '...' IN ROLE consentvault_console;
ALTER ROLE consentvault_owner NOLOGIN;
\i docker/initdb/20-trigger-guard.sql
```

Then point `CONSENTVAULT_OWNER_DSN` at the migrator, the operator console and `erasure-resume` at the operator login
(`CONSENTVAULT_OPERATOR_DSN`), and migrate. Migration 0019 refuses, by name, while `consentvault_console` is missing.

## Scheduled jobs

Run each as `python -m consentvault.jobs <name>`; a job that fails exits 2 and the schedule shows a failed task.

| job | login | when |
|---|---|---|
| `alarm-relay` | worker (`CONSENTVAULT_DSN`; in the cloud its own task role whose database user is a member of `consentvault_worker`, allowed `sns:Publish` to the alerts topic only). It reads and marks alarms through two functions and holds no table right | every 5 minutes. Publishes each operator alarm not yet relayed to the alerts channel (`CONSENTVAULT_ALERTS_TOPIC_ARN`, an SNS topic, in the cloud; `CONSENTVAULT_ALERTS_LOG`, a file, in the self-host; a log file is refused in the cloud), retrying with backoff, and marks it relayed only after the publish succeeded. The message carries the alarm kind, organisation id, counts and times and nothing else. Exit 2 names an alarm it could not publish; exit 3 says an alarm waited past 15 minutes, so the relay itself was down |
| `replay-sweep` | worker (`CONSENTVAULT_DSN`) | hourly. Deletes replay-guard rows that expired more than an hour ago (the hour is margin for clock skew between processes, so a late or early sweep never lets a signed request be accepted twice). On the runtime login it exits 2. |
| `erasure-resume` | operator (`CONSENTVAULT_OPERATOR_DSN`) plus the key provider setting | as before |
| `erasure-commit-sweep` | its own task role whose database user is a member of `consentvault_console` (the operator console's grants: read the requests and stop events, insert the commit record and the alarm). **No key provider, no KMS role, no key custody**: it never opens a contact key. Settings: the database login settings, `CONSENTVAULT_TOKEN_KEY_ID`/`_FILE`, and the ledger store (`CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET` and `_REGION` in the cloud, read and write on that bucket only; `CONSENTVAULT_LIFECYCLE_LEDGER_DIR` in the self-host). A local folder is refused in the cloud. Fails by name on the worker or runtime login | hourly. Writes the ledger commits that are due, raises an operator alarm for each organisation holding an intent over an hour old without a commit, and exits 3 while any is overdue |

## Settings

Environment wins over `consentvault.toml`.

| Setting | Env | Meaning |
|---|---|---|
| `dsn` | `CONSENTVAULT_DSN` | connection string for the runtime role |
| `owner_dsn` | `CONSENTVAULT_OWNER_DSN` | connection string for the migrator login (its default role is the NOLOGIN owner); `migrate` only |
| `operator_dsn` | `CONSENTVAULT_OPERATOR_DSN` | connection string for the operator console login; the operator console and `erasure-resume` |
| `purposes` | `CONSENTVAULT_PURPOSES` | the purposes consent may name (list, or comma separated); anything else is refused. `*` is reserved for stop-all |
| `anchor_sink` | `CONSENTVAULT_ANCHOR_SINK` | where `consentvault anchor` writes the chain head: a file path or an http(s) webhook URL |
| `seal_max_delay_seconds` | `CONSENTVAULT_SEAL_MAX_DELAY_SECONDS` | longest a seal's signing time may come after the event was received (default 86400) |
| `unsealed_grace_seconds` | `CONSENTVAULT_UNSEALED_GRACE_SECONDS` | longest an event may stay unsealed before `verify-seals` fails it (default 3600) |
| `raw_post_inline_limit_bytes` | `CONSENTVAULT_RAW_POST_INLINE_LIMIT_BYTES` | a captured body above this many bytes is kept whole in the evidence object store instead of the database row (default 65536); never cuts or refuses a post |
| `raw_post_unusual_size_bytes` | `CONSENTVAULT_RAW_POST_UNUSUAL_SIZE_BYTES` | a captured body above this many bytes raises the unusual-size alarm (default 1048576); never cuts or refuses a post |
| `backup_retention_days` | `CONSENTVAULT_BACKUP_RETENTION_DAYS` | age of the oldest database backup; a key version a rotation retired is kept this long so any backup still restores (default 35) |
| `default_region` | `CONSENTVAULT_DEFAULT_REGION` | region for phone numbers written without a country code |
| `tsa_url` | `CONSENTVAULT_TSA_URL` | timestamp authority (required; no default) |
| `migrations_dir` | `CONSENTVAULT_MIGRATIONS` | override the migrations directory |
| `[api] secret` | `CONSENTVAULT_API_SECRET` | HMAC secret that signs writes to the API |
| `[api] token` | `CONSENTVAULT_API_TOKEN` | bearer token for read endpoints |
| `[api] verified_secret` | `CONSENTVAULT_API_VERIFIED_SECRET` | optional second signing secret; only a request signed with it may claim a verified contact point |
| `[api] allowed_hosts` | `CONSENTVAULT_API_HOSTS` | accepted `Host` header values |
| none | `CONSENTVAULT_RELEASE_REQUIRE_NO_CONTACT_SINCE_STOP` | when `1`, a later grant releases an earlier stop only if no contact was logged between them |
| none | `CONSENTVAULT_OPENSSL` | path to the `openssl` binary used for timestamp requests and verification |
| none | `CONSENTVAULT_TSA_CAFILE` | CA bundle used to verify timestamp tokens (default: the system bundle) |

A missing required setting is a named error, not a default.

## Docker

`docker-compose.yml` runs PostgreSQL and the vault API. Set the four database passwords (admin, migrator, operator,
app) and the secrets in
your shell or an env file that is not committed (see the README quickstart for the full list), then:

```
docker compose up -d --build db
docker compose run --rm migrate      # as the migrator login, acting as the NOLOGIN owner
docker compose up -d vault           # as the runtime role
```

The API binds to the loopback interface of the host. Put your own TLS-terminating reverse proxy in front of
it if it must be reachable from elsewhere, and add the proxy's public host name to the allowed hosts.

## Without Docker

```
pip install .
CONSENTVAULT_OWNER_DSN=postgresql://consentvault_migrator@db/consentvault consentvault migrate
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

A grant may claim that the person's control of the contact point was verified (`contact_verification` of `otp`). The claim
is recorded and used by a policy rule that requires a verified contact; it is not needed to lift the person's own earlier stop.
Set `CONSENTVAULT_API_VERIFIED_SECRET` (or `verified_secret` under `[api]`) to a second secret and give it only to the
server-side integrator that checks one-time codes. Never give it to the capture edge. Without it, the API refuses every
such claim; `consentvault capture --verification otp` records one directly for the command-line integrator.

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
