# ConsentVault self-host kit

Postgres 17, RustFS (S3 Object Lock, COMPLIANCE default retention) as the write-once evidence store, OpenBao with the
transit engine on durable raft storage, Keycloak in production mode as the OIDC provider, and the vault service built from
the repository Dockerfile. No cloud account is needed. Read `docs/selfhost.md` first: it says what each provider choice
does and does not guarantee, and why RustFS replaced MinIO.

Run every command from the repository root. Every image is pinned by tag and digest.

## Files

| File | What it is |
|---|---|
| `docker-compose.yml` | the stack; the `suites` profile adds the throwaway test database and the test runner |
| `selfhost.example.settings` | placeholders only; `bin/make-settings.sh` fills a gitignored copy with random values |
| `bin/openbao-bootstrap.sh`, `bin/openbao-unseal.sh` | one-time initialise, and unseal after every restart |
| `openbao/` | server config (raft storage) and the vault's narrow policy |
| `keycloak/consentvault-realm.json` | the realm imported on first start |
| `Dockerfile.suites` | the test runner image (pinned, source mounted read-only) |

## Start

    deploy/selfhost/bin/make-settings.sh
    docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings up -d --build --wait db rustfs openbao keycloak
    deploy/selfhost/bin/openbao-bootstrap.sh
    docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings up -d --build --wait vault

`make-settings.sh` needs `CONSENTVAULT_TSA_URL` and `CONSENTVAULT_ANCHOR_SINK` in the environment. The `migrate` service
applies the schema as the migrator login (acting as the NOLOGIN owner); the `pin` service then pins the guards as the
superuser and removes the migrator's login; only then does the vault start as the runtime login.

OpenBao starts sealed after every restart: run `deploy/selfhost/bin/openbao-unseal.sh`.

## Check

    tests/selfhost/run_suites.sh
    tests/selfhost/restart_proof.sh

## Stop (data kept)

    docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings down

## Teardown (deletes the database, evidence and key volumes)

    docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings --profile suites down --volumes --remove-orphans
    rm -rf deploy/selfhost/secrets deploy/selfhost/selfhost.settings

Objects under COMPLIANCE retention cannot be deleted through the store; teardown removes the volume itself.
