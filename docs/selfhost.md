# Self-hosting ConsentVault.AI

This page says what you run, how to prove it works, and what each choice of provider does and does not guarantee.
Nothing here needs a cloud account. The files live in `deploy/selfhost/`.

## What the stack is

| Part | Choice | Pinned | Why |
|---|---|---|---|
| Ledger | PostgreSQL 17 | `postgres:17.11` + digest | the vault's own database; the NOLOGIN owner, migrator, operator console, runtime, operator and worker roles and the trigger guard from `docker/initdb` |
| Write-once evidence | RustFS, S3 Object Lock | `rustfs/rustfs:1.0.4` + digest | replaces MinIO (see below) |
| Key custody | OpenBao transit, raft storage, sealed at rest | `openbao:2.4.1` + digest | durable, not dev mode |
| Sign-in | Keycloak in production mode, own Postgres database, imported realm | `keycloak:26.3.3` + digest | any OIDC issuer works; this is the open one |
| Service | the repository `Dockerfile` | built locally | runs as the runtime role, never as the owner or the migrator |

Every image is pinned by exact tag and digest.

### Why the write-once store changed

The MinIO tag the kit first used (`quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z`) no longer resolves: MinIO stopped
publishing container images. Checked 2026-10-29 with `docker manifest inspect`. Three open S3 stores were then probed
with the vault's own `S3ObjectLockEvidenceStore` and with raw signed requests:

| Store | Overwrite of a taken key | Delete or shorten a locked version | Verdict |
|---|---|---|---|
| SeaweedFS 3.99 | accepted (`If-None-Match: *` ignored, a new version is written) | refused | rejected: breaks "evidence is never overwritten" |
| Versity S3 Gateway 1.10.0 | not reached | not reached | rejected: demands a `Content-MD5` header on locked writes, which the evidence store does not send |
| **RustFS 1.0.4** | **refused, 412** | **refused, 403, even with the governance-bypass header** | **chosen** |

RustFS is young (1.0 shipped September 2026) and has no independent compliance assessment. `tests/selfhost/test_write_once_store.py`
is the standing proof: re-run it on every image upgrade, and do not upgrade on a red run.

## Bring it up

From the repository root:

```
deploy/selfhost/bin/make-settings.sh          # random passwords into deploy/selfhost/selfhost.settings (gitignored)
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings up -d --build --wait db rustfs openbao keycloak
deploy/selfhost/bin/openbao-bootstrap.sh      # once: initialise, unseal, transit engine, narrow policy, the vault's token
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings up -d --build --wait vault
```

`make-settings.sh` needs `CONSENTVAULT_TSA_URL` and `CONSENTVAULT_ANCHOR_SINK` in the environment: they are yours to choose.
The bootstrap writes the unseal keys and root token to `deploy/selfhost/secrets/` (mode 600, gitignored). Move that file
off the machine, revoke the root token, and keep only the vault's own token (`openbao-vault-token`). The default is three
key shares with a threshold of two (`BAO_KEY_SHARES`, `BAO_KEY_THRESHOLD`). OpenBao comes back **sealed** after every restart;
run `deploy/selfhost/bin/openbao-unseal.sh`, or unseal by hand with keys held by different people.

The database service creates the roles and the trigger guard once, on first start (as the bootstrap superuser). The
`migrate` service applies the schema as the migrator login, whose default role is the NOLOGIN owner,
then a superuser step pins the guards (`SELECT consentvault_guard.pin_guards()`), checks there are no pin violations and
removes the migrator's login; only then does the vault start as the runtime role. The order is fixed by the compose
dependencies: roles and trigger guard (database init), migrator given LOGIN, migrate, pin and remove the migrator login,
vault. The vault refuses to serve while a migrator can log in, and the security manifest it checks at start is built for
PostgreSQL 17, which is why the image moved from 16. To migrate again, run `up` again: the migrator is given LOGIN for the
run and loses it after the pin. Keycloak and the vault must reach each other at the addresses in the settings
file; `KEYCLOAK_PUBLIC_URL` is the token issuer and must not change after people sign in. Plain HTTP is for loopback;
put TLS in front before any other machine reaches Keycloak, OpenBao or the vault.

## Prove it

```
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings --profile suites up -d --build --wait
tests/selfhost/run_suites.sh        # integrity, isolation, suppression sync, then the live provider tests
tests/selfhost/restart_proof.sh     # restart OpenBao and the store: sealed on return, old key still unwraps, evidence still locked
```

Result of the run on 2026-10-30 against this stack: integrity 159 passed (1 skipped), isolation 259 passed, suppression
sync 169 passed, live providers 25 passed, restart proof passed. The run writes `tests/selfhost/receipts/selfhost-suites.json`,
which the checkpoint's traceability stage reads for every requirement whose proving tests live here. The receipt records
a digest of the product files and of the security manifest it ran against, its exit code and every section; traceability
accepts it only for a clean run (exit 0, every section passed) of the current code, so any change to the product makes it
stale until the suites are run again. The 2026-10-30 run predates that format and was moved to
`tests/selfhost/receipts/superseded/`; the receipt is pending until the suites run against the current build.

What each part of that run covers:

* The three product suites run unchanged, inside the stack's network, against the stack's PostgreSQL 17 image. They run
  inside the VM because several tests compare a time the database stamps with a time the test reads; run from the host,
  a Colima VM clock that is 60 to 110 milliseconds ahead made 34 sync tests and 2 seal tests fail. A test host and a
  database host whose clocks differ by a tenth of a second will see the same.
* Those suites build their own roles and use in-process stand-ins for the key, evidence and identity providers. The
  live proof of the open providers is `tests/selfhost`: OpenBao transit (create, wrap, unwrap, destruction window,
  cancel, process, key gone from the server), S3 Object Lock on RustFS (below), and a real Keycloak token through
  `OIDCIdentityProvider` (valid, wrong audience, wrong issuer, tampered, password-only refused where MFA is required).
* Object Lock proof, all against the live store: a second write to a taken key is refused (412); deleting the locked
  version is refused (403) with and without the governance-bypass header; shortening or switching the retention is
  refused (403); the bucket cannot be deleted while it holds locked objects; a plain delete leaves the locked version
  readable by its version id; the bucket default is COMPLIANCE.

Not exercised: a real RFC 3161 timestamp authority (the suites use their local test authority; the stack's settings carry
your URL), a real anchor receiver, and a Keycloak login that carries a second factor. A multi-factor reading from a real
Keycloak token is **unverified** until a realm with OTP or a passkey has issued one.

## Guarantees by provider choice

The vault stores what happened; the providers decide how hard it is to change afterwards. State only the row you run.

### Evidence store

| Choice | What is guaranteed | What is not |
|---|---|---|
| S3 Object Lock, COMPLIANCE (RustFS here; AWS S3 or another lock-capable store) | The store refuses overwrite, early delete and shortened retention through its API, for every credential including its administrator. The evidence store verifies SHA-256 on every read and `verify_retention` reports `COMPLIANCE`. | On a self-run store, someone with root on the machine can still destroy the disk or the volume, or move the store host's clock. The lock is as strong as the store's code and the host's custody. RustFS has no independent assessment. |
| Local directory (`LocalAppendOnlyEvidenceStore`) | Refuses overwrite; a missing or altered file is **detected** by digest. | Nothing prevents deletion or replacement. `enforces_retention` is `False`. Never describe this as undeletable. |

### Key custody

| Choice | What is guaranteed | What is not |
|---|---|---|
| OpenBao transit, raft on a volume, Shamir seal (this stack) | Keys never leave the server (not exportable, no plaintext backup). Wrapping needs an unsealed server and the vault's token. Destruction waits at least 30 days, can be cancelled, then deletes the transit key on the server; the vault reports the key gone. Data keys wrapped by it are unreadable after. | **Destruction is not provable.** A raft snapshot, a volume backup or a disk copy taken before deletion still holds the key, and the vault reports `provable_destruction` as `False` unless you declare an HSM-backed or managed seal. The unseal keys decide who can start it. Keep the schedule file (`destruction.json`) in your backup set. |
| OpenBao with an HSM-backed or managed seal, no key backups, declared with `provable_destruction=True` | The same, and a deleted key cannot be recovered from storage alone. | The claim is yours to make and to evidence. |
| Local key file (`LocalFileKeyProvider`) | Keys are sealed by a passphrase on disk and overwritten on destruction. | **No provable destruction at all.** Any copy of the file made earlier undoes erasure. Do not promise irreversible erasure on this choice. |

### Identity

| Choice | What is guaranteed | What is not |
|---|---|---|
| Keycloak (this stack), or any OIDC issuer | Signature, issuer, audience, expiry and algorithm are checked on every token; `none` and HMAC are never accepted; a password-only login reads as not multi-factor and is refused where multi-factor is required. | Multi-factor is read from the token's `amr` claim; it is only as good as the realm's second-factor policy, and a Keycloak token carrying a second factor was not tested here. Plain-HTTP issuers are accepted only on loopback. |

### Ledger and anchors

| Choice | What is guaranteed | What is not |
|---|---|---|
| PostgreSQL with the shipped roles | The runtime role cannot update, delete, truncate or alter the ledger; the owner cannot log in and is not a superuser; the operator console owns nothing. The trigger guard refuses disabling or dropping a vault trigger for every role but a superuser, including the migrator acting as the owner. Hash chain and seals make any later change **detectable**. | A database superuser (the bootstrap admin) can still switch the append-only and hold triggers off. The chain then shows a ledger change; it does not stop it. Keep the superuser password out of every running service. |
| Outside timestamp (RFC 3161) and anchor sink you choose | Proof the chain head existed at a time and at a place the database owner does not control. | Without a reachable authority and a sink you do not run, the proof reduces to the operator's own word. An air-gapped site has no outside timestamp. |

## Teardown

```
docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings --profile suites down --volumes --remove-orphans
rm -rf deploy/selfhost/secrets deploy/selfhost/selfhost.settings
```

Objects under COMPLIANCE retention cannot be deleted through the store; teardown removes the volume itself, which is
also the one thing the lock does not defend against. Never run `--volumes` on a stack that holds real evidence.

## Host notes

* The stack needs Docker with the Compose plugin. On macOS the repository was proved on Colima
  (`colima start --cpu 4 --memory 8`), with the Compose plugin placed in `~/.docker/cli-plugins`.
* A bind mount must live under your home folder on Colima; `/tmp` is not shared with the VM.
* Ports are loopback only; change them in the settings file when one is taken.
