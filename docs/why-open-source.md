# Why ConsentVault is open source

A consent record is only worth something if the people who rely on it, and the people who question it, can check it
without taking the vendor's word. The vault's code, including the code that writes and checks each record, is MIT licensed; the records stay private to whoever runs it.

## What is open

Everything in this repository is MIT licensed (see [LICENSE](../LICENSE)), with one exception: the Geist font in `portal/app/src/fonts/` is under the SIL Open Font License (`portal/app/src/fonts/GEIST-LICENSE.txt`):

- **The vault itself**: the Python package in `src/consentvault/` that captures events, chains them, seals them and answers
  "what does the record show".
- **The schema**: every migration in `migrations/`, including the database roles and the triggers that refuse updates
  and deletes on the event ledger.
- **The capture edge**: the dependency-free worker and the checkbox widget in `edge/`.
- **The self-host kit**: `docker-compose.yml` for a quick start and `deploy/selfhost/` for the fuller stack
  ([docs/selfhost.md](selfhost.md)).
- **The tests and documentation** that describe what the code is meant to do.

## What is not in this repository

The managed service adds a private key provider to the open image (`docker/cloud.Dockerfile` shows where). Other parts of the managed service, such as the support assistant's answer service, are not open source.

## How anyone can check it

1. **Read the code.** The dependency list is short, and the runtime dependencies are installed from a hash-locked file.
2. **Run it.** The [quick start](../README.md#quick-start-about-5-minutes) takes about five minutes on a laptop with Docker.
3. **Run the tests.** `pytest` starts its own PostgreSQL server; see [CONTRIBUTING.md](../CONTRIBUTING.md).
4. **Verify a record without installing ConsentVault.** `consentvault export` writes a bundle with its own short `verify.py`. A reviewer
   needs only Python and `openssl`, plus two things taken from outside the bundle: the timestamp authority's root
   certificate and the anchors from the anchor sink. The bundle cannot vouch for itself. A good run ends with
   `RESULT PASS`; a changed event, a cut chain or a missing seal makes it fail.
5. **Report what you find.** Vulnerabilities go through the private advisory process in [SECURITY.md](../SECURITY.md).

## What open source does not claim

The code is deterministic and no model is on the record path: the same input gives the same output. Open code lets you
confirm that. It does not make a record legally sufficient. ConsentVault keeps evidence of what was recorded and when; whether
that evidence is enough for a given purpose is a question for you and your own counsel. See [docs/scope.md](scope.md).
