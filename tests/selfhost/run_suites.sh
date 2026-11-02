#!/bin/sh
# Runs the integrity, isolation and suppression-sync suites inside the stack's network (the `suites` service, same
# virtual-machine clock as the database), then the live provider tests from the host, against a running self-host
# stack. From the repository root:
#   deploy/selfhost/bin/make-settings.sh
#   docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings --profile suites up -d --build --wait
#   deploy/selfhost/bin/openbao-bootstrap.sh && tests/selfhost/run_suites.sh
# Every section runs even when an earlier one fails; the exit code is non-zero if any section failed.
# Every run, passed or failed, writes the receipt tests/selfhost/receipts/selfhost-suites.json (format and fields in
# tests/selfhost/write_receipt.py). The checkpoint's traceability test reads it for every requirement whose mapped tests
# live here, outside the checkpoint's run: a mapped test the receipt does not show passed fails that test.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
py=${PYTHON:-$root/.venv/bin/python}
export SELFHOST_SECRETS_DIR=${SELFHOST_SECRETS_DIR:-$root/deploy/selfhost/secrets} # loud-failure-exempt: a folder location with a documented default, not a credential; the token file inside is checked by the tests
export PATH="$HOME/.local/bin:$PATH"
dc="docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings --profile suites"
failed=""
receipt="$root/tests/selfhost/receipts/selfhost-suites.json"
work=$(mktemp -d "${TMPDIR:-/tmp}/selfhost-suites.XXXXXX")
junit="$work/live-providers.xml"
: >"$work/sections"
section() {
  name=$1; shift
  echo "== $name"
  if "$@"; then
    echo "$name=passed" >>"$work/sections"
  else
    failed="$failed [$name]"
    echo "$name=failed" >>"$work/sections"
  fi
}
section "integrity: ledger, seal, proof, evidence" $dc run --rm --no-deps suites \
  tests/test_ledger.py tests/test_ledger_guarantees.py tests/test_ledger_tenancy.py tests/test_seal.py tests/test_proof.py tests/test_evidence.py
section "isolation" $dc run --rm --no-deps suites tests/isolation
section "suppression sync" $dc run --rm --no-deps suites tests/sync
section "live providers: OpenBao keys, S3 Object Lock evidence, Keycloak OIDC, vault service" \
  "$py" -m pytest -p no:cacheprovider -o addopts="" -q --junitxml="$junit" tests/selfhost
code=0
if [ -n "$failed" ]; then code=1; fi
set --
while IFS= read -r line; do set -- "$@" "$line"; done <"$work/sections"
if ! "$py" tests/selfhost/write_receipt.py "$junit" "$receipt" "$code" "$@"; then
  echo "the self-host receipt could not be written to $receipt" >&2
  rm -rf "$work"
  exit 1
fi
rm -rf "$work"
if [ -n "$failed" ]; then
  echo "FAILED sections:$failed" >&2
  exit 1
fi
echo "all sections passed"
