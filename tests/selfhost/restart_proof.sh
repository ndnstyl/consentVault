#!/bin/sh
# Durability proof for the self-host stack's OpenBao and evidence store: a key made before a restart still unwraps
# after it, OpenBao comes back sealed (not dev mode), and a locked evidence object is still locked and readable.
# Needs the stack up and bootstrapped. From the repository root: tests/selfhost/restart_proof.sh
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
export PATH="$HOME/.local/bin:$PATH"
export SELFHOST_SECRETS_DIR=${SELFHOST_SECRETS_DIR:-$root/deploy/selfhost/secrets} # loud-failure-exempt: a folder location with a documented default, not a credential
py=${PYTHON:-$root/.venv/bin/python}
dc="docker compose -f deploy/selfhost/docker-compose.yml --env-file deploy/selfhost/selfhost.settings"
state=$(mktemp -d)
trap 'rm -rf "$state"' EXIT
PYTHONPATH="$root/src:$root" "$py" tests/selfhost/restart_helper.py wrap "$state"
$dc restart openbao rustfs
$dc up -d --wait openbao rustfs
# `bao status` exits 2 while sealed; any other non-zero exit is a real failure
rc=0
status=$($dc exec -T -e BAO_ADDR=http://127.0.0.1:8200 openbao bao status -format=json) || rc=$?
[ "$rc" -eq 2 ] || { echo "FAIL: openbao should come back sealed (exit 2) after a restart, exit was $rc" >&2; exit 1; }
echo "$status" | grep -q '"sealed": true' || { echo "FAIL: openbao status does not say sealed" >&2; exit 1; }
echo "openbao came back sealed, as a durable instance must"
deploy/selfhost/bin/openbao-unseal.sh >/dev/null
PYTHONPATH="$root/src:$root" "$py" tests/selfhost/restart_helper.py check "$state"
"$py" -m pytest -p no:cacheprovider -q tests/selfhost/test_write_once_store.py
echo "restart proof passed"
