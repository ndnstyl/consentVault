#!/bin/sh
# One-time: initialise OpenBao, unseal it, enable the transit engine, load the vault's policy and mint the vault's
# token. Writes the unseal keys and root token to $SELFHOST_SECRETS_DIR (default deploy/selfhost/secrets, mode 600).
# Move that file offline after the first run and revoke the root token; the vault needs only openbao-vault-token.
#   BAO_KEY_SHARES / BAO_KEY_THRESHOLD   default 3 / 2. A single-operator test may use 1 / 1.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
secrets=${SELFHOST_SECRETS_DIR:-$here/secrets}
shares=${BAO_KEY_SHARES:-3}
threshold=${BAO_KEY_THRESHOLD:-2}
dc="docker compose -f $here/docker-compose.yml --env-file $here/selfhost.settings"
bao() { $dc exec -T -e BAO_ADDR=http://127.0.0.1:8200 ${BAO_TOKEN:+-e BAO_TOKEN="$BAO_TOKEN"} openbao bao "$@" </dev/null; }
umask 077
mkdir -p "$secrets"
init="$secrets/openbao-init.json"
if bao operator init -status >/dev/null 2>&1; then
  [ -f "$init" ] || { echo "openbao is initialised but $init is missing; bootstrap needs the root token from it" >&2; exit 1; }
  echo "openbao is already initialised; resuming the remaining steps"
else
  bao operator init -format=json -key-shares="$shares" -key-threshold="$threshold" > "$init"
fi
"$here/bin/openbao-unseal.sh"
token=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["root_token"])' "$init")
if ! BAO_TOKEN=$token bao secrets list -format=json | grep -q '"transit/"'; then
  BAO_TOKEN=$token bao secrets enable transit
fi
$dc exec -T -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$token" openbao bao policy write consentvault - < "$here/openbao/consentvault-policy.hcl"
[ ! -s "$secrets/openbao-vault-token" ] || { echo "the vault token already exists: $secrets/openbao-vault-token"; exit 0; }
BAO_TOKEN=$token bao token create -policy=consentvault -orphan -period=720h -display-name=consentvault-vault -format=json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["auth"]["client_token"])' > "$secrets/openbao-vault-token"
echo "initialised. Keep $init offline and revoke the root token; the vault's token is $secrets/openbao-vault-token"
