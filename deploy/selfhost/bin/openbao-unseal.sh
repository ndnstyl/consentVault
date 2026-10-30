#!/bin/sh
# Unseals OpenBao with the threshold number of keys from $SELFHOST_SECRETS_DIR/openbao-init.json. A restart
# always comes back sealed; run this after every restart (or unseal by hand with keys held by separate people).
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
secrets=${SELFHOST_SECRETS_DIR:-$here/secrets}
dc="docker compose -f $here/docker-compose.yml --env-file $here/selfhost.settings"
python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
need=d.get("unseal_threshold",1)
print("\n".join(d["unseal_keys_b64"][:need]))' "$secrets/openbao-init.json" | while IFS= read -r key; do
  # </dev/null: exec would otherwise swallow the remaining keys from the loop's input
  $dc exec -T -e BAO_ADDR=http://127.0.0.1:8200 openbao bao operator unseal "$key" >/dev/null </dev/null
done
$dc exec -T -e BAO_ADDR=http://127.0.0.1:8200 openbao bao status
