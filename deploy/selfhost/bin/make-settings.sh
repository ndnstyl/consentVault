#!/bin/sh
# Writes deploy/selfhost/selfhost.settings from the placeholder file, with a random value for every CHANGE_ME
# password or key. Refuses to overwrite an existing file. The result is gitignored; never commit it.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out="$here/selfhost.settings"
[ ! -e "$out" ] || { echo "refusing: $out already exists" >&2; exit 1; }
umask 077
while IFS= read -r line; do
  case "$line" in
    *=CHANGE_ME_TSA_URL) echo "${line%=*}=${CONSENTVAULT_TSA_URL:?set CONSENTVAULT_TSA_URL to your timestamp authority}" ;;
    *=CHANGE_ME_ANCHOR_WEBHOOK_URL) echo "${line%=*}=${CONSENTVAULT_ANCHOR_SINK:?set CONSENTVAULT_ANCHOR_SINK to your anchor receiver}" ;;
    KEYCLOAK_ADMIN=CHANGE_ME) echo "KEYCLOAK_ADMIN=admin_$(openssl rand -hex 4)" ;;
    S3_ACCESS_KEY=CHANGE_ME) echo "S3_ACCESS_KEY=cv$(openssl rand -hex 8)" ;;
    *=CHANGE_ME) echo "${line%=*}=$(openssl rand -hex 24)" ;;
    *) echo "$line" ;;
  esac
done < "$here/selfhost.example.settings" > "$out"
echo "wrote $out"
