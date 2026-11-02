#!/usr/bin/env bash
# Start the throwaway Twenty for the contract suite and wait until it answers. Random settings live in a private temporary
# file that is removed on exit; nothing is printed. Exit 1 names what failed. Stop with ./down.sh.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export TAG="${TAG:-v2.46.0}" PORT="${PORT:-3100}"
envf="$(mktemp)"; chmod 600 "$envf"; trap 'rm -f "$envf"' EXIT
{ echo "PG_DATABASE_PASSWORD=$(openssl rand -hex 24)"; echo "APP_SECRET=$(openssl rand -hex 32)";
  echo "ENCRYPTION_KEY=$(openssl rand -hex 32)"; echo "TAG=$TAG"; echo "PORT=$PORT"; } > "$envf"
docker compose --env-file "$envf" -f "$here/docker-compose.yml" up -d --wait --wait-timeout 420 \
  || { echo "the test Twenty did not become healthy within 420 s" >&2; exit 1; }
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null || { echo "the test Twenty is not answering on port $PORT" >&2; exit 1; }
echo "test Twenty $TAG up at http://localhost:$PORT"
