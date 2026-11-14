#!/usr/bin/env bash
# Stop the throwaway Twenty and delete its data.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
TAG="${TAG:-v2.46.0}" PG_DATABASE_PASSWORD=x APP_SECRET=x ENCRYPTION_KEY=x \
  docker compose -f "$here/docker-compose.yml" down -v --remove-orphans
