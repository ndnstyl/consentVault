#!/bin/sh
# Runs once, when the database volume is first created, as the superuser. Creates the roles consentvault uses:
#   consentvault_owner     owns the schema; used only by `consentvault migrate`; never a superuser, never BYPASSRLS
#   consentvault_runtime   a member of the group role consentvault_app (SELECT + INSERT only); used by every other command
#   consentvault_operator  group role with BYPASSRLS; owns the narrow cross-organisation lookups (tenancy migration)
#   consentvault_worker    group role for background jobs (per-organisation worker tokens, replay-guard sweep)
# The owner is a member of consentvault_operator only so the migration can hand it those functions.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v owner_pw="$CONSENTVAULT_OWNER_PASSWORD" -v app_pw="$CONSENTVAULT_APP_PASSWORD" -v dbname="$POSTGRES_DB" <<'SQL'
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_app') AS make_app \gset
\if :make_app
CREATE ROLE consentvault_app NOLOGIN;
\endif
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_operator') AS make_operator \gset
\if :make_operator
CREATE ROLE consentvault_operator NOLOGIN BYPASSRLS;
\endif
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_worker') AS make_worker \gset
\if :make_worker
CREATE ROLE consentvault_worker NOLOGIN;
\endif
CREATE ROLE consentvault_owner LOGIN PASSWORD :'owner_pw';
GRANT consentvault_operator TO consentvault_owner;
CREATE ROLE consentvault_runtime LOGIN PASSWORD :'app_pw' IN ROLE consentvault_app;
ALTER DATABASE :"dbname" OWNER TO consentvault_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
