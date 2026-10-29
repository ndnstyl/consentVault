#!/bin/sh
# Runs once, when the database volume is first created. Creates the two roles consentvault uses:
#   consentvault_owner    owns the schema; used only by `consentvault migrate`
#   consentvault_runtime  a member of the group role consentvault_app (SELECT + INSERT only); used by every other command
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v owner_pw="$CONSENTVAULT_OWNER_PASSWORD" -v app_pw="$CONSENTVAULT_APP_PASSWORD" -v dbname="$POSTGRES_DB" <<'SQL'
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_app') AS make_app \gset
\if :make_app
CREATE ROLE consentvault_app NOLOGIN;
\endif
CREATE ROLE consentvault_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE consentvault_runtime LOGIN PASSWORD :'app_pw' IN ROLE consentvault_app;
ALTER DATABASE :"dbname" OWNER TO consentvault_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
