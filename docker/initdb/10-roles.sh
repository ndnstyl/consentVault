#!/bin/sh
# Runs once, when the database volume is first created, as the superuser. Creates the roles consentvault uses:
#   consentvault_owner     owns the database, the schema and every table, sequence and owner-rights function. NOLOGIN:
#                          nobody connects as it. Never a superuser, never BYPASSRLS.
#   consentvault_migrator  LOGIN; a member of consentvault_owner whose login default is SET ROLE consentvault_owner, so
#                          `consentvault migrate` runs every migration as the owner (a RESET ROLE inside a migration
#                          returns to the owner) and the owner owns what the migrations make.
#   consentvault_console   group role holding only the grants the operator console needs (migration 0019); owns nothing
#   consentvault_operator_login  LOGIN; a member of consentvault_console. The operator console and the operator jobs
#                          (erasure-resume) connect as it.
#   consentvault_runtime   LOGIN; a member of the group role consentvault_app (SELECT + INSERT only); every other command
#   consentvault_operator  group role with BYPASSRLS; owns the narrow cross-organisation lookups (tenancy migration)
#   consentvault_worker    group role for background jobs (per-organisation worker tokens, replay-guard sweep)
#   consentvault_records_jobs group role for the records export worker in multi-tenant mode (migration 0050); its login is a member.
#   consentvault_isolation_self_test group role for the nightly isolation self-test (migration 0059): canary tokens only.
#   consentvault_projection group role for the projection (migration 0093): the app's grants minus any read of the configuration tables; the app group is a member so a login can SET ROLE to it.
#   consentvault_restore_drill group role for the restore drill (migration 0059): appends the drill record only.
#   consentvault_integrity group role for the seal, verify and anchor jobs in multi-tenant mode (migration 0048): the
#                          per-organisation token handout and the evidence-table reads and appends those jobs make
# The owner is a member of consentvault_operator only so the migration can hand it those functions.
# 20-trigger-guard.sql runs next and refuses, for every role but a superuser, disabling or dropping a vault trigger.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v migrator_pw="$CONSENTVAULT_MIGRATOR_PASSWORD" -v operator_pw="$CONSENTVAULT_OPERATOR_PASSWORD" \
    -v app_pw="$CONSENTVAULT_APP_PASSWORD" -v dbname="$POSTGRES_DB" <<'SQL'
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
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_integrity') AS make_integrity \gset
\if :make_integrity
CREATE ROLE consentvault_integrity NOLOGIN;
\endif
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_records_jobs') AS make_records_jobs \gset
\if :make_records_jobs
CREATE ROLE consentvault_records_jobs NOLOGIN;
\endif
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_isolation_self_test') AS make_isolation \gset
\if :make_isolation
CREATE ROLE consentvault_isolation_self_test NOLOGIN;
\endif
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_restore_drill') AS make_drill \gset
\if :make_drill
CREATE ROLE consentvault_restore_drill NOLOGIN;
\endif
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_projection') AS make_projection \gset
\if :make_projection
CREATE ROLE consentvault_projection NOLOGIN;
\endif
GRANT consentvault_projection TO consentvault_app;
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_console') AS make_console \gset
\if :make_console
CREATE ROLE consentvault_console NOLOGIN;
\endif
CREATE ROLE consentvault_owner NOLOGIN;
GRANT consentvault_operator TO consentvault_owner;
CREATE ROLE consentvault_migrator LOGIN PASSWORD :'migrator_pw' IN ROLE consentvault_owner;
ALTER ROLE consentvault_migrator SET role = 'consentvault_owner';
CREATE ROLE consentvault_operator_login LOGIN PASSWORD :'operator_pw' IN ROLE consentvault_console;
CREATE ROLE consentvault_runtime LOGIN PASSWORD :'app_pw' IN ROLE consentvault_app;
ALTER DATABASE :"dbname" OWNER TO consentvault_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
