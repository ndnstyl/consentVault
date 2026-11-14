"""Connections and the migration runner."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Callable

import psycopg
from psycopg import sql as _sql
from psycopg.rows import dict_row

from .safelog import describe
from .errors import ConfigError, DatabaseError, MigrationDriftError, MigrationError

_MIGRATION_NAME = re.compile(r"^\d{4}_[a-z0-9_]+\.sql$")


def connect(dsn: str) -> psycopg.Connection:
    """Open an autocommit connection returning dict rows. Writers open their own transactions.

    An ``rds-iam://`` DSN (config ``db_auth = "iam"``) logs in with an RDS IAM token over verify-full TLS
    (providers/rds_iam.py); any other DSN is handed to libpq as is.
    """
    if not dsn:
        raise ConfigError("empty database DSN")
    if dsn.startswith("rds-iam://"):
        from .providers import rds_iam

        return rds_iam.connect_dsn(dsn)
    try:
        return psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
    except psycopg.Error as exc:
        raise DatabaseError(f"cannot connect to the database: {describe(exc)}") from exc


def connect_factory(cfg) -> "Callable[[], psycopg.Connection]":
    """A no-argument connect for the configured service login (what the sync worker and route apps take).

    IAM mode (``db_auth = "iam"``) yields fresh-token connections; a plain DSN is handed to libpq as is.
    """
    dsn = cfg.require_dsn()
    return lambda: connect(dsn)


def default_migrations_dir() -> Path:
    """The repo's migrations/ directory, else the copy packaged inside the wheel."""
    here = Path(__file__).resolve().parent
    for candidate in (here.parents[1] / "migrations", here / "_migrations"):
        if candidate.is_dir():
            return candidate
    raise MigrationError("migrations directory not found; set CONSENTVAULT_MIGRATIONS", code='migrations_dir_unset')


def list_migrations(directory: Path) -> list[Path]:
    if not directory.is_dir():
        raise MigrationError(f"migrations directory does not exist: {directory}", code='migrations_dir_missing')
    files = sorted(p for p in directory.iterdir() if p.is_file() and p.suffix == ".sql")
    bad = [p.name for p in files if not _MIGRATION_NAME.match(p.name)]
    if bad:
        raise MigrationError(f"migration files must be named NNNN_name.sql: {bad}", code='migration_file_misnamed')
    return files


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def migrate(conn: psycopg.Connection, directory: str | Path | None = None) -> list[str]:
    """Apply pending migrations in order. Returns the names applied.

    The connection is the migrator's login. Every migration runs under SET ROLE to the database's owner (the NOLOGIN
    schema owner), so the owner owns everything the migrations make. The migrator's login default is that role
    (``ALTER ROLE <migrator> SET role = <owner>``), so a migration that runs RESET ROLE stays the owner; a migration
    that leaves the session as any other role is rolled back by name. A login that is not a member of the owner is
    refused by name. Refuses if an applied file changed on disk, an applied file is missing,
    or a pending file is numbered at or below the highest applied one (history is never inserted in the middle).
    """
    folder = Path(directory) if directory else default_migrations_dir()
    files = list_migrations(folder)
    try:
        who = conn.execute("SELECT current_user AS me, pg_get_userbyid(d.datdba) AS owner FROM pg_database d"
                           " WHERE d.datname = current_database()").fetchone()
    except psycopg.Error as exc:
        raise DatabaseError(f"cannot read the database owner: {describe(exc)}") from exc
    if who["me"] == who["owner"]:
        return _migrate_as_owner(conn, folder, files, who["owner"])
    try:
        conn.execute(_sql.SQL("SET ROLE {}").format(_sql.Identifier(who["owner"])))
    except psycopg.Error as exc:
        raise MigrationError(f"the migration login {who['me']} cannot SET ROLE to the database owner {who['owner']}: "
                             f"make it a member of {who['owner']} ({describe(exc)})", code='migrator_cannot_set_role') from exc
    try:
        return _migrate_as_owner(conn, folder, files, who["owner"])
    finally:
        try:
            conn.execute(_sql.SQL("SET ROLE {}").format(_sql.Identifier(who["me"])))
        except psycopg.Error as exc:
            raise DatabaseError(f"migrations ran but the role could not be reset to {who['me']}: {describe(exc)}") from exc


def _grant_self_test_reads(conn: psycopg.Connection) -> None:
    """Inside a migration's transaction: the isolation self-test group reads every org_id table and view that exists now
    (migration 0059), so a migration that adds one covers it at once and a clean apply holds what a live database holds.
    Before 0059 the function does not exist and there is nothing to grant."""
    if conn.execute("SELECT to_regprocedure('consentvault.isolation_self_test_grant_reads()') IS NOT NULL AS f"
                    ).fetchone()["f"]:
        conn.execute("SELECT consentvault.isolation_self_test_grant_reads()")


def _migrate_as_owner(conn: psycopg.Connection, folder: Path, files: list[Path], owner: str) -> list[str]:
    try:
        with conn.transaction():
            conn.execute("CREATE SCHEMA IF NOT EXISTS consentvault")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS consentvault.schema_migration ("
                " name text PRIMARY KEY, sha256 text NOT NULL,"
                " applied_at timestamptz NOT NULL DEFAULT now())"
            )
        applied = {r["name"]: r["sha256"] for r in conn.execute("SELECT name, sha256 FROM consentvault.schema_migration")}
    except psycopg.Error as exc:
        raise DatabaseError(f"cannot read the migration ledger: {describe(exc)}") from exc

    on_disk = {p.name: p for p in files}
    for name, digest in applied.items():
        if name not in on_disk:
            raise MigrationDriftError(f"applied migration {name} is missing from {folder}", code='applied_migration_missing')
        if file_sha256(on_disk[name]) != digest:
            raise MigrationDriftError(
                f"applied migration {name} changed after it was applied; "
                "add a new migration instead of editing an applied one"
            , code='applied_migration_changed')

    highest = max((int(name[:4]) for name in applied), default=0)
    out_of_order = [p.name for p in files if p.name not in applied and int(p.name[:4]) <= highest]
    if out_of_order:
        raise MigrationError(
            f"pending migration(s) {out_of_order} are numbered at or below the highest applied ({highest:04d}); "
            "renumber them above it"
        , code='migration_out_of_order')

    done: list[str] = []
    for path in files:
        if path.name in applied:
            continue
        sql = path.read_text(encoding="utf-8")
        try:
            with conn.transaction():
                conn.execute(sql)
                _grant_self_test_reads(conn)
                now = conn.execute("SELECT current_user AS u, session_user AS s").fetchone()
                if now["u"] != owner:
                    raise MigrationError(
                        f"migration {path.name} left the session as role {now['u']}, not the schema owner {owner}, and "
                        f"was rolled back: set the migration login's default role (ALTER ROLE {now['s']} SET role = "
                        f"{owner}) so a RESET ROLE inside a migration returns to the owner", code='migration_left_wrong_role')
                conn.execute(
                    "INSERT INTO consentvault.schema_migration (name, sha256) VALUES (%s, %s)",
                    (path.name, file_sha256(path)),
                )
        except psycopg.Error as exc:
            raise MigrationError(f"migration {path.name} failed and was rolled back: {describe(exc)}", code='migration_failed') from exc
        done.append(path.name)
    return done
