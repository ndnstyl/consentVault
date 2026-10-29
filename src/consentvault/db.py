"""Connections and the migration runner."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from .errors import ConfigError, DatabaseError, MigrationDriftError, MigrationError

_MIGRATION_NAME = re.compile(r"^\d{4}_[a-z0-9_]+\.sql$")


def connect(dsn: str) -> psycopg.Connection:
    """Open an autocommit connection returning dict rows. Writers open their own transactions."""
    if not dsn:
        raise ConfigError("empty database DSN")
    try:
        return psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
    except psycopg.Error as exc:
        raise DatabaseError(f"cannot connect to the database: {exc}") from exc


def default_migrations_dir() -> Path:
    """The repo's migrations/ directory, else the copy packaged inside the wheel."""
    here = Path(__file__).resolve().parent
    for candidate in (here.parents[1] / "migrations", here / "_migrations"):
        if candidate.is_dir():
            return candidate
    raise MigrationError("migrations directory not found; set CONSENTVAULT_MIGRATIONS")


def list_migrations(directory: Path) -> list[Path]:
    if not directory.is_dir():
        raise MigrationError(f"migrations directory does not exist: {directory}")
    files = sorted(p for p in directory.iterdir() if p.is_file() and p.suffix == ".sql")
    bad = [p.name for p in files if not _MIGRATION_NAME.match(p.name)]
    if bad:
        raise MigrationError(f"migration files must be named NNNN_name.sql: {bad}")
    return files


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def migrate(conn: psycopg.Connection, directory: str | Path | None = None) -> list[str]:
    """Apply pending migrations in order. Returns the names applied.

    Refuses if an applied file changed on disk, an applied file is missing, or a pending file is numbered
    at or below the highest applied one (history is never inserted in the middle).
    """
    folder = Path(directory) if directory else default_migrations_dir()
    files = list_migrations(folder)
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
        raise DatabaseError(f"cannot read the migration ledger: {exc}") from exc

    on_disk = {p.name: p for p in files}
    for name, digest in applied.items():
        if name not in on_disk:
            raise MigrationDriftError(f"applied migration {name} is missing from {folder}")
        if file_sha256(on_disk[name]) != digest:
            raise MigrationDriftError(
                f"applied migration {name} changed after it was applied; "
                "add a new migration instead of editing an applied one"
            )

    highest = max((int(name[:4]) for name in applied), default=0)
    out_of_order = [p.name for p in files if p.name not in applied and int(p.name[:4]) <= highest]
    if out_of_order:
        raise MigrationError(
            f"pending migration(s) {out_of_order} are numbered at or below the highest applied ({highest:04d}); "
            "renumber them above it"
        )

    done: list[str] = []
    for path in files:
        if path.name in applied:
            continue
        sql = path.read_text(encoding="utf-8")
        try:
            with conn.transaction():
                conn.execute(sql)
                conn.execute(
                    "INSERT INTO consentvault.schema_migration (name, sha256) VALUES (%s, %s)",
                    (path.name, file_sha256(path)),
                )
        except psycopg.Error as exc:
            raise MigrationError(f"migration {path.name} failed and was rolled back: {exc}") from exc
        done.append(path.name)
    return done
