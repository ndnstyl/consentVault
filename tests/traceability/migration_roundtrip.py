#!/usr/bin/env python3
"""Migrations up, down, up round trip on a throwaway PostgreSQL. Exit 1 on any difference or failure.

Applies every migration as the non-superuser owner, records the schema shape, runs every down file in reverse order as
the superuser, checks nothing of the product is left, applies again and requires the same schema shape.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
import conftest as c  # noqa: E402  (the suite's own server and role helpers)

from consentvault import db  # noqa: E402

SHAPE = """
SELECT 'col', table_schema || '.' || table_name || '.' || column_name || ':' || data_type || ':' || is_nullable
  FROM information_schema.columns WHERE table_schema = 'consentvault'
UNION ALL SELECT 'fn', n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'consentvault'
UNION ALL SELECT 'idx', schemaname || '.' || indexname FROM pg_indexes WHERE schemaname = 'consentvault'
UNION ALL SELECT 'trg', event_object_table || '.' || trigger_name FROM information_schema.triggers WHERE trigger_schema = 'consentvault'
UNION ALL SELECT 'pol', tablename || '.' || policyname FROM pg_policies WHERE schemaname = 'consentvault'
ORDER BY 1, 2
"""
LEFT = """
SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'consentvault' AND c.relkind IN ('r', 'p', 'v', 'm') AND c.relname <> 'schema_migration'
"""


def shape(dsn: str) -> list[tuple]:
    with psycopg.connect(dsn) as conn:
        return [tuple(r) for r in conn.execute(SHAPE).fetchall()]


def main() -> int:
    bindir = c._pg_bin()
    root = Path(tempfile.mkdtemp(prefix="cv-roundtrip-"))
    c.claim_cluster(root)
    data, port = root / "data", c._free_port()
    subprocess.run([str(bindir / "initdb"), "-D", str(data), "-U", "postgres", "-A", "trust", "-E", "UTF8", "--locale=C"],
                   check=True, capture_output=True)
    started = False
    try:
        subprocess.run([str(bindir / "pg_ctl"), "start", "-w", "-t", "60", "-D", str(data), "-l", str(root / "pg.log"),
                        "-o", f"-p {port} -k {root} -c listen_addresses=127.0.0.1 -c fsync=off"], check=True, capture_output=True)
        started = True
        c.ensure_roles(port)
        name = "rt_" + uuid.uuid4().hex[:10]
        c.create_vault_database(port, name)  # owned by the NOLOGIN owner, trigger guard installed by the superuser
        owner_dsn, super_dsn = c._dsn(port, name, c.MIGRATOR_ROLE), c._dsn(port, name)
        with db.connect(owner_dsn) as conn:
            applied = db.migrate(conn)
        first = shape(super_dsn)
        print(f"up: {len(applied)} migrations, {len(first)} schema objects")
        downs = sorted((ROOT / "migrations" / "down").glob("*.sql"), reverse=True)
        ups = sorted(p.name for p in (ROOT / "migrations").glob("*.sql"))
        if [d.name for d in downs] != sorted((n for n in ups), reverse=True):
            print(f"FAIL: up files {ups} and down files {[d.name for d in downs]} do not pair one to one")
            return 1
        with psycopg.connect(super_dsn, autocommit=True) as su:
            for d in downs:
                su.execute(d.read_text())
            left = [r[0] for r in su.execute(LEFT).fetchall()]
            if left:
                print(f"FAIL: tables left after every down: {left}")
                return 1
            su.execute("DROP SCHEMA IF EXISTS consentvault CASCADE")
        print(f"down: {len(downs)} down files ran clean")
        with db.connect(owner_dsn) as conn:
            again = db.migrate(conn)
        second = shape(super_dsn)
        if first != second or applied != again:
            print(f"FAIL: schema after the second up differs: only first {sorted(set(first) - set(second))[:5]}, "
                  f"only second {sorted(set(second) - set(first))[:5]}")
            return 1
        print(f"up again: {len(again)} migrations, same {len(second)} schema objects")
        return 0
    finally:
        if started:
            subprocess.run([str(bindir / "pg_ctl"), "stop", "-m", "immediate", "-w", "-D", str(data)], capture_output=True)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
