#!/usr/bin/env python3
"""Build the security manifest from a clean apply of the shipped migrations, or check the committed one is current.

    scripts/build_security_manifest.py           write src/consentvault/data/security_manifest.sha256
    scripts/build_security_manifest.py --check   exit 1 (naming each drifted object) when the committed file is stale

Starts a throwaway PostgreSQL (PG_BIN, as the test suite finds it), makes the deployment's role layout under its own names,
installs the trigger guard as the superuser, applies every migration as the migration login under SET ROLE to the NOLOGIN
owner, switches the vault to multi mode (the surface the multi-tenant API checks: enable_multi_tenant() withdraws the
single-company grants), pins the guards as the superuser (as a deployment does after the run), reads the surface and
renders it. The same
migrations always render the same bytes. The server is stopped and its folder removed on every exit path.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))
import conftest as c  # noqa: E402  (the suite's server helpers: PG_BIN lookup and a free port)

from consentvault import db, surface  # noqa: E402

GUARD = ROOT / "docker" / "initdb" / "20-trigger-guard.sql"
OWNER = "cv_manifest_owner"
MIGRATOR = "cv_manifest_migrator"


def _admin(port: int, dbname: str = "postgres") -> str:
    return f"postgresql://postgres@127.0.0.1:{port}/{dbname}"


def clean_apply_surface(port: int) -> dict:
    """A new database on the server at ``port``, migrated from nothing the way a deployment does it; its surface."""
    with psycopg.connect(_admin(port), autocommit=True) as su:
        su.execute(
            "DO $$ BEGIN"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_app') THEN CREATE ROLE consentvault_app NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_worker') THEN CREATE ROLE consentvault_worker NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_operator') THEN CREATE ROLE consentvault_operator NOLOGIN BYPASSRLS; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_console') THEN CREATE ROLE consentvault_console NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_integrity') THEN CREATE ROLE consentvault_integrity NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_records_jobs') THEN CREATE ROLE consentvault_records_jobs NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_isolation_self_test') THEN CREATE ROLE consentvault_isolation_self_test NOLOGIN; END IF;"
            " IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'consentvault_restore_drill') THEN CREATE ROLE consentvault_restore_drill NOLOGIN; END IF;"
            f" IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{OWNER}') THEN CREATE ROLE {OWNER} NOLOGIN IN ROLE consentvault_operator; END IF;"
            f" IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{MIGRATOR}') THEN CREATE ROLE {MIGRATOR} LOGIN IN ROLE {OWNER};"
            f"   ALTER ROLE {MIGRATOR} SET role = '{OWNER}'; END IF;"
            " END $$")
        name = "manifest_" + uuid.uuid4().hex[:12]
        su.execute(f'CREATE DATABASE "{name}" OWNER {OWNER}')
    with psycopg.connect(_admin(port, name), autocommit=True) as su:
        su.execute(GUARD.read_text(encoding="utf-8"))
    with db.connect(f"postgresql://{MIGRATOR}@127.0.0.1:{port}/{name}") as m:
        db.migrate(m)
        m.execute("SELECT consentvault.enable_multi_tenant()")  # the surface the multi-tenant API serves
    with psycopg.connect(_admin(port, name), autocommit=True) as su:
        su.execute("SELECT consentvault_guard.pin_guards()")
        return surface.live_surface(su)


def build() -> bytes:
    bindir = c._pg_bin()
    root = Path(tempfile.mkdtemp(prefix="cv-manifest-"))
    data, port = root / "data", c._free_port()
    started = False
    try:
        subprocess.run([str(bindir / "initdb"), "-D", str(data), "-U", "postgres", "-A", "trust", "-E", "UTF8",
                        "--locale=C"], check=True, capture_output=True)
        subprocess.run([str(bindir / "pg_ctl"), "start", "-w", "-t", "60", "-D", str(data), "-l", str(root / "pg.log"),
                        "-o", f"-p {port} -k {root} -c listen_addresses=127.0.0.1 -c fsync=off"],
                       check=True, capture_output=True)
        started = True
        return surface.render(clean_apply_surface(port))
    finally:
        if started:
            subprocess.run([str(bindir / "pg_ctl"), "stop", "-m", "immediate", "-w", "-D", str(data)],
                           check=True, capture_output=True)
        shutil.rmtree(root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--check", action="store_true", help="fail when the committed manifest is not what the build makes")
    args = ap.parse_args(argv)
    built = build()
    if not args.check:
        surface.MANIFEST_PATH.write_bytes(built)
        print(f"wrote {surface.MANIFEST_PATH} ({len(surface.load_manifest()['objects'])} objects)")
        return 0
    try:
        committed = surface.load_manifest()
    except surface.ManifestError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    stale = surface.drift(surface.parse_manifest(built, "the build"), committed)
    if stale or built != surface.MANIFEST_PATH.read_bytes():
        print("FAIL: the committed security manifest is stale (run scripts/build_security_manifest.py and commit it):",
              file=sys.stderr)
        for line in stale or ["the file's bytes differ from the build's"]:
            print("  " + line, file=sys.stderr)
        return 1
    print(f"the committed security manifest matches a clean apply ({len(committed['objects'])} objects)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
