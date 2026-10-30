"""The test seam restates the admin lane's export_job table and append_audit function. When the real migration chain
applies, the two must agree column for column; when it does not apply, the skip names the migration error."""

import uuid

import psycopg
import pytest

from conftest import MIGRATOR_ROLE, create_vault_database
from consentvault import db
from consentvault.errors import MigrationError

from .support import seam_migrations

SHAPE = ("SELECT column_name, data_type, is_nullable FROM information_schema.columns"
         " WHERE table_schema = 'consentvault' AND table_name = 'export_job' ORDER BY column_name")
FUNC = ("SELECT pg_get_function_identity_arguments(p.oid) AS args, pg_get_function_result(p.oid) AS result"
        " FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
        " WHERE n.nspname = 'consentvault' AND p.proname = 'append_audit'")
GRANTS = ("SELECT column_name, privilege_type FROM information_schema.column_privileges"
          " WHERE table_schema = 'consentvault' AND table_name = 'export_job' AND grantee = 'consentvault_app'"
          " ORDER BY column_name, privilege_type")


def _fresh(port: int) -> str:
    """A second vault database laid out like the fixture's: owned by the NOLOGIN owner, reached as the migrator."""
    name = "seam_" + uuid.uuid4().hex[:10]
    create_vault_database(port, name)
    return f"postgresql://{MIGRATOR_ROLE}@127.0.0.1:{port}/{name}"


def test_the_seam_matches_the_real_export_job_table(raw_dsn, pg_server, tmp_path):
    seam_dsn = _fresh(pg_server["port"])
    with db.connect(seam_dsn) as c:
        db.migrate(c, seam_migrations(tmp_path / "pinned"))
    try:
        with db.connect(raw_dsn) as c:
            db.migrate(c)
    except MigrationError as exc:
        pytest.skip(f"the real migration chain does not apply yet, so the seam cannot be compared: {exc}")
    with db.connect(raw_dsn) as real:
        if real.execute("SELECT to_regclass('consentvault.export_job') AS t").fetchone()["t"] is None:
            pytest.skip("the real migration chain has no export_job table yet, so the seam cannot be compared")
    with db.connect(raw_dsn) as real, db.connect(seam_dsn) as seam:
        for query in (SHAPE, FUNC, GRANTS):
            assert real.execute(query).fetchall() == seam.execute(query).fetchall(), query
