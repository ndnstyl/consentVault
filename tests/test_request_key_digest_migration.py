"""Migration 0080 rewrites the plaintext request keys stored under migrations 0073 to 0078 to their sha256 digests (one-door review
round 5), so a key is only ever found by its digest, and running it again changes nothing."""

import hashlib
import os
import shutil
from pathlib import Path

import psycopg
import pytest

from consentvault import db, door

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
STOP = {"contact": "+12125550121", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword",
        "origin": "consumer"}


def _su(dsn):
    return dsn.replace("cv_test_migrator@", "postgres@", 1)


@pytest.mark.parametrize("multi", [False, True], ids=["single", "multi-tenant"])
def test_the_real_runner_rewrites_plaintext_keys_on_a_pinned_vault_in_either_mode(raw_dsn, tmp_path, multi):
    """Migrations up to 0079 are applied with the real runner, a plaintext key of each table is seeded, the guards are pinned, the
    vault is switched to multi-tenant mode if asked, and 0080 is applied by the runner as the superuser (break-glass), then repinned."""
    pre = tmp_path / "pre"
    pre.mkdir()
    for path in MIGRATIONS.glob("*.sql"):
        if int(path.name[:4]) <= 79:
            shutil.copy(path, pre / path.name)
    with db.connect(raw_dsn) as c:
        db.migrate(c, pre)
        door.submit(c, intake="library", region="US", allowed_purposes=["marketing"], payload=STOP)
        post = c.execute("SELECT org_id, post_id FROM consentvault.raw_post WHERE kind = 'post' LIMIT 1").fetchone()
    plain = "sig:" + "ab" * 40
    with psycopg.connect(_su(raw_dsn), autocommit=True) as su:
        su.execute("ALTER TABLE consentvault.event_source_post DISABLE TRIGGER event_source_post_append_only")
        su.execute("UPDATE consentvault.event_source_post SET request_key = %s WHERE post_id = %s", (plain, post["post_id"]))
        su.execute("ALTER TABLE consentvault.event_source_post ENABLE TRIGGER event_source_post_append_only")
        su.execute("INSERT INTO consentvault.raw_post_request (org_id, post_id, request_key) VALUES (%s, %s, %s)",
                   (post["org_id"], post["post_id"], plain))
    if multi:
        with db.connect(raw_dsn) as c:
            c.execute("SELECT consentvault.install_token_key(%s, %s)", ("k1", os.urandom(32)))
            c.execute("SELECT consentvault.enable_multi_tenant()")
    with psycopg.connect(_su(raw_dsn), autocommit=True) as su:
        su.execute("SELECT consentvault_guard.pin_guards()")
    with db.connect(_su(raw_dsn)) as c:
        db.migrate(c)
    with psycopg.connect(_su(raw_dsn), autocommit=True) as su:
        su.execute("SELECT consentvault_guard.repin()")
        want = hashlib.sha256(plain.encode()).hexdigest()
        assert [r[0] for r in su.execute("SELECT request_key FROM consentvault.raw_post_request").fetchall()] == [want]
        assert [r[0] for r in su.execute("SELECT request_key FROM consentvault.event_source_post"
                                         " WHERE request_key IS NOT NULL").fetchall()] == [want]
        assert su.execute("SELECT count(*) FROM consentvault.schema_migration WHERE name LIKE '0080%'").fetchone()[0] == 1
        assert su.execute("SELECT to_regprocedure('consentvault.rewrite_request_keys_to_digests()')").fetchone()[0] is None


def test_after_the_migration_the_tables_still_refuse_every_other_change(conn):
    door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=STOP)
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        conn.execute("UPDATE consentvault.event_source_post SET request_key = 'sig:other'")
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        conn.execute("DELETE FROM consentvault.event_source_post")
