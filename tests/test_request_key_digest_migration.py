"""Migration 0080 rewrites the plaintext request keys stored under migrations 0073 to 0078 to their sha256 digests (one-door review
round 5), so a key is only ever found by its digest, and running it again changes nothing."""

import hashlib
from pathlib import Path

import psycopg

from consentvault import door

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
STOP = {"contact": "+12125550121", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword",
        "origin": "consumer"}


def test_plaintext_request_keys_become_digests_and_a_second_run_changes_nothing(conn, super_dsn):
    door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=STOP)
    post = conn.execute("SELECT org_id, post_id FROM consentvault.raw_post WHERE kind = 'post' LIMIT 1").fetchone()
    plain = "sig:" + "ab" * 40
    with psycopg.connect(super_dsn, autocommit=True) as su:
        su.execute("ALTER TABLE consentvault.event_source_post DISABLE TRIGGER event_source_post_append_only")
        su.execute("UPDATE consentvault.event_source_post SET request_key = %s WHERE post_id = %s", (plain, post["post_id"]))
        su.execute("ALTER TABLE consentvault.event_source_post ENABLE TRIGGER event_source_post_append_only")
        su.execute("INSERT INTO consentvault.raw_post_request (org_id, post_id, request_key) VALUES (%s, %s, %s)",
                   (post["org_id"], post["post_id"], plain))
        sql = (MIGRATIONS / "0080_request_keys_as_digests.sql").read_text()
        su.execute(sql)
        su.execute(sql)
        want = hashlib.sha256(plain.encode()).hexdigest()
        assert [r[0] for r in su.execute("SELECT request_key FROM consentvault.raw_post_request").fetchall()] == [want]
        assert [r[0] for r in su.execute("SELECT request_key FROM consentvault.event_source_post"
                                         " WHERE request_key IS NOT NULL").fetchall()] == [want]
        assert su.execute("SELECT count(*) FROM pg_trigger WHERE tgrelid = 'consentvault.event_source_post'::regclass"
                          " AND tgname = 'event_source_post_append_only' AND tgenabled = 'O'").fetchone()[0] == 1


def test_after_the_migration_the_tables_still_refuse_every_other_change(conn):
    import pytest

    door.submit(conn, intake="library", region="US", allowed_purposes=["marketing"], payload=STOP)
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        conn.execute("UPDATE consentvault.event_source_post SET request_key = 'sig:other'")
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        conn.execute("DELETE FROM consentvault.event_source_post")
