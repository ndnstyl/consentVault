"""The raw post migration touches nothing sealed: on a populated copy, every event row, its hash, the chain and every
existing seal are byte for byte what they were before 0067 (task T021, data-model.md section 8)."""

import json
import shutil
from pathlib import Path

import pytest

from consentvault import db
from consentvault.ledger import verify_chain

from conftest import pin_as_superuser
from isolation.harness import build_tenancy

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
SNAPSHOT = {
    "event": "SELECT to_jsonb(e) AS j FROM consentvault.event e ORDER BY org_id, seq",
    "seal": "SELECT to_jsonb(s) AS j FROM consentvault.seal s ORDER BY seal_uuid",
    "chain_head": "SELECT to_jsonb(c) AS j FROM consentvault.chain_head c ORDER BY head_uuid",
    "contact_key": "SELECT to_jsonb(k) AS j FROM consentvault.contact_key k ORDER BY org_id, contact_fp",
}


def _snapshot(su):
    return {name: [json.dumps(r["j"], sort_keys=True) for r in su.execute(sql).fetchall()] for name, sql in SNAPSHOT.items()}


def _columns(su):
    return su.execute("SELECT table_name, column_name, data_type, is_nullable FROM information_schema.columns"
                      " WHERE table_schema = 'consentvault' AND table_name IN ('event', 'seal', 'chain_head', 'contact_key')"
                      " ORDER BY table_name, ordinal_position").fetchall()


def test_every_event_row_hash_and_existing_seal_is_identical_before_and_after_the_migration(raw_dsn, super_dsn, pg_server, tmp_path):
    before_dir = tmp_path / "up_to_0066"
    before_dir.mkdir()
    for p in MIGRATIONS.glob("*.sql"):
        if not p.name.startswith(("0067", "0068", "0069", "0070", "0071", "0072", "0073", "0074")):
            shutil.copy(p, before_dir / p.name)
    with db.connect(raw_dsn) as m:
        applied = db.migrate(m, before_dir)
    assert applied and not any(n.startswith(("0067", "0068", "0069", "0070", "0071", "0072", "0073", "0074")) for n in applied)
    pin_as_superuser(raw_dsn)
    t = build_tenancy(raw_dsn, pg_server["port"])  # populated: events, a revoke, contact keys, a synthetic seal per organisation
    with t.superuser() as su:
        before, cols_before = _snapshot(su), _columns(su)
    assert before["event"] and before["seal"] and before["chain_head"]
    with t.app() as app:
        from consentvault.tenancy.tokens import org_transaction
        for org in (t.a, t.b):
            with org_transaction(app, t.admin_token(org.org_id)):
                assert verify_chain(app, crypto=t.crypto) == []

    through_0067 = tmp_path / "up_to_0067"
    through_0067.mkdir()
    for p in MIGRATIONS.glob("*.sql"):
        if not p.name.startswith(("0068", "0069", "0070", "0071", "0072", "0073", "0074")):
            shutil.copy(p, through_0067 / p.name)
    with db.connect(raw_dsn) as m:
        assert db.migrate(m, through_0067) == ["0067_raw_post.sql"]
    pin_as_superuser(raw_dsn)
    # 0068 and 0069 change a pinned guard function, so they run as the superuser (the documented break-glass) and is re-pinned
    with db.connect(super_dsn) as m:
        assert db.migrate(m) == ["0068_release_needs_no_verification.sql", "0069_match_lookup.sql", "0070_single_fingerprint_secret.sql", "0071_stop_lift.sql", "0072_field_map_runtime_insert.sql", "0073_one_door_projection.sql", "0074_restore_reingests_as_a_post.sql"]
        m.execute("SELECT consentvault_guard.repin()")

    with t.superuser() as su:
        after, cols_after = _snapshot(su), _columns(su)
        assert su.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"] == 0
    assert after == before
    assert cols_after == cols_before  # no sealed column changed shape, none was added
    with t.app() as app:
        for org in (t.a, t.b):
            with org_transaction(app, t.admin_token(org.org_id)):
                assert verify_chain(app, crypto=t.crypto) == []
