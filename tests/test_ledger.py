from concurrent.futures import ThreadPoolExecutor

import psycopg
import pytest

from consentvault import db, disclosure, ledger
from consentvault.capture import capture
from consentvault.errors import (
    EmptyConsentError,
    MigrationDriftError,
    UncheckedConsentError,
    UnknownDisclosureError,
)


def _grant(conn, sha, contact="212-555-0101", **kw):
    return ledger.record_event(
        conn, contact=contact, event_type="grant", channels=["sms"], purposes=["marketing"],
        method="checkbox", origin="consumer", disclosure_sha256=sha, region="US", **kw,
    )


def _count(conn):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"]


def test_append_only_refused(conn, disclosure):
    _grant(conn, disclosure)
    with pytest.raises(psycopg.Error, match="append-only"):
        conn.execute("UPDATE consentvault.event SET source = 'x'")
    with pytest.raises(psycopg.Error, match="append-only"):
        conn.execute("DELETE FROM consentvault.event")
    with pytest.raises(psycopg.Error, match="append-only|cannot truncate"):
        conn.execute("TRUNCATE consentvault.event")
    with pytest.raises(psycopg.Error, match="append-only"):
        conn.execute("UPDATE consentvault.disclosure SET label = 'x'")


def test_seal_only_verified_at_updatable(conn, disclosure):
    ev = _grant(conn, disclosure)
    conn.execute(
        "INSERT INTO consentvault.seal (event_id, hash_version, columns, digest, tsa_url, token)"
        " VALUES (%s, 1, %s, %s, 'https://tsa.example.com', %s)",
        (ev.event_id, ["seq"], bytes(32), b"blob"),
    )
    conn.execute("UPDATE consentvault.seal SET verified_at = now()")
    with pytest.raises(psycopg.Error, match="only verified_at"):
        conn.execute("UPDATE consentvault.seal SET tsa_url = 'https://other.example.com'")
    with pytest.raises(psycopg.Error, match="append-only"):
        conn.execute("DELETE FROM consentvault.seal")
    assert conn.execute("SELECT count(*) AS n FROM consentvault.unsealed_events").fetchone()["n"] == 0


def test_chain_verifies(conn, disclosure):
    assert ledger.verify_chain(conn) == []
    for i in range(5):
        _grant(conn, disclosure, contact=f"212-555-01{i:02d}")
    ledger.record_event(
        conn, contact="212-555-0100", event_type="revoke", channels=["sms"], purposes=["marketing"],
        method="keyword", origin="consumer", region="US",
    )
    assert ledger.verify_chain(conn) == []
    assert conn.execute("SELECT count(*) AS n FROM consentvault.chain_breaks").fetchone()["n"] == 0


def test_tamper_detected(conn, disclosure):
    evs = [_grant(conn, disclosure, contact=f"212-555-01{i:02d}") for i in range(3)]
    conn.execute("ALTER TABLE consentvault.event DISABLE TRIGGER USER")
    conn.execute("UPDATE consentvault.event SET page_url = 'https://example.com/other' WHERE event_id = %s",
                 (evs[1].event_id,))
    conn.execute("ALTER TABLE consentvault.event ENABLE TRIGGER USER")
    breaks = ledger.verify_chain(conn)
    assert [(b.event_id, b.reason) for b in breaks] == [(evs[1].event_id, "row_hash_mismatch")]


def test_a_contact_point_swapped_under_its_commitment_is_two_breaks(conn, disclosure):
    evs = [_grant(conn, disclosure, contact=f"212-555-01{i:02d}") for i in range(3)]
    conn.execute("ALTER TABLE consentvault.event DISABLE TRIGGER USER")
    conn.execute("ALTER TABLE consentvault.event DROP CONSTRAINT event_contact_commit_matches")
    conn.execute("UPDATE consentvault.event SET contact_norm = '+12125550199' WHERE event_id = %s", (evs[1].event_id,))
    conn.execute("ALTER TABLE consentvault.event ENABLE TRIGGER USER")
    breaks = ledger.verify_chain(conn)
    assert [(b.event_id, b.reason) for b in breaks] == [
        (evs[1].event_id, "row_hash_mismatch"), (evs[1].event_id, "contact_commit_mismatch")]


def test_concurrent_writers_do_not_fork(dsn, disclosure):
    def worker(n):
        with db.connect(dsn) as c:
            for i in range(5):
                _grant(c, disclosure, contact=f"212-555-01{n}{i}")

    with ThreadPoolExecutor(max_workers=6) as pool:
        for fut in [pool.submit(worker, n) for n in range(6)]:
            fut.result()
    with db.connect(dsn) as c:
        row = c.execute("SELECT count(*) AS n, count(DISTINCT seq) AS d FROM consentvault.event").fetchone()
        assert row == {"n": 30, "d": 30}
        assert ledger.verify_chain(c) == []


def test_db_refuses_forked_insert(conn, disclosure):
    _grant(conn, disclosure)
    conn.execute("INSERT INTO consentvault.contact_salt (contact_norm, salt)"
                 " VALUES ('+12125550111', decode(repeat('cc', 32), 'hex'))")
    with pytest.raises(psycopg.Error, match="does not extend"):
        conn.execute(
            "INSERT INTO consentvault.event (seq, event_id, subject_key, contact_kind, contact_norm, contact_salt, contact_commit,"
            " event_type, channels, purposes, disclosure_sha256, method, origin, captured_at, received_at,"
            " hash_version, prev_hash, row_hash)"
            " SELECT 2, gen_random_uuid(), 'k', 'phone', '+12125550111', repeat('c', 64),"
            " encode(sha256(convert_to(repeat('c', 64) || '+12125550111', 'UTF8')), 'hex'), 'grant', ARRAY['sms'], ARRAY['m'],"
            " disclosure_sha256, 'checkbox', 'consumer', now(), now(), 1, repeat('a', 64), repeat('b', 64)"
            " FROM consentvault.event"
        )


def test_unknown_disclosure_refused(conn):
    with pytest.raises(UnknownDisclosureError):
        _grant(conn, "f" * 64)
    with pytest.raises(UnknownDisclosureError):
        ledger.record_event(
            conn, contact="212-555-0101", event_type="grant", channels=["sms"], purposes=["m"],
            method="checkbox", origin="consumer", region="US",
        )
    assert _count(conn) == 0


def test_unchecked_and_empty_consent_refused(conn, disclosure):
    kw = dict(contact="212-555-0101", disclosure_sha256=disclosure, region="US")
    with pytest.raises(UncheckedConsentError):
        capture(conn, checked=False, channels=["sms"], purposes=["marketing"], **kw)
    with pytest.raises(EmptyConsentError):
        capture(conn, checked=True, channels=[], purposes=["marketing"], **kw)
    with pytest.raises(EmptyConsentError):
        capture(conn, checked=True, channels=["sms"], purposes=[], **kw)
    assert _count(conn) == 0
    ev = capture(conn, checked=True, channels=["sms"], purposes=["marketing"], **kw)
    assert ev.seq == 1


def test_current_permission_stop_outranks_grant(conn, disclosure):
    _grant(conn, disclosure)
    perm = conn.execute("SELECT allowed, reason FROM consentvault.current_permission").fetchone()
    assert perm == {"allowed": True, "reason": "granted"}
    ledger.record_event(
        conn, contact="212-555-0101", event_type="revoke", channels=["sms"], purposes=["marketing"],
        method="keyword", origin="consumer", region="US",
    )
    _grant(conn, disclosure)
    perm = conn.execute("SELECT allowed, reason FROM consentvault.current_permission").fetchone()
    assert perm == {"allowed": False, "reason": "stopped:revoke"}


def test_migration_drift_refused(raw_dsn, tmp_path):
    (tmp_path / "0001_a.sql").write_text("CREATE TABLE public.t1 (id int);")
    with db.connect(raw_dsn) as c:
        assert db.migrate(c, tmp_path) == ["0001_a.sql"]
        assert db.migrate(c, tmp_path) == []
        (tmp_path / "0001_a.sql").write_text("CREATE TABLE public.t1 (id bigint);")
        with pytest.raises(MigrationDriftError):
            db.migrate(c, tmp_path)
        (tmp_path / "0001_a.sql").unlink()
        with pytest.raises(MigrationDriftError):
            db.migrate(c, tmp_path)


def test_disclosure_register_and_get(conn):
    sha = disclosure.register(conn, "Body text", "label", "en", ["sms", "email"], ["marketing"])
    assert sha == disclosure.sha256_of("Body text")
    assert disclosure.register(conn, "Body text", "label", "en", ["sms", "email"], ["marketing"]) == sha
    assert disclosure.get(conn, sha)["body"] == "Body text"
    with pytest.raises(UnknownDisclosureError):
        disclosure.get(conn, "0" * 64)
