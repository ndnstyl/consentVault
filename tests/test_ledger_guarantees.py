"""Guarantees of the vault: the runtime role, anchoring, ordering, scope, purposes and migrations."""

import hashlib
import json
import uuid
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import psycopg
import pytest

from conftest import superuser_of
from consentvault import anchor as anchor_mod
from consentvault import db, disclosure as disc
from consentvault.errors import (
    AnchorError,
    ChainError,
    ClockSkewError,
    EmptyConsentError,
    GrantScopeError,
    MigrationError,
    UnknownPurposeError,
)
from consentvault.gate import contact_facts
from consentvault.ledger import record_event, verify_chain

C = "+15555550123"


def _types(conn, contact=C):
    return [line["event_type"] for line in contact_facts(conn, contact).history]


SALT = "c" * 64


def _salt(conn, norm=C):
    conn.execute("INSERT INTO consentvault.contact_salt (contact_norm, salt) VALUES (%s, decode(%s, 'hex'))"
                 " ON CONFLICT DO NOTHING", (norm, SALT))
MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
COMMIT = "repeat('c', 64), encode(sha256(convert_to(repeat('c', 64) || '+15555550123', 'UTF8')), 'hex')"


def _d(conn, channels=("sms",), purposes=("marketing",), body="Texts about your account. Reply STOP to end."):
    return disc.register(conn, body, "f", "en", list(channels), list(purposes))


def _grant(conn, sha, **kw):
    kw.setdefault("channels", ["sms"])
    kw.setdefault("purposes", ["marketing"])
    kw.setdefault("contact_verification", "otp")
    return record_event(conn, contact=C, event_type="grant", method="checkbox", origin="consumer",
                        disclosure_sha256=sha, session_ref=kw.pop("session_ref", "s1"), **kw)


def _stop(conn, event_type="revoke", **kw):
    kw.setdefault("channels", ["sms"])
    kw.setdefault("purposes", ["marketing"])
    kw.setdefault("method", "keyword")
    return record_event(conn, contact=C, event_type=event_type, origin="consumer", **kw)


def _as_owner_without_triggers(conn, table, sql, params=()):
    """Tamper below the triggers. Only a superuser can switch a vault trigger off (the trigger guard), so it runs as one."""
    with superuser_of(conn) as su:
        su.execute(f"ALTER TABLE consentvault.{table} DISABLE TRIGGER USER")
        try:
            su.execute(sql, params)
        finally:
            su.execute(f"ALTER TABLE consentvault.{table} ENABLE TRIGGER USER")


# one migration, one hash version, ordered history ------------------------------------------------------------

def test_the_first_migration_holds_the_release_columns_and_single_company_rows_use_hash_version_1(conn):
    names = [p.name for p in sorted(MIGRATIONS.glob("*.sql"))]
    assert names[0] == "0001_init.sql"
    assert sorted(p.name for p in (MIGRATIONS / "down").glob("*.sql")) == names  # every migration has its down
    cols = {r["column_name"] for r in conn.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_schema = 'consentvault' AND table_name = 'event'")}
    assert {"release_of_event_id", "release_outcome", "release_cause", "contact_commit", "edge_received_at"} <= cols
    from consentvault import ledger, seal
    assert 1 in ledger.HASH_VERSIONS and list(seal.SEAL_HASH_VERSIONS) == [1, 2]
    assert {"release_of_event_id", "release_outcome", "release_cause", "contact_commit",
            "edge_received_at"} <= set(ledger.HASH_VERSIONS[1])
    assert _grant(conn, _d(conn)).seq == 1
    assert conn.execute("SELECT DISTINCT hash_version FROM consentvault.event").fetchall() == [{"hash_version": 1}]


def test_down_then_up_round_trips(raw_dsn, super_dsn):
    with db.connect(raw_dsn) as c, db.connect(super_dsn) as su:
        applied = db.migrate(c)
        for name in reversed(applied):  # newest first, as a superuser (the tenancy down needs row security off)
            su.execute((MIGRATIONS / "down" / name).read_text())
        assert c.execute("SELECT to_regclass('consentvault.event') AS t").fetchone()["t"] is None
        c.execute("DELETE FROM consentvault.schema_migration")
        assert db.migrate(c) == applied
        assert c.execute("SELECT count(*) AS n FROM consentvault.current_permission").fetchone()["n"] == 0


def test_a_pending_migration_numbered_below_the_highest_applied_is_refused(raw_dsn, tmp_path):
    (tmp_path / "0001_a.sql").write_text("CREATE TABLE public.t1 (id int);")
    (tmp_path / "0003_c.sql").write_text("CREATE TABLE public.t3 (id int);")
    with db.connect(raw_dsn) as c:
        assert db.migrate(c, tmp_path) == ["0001_a.sql", "0003_c.sql"]
        (tmp_path / "0002_b.sql").write_text("CREATE TABLE public.t2 (id int);")
        with pytest.raises(MigrationError, match="0002_b.sql"):
            db.migrate(c, tmp_path)
        assert c.execute("SELECT to_regclass('public.t2') AS t").fetchone()["t"] is None
        (tmp_path / "0002_b.sql").unlink()
        (tmp_path / "0003_other.sql").write_text("SELECT 1")
        with pytest.raises(MigrationError, match="0003_other.sql"):
            db.migrate(c, tmp_path)


# roles -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "UPDATE consentvault.event SET source = 'x'",
    "DELETE FROM consentvault.event",
    "TRUNCATE consentvault.event",
    "UPDATE consentvault.disclosure SET label = 'x'",
    "DELETE FROM consentvault.disclosure",
    "UPDATE consentvault.seal SET verified_at = now()",
    "DELETE FROM consentvault.chain_head",
    "ALTER TABLE consentvault.event DISABLE TRIGGER USER",
    "ALTER TABLE consentvault.event DISABLE TRIGGER event_append_only",
    "ALTER TABLE consentvault.event ADD COLUMN sneaky text",
    "DROP TABLE consentvault.event",
    "DROP TRIGGER event_append_only ON consentvault.event",
    "CREATE TABLE consentvault.sneaky (id int)",
    "SET session_replication_role = replica",
    "SELECT * FROM consentvault.schema_migration",
    "ALTER TABLE consentvault.event OWNER TO CURRENT_USER",
    "CREATE OR REPLACE FUNCTION consentvault.refuse_change() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'",
    "ALTER VIEW consentvault.current_permission RENAME TO other_view",
    "TRUNCATE consentvault.seal",
])
def test_the_runtime_role_cannot_change_history_or_the_schema(app_conn, conn, disclosure, sql):
    _grant(conn, disclosure)
    with pytest.raises(psycopg.Error):
        app_conn.execute(sql)
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 1


def test_the_runtime_role_can_read_and_append_and_owns_nothing(app_conn, conn, disclosure):
    ev = _grant(app_conn, disclosure)
    assert ev.seq == 1
    assert contact_facts(app_conn, C).event_ids == (ev.event_id,)
    assert verify_chain(app_conn) == []
    me = app_conn.execute("SELECT rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user"
                          ).fetchone()
    assert me == {"rolsuper": False, "rolcreaterole": False, "rolcreatedb": False}
    owned = app_conn.execute(
        "SELECT count(*) AS n FROM pg_tables WHERE schemaname = 'consentvault' AND tableowner = current_user").fetchone()
    assert owned["n"] == 0


# anchoring ---------------------------------------------------------------------------------------------------

def test_deleting_the_tail_is_caught_once_the_head_was_anchored(conn, tmp_path):
    _grant(conn, _d(conn))
    _stop(conn)
    assert len(contact_facts(conn, C).stops) == 1
    sink = tmp_path / "anchors.jsonl"
    assert anchor_mod.anchor(conn, str(sink))["seq"] == 2
    _as_owner_without_triggers(conn, "event", "DELETE FROM consentvault.event WHERE seq = 2")
    assert contact_facts(conn, C).stops == ()  # the stop is gone from the ledger
    assert [(b.seq, b.reason) for b in verify_chain(conn)] == [(2, "anchored_row_missing:chain_head")]
    assert [b.reason for b in verify_chain(conn, sink_file=str(sink))] == [
        "anchored_row_missing:chain_head", "anchored_row_missing:sink"]


def test_the_external_sink_still_catches_a_tail_cut_that_also_erased_chain_head(conn, tmp_path):
    _grant(conn, _d(conn))
    _stop(conn)
    sink = tmp_path / "anchors.jsonl"
    anchor_mod.anchor(conn, str(sink))
    _as_owner_without_triggers(conn, "event", "DELETE FROM consentvault.event WHERE seq = 2")
    _as_owner_without_triggers(conn, "chain_head", "DELETE FROM consentvault.chain_head")
    assert verify_chain(conn) == []
    assert [b.reason for b in verify_chain(conn, sink_file=str(sink))] == ["anchored_row_missing:sink"]


def test_a_changed_row_under_an_anchor_is_a_break(conn, tmp_path):
    _grant(conn, _d(conn))
    anchor_mod.anchor(conn, str(tmp_path / "a.jsonl"))
    _as_owner_without_triggers(conn, "chain_head", "UPDATE consentvault.chain_head SET row_hash = repeat('a', 64)")
    assert [b.reason for b in verify_chain(conn)] == ["anchored_row_changed:chain_head"]


def test_anchor_writes_the_head_to_chain_head_and_the_file_and_the_chain_keeps_verifying(conn, tmp_path):
    _grant(conn, _d(conn))
    sink = tmp_path / "anchors.jsonl"
    first = anchor_mod.anchor(conn, str(sink))
    _stop(conn)
    second = anchor_mod.anchor(conn, str(sink))
    lines = [json.loads(ln) for ln in sink.read_text().splitlines()]
    assert [(ln["seq"], ln["row_hash"]) for ln in lines] == [(1, first["row_hash"]), (2, second["row_hash"])]
    assert all("anchored_at" in ln for ln in lines)
    rows = conn.execute("SELECT seq, row_hash, sink FROM consentvault.chain_head ORDER BY head_id").fetchall()
    assert [(r["seq"], r["row_hash"]) for r in rows] == [(1, first["row_hash"]), (2, second["row_hash"])]
    assert rows[0]["sink"] == str(sink)
    assert verify_chain(conn, sink_file=str(sink)) == []


def test_anchor_posts_to_a_webhook_and_names_a_refusal(conn):
    got = []
    status = {"code": 200}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(status["code"])
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            return None

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        _grant(conn, _d(conn))
        url = f"http://127.0.0.1:{srv.server_address[1]}/hook?token=hunter2"
        rec = anchor_mod.anchor(conn, url)
        assert got[0]["seq"] == 1 and got[0]["row_hash"] == rec["row_hash"]
        assert "hunter2" not in rec["sink"]
        assert "hunter2" not in conn.execute("SELECT sink FROM consentvault.chain_head").fetchone()["sink"]
        status["code"] = 500
        with pytest.raises(AnchorError, match="HTTP 500"):
            anchor_mod.anchor(conn, url)
        assert conn.execute("SELECT count(*) AS n FROM consentvault.chain_head").fetchone()["n"] == 1
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=10)


def test_anchor_refuses_an_empty_an_unwritable_and_a_broken_ledger(conn, tmp_path):
    with pytest.raises(AnchorError, match="empty"):
        anchor_mod.anchor(conn, str(tmp_path / "a.jsonl"))
    _grant(conn, _d(conn))
    with pytest.raises(AnchorError, match="cannot append"):
        anchor_mod.anchor(conn, str(tmp_path / "no-such-dir" / "a.jsonl"))
    assert conn.execute("SELECT count(*) AS n FROM consentvault.chain_head").fetchone()["n"] == 0
    _as_owner_without_triggers(conn, "event", "UPDATE consentvault.event SET source = 'tampered'")
    with pytest.raises(ChainError, match="broken chain"):
        anchor_mod.anchor(conn, str(tmp_path / "a.jsonl"))


def test_a_missing_sink_file_is_reported_once_anchors_exist(conn, tmp_path):
    _grant(conn, _d(conn))
    sink = tmp_path / "anchors.jsonl"
    assert verify_chain(conn, sink_file=str(sink)) == []  # nothing anchored yet, nothing to miss
    anchor_mod.anchor(conn, str(sink))
    sink.unlink()
    with pytest.raises(ChainError, match="cannot read the anchor sink"):
        verify_chain(conn, sink_file=str(sink))


def test_the_runtime_role_can_anchor(app_conn, conn, tmp_path):
    _grant(app_conn, _d(conn))
    assert anchor_mod.anchor(app_conn, str(tmp_path / "a.jsonl"))["seq"] == 1


# ordering ----------------------------------------------------------------------------------------------------

def test_history_is_in_arrival_order_even_if_a_grant_claims_a_later_capture_time(conn):
    sha = _d(conn)
    now = datetime.now(timezone.utc)
    _stop(conn, captured_at=now - timedelta(days=2))
    _grant(conn, sha, captured_at=now + timedelta(minutes=4))
    _stop(conn)
    assert _types(conn) == ["revoke", "grant", "revoke"]


def test_a_captured_at_beyond_the_skew_is_refused_and_one_inside_it_is_evidence_only(conn):
    sha = _d(conn)
    now = datetime.now(timezone.utc)
    with pytest.raises(ClockSkewError):
        _grant(conn, sha, captured_at=now + timedelta(minutes=6))
    with pytest.raises(ClockSkewError):
        _grant(conn, sha, captured_at=now + timedelta(hours=5))
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0
    _grant(conn, sha, captured_at=now + timedelta(minutes=4))
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 1


def test_the_database_refuses_a_future_captured_at_too(conn):
    sha = _d(conn)
    _salt(conn)
    with pytest.raises(psycopg.errors.CheckViolation, match="event_captured_not_future"):
        conn.execute(
            "INSERT INTO consentvault.event (seq, event_id, subject_key, contact_kind, contact_norm, contact_salt, contact_commit,"
            " event_type, channels, purposes, disclosure_sha256, method, origin, captured_at, received_at,"
            " hash_version, prev_hash, row_hash)"
            " VALUES (1, gen_random_uuid(), 'k', 'phone', '+15555550123', " + COMMIT + ", 'grant', ARRAY['sms'],"
            " ARRAY['marketing'],"
            " %s, 'checkbox', 'consumer', now() + interval '1 day', now(), 1, repeat('0', 64), repeat('b', 64))",
            (sha,))


def test_a_backdated_stop_does_not_reorder_history(conn):
    sha = _d(conn)
    _stop(conn, captured_at=datetime.now(timezone.utc) - timedelta(days=30))
    _grant(conn, sha)
    assert _types(conn) == ["revoke", "grant"]  # the line is where it arrived; the captured time is shown beside it


# scope -------------------------------------------------------------------------------------------------------

def test_a_grant_beyond_its_disclosure_is_refused_by_name(conn):
    email_only = _d(conn, channels=["email"], body="Email only.")
    with pytest.raises(GrantScopeError, match="artificial_voice"):
        _grant(conn, email_only, channels=["artificial_voice"])
    with pytest.raises(GrantScopeError, match="billing"):
        _grant(conn, _d(conn), purposes=["billing"])
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0
    assert contact_facts(conn, C).status == "no_record_found"


def test_a_subset_of_the_disclosure_is_a_valid_grant(conn):
    wide = _d(conn, channels=["sms", "voice", "email"], purposes=["marketing", "billing"], body="All of it.")
    _grant(conn, wide, channels=["sms"], purposes=["billing"])
    line = contact_facts(conn, C).history[0]
    assert (line["channels"], line["purposes"]) == (["sms"], ["billing"])


def test_the_database_refuses_a_grant_beyond_its_disclosure_when_the_python_check_is_skipped(conn):
    sha = _d(conn, channels=["email"], body="Email only.")
    _salt(conn)
    with pytest.raises(psycopg.Error, match="grant scope"):
        conn.execute(
            "INSERT INTO consentvault.event (seq, event_id, subject_key, contact_kind, contact_norm, contact_salt, contact_commit,"
            " event_type, channels, purposes, disclosure_sha256, method, origin, captured_at, received_at,"
            " hash_version, prev_hash, row_hash)"
            " VALUES (1, gen_random_uuid(), 'k', 'phone', '+15555550123', " + COMMIT + ", 'grant',"
            " ARRAY['artificial_voice'], ARRAY['marketing'], %s, 'checkbox', 'consumer', now(), now(), 1, repeat('0', 64), repeat('b', 64))",
            (sha,))


# purposes ----------------------------------------------------------------------------------------------------

def test_purposes_are_lower_cased_so_a_stop_in_any_case_is_one_stop(conn):
    _grant(conn, _d(conn))
    _stop(conn, purposes=["Marketing"])
    assert contact_facts(conn, C).stops[0]["purposes"] == ["marketing"]
    assert conn.execute("SELECT DISTINCT unnest(purposes) AS p FROM consentvault.event").fetchall() == [{"p": "marketing"}]


def test_purposes_must_be_on_the_configured_list(conn):
    sha = _d(conn)
    with pytest.raises(UnknownPurposeError, match="lottery"):
        _grant(conn, sha, purposes=["lottery"], allowed_purposes=["marketing"])
    with pytest.raises(UnknownPurposeError):
        _stop(conn, purposes=["lottery"], allowed_purposes=["marketing"])
    with pytest.raises(UnknownPurposeError, match="malformed"):
        _stop(conn, purposes=["bad purpose!"])
    with pytest.raises(UnknownPurposeError):
        disc.register(conn, "Other wording.", "f", "en", ["sms"], ["lottery"], allowed_purposes=["marketing"])
    _grant(conn, sha, purposes=["MARKETING"], allowed_purposes=["Marketing"])
    with pytest.raises(EmptyConsentError):
        _stop(conn, purposes=[])


def test_a_stop_for_every_purpose_is_listed_as_a_stop_for_every_purpose(conn):
    wide = _d(conn, channels=["sms", "email"], purposes=["marketing", "billing"], body="Wide.")
    _grant(conn, wide, channels=["sms", "email"], purposes=["marketing", "billing"])
    other = "+15555550199"
    record_event(conn, contact=other, event_type="grant", channels=["sms"], purposes=["marketing"],
                 method="checkbox", origin="consumer", disclosure_sha256=wide)
    _stop(conn, channels=["sms"], purposes=["*"])
    stop = contact_facts(conn, C).stops[0]
    assert (stop["channels"], stop["purposes"]) == (["sms"], ["*"])
    assert _types(conn, other) == ["grant"]  # other people are untouched
    _grant(conn, wide, channels=["sms"], purposes=["marketing"], session_ref="again")
    assert _types(conn) == ["grant", "revoke", "grant"]  # a later grant is a later line; nothing is lifted
    assert contact_facts(conn, C).lifts == ()


def test_stop_all_is_only_for_stops_and_only_on_its_own(conn):
    sha = _d(conn)
    with pytest.raises(UnknownPurposeError, match="only on a stop"):
        _grant(conn, sha, purposes=["*"])
    with pytest.raises(UnknownPurposeError, match="only purpose"):
        _stop(conn, purposes=["*", "marketing"])
    with pytest.raises(UnknownPurposeError):
        disc.register(conn, "Star.", "f", "en", ["sms"], ["*"])
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("INSERT INTO consentvault.disclosure (sha256, body, label, locale, channels, purposes)"
                     " VALUES (repeat('c', 64), 'b', 'l', 'en', ARRAY['sms'], ARRAY['*'])")





# no release row can be written ----------------------------------------------------------------------------------------

def _raw_event(conn, **over):
    """Insert one row the way a writer holding only INSERT could: hand-built, chained, hashed."""
    import uuid as uuid_mod

    from consentvault.ledger import GENESIS, compute_row_hash, contact_commitment

    held = conn.execute("SELECT consentvault.mint_contact_salt(%s) AS s", (C,)).fetchone()["s"]
    head = conn.execute("SELECT seq, row_hash FROM consentvault.event ORDER BY seq DESC LIMIT 1").fetchone()
    now = datetime.now(timezone.utc)
    row = dict(
        seq=(head["seq"] + 1 if head else 1), event_id=uuid_mod.uuid4(), subject_key="k" * 64, contact_kind="phone",
        contact_norm=C, contact_salt=held, contact_commit=contact_commitment(held, C), event_type="grant", channels=["sms"],
        purposes=["marketing"], disclosure_sha256=None, method="checkbox", origin="consumer", captured_at=now,
        received_at=now, edge_received_at=None, page_url=None, client_ip=None, user_agent=None, session_ref=None,
        bot_check=None, payload_sha256=None, source=None, recorded_by=None, release_of_event_id=None,
        release_outcome=None, release_cause=None, contact_verification="none", hash_version=1)
    row.update(over)
    prev = head["row_hash"] if head else GENESIS
    full = {**row, "prev_hash": prev, "row_hash": compute_row_hash(prev, row, 1)}
    conn.execute(f"INSERT INTO consentvault.event ({', '.join(full)}) VALUES ({', '.join(['%s'] * len(full))})",
                 list(full.values()))
    return row














# the database refuses every release row, whatever it names -------------------------------------------------------

def test_the_database_refuses_a_release_row_whatever_it_names(app_conn, conn, disclosure):
    own = _grant(conn, disclosure)
    stop = _stop(conn)
    other = record_event(conn, contact="+15555550199", event_type="grant", channels=["sms"], purposes=["marketing"],
                         method="checkbox", origin="consumer", disclosure_sha256=disclosure, session_ref="s")
    for target in (own.event_id, stop.event_id, other.event_id, str(uuid.uuid4())):
        with pytest.raises(psycopg.Error, match="no release event can be written"):
            _raw_event(app_conn, event_type="release", release_of_event_id=uuid.UUID(target), release_outcome="released")
    assert contact_facts(conn, C).stops[0]["lifted_by_post_ids"] == []


# trigger functions pin their search path -------------------------------------------------------------------

def test_a_runtime_role_cannot_shadow_an_operator_to_widen_a_grant(app_conn, conn, disclosure):
    c = app_conn
    c.execute("CREATE FUNCTION pg_temp.always(text[], text[]) RETURNS boolean LANGUAGE sql AS 'SELECT true'")
    c.execute("CREATE OPERATOR pg_temp.<@ (LEFTARG = text[], RIGHTARG = text[], FUNCTION = pg_temp.always)")
    c.execute("SET search_path = pg_temp, pg_catalog")
    with pytest.raises(psycopg.Error, match="grant scope"):
        _raw_event(c, disclosure_sha256=disclosure, channels=["voice"], purposes=["marketing"])
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0


def test_an_object_planted_in_the_default_schema_is_not_picked_up(app_conn, conn, disclosure):
    conn.execute("GRANT CREATE ON SCHEMA public TO PUBLIC")  # the default before PostgreSQL 15
    c = app_conn
    c.execute("CREATE FUNCTION public.always(text[], text[]) RETURNS boolean LANGUAGE sql AS 'SELECT true'")
    c.execute("CREATE OPERATOR public.<@ (LEFTARG = text[], RIGHTARG = text[], FUNCTION = public.always)")
    c.execute("SET search_path = public, pg_catalog")
    with pytest.raises(psycopg.Error, match="grant scope"):
        _raw_event(c, disclosure_sha256=disclosure, channels=["voice"], purposes=["marketing"])


def test_the_migration_withdraws_create_on_the_default_schema_from_everyone(conn):
    assert conn.execute("SELECT has_schema_privilege('public', 'public', 'CREATE') AS ok").fetchone()["ok"] is False


def test_every_function_in_the_schema_pins_its_search_path(conn):
    rows = conn.execute(
        "SELECT p.proname, p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
        " WHERE n.nspname = 'consentvault'").fetchall()
    assert rows
    for r in rows:
        assert r["proconfig"] == ["search_path=pg_catalog, pg_temp"], r["proname"]


# receipt time is the vault's own clock ----------------------------------------------------------------------

def test_the_vault_sets_received_at_itself(conn):
    sha = _d(conn)
    with pytest.raises(TypeError):
        _grant(conn, sha, received_at=datetime.now(timezone.utc))
    before = datetime.now(timezone.utc)
    _grant(conn, sha)
    row = conn.execute("SELECT received_at FROM consentvault.event").fetchone()
    assert before - timedelta(seconds=2) <= row["received_at"] <= datetime.now(timezone.utc) + timedelta(seconds=2)


def test_the_edge_receipt_time_is_kept_apart_as_evidence(conn):
    sha = _d(conn)
    edge = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    _grant(conn, sha, edge_received_at=edge)
    row = conn.execute("SELECT received_at, edge_received_at FROM consentvault.event").fetchone()
    assert row["edge_received_at"] == edge and row["received_at"] != edge
    with pytest.raises(Exception, match="timezone-aware"):
        _grant(conn, sha, edge_received_at=datetime(2026, 1, 2, 3, 4, 5))
    assert verify_chain(conn) == []


def test_a_far_future_captured_at_is_refused_whatever_the_edge_claims(conn):
    sha = _d(conn)
    future = datetime.now(timezone.utc) + timedelta(days=3650)
    with pytest.raises(ClockSkewError):
        _grant(conn, sha, captured_at=future, edge_received_at=future)
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0


@pytest.mark.parametrize("offset", [timedelta(days=3650), -timedelta(days=30)])
def test_the_database_refuses_a_received_at_that_is_not_the_servers_clock(conn, offset):
    with pytest.raises(psycopg.Error, match="vault server's own clock"):
        _raw_event(conn, received_at=datetime.now(timezone.utc) + offset, captured_at=datetime.now(timezone.utc))


def test_the_database_refuses_a_contact_commitment_that_is_not_the_contacts_hash(conn):
    with pytest.raises(psycopg.errors.CheckViolation, match="event_contact_commit_matches"):
        _raw_event(conn, event_type="revoke", contact_commit="a" * 64)


# the down migration never destroys evidence ----------------------------------------------------------------

def test_the_down_migration_refuses_while_the_ledger_holds_events(conn, disclosure):
    _grant(conn, disclosure)
    with pytest.raises(psycopg.Error, match="down migration refused"):
        conn.execute((MIGRATIONS / "down" / "0001_init.sql").read_text())
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 1
    assert verify_chain(conn) == []


def test_a_row_must_carry_its_contacts_own_salt(conn):
    _salt(conn)
    with pytest.raises(psycopg.Error, match="contact's own salt"):
        _raw_event(conn, contact_salt="d" * 64, contact_commit=hashlib.sha256(("d" * 64 + C).encode()).hexdigest())


def test_the_contact_salt_table_is_append_only(conn):
    _salt(conn)
    with pytest.raises(psycopg.Error, match="append-only"):
        conn.execute("UPDATE consentvault.contact_salt SET salt = decode(repeat('dd', 32), 'hex')")
    with pytest.raises(psycopg.Error, match="append-only"):
        conn.execute("DELETE FROM consentvault.contact_salt")
