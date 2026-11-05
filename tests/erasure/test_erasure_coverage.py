"""Only a completed erasure of that contact makes a row read as erased, and coverage is decided by ledger sequence.

A row whose contact key is missing with no erasure covering it is a break. A completed erasure records the event ledger
sequence it covers (set by the database under the ledger lock), so the app clock never decides which rows are erased."""

from datetime import timedelta

import psycopg
import pytest

from consentvault.tenancy import erasure as er
from consentvault.tenancy.tokens import org_transaction

from isolation.cloud_harness import Cloud

from .test_erasure import _confirm, _request
from .test_erasure_stop import ALL, X, _verified_regrant, _verify


@pytest.fixture
def cloud(env, tmp_path):
    c = Cloud(env.t, str(tmp_path / "evidence"))
    try:
        yield c
    finally:
        c.close()


def _tamper_event(env, sql, params=()):
    with env.t.superuser() as su:
        su.execute("ALTER TABLE consentvault.event DISABLE TRIGGER USER")
        try:
            su.execute(sql, params)
        finally:
            su.execute("ALTER TABLE consentvault.event ENABLE TRIGGER USER")


def _rows(env, contact=X):
    with env.t.superuser() as su:
        return [r["seq"] for r in su.execute("SELECT seq FROM consentvault.event WHERE org_id = %s AND contact_fp = %s"
                                             " ORDER BY seq", (env.t.a.org_id, env.fp(env.t.a, contact))).fetchall()]


def _skewed(monkeypatch, delta):
    """The app host's own clock a day ahead or behind: erasure reads the database's clock, so this must change nothing."""
    real = er.datetime

    class Skewed(real):
        @classmethod
        def now(cls, tz=None):
            return real.now(tz) + delta

    monkeypatch.setattr(er, "datetime", Skewed)


def _erase_and_return(env, cloud):
    s, r = cloud.grant(cloud.a, X, **ALL)
    assert s == 201, r
    req = _request(env, env.t.a, X)
    assert _confirm(env, env.t.a, req["erasure_id"])["status"] == "completed"
    before = _rows(env)
    conn, tx = _verified_regrant(env, cloud, X, commit=True)  # the person returns under a new key
    tx.__exit__(None, None, None)
    conn.close()
    after = [s for s in _rows(env) if s not in before]
    assert after and env.key_present(env.t.a, X)
    return req, before, after


def test_a_hand_deleted_key_with_junk_ciphertext_is_a_break_not_an_erasure(env, cloud):
    s, r = cloud.grant(cloud.a, X, **ALL)
    assert s == 201, r
    seqs = _rows(env)
    with env.t.superuser() as su:
        su.execute("DELETE FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                   (env.t.a.org_id, env.fp(env.t.a, X)))
    _tamper_event(env, "UPDATE consentvault.event SET contact_ct = %s WHERE org_id = %s AND seq = %s",
                  (b"\x00" * 48, env.t.a.org_id, seqs[0]))
    assert _verify(env) == [("contact_key_missing", s) for s in seqs]


@pytest.mark.parametrize("delta", [timedelta(days=1), timedelta(days=-1)], ids=["app_clock_ahead", "app_clock_behind"])
def test_coverage_is_decided_by_sequence_whichever_way_the_app_clock_is_skewed(env, cloud, monkeypatch, delta):
    _skewed(monkeypatch, delta)
    req, before, after = _erase_and_return(env, cloud)
    with env.t.superuser() as su:
        covers = _covers(su, req["erasure_id"])
    assert max(before) <= covers < min(after)
    assert _verify(env) == []  # the rows sealed under the destroyed key read as erased; the new ones verify
    _tamper_event(env, "UPDATE consentvault.event SET contact_ct = %s WHERE org_id = %s AND seq = %s",
                  (b"\x00" * 48, env.t.a.org_id, after[0]))
    assert ("ciphertext_invalid", after[0]) in _verify(env)  # a returning person's row is checked, never skipped


def _covers(conn, eid):
    row = conn.execute("SELECT covers_through_seq FROM consentvault.erasure_coverage WHERE erasure_id = %s",
                       (eid,)).fetchone()
    return None if row is None else row["covers_through_seq"]


def test_the_covered_sequence_is_set_by_the_database_never_by_a_caller(env, cloud):
    s, r = cloud.grant(cloud.a, X, **ALL)
    assert s == 201, r
    req = _request(env, env.t.a, X)
    with env.t.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(app, env.t.token(env.t.a)):
                app.execute("INSERT INTO consentvault.erasure_coverage (org_id, erasure_id, covers_through_seq)"
                            " VALUES (%s, %s, 999)", (env.t.a.org_id, req["erasure_id"]))
    _confirm(env, env.t.a, req["erasure_id"])
    with env.t.superuser() as su:
        head = su.execute("SELECT max(seq) AS s FROM consentvault.event WHERE org_id = %s",
                          (env.t.a.org_id,)).fetchone()["s"]
        assert _covers(su, req["erasure_id"]) == head
        for sql in ("UPDATE consentvault.erasure_coverage SET covers_through_seq = 999",
                    "DELETE FROM consentvault.erasure_coverage"):
            with pytest.raises(psycopg.Error):
                su.execute(sql)
    with env.t.app() as app, org_transaction(app, env.t.token(env.t.a)):
        assert _covers(app, req["erasure_id"]) == head
    with env.t.app() as app, org_transaction(app, env.t.token(env.t.b)):
        assert _covers(app, req["erasure_id"]) is None  # another organisation never sees it


# ---- the migration's backfill and the verifier's refusal of an unsequenced erasure -----------------------------------------
from pathlib import Path  # noqa: E402
import uuid  # noqa: E402

from consentvault import db  # noqa: E402
import psycopg.sql  # noqa: E402

MIG = "0043_erasure_covers_seq.sql"
DOWN_0043 = Path(__file__).resolve().parents[2] / "migrations" / "down" / MIG


def _apply_0043(raw_dsn):
    """Run the migration file as the migrator does (one transaction, as the schema owner). A later migration may already be
    applied, so the migrator itself would refuse to re-run an earlier number."""
    with db.connect(raw_dsn) as c, c.transaction():
        owner = c.execute("SELECT nspowner::regrole::text AS o FROM pg_namespace WHERE nspname = 'consentvault'"
                          ).fetchone()["o"]
        c.execute(psycopg.sql.SQL("SET LOCAL ROLE {}").format(psycopg.sql.Identifier(owner)))
        c.execute((DOWN_0043.parents[1] / MIG).read_text())


def _reapply_0043(env, raw_dsn):
    with env.t.superuser() as su:
        su.execute(DOWN_0043.read_text())
    _apply_0043(raw_dsn)


def _stop_seq(env, eid):
    with env.t.superuser() as su:
        return su.execute("SELECT max(seq) AS s FROM consentvault.event WHERE org_id = %s AND source = 'erasure'"
                          " AND recorded_by LIKE %s", (env.t.a.org_id, f"erasure:{eid}:%")).fetchone()["s"]


def test_the_migration_backfills_a_completed_erasure_from_its_stop_in_the_event_ledger(env, cloud, raw_dsn):
    s, r = cloud.grant(cloud.a, X, **ALL)
    assert s == 201, r
    req = _request(env, env.t.a, X)
    _confirm(env, env.t.a, req["erasure_id"])
    stop = _stop_seq(env, req["erasure_id"])
    assert stop is not None
    _reapply_0043(env, raw_dsn)
    with env.t.superuser() as su:
        got = _covers(su, req["erasure_id"])
    assert got == stop and _verify(env) == []


def test_the_migration_fails_loudly_on_a_completed_erasure_the_ledger_holds_no_stop_for(env, cloud, raw_dsn):
    with env.t.superuser() as su:
        su.execute(DOWN_0043.read_text())
        eid = su.execute("INSERT INTO consentvault.erasure_request (org_id, contact_fp, reason, requested_by)"
                         " VALUES (%s, %s, 'asked', %s) RETURNING erasure_id",
                         (env.t.a.org_id, uuid.uuid4().hex * 2, uuid.uuid4())).fetchone()["erasure_id"]
        su.execute("UPDATE consentvault.erasure_request SET status = 'completed', completed_at = now(),"
                   " confirmed_by = 'op', confirmed_at = now(), ledger_seq = 1 WHERE erasure_id = %s", (eid,))
    with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match=f"no stop in the event ledger.*{eid}"):
        _apply_0043(raw_dsn)
    with env.t.superuser() as su:  # refused whole: nothing of the migration is left behind
        assert su.execute("SELECT to_regclass('consentvault.erasure_coverage') AS t").fetchone()["t"] is None


def test_a_completed_erasure_with_no_sequence_is_a_break_never_judged_by_time(env, cloud):
    s, r = cloud.grant(cloud.a, X, **ALL)
    assert s == 201, r
    req = _request(env, env.t.a, X)
    _confirm(env, env.t.a, req["erasure_id"])
    seqs = _rows(env)
    with env.t.superuser() as su:  # forge the shape the database never writes: completed, no covered sequence
        su.execute("SET session_replication_role = replica")
        su.execute("DELETE FROM consentvault.erasure_coverage WHERE erasure_id = %s", (req["erasure_id"],))
    assert _verify(env) == [("erasure_without_sequence", s) for s in seqs]


# ---- completion needs the key gone; the backfill covers a waited erasure; the cover waits for the ledger lock --------------
def _complete_sql(conn, eid):
    conn.execute("UPDATE consentvault.erasure_request SET status = 'completed', completed_at = now(), confirmed_by = 'op',"
                 " confirmed_at = now(), ledger_seq = 1 WHERE erasure_id = %s", (eid,))


def test_the_console_cannot_complete_a_request_while_the_contact_key_exists(env, cloud):
    from consentvault.tenancy.erasure import operator_org

    s, r = cloud.grant(cloud.a, X, **ALL)
    assert s == 201, r
    req = _request(env, env.t.a, X)
    with env.operator() as c:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="contact key still exists"):
            with operator_org(c, env.t.key, env.t.a.org_id):
                _complete_sql(c, req["erasure_id"])
    with env.t.superuser() as su:  # the probe: a key deleted by hand after a refused completion is still a break
        assert _covers(su, req["erasure_id"]) is None
        su.execute("DELETE FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                   (env.t.a.org_id, env.fp(env.t.a, X)))
    assert {reason for reason, _ in _verify(env)} == {"contact_key_missing"}


def test_the_backfill_covers_a_row_written_while_the_erasure_waited_for_delivery(env, cloud, raw_dsn, monkeypatch):
    s, r = cloud.grant(cloud.a, X, **ALL)
    assert s == 201, r
    req = _request(env, env.t.a, X)
    monkeypatch.setattr(er, "pending_pushes", lambda conn, fp: 1)
    assert _confirm(env, env.t.a, req["erasure_id"])["status"] == "held"  # the stop is written, the key stays
    monkeypatch.undo()
    with env.t.app() as app, org_transaction(app, env.t.token(env.t.a)):  # a row sealed under the key still held
        from consentvault.ledger import record_tenant_event
        late = record_tenant_event(app, env.t.crypto, contact=X, event_type="revoke", channels=["sms"],
                                   purposes=["marketing"], method="keyword", origin="consumer").seq
    assert late > _stop_seq(env, req["erasure_id"])
    assert _confirm(env, env.t.a, req["erasure_id"])["status"] == "completed"
    _reapply_0043(env, raw_dsn)
    with env.t.superuser() as su:
        assert _covers(su, req["erasure_id"]) == late
    assert _verify(env) == []


def test_the_cover_waits_for_a_writer_holding_the_ledger_lock(env, cloud):
    import threading
    import time

    s, r = cloud.grant(cloud.a, X, **ALL)
    assert s == 201, r
    req = _request(env, env.t.a, X)
    with env.t.superuser() as su:
        su.execute("DELETE FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                   (env.t.a.org_id, env.fp(env.t.a, X)))
    from consentvault.ledger import record_tenant_event

    holder = env.t.app()
    tx = org_transaction(holder, env.t.token(env.t.a))
    tx.__enter__()  # an event written and not yet committed: its writer holds the organisation's ledger lock
    pending = record_tenant_event(holder, env.t.crypto, contact="+15555550166", event_type="revoke", channels=["sms"],
                                  purposes=["marketing"], method="keyword", origin="consumer").seq
    errors = []

    def complete():
        from consentvault.tenancy.erasure import operator_org

        try:
            with env.operator() as c, operator_org(c, env.t.key, env.t.a.org_id):
                _complete_sql(c, req["erasure_id"])
        except Exception as exc:  # loud-failure-exempt: re-raised by the assertion below
            errors.append(exc)

    worker = threading.Thread(target=complete)
    worker.start()
    time.sleep(1.0)
    assert worker.is_alive()  # the completion waits on the lock instead of reading a head that is about to move
    tx.__exit__(None, None, None)
    holder.close()
    worker.join(10)
    assert not worker.is_alive() and errors == []
    with env.t.superuser() as su:
        assert _covers(su, req["erasure_id"]) == pending
