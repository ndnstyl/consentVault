"""Two runs of the sender can never take the same queued email, whatever their timing. Both tests use real connections and no
sleeping: the first holds one claim open while another claims; the second makes the second claim's snapshot older than the first
claim's commit, the one case that skipping locked rows does not cover and the recheck of status and attempts does."""

import threading
import time
import uuid

import pytest

from consentvault import db
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import make_login_role

from .support import SHARED, record_stop

PHONE = "+15555550177"
CLAIM = "SELECT * FROM consentvault.stop_notice_claim(500, 5, 0, 300, '{}'::uuid[])"


@pytest.fixture
def solo(vault, pg_server):
    vault.app._crypto = SHARED
    org, boss = vault.org_with_admin("Solo", "boss@solo.example")
    record_stop(vault, org["org_id"], PHONE)
    dsn = make_login_role(pg_server["port"], vault.super_dsn.rsplit("/", 1)[1], "consentvault_worker")
    return uuid.UUID(org["org_id"]), dsn


def _token(conn, org_id):
    return conn.execute("SELECT consentvault.dispatch_org_token('sync', %s) AS t", (org_id,)).fetchone()["t"]


def _attempts(vault, org_id):
    with vault.superuser() as su:
        return [(r["status"], r["attempts"]) for r in su.execute(
            "SELECT status, attempts FROM consentvault.stop_notice_mail WHERE org_id = %s", (org_id,)).fetchall()]


def test_a_claim_held_open_by_one_connection_gives_a_second_connection_nothing(vault, solo):
    org_id, dsn = solo
    a, b = db.connect(dsn), db.connect(dsn)
    try:
        hold = org_transaction(a, _token(a, org_id))
        hold.__enter__()
        first = a.execute(CLAIM).fetchall()
        assert len(first) == 1 and first[0]["attempts"] == 1
        with org_transaction(b, _token(b, org_id)):
            assert b.execute(CLAIM).fetchall() == []  # A has not committed; B must not take the row
        hold.__exit__(None, None, None)
        with org_transaction(b, _token(b, org_id)):
            assert b.execute(CLAIM).fetchall() == []  # A has committed: the row is in flight, not queued
    finally:
        a.close()
        b.close()
    assert _attempts(vault, str(org_id)) == [("sending", 1)]


def test_a_claim_committed_between_another_runs_snapshot_and_its_lock_is_refused(vault, solo):
    org_id, dsn = solo
    key = 424242
    with vault.superuser() as su:  # a gate on the queue table: reading a row waits for advisory lock 424242, after the snapshot
        su.execute("CREATE FUNCTION public.stop_notice_test_gate() RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN"
                   f" PERFORM pg_advisory_lock_shared({key}); PERFORM pg_advisory_unlock_shared({key}); RETURN true; END $$")
        su.execute("GRANT EXECUTE ON FUNCTION public.stop_notice_test_gate() TO PUBLIC")
        su.execute("CREATE POLICY stop_notice_test_gate ON consentvault.stop_notice_mail AS RESTRICTIVE USING (public.stop_notice_test_gate())")
    a, b = db.connect(dsn), db.connect(dsn)
    blocker = db.connect(vault.super_dsn)
    result: dict = {}
    try:
        hold = org_transaction(a, _token(a, org_id))
        hold.__enter__()
        assert len(a.execute(CLAIM).fetchall()) == 1  # A has claimed and not yet committed
        blocker.execute(f"SELECT pg_advisory_lock({key})")  # from here a reader of the queue table waits

        def second_claim():
            with org_transaction(b, _token(b, org_id)):
                result["rows"] = b.execute(CLAIM).fetchall()

        t = threading.Thread(target=second_claim)
        t.start()
        deadline = time.monotonic() + 30
        while True:  # B has taken its snapshot (A's claim uncommitted, so the row reads as queued) and is waiting at the gate
            waiting = blocker.execute("SELECT count(*) AS n FROM pg_locks WHERE locktype = 'advisory' AND NOT granted").fetchone()["n"]
            if waiting:
                break
            assert time.monotonic() < deadline, "the second claim never reached the gate"
            time.sleep(0.05)
        hold.__exit__(None, None, None)  # A commits: the row is now 'sending', attempts 1
        blocker.execute(f"SELECT pg_advisory_unlock({key})")
        t.join(30)
        assert not t.is_alive()
    finally:
        a.close()
        b.close()
        blocker.close()
    assert result["rows"] == []  # B re-checks the newer row version and refuses it
    assert _attempts(vault, str(org_id)) == [("sending", 1)]


def test_a_recipient_another_run_holds_is_skipped_so_the_pass_reaches_the_others(vault, pg_server):
    vault.app._crypto = SHARED
    org, boss = vault.org_with_admin("Duo", "boss@duo.example")
    vault.add_member(boss, "two@duo.example", "admin")
    record_stop(vault, org["org_id"], PHONE)
    org_id = uuid.UUID(org["org_id"])
    dsn = make_login_role(pg_server["port"], vault.super_dsn.rsplit("/", 1)[1], "consentvault_worker")
    a, b = db.connect(dsn), db.connect(dsn)
    try:
        hold = org_transaction(a, _token(a, org_id))
        hold.__enter__()
        first = a.execute(CLAIM).fetchall()
        with org_transaction(b, _token(b, org_id)):
            second = b.execute(CLAIM).fetchall()  # the oldest recipient is held by A: B takes the other one, not nothing
        hold.__exit__(None, None, None)
    finally:
        a.close()
        b.close()
    assert len(first) == 1 and len(second) == 1 and first[0]["address"] != second[0]["address"]
