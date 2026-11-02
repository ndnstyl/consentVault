"""Clock skew: a worker whose own clock is 11 minutes ahead of or behind the database decides exactly as one in step. Every
Twenty window and due test (the rejected-key window, the bad-signature window, the webhook freshness window, the reconcile's
due test) is decided on the database's clock. The process clock is moved alone here: the database keeps real time."""

import time
from datetime import datetime, timedelta, timezone

import pytest

from consentvault import cmd_twenty, db
from consentvault.tenancy.tokens import org_transaction
from consentvault.sync.connectors.twenty_reconcile import due

from .support import TwentyEnv, signed
from .test_connector import PHONE, PHONE2, stop, tw_env  # noqa: F401
from .test_job import _drop, _login

SKEWS = [timedelta(minutes=11), timedelta(minutes=-11), timedelta(0)]
IDS = ["worker 11 minutes ahead", "worker 11 minutes behind", "worker in step"]


def _skew(env, by: timedelta) -> None:
    env.clock.on_advance = None          # the process clock only; the database keeps real time
    env.clock.offset = by


@pytest.mark.parametrize("by", SKEWS, ids=IDS)
def test_two_rejected_keys_in_ten_minutes_flag_the_system_whatever_the_worker_clock(env, tw_env, by):
    _skew(env, by)
    tw_env.twenty.api_key = "rotated"
    stop(env, PHONE)
    stop(env, PHONE2)
    tw_env.drain(rounds=2)
    state = env.q("SELECT connector_state FROM consentvault.connected_system WHERE system_id = %s",
                  [tw_env.sys.system_id])[0]["connector_state"]
    assert state == "needs_attention:key_rejected"


@pytest.mark.parametrize("by", SKEWS, ids=IDS)
def test_five_bad_signatures_in_ten_minutes_flag_the_webhook_whatever_the_worker_clock(env, tw_env, by):
    _skew(env, by)
    raw = tw_env.twenty.event("person.updated", "x")
    real = datetime.now(timezone.utc)
    for _ in range(5):
        tw_env.receiver.handle(tw_env.sys.receiver_id, {**signed(raw, at=real), "X-Twenty-Webhook-Signature": "1" * 64}, raw)
    state = env.q("SELECT connector_state FROM consentvault.connected_system WHERE system_id = %s",
                  [tw_env.sys.system_id])[0]["connector_state"]
    assert state == "needs_attention:webhook_failing"


@pytest.mark.parametrize("by", SKEWS, ids=IDS)
def test_a_fresh_webhook_is_accepted_and_a_stale_one_refused_whatever_the_worker_clock(env, tw_env, by):
    """Twenty stamps its webhook with the real time; the 5-minute window is judged on the database's clock."""
    _skew(env, by)
    pid = tw_env.twenty.add(phone=PHONE)
    raw = tw_env.twenty.event("person.updated", pid)
    real = datetime.now(timezone.utc)
    assert tw_env.receiver.handle(tw_env.sys.receiver_id, signed(raw, at=real), raw)[0] == 202
    stale = tw_env.twenty.event("person.updated", pid)
    assert tw_env.receiver.handle(tw_env.sys.receiver_id, signed(stale, at=real - timedelta(minutes=6)), stale)[0] == 401


@pytest.mark.parametrize("by", SKEWS, ids=IDS)
def test_the_reconcile_runs_only_the_systems_due_on_the_databases_clock(env, pg_server, by):
    """Two systems on a 15-minute interval: one last ran 10 minutes ago (not due), one 20 minutes ago (due); both had their
    full scan an hour ago. A worker 11 minutes off in either direction runs exactly the second."""
    _skew(env, by)
    fresh, stale = TwentyEnv(env, env.t.a), TwentyEnv(env, env.t.b)
    for t, minutes in ((fresh, 10), (stale, 20)):
        env.q("INSERT INTO consentvault.connector_reconcile (org_id, system_id, last_run_at, last_full_scan_at)"
              " VALUES (%s, %s, clock_timestamp() - make_interval(mins => %s), clock_timestamp() - interval '1 hour')"
              " ON CONFLICT (org_id, system_id) DO UPDATE SET last_run_at = EXCLUDED.last_run_at,"
              " last_full_scan_at = EXCLUDED.last_full_scan_at", [t.org.org_id, t.sys.system_id, minutes])
        env.q("UPDATE consentvault.connected_system SET status = 'active', reconcile_requested_at = NULL WHERE system_id = %s",
              [t.sys.system_id])
    dsn = _login(pg_server["port"], env.dbname, "consentvault_worker")
    cap = _login(pg_server["port"], env.dbname, "consentvault_app")
    try:
        ran = []
        real_run = fresh.reconciler.run

        def watch(app, capture, worker, token, org_id, system_id, *, full):
            ran.append(str(system_id))
            return real_run(app, capture, worker, token, org_id, system_id, full=full)
        fresh.reconciler.run = watch
        with db.connect(dsn) as c:
            out = cmd_twenty.run_pass(c, lambda: db.connect(cap), fresh.reconciler, env.t.key)
        assert ran == [str(stale.sys.system_id)] and out["systems"] == 1
    finally:
        _drop(pg_server["port"], dsn)
        _drop(pg_server["port"], cap)


def test_the_due_test_is_the_databases_answer():
    row = {"reconcile_due": True, "full_scan_due": False}
    assert due(row) == (True, False)


def _bad_signature_state(env, tw_env, marks_minutes_ago: float, marks: int) -> str:
    """Hits already on the books ``marks_minutes_ago`` back, then one real bad signature; the system's state afterwards."""
    for _ in range(marks):
        env.q("INSERT INTO consentvault.connector_window_mark (org_id, system_id, name, at)"
              " VALUES (%s, %s, 'sigbad', clock_timestamp() - make_interval(secs => %s))",
              [tw_env.org.org_id, tw_env.sys.system_id, marks_minutes_ago * 60])
    raw = tw_env.twenty.event("person.updated", "x")
    real = datetime.now(timezone.utc)
    tw_env.receiver.handle(tw_env.sys.receiver_id, {**signed(raw, at=real), "X-Twenty-Webhook-Signature": "1" * 64}, raw)
    return env.q("SELECT connector_state FROM consentvault.connected_system WHERE system_id = %s",
                 [tw_env.sys.system_id])[0]["connector_state"]


def test_the_ten_minute_alarm_is_a_rolling_window_not_a_fixed_slot(env, tw_env):
    """Four hits 9.5 minutes ago and one now fall inside one rolling ten minutes whichever fixed slot edge lies between them."""
    assert _bad_signature_state(env, tw_env, 9.5, 4) == "needs_attention:webhook_failing"


def test_a_hit_older_than_ten_minutes_is_not_counted(env, tw_env):
    assert _bad_signature_state(env, tw_env, 10.5, 4) != "needs_attention:webhook_failing"


def _marks(env, tw_env) -> int:
    return env.q("SELECT count(*) AS n FROM consentvault.connector_window_mark WHERE system_id = %s", [tw_env.sys.system_id])[0]["n"]


def test_a_flood_of_bad_signatures_stops_writing_rows_at_the_alarm_count(env, tw_env):
    raw = tw_env.twenty.event("person.updated", "x")
    real = datetime.now(timezone.utc)
    for _ in range(12):
        tw_env.receiver.handle(tw_env.sys.receiver_id, {**signed(raw, at=real), "X-Twenty-Webhook-Signature": "1" * 64}, raw)
    assert _marks(env, tw_env) == 5


def test_a_disconnect_deletes_the_systems_window_counts(env, tw_env):
    _bad_signature_state(env, tw_env, 1, 2)
    assert _marks(env, tw_env) >= 2
    tok = env.t.token(env.t.a, scopes=("admin",))
    with env.t.app() as app, org_transaction(app, tok):
        app.execute("SELECT * FROM consentvault.sync_twenty_disconnect(%s, 'moving CRM')", (tw_env.sys.system_id,))
    assert _marks(env, tw_env) == 0


def test_two_simultaneous_hits_both_count_each_other(env, tw_env):
    """Two rejected keys at once, alarm count 2: the second hit waits for the first and reads its row, so one of them sees 2."""
    import threading
    tok = env.t.token(env.t.a, scopes=("admin",))
    first_in, results = threading.Event(), []

    def hit(hold: bool) -> None:
        with env.t.app() as app, org_transaction(app, tok):
            if not hold:
                first_in.wait(10)
            n = app.execute("SELECT consentvault.connector_window_hit(%s, 'key_rejected', 600, 2) AS n",
                            (tw_env.sys.system_id,)).fetchone()["n"]
            results.append(n)
            if hold:
                first_in.set()
                time.sleep(1.5)        # the first transaction stays open while the second arrives
    a, b = threading.Thread(target=hit, args=(True,)), threading.Thread(target=hit, args=(False,))
    a.start(); b.start(); a.join(30); b.join(30)
    assert sorted(results) == [1, 2], results
