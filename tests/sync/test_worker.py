"""The worker: ordering, supersede, retry with backoff, poison, dead, redrive, idempotency, loud failure."""

import json
import time
import uuid
from datetime import timedelta

import psycopg
import pytest

from consentvault.sync.connectors import webhook
from consentvault.sync.connectors.webhook import TransportResult
from consentvault.sync.errors import TransportError, WorkerError
from consentvault.sync.worker import WorkerConfig
from consentvault.tenancy.errors import KeyProviderError
from consentvault.tenancy.tokens import org_transaction

from .support import PHONES, of

P1, P2, P3 = PHONES[0], PHONES[1], PHONES[2]


def _claim(env, org, limit=50, lease=60):
    with env.worker_conn() as w:
        token = env.dispatch(w, org)
        with org_transaction(w, token):   # the database's clock decides what is due
            return w.execute("SELECT * FROM consentvault.sync_claim(%s, %s)", (limit, lease)).fetchall()


def _complete(env, org, row, outcome="acknowledged", status=200, cls=None, backoff=None):
    with env.worker_conn() as w:
        token = env.dispatch(w, org)
        with org_transaction(w, token):   # a retry passes its step; the database decides the time
            return w.execute("SELECT consentvault.sync_complete(%s, %s, %s, %s, %s, NULL, %s) AS f",
                             (row["outbox_id"], row["attempt"], outcome, status, cls, backoff)).fetchone()["f"]


def test_a_push_is_signed_acknowledged_and_idempotent(env):
    a = env.t.a
    hm = env.add_system(a, "crm", signature="hmac")
    ed = env.add_system(a, "dialer", signature="ed25519", contact_form="fingerprint")
    env.grant(a, P1)
    report = env.run_worker()
    assert report.ok and of(report, a).acknowledged == 2 and env.transport.default.http_status == 200
    for system in (hm, ed):
        (req,) = env.transport.to(system.endpoint)
        assert webhook.verify_signature(system.signature, system.verify_key, req.body, req.headers[webhook.HEADER_SIGNATURE])
        assert not webhook.verify_signature(system.signature, system.verify_key, req.body + b" ", req.headers[webhook.HEADER_SIGNATURE])
        body = json.loads(req.body)
        assert body["version"] == 1 and body["state"] == "permitted"
        assert body["contact"] == (P1 if system is hm else env.fp(a, P1))
        row = env.outbox(a, system_id=system.system_id)[0]
        assert req.headers[webhook.HEADER_DELIVERY] == str(row["outbox_id"])
        assert req.headers[webhook.HEADER_IDEMPOTENCY] == webhook.idempotency_key(a.org_id, row["contact_fp"], "sms", "marketing", 1)
    assert {r["status"] for r in env.outbox(a)} == {"acknowledged"}
    deliveries = env.q("SELECT status, attempt, http_status FROM consentvault.delivery WHERE org_id = %s", (a.org_id,))
    assert [(d["status"], d["attempt"], d["http_status"]) for d in deliveries] == [("acknowledged", 1, 200)] * 2
    env.run_worker()
    assert len(env.transport.sent) == 2  # nothing is sent twice


def test_the_same_idempotency_key_rides_every_retry(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 503, 503, 200)
    env.grant(a, P1)
    env.run_worker()
    env.clock.advance(seconds=31)
    env.run_worker()
    env.clock.advance(seconds=61)
    env.run_worker()
    keys = {r.headers[webhook.HEADER_IDEMPOTENCY] for r in env.transport.sent}
    assert len(env.transport.sent) == 3 and len(keys) == 1
    assert env.outbox(a)[0]["attempts"] == 3 and env.outbox(a)[0]["status"] == "acknowledged"


def test_retry_with_exponential_backoff(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 503, 500, 502, 200)
    env.grant(a, P1)
    rep = env.run_worker()
    row = env.outbox(a)[0]
    assert of(rep, a).retried == 1 and row["status"] == "failed" and row["last_error_class"] == "http_5xx"
    assert row["last_http_status"] == 503 and row["attempts"] == 1
    first_wait = (row["next_attempt_at"] - row["last_attempt_at"]).total_seconds()
    assert first_wait == pytest.approx(30, abs=0.01)
    env.run_worker()
    assert len(env.transport.sent) == 1  # not due yet
    env.clock.advance(seconds=31)
    env.run_worker()
    row = env.outbox(a)[0]
    assert (row["next_attempt_at"] - row["last_attempt_at"]).total_seconds() == pytest.approx(60, abs=0.01)
    env.clock.advance(seconds=61)
    env.run_worker()
    row = env.outbox(a)[0]
    assert (row["next_attempt_at"] - row["last_attempt_at"]).total_seconds() == pytest.approx(120, abs=0.01)
    env.clock.advance(seconds=121)
    env.run_worker()
    assert env.outbox(a)[0]["status"] == "acknowledged" and len(env.transport.sent) == 4
    assert [d["status"] for d in env.q("SELECT status FROM consentvault.delivery ORDER BY attempt")] == \
        ["failed", "failed", "failed", "acknowledged"]


def test_backoff_never_exceeds_its_cap():
    cfg = WorkerConfig(backoff_base_seconds=30, backoff_cap_seconds=3600)
    assert [cfg.backoff(n).total_seconds() for n in (1, 2, 3, 8, 20)] == [30, 60, 120, 3600, 3600]


@pytest.mark.parametrize("script,state,cls", [
    (TransportResult("timeout"), "failed", "timeout"),
    (TransportResult("unreachable", None, "no route"), "failed", "unreachable"),
    (408, "failed", "http_4xx"),
    (429, "failed", "http_4xx"),
])
def test_transient_failures_retry(env, script, state, cls):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, script)
    env.grant(a, P1)
    env.run_worker()
    row = env.outbox(a)[0]
    assert (row["status"], row["last_error_class"]) == (state, cls)


@pytest.mark.parametrize("script,cls", [(400, "http_4xx"), (404, "http_4xx"), (410, "http_4xx"), (301, "http_4xx"),
                                        (401, "signature_rejected"), (403, "signature_rejected"),
                                        (TransportResult("refused", None, "target_address_refused"), "unreachable")])
def test_a_poison_message_is_dead_at_once(env, script, cls):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, script)
    env.grant(a, P1)
    rep = env.run_worker()
    row = env.outbox(a)[0]
    assert (row["status"], row["last_error_class"], row["attempts"]) == ("dead", cls, 1)
    assert of(rep, a).dead == 1
    env.clock.advance(hours=3)
    env.run_worker()
    assert len(env.transport.sent) == 1  # a poison message is never retried


def test_the_retry_window_ends_in_dead(env):
    a = env.t.a
    s = env.add_system(a, "crm", retry_window_hours=1)
    env.transport.default = TransportResult("response", 503)
    env.grant(a, P1)
    env.run_worker()
    for _ in range(10):
        env.clock.advance(minutes=20)
        env.run_worker()
        if env.outbox(a)[0]["status"] == "dead":
            break
    row = env.outbox(a)[0]
    assert row["status"] == "dead" and row["last_error_class"] == "http_5xx"
    assert env.clock() >= row["window_start"] + timedelta(hours=1)
    last = env.q("SELECT status FROM consentvault.delivery WHERE outbox_id = %s ORDER BY attempt DESC LIMIT 1", (row["outbox_id"],))
    assert last[0]["status"] == "dead"
    assert s.system_id == row["system_id"]


def test_the_receivers_message_is_stored_only_as_a_ciphertext(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, TransportResult("response", 400, f"unknown number {P1}"))
    env.grant(a, P1)
    env.run_worker()
    d = env.q("SELECT error_ct FROM consentvault.delivery WHERE org_id = %s", (a.org_id,))[0]
    assert d["error_ct"] is not None and P1.encode() not in bytes(d["error_ct"])


def test_a_newer_push_waits_for_the_older_one_in_flight(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    first = _claim(env, a)
    assert [r["version"] for r in first] == [1]
    env.stop(a, P1)
    assert _claim(env, a) == []  # a second worker finds version 2 blocked behind version 1
    assert _complete(env, a, first[0]) == "acknowledged"
    second = _claim(env, a)
    assert [r["version"] for r in second] == [2]


def test_two_workers_never_hold_two_versions_of_one_key(env):
    a = env.t.a
    env.add_system(a, "crm")
    for _ in range(4):
        env.grant(a, P1)
        env.stop(a, P1)
    seen = []
    for _ in range(3):
        rows = _claim(env, a)
        seen += [(r["system_id"], r["contact_fp"], r["version"]) for r in rows]
        assert len({(r["system_id"], r["contact_fp"], r["channel"], r["purpose"]) for r in rows}) == len(rows)
    assert len(seen) == 1  # only the newest live version is ever in flight for the key


def test_one_dead_system_never_delays_another(env):
    a = env.t.a
    bad = env.add_system(a, "crm")
    good = env.add_system(a, "dialer")
    env.transport.script(bad.endpoint, 400)
    env.grant(a, P1)
    env.stop(a, P1)
    rep = env.run_worker()
    assert of(rep, a).dead == 1 and len(env.transport.to(good.endpoint)) == 1
    states = {r["system_id"]: [(x["version"], x["status"]) for x in env.outbox(a, system_id=r["system_id"])] for r in env.outbox(a)}
    assert states[good.system_id] == [(1, "superseded"), (2, "acknowledged")]


def test_a_failed_older_push_is_superseded_not_retried_when_a_newer_state_exists(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.grant(a, P1)
    rows = _claim(env, a)  # version 1 in flight
    env.stop(a, P1)  # version 2 queued behind it
    assert _complete(env, a, rows[0], outcome="retry", status=503, cls="http_5xx", backoff=30) == "superseded"
    env.run_worker()
    sent = env.transport.to(s.endpoint)
    assert [json.loads(r.body)["version"] for r in sent] == [2]


def test_a_dead_worker_loses_its_lease_and_the_push_is_taken_over(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.grant(a, P1)
    held = _claim(env, a, lease=60)
    assert len(held) == 1 and _claim(env, a, lease=60) == []
    env.clock.advance(seconds=61)
    env.run_worker()
    row = env.outbox(a)[0]
    assert row["status"] == "acknowledged" and row["attempts"] == 2
    attempts = env.q("SELECT attempt, status FROM consentvault.delivery ORDER BY attempt")
    assert [(d["attempt"], d["status"]) for d in attempts] == [(1, "failed"), (2, "acknowledged")]
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="not the open attempt"):
        _complete(env, a, held[0])  # the slow worker finishing late is refused
    assert len(env.transport.to(s.endpoint)) == 1


def test_a_paused_system_gets_nothing_until_resumed_and_then_only_the_newest_state(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.q("UPDATE consentvault.connected_system SET status = 'paused' WHERE system_id = %s", (s.system_id,))
    env.grant(a, P1)
    env.stop(a, P1)
    env.run_worker()
    assert env.transport.sent == []
    env.q("UPDATE consentvault.connected_system SET status = 'active' WHERE system_id = %s", (s.system_id,))
    env.run_worker()
    assert [json.loads(r.body)["state"] for r in env.transport.sent] == ["denied"]


def test_a_person_whose_key_was_erased_has_nothing_left_to_push(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    env.q("DELETE FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s", (a.org_id, env.fp(a, P1)))
    rep = env.run_worker()
    assert env.transport.sent == [] and rep.ok
    assert env.outbox(a)[0]["status"] == "superseded"


# loud failure: our side failing is named and never counted against the receiver -----------------------------------------

def test_a_door_failure_releases_the_attempt_and_raises_loudly(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    env.grant(a, P2)
    env.transport.raises = TransportError("the egress door answered 401 'unauthorized'")
    with pytest.raises(WorkerError, match="delivery door failure") as info:
        env.run_worker()
    assert not info.value.report.ok
    rows = env.outbox(a)
    assert {r["status"] for r in rows} == {"pending"} and {r["attempts"] for r in rows} == {0}
    assert env.q("SELECT 1 FROM consentvault.delivery WHERE org_id = %s", (a.org_id,)) == []
    env.transport.raises = None
    env.clock.advance(seconds=61)
    assert of(env.run_worker(), a).acknowledged == 2


def test_a_key_service_failure_is_named_and_counted_as_an_attempt(env):
    # second-wave review: a preparation failure is an attempt (backoff, dead at the window's end, alarmed), never an
    # endless silent release
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    original = env.t.provider.unwrap_data_key

    def down(org_id, wrapped):
        raise KeyProviderError("the key service is unreachable")

    env.t.provider.unwrap_data_key = down
    try:
        with pytest.raises(WorkerError, match="could not be prepared"):
            env.run_worker()
    finally:
        env.t.provider.unwrap_data_key = original
    row = env.outbox(a)[0]
    assert (row["status"], row["attempts"], row["last_error_class"]) == ("failed", 1, "prepare_failed")
    assert env.transport.sent == []


def test_a_preparation_failure_goes_dead_when_the_window_ends_and_leaves_an_alarm_row(env):
    a = env.t.a
    s = env.add_system(a, "crm", retry_window_hours=1)
    env.q("UPDATE consentvault.connected_system SET credentials_ct = '\\x00'::bytea WHERE system_id = %s", (s.system_id,))
    env.grant(a, P1)
    for _ in range(12):  # backoff retries until the one-hour window ends
        env.ageing(a)
        _run_quiet(env)
        env.clock.advance(minutes=10)
        if env.outbox(a)[0]["status"] == "dead":
            break
    row = env.outbox(a)[0]
    assert (row["status"], row["last_error_class"]) == ("dead", "prepare_failed") and row["attempts"] > 1
    alarms = env.q("SELECT name, ref_kind, ref_id, error_class FROM consentvault.operator_alarm WHERE org_id = %s",
                   (a.org_id,))
    assert alarms == [{"name": "sync.dead", "ref_kind": "system", "ref_id": s.system_id, "error_class": "prepare_failed"}]
    assert env.transport.sent == []


def _run_quiet(env):
    with env.worker_conn() as w:
        return env.make_worker().run_once(w, raise_on_error=False)


def test_one_organisations_failure_does_not_hide_another(env):
    a, b = env.t.a, env.t.b
    env.add_system(a, "crm")
    env.add_system(b, "crm")
    env.grant(a, P1)
    env.grant(b, P1)
    original = env.t.provider.unwrap_data_key

    def flaky(org_id, wrapped):
        if org_id == a.org_id:
            raise KeyProviderError("alpha's key is unavailable")
        return original(org_id, wrapped)

    env.t.provider.unwrap_data_key = flaky
    try:
        with pytest.raises(WorkerError) as info:
            env.run_worker()
    finally:
        env.t.provider.unwrap_data_key = original
    rep = info.value.report
    by_org = {o.org_id: o for o in rep.orgs}
    assert by_org[b.org_id].acknowledged == 1 and by_org[a.org_id].errors


def test_a_missing_credential_is_a_named_error(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.q("UPDATE consentvault.connected_system SET credentials_ct = '\\x00'::bytea WHERE system_id = %s", (s.system_id,))
    env.grant(a, P1)
    with pytest.raises(WorkerError, match=r"CredentialError \(code credential_unopenable\)"):  # the cause, by class and code
        env.run_worker()
    assert env.outbox(a)[0]["status"] == "failed"  # counted as an attempt (second-wave review)


# alarms ------------------------------------------------------------------------------------------------------------------

def test_dead_pushes_raise_one_alarm_per_system_and_class(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 400, 400, 400)
    for p in (P1, P2, P3):
        env.grant(a, p)
    env.run_worker()
    assert len(env.alarms.alarms) == 1
    alarm = env.alarms.alarms[0]
    assert (alarm.count, alarm.error_class, alarm.system_name, alarm.org_id) == (3, "http_4xx", "crm", a.org_id)
    assert P1 not in alarm.message() and "Fix the system" in alarm.message()
    env.run_worker()
    assert len(env.alarms.alarms) == 1  # a dead push alarms once


def test_two_failure_classes_on_one_system_are_two_alarms(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 400, 401)
    env.grant(a, P1)
    env.grant(a, P2)
    env.run_worker()
    assert sorted(x.error_class for x in env.alarms.alarms) == ["http_4xx", "signature_rejected"]


def test_an_alarm_that_could_not_be_raised_is_raised_again_on_the_next_run(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 400)
    env.alarms.fail = True
    env.grant(a, P1)
    with pytest.raises(WorkerError, match="could not be raised"):
        env.run_worker()
    assert env.alarms.alarms == [] and env.outbox(a)[0]["alarmed_at"] is None
    env.alarms.fail = False
    env.run_worker()
    assert len(env.alarms.alarms) == 1 and env.outbox(a)[0]["alarmed_at"] is not None


# redrive -----------------------------------------------------------------------------------------------------------------

def _redrive(env, org, system, reason="fixed the endpoint", scope="admin"):
    with env.t.app() as app, org_transaction(app, env.t.token(org, scopes=(scope,))):
        return app.execute("SELECT * FROM consentvault.sync_redrive_start(%s, %s, 'tester')", (system.system_id, reason)).fetchone()


def _status(env, org, rid):
    with env.t.app() as app, org_transaction(app, env.t.token(org, scopes=("admin",))):
        return app.execute("SELECT * FROM consentvault.sync_redrive_status(%s)", (rid,)).fetchone()


def test_redrive_requeues_dead_pushes_and_reports_progress(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 400, 400)
    env.grant(a, P1)
    env.grant(a, P2)
    env.run_worker()
    assert {r["status"] for r in env.outbox(a)} == {"dead"}
    env.clock.advance(hours=30)  # the old window is long over
    run = _redrive(env, a, s)
    assert run["requeued"] == 2
    st = _status(env, a, run["redrive_id"])
    assert (st["status"], st["requeued"], st["remaining"], st["acknowledged"]) == ("running", 2, 2, 0)
    rows = env.outbox(a)
    assert {r["status"] for r in rows} == {"pending"} and all(r["alarmed_at"] is None for r in rows)
    rep = env.run_worker()
    assert of(rep, a).acknowledged == 2
    st = _status(env, a, run["redrive_id"])
    assert (st["status"], st["acknowledged"], st["dead_again"], st["remaining"]) == ("done", 2, 0, 0) and st["finished_at"]


def test_a_redriven_push_gets_a_fresh_retry_window(env):
    a = env.t.a
    s = env.add_system(a, "crm", retry_window_hours=1)
    env.transport.script(s.endpoint, 400)
    env.grant(a, P1)
    env.run_worker()
    # the first window ended long ago (five hours, on the database's clock, which stamps push starts)
    env.q("UPDATE consentvault.outbox SET window_start = window_start - interval '5 hours' WHERE org_id = %s", (a.org_id,))
    before = env.outbox(a)[0]["window_start"]
    _redrive(env, a, s)
    assert env.outbox(a)[0]["window_start"] > before
    env.transport.script(s.endpoint, 503)
    env.run_worker()
    assert env.outbox(a)[0]["status"] == "failed"  # not dead at once: the window restarted at the redrive


def test_redrive_sends_only_the_latest_dead_state_of_a_key(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 400)
    env.grant(a, P1)
    env.run_worker()
    env.stop(a, P1)  # a newer state queues behind the dead one (dead is terminal)
    env.transport.script(s.endpoint, 400)
    env.run_worker()
    assert [(r["version"], r["status"]) for r in env.outbox(a)] == [(1, "dead"), (2, "dead")]
    run = _redrive(env, a, s)
    assert run["requeued"] == 1
    assert [(r["version"], r["status"]) for r in env.outbox(a)] == [(1, "superseded"), (2, "pending")]
    env.run_worker()
    assert [json.loads(r.body)["state"] for r in env.transport.sent][-1] == "denied"


def test_redrive_with_nothing_dead_is_a_valid_empty_run(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    run = _redrive(env, a, s)
    assert run["requeued"] == 0
    st = _status(env, a, run["redrive_id"])
    assert st["status"] == "done" and st["finished_at"] is not None


def test_only_one_redrive_runs_per_system(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 400)
    env.grant(a, P1)
    env.run_worker()
    _redrive(env, a, s)
    with pytest.raises(psycopg.errors.UniqueViolation, match="redrive_run_one_running_idx"):
        _redrive(env, a, s)
    env.run_worker()  # the first one finishes ...
    again = _redrive(env, a, s)  # ... and the system can be redriven again
    assert again["requeued"] == 0


def test_a_redriven_push_that_dies_again_is_counted_and_alarms_again(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 400, 400)
    env.grant(a, P1)
    env.run_worker()
    run = _redrive(env, a, s)
    env.run_worker()
    st = _status(env, a, run["redrive_id"])
    assert (st["status"], st["dead_again"], st["acknowledged"]) == ("done", 1, 0)
    assert len(env.alarms.alarms) == 2


def test_redrive_needs_a_reason(env):
    a = env.t.a
    s = env.add_system(a, "crm")
    with pytest.raises(psycopg.errors.InvalidParameterValue, match="needs a reason"):
        _redrive(env, a, s, reason="   ")


# the loop and the clock -------------------------------------------------------------------------------------------------

def test_the_loop_runs_until_stopped_and_logs_a_failed_pass(env, caplog):
    import threading
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    stop = threading.Event()
    calls = {"n": 0}

    def connect():
        calls["n"] += 1
        if calls["n"] == 1:
            raise WorkerError("the database is down")
        if calls["n"] == 3:
            stop.set()
        return env.worker_conn()

    worker = env.make_worker()
    with caplog.at_level("ERROR", logger="consentvault.sync"):
        worker.run_loop(connect, stop, interval_seconds=0)
    # the failure is logged loudly by its class; the exception's own text is free text and never reaches a log line (safelog)
    assert any(r.levelname == "ERROR" and "error=WorkerError" in r.getMessage() for r in caplog.records)
    assert "the database is down" not in caplog.text
    assert env.outbox(a)[0]["status"] == "acknowledged"


def test_concurrent_workers_never_double_claim_and_never_skip_ahead(env):
    import threading
    a = env.t.a
    env.add_system(a, "crm")
    people = PHONES[:12]
    for p in people:
        env.grant(a, p)
    first = _claim(env, a, limit=6)  # six people have version 1 in flight
    assert len(first) == 6
    in_flight = {r["contact_fp"] for r in first}
    for p in people:
        if env.fp(a, p) in in_flight:
            env.stop(a, p)  # their version 2 is queued behind the one in flight
    claimed, errors, barrier = [], [], threading.Barrier(4)

    def work():
        try:
            with env.worker_conn() as w:
                token = env.dispatch(w, a)
                barrier.wait(timeout=30)
                for _ in range(3):
                    with org_transaction(w, token):
                        claimed.extend(w.execute("SELECT * FROM consentvault.sync_claim(2, 60)").fetchall())
        except Exception as exc:  # reported through the list so the main thread asserts it
            errors.append(repr(exc))

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
        assert not t.is_alive(), "a claiming thread hung"
    assert errors == []
    ids = [r["outbox_id"] for r in claimed]
    assert len(ids) == len(set(ids)) == 6  # the six people who had nothing in flight, each claimed exactly once
    assert all(r["version"] == 1 for r in claimed) and not ({r["contact_fp"] for r in claimed} & in_flight)


# ---- second-wave review: one slow organisation never holds another's stops -----------------------------------------
def _iat(token: str) -> int:
    import json as _json
    return _json.loads(bytes.fromhex(token.split(".")[2]))["iat"]


def test_a_slow_receiver_for_org_a_never_holds_back_org_bs_stops(env):
    import time as _time
    from consentvault.sync.worker import SyncWorker
    from .support import PHONES

    a, b = env.t.a, env.t.b
    slow = env.add_system(a, "crm")
    fast = env.add_system(b, "crm")
    for phone in PHONES[:30]:
        env.stop(a, phone)
    env.stop(b, P1)
    real_send = env.transport.send

    def send(request):  # org A's receiver takes 20 s an answer
        if request.target_url == slow.endpoint:
            env.clock.advance(seconds=20)
        return real_send(request)
    env.transport.send = send

    seen: list[tuple] = []

    class Spy(SyncWorker):
        def run_org(self, conn, org_id, token, report=None):
            seen.append((org_id, _iat(token)))
            out = super().run_org(conn, org_id, token, report)
            if org_id == a.org_id:
                _time.sleep(1.1)  # real time passes after A's drain: B's token must be minted after it
            return out

    with env.worker_conn() as w:
        report = Spy(env.t.crypto, env.custody, env.transport, env.alarms, config=env.config,
                     clock=env.clock).run_once(w, raise_on_error=False)
    assert len(env.transport.to(fast.endpoint)) == 1  # B's stop went out in this very run
    a_report = of(report, a)
    assert 0 < a_report.acknowledged < 30 and any("deadline" in e for e in a_report.errors)  # A was cut off
    if [o for o, _ in seen].index(a.org_id) < [o for o, _ in seen].index(b.org_id):
        assert dict(seen)[b.org_id] >= dict(seen)[a.org_id] + 1  # minted just before B's drain, not at run start


def test_the_starting_org_rotates_and_pushes_per_org_are_capped(env):
    from consentvault.sync.worker import WorkerConfig
    from .support import PHONES

    a, b = env.t.a, env.t.b
    env.add_system(a, "crm")
    env.add_system(b, "crm")
    for phone in PHONES[:10]:
        env.stop(a, phone)
    firsts = []
    for _ in range(3):
        with env.worker_conn() as w:
            worker = env.make_worker(max_pushes_per_org=4)
            worker._runs = len(firsts)
            r = worker.run_once(w, raise_on_error=False)
        firsts.append(r.orgs[0].org_id)
        assert of(r, a).acknowledged <= 4 and (of(r, a).capped or of(r, a).acknowledged < 4)
    assert len(set(firsts)) > 1  # a different organisation went first
    with pytest.raises(WorkerError, match="lease_seconds"):
        WorkerConfig(batch_size=50, lease_seconds=60)


# ---- wave 2 hardening, item (c): organisations drain in parallel on a bounded pool ----------------------------------
def _parallel(env, **config):
    worker = env.make_worker(**config)
    with env.worker_conn() as w:
        return worker.run_once(w, raise_on_error=False, connect=env.worker_conn)


def test_a_slow_receiver_holds_one_thread_and_another_org_goes_out_in_the_same_moment(env):
    import threading
    import time as _time
    a, b = env.t.a, env.t.b
    slow = env.add_system(a, "crm")
    fast = env.add_system(b, "crm")
    for phone in PHONES[:3]:
        env.stop(a, phone)
    env.stop(b, P1)
    b_sent, real_send = threading.Event(), env.transport.send

    def send(request):
        if request.target_url == slow.endpoint:
            assert b_sent.wait(20), "org B's stop did not go out while org A's receiver was stuck: the drain is serial"
        elif request.target_url == fast.endpoint:
            b_sent.set()
        return real_send(request)
    env.transport.send = send
    t0 = _time.monotonic()
    report = _parallel(env, max_parallel_orgs=2)
    assert _time.monotonic() - t0 < 15
    assert len(env.transport.to(fast.endpoint)) == 1 and len(env.transport.to(slow.endpoint)) == 3
    assert (of(report, a).acknowledged, of(report, b).acknowledged) == (3, 1) and report.ok


def test_the_parallel_drain_keeps_each_orgs_cap_and_matches_the_serial_counts(env):
    a, b = env.t.a, env.t.b
    env.add_system(a, "crm")
    env.add_system(b, "crm")
    for phone in PHONES[:10]:
        env.stop(a, phone)
    for phone in PHONES[:3]:
        env.stop(b, phone)
    report = _parallel(env, max_parallel_orgs=4, max_pushes_per_org=4)
    assert of(report, a).acknowledged == 4 and of(report, a).capped
    assert of(report, b).acknowledged == 3 and not of(report, b).capped and report.ok
    again = _parallel(env, max_parallel_orgs=4, max_pushes_per_org=4)  # the next run continues where the cap stopped
    assert of(again, a).acknowledged == 4


def test_the_parallel_drain_keeps_the_per_org_deadline(env):
    a, b = env.t.a, env.t.b
    slow = env.add_system(a, "crm")
    env.add_system(b, "crm")
    for phone in PHONES[:30]:
        env.stop(a, phone)
    env.stop(b, P1)
    real_send = env.transport.send

    def send(request):
        if request.target_url == slow.endpoint:
            env.clock.advance(seconds=20)
        return real_send(request)
    env.transport.send = send
    report = _parallel(env, max_parallel_orgs=2)
    assert 0 < of(report, a).acknowledged < 30 and any("deadline" in e for e in of(report, a).errors)
    assert of(report, b).acknowledged == 1


def test_a_pool_thread_that_cannot_connect_is_a_named_run_error_not_a_skip(env):
    env.add_system(env.t.a, "crm")
    env.add_system(env.t.b, "crm")
    env.stop(env.t.a, P1)
    env.stop(env.t.b, P1)

    def no_connect():
        raise psycopg.OperationalError("the database is gone")
    worker = env.make_worker(max_parallel_orgs=2)
    with env.worker_conn() as w:
        with pytest.raises(WorkerError, match="could not open its connection") as e:
            worker.run_once(w, connect=no_connect)
    assert all("no pool thread could run it" in " ".join(o.errors) for o in e.value.report.orgs)


def test_the_pool_size_is_bounded():
    for bad in (0, 65):
        with pytest.raises(WorkerError, match="max_parallel_orgs"):
            WorkerConfig(max_parallel_orgs=bad)


def test_the_backoff_counts_from_the_attempt_however_long_the_push_takes(env):
    """The wait between attempts is exactly the backoff from the attempt the claim stamped, even when the push itself takes
    five seconds (once measured from the clock read after the push, the push's own time leaked into the delay)."""
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 503)
    real_send = env.transport.send

    def slow_send(request):
        env.clock.advance(seconds=5)  # the push takes five seconds by the injected clock
        return real_send(request)
    env.transport.send = slow_send
    env.grant(a, P1)
    env.run_worker()
    row = env.outbox(a)[0]
    assert row["status"] == "failed" and (row["next_attempt_at"] - row["last_attempt_at"]).total_seconds() == 30


def test_each_push_in_a_batch_is_stamped_when_it_starts_and_waits_exactly_the_backoff_from_there(env):
    """Two pushes claimed together; the first takes 0.3 seconds. The second is stamped (on the database's clock) when its own push
    starts (at least 0.3 seconds after the first), so its delay is exactly the backoff, not short by the first push's time."""
    a = env.t.a
    s = env.add_system(a, "crm")
    env.transport.script(s.endpoint, 503, 503)
    real_send, seen = env.transport.send, []

    def first_is_slow(request):
        if not seen:
            time.sleep(0.3)
        seen.append(1)
        return real_send(request)
    env.transport.send = first_is_slow
    env.grant(a, P1)
    env.grant(a, P2)
    env.run_worker()
    rows = sorted(env.outbox(a), key=lambda r: r["last_attempt_at"])
    assert [r["status"] for r in rows] == ["failed", "failed"] and len(seen) == 2
    assert [(r["next_attempt_at"] - r["last_attempt_at"]).total_seconds() for r in rows] == [30, 30]
    assert (rows[1]["last_attempt_at"] - rows[0]["last_attempt_at"]).total_seconds() >= 0.3


def test_a_row_another_worker_took_before_its_push_started_is_counted_stale_not_a_failed_run(env):
    """Worker one claims a row; before its push starts its lease runs out and worker two claims and delivers it. Worker one's
    push-start stamp is refused by the database (the attempt is no longer open): that row is counted stale and the run goes on."""
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, P1)
    first = env.make_worker()
    real_deliver, second = first._deliver, []

    def taken_before_the_push(conn, token, org_id, row, report):
        env.clock.advance(seconds=env.config.lease_seconds + 1)  # worker one's lease runs out
        second.append(env.run_worker())  # worker two claims the row and delivers it
        return real_deliver(conn, token, org_id, row, report)
    first._deliver = taken_before_the_push
    with env.worker_conn() as w:
        rep = first.run_once(w)
    assert of(rep, a).stale == 1 and of(second[0], a).acknowledged == 1
    assert len(env.transport.sent) == 1 and env.outbox(a)[0]["status"] == "acknowledged"
