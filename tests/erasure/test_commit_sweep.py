"""The hourly commit sweep: it writes the commits that are due, and it alarms and fails when an intent is over an hour old
without one."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from consentvault import cli
from consentvault.tenancy import erasure
from consentvault.tenancy.erasure import LedgerUnavailableError, LifecycleLedger

from isolation.cloud_harness import Cloud

from .support import OPERATOR
from .test_erasure import _confirm, _request
from .test_erasure_job import _env


def now_utc():
    return datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _channels(env, tmp_path):
    """The organisations need their channels for a stop to have anything to stop."""
    c = Cloud(env.t, str(tmp_path / "evidence"))
    yield
    c.close()


class FlakyCommits(LifecycleLedger):
    down = True

    def append(self, org, entry, *, hint=0):
        if self.down and entry["kind"] == "erasure_stop_commit":
            raise LedgerUnavailableError("the archive is down")
        return super().append(org, entry, hint=hint)


def _held_with_ledger_down(env, ledger):
    req = _request(env, env.t.a)
    with pytest.MonkeyPatch.context() as m:
        m.setattr(erasure, "pending_pushes", lambda conn, fp: 1)
        out = _confirm_with(env, req["erasure_id"], ledger)
    assert out["status"] == "held"
    return req["erasure_id"]


def _confirm_with(env, eid, ledger):
    with env.operator() as c:
        return erasure.confirm_erasure(c, token_key=env.t.key, crypto=env.t.crypto, ledger=ledger, operator_id=OPERATOR,
                                       request_id="req-op", org_id=env.t.a.org_id, erasure_id=eid)


def _alarms(env):
    with env.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.operator_alarm WHERE name = %s",
                          (erasure.ALARM_COMMIT_OVERDUE,)).fetchone()["n"]


def test_the_sweep_writes_the_commit_once_the_ledger_is_back_and_raises_no_alarm(env):
    ledger = FlakyCommits(env.archive, clock=env.ledger._clock)
    _held_with_ledger_down(env, ledger)
    ledger.down = False
    with env.operator() as c:
        out = erasure.commit_sweep(c, token_key=env.t.key, ledger=ledger, request_id="r")
    assert out["overdue"] == 0
    assert [e["kind"] for e in env.ledger.entries(env.t.a.org_id)] == ["erasure_stop", "erasure_stop_commit"]
    assert _alarms(env) == 0


def test_an_intent_over_an_hour_old_without_a_commit_alarms_and_the_job_fails(env, monkeypatch, tmp_path, capsys):
    old = FlakyCommits(env.archive, clock=lambda: now_utc() - timedelta(hours=2))
    _held_with_ledger_down(env, old)  # the ledger stays down: the stop entry is two hours old and uncommitted
    with env.operator() as c:
        out = erasure.commit_sweep(c, token_key=env.t.key, ledger=old, request_id="r")
    late = out["orgs"][str(env.t.a.org_id)]["overdue"]
    assert out["overdue"] == 1 and late[0]["kind"] == "erasure_stop"
    assert _alarms(env) == 1


def test_a_young_uncommitted_intent_is_not_overdue_and_a_rolled_back_one_is_not_due(env):
    young = FlakyCommits(env.archive, clock=env.ledger._clock)
    _held_with_ledger_down(env, young)
    with env.operator() as c:
        assert erasure.commit_sweep(c, token_key=env.t.key, ledger=young, request_id="r")["overdue"] == 0
    assert _alarms(env) == 0


def test_the_job_is_registered_runs_hourly_and_exits_3_when_something_is_overdue(env, monkeypatch, tmp_path, capsys):
    from consentvault import jobs

    assert jobs.JOBS["erasure-commit-sweep"] == "erasure-commit-sweep"
    cli.build_parser()
    assert "erasure-commit-sweep" in cli.REGISTRY
    _env(monkeypatch, env, tmp_path)
    assert cli.main(["erasure-commit-sweep"]) == cli.EXIT_OK  # nothing pending
    assert json.loads(capsys.readouterr().out)["overdue"] == 0
    # an erasure intent written two hours ago whose commit never came (the request is still open)
    from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore

    old = LifecycleLedger(LocalAppendOnlyEvidenceStore(str(tmp_path / "archive")),
                          clock=lambda: now_utc() - timedelta(hours=2))
    req = _request(env, env.t.a)
    old.append(env.t.a.org_id, {"kind": "erasure_intent", "contact_fp": env.fp(env.t.a), "erasure_id": req["erasure_id"],
                                "erased_at": now_utc().isoformat()}, hint=0)
    assert cli.main(["erasure-commit-sweep"]) == cli.EXIT_BROKEN
    assert json.loads(capsys.readouterr().out)["overdue"] == 1
    assert _alarms(env) == 1


def test_the_sweep_needs_no_key_custody_and_no_worker_or_runtime_login_can_run_it(env, monkeypatch, tmp_path, capsys):
    """Least privilege: the operator console's grants and nothing else. It never loads a key provider (no KMS role, no
    contact key opened); the worker and runtime logins hold none of the grants and the job fails by name on them."""
    from consentvault.providers import plugins
    from isolation.harness import make_login_role

    cli.build_parser()
    monkeypatch.setattr(plugins, "load_key_provider", lambda *a, **k: pytest.fail("the sweep loaded a key provider"))
    _env(monkeypatch, env, tmp_path)
    assert cli.main(["erasure-commit-sweep"]) == cli.EXIT_OK
    capsys.readouterr()
    port = int(env.t.operator_dsn.split("@")[1].split("/")[0].rsplit(":", 1)[1])
    worker = make_login_role(port, env.t.operator_dsn.rsplit("/", 1)[1], "consentvault_worker")
    for dsn in (worker, env.t.app_dsn):
        monkeypatch.setenv("CONSENTVAULT_OPERATOR_DSN", dsn)
        assert cli.main(["erasure-commit-sweep"]) != cli.EXIT_OK, dsn
        capsys.readouterr()


def _old(env):
    return LifecycleLedger(env.archive, clock=lambda: now_utc() - timedelta(hours=2))


def _overdue(env, ledger):
    with env.operator() as c:
        return erasure.commit_sweep(c, token_key=env.t.key, ledger=ledger, request_id="r")["overdue"]


def test_a_declined_requests_old_intent_is_not_due(env):
    req = _request(env, env.t.a)
    with env.operator() as c:
        erasure.decline_erasure(c, token_key=env.t.key, operator_id=OPERATOR, request_id="d", org_id=env.t.a.org_id,
                                erasure_id=req["erasure_id"], reason="identity unproven")
    old = _old(env)
    old.append(env.t.a.org_id, {"kind": "erasure_intent", "contact_fp": env.fp(env.t.a), "erasure_id": req["erasure_id"],
                                "erased_at": now_utc().isoformat()}, hint=0)
    assert _overdue(env, old) == 0 and _alarms(env) == 0


def test_an_open_requests_old_intent_without_a_commit_is_overdue(env):
    req = _request(env, env.t.a)
    old = _old(env)
    old.append(env.t.a.org_id, {"kind": "erasure_intent", "contact_fp": env.fp(env.t.a), "erasure_id": req["erasure_id"],
                                "erased_at": now_utc().isoformat()}, hint=0)
    assert _overdue(env, old) == 1 and _alarms(env) == 1


def test_a_rolled_back_stop_entry_is_never_due_however_old(env):
    from consentvault.tenancy.erasure import operator_org, record_erasure_stop

    old = _old(env)

    class Rollback(Exception):
        pass

    with env.operator() as c:
        with pytest.raises(Rollback):
            with operator_org(c, env.t.key, env.t.a.org_id):
                record_erasure_stop(c, env.t.crypto, fp=env.fp(env.t.a), erasure_id="44444444-4444-4444-8444-444444444444",
                                    ledger=old)
                raise Rollback()
    assert [e["kind"] for e in env.ledger.entries(env.t.a.org_id)] == ["erasure_stop"]
    assert _overdue(env, old) == 0 and _alarms(env) == 0


def test_an_erasure_is_settled_once_any_commit_exists_so_a_successful_retry_ends_the_alarm(env):
    req = _request(env, env.t.a)
    old, org, fp = _old(env), env.t.a.org_id, env.fp(env.t.a)
    first, _ = old.append(org, {"kind": "erasure_intent", "contact_fp": fp, "erasure_id": req["erasure_id"],
                                "erased_at": now_utc().isoformat()}, hint=0)  # the attempt that failed
    assert _overdue(env, old) == 1
    second, _ = old.append(org, {"kind": "erasure_intent", "contact_fp": fp, "erasure_id": req["erasure_id"],
                                 "erased_at": now_utc().isoformat()}, hint=0)  # the retry
    old.append(org, {"kind": "erasure_commit", "erasure_id": req["erasure_id"], "contact_fp": fp, "intent_seq": second},
               hint=0)
    assert _overdue(env, old) == 0
