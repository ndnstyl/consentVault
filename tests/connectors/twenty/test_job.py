"""The twenty-reconcile job (twenty.md 3.5): its own login, refused by name otherwise; a pass reconciles every due system."""

import uuid

import psycopg
import pytest

from consentvault import cmd_twenty, db, jobs

from .support import TwentyEnv


def _login(port, dbname, *groups) -> str:
    role = "t_" + uuid.uuid4().hex[:10]
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True) as su:
        su.execute(f'CREATE ROLE "{role}" LOGIN IN ROLE {", ".join(groups)}')
    return f"postgresql://{role}@127.0.0.1:{port}/{dbname}"


def _drop(port, dsn):
    role = dsn.split("//", 1)[1].split("@", 1)[0]
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True) as su:
        su.execute(f'DROP ROLE "{role}"')


@pytest.mark.parametrize("main,capture", [("consentvault_app", "consentvault_app"),
                                          ("consentvault_worker", "consentvault_worker")])
def test_a_login_that_is_not_the_jobs_own_is_refused_by_name(env, pg_server, main, capture):
    """The job's own login is a worker-group login; the stops it finds are recorded under a runtime-group login."""
    m, c = _login(pg_server["port"], env.dbname, main), _login(pg_server["port"], env.dbname, capture)
    try:
        with db.connect(m) as mc, db.connect(c) as cc, pytest.raises(cmd_twenty.WrongLoginError):
            cmd_twenty.require_job_logins(mc, cc)
    finally:
        _drop(pg_server["port"], m)
        _drop(pg_server["port"], c)


def test_the_capture_login_is_the_jobs_dsn_with_its_user_swapped():
    assert cmd_twenty.with_user("rds-iam://consentvault_twenty_login@db.example.test:5432/cv?x=1", "consentvault_runtime") == \
        "rds-iam://consentvault_runtime@db.example.test:5432/cv?x=1"
    assert cmd_twenty.with_user("postgresql://a@h/d", "b") == "postgresql://b@h/d"
    with pytest.raises(cmd_twenty.WrongLoginError):
        cmd_twenty.with_user("postgresql://h/d", "b")


def test_a_pass_under_the_jobs_login_reconciles_a_due_system_and_records_a_missed_stop(env, pg_server):
    tw = TwentyEnv(env, env.t.a)
    tw.twenty.add(phone="+15555552001", flag=True)          # no webhook ever arrived
    dsn = _login(pg_server["port"], env.dbname, "consentvault_worker")
    cap = _login(pg_server["port"], env.dbname, "consentvault_app")
    try:
        with db.connect(dsn) as c, db.connect(cap) as cc:
            cmd_twenty.require_job_logins(c, cc)
        with db.connect(dsn) as c:
            out = cmd_twenty.run_pass(c, lambda: db.connect(cap), tw.reconciler, env.t.key)
        assert out["failed"] == [] and out["systems"] >= 1 and out["stops_found"] >= 1
        assert tw.gate("+15555552001") == "denied"
    finally:
        _drop(pg_server["port"], dsn)
        _drop(pg_server["port"], cap)


def test_a_failing_system_is_named_and_fails_the_pass(env, pg_server):
    tw = TwentyEnv(env, env.t.a)
    tw.twenty.script("GET", 500)
    dsn = _login(pg_server["port"], env.dbname, "consentvault_worker")
    cap = _login(pg_server["port"], env.dbname, "consentvault_app")
    try:
        with db.connect(dsn) as c:
            out = cmd_twenty.run_pass(c, lambda: db.connect(cap), tw.reconciler, env.t.key)
        assert len(out["failed"]) == 1 and out["failed"][0]["system_id"] == str(tw.sys.system_id)
    finally:
        _drop(pg_server["port"], dsn)
        _drop(pg_server["port"], cap)


def test_the_job_is_registered_with_a_heartbeat_and_its_metrics():
    from consentvault import metrics

    assert jobs.JOBS["twenty-reconcile"] == "twenty-reconcile"
    assert "twenty-reconcile" in jobs.HEARTBEAT_JOBS
    assert {"TwentyReconcileFailures", "TwentyHiddenStops"} <= set(metrics.METRICS)



def test_a_failed_system_is_named_by_type_and_ids_only(env, pg_server):
    """The allowlist logging rule: the pass's output names the error type, the organisation and the system, never a message."""
    tw = TwentyEnv(env, env.t.a)

    class Leaky:
        def run(self, *a, **k):
            raise RuntimeError("contact ann@example.com at https://crm.example.test")
    dsn = _login(pg_server["port"], env.dbname, "consentvault_worker")
    cap = _login(pg_server["port"], env.dbname, "consentvault_app")
    try:
        with db.connect(dsn) as c:
            out = cmd_twenty.run_pass(c, lambda: db.connect(cap), Leaky(), env.t.key)
        assert out["failed"] == [{"org_id": str(env.t.a.org_id), "system_id": str(tw.sys.system_id), "error": "RuntimeError"}]
    finally:
        _drop(pg_server["port"], dsn)
        _drop(pg_server["port"], cap)
