"""The restore drill against a real backup: the vault is dumped with pg_dump (the backup), work continues on the original (an
erasure confirmed and committed to the lifecycle ledger), and the drill restores the dump into a scratch database, proves
the copy (the gate closed during the restore, the ledger replayed so the erasure survives, every chain and seal
re-verified, every committed erasure covered), times it against the target, removes the copy and records the drill.

A drill that finds anything (a broken chain, an erasure the copy does not cover, a restore over its target, a copy that
could not be removed) records ``failed`` and raises; the record names checks, organisation ids and counts only."""

from error_names import named, named_any  # noqa: F401
import io
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest

from consentvault import cmd_restore_drill, db, metrics, restore_drill as rd
from consentvault.tenancy import erasure, restore

from isolation.harness import PHONE, make_login_role

from .support import OPERATOR
from .test_attacks_wave3_lifecycle import drop_synthetic_seals


def _pg(tool):
    return str(Path(os.environ["PG_BIN"]) / tool) if os.environ.get("PG_BIN") else tool


def _dump(t, folder: Path, stamp: str = "20261031T120000Z") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    out = folder / f"consentvault-{stamp}.dump"
    subprocess.run([_pg("pg_dump"), "--format=custom", "--file", str(out), t.super_dsn], check=True, capture_output=True,
                   timeout=120)
    return out


def _admin(t):
    return t.super_dsn.rsplit("/", 1)[0] + "/postgres"


def _scratch_dbs(t):
    with psycopg.connect(_admin(t)) as su:
        return [r[0] for r in su.execute("SELECT datname FROM pg_database WHERE datname LIKE 'cv_restore_drill_%'")]


@pytest.fixture
def drill(env, tmp_path, pg_server):
    t = env.t
    drop_synthetic_seals(t)  # the harness's fake seals would rightly fail the copy's seal re-check
    dbname = t.operator_dsn.rsplit("/", 1)[1]
    env.drill_dsn = make_login_role(pg_server["port"], dbname, "consentvault_restore_drill")
    env.backups = tmp_path / "backups"
    env.evidence = tmp_path / "evidence"
    env.evidence.mkdir()
    return env


def _target(env, **kw):
    return rd.PgDumpTarget(backup_dir=env.backups, admin_dsn=_admin(env.t), console_dsn=env.t.operator_dsn,
                           pg_restore=_pg("pg_restore"), **kw)


def _run(env, target=None, **kw):
    kw.setdefault("target_seconds", 3600)
    return rd.run_drill(target or _target(env), record_connect=lambda: db.connect(env.drill_dsn), token_key=env.t.key,
                        crypto_for=lambda connect: env.t.crypto, store=env.archive, ledger=env.ledger,
                        inventory=restore.local_inventory(env.evidence), request_id="req-drill", **kw)


def _records(env):
    with db.connect(env.drill_dsn) as c:
        return c.execute("SELECT * FROM consentvault.restore_drill_runs(10)").fetchall()


def _erase_after_the_backup(env):
    t = env.t
    with env.admin(t.a) as ctx:
        eid = erasure.request_erasure(ctx, {"contact": PHONE, "reason": "asked"}, crypto=t.crypto)["erasure_id"]
    with env.operator() as c:
        erasure.confirm_erasure(c, token_key=t.key, crypto=t.crypto, ledger=env.ledger, operator_id=OPERATOR,
                                request_id="req-e", org_id=t.a.org_id, erasure_id=eid)
    assert not env.key_present(t.a)
    return eid


def test_a_drill_restores_the_newest_backup_proves_it_and_records_the_time(drill):
    _dump(drill.t, drill.backups, "20261001T000000Z")
    _dump(drill.t, drill.backups, "20261031T120000Z")  # the newest one is restored
    eid = _erase_after_the_backup(drill)
    rec = _run(drill)
    assert rec["outcome"] == "passed" and rec["report"]["findings"] == []
    assert rec["backup_ref"] == "consentvault-20261031T120000Z.dump"
    assert rec["backup_taken_at"] == datetime(2026, 10, 31, 12, tzinfo=timezone.utc).isoformat()
    assert rec["orgs"] >= 2 and 0 <= rec["seconds"] < 3600
    a = rec["report"]["orgs"][str(drill.t.a.org_id)]
    assert a["erasures_replayed"] == 1 and a["keys_deleted"] == 1  # the erasure survived the restore
    assert _scratch_dbs(drill.t) == []  # the copy is gone
    [row] = _records(drill)
    assert row["outcome"] == "passed" and str(row["drill_id"]) == rec["drill_id"] and row["target_seconds"] == 3600
    assert float(row["seconds"]) == pytest.approx(rec["seconds"], abs=0.01)
    assert row["recorded_by"] == drill.drill_dsn.split("//", 1)[1].split("@", 1)[0]
    assert PHONE not in json.dumps(row["report"]) and str(eid) not in json.dumps(row["report"])


def test_a_broken_chain_in_the_backup_fails_the_drill_by_organisation(drill):
    with psycopg.connect(drill.t.super_dsn, autocommit=True) as su:
        su.execute("SET session_replication_role = replica")
        su.execute("UPDATE consentvault.event SET method = 'keyword' WHERE org_id = %s AND seq = 1", (drill.t.b.org_id,))
    _dump(drill.t, drill.backups)
    with pytest.raises(rd.DrillFailed) as e:
        _run(drill)
    rec = e.value.record
    assert rec["outcome"] == "failed"
    assert {(f["check"], f.get("org_id")) for f in rec["report"]["findings"]} >= {("reconcile", str(drill.t.b.org_id))}
    assert any(f["key"].startswith("chain:event") for f in rec["report"]["findings"] if f["check"] == "reconcile")
    assert _scratch_dbs(drill.t) == [] and _records(drill)[0]["outcome"] == "failed"


def test_an_erasure_the_copy_does_not_cover_is_caught_by_the_independent_check(drill, monkeypatch):
    _dump(drill.t, drill.backups)
    _erase_after_the_backup(drill)
    monkeypatch.setattr(restore, "_replay_erasure", lambda *a, **kw: None)  # a reconcile that forgets the erasure
    with pytest.raises(rd.DrillFailed) as e:
        _run(drill)
    [f] = e.value.record["report"]["findings"]
    assert (f["check"], f["org_id"], f["count"]) == ("erasure_not_covered", str(drill.t.a.org_id), 1)


def test_a_drill_over_its_target_fails(drill):
    _dump(drill.t, drill.backups)
    ticks = iter([0.0, 7200.0])
    with pytest.raises(rd.DrillFailed) as e:
        _run(drill, target_seconds=3600, clock=lambda: next(ticks))
    assert e.value.record["report"]["findings"] == [{"check": "over_target", "seconds": 7200.0, "target_seconds": 3600}]


def test_no_backup_is_a_failed_drill_and_is_recorded(drill):
    drill.backups.mkdir()
    with pytest.raises(rd.DrillFailed) as e:
        _run(drill)
    [f] = e.value.record["report"]["findings"]
    assert (f["check"], f["reason"]) == ("restore_failed", "DrillError")  # the class only: error text never travels
    assert _records(drill)[0]["backup_ref"] == "none"


class _Leaky:
    """A target whose copy cannot be removed."""

    def __init__(self, inner):
        self.inner = inner
        self.stale_removed = inner.stale_removed

    def restore_latest(self):
        return self.inner.restore_latest()

    def discard(self):
        self.inner.discard()
        raise rd.DrillError("the scratch instance is still deleting after the deadline")


def test_a_copy_that_cannot_be_removed_fails_the_drill(drill):
    _dump(drill.t, drill.backups)
    with pytest.raises(rd.DrillFailed) as e:
        _run(drill, target=_Leaky(_target(drill)))
    assert [f["check"] for f in e.value.record["report"]["findings"]] == ["scratch_not_removed"]


def test_the_wrong_production_login_is_refused_before_anything_is_restored(drill):
    calls = []

    class Spy:
        def restore_latest(self):
            calls.append("restore")

        def discard(self):
            calls.append("discard")
    with pytest.raises(rd.DrillLoginRefused):
        rd.run_drill(Spy(), record_connect=drill.t.operator, token_key=drill.t.key, crypto_for=lambda c: drill.t.crypto,
                     store=drill.archive, ledger=drill.ledger, inventory=lambda o, s: [], request_id="r")
    assert calls == []


def test_the_drill_record_is_append_only_and_the_drill_login_reads_nothing_else(drill):
    _dump(drill.t, drill.backups)
    _run(drill)
    with db.connect(drill.drill_dsn) as c:
        for forbidden in ("UPDATE consentvault.restore_drill_run SET outcome = 'passed'",
                          "SELECT * FROM consentvault.restore_drill_run", "SELECT * FROM consentvault.event",
                          "SELECT consentvault.isolation_canary_pair()"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute(forbidden)
    with psycopg.connect(drill.t.super_dsn, autocommit=True) as su:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            su.execute("DELETE FROM consentvault.restore_drill_run")
    with drill.operator() as c:  # the operator console reads the records
        assert len(c.execute("SELECT * FROM consentvault.restore_drill_runs(5)").fetchall()) == 1


def test_the_target_setting_is_checked():
    assert rd.target_seconds_from({}) == rd.DEFAULT_TARGET_SECONDS == 14400
    assert rd.target_seconds_from({rd.ENV_TARGET_SECONDS: "7200"}) == 7200
    for bad in ("0", "59", "x", "604801"):
        with pytest.raises(rd.DrillError):
            rd.target_seconds_from({rd.ENV_TARGET_SECONDS: bad})


def test_a_backup_name_without_its_time_is_not_a_backup(tmp_path):
    (tmp_path / "vault.dump").write_bytes(b"x")
    t = rd.PgDumpTarget(backup_dir=tmp_path, admin_dsn="postgresql://x@h/postgres", console_dsn="postgresql://y@h/v",
                        pg_restore="/bin/false")
    with pytest.raises(rd.DrillError):
        t.latest()


# ---- the command --------------------------------------------------------------------------------------------------------------
def _cli(monkeypatch, outcome):
    out = io.StringIO()
    real = metrics.emit
    monkeypatch.setattr(metrics, "emit", lambda name, value, stream=None: real(name, value, stream=out))
    monkeypatch.setattr(cmd_restore_drill, "_run_job", lambda cfg, env: outcome())
    return cmd_restore_drill.run_command(None, None), out.getvalue()


def test_the_command_exits_0_on_a_pass_and_3_on_a_failure_or_the_wrong_login(monkeypatch, capsys):
    rc, emitted = _cli(monkeypatch, lambda: {"outcome": "passed", "seconds": 12.5})
    assert rc == 0 and emitted == "" and json.loads(capsys.readouterr().out)["outcome"] == "passed"

    def failed():
        raise rd.DrillFailed("the restore drill failed with 1 finding(s): over_target", {"outcome": "failed"})
    rc, _ = _cli(monkeypatch, failed)
    printed = capsys.readouterr()
    assert rc == 3 and named("DrillFailed", printed.err) and "over_target" not in printed.err
    assert json.loads(printed.out)["outcome"] == "failed"  # the failed record is still printed for the operator

    def refused():
        raise rd.DrillLoginRefused("login x is not a member of consentvault_restore_drill")
    rc, _ = _cli(monkeypatch, refused)
    err = capsys.readouterr().err
    assert rc == 3 and named("DrillLoginRefused", err) and "consentvault_restore_drill" not in err


def test_the_cloud_copy_is_reached_as_a_master_that_grants_itself_the_console_role_on_the_copy(drill, pg_server):
    """A managed database's master holds an admin-only grant on the roles it made; on the copy the drill grants it the
    console role and acts as it, so the reconcile runs with the console's grants and nothing more."""
    import uuid as _uuid

    who = "t_master_" + _uuid.uuid4().hex[:8]
    with psycopg.connect(_admin(drill.t), autocommit=True) as su:
        su.execute(f'CREATE ROLE "{who}" LOGIN')
        su.execute(f'GRANT consentvault_console TO "{who}" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE')
    try:
        dsn = drill.t.operator_dsn.split("//", 1)[0] + f"//{who}@" + drill.t.operator_dsn.split("@", 1)[1]
        restored = rd.Restored(rd.Backup("snap", datetime.now(timezone.utc)), dsn, set_role="consentvault_console",
                               grant_role=True)
        with rd.scratch_connector(restored)() as c:
            assert c.execute("SELECT current_user AS u").fetchone()["u"] == "consentvault_console"
            assert c.execute("SELECT count(*) AS n FROM consentvault.restore_run").fetchone()["n"] == 0
    finally:
        with psycopg.connect(_admin(drill.t), autocommit=True) as su:
            su.execute(f'DROP OWNED BY "{who}" CASCADE')
            su.execute(f'DROP ROLE "{who}"')


def test_the_admin_password_reaches_pg_restore_through_its_environment_never_its_command_line(tmp_path):
    t = rd.PgDumpTarget(backup_dir=tmp_path, admin_dsn="postgresql://drill:s3cret@db.internal:5433/postgres?sslmode=verify-full",
                        console_dsn="postgresql://console@db.internal:5433/vault", pg_restore="/bin/false")
    env = t._libpq_env()
    assert (env["PGHOST"], env["PGPORT"], env["PGUSER"], env["PGPASSWORD"], env["PGSSLMODE"]) == (
        "db.internal", "5433", "drill", "s3cret", "verify-full")
    odd = rd.PgDumpTarget(backup_dir=tmp_path, admin_dsn="postgresql://drill@h/postgres?options=-csearch_path%3Dx",
                          console_dsn="postgresql://c@h/v", pg_restore="/bin/false")
    with pytest.raises(rd.DrillError, match="options"):
        odd._libpq_env()


# ---- review round two: the copy is the drill's alone, stale copies go first, no error text, no privileged login ---------------
class _Probe:
    """Wraps the real target; right after the copy is restored, tries it as the runtime login."""

    def __init__(self, inner, app_dsn):
        self.inner, self.app_dsn, self.app_error = inner, app_dsn, None

    @property
    def stale_removed(self):
        return self.inner.stale_removed

    def restore_latest(self):
        restored = self.inner.restore_latest()
        copy = restored.dsn.rsplit("/", 1)[1]
        try:
            psycopg.connect(self.app_dsn.rsplit("/", 1)[0] + "/" + copy).close()
        except psycopg.OperationalError as exc:
            self.app_error = str(exc)
        return restored

    def discard(self):
        self.inner.discard()


def test_only_the_drill_reaches_the_copy_the_runtime_login_is_refused(drill):
    _dump(drill.t, drill.backups)
    probe = _Probe(_target(drill), drill.t.app_dsn)
    assert _run(drill, target=probe)["outcome"] == "passed"  # the console login the drill acts as still connects
    assert probe.app_error is not None and "permission denied for database" in probe.app_error


def test_a_copy_left_by_a_killed_drill_is_removed_first_and_named(drill, capsys):
    _dump(drill.t, drill.backups)
    with psycopg.connect(_admin(drill.t), autocommit=True) as su:
        su.execute('CREATE DATABASE "cv_restore_drill_dead00000001"')
    rec = _run(drill)
    assert rec["report"]["stale_copies_removed"] == ["cv_restore_drill_dead00000001"]
    assert _scratch_dbs(drill.t) == [] and "cv_restore_drill_dead00000001" in capsys.readouterr().err
    assert _records(drill)[0]["report"]["stale_copies_removed"] == ["cv_restore_drill_dead00000001"]


EMAIL = "jane.doe@example.com"


class _Raises:
    stale_removed: list = []

    def __init__(self, exc):
        self.exc = exc

    def restore_latest(self):
        raise self.exc

    def discard(self):
        raise self.exc


@pytest.mark.parametrize("exc", [rd.DrillError(f"pg_restore exited 1: DETAIL: Key (email)=({EMAIL}) already exists"),
                                 psycopg.errors.UniqueViolation(f"duplicate key; DETAIL: Key (email)=({EMAIL}) exists")])
def test_error_text_never_reaches_the_record_or_the_log(drill, capsys, exc):
    with pytest.raises(rd.DrillFailed) as e:
        _run(drill, target=_Raises(exc))
    reasons = [f["reason"] for f in e.value.record["report"]["findings"]]
    assert reasons and all(EMAIL not in r for r in reasons) and type(exc).__name__ in reasons[0]
    if isinstance(exc, psycopg.Error):
        assert "SQLSTATE 23505" in reasons[0]
    out = capsys.readouterr()
    assert EMAIL not in str(e.value) and EMAIL not in out.err + out.out
    assert EMAIL not in json.dumps(_records(drill)[0]["report"])


def test_a_reconcile_cause_carrying_error_text_is_cut_to_its_name(drill, monkeypatch):
    _dump(drill.t, drill.backups)

    def failing(conn, **kw):
        raise restore.RestoreIncompleteError("x", {"orgs": {str(drill.t.a.org_id): {
            "failed_checks": [{"key": f"ledger:7 {EMAIL}", "cause": f"erasure_stop_not_replayable: {EMAIL}"}]}}})
    monkeypatch.setattr(restore, "reconcile", failing)
    with pytest.raises(rd.DrillFailed) as e:
        _run(drill)
    [f] = e.value.record["report"]["findings"]
    assert (f["key"], f["cause"]) == ("unnamed", "erasure_stop_not_replayable")
    assert EMAIL not in json.dumps(e.value.record)


def test_a_superuser_or_bypassrls_production_login_is_refused(drill, pg_server):
    for connect in (drill.t.superuser,):
        with pytest.raises(rd.DrillLoginRefused, match="superuser or bypasses row security"):
            rd.run_drill(_Raises(rd.DrillError("unused")), record_connect=connect, token_key=drill.t.key,
                         crypto_for=lambda c: drill.t.crypto, store=drill.archive, ledger=drill.ledger,
                         inventory=lambda o, s: [], request_id="r")
    role = drill.drill_dsn.split("//", 1)[1].split("@", 1)[0]
    with psycopg.connect(_admin(drill.t), autocommit=True) as su:
        su.execute(f'ALTER ROLE "{role}" BYPASSRLS')
    try:
        with pytest.raises(rd.DrillLoginRefused, match="bypasses row security"):
            _run(drill)
    finally:  # roles are cluster-wide: never leave a BYPASSRLS login behind for later tests
        with psycopg.connect(_admin(drill.t), autocommit=True) as su:
            su.execute(f'ALTER ROLE "{role}" NOBYPASSRLS')


class _Nested:
    """Drill A's target: right after A's copy exists, a second drill runs from start to finish."""

    def __init__(self, inner, second):
        self.inner, self.second, self.second_record, self.copy_seen = inner, second, None, None

    @property
    def stale_removed(self):
        return self.inner.stale_removed

    def restore_latest(self):
        restored = self.inner.restore_latest()
        self.copy_seen = restored.dsn.rsplit("/", 1)[1]
        self.second_record = self.second()
        return restored

    def discard(self):
        self.inner.discard()


def test_two_concurrent_drills_leave_each_others_copy_alone(drill):
    _dump(drill.t, drill.backups)
    b_target = _target(drill)
    a = _Nested(_target(drill), lambda: _run(drill, target=b_target))
    rec_a = _run(drill, target=a)  # A's copy must survive B's start, B's own copy and B's clean-up
    assert rec_a["outcome"] == "passed" and a.second_record["outcome"] == "passed"
    assert b_target.live_skipped == [a.copy_seen] and a.second_record["report"]["stale_copies_removed"] == []
    assert rec_a["report"]["stale_copies_removed"] == [] and _scratch_dbs(drill.t) == []
    assert [r["outcome"] for r in _records(drill)] == ["passed", "passed"]


def test_a_killed_drills_copy_is_stale_once_its_session_is_gone(drill):
    _dump(drill.t, drill.backups)
    dead = _target(drill)
    dead.restore_latest()  # its session holds the lock ...
    name = dead._db
    dead._release()        # ... until the process dies (no discard ran)
    rec = _run(drill)
    assert rec["report"]["stale_copies_removed"] == [name] and _scratch_dbs(drill.t) == []
