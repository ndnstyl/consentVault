"""The scheduled key-lifecycle job: once a day, as the key-lifecycle login (a member of the operator console group), it
starts a rotation for every organisation whose active key version has reached its rotation age, runs every open rotation
to the end through the existing rotation job, and then reads the key census of every organisation again.

Two findings fail the run (exit 3, no heartbeat) and are counted in their own metric for the alarm: an active key still
past its rotation age after the run (``KeysPastRotationAge``), and anything still wrapped under a version that is no
longer active (``KeysOnOldVersion``). A clean run writes both as zeros. The findings name organisation ids and version
numbers only, never a contact point."""

from error_names import named, named_any  # noqa: F401
import io
import json
import uuid

import psycopg
import pytest

from consentvault import cmd_key_lifecycle, db, key_lifecycle as kl, metrics
from consentvault.providers.errors import KeyProviderError as CustodyKeyError
from consentvault.tenancy import key_rotation as kr

from isolation.harness import make_login_role

from .test_key_rotation import PHONES, Rot

DAY = 86400


@pytest.fixture
def rot(env):
    return Rot(env)


def _age(rot, org, days):
    """Make the organisation's active key version ``days`` old, out of band (as if it had been in service that long)."""
    with psycopg.connect(rot.t.super_dsn, autocommit=True) as su:
        su.execute("SET session_replication_role = replica")
        su.execute("UPDATE consentvault.org_key SET created_at = now() - make_interval(days => %s)"
                   " WHERE org_id = %s AND status = 'active'", (days, org))


def _run(rot, **kw):
    kw.setdefault("rotation_days", 365)
    return kl.run(rot.env.operator, token_key=rot.t.key, custody=rot.env.custody, crypto=rot.crypto,
                  ledger=rot.env.ledger, request_id="req-kl", **kw)


def test_a_key_past_its_rotation_age_is_rotated_and_the_census_reads_clean(rot):
    _age(rot, rot.c, 400)
    _age(rot, rot.d, 100)
    out = _run(rot)
    assert out["started"] == [str(rot.c)]
    assert out["past_rotation_age"] == [] and out["on_old_version"] == [] and out["failures"] == []
    assert rot.versions(rot.c) == [2] * len(PHONES) and rot.versions(rot.d) == [1] * len(PHONES)
    assert rot.env.custody.active_version(str(rot.c)) == 2 and rot.env.custody.active_version(str(rot.d)) == 1
    [row] = rot.sql("SELECT status, reason, started_by FROM consentvault.key_rotation WHERE org_id = %s", rot.c)
    assert row["status"] == "complete" and row["started_by"] == kl.OPERATOR_ID
    assert row["reason"].startswith("scheduled: version 1 is 400 days old")
    assert kl.counts(out) == {"KeysPastRotationAge": 0, "KeysOnOldVersion": 0}
    assert _run(rot)["started"] == []  # the next day: the new version is young, nothing starts twice


def test_an_org_that_cannot_be_rotated_stays_past_its_age_and_fails_the_run_by_id(rot, monkeypatch):
    _age(rot, rot.c, 400)

    def refuse(org_id):
        raise CustodyKeyError("the key service is unavailable")
    monkeypatch.setattr(rot.env.custody, "rotate_org_key", refuse)
    with pytest.raises(kl.KeyLifecycleError) as e:
        _run(rot)
    rep = e.value.report
    assert [r["org_id"] for r in rep["past_rotation_age"]] == [str(rot.c)]
    assert rep["past_rotation_age"][0]["version"] == 1 and rep["past_rotation_age"][0]["age_days"] >= 400
    assert [f["org_id"] for f in rep["failures"]] == [str(rot.c)] and "key_unavailable" in rep["failures"][0]["reason"]
    assert kl.counts(rep) == {"KeysPastRotationAge": 1, "KeysOnOldVersion": 0}
    assert str(rot.c) in str(e.value) and not any(p in str(e.value) for p in PHONES)


def test_a_census_row_left_on_an_old_version_fails_the_run_by_org_version_and_kind(rot):
    rot.start(rot.c)
    assert _run(rot)["on_old_version"] == []  # the open rotation is run to the end first
    with psycopg.connect(rot.t.super_dsn, autocommit=True) as su:  # one contact key left behind on version 1
        su.execute("SET session_replication_role = replica")
        su.execute("UPDATE consentvault.contact_key SET key_version = 1 WHERE org_id = %s"
                   " AND contact_fp = (SELECT min(contact_fp) FROM consentvault.contact_key WHERE org_id = %s)",
                   (rot.c, rot.c))
    with pytest.raises(kl.KeyLifecycleError) as e:
        _run(rot)
    assert e.value.report["on_old_version"] == [{"org_id": str(rot.c), "version": 1, "status": "retained_for_backup",
                                                 "kinds": {"contact_key": 1}}]
    assert kl.counts(e.value.report) == {"KeysPastRotationAge": 0, "KeysOnOldVersion": 1}


def test_a_blocked_rotation_is_named_and_its_keys_count_as_still_on_the_old_version(rot, monkeypatch):
    rot.start(rot.c)

    def broken(*a, **kw):
        raise kr.KeyRotationError("re-wrap refused")
    monkeypatch.setattr(kr, "_drain", broken)
    with pytest.raises(kl.KeyLifecycleError) as e:
        _run(rot)
    rep = e.value.report
    assert [f["org_id"] for f in rep["failures"]] == [str(rot.c)]
    assert rep["on_old_version"][0]["org_id"] == str(rot.c) and rep["on_old_version"][0]["kinds"]["contact_key"] == len(PHONES)


def test_offboarding_and_closed_orgs_are_neither_rotated_nor_alarmed(rot):
    _age(rot, rot.c, 400)
    with psycopg.connect(rot.t.super_dsn, autocommit=True) as su:
        su.execute("SET session_replication_role = replica")
        su.execute("UPDATE consentvault.organization SET status = 'offboarding' WHERE org_id = %s", (rot.c,))
    out = _run(rot)
    assert out["started"] == [] and out["past_rotation_age"] == [] and str(rot.c) in out["skipped"]


def test_only_a_console_login_may_run_it(rot, pg_server):
    dbname = rot.t.operator_dsn.rsplit("/", 1)[1]
    worker = make_login_role(pg_server["port"], dbname, "consentvault_worker")
    with pytest.raises(kl.LifecycleLoginRefused) as e:
        kl.run(lambda: db.connect(worker), token_key=rot.t.key, custody=rot.env.custody, crypto=rot.crypto,
               ledger=rot.env.ledger, request_id="req-kl", rotation_days=365)
    assert "consentvault_console" in str(e.value)
    with db.connect(worker) as c:
        assert kl.is_console_login(c) is False
    with rot.env.operator() as c:
        assert kl.is_console_login(c) is True


@pytest.mark.parametrize("days", [0, -1, True, "365", 36501])
def test_the_rotation_age_must_be_a_sensible_whole_number_of_days(rot, days):
    with pytest.raises(kl.KeyLifecycleError):
        _run(rot, rotation_days=days)


def test_the_rotation_age_setting_is_read_and_checked():
    assert kl.rotation_days_from({}) == kl.DEFAULT_ROTATION_DAYS == 365
    assert kl.rotation_days_from({kl.ENV_ROTATION_DAYS: "90"}) == 90
    for bad in ("0", "abc", "-3", "1.5"):
        with pytest.raises(kl.KeyLifecycleError):
            kl.rotation_days_from({kl.ENV_ROTATION_DAYS: bad})


# ---- the command: exit codes, metrics and the printed answer --------------------------------------------------------------
def _cli(monkeypatch, outcome):
    out = io.StringIO()
    real = metrics.emit
    monkeypatch.setattr(metrics, "emit", lambda name, value, stream=None: real(name, value, stream=out))
    monkeypatch.setattr(cmd_key_lifecycle, "_run_job", lambda cfg, env: outcome())
    rc = cmd_key_lifecycle.run_command(None, None)
    return rc, [json.loads(x) for x in out.getvalue().splitlines()]


def _metric_values(lines):
    return {k: v for doc in lines for k, v in doc.items() if k != "_aws"}


def test_a_clean_run_exits_0_and_writes_both_metrics_as_zero(monkeypatch, capsys):
    rc, lines = _cli(monkeypatch, lambda: {"started": [], "past_rotation_age": [], "on_old_version": [], "failures": [],
                                           "skipped": [], "orgs": 2})
    assert rc == 0 and _metric_values(lines) == {"KeysPastRotationAge": 0, "KeysOnOldVersion": 0}
    assert json.loads(capsys.readouterr().out)["orgs"] == 2


def test_a_finding_exits_3_with_its_counts(monkeypatch, capsys):
    org = str(uuid.uuid4())
    rep = {"started": [], "past_rotation_age": [{"org_id": org, "version": 1, "age_days": 400}],
           "on_old_version": [{"org_id": org, "version": 1, "status": "retired", "kinds": {"contact_key": 2}}],
           "failures": [], "skipped": [], "orgs": 1}

    def boom():
        raise kl.KeyLifecycleError("findings", rep)
    rc, lines = _cli(monkeypatch, boom)
    assert rc == 3 and _metric_values(lines) == {"KeysPastRotationAge": 1, "KeysOnOldVersion": 1}
    printed = capsys.readouterr()
    assert named("KeyLifecycleError", printed.err) and json.loads(printed.out)["past_rotation_age"][0]["org_id"] == org


def test_a_wrong_login_exits_3_and_writes_no_metric(monkeypatch, capsys):
    def refuse():
        raise kl.LifecycleLoginRefused("login t_x is not a member of consentvault_console")
    rc, lines = _cli(monkeypatch, refuse)
    err = capsys.readouterr().err
    assert rc == 3 and lines == [] and named("LifecycleLoginRefused", err) and "consentvault_console" not in err


def test_single_company_mode_has_nothing_to_rotate(monkeypatch, capsys):
    rc, lines = _cli(monkeypatch, lambda: None)
    assert rc == 0 and lines == [] and "single-company" in capsys.readouterr().out


def test_a_refused_setting_exits_2_and_writes_no_metric(monkeypatch, capsys):
    def refuse():
        raise kl.KeyLifecycleError("CONSENTVAULT_KEY_ROTATION_DAYS must be a whole number of days")
    rc, lines = _cli(monkeypatch, refuse)
    err = capsys.readouterr().err
    assert rc == 2 and lines == [] and named("KeyLifecycleError", err) and "CONSENTVAULT_KEY_ROTATION_DAYS" not in err


EMAIL = "jane.doe@example.com"


def test_error_text_never_reaches_the_report(rot, monkeypatch):
    rot.start(rot.c)

    def broken(*a, **kw):
        raise kr.KeyRotationError(f"DETAIL: Key (email)=({EMAIL}) already exists")
    monkeypatch.setattr(kr, "_drain", broken)
    with pytest.raises(kl.KeyLifecycleError) as e:
        _run(rot)
    assert EMAIL not in str(e.value) and EMAIL not in json.dumps(e.value.report)
    assert e.value.report["failures"][0]["reason"] == "KeyRotationError"


def test_a_superuser_or_bypassrls_login_is_refused(rot, pg_server):
    with pytest.raises(kl.LifecycleLoginRefused, match="superuser or bypasses row security"):
        kl.run(rot.t.superuser, token_key=rot.t.key, custody=rot.env.custody, crypto=rot.crypto, ledger=rot.env.ledger,
               request_id="r")
    dbname = rot.t.operator_dsn.rsplit("/", 1)[1]
    dsn = make_login_role(pg_server["port"], dbname, "consentvault_console")
    role = dsn.split("//", 1)[1].split("@", 1)[0]
    with psycopg.connect(rot.t.super_dsn, autocommit=True) as su:
        su.execute(f'ALTER ROLE "{role}" BYPASSRLS')
    try:
        with pytest.raises(kl.LifecycleLoginRefused, match="bypasses row security"):
            kl.run(lambda: db.connect(dsn), token_key=rot.t.key, custody=rot.env.custody, crypto=rot.crypto,
                   ledger=rot.env.ledger, request_id="r")
    finally:  # roles are cluster-wide: a BYPASSRLS console member left behind makes every later startup check refuse
        with psycopg.connect(rot.t.super_dsn, autocommit=True) as su:
            su.execute(f'DROP OWNED BY "{role}" CASCADE')
            su.execute(f'DROP ROLE "{role}"')


@pytest.mark.parametrize("raised,reason", [
    (psycopg.errors.UniqueViolation(f"duplicate key; DETAIL: Key (email)=({EMAIL}) exists"), "UniqueViolation (SQLSTATE 23505)"),
    (kr.KeyRotationError(f"refused for {EMAIL}"), "KeyRotationError"),
])
def test_a_failed_start_is_reported_by_class_and_code_only(rot, monkeypatch, raised, reason):
    _age(rot, rot.c, 400)

    def start(*a, **kw):
        raise raised
    monkeypatch.setattr(kr, "start_rotation", start)
    with pytest.raises(kl.KeyLifecycleError) as e:
        _run(rot)
    [f] = e.value.report["failures"]
    assert (f["org_id"], f["step"], f["reason"]) == (str(rot.c), "start", reason)
    assert EMAIL not in str(e.value) and EMAIL not in json.dumps(e.value.report)
