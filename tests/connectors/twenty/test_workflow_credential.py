"""The Twenty workflow credential (twenty.md 4.2): scope gate_check, POST /v1/permission only, one per connected system, admin
only and only once a policy is in force, an opaque secret shown once and stored as a SHA-256, 90 days with a replacement from
day 76 and a 14-day overlap, reminders at 14 and 3 days, revocable at once, 60 checks a minute, and every check recorded with
the credential's id."""

from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from consentvault import cmd_twenty, db
from consentvault.sync.connectors import twenty as tw_mod
from consentvault.sync.connectors import twenty_workflow as wf
from consentvault.tenancy.admin_base import ROLE_SCOPES
from consentvault.tenancy.session import MEMBER_CREDENTIAL_PREFIX
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from isolation.cloud_harness import Cloud
from .support import TwentyEnv

T0 = datetime.now(timezone.utc).replace(microsecond=0)      # checks are read against this; an issue is always the database's now


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def _admin(env, org):
    return env.t.app(), env.t.admin_token(org.org_id)


def issue(env, org, system_id, now=None):
    """Issue on the database's clock, as the app does. ``now`` (tests only) then moves the new credential's whole life so it reads
    as issued at that time: a superuser's edit of the row, never a time the issue was told."""
    conn, tok = _admin(env, org)
    with conn, org_transaction(conn, tok):
        got = wf.issue(conn, system_id, created_by="admin-1")
    if now is not None:
        row = env.q("SELECT created_at FROM consentvault.workflow_credential WHERE credential_id = %s", [got["credential_id"]])[0]
        _shift_back(env, got["credential_id"], row["created_at"] - now)
        got["expires_at"] = now + timedelta(hours=2160)
    return got


def use(env, secret, now=None):
    """The check, on the database's clock as the app runs it. ``now`` (tests only) reads the check as made at that time: the
    credential's whole life is moved by a superuser so the database's clock stands where ``now`` would, then moved back."""
    if now is None:
        with env.t.app() as conn:
            return wf.use(conn, secret)
    row = env.q("SELECT credential_id, clock_timestamp() AS db_now FROM consentvault.workflow_credential WHERE secret_hash = %s",
                [wf.secret_hash(secret)])
    if not row:
        with env.t.app() as conn:
            return wf.use(conn, secret)
    cid, delta = row[0]["credential_id"], now - row[0]["db_now"]
    _move(env, cid, -delta)
    try:
        with env.t.app() as conn:
            return wf.use(conn, secret)
    finally:
        _move(env, cid, delta)


def _move(env, credential_id, delta):
    secs = delta.total_seconds()           # in seconds: a day interval would move with the session's zone across a change
    env.q("UPDATE consentvault.workflow_credential SET created_at = created_at + make_interval(secs => %s),"
          " expires_at = expires_at + make_interval(secs => %s), refilled_at = refilled_at + make_interval(secs => %s),"
          " overlap_until = overlap_until + make_interval(secs => %s) WHERE credential_id = %s",
          [secs, secs, secs, secs, credential_id])


def test_issue_shows_the_secret_once_and_stores_only_its_hash(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id)
    row = env.q("SELECT created_at, expires_at, now() - created_at AS age FROM consentvault.workflow_credential"
                " WHERE credential_id = %s", [got["credential_id"]])[0]
    assert got["secret"].startswith(wf.PREFIX) and got["expires_at"] == row["expires_at"]
    assert _utc(row["expires_at"]) - _utc(row["created_at"]) == timedelta(hours=2160) and abs(row["age"]) < timedelta(minutes=1)
    rows = env.q("SELECT * FROM consentvault.workflow_credential WHERE org_id = %s", [env.t.a.org_id])
    assert len(rows) == 1 and got["secret"] not in str(rows[0]) and len(rows[0]["secret_hash"]) == 64


def test_only_an_admin_may_issue_and_only_once_a_policy_is_in_force(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    with env.t.app() as c, org_transaction(c, env.t.token(env.t.a, scopes=("developer",))), \
            pytest.raises(psycopg.errors.InsufficientPrivilege):
        wf.issue(c, tw.sys.system_id, created_by="dev")
    twb = TwentyEnv(env, env.t.b)                               # organisation B has no approved policy
    with pytest.raises(wf.WorkflowCredentialError, match="policy_required"):
        issue(env, env.t.b, twb.sys.system_id)


def test_one_per_system_a_replacement_only_from_day_76_and_a_14_day_overlap(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    first = issue(env, env.t.a, tw.sys.system_id, now=_now() - timedelta(days=75))          # day 75 of the first
    with pytest.raises(wf.WorkflowCredentialError, match="replacement"):
        issue(env, env.t.a, tw.sys.system_id)
    _shift_back(env, first["credential_id"], timedelta(days=1, minutes=1))                 # day 76
    second = issue(env, env.t.a, tw.sys.system_id)
    base = _now()
    with pytest.raises(wf.WorkflowCredentialError, match="replacement"):     # never a third
        issue(env, env.t.a, tw.sys.system_id)
    for day, old_ok in ((0, True), (13, True), (14, False)):
        assert (use(env, first["secret"], now=base + timedelta(days=day))["outcome"] == "ok") is old_ok, day
        assert use(env, second["secret"], now=base + timedelta(days=day))["outcome"] == "ok"
    assert use(env, second["secret"], now=base + timedelta(days=90, minutes=1))["outcome"] == "expired"


def test_revoked_at_once_unknown_secrets_refused_and_60_checks_a_minute(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id)
    assert env.q("SELECT tokens FROM consentvault.workflow_credential WHERE credential_id = %s",
                 [got["credential_id"]])[0]["tokens"] == 60                      # a full bucket: 60 checks a minute
    env.q("UPDATE consentvault.workflow_credential SET tokens = 0.5, refilled_at = clock_timestamp() WHERE credential_id = %s",
          [got["credential_id"]])
    limited = use(env, got["secret"])
    assert limited["outcome"] == "rate_limited" and 1 <= limited["retry_after"] <= 31
    env.q("UPDATE consentvault.workflow_credential SET refilled_at = refilled_at - interval '61 seconds' WHERE credential_id = %s",
          [got["credential_id"]])
    assert use(env, got["secret"])["outcome"] == "ok"                             # the bucket refills at one a second
    conn, tok = _admin(env, env.t.a)
    with conn, org_transaction(conn, tok):
        assert wf.revoke(conn, tw.sys.system_id, got["credential_id"]) is True
        assert wf.revoke(conn, tw.sys.system_id, got["credential_id"]) is False      # already revoked
    assert use(env, got["secret"])["outcome"] == "revoked"
    assert use(env, wf.PREFIX + "x" * 43)["outcome"] == "unknown"


def test_an_ended_credential_stays_refused_whatever_time_is_passed(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=_now() - timedelta(days=91))      # ended a day ago
    assert use(env, got["secret"])["outcome"] == "expired"
    for when in (_now() - timedelta(days=60), _now() + timedelta(days=60), datetime(2000, 1, 1, tzinfo=timezone.utc)):
        with env.t.app() as conn, pytest.raises(psycopg.errors.UndefinedFunction):
            conn.execute("SELECT * FROM consentvault.workflow_credential_use(%s, %s, %s)", (wf.secret_hash(got["secret"]), 60, when))
        with env.t.app() as conn, pytest.raises(psycopg.errors.UndefinedFunction):
            conn.execute("SELECT * FROM consentvault.workflow_credential_use(%s, %s)", (wf.secret_hash(got["secret"]), 10 ** 6))
    assert use(env, got["secret"])["outcome"] == "expired"
    assert cloud.gate(cloud.a, "+15555552001", token=got["secret"])[0] == 401


def test_no_connector_function_takes_a_callers_time(env, cloud):
    """Every Twenty connector function (migrations 0060 to 0062) reads the database's clock: none takes a time argument, and
    none survives in the old form that did. The generic claim (migration 0004's contract) is the sync lane's and is not one."""
    rows = env.q("SELECT p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) AS args FROM pg_catalog.pg_proc p"
                 " JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'consentvault'"
                 " AND (p.proname LIKE 'connector\\_%%' OR p.proname IN ('sync_claim_person', 'sync_extend_lease', 'sync_lease_person',"
                 " 'sync_rate_take', 'sync_complete_connector', 'sync_attempt_started') OR p.proname LIKE 'workflow\\_credential\\_%%')")
    names = {r["proname"] for r in rows}
    assert {"sync_complete_connector", "sync_attempt_started", "connector_deleted_wait", "connector_count"} <= names
    takes_time = [f"{r['proname']}({r['args']})" for r in rows if "p_now" in r["args"] or "p_at " in r["args"]]
    assert takes_time == []
    assert not {"connector_clock", "connector_link_deleted", "connector_link_alarmed"} & names


@pytest.mark.parametrize("old_form", [
    "consentvault.sync_claim(5, 60, now())",
    "consentvault.sync_complete(gen_random_uuid(), 1, 'retry', 503, NULL, NULL, now() + interval '30 seconds', now())",
    "consentvault.sync_release(gen_random_uuid(), 1, now())",
    "consentvault.record_call_take('m', now(), 30, 600)",
    "consentvault.record_reveal_note('m', ARRAY[gen_random_uuid()], now())",
    "consentvault.usage_retry_due(now())",
    "consentvault.usage_run_age(now())",
])
def test_a_function_that_decides_by_time_refuses_a_callers_time(env, cloud, old_form):
    """Migrations 0064 and 0065: the generic sync claim, completion and release, the records call limit and reveal log and the
    billing reads use the database's clock; their old forms, which took a caller's time, are gone, so passing one is refused."""
    with pytest.raises(psycopg.errors.UndefinedFunction):
        env.q(f"SELECT * FROM {old_form}")


def test_no_live_function_that_decides_by_time_takes_a_callers_time(env, cloud):
    rows = env.q("SELECT p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) AS args FROM pg_catalog.pg_proc p"
                 " JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'consentvault' AND p.proname = ANY(%s)",
                 [["sync_claim", "sync_complete", "sync_release", "record_call_take", "record_reveal_note", "usage_retry_due",
                   "usage_run_age"]])
    assert len(rows) == 7 and [f"{r['proname']}({r['args']})" for r in rows if "timestamp" in r["args"]] == []


def test_the_api_refuses_to_start_and_the_nightly_self_test_raises_while_a_test_clock_role_exists(env, cloud, tenancy, pg_server):
    from consentvault import api, isolation
    from consentvault.api import StartupRefusedError

    from isolation.harness import make_login_role

    selftest_dsn = make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_isolation_self_test")
    api.startup_check(tenancy.app_dsn)                                       # no such role: the start check passes
    env.q("CREATE ROLE consentvault_test_clock NOLOGIN")
    try:
        with pytest.raises(StartupRefusedError) as ei:
            api.startup_check(tenancy.app_dsn)
        assert ei.value.code == "startup_test_clock_role"
        with pytest.raises(isolation.IsolationLeak) as leak:
            isolation.run(lambda: db.connect(selftest_dsn))
        assert {"table": None, "kind": "test_clock_role_present"} in leak.value.report["findings"]
    finally:
        env.q("DROP ROLE consentvault_test_clock")
    api.startup_check(tenancy.app_dsn)



def _now():
    return datetime.now(timezone.utc)


def _shift_back(env, credential_id, delta):
    """Move a credential's whole life earlier by ``delta`` (its lifetime check holds): the database's clock then sees it older."""
    secs = delta.total_seconds()           # in seconds: a day interval would move with the session's zone across a change
    env.q("UPDATE consentvault.workflow_credential SET created_at = created_at - make_interval(secs => %s),"
          " expires_at = expires_at - make_interval(secs => %s), refilled_at = refilled_at - make_interval(secs => %s)"
          " WHERE credential_id = %s", [secs, secs, secs, credential_id])


def _due(env, org):
    conn, tok = _admin(env, org)
    with conn, org_transaction(conn, tok):
        return [r["days_left"] for r in wf.reminders_due(conn)]


def test_reminders_fall_due_at_14_and_3_days_once_each_on_the_databases_clock(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=_now() - timedelta(days=75))
    assert _due(env, env.t.a) == []
    _shift_back(env, got["credential_id"], timedelta(days=1, minutes=1))          # 76 days old: 14 days or fewer left
    assert _due(env, env.t.a) == [14]
    assert _due(env, env.t.a) == []
    _shift_back(env, got["credential_id"], timedelta(days=11))                    # 87 days old: 3 days or fewer left
    assert _due(env, env.t.a) == [3]
    assert _due(env, env.t.a) == []


def test_no_caller_can_name_the_reminders_clock_so_a_future_time_marks_nothing(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=_now())
    tok = mint_org_token(env.t.key, env.t.a.org_id, ["worker:sync"], credential_id=None)
    with env.t.app() as c, pytest.raises(psycopg.errors.UndefinedFunction), org_transaction(c, tok):
        c.execute("SELECT * FROM consentvault.workflow_credential_reminders_due(%s)", (_now() + timedelta(days=89),))
    with env.t.app() as c, org_transaction(c, tok):
        assert c.execute("SELECT * FROM consentvault.workflow_credential_reminders_due()").fetchall() == []
    r = env.q("SELECT reminded_14, reminded_3 FROM consentvault.workflow_credential WHERE credential_id = %s",
              [got["credential_id"]])[0]
    assert r["reminded_14"] is None and r["reminded_3"] is None


def _utc(d):
    return d.astimezone(timezone.utc)      # an aware datetime in a zone subtracts by wall clock in Python


def test_the_lifetime_is_2160_hours_across_a_daylight_saving_change(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    zone = _spring_forward_zone(5)                                   # the next 90 days hold a 23-hour day in this zone
    got = _issue_in(env, env.t.a, tw.sys.system_id, zone)
    row = env.q("SELECT created_at, expires_at FROM consentvault.workflow_credential WHERE credential_id = %s",
                [got["credential_id"]])[0]
    assert _utc(row["expires_at"]) - _utc(row["created_at"]) == timedelta(hours=2160)
    assert _utc(got["expires_at"]) == _utc(row["expires_at"])
    assert use(env, got["secret"], now=_utc(row["expires_at"]) - timedelta(minutes=1))["outcome"] == "ok"
    assert use(env, got["secret"], now=_utc(row["expires_at"]))["outcome"] == "expired"


def test_no_caller_names_a_credentials_lifetime(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    for when in (_now() + timedelta(days=365), _now() - timedelta(days=365)):
        conn, tok = _admin(env, env.t.a)
        with conn, pytest.raises(psycopg.errors.UndefinedFunction), org_transaction(conn, tok):
            conn.execute("SELECT * FROM consentvault.workflow_credential_issue(%s, %s, 'admin-1', %s)",
                         (tw.sys.system_id, "a" * 64, when))
    assert env.q("SELECT count(*) AS n FROM consentvault.workflow_credential WHERE system_id = %s", [tw.sys.system_id])[0]["n"] == 0
    got = issue(env, env.t.a, tw.sys.system_id)
    conn, tok = _admin(env, env.t.a)
    with conn, pytest.raises(psycopg.errors.UndefinedFunction), org_transaction(conn, tok):
        conn.execute("SELECT consentvault.workflow_credential_revoke(%s, %s, %s)",
                     (tw.sys.system_id, got["credential_id"], _now() - timedelta(days=365)))
    row = env.q("SELECT now() - created_at AS age, expires_at - created_at AS life, revoked_at"
                " FROM consentvault.workflow_credential WHERE credential_id = %s", [got["credential_id"]])[0]
    assert abs(row["age"]) < timedelta(minutes=1) and row["life"] == timedelta(hours=2160) and row["revoked_at"] is None


def test_issuing_on_a_disconnected_system_is_its_own_refusal_not_policy_required(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    _disconnect(env, env.t.a, tw.sys.system_id)
    conn, tok = _admin(env, env.t.a)
    with pytest.raises(wf.DisconnectedRefused) as ei, conn, org_transaction(conn, tok):
        wf.issue(conn, tw.sys.system_id, created_by="admin-1")
    assert not isinstance(ei.value, wf.PolicyRequiredRefused) and ei.value.code == "twenty_gate_system_disconnected"


def test_each_issue_refusal_has_its_own_sqlstate_and_code(env, cloud):
    tw, twb = TwentyEnv(env, env.t.a), TwentyEnv(env, env.t.b)
    with pytest.raises(wf.PolicyRequiredRefused) as p:
        issue(env, env.t.b, twb.sys.system_id)
    issue(env, env.t.a, tw.sys.system_id)
    with pytest.raises(wf.ReplacementRefused) as r:
        issue(env, env.t.a, tw.sys.system_id)
    _disconnect(env, env.t.a, tw.sys.system_id)
    with pytest.raises(wf.DisconnectedRefused) as d:
        issue(env, env.t.a, tw.sys.system_id)
    states = [e.value.__cause__.sqlstate for e in (p, d, r)]
    codes = [e.value.code for e in (p, d, r)]
    assert states == ["CVW01", "CVW02", "CVW03"]
    assert codes == ["twenty_gate_policy_required", "twenty_gate_system_disconnected", "twenty_gate_credential_exists"]


# ---- races (the reviewer's probes) -----------------------------------------------------------------------------------------
def _bg(fn):
    import threading

    out = {}

    def run():
        try:
            out["v"] = fn()
        except Exception as exc:  # loud-failure-exempt: the test asserts on what the thread raised
            out["e"] = exc
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, out


def test_a_disconnect_racing_an_uncommitted_issue_waits_and_then_revokes_it(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    sid = tw.sys.system_id
    conn, tok = _admin(env, env.t.a)
    with conn, org_transaction(conn, tok):
        got = wf.issue(conn, sid, created_by="admin-1")                       # uncommitted, holding the system row
        t, out = _bg(lambda: _disconnect(env, env.t.a, sid))
        t.join(3)
        assert t.is_alive(), "the disconnect did not wait for the issue holding the system row"
    t.join(15)
    assert not t.is_alive() and "e" not in out, out
    assert env.q("SELECT status FROM consentvault.connected_system WHERE system_id = %s", [sid])[0]["status"] == "disconnected"
    assert env.q("SELECT revoked_at FROM consentvault.workflow_credential WHERE credential_id = %s",
                 [got["credential_id"]])[0]["revoked_at"] is not None
    assert use(env, got["secret"], now=_now())["outcome"] == "revoked"


def test_an_issue_racing_an_uncommitted_disconnect_waits_and_is_refused(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    sid = tw.sys.system_id
    conn, tok = _admin(env, env.t.a)
    with conn, org_transaction(conn, tok):
        conn.execute("SELECT * FROM consentvault.sync_twenty_disconnect(%s, 'moving CRM')", (sid,))
        t, out = _bg(lambda: issue(env, env.t.a, sid, now=_now()))
        t.join(3)
        assert t.is_alive(), "the issue did not wait for the disconnect"
    t.join(15)
    assert isinstance(out.get("e"), wf.DisconnectedRefused), out
    assert env.q("SELECT count(*) AS n FROM consentvault.workflow_credential WHERE system_id = %s", [sid])[0]["n"] == 0


def test_a_revoke_waits_for_an_in_flight_use(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=_now())
    c1 = env.t.app()
    try:
        c1.autocommit = False
        assert wf.use(c1, got["secret"])["outcome"] == "ok"                     # holds the credential row
        conn, tok = _admin(env, env.t.a)

        def rv():
            with conn, org_transaction(conn, tok):
                return wf.revoke(conn, tw.sys.system_id, got["credential_id"])
        t, out = _bg(rv)
        t.join(2)
        assert t.is_alive(), "the revoke did not wait for the in-flight use"
        c1.commit()
    finally:
        c1.close()
    t.join(15)
    assert out.get("v") is True
    assert use(env, got["secret"], now=_now())["outcome"] == "revoked"


def test_a_use_racing_an_uncommitted_disconnect_waits_and_is_refused(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=_now())
    conn, tok = _admin(env, env.t.a)
    with conn, org_transaction(conn, tok):
        conn.execute("SELECT * FROM consentvault.sync_twenty_disconnect(%s, 'x')", (tw.sys.system_id,))
        t, out = _bg(lambda: use(env, got["secret"], now=_now()))
        t.join(2)
        assert t.is_alive(), "the use did not wait for the in-flight disconnect"
    t.join(15)
    assert out["v"]["outcome"] in ("revoked", "disconnected"), out


def test_the_old_credential_stops_when_its_overlap_ends(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    start = _now() - timedelta(days=80)
    old = issue(env, env.t.a, tw.sys.system_id, now=start)
    new = issue(env, env.t.a, tw.sys.system_id, now=start + timedelta(days=77))
    assert use(env, old["secret"], now=start + timedelta(days=89))["outcome"] == "ok"
    assert use(env, old["secret"], now=start + timedelta(days=90, seconds=1))["outcome"] == "expired"
    assert use(env, new["secret"], now=start + timedelta(days=90, seconds=1))["outcome"] == "ok"


def test_the_credential_checks_permission_only_and_every_check_names_it(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=datetime.now(timezone.utc))
    status, body = cloud.gate(cloud.a, "+15555552001", token=got["secret"])
    assert status == 200 and body["evidence_status"] == "no_record"
    rows = env.q("SELECT requested_by FROM consentvault.gate_decision WHERE org_id = %s ORDER BY at DESC LIMIT 1",
                 [env.t.a.org_id])
    assert rows[0]["requested_by"] == str(got["credential_id"])
    status, body = cloud.call("/v1/permission:batch", {"items": [{"contact": "+15555552001", "channel": "sms",
                                                                  "purpose": "marketing"}]}, token=got["secret"])
    assert status == 403 and body["error"] == "role_not_allowed"
    status, body = cloud.call("/v1/events", {"contact": "+15555552001"}, token=got["secret"])
    assert status == 403 and body["error"] == "role_not_allowed"
    conn, tok = _admin(env, env.t.a)
    with conn, org_transaction(conn, tok):
        wf.revoke(conn, tw.sys.system_id, got["credential_id"])
    status, body = cloud.gate(cloud.a, "+15555552001", token=got["secret"])
    assert status == 401


def test_a_rate_limited_check_answers_429_with_retry_after(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=datetime.now(timezone.utc))
    assert cloud.gate(cloud.a, "+15555552001", token=got["secret"])[0] == 200
    env.q("UPDATE consentvault.workflow_credential SET tokens = 0, refilled_at = clock_timestamp() WHERE credential_id = %s",
          [got["credential_id"]])
    status, body = cloud.gate(cloud.a, "+15555552001", token=got["secret"])
    assert status == 429 and body["error"] == "rate_limited"


def _disconnect(env, org, system_id):
    conn, tok = _admin(env, org)
    with conn, org_transaction(conn, tok):
        tw_mod.disconnect(conn, system_id, "moving CRM")


def test_a_disconnect_revokes_the_credential_in_the_same_transaction(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=datetime.now(timezone.utc))
    assert cloud.gate(cloud.a, "+15555552001", token=got["secret"])[0] == 200
    _disconnect(env, env.t.a, tw.sys.system_id)
    row = env.q("SELECT revoked_at FROM consentvault.workflow_credential WHERE credential_id = %s", [got["credential_id"]])[0]
    assert row["revoked_at"] is not None
    assert use(env, got["secret"], now=datetime.now(timezone.utc))["outcome"] == "revoked"
    assert cloud.gate(cloud.a, "+15555552001", token=got["secret"])[0] == 401


def test_a_disconnected_system_refuses_its_credential_even_if_the_revoke_were_undone(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=datetime.now(timezone.utc))
    _disconnect(env, env.t.a, tw.sys.system_id)
    env.q("UPDATE consentvault.workflow_credential SET revoked_at = NULL WHERE credential_id = %s", [got["credential_id"]])
    assert use(env, got["secret"], now=datetime.now(timezone.utc))["outcome"] == "disconnected"
    status, body = cloud.gate(cloud.a, "+15555552001", token=got["secret"])
    assert status == 401 and body["error"] == "unauthenticated"


# ---- the admin routes ----------------------------------------------------------------------------------------------------
def _portal(env, org, role):
    rows = env.q("SELECT member_id FROM consentvault.member WHERE org_id = %s AND role = %s LIMIT 1", [org.org_id, role])
    if rows:
        mid = rows[0]["member_id"]
    else:
        mid = env.q("INSERT INTO consentvault.member (org_id, idp_issuer, idp_subject, role) VALUES (%s, %s, %s, %s)"
                    " RETURNING member_id", [org.org_id, "https://idp.example.com", f"{role}-{org.org_id}", role])[0]["member_id"]
    return mint_org_token(env.t.key, org.org_id, ROLE_SCOPES[role], credential_id=MEMBER_CREDENTIAL_PREFIX + str(mid))


@pytest.fixture
def wired(cloud, tmp_path, pg_server):
    from isolation.test_route_wiring import Wired

    w = Wired(cloud, tmp_path, pg_server)
    yield w
    w.close()


def _post(wired, path, body, token):
    import json

    status, raw, _ = wired.call("POST", path, body, token=token)
    return status, json.loads(raw)


def _audit(env, org, action):
    return env.q("SELECT target_id, reason FROM consentvault.audit_event WHERE org_id = %s AND action = %s ORDER BY at",
                 [org.org_id, action])


def test_only_an_admin_issues_or_revokes_through_the_routes_and_each_is_audited(env, cloud, wired):
    tw = TwentyEnv(env, env.t.a)
    sid = tw.sys.system_id
    path = f"/v1/systems/{sid}/workflow-credential"
    for role in ("developer", "compliance_viewer"):
        status, body = _post(wired, path, {}, _portal(env, env.t.a, role))
        assert (status, body["error"]) == (403, "role_not_allowed"), role
    admin = _portal(env, env.t.a, "admin")
    status, got = _post(wired, path, {}, admin)
    assert status == 201 and got["secret"].startswith(wf.PREFIX) and got["scope"] == "gate_check" and got["replaced"] is None
    assert [r["target_id"] for r in _audit(env, env.t.a, "system.gate_credential_issued")] == [got["credential_id"]]
    assert got["secret"] not in str(env.q("SELECT * FROM consentvault.audit_event WHERE org_id = %s", [env.t.a.org_id]))
    status, body = _post(wired, path, {}, admin)                       # a second one before day 76
    assert (status, body["error"]) == (409, "credential_exists")
    revoke = f"{path}/{got['credential_id']}:revoke"
    status, body = _post(wired, revoke, {"reason": "rotating"}, _portal(env, env.t.a, "developer"))
    assert (status, body["error"]) == (403, "role_not_allowed")
    status, body = _post(wired, revoke, {"reason": "rotating"}, admin)
    assert status == 200 and body["revoked"] is True
    assert [(r["target_id"], r["reason"]) for r in _audit(env, env.t.a, "system.gate_credential_revoked")] == \
        [(got["credential_id"], "rotating")]
    status, body = _post(wired, revoke, {"reason": "again"}, admin)
    assert (status, body["error"]) == (404, "not_found")
    assert cloud.gate(cloud.a, "+15555552001", token=got["secret"])[0] == 401


def test_a_revoke_needs_a_reason_and_names_a_credential_of_that_system(env, cloud, wired):
    tw = TwentyEnv(env, env.t.a)
    admin = _portal(env, env.t.a, "admin")
    path = f"/v1/systems/{tw.sys.system_id}/workflow-credential"
    got = _post(wired, path, {}, admin)[1]
    status, body = _post(wired, f"{path}/{got['credential_id']}:revoke", {}, admin)
    assert (status, body["error"]) == (422, "validation_failed")
    other = TwentyEnv(env, env.t.b)
    status, body = _post(wired, f"/v1/systems/{other.sys.system_id}/workflow-credential/{got['credential_id']}:revoke",
                         {"reason": "x"}, admin)
    assert (status, body["error"]) == (404, "not_found")
    assert use(env, got["secret"], now=datetime.now(timezone.utc))["outcome"] == "ok"


# ---- the reminder job ----------------------------------------------------------------------------------------------------
class FakeNotifier:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def send(self, template, to, variables):
        from consentvault.notify.errors import SendFailed
        from consentvault.notify.templates import render

        render(template, variables)                       # the real template refuses a bad variable
        if self.fail:
            raise SendFailed("throttled", "provider said no")
        self.sent.append((template, to, variables))
        return "m-1"


def _worker_login(env, pg_server):
    import uuid as _uuid
    role = "t_" + _uuid.uuid4().hex[:10]
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{pg_server['port']}/postgres", autocommit=True) as su:
        su.execute(f'CREATE ROLE "{role}" LOGIN IN ROLE consentvault_worker')
    return role, f"postgresql://{role}@127.0.0.1:{pg_server['port']}/{env.dbname}"


def _drop_login(pg_server, role):
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{pg_server['port']}/postgres", autocommit=True) as su:
        su.execute(f'DROP ROLE "{role}"')


def test_the_reminder_job_emails_each_admin_at_14_and_3_days_once_each_under_a_worker_login(env, cloud, pg_server):
    tw = TwentyEnv(env, env.t.a)
    env.q("UPDATE consentvault.member SET email_norm = 'boss@a.example.com' WHERE org_id = %s AND role = 'admin'",
          [env.t.a.org_id])
    got = issue(env, env.t.a, tw.sys.system_id, now=_now() - timedelta(days=75))
    role, dsn = _worker_login(env, pg_server)
    try:
        n = FakeNotifier()
        with db.connect(dsn) as c:
            assert cmd_twenty.run_reminders(c, n, "https://app.example.test") == {"sent": 0, "failed": []}
            _shift_back(env, got["credential_id"], timedelta(days=1, minutes=1))
            assert cmd_twenty.run_reminders(c, n, "https://app.example.test") == {"sent": 1, "failed": []}
            assert cmd_twenty.run_reminders(c, n, "https://app.example.test")["sent"] == 0
            _shift_back(env, got["credential_id"], timedelta(days=11))
            assert cmd_twenty.run_reminders(c, n, "https://app.example.test")["sent"] == 1
        (t1, to1, v1), (t2, to2, v2) = n.sent
        assert t1 == t2 == "security_alert" and to1 == to2 == "boss@a.example.com"
        assert "14 days" in v1["event"] and "3 days" in v2["event"]
        assert v1["review_url"] == f"https://app.example.test/systems/{tw.sys.system_id}"
    finally:
        _drop_login(pg_server, role)


def test_a_reminder_that_could_not_be_sent_stays_due_and_is_named(env, cloud, pg_server):
    tw = TwentyEnv(env, env.t.a)
    env.q("UPDATE consentvault.member SET email_norm = 'boss@a.example.com' WHERE org_id = %s AND role = 'admin'",
          [env.t.a.org_id])
    issue(env, env.t.a, tw.sys.system_id, now=_now() - timedelta(days=76, minutes=1))
    role, dsn = _worker_login(env, pg_server)
    try:
        with db.connect(dsn) as c:
            out = cmd_twenty.run_reminders(c, FakeNotifier(fail=True), "https://app.example.test")
            assert out["sent"] == 0 and out["failed"] == [{"org_id": str(env.t.a.org_id), "error": "SendFailed"}]
            n = FakeNotifier()
            assert cmd_twenty.run_reminders(c, n, "https://app.example.test")["sent"] == 1
    finally:
        _drop_login(pg_server, role)


def test_an_organisation_with_no_admin_address_is_a_named_failure(env, cloud, pg_server):
    tw = TwentyEnv(env, env.t.a)
    env.q("UPDATE consentvault.member SET email_norm = NULL WHERE org_id = %s", [env.t.a.org_id])
    issue(env, env.t.a, tw.sys.system_id, now=_now() - timedelta(days=76, minutes=1))
    role, dsn = _worker_login(env, pg_server)
    try:
        with db.connect(dsn) as c:
            out = cmd_twenty.run_reminders(c, FakeNotifier(), "https://app.example.test")
        assert out["failed"] == [{"org_id": str(env.t.a.org_id), "error": "NoAdminAddress"}]
    finally:
        _drop_login(pg_server, role)


# ---- one current credential per system (two admins at once) ----------------------------------------------------------------
def test_two_admins_issuing_at_once_leave_one_current_credential(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    sid = tw.sys.system_id
    conn, tok = _admin(env, env.t.a)
    with conn, org_transaction(conn, tok):
        first = wf.issue(conn, sid, created_by="admin-1")                          # uncommitted
        t, out = _bg(lambda: issue(env, env.t.a, sid, now=_now()))                 # a second admin, its own connection
        t.join(3)
        assert t.is_alive(), "the second issue did not wait for the first"
    t.join(15)
    assert isinstance(out.get("e"), wf.ReplacementRefused), out
    live = env.q("SELECT credential_id FROM consentvault.workflow_credential WHERE system_id = %s AND revoked_at IS NULL",
                 [sid])
    assert [str(r["credential_id"]) for r in live] == [str(first["credential_id"])]


def test_the_database_itself_refuses_a_second_current_credential(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=_now())
    with pytest.raises(psycopg.errors.UniqueViolation, match="workflow_credential_one_current"):
        env.q("INSERT INTO consentvault.workflow_credential (org_id, system_id, secret_hash, created_by, created_at, expires_at,"
              " refilled_at) SELECT org_id, system_id, repeat('a', 64), 'x', now(), now() + interval '2160 hours', now()"
              " FROM consentvault.workflow_credential WHERE credential_id = %s", [got["credential_id"]])


def test_an_ended_credential_never_blocks_the_next_one(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    old = issue(env, env.t.a, tw.sys.system_id, now=_now() - timedelta(days=91))
    new = issue(env, env.t.a, tw.sys.system_id, now=_now())
    assert new["replaced"] is None
    assert use(env, old["secret"], now=_now())["outcome"] == "expired"
    assert use(env, new["secret"], now=_now())["outcome"] == "ok"


# ---- every span across a daylight-saving change (a day interval would move by an hour in these zones) -----------------------
def _issue_in(env, org, sid, zone):
    conn, tok = _admin(env, org)
    with conn, org_transaction(conn, tok):
        conn.execute(f"SET LOCAL TimeZone = '{zone}'")
        return wf.issue(conn, sid, created_by="admin-1")


def _set_created(env, credential_id, created):
    env.q("UPDATE consentvault.workflow_credential SET created_at = %s, expires_at = %s::timestamptz + interval '2160 hours',"
          " refilled_at = %s WHERE credential_id = %s", [created, created, created, credential_id])


def test_a_replacement_opens_at_1824_hours_across_a_daylight_saving_change(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    zone = _spring_forward_zone(-30)                       # the last 76 days hold a 23-hour day in this zone
    first = issue(env, env.t.a, tw.sys.system_id)
    _set_created(env, first["credential_id"], _now() - timedelta(hours=1824, minutes=-2))    # 2 minutes short of day 76
    with pytest.raises(wf.ReplacementRefused):
        _issue_in(env, env.t.a, tw.sys.system_id, zone)
    _set_created(env, first["credential_id"], _now() - timedelta(hours=1824, minutes=2))
    assert _issue_in(env, env.t.a, tw.sys.system_id, zone)["replaced"] == first["credential_id"]


def test_the_overlap_is_336_hours_across_a_daylight_saving_change(env, cloud):
    tw = TwentyEnv(env, env.t.a)
    zone = _spring_forward_zone(5)                         # the next 14 days hold a 23-hour day in this zone
    old = issue(env, env.t.a, tw.sys.system_id, now=_now() - timedelta(days=77))
    new = _issue_in(env, env.t.a, tw.sys.system_id, zone)
    row = env.q("SELECT o.overlap_until, n.created_at FROM consentvault.workflow_credential o, consentvault.workflow_credential n"
                " WHERE o.credential_id = %s AND n.credential_id = %s", [old["credential_id"], new["credential_id"]])[0]
    assert _utc(row["overlap_until"]) - _utc(row["created_at"]) == timedelta(hours=336)
    ends = min(_utc(row["overlap_until"]), _utc(old["expires_at"]))          # the old one stops at the sooner of the two
    assert use(env, old["secret"], now=ends - timedelta(minutes=1))["outcome"] == "ok"
    assert use(env, old["secret"], now=ends)["outcome"] == "expired"


def _spring_forward_zone(days_ahead: int) -> str:
    """A POSIX zone whose clocks jump forward an hour at the start of the day ``days_ahead`` from now (a 23-hour day), so
    "N days" before a time past that change is one hour later than "N times 24 hours" before it."""
    doy = lambda d: (d - datetime(d.year, 1, 1, tzinfo=timezone.utc)).days + 1  # noqa: E731
    start = min(doy(_now() + timedelta(days=days_ahead)), 365)
    return f"AAA0BBB,J{start}/0,J{(start + 99) % 365 + 1}/0"


@pytest.mark.parametrize("hours,days_left", [(336, 14), (72, 3)])
def test_each_reminder_falls_due_at_its_hours_across_a_daylight_saving_change(env, cloud, hours, days_left):
    tw = TwentyEnv(env, env.t.a)
    got = issue(env, env.t.a, tw.sys.system_id, now=_now() - timedelta(days=60))
    # ends half an hour inside the reminder's span; counted in days across the jump, it would still be half an hour outside it
    ends = _now() + timedelta(hours=hours, minutes=-30)
    env.q("UPDATE consentvault.workflow_credential SET created_at = %s - interval '2160 hours', expires_at = %s,"
          " reminded_14 = CASE WHEN %s = 3 THEN created_at END WHERE credential_id = %s",
          [ends, ends, days_left, got["credential_id"]])
    zone = _spring_forward_zone(1 if days_left == 3 else 2)
    conn, tok = _admin(env, env.t.a)
    with conn, org_transaction(conn, tok):
        conn.execute(f"SET LOCAL TimeZone = '{zone}'")
        assert conn.execute("SELECT (%s::timestamptz - make_interval(days => %s)) - (%s::timestamptz - make_interval(hours => %s))"
                            " AS d", (ends, hours // 24, ends, hours)).fetchone()["d"] == timedelta(hours=1)
        assert [r["days_left"] for r in wf.reminders_due(conn)] == [days_left]
