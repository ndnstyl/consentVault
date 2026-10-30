"""The final attack wave on this checkpoint, each attack kept as a test that must now fail to land.

1. A key rotation blocked by a legal hold never names the hold to the tenant. An operator's hold reads as a neutral
   "blocked; operator alerted" row on the tenant chain; a legal-process hold the customer has not been told of leaves no
   tenant row at all. The hold id is on the rotation record, the platform chain and the operator alarm only.
2. The trigger guard (docker/initdb/20-trigger-guard.sql) refuses, for every role that is not a superuser, the ways
   around a guard trigger the schema owner still had: replacing a guard function's body, replacing a guarded trigger,
   renaming the schema or moving a table out of it to switch a trigger off, and altering a guard function or trigger.
   Each guard function's and guarded trigger's definition is pinned by SHA-256 in the superuser-owned guard schema, and a
   mismatch is a violation the API refuses to start on.
3. The API start check refuses a login that is the schema owner, a member of it, a superuser, or a member of a
   BYPASSRLS role; every member of consentvault_console is held to the same test.
4. (tests/traceability/test_requirements_traceability.py) A mapped test under an ignored path or skipped in this run
   needs a named owner and receipt.
5. A rotation keeps the retired version until the oldest backup taken while it still wrapped keys ages out.
6. Offboarding cancels an open rotation first, visibly, then proceeds; the keys end destroyed and no job error repeats.
7. Row security on every table a guard reads or guards is pinned (flags and every policy) and the trigger guard refuses,
   for every role that is not a superuser, CREATE / ALTER / DROP POLICY and ENABLE / DISABLE / FORCE / NO FORCE ROW
   LEVEL SECURITY on it. Pinning is a superuser's only. The API compares the live security surface with the manifest built
   from a clean apply of the shipped migrations and refuses on any drift, naming each object, and refuses while a
   migration login can still log in.
8. Every partition and inheritance child of a vault table, in any schema, is guarded. The trigger guard refuses, for every
   role that is not a superuser, a vault table's child leaving the vault schema, being renamed, detached, un-inherited or
   newly attached, and a table made outside the vault schema that inherits from or is a partition of a vault table; the
   trigger-disable and guard-change checks resolve a child to its vault root. The security surface names every child in
   any schema, so the start check refuses on an unexpected child or one outside the vault schema.
9. (tests/traceability) The self-host receipt is tied to the code it proved: it records a digest of the product files and
   of the security manifest, the run's exit code and every section; traceability accepts it only with exit 0, every
   section the runner runs passed, and both digests equal to the current ones. A stale or forged receipt fails.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import psycopg
import pytest

from consentvault import api, config, surface
from consentvault.tenancy import erasure, holds, key_rotation as kr, legal_process, offboard
from consentvault.tenancy.erasure import LifecycleLedger
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from isolation.harness import PHONE

from .support import OPERATOR
from .test_key_rotation import PHONES, Rot

BASIS = "18 USC 2705(b) order 26-mj-901"
REQUESTER = "Field Office Nine"
SCOPE = "all records of the subscriber"


# ---- shared ---------------------------------------------------------------------------------------------------------------
def _sql(env, q, *args):
    with env.t.superuser() as su:
        return su.execute(q, args).fetchall()


def _owner(m):
    return m.execute("SELECT pg_get_userbyid(datdba) AS o FROM pg_database WHERE datname = current_database()"
                     ).fetchone()["o"]


def _violations(env):
    with env.t.superuser() as su:
        return su.execute("SELECT * FROM consentvault.owner_rights_violations()").fetchall()


def _tenant_surfaces(env, org) -> str:
    """Everything the tenant can read about the organisation: its whole audit chain (a superset of every audit page), the
    notices sent, and what the runtime role reads of holds; the rotation record and the alarms it cannot read at all."""
    out = {"audit": _sql(env, "SELECT action, target_kind, target_id, reason FROM consentvault.audit_event"
                              " WHERE org_id = %s ORDER BY seq", org),
           "notices": env.notifier.sent}
    with env.t.app() as app, org_transaction(app, mint_org_token(env.t.key, org, ["admin", "audit_read"],
                                                                 credential_id=None)):
        out["legal_hold"] = app.execute("SELECT hold_id, scope, set_by_kind FROM consentvault.legal_hold").fetchall()
        for table in ("key_rotation", "operator_alarm"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), app.transaction():
                app.execute(f"SELECT * FROM consentvault.{table}")
    return json.dumps(out, default=str)


def _no_trace(text, *secrets):
    for s in secrets + (BASIS, REQUESTER, SCOPE, "legal_hold_active", "legal process", "search_warrant", "legal hold"):
        assert str(s) not in text, f"{s!r} reached a tenant-readable surface"


def _gagged_process(env, rot, org):
    with env.operator() as c:
        p = legal_process.log_legal_process(
            c, token_key=env.t.key, ledger=env.ledger, custody=env.custody, crypto=rot.crypto, operator_id=OPERATOR,
            request_id="req-lp", org_id=org, type="search_warrant", received_at=datetime.now(timezone.utc),
            received_via="email", requester=REQUESTER, scope_summary=SCOPE, hold_scope="org")
        legal_process.record_customer_notice(c, token_key=env.t.key, notifier=env.notifier, operator_id=OPERATOR,
                                             request_id="req-lp2", org_id=org, process_id=p["process_id"],
                                             prohibited_basis=BASIS)
    return p


def _platform_reasons(env, rotation_id):
    return [r["reason"] for r in _sql(env, "SELECT reason FROM consentvault.audit_event WHERE org_id IS NULL AND target_id = %s",
                                      str(rotation_id))]


def _alarms(env, org):
    return _sql(env, "SELECT name, ref_kind, ref_id, error_class FROM consentvault.operator_alarm WHERE org_id = %s"
                     " ORDER BY raised_at", org)


# ---- 1. a rotation blocked by a hold never names it to the tenant ------------------------------------------------------------
def test_a_rotation_blocked_by_an_undisclosed_hold_leaves_no_tenant_row_and_names_the_hold_only_to_the_operator(env):
    rot = Rot(env)
    org = rot.c
    p = _gagged_process(env, rot, org)
    started = rot.start(org)
    out = rot.run(org)
    assert out["status"] == "blocked" and out["blocked_reason"] == f"legal_hold_active:{p['hold_id']}"
    actions = [r["action"] for r in _sql(env, "SELECT action FROM consentvault.audit_event WHERE org_id = %s", org)]
    assert "org_key.rotation_blocked" not in actions
    _no_trace(_tenant_surfaces(env, org), p["hold_id"], p["process_id"])
    assert any(p["hold_id"] in (r or "") for r in _platform_reasons(env, started["rotation_id"]))
    assert {"name": kr.ALARM_BLOCKED, "ref_kind": "legal_hold", "ref_id": uuid.UUID(p["hold_id"]),
            "error_class": "LegalHoldActive"} in _alarms(env, org)
    assert rot.read_all(org) == PHONES


def test_a_rotation_blocked_by_an_operator_hold_reads_neutral_on_every_tenant_surface(env):
    rot = Rot(env)
    org = rot.c
    with env.operator() as c:
        h = holds.place_hold_operator(c, token_key=env.t.key, ledger=env.ledger, custody=env.custody,
                                      operator_id=OPERATOR, request_id="req-h", org_id=org, scope="org",
                                      reason="billing dispute preservation", contacts=(), crypto=rot.crypto)
    started = rot.start(org)
    assert rot.run(org)["blocked_reason"] == f"legal_hold_active:{h['hold_id']}"
    rows = _sql(env, "SELECT reason FROM consentvault.audit_event WHERE org_id = %s"
                     " AND action = 'org_key.rotation_blocked'", org)
    assert [r["reason"] for r in rows] == [kr.TENANT_BLOCKED_NOTE] and kr.TENANT_BLOCKED_NOTE == "blocked; operator alerted"
    # an operator's hold is itself a neutral row the tenant reads (by id, no reason); the rotation never adds to that
    rotation_rows = _sql(env, "SELECT action, reason FROM consentvault.audit_event WHERE org_id = %s"
                              " AND target_kind = 'org_key'", org)
    _no_trace(json.dumps({"rotation": rotation_rows, "notices": env.notifier.sent}, default=str), h["hold_id"])
    _no_trace(_tenant_surfaces(env, org), "billing dispute")
    assert any(h["hold_id"] in (r or "") for r in _platform_reasons(env, started["rotation_id"]))
    assert _alarms(env, org)[-1]["ref_id"] == uuid.UUID(h["hold_id"])


# ---- 2. the trigger guard against the schema owner ---------------------------------------------------------------------------
def _op_hold(env, org):
    with env.operator() as c:
        return holds.place_hold_operator(c, token_key=env.t.key, ledger=env.ledger, custody=env.custody,
                                         operator_id=OPERATOR, request_id="req-h", org_id=org.org_id,
                                         scope="contacts", reason="subpoena preservation", contacts=[PHONE],
                                         crypto=env.t.crypto)


def _as_owner(env, *statements):
    """Run the statements as the schema owner (the migrator's SET ROLE), in one transaction; returns the refusal."""
    with env.t.migrator() as m:
        m.execute("SET ROLE " + _owner(m))
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="consentvault trigger guard") as e:
            with m.transaction():
                for s in statements:
                    m.execute(s)
        return str(e.value)


def _delete_held(env):
    with env.t.migrator() as m, erasure.operator_org(m, env.t.key, env.t.a.org_id):
        with pytest.raises(psycopg.Error):
            m.execute("DELETE FROM consentvault.contact_key WHERE contact_fp = %s", (env.fp(env.t.a),))


def test_replacing_a_guard_function_body_is_refused(env):
    _op_hold(env, env.t.a)
    _as_owner(env, "CREATE OR REPLACE FUNCTION consentvault.contact_key_hold_guard() RETURNS trigger LANGUAGE plpgsql"
                   " AS $$ BEGIN RETURN OLD; END $$")
    _delete_held(env)
    assert env.key_present(env.t.a) and _violations(env) == []


def test_re_running_a_guard_definition_unchanged_is_not_a_change(env):
    with env.t.superuser() as su:
        body = su.execute("SELECT pg_get_functiondef('consentvault.contact_key_hold_guard()'::regprocedure) AS d"
                          ).fetchone()["d"]
    with env.t.migrator() as m:
        m.execute("SET ROLE " + _owner(m))
        m.execute(body)  # the same definition, byte for byte: allowed, and nothing to report
        m.commit()
    assert _violations(env) == []
    _as_owner(env, body.replace("RETURN OLD;", "RETURN OLD; -- edited"))


def test_renaming_the_schema_is_refused(env):
    _op_hold(env, env.t.a)
    _as_owner(env, "ALTER SCHEMA consentvault RENAME TO cvx",
              "ALTER TABLE cvx.contact_key DISABLE TRIGGER contact_key_hold_guard",
              "ALTER SCHEMA cvx RENAME TO consentvault")
    _as_owner(env, "ALTER SCHEMA consentvault RENAME TO cvx")
    _delete_held(env)
    assert env.key_present(env.t.a)


def test_moving_a_guarded_table_out_of_the_schema_is_refused(env):
    _op_hold(env, env.t.a)
    msg = _as_owner(env, "CREATE SCHEMA zz", "ALTER TABLE consentvault.contact_key SET SCHEMA zz")
    assert "leaves" in msg or "schema" in msg
    _delete_held(env)
    assert env.key_present(env.t.a)


def test_create_or_replace_trigger_on_a_guarded_table_is_refused(env):
    _op_hold(env, env.t.a)
    _as_owner(env, "CREATE FUNCTION consentvault.zz_noop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END $$",
              "CREATE OR REPLACE TRIGGER contact_key_hold_guard BEFORE DELETE ON consentvault.contact_key"
              " FOR EACH ROW EXECUTE FUNCTION consentvault.zz_noop()")
    _delete_held(env)
    assert env.key_present(env.t.a)


@pytest.mark.parametrize("stmt", [
    "ALTER FUNCTION consentvault.contact_key_hold_guard() SECURITY INVOKER",
    "ALTER FUNCTION consentvault.contact_key_hold_guard() RENAME TO zz_hold_guard",
    "ALTER FUNCTION consentvault.refuse_change() SET search_path = public",
    "ALTER TRIGGER contact_key_hold_guard ON consentvault.contact_key RENAME TO zz_guard",
    "ALTER FUNCTION consentvault.legal_hold_on(uuid, text) VOLATILE",
    "CREATE OR REPLACE FUNCTION consentvault.owner_rights_violations() RETURNS TABLE (object_kind text, object_name text,"
    " owner_name text, problem text) LANGUAGE sql AS $$ SELECT NULL::text, NULL::text, NULL::text, NULL::text"
    " WHERE false $$",
])
def test_altering_a_pinned_guard_is_refused(env, stmt):
    _as_owner(env, stmt)
    assert _violations(env) == []


def test_a_guard_changed_below_the_guard_is_reported_and_the_api_refuses_to_start(env):
    api.startup_check(env.t.app_dsn)
    with env.t.superuser() as su:  # the break-glass path: only a superuser can still change a guard
        su.execute("CREATE OR REPLACE FUNCTION consentvault.contact_key_hold_guard() RETURNS trigger LANGUAGE plpgsql"
                   " AS $$ BEGIN RETURN OLD; END $$")
        su.execute("CREATE OR REPLACE TRIGGER key_rotation_no_truncate BEFORE TRUNCATE ON consentvault.key_rotation"
                   " FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change('changed')")
    got = {(v["object_name"], v["problem"].split(":")[0]) for v in _violations(env)}
    assert ("consentvault.contact_key_hold_guard()", "a pinned guard function changed") in got
    assert ("key_rotation_no_truncate on consentvault.key_rotation", "a pinned guard trigger changed") in got
    with pytest.raises(api.StartupRefusedError, match="pinned guard"):
        api.startup_check(env.t.app_dsn)
    with env.t.migrator() as m:  # pinning and re-pinning are a superuser's: the owner cannot bless the change
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            m.execute("SELECT consentvault_guard.pin_guards()")
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="only a superuser"):
            m.execute("SELECT consentvault_guard.repin()")
    assert len(_violations(env)) == 2
    with env.t.superuser() as su:
        su.execute("SELECT consentvault_guard.repin()")
    assert _violations(env) == []


def test_a_replaced_start_check_cannot_hide_a_changed_guard(env):
    with env.t.superuser() as su:
        su.execute("CREATE OR REPLACE FUNCTION consentvault.contact_key_hold_guard() RETURNS trigger LANGUAGE plpgsql"
                   " AS $$ BEGIN RETURN OLD; END $$")
        su.execute("CREATE OR REPLACE FUNCTION consentvault.owner_rights_violations() RETURNS TABLE (object_kind text,"
                   " object_name text, owner_name text, problem text) LANGUAGE sql AS $$ SELECT NULL::text, NULL::text,"
                   " NULL::text, NULL::text WHERE false $$")
    with pytest.raises(api.StartupRefusedError, match="pinned guard"):
        api.startup_check(env.t.app_dsn)


def test_a_new_trigger_is_unpinned_until_pinned_and_pinning_never_overwrites(env):
    with env.t.migrator() as m:
        m.execute("CREATE TRIGGER zz_new BEFORE TRUNCATE ON consentvault.key_rotation"
                  " FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change()")
        m.commit()
    assert [v["problem"].split(":")[0] for v in _violations(env)] == ["a guard trigger is not pinned"]
    with env.t.migrator() as m, pytest.raises(psycopg.errors.InsufficientPrivilege):
        m.execute("SELECT consentvault_guard.pin_guards()")
    with env.t.superuser() as su:
        su.execute("SELECT consentvault_guard.pin_guards()")
    assert _violations(env) == []
    with pytest.raises(api.StartupRefusedError, match="zz_new on consentvault.key_rotation"):
        api.startup_check(env.t.app_dsn)  # pinned, but not shipped: the security manifest does not know it
    _as_owner(env, "CREATE OR REPLACE TRIGGER zz_new BEFORE TRUNCATE ON consentvault.key_rotation"
                   " FOR EACH STATEMENT EXECUTE FUNCTION consentvault.refuse_change('x')")


# ---- 3. the start check and the console's members ---------------------------------------------------------------------------
def _login(env, port, *groups):
    role = "x_" + uuid.uuid4().hex[:8]
    db = env.t.app_dsn.rsplit("/", 1)[1]
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True) as su:
        su.execute(f'CREATE ROLE "{role}" LOGIN IN ROLE ' + ", ".join(groups))
    return role, f"postgresql://{role}@127.0.0.1:{port}/{db}"


def _drop(port, role):
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True) as su:
        su.execute(f'DROP ROLE IF EXISTS "{role}"')


def test_the_api_refuses_the_migrator_login(env):
    with pytest.raises(api.StartupRefusedError, match="schema owner"):
        api.startup_check(env.t.migrator_dsn)


def test_the_api_refuses_a_superuser_login(env):
    with pytest.raises(api.StartupRefusedError, match="superuser"):
        api.startup_check(env.t.app_dsn.replace(env.t.app_dsn.split("//", 1)[1].split("@", 1)[0] + "@", "postgres@", 1))


def test_the_api_refuses_an_app_login_that_can_set_role_to_a_bypassrls_role(env, pg_server):
    role, dsn = _login(env, pg_server["port"], "consentvault_app", "consentvault_operator")
    try:
        with pytest.raises(api.StartupRefusedError, match="BYPASSRLS"):
            api.startup_check(dsn)
    finally:
        _drop(pg_server["port"], role)
    api.startup_check(env.t.app_dsn)


@pytest.mark.parametrize("extra", ["consentvault_operator", "owner"])
def test_a_console_member_that_bypasses_row_security_or_acts_as_the_owner_is_a_violation(env, pg_server, extra):
    if extra == "owner":
        with env.t.migrator() as m:
            extra = _owner(m)
    role, _ = _login(env, pg_server["port"], "consentvault_console", extra)
    try:
        got = [v for v in _violations(env) if v["object_name"] == role]
        assert got and "consentvault_console" in got[0]["problem"], _violations(env)
        with pytest.raises(api.StartupRefusedError, match=role):
            api.startup_check(env.t.app_dsn)
    finally:
        _drop(pg_server["port"], role)
    assert _violations(env) == []


# ---- 5. a retired version outlives the backups that still need it -----------------------------------------------------------
def _job(rot, now, **kw):
    return kr.run_rotation_job(rot.env.operator, token_key=rot.t.key, custody=rot.env.custody, crypto=rot.crypto,
                               ledger=LifecycleLedger(rot.env.archive, clock=lambda: now), request_id="req-job", **kw)


def test_the_backup_retention_setting_defaults_to_35_days_and_is_read_from_the_environment(tmp_path):
    assert config.DEFAULT_BACKUP_RETENTION_DAYS == 35
    assert config.load_config(env={}).backup_retention_days == 35
    assert config.load_config(env={config.ENV_BACKUP_RETENTION: "90"}).backup_retention_days == 90
    for bad in ("-1", "x", "1.5"):
        with pytest.raises(config.ConfigError, match="backup_retention_days"):
            config.load_config(env={config.ENV_BACKUP_RETENTION: bad})


def test_a_rotation_keeps_the_retired_version_until_the_oldest_backup_ages_out(env):
    rot = Rot(env)
    org = rot.c
    rot.start(org)
    now = datetime.now(timezone.utc)
    [state] = [s for s in _job(rot, now) if s["org_id"] == str(org)]
    assert state["status"] == "complete" and state["remaining"] == 0
    assert state["old_version"] == "retained_for_backup" and state["old_version_destroyed"] is False
    until = datetime.fromisoformat(state["old_version_destroy_after"])
    assert until == now + timedelta(days=config.DEFAULT_BACKUP_RETENTION_DAYS)
    assert rot.env.custody.versions(str(org)) == {1: "retired", 2: "active"}
    assert "org_key.version_retained_for_backups" in rot.actions(org)
    _job(rot, until - timedelta(seconds=1))
    assert rot.env.custody.versions(str(org))[1] == "retired"
    _job(rot, until + timedelta(seconds=1))
    assert rot.env.custody.versions(str(org)) == {1: "destroyed", 2: "active"}
    assert _sql(env, "SELECT status FROM consentvault.org_key WHERE org_id = %s AND version = 1", org)[0]["status"] \
        == "destroyed"
    assert rot.read_all(org) == PHONES


def test_the_job_reads_the_backup_retention_setting(env, monkeypatch):
    monkeypatch.setenv(config.ENV_BACKUP_RETENTION, "3")
    rot = Rot(env)
    rot.start(rot.c)
    now = datetime.now(timezone.utc)
    [state] = [s for s in _job(rot, now) if s["org_id"] == str(rot.c)]
    assert datetime.fromisoformat(state["old_version_destroy_after"]) == now + timedelta(days=3)


# ---- 6. offboarding with a rotation open -------------------------------------------------------------------------------------
def _admin_for(env, org):
    with env.t.superuser() as su:
        su.execute("INSERT INTO consentvault.member (org_id, idp_issuer, idp_subject, role) VALUES (%s, 'i', 's', 'admin')",
                   (org,))
        su.execute("UPDATE consentvault.member SET email_norm = 'admin@charlie.example.com' WHERE org_id = %s", (org,))
    return SimpleNamespace(org_id=org, name="charlie")


def test_offboarding_cancels_an_open_rotation_first_and_the_keys_end_destroyed(env):
    rot = Rot(env)
    org = _admin_for(env, rot.c)
    started = rot.start(org.org_id)
    rot.run(org.org_id, max_batches=1)  # part way: some keys moved, the rotation is open
    env.open_access(org)
    with env.operator() as c:
        out = offboard.run_offboard(c, token_key=env.t.key, custody=env.custody, crypto=rot.crypto, signer=env.signer,
                                    store=env.archive, notifier=env.notifier, operator_id=OPERATOR, request_id="o",
                                    org_id=org.org_id, reason="contract ended", window_days=30, clock=env.clock,
                                    deliver=lambda *a: None)
    assert out["steps"]["rotation_cancelled"]["status"] == "done"
    assert out["steps"]["rotation_cancelled"]["rotation_id"] == started["rotation_id"]
    state = kr.get_rotation_state(env.operator, env.t.key, org.org_id)
    assert state["status"] == "cancelled" and state["cancel_reason"] == "organization offboarding"
    assert "org_key.rotation_cancelled" in rot.actions(org.org_id)
    alarms = len(_alarms(env, org.org_id))
    for i in range(2):  # the job finds nothing open and raises nothing
        kr.run_rotation_job(env.operator, token_key=env.t.key, custody=env.custody, crypto=rot.crypto,
                            ledger=env.ledger, request_id=f"job{i}")
    assert len(_alarms(env, org.org_id)) == alarms
    with pytest.raises(Exception), env.t.superuser() as su:  # a cancelled rotation stays cancelled
        su.execute("UPDATE consentvault.key_rotation SET status = 'rewrapping' WHERE rotation_id = %s",
                   (started["rotation_id"],))
    env.clock.advance(31)
    with env.operator() as c:
        done = offboard.complete_destructions(c, token_key=env.t.key, custody=env.custody, request_id="job")
    assert str(org.org_id) in done["destroyed"] and env.custody.is_destroyed(str(org.org_id))
    assert {r["status"] for r in _sql(env, "SELECT status FROM consentvault.org_key WHERE org_id = %s", org.org_id)} \
        == {"destroyed"}
    assert set(env.custody.versions(str(org.org_id)).values()) == {"destroyed"}
    for i in range(2):
        kr.run_rotation_job(env.operator, token_key=env.t.key, custody=env.custody, crypto=rot.crypto,
                            ledger=env.ledger, request_id=f"after{i}")
    assert len(_alarms(env, org.org_id)) == alarms


def test_a_rotation_job_mid_pass_stops_cleanly_when_offboarding_cancels_it(env, monkeypatch):
    rot = Rot(env)
    org = _admin_for(env, rot.c)
    rot.start(org.org_id)
    real = kr._contact_batch
    calls = []

    def batch(conn, **kw):  # offboarding cancels the rotation between two batches of the same pass
        if calls:
            with env.operator() as c, erasure.operator_org(c, env.t.key, org.org_id):
                offboard.cancel_open_rotation(c, actor_id=OPERATOR, request_id="o")
        calls.append(1)
        return real(conn, **kw)

    monkeypatch.setattr(kr, "_contact_batch", batch)
    out = rot.run(org.org_id, batch_size=2)
    assert out["status"] == "cancelled"
    assert not [a for a in _alarms(env, org.org_id)]


# ---- 7. row security on the tables the guards read, pinning, and the shipped security manifest ------------------------------
# Round five of the toughlove: the schema owner hid a hold from the hold guard by adding a restrictive policy to (or dropping
# the tenant policy of) a table the guard reads, nothing reported it; it pinned its own new trigger with pin_guards(); and a
# migration login that still logs in kept every one of those doors open after the migration run.

GUARD_READ = ("legal_hold", "org_key", "contact_key")


def _policies(env, table):
    return [r["policyname"] for r in _sql(env, "SELECT policyname FROM pg_policies WHERE schemaname = 'consentvault'"
                                               " AND tablename = %s ORDER BY policyname", table)]


def _delete_held_quietly(env):
    """The hold guard's answer to deleting the held key, as the owner acting for the organisation."""
    with env.t.migrator() as m, erasure.operator_org(m, env.t.key, env.t.a.org_id):
        try:
            return m.execute("DELETE FROM consentvault.contact_key WHERE contact_fp = %s", (env.fp(env.t.a),)).rowcount
        except psycopg.Error:
            return "refused"


def test_the_guard_reads_every_table_this_section_names(env):
    pinned = {r["identity"] for r in _sql(env, "SELECT identity FROM consentvault_guard.table_pin")}
    assert {f"consentvault.{t}" for t in GUARD_READ} <= pinned, pinned


@pytest.mark.parametrize("table", GUARD_READ)
@pytest.mark.parametrize("stmt", [
    "CREATE POLICY zz ON consentvault.{t} AS RESTRICTIVE FOR SELECT USING (false)",
    "CREATE POLICY zz ON consentvault.{t} AS PERMISSIVE FOR ALL USING (true)",
    "DROP POLICY {p} ON consentvault.{t}",
    "ALTER POLICY {p} ON consentvault.{t} USING (false)",
    "ALTER POLICY {p} ON consentvault.{t} RENAME TO zz",
    "ALTER TABLE consentvault.{t} DISABLE ROW LEVEL SECURITY",
    "ALTER TABLE consentvault.{t} NO FORCE ROW LEVEL SECURITY",
])
def test_a_policy_or_row_security_change_on_a_table_a_guard_reads_is_refused(env, table, stmt):
    _op_hold(env, env.t.a)
    msg = _as_owner(env, stmt.format(t=table, p=_policies(env, table)[0]))
    assert "row security" in msg and f"consentvault.{table}" in msg
    assert _delete_held_quietly(env) == "refused" and env.key_present(env.t.a)
    assert _violations(env) == []
    api.startup_check(env.t.app_dsn)


def test_every_permissive_policy_on_the_holds_table_dropped_in_one_go_is_refused(env):
    _op_hold(env, env.t.a)
    _as_owner(env, *[f"DROP POLICY {p} ON consentvault.legal_hold" for p in _policies(env, "legal_hold")])
    assert _delete_held_quietly(env) == "refused" and env.key_present(env.t.a)


def test_enabling_row_security_on_a_guard_read_table_that_had_none_is_refused(env):
    rows = _sql(env, "SELECT p.identity FROM consentvault_guard.table_pin p WHERE NOT p.rowsec")
    if not rows:
        pytest.skip("every table a guard reads already has row security on; the DISABLE and NO FORCE cases cover it")
    msg = _as_owner(env, f"ALTER TABLE {rows[0]['identity']} ENABLE ROW LEVEL SECURITY")
    assert "row security" in msg


def test_a_policy_added_below_the_guard_is_reported_and_the_api_refuses_to_start_naming_it(env):
    _op_hold(env, env.t.a)
    api.startup_check(env.t.app_dsn)
    with env.t.superuser() as su:  # break-glass, without the reviewed re-pin and without a new manifest
        su.execute("CREATE POLICY zz ON consentvault.legal_hold AS RESTRICTIVE FOR SELECT USING (false)")
    got = {(v["object_name"], v["problem"].split(":")[0]) for v in _violations(env)}
    assert ("consentvault.legal_hold", "a pinned guard table changed") in got, got
    with pytest.raises(api.StartupRefusedError, match="pinned guard table"):
        api.startup_check(env.t.app_dsn)
    with env.t.superuser() as su:
        su.execute("SELECT consentvault_guard.repin()")
    assert _violations(env) == []
    with pytest.raises(api.StartupRefusedError, match=r"security manifest.*policy zz on consentvault\.legal_hold"):
        api.startup_check(env.t.app_dsn)


@pytest.mark.parametrize("who", ["app", "migrator", "owner", "operator"])
def test_only_a_superuser_may_pin_guards(env, who):
    conn = {"app": env.t.app, "migrator": env.t.migrator, "owner": env.t.migrator, "operator": env.t.operator}[who]()
    with conn:
        if who == "owner":
            conn.execute("SET ROLE " + _owner(conn))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT consentvault_guard.pin_guards()")
    assert _sql(env, "SELECT has_function_privilege('public', 'consentvault_guard.pin_guards()', 'EXECUTE') AS x"
                ) == [{"x": False}]
    with env.t.superuser() as su:
        assert su.execute("SELECT consentvault_guard.pin_guards() AS n").fetchone()["n"] == 0


def test_a_pin_guards_still_open_to_public_is_a_violation(env):
    with env.t.superuser() as su:
        su.execute("GRANT EXECUTE ON FUNCTION consentvault_guard.pin_guards() TO PUBLIC")
    got = [v for v in _violations(env) if v["object_name"] == "consentvault_guard.pin_guards()"]
    assert got and "superuser" in got[0]["problem"], _violations(env)
    with pytest.raises(api.StartupRefusedError, match="pin_guards"):
        api.startup_check(env.t.app_dsn)


def test_the_policy_guard_is_required_by_the_start_check(env):
    with env.t.superuser() as su:
        su.execute("DROP EVENT TRIGGER consentvault_refuse_policy_change")
    assert [v["object_name"] for v in _violations(env)] == ["consentvault_refuse_policy_change"]
    with pytest.raises(api.StartupRefusedError, match="consentvault_refuse_policy_change"):
        api.startup_check(env.t.app_dsn)


def test_a_new_trigger_the_owner_adds_cannot_be_self_pinned_and_the_api_refuses_naming_it(env):
    with env.t.migrator() as m:
        m.execute("SET ROLE " + _owner(m))
        with m.transaction():
            m.execute("CREATE FUNCTION consentvault.zz_swallow() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN"
                      " IF NEW.event_type = 'revoke' THEN NEW.event_type := 'grant'; END IF; RETURN NEW; END $$")
            m.execute("CREATE TRIGGER aaa_swallow BEFORE INSERT ON consentvault.event FOR EACH ROW"
                      " EXECUTE FUNCTION consentvault.zz_swallow()")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            m.execute("SELECT consentvault_guard.pin_guards()")
    assert "aaa_swallow on consentvault.event" in {v["object_name"] for v in _violations(env)}
    with pytest.raises(api.StartupRefusedError) as refused:
        api.startup_check(env.t.app_dsn)
    assert "aaa_swallow" in str(refused.value)
    with env.t.superuser() as su:  # even a superuser who pins it by mistake does not make it shipped
        su.execute("SELECT consentvault_guard.pin_guards()")
    assert _violations(env) == []
    with pytest.raises(api.StartupRefusedError) as refused:
        api.startup_check(env.t.app_dsn)
    assert "trigger aaa_swallow on consentvault.event" in str(refused.value)
    assert "function consentvault.zz_swallow()" in str(refused.value)


def test_the_live_test_database_matches_the_committed_manifest(env):
    with env.t.superuser() as su:
        live = surface.live_surface(su)
    assert surface.drift(live, surface.load_manifest()) == []


def test_partitions_made_months_later_are_not_drift_but_a_partition_with_its_own_policy_is(env):
    with env.t.superuser() as su:
        su.execute("SET ROLE consentvault_worker")
        assert su.execute("SELECT consentvault.ensure_gate_decision_partitions(14) AS n").fetchone()["n"] >= 10
    api.startup_check(env.t.app_dsn)
    with env.t.superuser() as su:
        part = su.execute("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid"
                          " WHERE i.inhparent = 'consentvault.gate_decision'::regclass ORDER BY 1 DESC LIMIT 1"
                          ).fetchone()["relname"]
        su.execute(f"CREATE POLICY zz ON consentvault.{part} FOR SELECT USING (true)")
    with pytest.raises(api.StartupRefusedError, match="changed: partitions of consentvault.gate_decision"):
        api.startup_check(env.t.app_dsn)


def test_the_manifest_lists_each_object_once_in_order():
    lines = surface.MANIFEST_PATH.read_text().splitlines()
    assert lines[0] == f"# {surface.FORMAT}" and lines[1].startswith("# postgres_major ")
    names = [l.split("  ", 1)[1] for l in lines[2:]]
    assert names == sorted(names) and len(set(names)) == len(names) == len(surface.load_manifest()["objects"])


def test_drift_names_every_added_removed_and_changed_object():
    shipped = {"format": surface.FORMAT, "postgres_major": 17,
               "objects": {"function a()": "1" * 64, "policy p on t": "2" * 64, "trigger x on t": "3" * 64}}
    live = {"postgres_major": 17, "objects": {"function a()": "9" * 64, "trigger x on t": "3" * 64,
                                              "trigger y on t": "4" * 64}}
    assert surface.drift(live, shipped) == ["added: trigger y on t", "changed: function a()", "removed: policy p on t"]
    assert surface.drift({**live, "postgres_major": 16}, shipped)[0].startswith("postgres major")


def _builder():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / "scripts" / "build_security_manifest.py"
    spec = importlib.util.spec_from_file_location("build_security_manifest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_manifest_renders_the_same_bytes_from_two_clean_applies(pg_server):
    outs = [surface.render(_builder().clean_apply_surface(pg_server["port"])) for _ in range(2)]
    assert outs[0] == outs[1]
    assert outs[0] == surface.MANIFEST_PATH.read_bytes(), (
        "the committed security manifest is stale: run scripts/build_security_manifest.py and commit the file")


def test_a_missing_or_malformed_manifest_refuses_by_name(tmp_path):
    with pytest.raises(surface.ManifestError, match="missing"):
        surface.load_manifest(tmp_path / "none.json")
    (tmp_path / "bad").write_text("# other/1\n# postgres_major 17\n" + "0" * 64 + "  function x()\n")
    with pytest.raises(surface.ManifestError, match="format"):
        surface.load_manifest(tmp_path / "bad")
    (tmp_path / "torn").write_text(f"# {surface.FORMAT}\n# postgres_major 17\n" + "0" * 63 + "  function x()\n")
    with pytest.raises(surface.ManifestError, match="not '<sha256>  <object>'"):
        surface.load_manifest(tmp_path / "torn")


@pytest.mark.migration_login_check
def test_the_api_refuses_to_serve_while_a_migration_login_can_log_in(env, pg_server):
    with env.t.migrator() as m:
        login = m.execute("SELECT session_user AS s").fetchone()["s"]
    with pytest.raises(api.StartupRefusedError, match=f"migration login {login}"):
        api.startup_check(env.t.app_dsn)
    admin = f"postgresql://postgres@127.0.0.1:{pg_server['port']}/postgres"
    with psycopg.connect(admin, autocommit=True) as su:
        su.execute(f'ALTER ROLE "{login}" NOLOGIN')
    try:
        api.startup_check(env.t.app_dsn)
    finally:
        with psycopg.connect(admin, autocommit=True) as su:
            su.execute(f'ALTER ROLE "{login}" LOGIN')


# ---- 8. partitions and inheritance children of a vault table, in any schema ----------------------------------------------------
GD_FP = "a" * 64


def _hold_decision(env):
    """One gate decision on record (hold, a stop is on record); returns the partition it landed in."""
    with env.t.superuser() as su:
        su.execute("INSERT INTO consentvault.gate_decision (org_id, contact_fp, channel, purpose, evidence_status,"
                   " policy_action, policy_version) VALUES (%s, %s, 'sms', 'marketing', 'stop_on_record', 'hold', 1)",
                   (env.t.a.org_id, GD_FP))
        return su.execute("SELECT tableoid::regclass::text AS p FROM consentvault.gate_decision WHERE contact_fp = %s",
                          (GD_FP,)).fetchone()["p"]


def _decision(env):
    return _sql(env, "SELECT evidence_status, policy_action FROM consentvault.gate_decision WHERE contact_fp = %s",
                GD_FP)[0]


def _drift(env):
    with env.t.superuser() as su:
        return api._manifest_drift(su)


def test_a_partition_moved_through_another_schema_to_rewrite_a_gate_decision_is_refused(env):
    part = _hold_decision(env)
    before = _drift(env)
    msg = _as_owner(env, "CREATE SCHEMA zz", f"ALTER TABLE {part} SET SCHEMA zz")
    assert "leaves the vault schema" in msg and part.split(".")[1] in msg
    with env.t.migrator() as m, erasure.operator_org(m, env.t.key, env.t.a.org_id):
        with pytest.raises(psycopg.Error):
            m.execute("UPDATE consentvault.gate_decision SET evidence_status = 'consent_record_found',"
                      " policy_action = 'proceed' WHERE contact_fp = %s", (GD_FP,))
    assert dict(_decision(env)) == {"evidence_status": "stop_on_record", "policy_action": "hold"}
    assert _drift(env) == before


@pytest.mark.parametrize("stmt", [
    "ALTER TABLE {part} RENAME TO zz_renamed",
    "ALTER TABLE consentvault.gate_decision DETACH PARTITION {part}",
    "ALTER TABLE {part} SET SCHEMA public",
])
def test_renaming_detaching_or_moving_a_partition_is_refused(env, stmt):
    part = _hold_decision(env)
    msg = _as_owner(env, stmt.format(part=part))
    assert part.split(".")[1] in msg
    assert _sql(env, "SELECT tableoid::regclass::text AS p FROM consentvault.gate_decision WHERE contact_fp = %s",
                GD_FP)[0]["p"] == part


@pytest.mark.parametrize("stmt", [
    "CREATE TABLE zz.ev () INHERITS (consentvault.event)",
    "CREATE TABLE zz.gd PARTITION OF consentvault.gate_decision FOR VALUES FROM ('2031-01-01') TO ('2031-02-01')",
])
def test_a_child_of_a_vault_table_made_outside_the_vault_schema_is_refused(env, stmt):
    msg = _as_owner(env, "CREATE SCHEMA zz", stmt)
    assert "outside the vault schema" in msg


def test_an_inheritance_child_outside_the_schemas_cannot_inject_rows_into_an_append_only_table(env):
    before = _drift(env)
    with env.t.migrator() as m:
        m.execute("SET ROLE " + _owner(m))
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="consentvault trigger guard"):
            with m.transaction():
                m.execute("CREATE SCHEMA zz")
                m.execute("CREATE TABLE zz.ev () INHERITS (consentvault.event)")
                m.execute("INSERT INTO zz.ev SELECT * FROM ONLY consentvault.event LIMIT 1")
    assert _drift(env) == before
    assert _sql(env, "SELECT count(*) AS n FROM pg_inherits WHERE inhparent = 'consentvault.event'::regclass"
                )[0]["n"] == 0


def _owned_child_made_by_superuser(env):
    with env.t.superuser() as su:
        owner = _owner(su)
        su.execute("CREATE TABLE consentvault.zz_c () INHERITS (consentvault.event)")
        su.execute(f'ALTER TABLE consentvault.zz_c OWNER TO "{owner}"')


def test_un_inheriting_a_child_of_a_vault_table_is_refused(env):
    _owned_child_made_by_superuser(env)
    msg = _as_owner(env, "ALTER TABLE consentvault.zz_c NO INHERIT consentvault.event")
    assert "zz_c" in msg


def test_attaching_a_table_to_a_vault_table_by_alter_is_refused(env):
    _owned_child_made_by_superuser(env)
    with env.t.superuser() as su:
        su.execute("ALTER TABLE consentvault.zz_c NO INHERIT consentvault.event")
    msg = _as_owner(env, "ALTER TABLE consentvault.zz_c INHERIT consentvault.event")
    assert "zz_c" in msg


def test_disabling_the_append_only_trigger_on_a_partition_outside_the_schema_is_refused(env):
    part = _hold_decision(env)
    name = part.split(".")[1]
    with env.t.superuser() as su:  # break-glass: only a superuser can still move a partition out
        su.execute(f'CREATE SCHEMA zz AUTHORIZATION "{_owner(su)}"')
        su.execute(f"ALTER TABLE {part} SET SCHEMA zz")
    _as_owner(env, f"ALTER TABLE zz.{name} DISABLE TRIGGER gate_decision_append_only")
    assert _sql(env, "SELECT tgenabled FROM pg_trigger WHERE tgrelid = %s::regclass"
                     " AND tgname = 'gate_decision_append_only'", f"zz.{name}")[0]["tgenabled"] == "O"


def test_a_child_outside_the_vault_schema_is_on_the_surface_and_the_api_refuses_to_start(env):
    api.startup_check(env.t.app_dsn)
    with env.t.superuser() as su:
        su.execute("CREATE SCHEMA zz")
        su.execute("CREATE TABLE zz.ev () INHERITS (consentvault.event)")
        live = surface.live_surface(su)
    assert "child zz.ev of consentvault.event" in live["objects"]
    with pytest.raises(api.StartupRefusedError, match="child zz.ev of consentvault.event"):
        api.startup_check(env.t.app_dsn)


def test_a_partition_moved_out_by_a_superuser_is_drift_the_api_refuses_on(env):
    part = _hold_decision(env)
    with env.t.superuser() as su:
        su.execute("CREATE SCHEMA zz")
        su.execute(f"ALTER TABLE {part} SET SCHEMA zz")
    with pytest.raises(api.StartupRefusedError, match="child zz." + part.split(".")[1]):
        api.startup_check(env.t.app_dsn)


def test_an_unexpected_inheritance_child_inside_the_vault_schema_is_drift_naming_it(env):
    _owned_child_made_by_superuser(env)
    with pytest.raises(api.StartupRefusedError, match="child consentvault.zz_c of consentvault.event"):
        api.startup_check(env.t.app_dsn)


def test_the_worker_still_makes_monthly_partitions_and_they_are_not_drift(env):
    with env.t.superuser() as su:
        su.execute("SET ROLE consentvault_worker")
        assert su.execute("SELECT consentvault.ensure_gate_decision_partitions(6) AS n").fetchone()["n"] >= 3
    api.startup_check(env.t.app_dsn)


# ---- 9. the self-host receipt is tied to the code it proved -----------------------------------------------------------------
def _trace():
    from traceability import test_requirements_traceability as tr
    return tr


def _selfhost_mapped(tr):
    reqs = tr.load_map()["requirements"]
    return reqs, sorted({t for r in reqs.values() for t in r.get("tests", []) if t.startswith("tests/selfhost/")})


def _receipt_root(tmp_path, tr):
    import shutil
    shutil.copy(tr.REPO / "pyproject.toml", tmp_path / "pyproject.toml")
    (tmp_path / "tests/selfhost").mkdir(parents=True)
    shutil.copy(tr.REPO / "tests/selfhost/run_suites.sh", tmp_path / "tests/selfhost/run_suites.sh")
    (tmp_path / "src/consentvault/data").mkdir(parents=True)
    (tmp_path / "src/consentvault/data/security_manifest.sha256").write_text("# manifest\n")
    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations/0001_x.sql").write_text("SELECT 1;\n")
    return tmp_path


def _honest(tr, root, mapped, **over):
    body = {"format": tr.RECEIPT_FORMAT, "finished_at": "2026-10-30T00:00:00Z", "exit_code": 0,
            "product_sha256": tr.product_digest(root), "manifest_sha256": tr.manifest_digest(root),
            "sections": {s: "passed" for s in tr.runner_sections(root)}, "tests": {t: "passed" for t in mapped}}
    body.update(over)
    p = root / tr.SELFHOST_RECEIPT
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(body))
    return body


def test_a_forged_stale_failed_receipt_is_refused(tmp_path):
    tr = _trace()
    root = _receipt_root(tmp_path, tr)
    reqs, mapped = _selfhost_mapped(tr)
    forged = {"format": tr.RECEIPT_FORMAT, "finished_at": "2019-01-01T00:00:00Z", "exit_code": 1,
              "sections": {"integrity": "failed", "isolation": "failed", "suppression sync": "failed"},
              "tests": {t: "passed" for t in mapped}}
    p = root / tr.SELFHOST_RECEIPT
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps(forged))
    out = tr.out_of_run(reqs, root=root)
    assert out["problems"] and out["pending"] == []
    text = "\n".join(out["problems"])
    assert "exit code 1" in text and "product" in text


@pytest.mark.parametrize("over, says", [
    ({"exit_code": 1}, "exit code 1"),
    ({"product_sha256": "0" * 64}, "product files"),
    ({"manifest_sha256": "0" * 64}, "security manifest"),
    ({"sections": {"isolation": "passed"}}, "section"),
    ({"sections": None}, "section"),
    ({"finished_at": "2999-01-01T00:00:00Z"}, "future"),
])
def test_a_receipt_that_is_not_a_clean_run_of_this_code_is_refused(tmp_path, over, says):
    tr = _trace()
    root = _receipt_root(tmp_path, tr)
    reqs, mapped = _selfhost_mapped(tr)
    body = _honest(tr, root, mapped)
    for k, v in over.items():
        if v is None:
            body.pop(k)
        else:
            body[k] = v
    (root / tr.SELFHOST_RECEIPT).write_text(json.dumps(body))
    out = tr.out_of_run(reqs, root=root)
    assert any(says in p for p in out["problems"]), out


def test_a_receipt_of_a_clean_run_of_this_code_is_accepted_and_goes_stale_on_any_product_change(tmp_path):
    tr = _trace()
    root = _receipt_root(tmp_path, tr)
    reqs, mapped = _selfhost_mapped(tr)
    _honest(tr, root, mapped)
    assert tr.out_of_run(reqs, root=root) == {"problems": [], "pending": []}
    (root / "migrations/0002_y.sql").write_text("SELECT 2;\n")
    assert any("product files" in p for p in tr.out_of_run(reqs, root=root)["problems"])


def test_the_receipt_writer_records_the_code_and_the_manifest_it_ran_against(tmp_path):
    import subprocess
    import sys
    tr = _trace()
    junit = tmp_path / "j.xml"
    junit.write_text('<testsuites><testsuite><testcase classname="tests.selfhost.test_openbao_keys" name="test_a"/>'
                     '</testsuite></testsuites>')
    out = tmp_path / "r.json"
    done = subprocess.run([sys.executable, str(tr.REPO / "tests/selfhost/write_receipt.py"), str(junit), str(out), "0",
                           "isolation=passed"], capture_output=True, text=True, cwd=tr.REPO)
    assert done.returncode == 0, done.stderr
    body = json.loads(out.read_text())
    assert body["product_sha256"] == tr.product_digest(tr.REPO)
    assert body["manifest_sha256"] == tr.manifest_digest(tr.REPO)
    assert body["exit_code"] == 0 and body["sections"] == {"isolation": "passed"}


def test_the_receipt_folder_is_tracked():
    tr = _trace()
    folder = tr.REPO / "tests/selfhost/receipts"
    assert folder.is_dir() and any(p.name != ".gitignore" for p in folder.iterdir())
    for ignore in (tr.REPO / ".gitignore", tr.REPO / "tests/.gitignore", tr.REPO / "tests/selfhost/.gitignore",
                   folder / ".gitignore"):
        if ignore.is_file():
            assert "receipts" not in ignore.read_text() and "*.json" not in ignore.read_text()
