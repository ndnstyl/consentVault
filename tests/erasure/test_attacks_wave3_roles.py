"""Third adversarial review, roles.

- Every table, sequence and owner-rights function is owned by a NOLOGIN owner role. Migrations connect as a migrator
  login whose login default is SET ROLE to that owner; the operator console connects as its own login (a member of
  consentvault_console) that owns nothing.
- The trigger guard (docker/initdb/20-trigger-guard.sql, an event trigger a superuser installs) refuses, for every role
  but a superuser, ALTER TABLE ... DISABLE TRIGGER (or ENABLE REPLICA, which stops a trigger in normal sessions) and
  any drop of a trigger on a vault table: the migrator, the operator console and the runtime role are all refused.
- release_hold_as_operator takes the operator from the signed operator session (the tenant token the console entered
  the organisation with names it), never from a parameter: a caller-named operator that differs is refused.
"""

import uuid

import psycopg
import pytest

from consentvault import api
from consentvault.tenancy import erasure, holds
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from isolation.harness import PHONE

from .support import OPERATOR

GUARDED = ("contact_key", "org_key", "legal_hold", "erasure_request", "event")
TRIGGER = {"contact_key": "contact_key_hold_guard", "org_key": "org_key_hold_guard", "legal_hold": "legal_hold_guard",
           "erasure_request": "erasure_request_guard", "event": "event_append_only"}


def _op_hold(env, org):
    with env.operator() as c:
        return holds.place_hold_operator(c, token_key=env.t.key, ledger=env.ledger, custody=env.custody,
                                         operator_id=OPERATOR, request_id="req-h", org_id=org.org_id,
                                         scope="contacts", reason="subpoena preservation", contacts=[PHONE],
                                         crypto=env.t.crypto)


def _connect(env, who):
    return {"migrator": env.t.migrator, "operator": env.t.operator, "app": env.t.app}[who]()


def _trigger_state(env, table, name):
    with env.t.superuser() as su:
        return su.execute("SELECT tgenabled FROM pg_trigger WHERE tgrelid = %s::regclass AND tgname = %s",
                          (f"consentvault.{table}", name)).fetchone()


# Attack F: the console's connection disabled the hold trigger and deleted a held key --------------------------------------
def test_F_operator_console_cannot_disable_the_hold_trigger_and_delete_a_held_key(env):
    t = env.t
    _op_hold(env, t.a)
    fp = env.fp(t.a)
    with env.operator() as o:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with erasure.operator_org(o, t.key, t.a.org_id):
                o.execute("ALTER TABLE consentvault.contact_key DISABLE TRIGGER contact_key_hold_guard")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):  # the console holds no delete; erasure is a function
            with erasure.operator_org(o, t.key, t.a.org_id):
                o.execute("DELETE FROM consentvault.contact_key WHERE contact_fp = %s", (fp,))
    with t.migrator() as m:  # the owner's rights still meet the hold trigger, which nobody but a superuser switches off
        with pytest.raises(psycopg.Error, match="hold"):
            with erasure.operator_org(m, t.key, t.a.org_id):
                m.execute("DELETE FROM consentvault.contact_key WHERE contact_fp = %s", (fp,))
    assert env.key_present(t.a)
    assert _trigger_state(env, "contact_key", "contact_key_hold_guard") == {"tgenabled": "O"}


def test_F_the_migrator_acting_as_owner_cannot_disable_or_drop_the_hold_trigger(env):
    t = env.t
    _op_hold(env, t.a)
    with t.migrator() as m:
        for sql in ("ALTER TABLE consentvault.contact_key DISABLE TRIGGER contact_key_hold_guard",
                    "DROP TRIGGER contact_key_hold_guard ON consentvault.contact_key",
                    "DROP FUNCTION consentvault.contact_key_hold_guard() CASCADE"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege, match="trigger guard"):
                with m.transaction():
                    m.execute("SET LOCAL ROLE " + m.execute(
                        "SELECT pg_get_userbyid(datdba) AS o FROM pg_database WHERE datname = current_database()"
                    ).fetchone()["o"])
                    m.execute(sql)
    assert env.key_present(t.a)
    assert _trigger_state(env, "contact_key", "contact_key_hold_guard") == {"tgenabled": "O"}


# Every non-superuser is refused, on every guarded table, every way of switching a trigger off ----------------------------
@pytest.mark.parametrize("who", ["migrator", "operator", "app"])
@pytest.mark.parametrize("table", GUARDED)
def test_no_login_role_disables_or_drops_a_trigger_on_a_vault_table(env, who, table):
    name = TRIGGER[table]
    stmts = (f"ALTER TABLE consentvault.{table} DISABLE TRIGGER {name}",
             f"ALTER TABLE consentvault.{table} DISABLE TRIGGER ALL",
             f"ALTER TABLE consentvault.{table} DISABLE TRIGGER USER",
             f"ALTER TABLE consentvault.{table} ENABLE REPLICA TRIGGER {name}",
             f"DROP TRIGGER {name} ON consentvault.{table}")
    with _connect(env, who) as c:
        for sql in stmts:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute(sql)
    assert _trigger_state(env, table, name) == {"tgenabled": "O"}


def test_a_superuser_is_the_only_break_glass(env):
    """The guard is scoped: a superuser can still disable a trigger (a down migration runs as one)."""
    with env.t.superuser() as su:
        with su.transaction(force_rollback=True):
            su.execute("ALTER TABLE consentvault.contact_key DISABLE TRIGGER contact_key_hold_guard")
            assert su.execute("SELECT tgenabled FROM pg_trigger WHERE tgname = 'contact_key_hold_guard'"
                              ).fetchone() == {"tgenabled": "D"}
    assert _trigger_state(env, "contact_key", "contact_key_hold_guard") == {"tgenabled": "O"}


# The role layout --------------------------------------------------------------------------------------------------------
def test_a_nologin_owner_owns_everything_and_the_two_logins_are_separate(env):
    with env.t.superuser() as su:
        owner = su.execute("SELECT r.rolname, r.rolcanlogin, r.rolsuper, r.rolbypassrls FROM pg_namespace n"
                           " JOIN pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'consentvault'").fetchone()
        assert owner["rolcanlogin"] is False and not owner["rolsuper"] and not owner["rolbypassrls"]
        stray = su.execute(
            "SELECT c.relname, pg_get_userbyid(c.relowner) AS o FROM pg_class c JOIN pg_namespace n ON n.oid ="
            " c.relnamespace WHERE n.nspname = 'consentvault' AND c.relkind IN ('r', 'p', 'S', 'v', 'm')"
            " AND pg_get_userbyid(c.relowner) <> %s", (owner["rolname"],)).fetchall()
        assert stray == []
        stray_fn = su.execute(
            "SELECT p.oid::regprocedure::text AS f, pg_get_userbyid(p.proowner) AS o FROM pg_proc p JOIN pg_namespace n"
            " ON n.oid = p.pronamespace WHERE n.nspname = 'consentvault'"
            " AND pg_get_userbyid(p.proowner) NOT IN (%s, 'consentvault_operator')", (owner["rolname"],)).fetchall()
        assert stray_fn == []
    with env.t.migrator() as m:
        me = m.execute("SELECT session_user AS login, current_user AS acting,"
                       " pg_has_role(session_user, %s, 'MEMBER') AS member", (owner["rolname"],)).fetchone()
        assert me["login"] != owner["rolname"] and me["member"] and me["acting"] == owner["rolname"]
    with env.t.operator() as o:
        me = o.execute("SELECT r.rolname, r.rolsuper, r.rolbypassrls, pg_has_role(r.oid, %s, 'MEMBER') AS owner_member,"
                       " pg_has_role(r.oid, 'consentvault_console', 'MEMBER') AS console"
                       " FROM pg_roles r WHERE r.rolname = current_user", (owner["rolname"],)).fetchone()
        assert me["console"] and not me["owner_member"] and not me["rolsuper"] and not me["rolbypassrls"]
        owned = o.execute("SELECT count(*) AS n FROM pg_class WHERE relowner = (SELECT oid FROM pg_roles"
                          " WHERE rolname = current_user)").fetchone()["n"]
        assert owned == 0


def test_the_api_refuses_a_schema_owner_that_can_log_in(env):
    t = env.t
    api.startup_check(t.app_dsn)
    with t.superuser() as su:
        owner = su.execute("SELECT pg_get_userbyid(nspowner) AS o FROM pg_namespace WHERE nspname = 'consentvault'"
                           ).fetchone()["o"]
        su.execute(f'ALTER ROLE "{owner}" LOGIN')
    try:
        with pytest.raises(api.StartupRefusedError, match="can log in"):
            api.startup_check(t.app_dsn)
    finally:
        with t.superuser() as su:
            su.execute(f'ALTER ROLE "{owner}" NOLOGIN')
    api.startup_check(t.app_dsn)


def test_the_api_refuses_a_vault_without_the_trigger_guard(env):
    t = env.t
    with t.superuser() as su:
        su.execute("ALTER EVENT TRIGGER consentvault_refuse_trigger_disable DISABLE")
    try:
        with pytest.raises(api.StartupRefusedError, match="trigger guard"):
            api.startup_check(t.app_dsn)
    finally:
        with t.superuser() as su:
            su.execute("ALTER EVENT TRIGGER consentvault_refuse_trigger_disable ENABLE")
    api.startup_check(t.app_dsn)


# The operator who releases a hold comes from the signed session ----------------------------------------------------------
def _release_sql(c, hold_id, expected):
    return c.execute("SELECT consentvault.release_hold_as_operator(%s, 'ocv1:x', clock_timestamp(), 1, %s) AS h",
                     (hold_id, expected)).fetchone()


def _hold_row(env, org, hold_id):
    with env.t.superuser() as su:
        return su.execute("SELECT * FROM consentvault.legal_hold WHERE org_id = %s AND hold_id = %s",
                          (org.org_id, hold_id)).fetchone()


def test_a_forged_operator_id_is_refused(env):
    t = env.t
    h = _op_hold(env, t.a)
    with t.operator() as o:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="does not match"):
            with erasure.operator_org(o, t.key, t.a.org_id, operator_id=OPERATOR):
                _release_sql(o, h["hold_id"], "op-forged")
    assert _hold_row(env, t.a, h["hold_id"])["released_at"] is None


def test_an_operator_release_needs_an_operator_session(env):
    """Entered with a token that names no operator (a machine admin token), the release is refused whatever the caller
    names."""
    t = env.t
    h = _op_hold(env, t.a)
    machine = mint_org_token(t.key, t.a.org_id, ["admin"], credential_id=None)
    with t.operator() as o:
        for named in (OPERATOR, None):
            with pytest.raises(psycopg.errors.InsufficientPrivilege, match="no operator session"):
                with org_transaction(o, machine):
                    _release_sql(o, h["hold_id"], named)
    assert _hold_row(env, t.a, h["hold_id"])["released_at"] is None


def test_the_runtime_role_cannot_call_the_operator_release_even_with_an_operator_token(env):
    t = env.t
    h = _op_hold(env, t.a)
    forged = mint_org_token(t.key, t.a.org_id, ["admin"], credential_id="operator:" + OPERATOR)
    with t.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(app, forged):
                _release_sql(app, h["hold_id"], OPERATOR)
    assert _hold_row(env, t.a, h["hold_id"])["released_at"] is None


def test_the_release_records_the_session_operator(env):
    t = env.t
    h = _op_hold(env, t.a)
    with t.operator() as c:
        holds.release_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, operator_id="op-7",
                                    request_id="req-r", org_id=t.a.org_id, hold_id=h["hold_id"], reason="closed",
                                    crypto=t.crypto)
    row = _hold_row(env, t.a, h["hold_id"])
    assert (row["released_by_kind"], row["released_by"]) == ("operator", "op-7")


# The migration runner and the down file ----------------------------------------------------------------------------------
def test_a_migration_that_leaves_the_owner_role_is_rolled_back_by_name(pg_server, tmp_path):
    """A migrator login without the owner as its default role: a migration that runs RESET ROLE would make its later
    objects the login's own. The runner refuses it, names the fix, and keeps nothing."""
    from conftest import _dsn, create_vault_database, ensure_roles
    from consentvault import db
    from consentvault.errors import MigrationError

    port = pg_server["port"]
    ensure_roles(port)
    name, login = "m_" + uuid.uuid4().hex[:10], "mig_" + uuid.uuid4().hex[:10]
    create_vault_database(port, name)
    with psycopg.connect(_dsn(port, "postgres"), autocommit=True) as su:
        su.execute(f'CREATE ROLE "{login}" LOGIN IN ROLE cv_test_owner')  # no default role
    try:
        (tmp_path / "0001_leak.sql").write_text("CREATE TABLE consentvault.before_reset (i int);\nRESET ROLE;\n"
                                               "CREATE TABLE consentvault.after_reset (i int);\n")
        with db.connect(_dsn(port, name, login)) as m:
            with pytest.raises(MigrationError, match=f"ALTER ROLE {login} SET role = cv_test_owner"):
                db.migrate(m, tmp_path)
            assert m.execute("SELECT current_user AS u").fetchone()["u"] == login
        with psycopg.connect(_dsn(port, name), row_factory=psycopg.rows.dict_row) as su:
            assert su.execute("SELECT to_regclass('consentvault.before_reset') AS a, to_regclass('consentvault.after_reset')"
                              " AS b").fetchone() == {"a": None, "b": None}
            assert su.execute("SELECT pg_get_userbyid(nspowner) AS o FROM pg_namespace WHERE nspname = 'consentvault'"
                              ).fetchone()["o"] == "cv_test_owner"
    finally:
        # a second migration login on the shared owner would read, rightly, as one left open to every later start check;
        # dropped whether the assertions above passed or not
        with psycopg.connect(_dsn(port, "postgres"), autocommit=True) as su:
            su.execute(f'DROP ROLE IF EXISTS "{login}"')


def test_the_down_file_returns_the_release_to_its_earlier_shape_and_takes_the_console_grants(env):
    import os

    down = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "down", "0019_role_layout.sql")
    with env.t.superuser() as su:
        su.execute(open(down, encoding="utf-8").read())
        assert su.execute("SELECT prosecdef FROM pg_proc WHERE proname = 'release_hold_as_operator'"
                          ).fetchone() == {"prosecdef": False}
        assert su.execute("SELECT count(*) AS n FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace,"
                          " aclexplode(c.relacl) a WHERE ns.nspname = 'consentvault'"
                          " AND a.grantee = 'consentvault_console'::regrole").fetchone()["n"] == 0
        assert su.execute("SELECT count(*) AS n FROM pg_proc p JOIN pg_namespace ns ON ns.oid = p.pronamespace,"
                          " aclexplode(p.proacl) a WHERE ns.nspname = 'consentvault'"
                          " AND a.grantee = 'consentvault_console'::regrole").fetchone()["n"] == 0
        assert not su.execute("SELECT has_schema_privilege('consentvault_console', 'consentvault', 'USAGE') AS u"
                              ).fetchone()["u"]
        with pytest.raises(psycopg.errors.RaiseException, match="0019 is not applied"):
            su.execute(open(down, encoding="utf-8").read())
