"""The console-member clause counts only memberships that let a role act as the console (migration 0026).

On a managed database the master user is not a superuser, holds CREATEROLE and BYPASSRLS, and PostgreSQL 16+ gives the role
that creates a role an admin-only membership in it (no INHERIT, no SET): it may grant the role, never act as it. The clause
follows only memberships with INHERIT or SET, so that automatic grant is not a console membership. There is no exemption by
role name or by rds_superuser membership: a console member that is a superuser, the owner or a member of it, or a member of
a BYPASSRLS role through an INHERIT or SET membership is a violation. On PostgreSQL 15 (no such columns) every membership
counts, as before."""

import re
import uuid
from pathlib import Path

import psycopg
import pytest

from consentvault import api

from .test_attacks_wave3_final import _drop, _login, _owner, _violations

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "deployment.md"


def _su(port):
    return psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True)


def _db(env):
    return env.t.app_dsn.rsplit("/", 1)[1]


def _named(env, *roles):
    return [v for v in _violations(env) if v["object_name"] in roles]


def _flagged(env, role):
    got = _named(env, role)
    assert got and "consentvault_console" in got[0]["problem"], _violations(env)
    with pytest.raises(api.StartupRefusedError, match=role):
        api.startup_check(env.t.app_dsn)


def _no_rds_superuser(port):
    with _su(port) as su:
        assert not su.execute("SELECT 1 FROM pg_roles WHERE rolname = 'rds_superuser'").fetchall(), \
            "a role named rds_superuser already exists on the test cluster"


def _master(port, membership="ADMIN OPTION, INHERIT FALSE, SET FALSE"):
    """The RDS master's shape: LOGIN CREATEROLE BYPASSRLS, not a superuser, holding a console membership granted with
    `membership` (by default admin-only, what PostgreSQL 16+ gives a role's creator)."""
    m = "master_" + uuid.uuid4().hex[:8]
    with _su(port) as su:
        su.execute(f'CREATE ROLE "{m}" LOGIN CREATEROLE BYPASSRLS')
        su.execute(f'GRANT consentvault_console TO "{m}" WITH {membership} GRANTED BY postgres')
    return m


def test_a_realistic_rds_master_with_only_admin_memberships_is_not_a_console_member(env, pg_server):
    port = pg_server["port"]
    master = _master(port)
    login = "x_" + uuid.uuid4().hex[:8]
    try:
        with psycopg.connect(f"postgresql://{master}@127.0.0.1:{port}/{_db(env)}", autocommit=True) as m:
            m.execute(f'CREATE ROLE "{login}" LOGIN IN ROLE consentvault_console')  # the server grants the creator admin
        with _su(port) as su:
            rows = su.execute(
                "SELECT r.rolname, m.admin_option, m.inherit_option, m.set_option FROM pg_auth_members m"
                " JOIN pg_roles r ON r.oid = m.roleid WHERE m.member = %s::regrole ORDER BY 1", (master,)).fetchall()
            attrs = su.execute("SELECT rolsuper, rolbypassrls, rolcreaterole FROM pg_roles WHERE rolname = %s",
                               (master,)).fetchone()
        assert attrs == (False, True, True)
        assert rows == sorted([("consentvault_console", True, False, False), (login, True, False, False)]), rows
        assert _named(env, master, login) == [], _violations(env)
        api.startup_check(env.t.app_dsn)
    finally:
        _drop(port, login)
        _drop(port, master)
    assert _violations(env) == []


@pytest.mark.parametrize("membership", ["INHERIT TRUE, SET FALSE", "INHERIT FALSE, SET TRUE",
                                        "ADMIN OPTION, INHERIT TRUE, SET FALSE", "ADMIN OPTION, INHERIT FALSE, SET TRUE"])
def test_a_master_whose_console_membership_can_inherit_or_set_role_is_a_violation(env, pg_server, membership):
    port = pg_server["port"]
    master = _master(port, membership)
    try:
        _flagged(env, master)
    finally:
        _drop(port, master)
    assert _violations(env) == []


def test_a_master_acting_as_the_console_through_its_own_login_is_a_violation(env, pg_server):
    """Admin-only on the console, but SET on a console login it made: it can act as the console through the login."""
    port = pg_server["port"]
    master = _master(port)
    login = "x_" + uuid.uuid4().hex[:8]
    try:
        with psycopg.connect(f"postgresql://{master}@127.0.0.1:{port}/{_db(env)}", autocommit=True) as m:
            m.execute(f'CREATE ROLE "{login}" LOGIN IN ROLE consentvault_console')
            m.execute(f'GRANT "{login}" TO "{master}" WITH INHERIT FALSE, SET TRUE')
        _flagged(env, master)
    finally:
        _drop(port, login)
        _drop(port, master)


@pytest.mark.parametrize("kind", ["bypassrls_attribute", "owner_member"])
def test_an_ordinary_console_member_that_bypasses_row_security_or_acts_as_the_owner_is_a_violation(
        env, pg_server, kind):
    port = pg_server["port"]
    if kind == "owner_member":
        with env.t.migrator() as m:
            role, _ = _login(env, port, "consentvault_console", _owner(m))
    else:
        role = "x_" + uuid.uuid4().hex[:8]
        with _su(port) as su:
            su.execute(f'CREATE ROLE "{role}" LOGIN BYPASSRLS IN ROLE consentvault_console')
    try:
        _flagged(env, role)
    finally:
        _drop(port, role)
    assert _violations(env) == []


def test_a_superuser_console_member_is_a_violation(env, pg_server):
    port = pg_server["port"]
    login = "x_" + uuid.uuid4().hex[:8]
    with _su(port) as su:
        su.execute(f'CREATE ROLE "{login}" LOGIN SUPERUSER IN ROLE consentvault_console')
    try:
        _flagged(env, login)
    finally:
        _drop(port, login)
    assert _violations(env) == []


# ---- the reviewer's attacks on a name-based exemption, kept: each must now fail to land ------------------------------------
def test_minting_a_role_named_rds_superuser_does_not_clear_a_flagged_master(env, pg_server):
    port = pg_server["port"]
    _no_rds_superuser(port)
    m = _master(port, "ADMIN OPTION, INHERIT TRUE, SET TRUE")
    try:
        assert _named(env, m), "precondition: flagged"
        with psycopg.connect(f"postgresql://{m}@127.0.0.1:{port}/{_db(env)}", autocommit=True) as c:
            c.execute("CREATE ROLE rds_superuser NOLOGIN")
            c.execute(f'GRANT rds_superuser TO "{m}"')
            assert c.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()[0] is False
        _flagged(env, m)
    finally:
        _drop(port, m)
        _drop(port, "rds_superuser")


def test_minting_rds_superuser_does_not_clear_a_bypassrls_console_login_it_creates(env, pg_server):
    port = pg_server["port"]
    _no_rds_superuser(port)
    m = _master(port)
    login = "x_" + uuid.uuid4().hex[:8]
    try:
        with psycopg.connect(f"postgresql://{m}@127.0.0.1:{port}/{_db(env)}", autocommit=True) as c:
            c.execute(f'CREATE ROLE "{login}" LOGIN BYPASSRLS IN ROLE consentvault_console')
            c.execute("CREATE ROLE rds_superuser NOLOGIN")
            c.execute(f'GRANT rds_superuser TO "{m}", "{login}"')
        _flagged(env, login)
    finally:
        _drop(port, login)
        _drop(port, m)
        _drop(port, "rds_superuser")


# ---- the migration files -------------------------------------------------------------------------------------------------
def _body(path):
    return re.search(r"CREATE OR REPLACE FUNCTION consentvault\.owner_rights_violations.*?\n\$\$;", path.read_text(),
                     re.S).group(0)


def test_the_down_migration_restores_the_0025_start_check_exactly():
    mig = ROOT / "migrations"
    assert _body(mig / "0025_partition_guard.sql") == _body(mig / "down" / "0026_rds_master_allowance.sql")


def test_the_start_check_names_no_role_to_exempt_and_counts_every_membership_where_the_columns_are_absent():
    body = _body(ROOT / "migrations" / "0026_rds_master_allowance.sql")
    console = body[body.index("acting(roleid, member) AS"):body.index("SELECT 'schema'")]
    assert "rds_superuser" not in console and "breakglass" not in console
    for col in ("inherit_option", "set_option"):  # PostgreSQL 15 has neither: a missing column reads as counting
        assert f"COALESCE((pg_catalog.to_jsonb(m) OPERATOR(pg_catalog.->>) '{col}')::pg_catalog.bool, true)" in console, col


def test_the_deployment_guide_names_no_break_glass_by_role_name():
    text = " ".join(DOCS.read_text().split())
    assert "granted `rds_superuser` membership by anyone other than the bootstrap" not in text
    assert "admin-only membership" in text and "`INHERIT` or `SET`" in text
