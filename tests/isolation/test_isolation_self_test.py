"""The nightly isolation self-test (``consentvault isolation-self-test``): a canary organisation pair kept in the live vault
for this test only, and a proof, read from the database every night, that neither canary can read the other, or any
other organisation, through any table or view with row security.

The table list is the isolation suite's own registry (``consentvault.isolation.tenant_tables``: every table with an
org_id column, read from the catalog), so a table added later is covered without editing the job. Each table is checked
twice: its shape (row security enabled and forced, a tenant policy bound to ``current_org()``) and its behaviour (under
each canary's token, no row of another organisation is visible; with no token, nothing is). A table the job cannot read is
a finding, never a skip. The canaries are closed organisations: no sign-in, no capture, outside every evidence and
billing job."""

from error_names import named, named_any  # noqa: F401
import io
import json

import psycopg
import pytest

from consentvault import cmd_isolation_self_test, db, isolation, metrics

from .harness import PLATFORM_TABLES, make_login_role, tenant_tables, tenant_views

GROUP = "consentvault_isolation_self_test"


@pytest.fixture
def selftest(tenancy, pg_server):
    dbname = tenancy.operator_dsn.rsplit("/", 1)[1]
    tenancy.selftest_dsn = make_login_role(pg_server["port"], dbname, GROUP)
    return tenancy


def _run(t):
    return isolation.run(lambda: db.connect(t.selftest_dsn))


def _su(t, *sql):
    with psycopg.connect(t.super_dsn, autocommit=True) as su:
        for s in sql:
            su.execute(s)


def test_the_suite_and_the_job_read_one_registry():
    assert tenant_tables is isolation.tenant_tables and tenant_views is isolation.tenant_views
    assert PLATFORM_TABLES is isolation.PLATFORM_TABLES


def test_a_clean_vault_passes_and_every_tenant_table_and_view_is_probed(selftest):
    out = _run(selftest)
    with selftest.superuser() as su:
        tables, views = set(tenant_tables(su)), set(tenant_views(su))
    assert out["findings"] == [] and set(out["probed"]) == tables | views
    assert set(out["canaries"]) == {"a", "b"} and len(set(out["canaries"].values())) == 2
    assert out["positive_controls"] == {"a": {"organization": 1, "brand": 1, "capture_source": 1},
                                        "b": {"organization": 1, "brand": 1, "capture_source": 1}}
    assert _run(selftest)["canaries"] == out["canaries"]  # the pair is made once and kept


def test_the_canaries_are_closed_and_outside_every_evidence_and_billing_job(selftest):
    pair = _run(selftest)["canaries"]
    with selftest.superuser() as su:
        rows = su.execute("SELECT org_id::text AS o, status FROM consentvault.organization WHERE org_id = ANY(%s::uuid[])",
                          (list(pair.values()),)).fetchall()
        assert {r["status"] for r in rows} == {"closed"} and len(rows) == 2
        for fn in ("evidence_org_ids", "active_org_ids"):
            ids = {str(r["o"]) for r in su.execute(f"SELECT o FROM consentvault.{fn}() o")}
            assert not ids & set(pair.values()), fn


def test_the_self_test_login_holds_only_canary_tokens_and_reads_nothing_without_one(selftest):
    _run(selftest)
    with db.connect(selftest.selftest_dsn) as c:
        for table in ("event", "contact_key", "organization", "brand", "audit_event"):
            assert c.execute(f"SELECT count(*) AS n FROM consentvault.{table}").fetchone()["n"] == 0
        for forbidden in (f"SELECT consentvault.sign_org_token('{selftest.a.org_id}', ARRAY['admin'], NULL, 60)",
                          "SELECT consentvault.dispatch_org_token('seal', gen_random_uuid())",
                          "INSERT INTO consentvault.brand (org_id, display_name) VALUES (gen_random_uuid(), 'x')",
                          "SELECT * FROM consentvault.tenant_token_key",
                          "SELECT * FROM consentvault.isolation_canary"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute(forbidden)
        with pytest.raises(psycopg.errors.NoDataFound):
            with c.transaction():
                c.execute("SELECT consentvault.isolation_canary_token('c')")  # only the two canaries have a token


def test_a_policy_that_lets_rows_through_is_caught_by_shape_and_by_behaviour(selftest):
    _su(selftest, "DROP POLICY brand_tenant ON consentvault.brand",
        "CREATE POLICY brand_tenant ON consentvault.brand USING (true) WITH CHECK (true)")
    with pytest.raises(isolation.IsolationLeak) as e:
        _run(selftest)
    kinds = {(f["table"], f["kind"]) for f in e.value.report["findings"]}
    assert ("brand", "policy_not_bound_to_tenant") in kinds
    assert ("brand", "reads_other_organisations") in kinds
    leak = [f for f in e.value.report["findings"] if f["kind"] == "reads_other_organisations"]
    assert {f["canary"] for f in leak} == {"a", "b"} and all(f["rows"] >= 3 for f in leak)  # the pair and both real orgs
    assert "brand" in str(e.value)


def test_a_table_whose_row_security_is_not_forced_is_a_finding(selftest):
    _su(selftest, "ALTER TABLE consentvault.capture_source NO FORCE ROW LEVEL SECURITY")
    with pytest.raises(isolation.IsolationLeak) as e:
        _run(selftest)
    assert {(f["table"], f["kind"]) for f in e.value.report["findings"]} == {("capture_source", "row_security_not_forced")}


def test_a_table_the_self_test_cannot_read_is_a_finding_never_a_skip(selftest):
    _su(selftest, f"REVOKE SELECT ON consentvault.member FROM {GROUP}")
    with pytest.raises(isolation.IsolationLeak) as e:
        _run(selftest)
    [f] = e.value.report["findings"]
    assert (f["table"], f["kind"]) == ("member", "not_probed") and "InsufficientPrivilege" in f["reason"]


def test_a_canary_that_cannot_see_its_own_rows_fails_the_positive_control(selftest):
    _run(selftest)
    _su(selftest, "SET session_replication_role = replica",
        "DELETE FROM consentvault.brand WHERE org_id = (SELECT canary_org FROM consentvault.isolation_canary WHERE label = 'a')")
    with pytest.raises(isolation.IsolationLeak) as e:
        _run(selftest)
    assert {(f["table"], f["kind"], f.get("canary")) for f in e.value.report["findings"]} == {("brand", "probe_blind", "a")}


def test_a_table_a_later_migration_adds_is_granted_by_the_runner(selftest, tmp_path):
    """The migration runner grants the self-test group every org_id table a migration adds, in that migration's
    transaction, so the job covers it from the first night and a clean apply matches the live grants."""
    import shutil

    folder = tmp_path / "migrations"
    shutil.copytree(db.default_migrations_dir(), folder, ignore=shutil.ignore_patterns("down"))
    (folder / "9999_probe_table.sql").write_text(
        "CREATE TABLE consentvault.zz_probe (org_id uuid NOT NULL, note text);"
        " ALTER TABLE consentvault.zz_probe ENABLE ROW LEVEL SECURITY; ALTER TABLE consentvault.zz_probe FORCE ROW LEVEL SECURITY;"
        " CREATE POLICY zz_probe_tenant ON consentvault.zz_probe USING (org_id = (SELECT consentvault.current_org()))"
        " WITH CHECK (org_id = (SELECT consentvault.current_org()));")
    with db.connect(selftest.migrator_dsn) as m:
        assert db.migrate(m, folder) == ["9999_probe_table.sql"]
    with selftest.superuser() as su:
        assert su.execute("SELECT has_table_privilege(%s, 'consentvault.zz_probe', 'SELECT') AS g", (GROUP,)).fetchone()["g"]
    assert "zz_probe" in _run(selftest)["probed"]


def test_every_tenant_table_and_view_is_granted_to_the_self_test(selftest):
    """Every org_id table and view is readable by the self-test group (the runner grants each as its migration lands)."""
    with selftest.superuser() as su:
        missing = [r["relname"] for r in su.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = 'consentvault' AND c.relname = ANY(%s)"
            " AND NOT has_table_privilege(%s, c.oid, 'SELECT')",
            (list(tenant_tables(su)) + list(tenant_views(su)), GROUP)).fetchall()]
    assert missing == [], f"grant SELECT on these to {GROUP} in the migration that made them: {missing}"


def test_a_login_outside_the_group_is_refused(selftest):
    with pytest.raises(isolation.SelfTestLoginRefused) as e:
        isolation.run(selftest.app)
    assert GROUP in str(e.value)


# ---- the command --------------------------------------------------------------------------------------------------------------
def _cli(monkeypatch, outcome):
    out = io.StringIO()
    real = metrics.emit
    monkeypatch.setattr(metrics, "emit", lambda name, value, stream=None: real(name, value, stream=out))
    monkeypatch.setattr(cmd_isolation_self_test, "_run_job", lambda cfg: outcome())
    rc = cmd_isolation_self_test.run_command(None, None)
    return rc, {k: v for x in out.getvalue().splitlines() for k, v in json.loads(x).items() if k != "_aws"}


def test_the_command_exits_0_with_a_zero_metric_on_a_clean_run(monkeypatch, capsys):
    rc, m = _cli(monkeypatch, lambda: {"findings": [], "probed": ["brand"], "canaries": {}})
    assert rc == 0 and m == {"IsolationLeaks": 0} and json.loads(capsys.readouterr().out)["ok"] is True


def test_the_command_exits_3_with_the_count_on_a_leak(monkeypatch, capsys):
    rep = {"findings": [{"table": "brand", "kind": "reads_other_organisations", "canary": "a", "rows": 3}] * 2}

    def leak():
        raise isolation.IsolationLeak("leak", rep)
    rc, m = _cli(monkeypatch, leak)
    assert rc == 3 and m == {"IsolationLeaks": 2} and "brand" in capsys.readouterr().out


def test_the_command_exits_3_without_a_metric_on_the_wrong_login(monkeypatch, capsys):
    def refuse():
        raise isolation.SelfTestLoginRefused(f"not a member of {GROUP}")
    rc, m = _cli(monkeypatch, refuse)
    err = capsys.readouterr().err
    assert rc == 3 and m == {} and named("SelfTestLoginRefused", err) and GROUP not in err


def test_the_command_has_nothing_to_isolate_in_single_company_mode(monkeypatch, capsys):
    rc, m = _cli(monkeypatch, lambda: None)
    assert rc == 0 and m == {} and "single-company" in capsys.readouterr().out


# ---- a permissive policy on any role widens what that role reads; every one must be bound to the tenant ---------------
@pytest.mark.parametrize("planted", [
    "CREATE POLICY brand_app_open ON consentvault.brand AS PERMISSIVE FOR SELECT TO consentvault_app USING (true)",
    "CREATE POLICY brand_app_open ON consentvault.brand AS PERMISSIVE FOR ALL TO consentvault_app"
    " USING (true OR org_id = (SELECT consentvault.current_org()))"
    " WITH CHECK (org_id = (SELECT consentvault.current_org()))",
])
def test_an_open_permissive_policy_for_another_role_is_a_finding(selftest, planted):
    _su(selftest, planted)
    with pytest.raises(isolation.IsolationLeak) as e:
        _run(selftest)
    [f] = e.value.report["findings"]  # the self-test's own role never sees it: only the shape check can
    assert (f["table"], f["kind"], f["policy"]) == ("brand", "policy_not_bound_to_tenant", "brand_app_open")
    assert "consentvault_app" in f["roles"]


def test_a_narrowing_permissive_policy_and_a_restrictive_one_pass(selftest):
    _su(selftest, "CREATE POLICY brand_narrow ON consentvault.brand AS PERMISSIVE FOR SELECT TO consentvault_app"
                  " USING (org_id = (SELECT consentvault.current_org()) AND display_name <> '')",
        "CREATE POLICY brand_limit ON consentvault.brand AS RESTRICTIVE FOR SELECT USING (display_name <> '')")
    assert _run(selftest)["findings"] == []


# ---- the runner's grants: reads past row security are never granted --------------------------------------------------------
def _migrate_extra(selftest, tmp_path, sql_text, name="9999_extra.sql"):
    import shutil

    folder = tmp_path / "migrations"
    if not folder.exists():
        shutil.copytree(db.default_migrations_dir(), folder, ignore=shutil.ignore_patterns("down"))
    (folder / name).write_text(sql_text)
    with db.connect(selftest.migrator_dsn) as m:
        db.migrate(m, folder)


def _granted(selftest, obj, kind="table"):
    with selftest.superuser() as su:
        q = ("SELECT has_table_privilege(%s, %s, 'SELECT') AS g" if kind == "table"
             else "SELECT has_function_privilege(%s, %s, 'EXECUTE') AS g")
        return su.execute(q, (GROUP, obj)).fetchone()["g"]


def test_a_table_without_forced_row_security_is_never_granted_and_is_a_finding(selftest, tmp_path):
    _migrate_extra(selftest, tmp_path, "CREATE TABLE consentvault.zz_open (org_id uuid NOT NULL, note text);")
    assert not _granted(selftest, "consentvault.zz_open")
    with pytest.raises(isolation.IsolationLeak) as e:
        _run(selftest)
    assert {(f["table"], f["kind"]) for f in e.value.report["findings"]} >= {("zz_open", "row_security_off")}


def test_a_view_that_runs_with_its_owners_rights_is_never_granted_and_is_a_finding(selftest, tmp_path):
    _migrate_extra(selftest, tmp_path, "CREATE VIEW consentvault.zz_billing AS SELECT org_id FROM consentvault.billing_event;")
    assert not _granted(selftest, "consentvault.zz_billing")
    with pytest.raises(isolation.IsolationLeak) as e:
        _run(selftest)
    kinds = {(f["table"], f["kind"]) for f in e.value.report["findings"]}
    assert ("zz_billing", "view_not_security_invoker") in kinds


def test_an_owner_rights_function_or_overload_a_policy_calls_is_never_granted(selftest, tmp_path):
    _migrate_extra(selftest, tmp_path, """
        CREATE FUNCTION consentvault.zz_definer() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp AS $$ SELECT true $$;
        REVOKE ALL ON FUNCTION consentvault.zz_definer() FROM PUBLIC;
        CREATE FUNCTION consentvault.may_read_evidence(integer) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp AS $$ SELECT true $$;
        REVOKE ALL ON FUNCTION consentvault.may_read_evidence(integer) FROM PUBLIC;
        CREATE TABLE consentvault.zz_scoped (org_id uuid NOT NULL);
        ALTER TABLE consentvault.zz_scoped ENABLE ROW LEVEL SECURITY; ALTER TABLE consentvault.zz_scoped FORCE ROW LEVEL SECURITY;
        CREATE POLICY zz_scoped_tenant ON consentvault.zz_scoped USING (org_id = (SELECT consentvault.current_org()))
            WITH CHECK (org_id = (SELECT consentvault.current_org()));
        CREATE POLICY zz_scoped_read_scope ON consentvault.zz_scoped AS RESTRICTIVE FOR SELECT
            USING (consentvault.zz_definer() AND consentvault.may_read_evidence());""")
    assert _granted(selftest, "consentvault.zz_scoped")
    assert not _granted(selftest, "consentvault.zz_definer()", "function")
    assert not _granted(selftest, "consentvault.may_read_evidence(integer)", "function")
    assert _granted(selftest, "consentvault.may_read_evidence()", "function")


# ---- a login that reads past row security is refused ---------------------------------------------------------------------------
def test_a_superuser_or_bypassrls_login_is_refused(selftest, pg_server):
    with pytest.raises(isolation.SelfTestLoginRefused, match="superuser or bypasses row security"):
        isolation.run(selftest.superuser)
    dbname = selftest.operator_dsn.rsplit("/", 1)[1]
    dsn = make_login_role(pg_server["port"], dbname, GROUP)
    role = dsn.split("//", 1)[1].split("@", 1)[0]
    _su(selftest, f'ALTER ROLE "{role}" BYPASSRLS')
    with pytest.raises(isolation.SelfTestLoginRefused, match="bypasses row security"):
        isolation.run(lambda: db.connect(dsn))


EMAIL = "jane.doe@example.com"


def test_a_canary_pair_that_cannot_be_made_is_a_finding_without_its_error_text(selftest):
    _su(selftest, f"""CREATE FUNCTION consentvault.zz_refuse_canary() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'refused: owner {EMAIL}' USING ERRCODE = 'P0001', DETAIL = 'contact {EMAIL}'; END $$""",
        "CREATE TRIGGER zz_refuse_canary BEFORE INSERT ON consentvault.organization FOR EACH ROW"
        " EXECUTE FUNCTION consentvault.zz_refuse_canary()")
    with pytest.raises(isolation.IsolationLeak) as e:
        _run(selftest)
    assert e.value.report["findings"] == [{"table": None, "kind": "no_canary_pair",
                                           "reason": "RaiseException (SQLSTATE P0001)"}]
    assert EMAIL not in str(e.value) and EMAIL not in json.dumps(e.value.report) and e.value.__cause__ is None


def test_the_runner_skips_a_table_whose_row_security_is_enabled_but_not_forced(selftest, tmp_path):
    """Row security on but not forced: the table's owner reads past it, so the self-test group is never granted it. The
    second half removes the forced-row-security condition from the grant function and shows this test would catch it."""
    sql_text = ("CREATE TABLE consentvault.{t} (org_id uuid NOT NULL); ALTER TABLE consentvault.{t} ENABLE ROW LEVEL SECURITY;"
                " CREATE POLICY {t}_tenant ON consentvault.{t} USING (org_id = (SELECT consentvault.current_org()))"
                " WITH CHECK (org_id = (SELECT consentvault.current_org()));")
    _migrate_extra(selftest, tmp_path, sql_text.format(t="zz_unforced"), "9998_unforced.sql")
    assert not _granted(selftest, "consentvault.zz_unforced")
    with selftest.superuser() as su:  # the mutation: the same function without "AND c.relforcerowsecurity"
        body = su.execute("SELECT pg_get_functiondef('consentvault.isolation_self_test_grant_reads()'::regprocedure) AS d"
                          ).fetchone()["d"]
        assert " AND c.relforcerowsecurity" in body
        su.execute(body.replace(" AND c.relforcerowsecurity", ""))
    _migrate_extra(selftest, tmp_path, sql_text.format(t="zz_unforced2"), "9999_unforced.sql")
    assert _granted(selftest, "consentvault.zz_unforced2")  # without the condition the grant happens: the assertion bites
