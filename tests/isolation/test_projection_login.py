"""The projection runs under a role that cannot read the configuration tables (migration 0093, one-door review round 9), so a hidden
read of live configuration, however it is written, raises at runtime instead of deciding a post. The static scan stays as a second
net. What this proves, and what it cannot:

* a planted read in each of the eleven forms the reviewer used to hide one from the source scan, and the two SQL forms, raises
  ``permission denied`` under the login (the post gets an attempt, never a decision);
* a SECURITY DEFINER function runs with its owner's rights and so is NOT stopped by the role: a changed body of one (the trigger
  functions on the tables the projection writes) is caught by the pinned body hashes below, and the list of triggers is pinned in
  the guard test.
"""

import uuid

import psycopg
import pytest

from consentvault import api, door
from .cloud_harness import attempts_of
from .test_door_site_key_state import _orgs, hw  # noqa: F401

CONFIG_TABLES = ("capture_source", "brand", "disclosure", "channel", "purpose", "credential", "tenancy_setting")


def _can(hw, sql, *params):
    with hw.t.superuser() as su:
        return su.execute(sql, params).fetchone()[0] if False else list(su.execute(sql, params).fetchone().values())[0]


def test_the_projection_role_cannot_read_any_configuration_table(hw):
    for t in CONFIG_TABLES:
        assert _can(hw, "SELECT has_table_privilege('consentvault_projection', %s, 'SELECT')", f"consentvault.{t}") is False, t
        assert _can(hw, "SELECT has_table_privilege('consentvault_app', %s, 'SELECT')", f"consentvault.{t}") or t in (
            "tenancy_setting", "credential", "capture_source", "brand", "disclosure", "channel", "purpose")   # the app may; the projection may not
    assert _can(hw, "SELECT has_column_privilege('consentvault_projection', 'consentvault.organization', 'default_region', 'SELECT')") is False
    assert _can(hw, "SELECT has_column_privilege('consentvault_projection', 'consentvault.organization', 'status', 'SELECT')") is True


def test_the_projection_role_holds_everything_the_app_holds_except_the_configuration(hw):
    """Drift: a table, function or sequence the app has gained and the projection has not (a migration that grants the app something
    must call consentvault.sync_projection_grants())."""
    with hw.t.superuser() as su:
        tables = su.execute(
            "SELECT c.relname AS t, p AS priv FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace,"
            " unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AS p WHERE n.nspname = 'consentvault' AND c.relkind IN ('r','p','v','m')"
            " AND has_table_privilege('consentvault_app', c.oid, p) AND NOT has_table_privilege('consentvault_projection', c.oid, p)"
            " AND c.relname <> ALL(%s)", (list(CONFIG_TABLES) + ["organization"],)).fetchall()
        funcs = su.execute(
            "SELECT p.oid::regprocedure::text AS f FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'consentvault'"
            " AND p.prokind IN ('f','p') AND has_function_privilege('consentvault_app', p.oid, 'EXECUTE')"
            " AND NOT has_function_privilege('consentvault_projection', p.oid, 'EXECUTE')"
            " AND (NOT p.prosecdef OR p.proname = ANY(%s))", (sorted(ALLOWED_DEFINERS),)).fetchall()
    assert tables == [] and funcs == [], (tables, funcs)


def _plant(hw, monkeypatch, statement):
    """Run ``statement(conn)`` first thing in the pure phase of a stop's projection; return (events added, the post's attempt classes)."""
    a = hw.cloud.a
    real = door.TenantBackend.prepare

    def planted(self, conn, payload, body, auth):
        statement(conn)
        return real(self, conn, payload, body, auth)

    monkeypatch.setattr(door.TenantBackend, "prepare", planted)
    with hw.t.superuser() as su:
        before = su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke'", (a.org.org_id,)).fetchone()["n"]
    hw.cloud.call("/v1/events", {"contact": "+12125550471", "event_type": "revoke", "channels": ["sms"], "purposes": ["*"],
                                 "method": "keyword", "origin": "consumer", "client_nonce": str(uuid.uuid4())},
                  token=hw.cloud.token(a, "capture"))
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    with hw.t.superuser() as su:
        after = su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke'", (a.org.org_id,)).fetchone()["n"]
        post = su.execute("SELECT org_id, post_id, seq, intake FROM consentvault.raw_post WHERE org_id = %s AND kind = 'post' ORDER BY seq DESC LIMIT 1",
                          (a.org.org_id,)).fetchone()
    return after - before, attempts_of(hw.t, post)


def _planted_cache():
    return None


def _live_helper_in_another_module(conn):
    return conn.execute("SELECT status FROM consentvault.capture_source").fetchall()


PLANTS = {
    "E1 whole-name constant in a variable": lambda c: c.execute(f"SELECT status FROM {'consentvault.capture_source'} WHERE source_id = %s", (uuid.uuid4(),)),
    "E2 quoted identifiers": lambda c: c.execute('SELECT status FROM "consentvault"."capture_source" WHERE source_id = %s', (uuid.uuid4(),)),
    "E3 upper case schema": lambda c: c.execute("SELECT status FROM CONSENTVAULT.capture_source WHERE source_id = %s", (uuid.uuid4(),)),
    "E4 whitespace around the dot": lambda c: c.execute("SELECT status FROM consentvault . capture_source WHERE source_id = %s", (uuid.uuid4(),)),
    "E5 search_path then unqualified": lambda c: (c.execute("SET search_path = consentvault, pg_catalog"),
                                                   c.execute("SELECT status FROM capture_source WHERE source_id = %s", (uuid.uuid4(),))),
    "E6 getattr indirection to projection_settings": lambda c: getattr(__import__("consentvault.tenancy.pipeline", fromlist=["x"]).CapturePipeline,
                                                                         "projection_" + "settings")(None, c, uuid.uuid4()),
    "E7 bound alias of projection_settings": lambda c: (lambda ps: ps(c, uuid.uuid4()))(
        __import__("consentvault.tenancy.pipeline", fromlist=["x"]).CapturePipeline.projection_settings.__get__(
            __import__("types").SimpleNamespace(region=None))),
    "E8 helper in another module": _live_helper_in_another_module,
    "E10 read from the rebuild path": lambda c: c.execute("SELECT status FROM consentvault.capture_source").fetchall(),
    "E11 psycopg sql.Identifier": lambda c: c.execute(psycopg.sql.SQL("SELECT status FROM {}").format(psycopg.sql.Identifier("consentvault", "capture_source"))),
    "S1 the region column": lambda c: c.execute("SELECT default_region FROM consentvault.organization"),
    "S2 the brands": lambda c: c.execute("SELECT brand_id FROM consentvault.brand"),
    "S3 the wording": lambda c: c.execute("SELECT sha256 FROM consentvault.disclosure"),
    "S4 the site keys": lambda c: c.execute("SELECT site_key_hash FROM consentvault.credential"),
}


@pytest.mark.parametrize("name", list(PLANTS))
def test_a_planted_read_of_configuration_raises_under_the_projection_login(hw, monkeypatch, name):
    added, attempts = _plant(hw, monkeypatch, PLANTS[name])
    assert added == 0 and "InsufficientPrivilege" in attempts, (name, added, attempts)


def test_the_projection_login_is_reset_after_every_projection(hw):
    hw.cloud.call("/v1/events", {"contact": "+12125550472", "event_type": "revoke", "channels": ["sms"], "purposes": ["*"],
                                 "method": "keyword", "origin": "consumer", "client_nonce": str(uuid.uuid4())},
                  token=hw.cloud.token(hw.cloud.a, "capture"))
    from consentvault.api import connect
    with connect(hw.cloud.settings.dsn) as conn:
        door.rebuild  # noqa: B018  (the module imports)
        assert conn.execute("SELECT current_user <> 'consentvault_projection' AS ok").fetchone()["ok"]


def test_a_planted_invoker_trigger_that_reads_configuration_raises_under_the_login(hw, monkeypatch):
    """The SQL form: a trigger (security INVOKER) added on a table the projection writes, reading configuration, runs with the
    projection's rights and raises. (A SECURITY DEFINER one does not; see the pinned bodies.)"""
    hw.cloud.call("/v1/events", {"contact": "+12125550473", "event_type": "revoke", "channels": ["sms"], "purposes": ["*"],
                                 "method": "keyword", "origin": "consumer", "client_nonce": str(uuid.uuid4())},
                  token=hw.cloud.token(hw.cloud.a, "capture"))   # a stored post for the insert below to point at
    with hw.t.superuser() as su:
        su.execute("CREATE FUNCTION consentvault.r9_plant() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN"
                   " PERFORM 1 FROM consentvault.capture_source; RETURN NEW; END $$")
        su.execute("CREATE TRIGGER r9_plant BEFORE INSERT ON consentvault.projection_attempt FOR EACH ROW EXECUTE FUNCTION consentvault.r9_plant()")
        su.execute("CREATE TRIGGER r9_plant2 BEFORE INSERT ON consentvault.raw_post_fact FOR EACH ROW EXECUTE FUNCTION consentvault.r9_plant()")
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with hw.t.app() as app:
                from consentvault.tenancy.tokens import org_transaction
                app.execute("SET ROLE consentvault_projection")
                with org_transaction(app, hw.t.token(hw.cloud.a.org)):
                    app.execute("INSERT INTO consentvault.projection_attempt (org_id, post_id, code_version, error_class)"
                                " SELECT %s, post_id, 'x', 'x' FROM consentvault.raw_post LIMIT 1", (hw.cloud.a.org.org_id,))
    finally:
        with hw.t.superuser() as su:
            su.execute("DROP TRIGGER r9_plant2 ON consentvault.raw_post_fact")
            su.execute("DROP TRIGGER r9_plant ON consentvault.projection_attempt")
            su.execute("DROP FUNCTION consentvault.r9_plant()")


PINNED_TRIGGER_FUNCTIONS = {
    "refuse_change": "a5eac1a38d7e6734", "check_chain_head": "7dfe756985548afb",
    "check_clear_contact_home_only": "e0342abb7255541a", "check_contact_salt": "04044692bf122be2",
    "check_received_at": "2715a692ae83657b", "check_release_ref": "c8250d80d1981c47", "check_grant_scope": "e4c419982af070ed",
    "check_verified_claim": "5b9a2ab480021b14", "refuse_change_except_key_digest": "c6315736a801eb28",
    "evidence_object_guard": "98dc3d43a094e412", "check_raw_post_chain": "f45b0a6d2d720fd4",
}
PROJECTION_TABLES = ("event", "evidence_object", "event_source_post", "raw_post", "raw_post_fact", "raw_post_request",
                     "projection_attempt", "raw_post_original_arrival")


def test_the_trigger_functions_on_every_table_the_projection_writes_are_pinned_by_body_hash(hw):
    import hashlib

    with hw.t.superuser() as su:
        rows = su.execute(
            "SELECT DISTINCT p.proname AS f, pg_get_functiondef(p.oid) AS d FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid"
            " JOIN pg_proc p ON p.oid = g.tgfoid JOIN pg_namespace ns ON ns.oid = c.relnamespace"
            " WHERE ns.nspname = 'consentvault' AND NOT g.tgisinternal AND c.relname = ANY(%s)", (list(PROJECTION_TABLES),)).fetchall()
    assert {r["f"]: hashlib.sha256(r["d"].encode()).hexdigest()[:16] for r in rows} == PINNED_TRIGGER_FUNCTIONS


# The security-definer functions the projection role may execute: its own plumbing and the identity lookups. Everything else that
# runs with its owner's rights (resolve_credential, the billing, connector and audit functions, ...) is out of its reach.
ALLOWED_DEFINERS = {"current_org", "home_org", "enter_org", "current_token_scopes", "current_token_claims", "may_read_evidence",
                    "ledger_lock_key", "raw_post_lock_key", "raw_post_head", "ledger_head", "contact_key_of", "receipt_of",
                    "request_counted", "arrival_at", "arrival_key", "arrival_place", "arrival_post_seq", "sync_targets",
                    "sync_echo_targets", "sync_advance_state", "sync_enqueue", "sync_enqueue_refresh", "confirmation_enqueue",
                    "record_upsert", "record_index_refresh", "record_display_write", "resolve_site_key", "resolve_site_key_times"}


def test_the_projection_role_executes_only_the_listed_definer_functions(hw):
    with hw.t.superuser() as su:
        got = {r["f"] for r in su.execute(
            "SELECT p.proname AS f FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'consentvault'"
            " AND p.prosecdef AND p.prokind IN ('f','p') AND has_function_privilege('consentvault_projection', p.oid, 'EXECUTE')"
            " AND NOT EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgfoid = p.oid)").fetchall()}
    assert got <= ALLOWED_DEFINERS, sorted(got - ALLOWED_DEFINERS)


@pytest.mark.parametrize("call", [
    "SELECT * FROM consentvault.resolve_credential(gen_random_uuid())",
    "SELECT * FROM consentvault.invite_lookup('x')",
    "SELECT * FROM consentvault.billing_resolve_org('x', gen_random_uuid())",
    "SELECT * FROM consentvault.confirmation_host_lookup('x')",
])
def test_a_planted_call_of_another_definer_function_raises_under_the_projection_login(hw, monkeypatch, call):
    added, attempts = _plant(hw, monkeypatch, lambda c: c.execute(call).fetchall())
    assert added == 0 and "InsufficientPrivilege" in attempts, (call, added, attempts)
