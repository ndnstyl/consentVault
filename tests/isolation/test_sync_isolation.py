"""Every owner-rights function of the suppression-sync lane, attacked across organisations.

Both organisations hold the same person (the fingerprints differ), a connected system with a signal credential, one
dead push and one pending push. Each test acts as organisation B on organisation A's ids, fingerprints, keys and rows
and asserts that nothing of A's is read, changed or revealed, and that B's own data answers normally. Also: the
runtime and worker roles hold no table privileges, scopes are enforced inside the functions, and the row-level fence
holds even when a function's own filter is bypassed (the owner is bound by FORCE).
"""

import uuid

import psycopg
import pytest

from consentvault.sync.connectors.webhook import TransportResult
from consentvault.tenancy.tokens import org_transaction

from sync.support import PHONES, SyncEnv

P1, P2 = PHONES[0], PHONES[1]


@pytest.fixture
def env(tenancy, pg_server):
    return SyncEnv(tenancy, pg_server["port"])


class Seed:
    def __init__(self, env: SyncEnv, org) -> None:
        self.org = org
        self.system = env.add_system(org, "crm", signal=True)
        env.transport.script(self.system.endpoint, 400)
        env.grant(org, P1)


@pytest.fixture
def two(env):
    a, b = Seed(env, env.t.a), Seed(env, env.t.b)
    env.run_worker()  # one dead push in each organisation
    for s in (a, b):
        env.grant(s.org, P2)  # one pending push in each
        s.dead = env.outbox(s.org, status="dead")[0]
        s.pending = env.outbox(s.org, status="pending")[0]
        s.fp = env.fp(s.org, P1)
    return env, a, b


def app_as(env, org, scopes):
    class Ctx:
        def __enter__(self):
            self.conn = env.t.app()
            self.tx = org_transaction(self.conn, env.t.token(org, scopes=scopes))
            self.tx.__enter__()
            return self.conn

        def __exit__(self, *exc):
            try:
                return self.tx.__exit__(*exc)
            finally:
                self.conn.close()

    return Ctx()


def worker_as(env, org):
    class Ctx:
        def __enter__(self):
            self.conn = env.worker_conn()
            self.tx = org_transaction(self.conn, env.dispatch(self.conn, org))
            self.tx.__enter__()
            return self.conn

        def __exit__(self, *exc):
            try:
                return self.tx.__exit__(*exc)
            finally:
                self.conn.close()

    return Ctx()


def row_of(env, outbox_id):
    return env.q("SELECT * FROM consentvault.outbox WHERE outbox_id = %s", (outbox_id,))[0]


# capture-side functions ---------------------------------------------------------------------------------------------------

def test_advance_state_refuses_another_organisations_event(two):
    env, a, b = two
    a_event = env.q("SELECT event_id FROM consentvault.event WHERE org_id = %s AND contact_fp = %s ORDER BY seq LIMIT 1", (a.org.org_id, a.fp))[0]["event_id"]
    before = env.q("SELECT * FROM consentvault.state_version WHERE org_id = %s ORDER BY contact_fp, purpose", (a.org.org_id,))
    with pytest.raises(psycopg.errors.NoDataFound):
        with app_as(env, b.org, ("capture",)) as c:
            c.execute("SELECT * FROM consentvault.sync_advance_state(%s, %s)", (a_event, a.fp))
    assert env.q("SELECT * FROM consentvault.state_version WHERE org_id = %s ORDER BY contact_fp, purpose", (a.org.org_id,)) == before


def test_advance_state_refuses_a_fingerprint_that_is_not_the_events(two):
    env, a, b = two
    b_event = env.q("SELECT event_id FROM consentvault.event WHERE org_id = %s AND contact_fp = %s ORDER BY seq LIMIT 1", (b.org.org_id, b.fp))[0]["event_id"]
    with pytest.raises(psycopg.errors.InvalidParameterValue):
        with app_as(env, b.org, ("capture",)) as c:
            c.execute("SELECT * FROM consentvault.sync_advance_state(%s, %s)", (b_event, a.fp))


def test_targets_list_only_the_callers_systems(two):
    env, a, b = two
    with app_as(env, b.org, ("capture",)) as c:
        got = {r["system_id"] for r in c.execute("SELECT * FROM consentvault.sync_targets()").fetchall()}
    assert got == {b.system.system_id} and a.system.system_id not in got


def test_enqueue_refuses_another_organisations_system_and_state(two):
    env, a, b = two
    with pytest.raises(psycopg.errors.NoDataFound):
        with app_as(env, b.org, ("capture",)) as c:
            ev = c.execute("SELECT 1").fetchone()
            from consentvault.ledger import record_tenant_event
            e = record_tenant_event(c, env.t.crypto, contact=PHONES[5], event_type="grant", channels=["sms"],
                                    purposes=["marketing"], method="checkbox", origin="consumer", disclosure_sha256=b.org.disclosure)
            fp = env.fp(b.org, PHONES[5])
            c.execute("SELECT * FROM consentvault.sync_advance_state(%s, %s)", (e.event_id, fp)).fetchall()
            c.execute("SELECT consentvault.sync_enqueue(%s, %s, %s, 'sms', 'marketing', 1, %s)",
                      (uuid.uuid4(), a.system.system_id, fp, b"x"))  # B's fresh state, A's system
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        with app_as(env, b.org, ("capture",)) as c:
            c.execute("SELECT consentvault.sync_enqueue(%s, %s, %s, 'sms', 'marketing', 1, %s)",
                      (uuid.uuid4(), b.system.system_id, a.fp, b"x"))  # A's contact, never advanced here
    assert len(env.outbox(a.org)) == 2


def test_binding_a_credential_never_crosses_organisations(two):
    env, a, b = two
    with pytest.raises(psycopg.errors.NoDataFound):
        with app_as(env, b.org, ("admin",)) as c:
            c.execute("SELECT consentvault.sync_system_bind_credential(%s, %s)", (a.system.system_id, b.org.credential_id))
    with pytest.raises(psycopg.errors.NoDataFound):
        with app_as(env, b.org, ("admin",)) as c:
            c.execute("SELECT consentvault.sync_system_bind_credential(%s, %s)", (b.system.system_id, a.org.credential_id))
    assert env.q("SELECT signal_credential_id FROM consentvault.connected_system WHERE system_id = %s", (a.system.system_id,))[0]["signal_credential_id"] == a.org.credential_id


def test_the_credential_lookup_does_not_resolve_another_organisations_credential(two):
    env, a, b = two
    with app_as(env, b.org, ("capture",)) as c:
        assert c.execute("SELECT consentvault.sync_system_of_credential(%s) AS s", (a.org.credential_id,)).fetchone()["s"] is None
        assert c.execute("SELECT consentvault.sync_system_of_credential(%s) AS s", (b.org.credential_id,)).fetchone()["s"] == b.system.system_id


def test_the_ledger_state_lookup_sees_only_the_callers_ledger(two):
    env, a, b = two
    only_a = PHONES[9]
    env.grant(a.org, only_a)
    with app_as(env, b.org, ("capture",)) as c:
        assert c.execute("SELECT consentvault.sync_ledger_state(%s, 'sms', 'marketing') AS s", (env.fp(a.org, only_a),)).fetchone()["s"] is None
        assert c.execute("SELECT consentvault.sync_ledger_state(%s, 'sms', 'marketing') AS s", (a.fp,)).fetchone()["s"] is None
    with app_as(env, a.org, ("capture",)) as c:
        assert c.execute("SELECT consentvault.sync_ledger_state(%s, 'sms', 'marketing') AS s", (env.fp(a.org, only_a),)).fetchone()["s"] == "permitted"


def test_signal_lookup_and_record_never_cross_organisations(two):
    env, a, b = two
    from consentvault.sync.signals import parse_signal, process_signal
    with app_as(env, a.org, ("capture",)) as c:
        res = process_signal(c, env.t.crypto, org_id=a.org.org_id, system_id=a.system.system_id,
                             signal=parse_signal({"contact": P2, "channel": "sms", "purpose": "marketing",
                                                  "claimed_state": "denied", "external_ref": "A-1"}))
    mac = env.q("SELECT external_ref_mac FROM consentvault.inbound_signal WHERE signal_id = %s", (res.signal_id,))[0]["external_ref_mac"]
    with app_as(env, b.org, ("capture",)) as c:
        assert c.execute("SELECT * FROM consentvault.sync_signal_lookup(%s, %s)", (a.system.system_id, mac)).fetchall() == []
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with app_as(env, b.org, ("capture",)) as c:
            c.execute("SELECT consentvault.sync_signal_record(%s, %s, %s, 'sms', 'marketing', 'denied', NULL, 'no_change', NULL, %s, %s)",
                      (uuid.uuid4(), a.system.system_id, a.fp, b"x", "f" * 64))
    assert env.q("SELECT count(*) AS n FROM consentvault.inbound_signal")[0]["n"] == 1


# worker-side functions -------------------------------------------------------------------------------------------------------

def test_claim_hands_a_worker_only_its_own_organisations_pushes(two):
    env, a, b = two
    with worker_as(env, b.org) as w:
        rows = w.execute("SELECT * FROM consentvault.sync_claim(50, 60)").fetchall()
    assert [r["outbox_id"] for r in rows] == [b.pending["outbox_id"]]
    assert row_of(env, a.pending["outbox_id"])["status"] == "pending" and row_of(env, a.pending["outbox_id"])["attempts"] == 0
    assert all(r["system_id"] == b.system.system_id for r in rows)


def test_complete_and_release_never_touch_another_organisations_attempt(two):
    env, a, b = two
    with worker_as(env, a.org) as w:
        held = w.execute("SELECT * FROM consentvault.sync_claim(50, 60)").fetchall()
    assert [r["outbox_id"] for r in held] == [a.pending["outbox_id"]]
    with pytest.raises(psycopg.errors.NoDataFound):
        with worker_as(env, b.org) as w:
            w.execute("SELECT consentvault.sync_complete(%s, 1, 'acknowledged', 200, NULL, NULL, NULL)",
                      (a.pending["outbox_id"],))
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        with worker_as(env, b.org) as w:
            w.execute("SELECT consentvault.sync_release(%s, 1, 60)", (a.pending["outbox_id"],))
    now = row_of(env, a.pending["outbox_id"])
    assert (now["status"], now["attempts"]) == ("sent", 1)
    assert env.q("SELECT status FROM consentvault.delivery WHERE outbox_id = %s", (a.pending["outbox_id"],)) == [{"status": "sent"}]


def test_dead_groups_and_alarm_acknowledgement_stay_inside_the_organisation(two):
    env, a, b = two
    env.q("UPDATE consentvault.outbox SET alarmed_at = NULL WHERE status = 'dead'")
    with worker_as(env, b.org) as w:
        groups = w.execute("SELECT * FROM consentvault.sync_dead_groups()").fetchall()
        assert [(g["system_id"], list(g["outbox_ids"])) for g in groups] == [(b.system.system_id, [b.dead["outbox_id"]])]
        assert w.execute("SELECT consentvault.sync_ack_alarms(%s) AS n", ([a.dead["outbox_id"]],)).fetchone()["n"] == 0
    assert row_of(env, a.dead["outbox_id"])["alarmed_at"] is None


def test_refreshing_redrives_finishes_only_the_callers(two):
    env, a, b = two
    from consentvault.tenancy.tokens import org_transaction as _tx  # noqa: F401
    with app_as(env, a.org, ("admin",)) as c:
        ra = c.execute("SELECT * FROM consentvault.sync_redrive_start(%s, 'fixed', 'x')", (a.system.system_id,)).fetchone()
    with app_as(env, b.org, ("admin",)) as c:
        c.execute("SELECT * FROM consentvault.sync_redrive_start(%s, 'fixed', 'x')", (b.system.system_id,)).fetchone()
    env.q("UPDATE consentvault.outbox SET status = 'acknowledged', finished_at = now(), next_attempt_at = NULL WHERE redrive_id IS NOT NULL")
    with worker_as(env, b.org) as w:
        w.execute("SELECT consentvault.sync_refresh_redrives()")
    states = {r["org_id"]: r["status"] for r in env.q("SELECT org_id, status FROM consentvault.redrive_run")}
    assert states == {a.org.org_id: "running", b.org.org_id: "done"} and ra["redrive_id"]


# portal and query functions -----------------------------------------------------------------------------------------------------

def test_delivery_lists_never_show_another_organisations_system_or_contact(two):
    env, a, b = two
    with app_as(env, b.org, ("admin",)) as c:
        with pytest.raises(psycopg.errors.NoDataFound):
            c.execute("SELECT * FROM consentvault.sync_deliveries_of_system(%s, NULL, NULL, NULL, 50, NULL, NULL)", (a.system.system_id,))
    with pytest.raises(psycopg.errors.NoDataFound):
        with app_as(env, b.org, ("admin",)) as c:
            c.execute("SELECT * FROM consentvault.sync_deliveries_of_contact(%s, %s, 50, NULL, NULL)", (a.fp, a.system.system_id))
    with app_as(env, b.org, ("admin",)) as c:
        mine = c.execute("SELECT * FROM consentvault.sync_deliveries_of_system(%s, NULL, NULL, NULL, 50, NULL, NULL)", (b.system.system_id,)).fetchall()
        assert {r["outbox_id"] for r in mine} == {b.dead["outbox_id"], b.pending["outbox_id"]}
        assert c.execute("SELECT * FROM consentvault.sync_deliveries_of_contact(%s, %s, 50, NULL, NULL)", (a.fp, b.system.system_id)).fetchall() == []
        own = c.execute("SELECT * FROM consentvault.sync_deliveries_of_contact(%s, %s, 50, NULL, NULL)", (b.fp, b.system.system_id)).fetchall()
        assert [r["outbox_id"] for r in own] == [b.dead["outbox_id"]]


def test_redrive_never_requeues_another_organisations_dead_pushes(two):
    env, a, b = two
    with pytest.raises(psycopg.errors.NoDataFound):
        with app_as(env, b.org, ("admin",)) as c:
            c.execute("SELECT * FROM consentvault.sync_redrive_start(%s, 'sneaky', 'x')", (a.system.system_id,))
    assert row_of(env, a.dead["outbox_id"])["status"] == "dead" and env.q("SELECT 1 FROM consentvault.redrive_run") == []


def test_redrive_status_never_answers_for_another_organisation(two):
    env, a, b = two
    with app_as(env, a.org, ("admin",)) as c:
        rid = c.execute("SELECT * FROM consentvault.sync_redrive_start(%s, 'fixed', 'x')", (a.system.system_id,)).fetchone()["redrive_id"]
    with pytest.raises(psycopg.errors.NoDataFound):
        with app_as(env, b.org, ("admin",)) as c:
            c.execute("SELECT * FROM consentvault.sync_redrive_status(%s)", (rid,))
    with app_as(env, a.org, ("developer",)) as c:
        assert c.execute("SELECT * FROM consentvault.sync_redrive_status(%s)", (rid,)).fetchone()["system_id"] == a.system.system_id


def test_a_worker_run_for_one_organisation_sends_nothing_of_the_others(two):
    env, a, b = two
    env.transport.sent.clear()
    with env.worker_conn() as w:
        env.make_worker().run_org(w, b.org.org_id, env.dispatch(w, b.org))
    assert {r.target_url for r in env.transport.sent} == {b.system.endpoint}
    assert row_of(env, a.pending["outbox_id"])["status"] == "pending"


# privileges, scopes and the row-level fence ---------------------------------------------------------------------------------------

SYNC_TABLES = ("outbox", "delivery", "state_version", "inbound_signal", "redrive_run")


@pytest.mark.parametrize("who", ["app", "worker"])
@pytest.mark.parametrize("table", SYNC_TABLES)
def test_no_runtime_role_holds_a_privilege_on_a_sync_table(two, who, table):
    env, a, b = two
    conn = env.t.app() if who == "app" else env.worker_conn()
    with conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(conn, env.t.token(a.org, scopes=("admin",)) if who == "app" else env.dispatch(conn, a.org)):
                conn.execute(f"SELECT * FROM consentvault.{table}")
        for verb in ("INSERT INTO consentvault.%s DEFAULT VALUES", "UPDATE consentvault.%s SET org_id = org_id", "DELETE FROM consentvault.%s"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with org_transaction(conn, env.t.token(a.org, scopes=("admin",)) if who == "app" else env.dispatch(conn, a.org)):
                    conn.execute(verb % table)


def test_the_signing_credential_is_unreadable_to_the_runtime_roles(two):
    env, a, b = two
    with env.t.app() as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(c, env.t.token(a.org, scopes=("admin",))):
                c.execute("SELECT credentials_ct FROM consentvault.connected_system")
    with env.worker_conn() as w:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(w, env.dispatch(w, a.org)):
                w.execute("SELECT credentials_ct FROM consentvault.connected_system")


def test_a_worker_token_reads_no_evidence_row(two):
    env, a, b = two
    with env.worker_conn() as w:
        for table in ("event", "contact_key", "contact_log", "review"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with org_transaction(w, env.dispatch(w, a.org)):
                    w.execute(f"SELECT * FROM consentvault.{table}")


@pytest.mark.parametrize("fn,args", [
    ("sync_advance_state(%s::uuid, %s)", (uuid.uuid4(), "a" * 64)),
    ("sync_targets()", ()),
    ("sync_ledger_state(%s, 'sms', 'marketing')", ("a" * 64,)),
])
def test_capture_side_functions_refuse_a_worker_token(two, fn, args):
    env, a, b = two
    with env.t.migrator() as o:  # the owner's rights can execute everything, so only the scope check refuses
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="none of the scopes"):
            with org_transaction(o, env.dispatch(env.worker_conn(), a.org)):
                o.execute(f"SELECT * FROM consentvault.{fn}", args)


@pytest.mark.parametrize("fn,args", [
    ("sync_claim(5, 60)", ()),
    ("sync_dead_groups()", ()),
    ("sync_refresh_redrives()", ()),
    ("sync_ack_alarms(ARRAY[]::uuid[])", ()),
])
@pytest.mark.parametrize("scope", ["capture", "admin", "proof_read", "developer", "gate_read"])
def test_worker_functions_refuse_every_non_worker_scope(two, fn, args, scope):
    env, a, b = two
    with env.t.migrator() as o:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="none of the scopes"):
            with org_transaction(o, env.t.token(a.org, scopes=(scope,))):
                o.execute(f"SELECT * FROM consentvault.{fn}", args)


@pytest.mark.parametrize("fn", [
    "sync_deliveries_of_contact(%s, %s, 50, NULL, NULL)",
])
def test_the_contact_delivery_query_refuses_the_developer_scope(two, fn):
    env, a, b = two
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="none of the scopes"):
        with app_as(env, a.org, ("developer",)) as c:
            c.execute(f"SELECT * FROM consentvault.{fn}", (a.fp, a.system.system_id))


def test_redrive_and_system_lists_refuse_a_capture_token(two):
    env, a, b = two
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with app_as(env, a.org, ("capture",)) as c:
            c.execute("SELECT * FROM consentvault.sync_redrive_start(%s, 'r', 'x')", (a.system.system_id,))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with app_as(env, a.org, ("capture",)) as c:
            c.execute("SELECT * FROM consentvault.sync_deliveries_of_system(%s, NULL, NULL, NULL, 5, NULL, NULL)", (a.system.system_id,))


def test_the_worker_role_cannot_call_the_capture_side_and_the_app_role_cannot_call_the_worker_side(two):
    env, a, b = two
    with env.worker_conn() as w:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(w, env.dispatch(w, a.org)):
                w.execute("SELECT * FROM consentvault.sync_targets()")
    with env.t.app() as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(c, env.t.token(a.org, scopes=("capture",))):
                c.execute("SELECT * FROM consentvault.sync_claim(5, 60)")


def test_the_internal_helpers_are_callable_by_nobody_but_the_owner(two):
    env, a, b = two
    for role in ("consentvault_app", "consentvault_worker"):
        for fn in ("sync_org(text[])", "sync_redrive_refresh(uuid)"):
            assert env.q("SELECT has_function_privilege(%s, %s, 'EXECUTE') AS ok", (role, f"consentvault.{fn}"))[0]["ok"] is False


def test_every_sync_function_is_owned_by_the_schema_owner_and_pins_its_search_path(two):
    env, a, b = two
    rows = env.q("SELECT p.proname, pg_get_userbyid(p.proowner) AS owner, p.prosecdef, p.proconfig, r.rolsuper, r.rolbypassrls"
                 " FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner JOIN pg_namespace n ON n.oid = p.pronamespace"
                 " WHERE n.nspname = 'consentvault' AND p.proname LIKE 'sync\\_%'")
    # 21: sync_system_unbind_credential (0011); 36 with the Twenty connector's 15 (0060); 37 with sync_attempt_started (0062),
    # which stamps a push's attempt time when that push starts
    assert len(rows) == 37, sorted(r["proname"] for r in rows)
    for r in rows:
        # the receiver resolver reads across organisations by design (only the hash it is given; it answers an org, a system
        # and a status), as resolve_site_key does: its owner is the operator role, which bypasses row security
        assert r["prosecdef"] and not r["rolsuper"] and (not r["rolbypassrls"] or r["proname"] == "sync_receiver_resolve"), r["proname"]
        assert any("search_path=pg_catalog, pg_temp" in c for c in (r["proconfig"] or [])), r["proname"]
    # the Twenty receiver resolves its id before a tenant is entered, so the operator role owns that one reader (as the
    # site-key lookup); every other sync function has the schema owner
    assert {r["owner"] for r in rows if r["proname"] == "sync_receiver_resolve"} == {"consentvault_operator"}
    assert len({r["owner"] for r in rows if r["proname"] != "sync_receiver_resolve"}) == 1


def test_the_row_level_fence_holds_even_without_a_functions_own_filter(two):
    env, a, b = two
    with env.t.migrator() as o:  # the owner's rights are bound by FORCE; a function that forgot its filter is still fenced
        for org, other in ((a.org, b.org), (b.org, a.org)):
            with org_transaction(o, env.t.admin_token(org.org_id)):
                for table in SYNC_TABLES + ("connected_system",):
                    orgs = {r["org_id"] for r in o.execute(f"SELECT org_id FROM consentvault.{table}").fetchall()}
                    assert orgs <= {org.org_id}, table
                    assert orgs or table in ("inbound_signal", "redrive_run"), table
                    assert o.execute(f"SELECT count(*) AS n FROM consentvault.{table} WHERE org_id = %s", (other.org_id,)).fetchone()["n"] == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):  # and cannot write a row for the other organisation
            with org_transaction(o, env.t.admin_token(a.org.org_id)):
                o.execute("INSERT INTO consentvault.redrive_run (org_id, system_id, reason) VALUES (%s, %s, 'x')", (b.org.org_id, b.system.system_id))
    assert env.q("SELECT 1 FROM consentvault.redrive_run") == []


def test_no_token_in_multi_mode_reads_nothing_and_calls_nothing(two):
    env, a, b = two
    with env.t.migrator() as o:
        for table in SYNC_TABLES + ("connected_system",):
            assert o.execute(f"SELECT count(*) AS n FROM consentvault.{table}").fetchone()["n"] == 0
        with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
            o.execute("SELECT * FROM consentvault.sync_targets()")
    with env.worker_conn() as w:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            w.execute("SELECT * FROM consentvault.outbox")


def test_a_forged_token_is_refused_by_every_function(two):
    env, a, b = two
    with env.t.migrator() as o:
        o.execute("SELECT set_config('consentvault.org_token', %s, false)", ("v1.test-k1.00.00",))
        try:
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                o.execute("SELECT * FROM consentvault.sync_targets()")
            with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
                o.execute("SELECT * FROM consentvault.sync_claim(5, 60)")
        finally:
            o.execute("SELECT set_config('consentvault.org_token', '', false)")
