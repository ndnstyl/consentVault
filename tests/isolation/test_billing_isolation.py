"""Billing isolation: every billing table and every owner-rights billing function, tenant A's credentials against
tenant B's rows. (Review condition: a new owner-rights function filters on current_org() itself and has an isolation
test; this file carries those tests for the billing functions.)

Runs on the schema billing depends on (0001-0003 and 0007), so a neighbour lane's unfinished migration cannot turn it red.
"""

import psycopg
import pytest

from billing.schema import apply_billing_schema
from consentvault import db
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from .harness import make_login_role


@pytest.fixture(autouse=True)
def no_records_tables(monkeypatch):
    """This suite runs on a partial schema that has no contact-record tables, so the writer that fills them is switched off here
    and nowhere else."""
    monkeypatch.setattr("consentvault.records.write_event_records", lambda *a, **k: "00000000-0000-0000-0000-000000000000")
    monkeypatch.setattr("consentvault.confirmations.enqueue_confirmation_intents", lambda *a, **k: 0)  # no confirmation tables here
    monkeypatch.setattr("consentvault.sync.outbox._echo_targets", lambda conn: set())  # no connector migration here


@pytest.fixture
def dsn(raw_dsn):
    apply_billing_schema(raw_dsn)
    return raw_dsn


def seed_billing(t):
    with t.superuser() as su:
        for i, org in enumerate((t.a, t.b)):
            su.execute("INSERT INTO consentvault.billing_account (org_id, stripe_customer_id) VALUES (%s, %s)",
                       (org.org_id, f"cus_org{i}"))
            su.execute("INSERT INTO consentvault.usage_day (org_id, day, events, gate_checks) VALUES (%s, '2026-10-01', %s, %s)",
                       (org.org_id, 10 + i, 100 + i))


def as_org(t, org, scopes, **kw):
    return mint_org_token(t.key, org.org_id, scopes, credential_id=None, **kw)


@pytest.mark.parametrize("table", ["billing_account", "usage_day", "org_status_history"])
def test_a_tenant_reads_only_its_own_billing_rows(tenancy, table):
    seed_billing(tenancy)
    with tenancy.app() as app:
        assert app.execute(f"SELECT count(*) AS n FROM consentvault.{table}").fetchone()["n"] == 0  # no tenant entered
    for org, other in ((tenancy.a, tenancy.b), (tenancy.b, tenancy.a)):
        with tenancy.app() as app, org_transaction(app, tenancy.token(org)):
            ids = {r["org_id"] for r in app.execute(f"SELECT org_id FROM consentvault.{table}")}
            assert ids == {org.org_id} and other.org_id not in ids


def test_a_tenant_cannot_write_billing_rows_for_itself_or_another(tenancy):
    for sql in ("INSERT INTO consentvault.usage_day (org_id, day, events) VALUES (consentvault.current_org(), '2026-10-02', 1)",
                "INSERT INTO consentvault.billing_account (org_id, stripe_customer_id) VALUES (consentvault.current_org(), 'cus_self')"):
        with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)), pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(sql)


def test_usage_functions_need_a_tenant_and_the_usage_scope(tenancy):
    with tenancy.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT consentvault.usage_events_for_day('2026-10-01')")
    for scopes in (["capture"], ["gate_read"], ["proof_read"], ["billing"]):
        for sql in ("SELECT consentvault.usage_events_for_day('2026-10-01')",
                    "SELECT consentvault.usage_record_day('2026-10-01', 1, 1)",
                    "SELECT * FROM consentvault.usage_target('2026-10-01')",
                    "SELECT consentvault.usage_mark_reported('2026-10-01', 'events', 'k')"):
            with tenancy.app() as app, org_transaction(app, as_org(tenancy, tenancy.a, scopes)), \
                    pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(sql)


def test_events_counted_are_the_tokens_own_org_only(tenancy):
    today = db.connect(tenancy.super_dsn).execute("SELECT (now() AT TIME ZONE 'UTC')::date AS d").fetchone()["d"]
    counts = {}
    for org in (tenancy.a, tenancy.b):
        with tenancy.app() as app, org_transaction(app, as_org(tenancy, org, ["worker:usage"])):
            counts[org.name] = app.execute("SELECT consentvault.usage_events_for_day(%s) AS n", (today,)).fetchone()["n"]
    with tenancy.superuser() as su:
        total = su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id IN (%s, %s)"
                           " AND (received_at AT TIME ZONE 'UTC')::date = %s", (tenancy.a.org_id, tenancy.b.org_id, today)).fetchone()["n"]
    assert counts == {"alpha": 2, "bravo": 2} and total == 4  # never the sum of both


def test_usage_writes_land_on_the_tokens_org_and_cannot_name_another(tenancy, pg_server):
    seed_billing(tenancy)
    worker = db.connect(make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker"))
    with worker:
        tok = worker.execute("SELECT token FROM consentvault.dispatch_orgs('usage') WHERE org_id = %s",
                             (tenancy.a.org_id,)).fetchone()["token"]
        with org_transaction(worker, tok):
            worker.execute("SELECT consentvault.usage_record_day('2026-10-03', 7, 70)")
            worker.execute("SELECT consentvault.usage_mark_reported('2026-10-03', 'events', 'k1')")
            target = worker.execute("SELECT * FROM consentvault.usage_target('2026-10-03')").fetchone()
            assert (target["events"], target["stripe_customer_id"]) == (7, "cus_org0")
            worker.execute("SELECT consentvault.usage_mark_reported('2026-10-01', 'gate_checks', 'k2')")  # same day as B's
    with tenancy.superuser() as su:
        b_rows = su.execute("SELECT day, events, stripe_ack FROM consentvault.usage_day WHERE org_id = %s",
                            (tenancy.b.org_id,)).fetchall()
    assert [(str(r["day"]), r["events"], r["stripe_ack"]) for r in b_rows] == [("2026-10-01", 11, {})]


def test_webhook_functions_are_the_app_roles_alone(tenancy, pg_server):
    worker = db.connect(make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker"))
    with worker:
        for sql in ("SELECT consentvault.billing_record_event('evt_1', 'x')",
                    "SELECT consentvault.billing_apply_status(gen_random_uuid(), 'active', 'invoice_paid', 'evt_1')",
                    "SELECT consentvault.billing_resolve_org('cus_1', NULL)"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute(sql)
    with tenancy.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT * FROM consentvault.billing_event")


def test_a_webhook_function_never_leaves_its_own_tenant_token_behind(tenancy):
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
        before = app.execute("SELECT consentvault.current_org() AS o").fetchone()["o"]
        app.execute("SELECT consentvault.billing_link_account(%s, 'cus_b', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
                    (tenancy.b.org_id,))
        app.execute("SELECT consentvault.billing_apply_status(%s, 'past_due', 'payment_failed', 'evt_9')", (tenancy.b.org_id,))
        assert app.execute("SELECT consentvault.current_org() AS o").fetchone()["o"] == before == tenancy.a.org_id
    with tenancy.app() as app:
        assert app.execute("SELECT consentvault.current_org() AS o").fetchone()["o"] is None


def test_an_organisation_cannot_be_linked_to_two_customers_nor_a_customer_to_two_organisations(tenancy):
    with tenancy.app() as app:
        app.execute("SELECT consentvault.billing_link_account(%s, 'cus_one', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
                    (tenancy.a.org_id,))
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            app.execute("SELECT consentvault.billing_link_account(%s, 'cus_two', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
                        (tenancy.a.org_id,))
        with pytest.raises(psycopg.errors.UniqueViolation):
            app.execute("SELECT consentvault.billing_link_account(%s, 'cus_one', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
                        (tenancy.b.org_id,))
        assert app.execute("SELECT consentvault.billing_resolve_org('cus_one', NULL) AS o").fetchone()["o"] == tenancy.a.org_id
