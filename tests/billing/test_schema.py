"""Migration 0007: statuses, history, live statuses for capture, down migration, the no-card-data rule."""

import psycopg
import pytest

from consentvault import db
from consentvault.ledger import record_tenant_event
from consentvault.tenancy.tokens import org_transaction

from .helpers import history, set_status

DOWN = db.default_migrations_dir() / "down" / "0007_billing.sql"


def test_every_status_in_the_contract_is_accepted_and_nothing_else(tenancy):
    for status in ("trial", "active", "past_due", "suspended", "offboarding", "closed"):
        set_status(tenancy, tenancy.a, status)
    with tenancy.superuser() as su, pytest.raises(psycopg.errors.CheckViolation):
        su.execute("UPDATE consentvault.organization SET status = 'paused' WHERE org_id = %s", (tenancy.a.org_id,))


def test_each_status_change_writes_one_history_row_with_cause_and_actor(tenancy):
    rows = history(tenancy, tenancy.a)
    assert [(r["seq"], r["status"], r["cause"]) for r in rows] == [(1, "active", "created")]
    set_status(tenancy, tenancy.a, "suspended")
    set_status(tenancy, tenancy.a, "suspended")  # no change, no row
    with tenancy.superuser() as su, su.transaction():
        su.execute("SELECT set_config('consentvault.status_cause', 'offboard_run', true),"
                   " set_config('consentvault.status_actor', 'run-7', true)")
        su.execute("UPDATE consentvault.organization SET status = 'offboarding' WHERE org_id = %s", (tenancy.a.org_id,))
    rows = history(tenancy, tenancy.a)
    assert [(r["seq"], r["status"], r["cause"], r["actor"]) for r in rows[1:]] == [
        (2, "suspended", "operator", "unknown"), (3, "offboarding", "offboard_run", "run-7")]


def test_history_is_append_only_and_hidden_from_other_tenants(tenancy):
    with tenancy.superuser() as su:
        for sql in ("UPDATE consentvault.org_status_history SET actor = 'x'", "DELETE FROM consentvault.org_status_history",
                    "TRUNCATE consentvault.org_status_history"):
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
                su.execute(sql)
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
        assert {r["org_id"] for r in app.execute("SELECT org_id FROM consentvault.org_status_history")} == {
            tenancy.a.org_id}


@pytest.mark.parametrize("status,expected", [("trial", "active"), ("active", "active"), ("past_due", "active"),
                                             ("suspended", "org_suspended"), ("offboarding", "org_offboarding"),
                                             ("closed", "org_closed")])
def test_trial_and_past_due_orgs_are_live_for_capture_lookups(tenancy, status, expected):
    set_status(tenancy, tenancy.a, status)
    with tenancy.app() as app:
        assert app.execute("SELECT status FROM consentvault.resolve_credential(%s)",
                           (tenancy.a.credential_id,)).fetchone()["status"] == expected
    with tenancy.operator() as owner:
        live = {r["active_org_ids"] for r in owner.execute("SELECT * FROM consentvault.active_org_ids()")}
    with tenancy.app() as app:
        members = app.execute("SELECT * FROM consentvault.resolve_member('https://idp.example.com', 'user_alpha')").fetchall()
    assert (tenancy.a.org_id in live) == (expected == "active") and bool(members) == (expected == "active")



def test_capture_is_recorded_while_an_org_is_past_due_or_in_trial(tenancy):
    """Nothing in billing can refuse an event for non-payment: the ledger path never reads the status."""
    for status in ("past_due", "trial"):
        set_status(tenancy, tenancy.a, status)
        with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
            ev = record_tenant_event(app, tenancy.crypto, contact="+15555550199", event_type="grant", channels=["sms"],
                                     purposes=["marketing"], method="checkbox", origin="consumer",
                                     disclosure_sha256=tenancy.a.disclosure, source_id=tenancy.a.source_id,
                                     brand_ids=[tenancy.a.brand_id], payload=b"{}")
        assert ev.seq >= 1


def test_no_table_holds_card_bank_or_address_columns(tenancy):
    with tenancy.superuser() as su:
        cols = {r["column_name"] for r in su.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'consentvault'"
            " AND table_name IN ('billing_account', 'billing_event', 'usage_day', 'org_status_history')")}
    banned = ("card", "pan", "cvc", "iban", "routing", "account_number", "address", "street", "postal", "email", "name_on")
    assert not [c for c in cols if any(b in c for b in banned)], cols
    assert "stripe_customer_id" in cols


def test_billing_tables_are_not_writable_by_the_runtime_role(tenancy):
    with tenancy.app() as app:
        for sql in ("INSERT INTO consentvault.billing_account (org_id, stripe_customer_id) VALUES (gen_random_uuid(), 'cus_x')",
                    "UPDATE consentvault.usage_day SET events = 1", "SELECT * FROM consentvault.billing_event",
                    "UPDATE consentvault.organization SET status = 'closed'"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(sql)


def test_down_migration_restores_the_older_schema_and_refuses_while_billing_data_exists(tenancy):
    sql = DOWN.read_text()
    with tenancy.superuser() as su:
        with pytest.raises(psycopg.errors.RaiseException, match="billing accounts, webhook events or usage counts"):
            su.execute("INSERT INTO consentvault.billing_event (stripe_event_id, type) VALUES ('evt_1', 'x')")
            su.execute(sql)
    with tenancy.superuser() as su:
        su.rollback()
        su.execute("DELETE FROM consentvault.billing_event")
        set_status(tenancy, tenancy.a, "past_due")
        with pytest.raises(psycopg.errors.RaiseException, match="trial or past_due"):
            su.execute(sql)
        su.rollback()
        su.execute("UPDATE consentvault.organization SET status = 'suspended' WHERE org_id = %s", (tenancy.a.org_id,))
        su.execute(sql)
        assert su.execute("SELECT to_regclass('consentvault.billing_account') AS t").fetchone()["t"] is None
        with pytest.raises(psycopg.errors.CheckViolation):
            su.execute("UPDATE consentvault.organization SET status = 'trial' WHERE org_id = %s", (tenancy.a.org_id,))
        assert su.execute("SELECT status FROM consentvault.resolve_credential(%s)",
                          (tenancy.a.credential_id,)).fetchone()["status"] == "org_suspended"
