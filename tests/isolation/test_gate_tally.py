"""Gate checks are tallied per organisation per day, in the same transaction as the decision, and the usage job reads
that tally. A day the tally does not cover reads as no count, never as zero, and never as a Stripe failure."""

from datetime import datetime, timedelta, timezone

import pytest

from billing.fakes import FakeStripe
from billing.helpers import link, subscribed
from billing.test_usage import Alarms, worker_conn
from consentvault.billing.errors import GateCountUnavailableError, StripeUnavailableError, UsageReportError
from consentvault.billing.usage import closed_day, db_gate_counter, run_daily_usage
from consentvault.tenancy.tokens import org_transaction

from .cloud_harness import Cloud
from .test_endpoints import U, X



def today():
    """The UTC day now. Read when a test starts, never at import: a suite that crosses UTC midnight would otherwise count a
    day earlier than the one the gate wrote (the tally is stamped with the database's UTC day)."""
    return datetime.now(timezone.utc).date()


def yesterday():
    return closed_day()


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def count(tenancy, pg_server, org, day):
    with worker_conn(tenancy, pg_server) as w:
        token = next(j["token"] for j in w.execute("SELECT org_id, token FROM consentvault.dispatch_orgs('usage')")
                     .fetchall() if j["org_id"] == org.org_id)
        with org_transaction(w, token):
            return db_gate_counter(w, org.org_id, day)


def tally_from(tenancy, day):
    with tenancy.superuser() as su:
        su.execute("UPDATE consentvault.gate_check_tally_start SET started_on = %s", (day,))


def test_single_and_batch_checks_are_counted_per_organisation(cloud, tenancy, pg_server):
    TODAY = today()   # read now, at the test's start
    tally_from(tenancy, TODAY)
    assert cloud.grant(cloud.a, X)[0] == 201
    cloud.gate(cloud.a, X)
    cloud.gate(cloud.a, U)
    items = [{"contact": X, "channel": "sms", "purpose": "marketing"},
             {"contact": "not a phone", "channel": "sms", "purpose": "marketing"},
             {"contact": U, "channel": "sms", "purpose": "marketing"}]
    s, r = cloud.call("/v1/permission:batch", {"items": items}, token=cloud.token(cloud.a, "gate_read"))
    assert s == 200
    cloud.gate(cloud.b, U)
    assert count(tenancy, pg_server, tenancy.a, TODAY) == 4  # two single, two valid batch items; the bad contact is no decision
    assert count(tenancy, pg_server, tenancy.b, TODAY) == 1
    with tenancy.superuser() as su:  # the tally and the decisions are written together, so they agree
        for org in (tenancy.a, tenancy.b):
            d = su.execute("SELECT count(*) AS n FROM consentvault.gate_decision WHERE org_id = %s", (org.org_id,))
            t = su.execute("SELECT count(*) AS n FROM consentvault.gate_check_tally WHERE org_id = %s", (org.org_id,))
            assert d.fetchone()["n"] == t.fetchone()["n"]


def test_a_day_before_the_tally_began_reads_as_no_count_not_zero(cloud, tenancy, pg_server):
    TODAY = today()   # read now, at the test's start
    YESTERDAY = yesterday()   # read now, at the test's start
    tally_from(tenancy, TODAY)
    with pytest.raises(GateCountUnavailableError, match="tally"):
        count(tenancy, pg_server, tenancy.a, YESTERDAY)
    assert count(tenancy, pg_server, tenancy.a, TODAY) == 0  # covered and quiet: a real zero


def _seed(tenancy, day, n):
    with tenancy.superuser() as su:
        for _ in range(n):
            su.execute("INSERT INTO consentvault.gate_check_tally (org_id, day) VALUES (%s, %s)",
                       (tenancy.a.org_id, day))


def test_a_stripe_failure_is_told_apart_from_no_count(tenancy, pg_server):
    YESTERDAY = yesterday()   # read now, at the test's start
    stripe = FakeStripe()
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    # no count: the tally begins tomorrow in a fresh vault
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError, match="gate_checks count unavailable"):
        run_daily_usage(w, stripe, YESTERDAY, gate_counter=db_gate_counter, alarm=alarms, sleep=lambda s: None)
    assert "gate_check_count_unavailable" in alarms.names and "usage_report_failed" not in alarms.names
    # a count, and Stripe down: the failure is Stripe's and says so
    day = YESTERDAY - timedelta(days=1)  # a day the tally covers (the first one stays unreported for want of a count)
    tally_from(tenancy, day)
    _seed(tenancy, day, 3)
    stripe.fail["create_meter_event"] = StripeUnavailableError("down")
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w, pytest.raises(UsageReportError) as exc:
        run_daily_usage(w, stripe, day, gate_counter=db_gate_counter, alarm=alarms, sleep=lambda s: None)
    assert "usage_report_failed" in alarms.names and "gate_check_count_unavailable" not in alarms.names
    assert "unavailable" not in str(exc.value).split("not reported")[0]
    with tenancy.superuser() as su:
        assert su.execute("SELECT gate_checks FROM consentvault.usage_day WHERE org_id = %s AND day = %s",
                          (tenancy.a.org_id, day)).fetchone()["gate_checks"] == 3
    # Stripe back: the same count is reported
    stripe.fail.clear()
    with worker_conn(tenancy, pg_server) as w:
        run_daily_usage(w, stripe, day, gate_counter=db_gate_counter, alarm=Alarms(), sleep=lambda s: None)
    assert 3 in [e["value"] for e in stripe.meter_events if e["event_name"] == "consentvault_gate_checks"]


# the permission answer is sent only after the decision commits ------------------------------------------------------------------

def _counts(tenancy, org):
    with tenancy.superuser() as su:
        d = su.execute("SELECT count(*) AS n FROM consentvault.gate_decision WHERE org_id = %s", (org.org_id,))
        t = su.execute("SELECT count(*) AS n FROM consentvault.gate_check_tally WHERE org_id = %s", (org.org_id,))
        return d.fetchone()["n"], t.fetchone()["n"]


def _trigger(tenancy, table, name, deferred=False):
    with tenancy.superuser() as su:
        su.execute("CREATE OR REPLACE FUNCTION public.cv_test_refuse() RETURNS trigger LANGUAGE plpgsql AS $$"
                   " BEGIN RAISE EXCEPTION 'refused by the test'; END $$")
        if deferred:
            su.execute(f"CREATE CONSTRAINT TRIGGER {name} AFTER INSERT ON consentvault.{table} DEFERRABLE INITIALLY"
                       " DEFERRED FOR EACH ROW EXECUTE FUNCTION public.cv_test_refuse()")
        else:
            su.execute(f"CREATE TRIGGER {name} BEFORE INSERT ON consentvault.{table} FOR EACH ROW"
                       " EXECUTE FUNCTION public.cv_test_refuse()")


@pytest.mark.parametrize("many", [False, True])
def test_a_commit_that_fails_gives_one_clean_503_and_records_nothing(cloud, tenancy, many):
    assert cloud.grant(cloud.a, X)[0] == 201
    _trigger(tenancy, "gate_check_tally", "cv_fail_at_commit", deferred=True)
    tok = cloud.token(cloud.a, "gate_read")
    if many:
        s, r = cloud.call("/v1/permission:batch", {"items": [{"contact": X, "channel": "sms", "purpose": "marketing"}]},
                          token=tok)
    else:
        s, r = cloud.gate(cloud.a, X, token=tok)
    assert s == 503 and str(r["evidence_status"]).startswith("unavailable:")
    answer = r["items"][0] if many else r
    assert answer["policy_action"] == "hold"  # the approved policy's own cell for an unavailable answer is honored
    assert answer["policy_version"] == cloud.a.policy_version
    assert _counts(tenancy, tenancy.a) == (0, 0)


def test_a_commit_failure_for_an_organisation_with_no_approved_policy_holds_nothing(cloud, tenancy):
    assert cloud.grant(cloud.b, X)[0] == 201
    _trigger(tenancy, "gate_check_tally", "cv_fail_at_commit", deferred=True)
    s, r = cloud.gate(cloud.b, X)
    assert s == 503 and r["policy_action"] is None and r["policy_version"] is None


# the decision and its tally are one unit --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("table", ["gate_decision", "gate_check_tally"])
def test_a_failing_decision_or_tally_insert_leaves_neither_row(cloud, tenancy, table):
    assert cloud.grant(cloud.a, X)[0] == 201
    _trigger(tenancy, table, "cv_fail_insert")
    s, r = cloud.gate(cloud.a, X)
    assert s == 503
    assert _counts(tenancy, tenancy.a) == (0, 0)


# the job command reports the gate count to Stripe -------------------------------------------------------------------------------------

def test_the_usage_daily_command_sends_the_gate_check_count_to_stripe(tenancy, pg_server, monkeypatch):
    YESTERDAY = yesterday()   # read now, at the test's start
    import argparse

    from billing.test_billing_round4 import Cfg
    from consentvault import cli, cmd_usage
    from isolation.harness import make_login_role

    cli.build_parser()
    stripe = FakeStripe()
    cus, sub = subscribed(stripe, tenancy.a)
    link(tenancy, tenancy.a, cus, sub, "active")
    tally_from(tenancy, YESTERDAY)
    _seed(tenancy, YESTERDAY, 3)
    monkeypatch.setattr(cmd_usage, "make_client", lambda env=None: stripe)
    dsn = make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker")
    assert cli.REGISTRY["usage-daily"].run(argparse.Namespace(day=None), Cfg(dsn)) == 0
    sent = {(e["event_name"], e["value"]) for e in stripe.meter_events if e["customer"] == cus}
    assert ("consentvault_gate_checks", 3) in sent
