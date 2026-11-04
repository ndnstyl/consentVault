"""A billing worker whose clock is 11 minutes ahead of or behind the database opens and shuts the invoice window on the
database's clock."""
from datetime import datetime, timedelta, timezone
import pytest
from consentvault.billing import usage as U
from consentvault.billing.errors import UsageReportError
from billing.helpers import subscribed
from billing.test_billing_round3 import link_period
from billing.test_usage import Alarms, backdate_events, gates, worker_conn


def _skew_process_clock(monkeypatch, by):
    real = datetime
    class Skewed(real):
        @classmethod
        def now(cls, tz=None):
            return real.now(tz) + by
    monkeypatch.setattr(U, "datetime", Skewed)
    import time as _t
    rt = _t.time
    monkeypatch.setattr(_t, "time", lambda: rt() + by.total_seconds())


def _setup(tenancy, stripe, start):
    day = start.astimezone(timezone.utc).date() - timedelta(days=1)  # the usage day is a UTC day; the database's own zone can be on the other side of midnight
    backdate_events(tenancy, tenancy.a, day, 2)
    cus, sub = subscribed(stripe, tenancy.a)
    link_period(tenancy, tenancy.a, cus, sub, start)
    return day


@pytest.mark.parametrize("by", [timedelta(minutes=11), timedelta(minutes=-11)], ids=["ahead", "behind"])
@pytest.mark.parametrize("minutes_ago,open_", [(45, True), (65, False)])
def test_invoice_window_on_db_clock(tenancy, stripe, pg_server, monkeypatch, by, minutes_ago, open_):
    with worker_conn(tenancy, pg_server) as w:
        dbt = U.db_now(w)
    start = dbt - timedelta(minutes=minutes_ago)   # deadline = start + 55 min: 10 min ahead (open) or 10 min gone (shut) by the DB
    day = _setup(tenancy, stripe, start)
    _skew_process_clock(monkeypatch, by)
    alarms = Alarms()
    with worker_conn(tenancy, pg_server) as w:
        if open_:
            U.run_daily_usage(w, stripe, day, gate_counter=gates(7), alarm=alarms, sleep=lambda s: None)
        else:
            with pytest.raises(UsageReportError, match="abandoned"):
                U.run_daily_usage(w, stripe, day, gate_counter=gates(7), alarm=alarms, sleep=lambda s: None)
    assert (len(stripe.meter_events) == 2) is open_
    assert ("usage_day_abandoned" in alarms.names) is (not open_)


@pytest.mark.parametrize("by", [timedelta(minutes=11), timedelta(minutes=-11)], ids=["ahead", "behind"])
def test_retry_pass_window_on_db_clock(tenancy, stripe, pg_server, monkeypatch, by):
    with worker_conn(tenancy, pg_server) as w:
        dbt = U.db_now(w)
    start = dbt - timedelta(minutes=65)
    _setup(tenancy, stripe, start)
    _skew_process_clock(monkeypatch, by)
    with worker_conn(tenancy, pg_server) as w:
        U.run_usage_retries(w, stripe, sleep=lambda s: None, check_daily_run=False)
    assert stripe.meter_events == []
