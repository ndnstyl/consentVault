"""A worker whose clock is 11 minutes ahead of or behind the database sends, stamps and dedupes exactly as one in step:
quiet hours, the delivery stamp and the 24-hour window all follow the database's clock."""
from datetime import datetime, timedelta, timezone
import pytest
from consentvault.confirm import sender as S

UTC = timezone.utc
PHONE_NY = "+13055550142"
SKEWS = [timedelta(minutes=11), timedelta(minutes=-11)]


def _pin_db(monkeypatch, t):
    box = {"t": t}
    monkeypatch.setattr(S, "db_now", lambda conn: box["t"])
    return box


@pytest.mark.parametrize("db_t,ok", [
    (datetime(2026, 11, 4, 0, 55, tzinfo=UTC), True),    # 19:55 ET, open; worker +11 reads 20:06
    (datetime(2026, 11, 4, 1, 5, tzinfo=UTC), False),    # 20:05 ET, shut; worker -11 reads 19:54
    (datetime(2026, 11, 3, 13, 55, tzinfo=UTC), False),  # 08:55 ET, shut; worker +11 reads 09:06
    (datetime(2026, 11, 3, 14, 5, tzinfo=UTC), True),    # 09:05 ET, open; worker -11 reads 08:54
])
@pytest.mark.parametrize("by", SKEWS, ids=["ahead", "behind"])
def test_quiet_hours_follow_the_database_clock(world, stack, armed, monkeypatch, db_t, ok, by):
    _pin_db(monkeypatch, db_t)
    stack.clock.set(db_t + by)
    world.capture(world.a, PHONE_NY)
    stack.service.run_sender()          # production path: no pinned time
    assert (len(stack.twilio.sent) == 1) is ok


def test_db_now_reads_clock_timestamp(world, stack):
    import consentvault.db as db
    with db.connect(world._get().vault.app_dsn) as c:
        t = S.db_now(c)
    assert abs((t - datetime.now(UTC)).total_seconds()) < 5


@pytest.mark.parametrize("by", SKEWS, ids=["ahead", "behind"])
def test_delivery_report_stamp_and_dedupe(world, stack, armed, monkeypatch, by):
    """send at db T1; Twilio reports delivered one minute later to an API host whose clock is skewed; a second grant at
    T1 + 23h55m by the database must be skipped as a recent confirmation."""
    o = world.a
    t1 = datetime(2026, 11, 3, 15, 0, tzinfo=UTC)
    box = _pin_db(monkeypatch, t1)
    stack.clock.set(t1 + by)
    world.capture(o, PHONE_NY)
    stack.service.run_sender()
    assert len(stack.twilio.sent) == 1
    msg_id = world.sql(o, "SELECT provider_message_id FROM consentvault.confirmation_send WHERE org_id = %s", (o.org_id,))[0]["provider_message_id"]
    stack.clock.set(t1 + timedelta(minutes=1) + by)
    assert stack.inbound(armed.twilio_key, {"MessageSid": msg_id, "MessageStatus": "delivered", "To": PHONE_NY,
                                            "From": "+15555550100"}).status == 200
    row = world.sql(o, "SELECT status, at FROM consentvault.confirmation_send_intent WHERE org_id = %s AND channel = 'sms'", (o.org_id,))[0]
    with world._get().vault.superuser() as su:
        real = su.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
    assert abs((row["at"] - real).total_seconds()) < 60, "the delivery stamp came from the worker's clock, not the database's"
    with world._get().vault.superuser() as su:    # what the database would have stamped had its clock stood at T1
        su.execute("UPDATE consentvault.confirmation_send_intent SET at = %s WHERE org_id = %s AND channel = 'sms'",
                   (t1 + timedelta(minutes=1), o.org_id))
    box["t"] = t1 + timedelta(hours=23, minutes=55)
    stack.clock.set(box["t"] + by)
    world.capture(o, PHONE_NY)
    stack.service.run_sender()
    assert len(stack.twilio.sent) == 1, "a second confirmation went out inside the 24-hour window"


@pytest.mark.parametrize("by", SKEWS, ids=["ahead", "behind"])
def test_a_five_minute_inflight_send_is_not_marked_dead(world, stack, armed, monkeypatch, by):
    o = world.a
    t1 = datetime(2026, 11, 3, 15, 0, tzinfo=UTC)
    _pin_db(monkeypatch, t1)
    stack.clock.set(t1)
    world.capture(o, PHONE_NY)
    with world._get().vault.superuser() as su:
        real = su.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
        su.execute("UPDATE consentvault.confirmation_send_intent SET status='sending', at=%s WHERE org_id=%s AND channel='sms'",
                   (real - timedelta(minutes=5), o.org_id))
    stack.clock.set(real + by)        # db says the send has been out 5 minutes; reaper threshold is 15
    stack.service.run_alarm_checks()
    st = world.sql(o, "SELECT status, dead_cause FROM consentvault.confirmation_send_intent WHERE org_id=%s AND channel='sms'", (o.org_id,))[0]
    assert st["status"] == "sending"


@pytest.mark.parametrize("by", SKEWS, ids=["ahead", "behind"])
def test_a_delivered_text_never_reads_as_reports_stopped_whatever_the_worker_clock(world, stack, armed, monkeypatch, by):
    """The report's receipt stamp and the send time are both the database's: a worker 11 minutes behind cannot make a text
    delivered five minutes after it went out look like a report that arrived before the send."""
    o = world.a
    _pin_db(monkeypatch, datetime(2026, 11, 3, 15, 0, tzinfo=UTC))
    stack.clock.set(datetime(2026, 11, 3, 15, 0, tzinfo=UTC))
    world.capture(o, PHONE_NY)
    stack.service.run_sender()
    assert len(stack.twilio.sent) == 1
    msg_id = world.sql(o, "SELECT provider_message_id FROM consentvault.confirmation_send WHERE org_id = %s", (o.org_id,))[0]["provider_message_id"]
    with world._get().vault.superuser() as su:
        real = su.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
        su.execute("UPDATE consentvault.confirmation_send_intent SET last_attempt_at = %s WHERE org_id = %s AND channel = 'sms'",
                   (real - timedelta(minutes=5), o.org_id))
    stack.clock.set(real + by)
    assert stack.inbound(armed.twilio_key, {"MessageSid": msg_id, "MessageStatus": "delivered", "To": PHONE_NY,
                                            "From": "+15555550100"}).status == 200
    stack.clock.set(real + timedelta(hours=3, minutes=10) + by)   # the database says three hours ten minutes on
    stack.service.run_alarm_checks()
    assert "delivery_reports_stale" not in stack.alarms(o.boss)


def _real(world):
    with world._get().vault.superuser() as su:
        return su.execute("SELECT clock_timestamp() AS t").fetchone()["t"]


@pytest.mark.parametrize("by", SKEWS, ids=["ahead", "behind"])
def test_a_reply_is_stamped_on_the_database_clock_whatever_the_worker_clock(world, stack, armed, by):
    from contract_world.confirm import text_in
    o = world.a
    stack.clock.set(_real(world) + by)
    assert text_in(armed, "STOP").status == 200
    assert text_in(armed, "when do you open").status == 200
    rows = world.sql(o, "SELECT received_at, state FROM consentvault.confirmation_reply WHERE org_id = %s ORDER BY received_at", (o.org_id,))
    assert [r["state"] for r in rows] == ["stop", "to_read"]
    real = _real(world)
    assert all(abs((r["received_at"] - real).total_seconds()) < 60 for r in rows), "a reply was stamped on the worker's clock"
    assert rows[0]["received_at"] < rows[1]["received_at"]


@pytest.mark.parametrize("by,aged,raised", [(timedelta(minutes=11), timedelta(hours=23, minutes=55), False),
                                            (timedelta(minutes=-11), timedelta(hours=24, minutes=5), True)])
def test_the_unread_alarm_follows_the_database_clock(world, stack, armed, by, aged, raised):
    from contract_world.confirm import text_in
    o = world.a
    assert text_in(armed, "when do you open").status == 200
    with world._get().vault.superuser() as su:    # the reply has been waiting ``aged`` by the database's clock
        su.execute("ALTER TABLE consentvault.confirmation_reply DISABLE TRIGGER USER")
        su.execute("UPDATE consentvault.confirmation_reply SET received_at = received_at - %s WHERE org_id = %s", (aged, o.org_id))
        su.execute("ALTER TABLE consentvault.confirmation_reply ENABLE TRIGGER USER")
    stack.clock.set(_real(world) + by)
    stack.service.run_alarm_checks()
    assert ("replies_unread_24h" in stack.alarms(o.boss)) is raised


@pytest.mark.parametrize("by", SKEWS, ids=["ahead", "behind"])
def test_the_test_reply_is_stamped_on_the_database_clock_whatever_the_worker_clock(world, stack, by):
    from contract_world.confirm import connect_twilio, set_sender, verify_inbound
    o = world.a
    set_sender(o.boss)
    acct = connect_twilio(stack, o.boss)
    stack.clock.set(_real(world) + by)
    verify_inbound(stack, acct)
    (t,) = world.sql(o, "SELECT received_at FROM consentvault.confirmation_connect_test WHERE org_id = %s", (o.org_id,))
    (a,) = world.sql(o, "SELECT inbound_verified_at FROM consentvault.sending_account WHERE org_id = %s AND account_id = %s",
                     (o.org_id, acct["account_id"]))
    real = _real(world)
    assert abs((t["received_at"] - real).total_seconds()) < 60 and abs((a["inbound_verified_at"] - real).total_seconds()) < 60


@pytest.mark.parametrize("by,aged,accepted", [(timedelta(minutes=11), timedelta(days=29, hours=23, minutes=55), True),
                                              (timedelta(minutes=-11), timedelta(days=30, minutes=5), False)])
def test_a_removed_account_stops_accepting_replies_on_the_database_clock(world, stack, armed, by, aged, accepted):
    """The removal time is the database's, and the 30-day window it opens is judged on the database's clock."""
    from contract_world.confirm import text_in
    o = world.a
    acct = [x for x in o.boss.ok("GET", "/v1/confirmations/settings")["sending_accounts"] if x["channel"] == "sms"][0]
    stack.clock.set(_real(world) + by)
    o.boss.ok("DELETE", f"/v1/confirmations/sending-accounts/{acct['account_id']}", body={"reason": "moving"})
    (row,) = world.sql(o, "SELECT disconnected_at FROM consentvault.sending_account WHERE org_id = %s AND account_id = %s",
                       (o.org_id, acct["account_id"]))
    assert abs((row["disconnected_at"] - _real(world)).total_seconds()) < 60, "the removal was stamped on the worker's clock"
    with world._get().vault.superuser() as su:
        su.execute("UPDATE consentvault.sending_account SET disconnected_at = disconnected_at - %s WHERE org_id = %s AND account_id = %s",
                   (aged, o.org_id, acct["account_id"]))
    assert (text_in(armed, "when do you open").status == 200) is accepted
