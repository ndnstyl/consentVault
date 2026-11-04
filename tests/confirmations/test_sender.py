"""confirmations.md sections 5 and 6: when a send happens, every skip, retries, the message, the contact log, billing."""

import hashlib
import threading
from datetime import datetime, timedelta, timezone

import pytest

from consentvault.tenancy.tokens import org_transaction

from contract_world.confirm import OUR_NUMBER, PHONE, arm, replies, sends
from contract_world.world import EMAIL, PENDING, PHONE2

PHONE_NY = "+13055550142"   # 305: one zone (Eastern)
PHONE_PT = "+14155550142"   # 415: one zone (Pacific)
PHONE_SPLIT = "+19065550142"  # 906: spans Eastern and Central
UTC = timezone.utc


def at(stack, y, m, d, h, mi=0):
    stack.clock.set(datetime(y, m, d, h, mi, tzinfo=UTC))


def one(admin, channel):
    got = sends(admin, channel=channel)
    assert len(got) == 1, got
    return got[0]


def test_a_grant_inserts_one_intent_in_the_events_transaction_and_a_duplicate_does_nothing(world, stack, armed):
    """confirmations.md section 5 (intent row {send_id, basis_event_id, contact_fp, channel, status intent}; unique key)."""
    o = world.a
    ev = world.capture(o, PHONE, channels=("sms",))
    rows = world.sql(o, "SELECT * FROM consentvault.confirmation_send_intent WHERE org_id = %s", (o.org_id,))
    assert len(rows) == 2  # one intent per enabled rule: the armed world has an sms rule and an email rule on this source
    (sms,) = [r for r in rows if r["channel"] == "sms"]
    assert sms["status"] == "intent" and str(sms["basis_event_id"]) == ev.event_id
    with world.vault.superuser() as su:
        su.execute("INSERT INTO consentvault.confirmation_send_intent (org_id, send_id, basis_event_id, contact_fp, channel, status, created_at)"
                   " SELECT org_id, gen_random_uuid(), basis_event_id, contact_fp, channel, 'intent', now() FROM consentvault.confirmation_send_intent"
                   " WHERE org_id = %s ON CONFLICT DO NOTHING", (o.org_id,))
    assert len(world.sql(o, "SELECT 1 FROM consentvault.confirmation_send_intent WHERE org_id = %s AND channel = 'sms'", (o.org_id,))) == 1


def test_only_enabled_rules_on_the_events_source_make_intents_and_older_grants_never_send(world, stack):
    """confirmations.md section 4 and 5 (for each enabled rule on its source; turning on never sends for older grants)."""
    o = world.a
    world.capture(o, PHONE)
    arm(stack, o)
    world.capture(o, PHONE2, source_id=o.import_id)
    stack.run()
    assert sends(o.boss) == [] and stack.twilio.sent == []
    world.capture(o, "+15555550123", source_id=o.web_id)
    assert len(world.sql(o, "SELECT 1 FROM consentvault.confirmation_send_intent WHERE org_id = %s AND channel = 'sms'", (o.org_id,))) == 1


def test_a_text_is_sent_from_the_customers_number_with_the_fixed_text_and_a_status_callback(world, stack, armed):
    """confirmations.md section 1 and 6 (own number; exact fixed text; time in the recipient's zone named; callback URL)."""
    o = world.a
    world.capture(o, PHONE_NY, channels=("sms", "voice"))
    stack.run()
    (m,) = stack.twilio.sent
    assert m["from"] and m["to"] == PHONE_NY and m["status_callback"].startswith("https://api.consentvault.ai/")
    from zoneinfo import ZoneInfo
    received = datetime.fromisoformat(o.boss.ok("GET", "/v1/records", {})["items"][0]["first_recorded_at"].replace("Z", "+00:00"))
    local = received.astimezone(ZoneInfo("America/New_York"))
    shown = f"{local.strftime('%b')} {local.day}, {local.year} at {local.strftime('%I').lstrip('0')}:{local.strftime('%M %p')} E"
    assert m["body"].startswith("Acme Flooring: on " + shown) and " you agreed to texts and calls about " in m["body"]  # the grant's received_at in the recipient's zone, zone named
    assert m["body"].endswith("Msg frequency varies. Msg & data rates may apply. Reply STOP to opt out, HELP for help.")
    assert "https://consent.example.com/c/r/" in m["body"] and PHONE_NY not in m["body"]
    assert one(o.boss, "sms")["status"] == "sent"
    row = world.sql(o, "SELECT * FROM consentvault.confirmation_send WHERE org_id = %s", (o.org_id,))[0]
    digest = hashlib.sha256(m["body"].encode()).digest()
    assert any(digest in bytes(v) if isinstance(v, (bytes, memoryview)) else digest.hex() in str(v) for v in row.values()), \
        "the row must hold the SHA-256 of the exact text sent"
    assert m["body"].encode() not in b"".join(bytes(v) for v in row.values() if isinstance(v, (bytes, memoryview)))


def test_an_email_has_the_fixed_parts_the_exact_wording_and_the_one_click_headers(world, stack, armed):
    """confirmations.md section 6 (email fixed text, headers List-Unsubscribe and List-Unsubscribe-Post, no reply STOP)."""
    o = world.a
    world.email_grant(o, EMAIL)
    stack.run()
    (m,) = stack.email.sent
    assert m["to"] == EMAIL and f"you agreed to the following from Acme Flooring at Web form:" in m["body"]
    with world.vault.superuser() as su:
        wording = su.execute("SELECT body FROM consentvault.disclosure WHERE org_id = %s AND sha256 = %s", (o.org_id, o.wording)).fetchone()["body"]
    assert wording in m["body"]
    assert "To stop email from Acme Flooring, use this link: https://consent.example.com/c/stop/" in m["body"]
    assert "The page also lets you stop texts and calls. Texts and calls are not affected unless you choose that." in m["body"]
    assert "1 Main St, Tampa FL 33601" in m["body"] and "help@acme.example" in m["body"] and "Reply STOP" not in m["body"].replace(wording, "")
    assert m["headers"]["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click" and "/c/stop/" in m["headers"]["List-Unsubscribe"]
    assert "UTC" in m["body"]


@pytest.mark.parametrize("h,mi,ok", [(13, 59, False), (14, 0, True), (0, 59, True), (1, 0, False)])
def test_text_quiet_hours_monday_to_saturday_run_9_am_to_8_pm_local(world, stack, armed, h, mi, ok):
    """confirmations.md section 5 item 5 (9:00 AM to 8:00 PM local, start inclusive and end exclusive: 8:00 PM exactly is outside;
    ET = UTC-5 in November; skipped, never delayed)."""
    o = world.a
    day = 3 if h >= 13 else 4  # Tue 3 Nov 2026; the small hours belong to the evening of the day before
    at(stack, 2026, 11, day, h, mi)
    world.capture(o, PHONE_NY)
    stack.run()
    assert (len(stack.twilio.sent) == 1) is ok
    if not ok:
        assert one(o.boss, "sms")["skip_reason"] == "quiet_hours"
        at(stack, 2026, 11, 4, 16)
        stack.run()
        assert stack.twilio.sent == [] and one(o.boss, "sms")["skip_reason"] == "quiet_hours"


@pytest.mark.parametrize("h,ok", [(16, False), (17, True)])  # noon is inside (start inclusive)
def test_sunday_texts_start_at_noon_local(world, stack, armed, h, ok):
    """confirmations.md section 5 item 5 (Sunday: noon to 8:00 PM)."""
    at(stack, 2026, 11, 8, h, 0)  # Sunday 8 Nov 2026
    world.capture(world.a, PHONE_NY)
    stack.run()
    assert (len(stack.twilio.sent) == 1) is ok


@pytest.mark.parametrize("d,h,mi,ok", [(9, 0, 59, True), (9, 1, 0, False)])
def test_sunday_texts_end_at_8_pm_exclusive(world, stack, armed, d, h, mi, ok):
    """confirmations.md section 5 item 5 (Sunday 8:00 PM local exactly is outside: Sunday 8 Nov 20:00 ET is Monday 9 Nov 01:00 UTC)."""
    at(stack, 2026, 11, d, h, mi)
    world.capture(world.a, PHONE_NY)
    stack.run()
    assert (len(stack.twilio.sent) == 1) is ok


def test_the_fixed_text_version_is_read_at_send_time(world, stack, armed, monkeypatch):
    """confirmations.md sections 3 and 13 (a grant queued while the mark was current is skipped texting_not_registered if the
    fixed text changed before the send: the version is read at send time, not at queue time)."""
    from contract_world.world import need
    version = need("consentvault.confirm.texts", "FIXED_TEXT_VERSION")
    world.capture(world.a, PHONE_NY)
    monkeypatch.setattr("consentvault.confirm.texts.FIXED_TEXT_VERSION", version + 1)
    stack.run()
    assert stack.twilio.sent == []
    assert one(world.a.boss, "sms")["skip_reason"] == "texting_not_registered"


def test_the_zone_comes_from_the_area_code_and_an_unknown_zone_skips_the_text(world, stack, armed):
    """confirmations.md section 5 item 5 (own area code; Pacific; an area code in two zones or a foreign number: time_zone_unknown)."""
    at(stack, 2026, 11, 3, 15, 0)  # 10 AM ET, 7 AM PT
    world.capture(world.a, PHONE_PT)
    world.capture(world.a, PHONE_SPLIT)
    stack.run()
    got = {s["skip_reason"] for s in sends(world.a.boss, channel="sms")}
    assert got == {"quiet_hours", "time_zone_unknown"} and stack.twilio.sent == []


def test_email_has_no_sending_hours_and_needs_no_phone_or_zone(world, stack, armed):
    """confirmations.md section 5 item 5 (email never skipped for quiet hours, a missing phone or an unknown zone)."""
    at(stack, 2026, 11, 4, 7, 0)  # 2 AM ET
    world.email_grant(world.a, EMAIL)
    stack.run()
    assert len(stack.email.sent) == 1 and one(world.a.boss, "email")["status"] == "sent"


@pytest.mark.parametrize("name,setup", [
    ("contact_erased", "erase"), ("channel_not_in_grant", "email_only_grant"), ("brand_not_in_grant", "other_brand"),
    ("late", "late"), ("stop_on_record", "stop"), ("org_not_active", "suspended"), ("test_event", "trial_rule_off"),
])
def test_each_skip_is_recorded_by_name_and_nothing_is_sent(world, stack, armed, name, setup):
    """confirmations.md section 5 items 1, 2, 3, 4, 6, 8, 9 (the first failing check names the skip and ends the intent)."""
    o = world.a
    kw = {}
    if setup == "email_only_grant":
        kw = {"channels": ("email",), "kind": "email"}
    if setup == "other_brand":
        o.boss.ok("PUT", f"/v1/confirmations/rules/{o.web_id}/sms", body={"enabled": True, "sending_brand_id": o.brand2_id})
        kw = {"brand_ids": [o.brand_id]}
    if setup == "late":
        kw = {"captured_at": datetime.now(UTC) - __import__("datetime").timedelta(hours=1)}
    if setup == "trial_rule_off":
        o.boss.ok("PUT", f"/v1/confirmations/rules/{o.web_id}/sms", body={"enabled": True, "sending_brand_id": o.brand_id, "send_for_test_events": False})
    contact = EMAIL if setup == "email_only_grant" else PHONE_NY
    world.capture(o, contact, **kw)
    if setup == "stop":
        world.stop(o, PHONE_NY)
    if setup == "erase":
        world.erase(o, PHONE_NY)
    if setup == "suspended":
        world.set_status(o, "suspended")
    stack.run()
    (text,) = sends(o.boss, channel="sms")
    assert (text["status"], text["skip_reason"]) == ("skipped", name)
    assert stack.twilio.sent == []
    if setup == "email_only_grant":
        assert [m["to"] for m in stack.email.sent] == [EMAIL]  # the email half of the same grant is legitimately sent
    else:
        assert stack.email.sent == []


def test_a_text_to_an_email_record_is_never_sent(world, stack, armed):
    """confirmations.md section 5 item 2 (a text goes only to a phone record, an email only to an email record)."""
    world.capture(world.a, EMAIL, channels=("sms",), kind="email")
    stack.run()
    assert stack.twilio.sent == [] and stack.email.sent == []
    (text,) = sends(world.a.boss, channel="sms")
    assert (text["status"], text["skip_reason"]) == ("skipped", "contact_kind")


def test_back_dated_grants_never_send_and_a_grant_with_none_or_a_fresh_one_does(world, stack, armed):
    """confirmations.md section 5 item 4 (the grant must arrive within max_delay_minutes of its captured_at, or carry none;
    imported or back-dated grants never trigger a message: skipped late)."""
    o = world.a
    now = datetime.now(UTC)
    world.capture(o, "+13055550131")                                                       # no captured_at
    world.capture(o, "+13055550132", captured_at=now - timedelta(minutes=5))              # inside the default 10 minutes
    world.capture(o, "+13055550133", captured_at=now - timedelta(days=30))                # imported / back-dated
    world.capture(o, "+13055550134", captured_at=now - timedelta(minutes=11))             # just past the window
    stack.run()
    by = {s["contact"]["fp_hint"]: s for s in sends(o.boss, channel="sms")}
    status = lambda c: (by[o.fp(c)[:8]]["status"], by[o.fp(c)[:8]]["skip_reason"])
    assert status("+13055550131") == ("sent", None) and status("+13055550132") == ("sent", None)
    assert status("+13055550133") == ("skipped", "late") and status("+13055550134") == ("skipped", "late")
    assert len(stack.twilio.sent) == 2


def test_past_due_still_sends_but_offboarding_and_closed_do_not(world, stack, armed):
    """confirmations.md section 5 item 8 (suspended, offboarding, closed skip org_not_active; past_due still sends)."""
    o = world.a
    world.set_status(o, "past_due")
    world.capture(o, PHONE_NY)
    stack.run()
    assert len(stack.twilio.sent) == 1
    world.set_status(o, "offboarding")
    world.capture(o, "+13055550143")
    stack.run()
    assert len(stack.twilio.sent) == 1 and "org_not_active" in {s["skip_reason"] for s in sends(o.boss, channel="sms")}


def test_a_trial_event_sends_when_the_rule_says_so_and_skips_test_event_when_it_does_not(world, stack, armed):
    """confirmations.md section 4 and 5 item 9 (send_for_test_events; an event written in trial is a test event)."""
    o = world.a
    o.boss.ok("PUT", f"/v1/confirmations/rules/{o.web_id}/sms", body={"enabled": True, "sending_brand_id": o.brand_id, "send_for_test_events": False})
    world.capture(o, PHONE_NY)
    stack.run()
    assert one(o.boss, "sms")["skip_reason"] == "test_event"
    world.set_status(o, "active")
    world.capture(o, "+13055550143")
    stack.run()
    assert len(stack.twilio.sent) == 1


def test_a_second_confirmation_inside_the_dedupe_window_is_skipped_and_one_after_it_is_sent(world, stack, armed):
    """confirmations.md section 5 item 6 (recent_confirmation within dedupe_hours)."""
    o = world.a
    world.capture(o, PHONE_NY)
    stack.run()
    world.capture(o, PHONE_NY)
    stack.run()
    assert len(stack.twilio.sent) == 1 and "recent_confirmation" in {s["skip_reason"] for s in sends(o.boss, channel="sms")}
    stack.clock.advance(hours=25)
    at(stack, 2026, 11, 5, 16)
    world.capture(o, PHONE_NY)
    stack.run()
    assert len(stack.twilio.sent) == 2


def test_two_workers_racing_on_one_contact_send_exactly_one_message(world, stack, armed):
    """confirmations.md section 5 (SKIP LOCKED claim and the per-contact lock: two consents a second apart run one at a time)."""
    o = world.a
    world.capture(o, PHONE_NY)
    world.capture(o, PHONE_NY)
    import time as _t
    real = stack.twilio.send

    def slow(*a, **k):
        _t.sleep(0.3)
        return real(*a, **k)
    stack.twilio.send = slow
    threads = [threading.Thread(target=stack.run) for _ in range(3)]
    [t.start() for t in threads]
    [t.join(30) for t in threads]
    assert len(stack.twilio.sent) == 1
    assert sorted(s["status"] for s in sends(o.boss, channel="sms")) == ["sent", "skipped"]


def test_a_retryable_error_is_retried_at_offsets_from_the_first_attempt_then_dead(world, stack, armed):
    """confirmations.md section 5 retries (offsets 1, 2, 4, 8, 16, 32, 57 minutes from the START of the FIRST attempt, not from
    the previous one; jitter 0 gives exactly those offsets; after the seventh retry fails the send is dead with dead_cause =
    the last error, never retried)."""
    o = world.a
    stack.twilio.script = [("retry", 503)] * 20
    world.capture(o, PHONE_NY)
    start = stack.clock.now
    stack.run()
    assert len(stack.twilio.sent) == 1
    for n, offset in enumerate((1, 2, 4, 8, 16, 32, 57), start=2):
        stack.clock.set(start + timedelta(minutes=offset) - timedelta(seconds=5))
        stack.run(seconds=0)
        assert len(stack.twilio.sent) == n - 1, f"retry {n} came before offset {offset} minutes from the first attempt"
        stack.run(seconds=5)
        assert len(stack.twilio.sent) == n, f"retry {n} missed offset {offset} minutes from the first attempt"
    item = one(o.boss, "sms")
    assert (item["status"], item["dead_cause"], item["attempts"]) == ("dead", "retry:503", 8)
    assert item["first_attempt_at"] and item["last_attempt_at"] > item["first_attempt_at"] and item["failed_code"] is None
    stack.run(hours=5)
    assert len(stack.twilio.sent) == 8


def test_the_retry_delay_stretches_by_the_injected_jitter_at_most_20_percent(world):
    """confirmations.md sections 5 and 13 (jitter is a constructor argument of the sender service and returns the fraction of
    extra delay in [0, 0.2]; each offset is multiplied by 1 + jitter())."""
    from contract_world.confirm import arm, build_stack
    o = world.a
    stack = build_stack(world, jitter=lambda: 0.2)
    arm(stack, o)
    stack.twilio.script = [("retry", 503)] * 3
    world.capture(o, PHONE_NY)
    start = stack.clock.now
    stack.run()
    stack.run(seconds=70)
    assert len(stack.twilio.sent) == 1  # 1 minute times 1.2 is 72 seconds from the first attempt
    stack.run(seconds=5)
    assert len(stack.twilio.sent) == 2
    stack.clock.set(start + timedelta(seconds=2 * 60 * 1.2 - 3))
    stack.run(seconds=0)
    assert len(stack.twilio.sent) == 2
    stack.run(seconds=4)
    assert len(stack.twilio.sent) == 3


def test_a_retry_that_lands_after_a_stop_or_in_quiet_hours_ends_as_that_skip(world, stack, armed):
    """confirmations.md section 5 retries (every attempt re-runs checks 1, 5, 6, 7 and 8)."""
    o = world.a
    at(stack, 2026, 11, 4, 0, 30)  # 7:30 PM ET: inside the window, 30 minutes left
    stack.twilio.script = [("retry", 429)] * 3
    world.capture(o, PHONE_NY)
    stack.run()
    stack.run(minutes=45)
    assert one(o.boss, "sms")["skip_reason"] == "quiet_hours" and len(stack.twilio.sent) == 1
    world.capture(o, "+13055550143")
    at(stack, 2026, 11, 4, 16)
    stack.twilio.script = [("retry", 500)] * 3
    stack.run()
    world.stop(o, "+13055550143")
    stack.run(minutes=2)
    assert "stop_on_record" in {s["skip_reason"] for s in sends(o.boss, channel="sms")}


def test_a_key_that_will_not_open_is_retried_then_dead_with_cause_key_unavailable_and_nothing_is_sent(world, stack, armed):
    """confirmations.md section 5 item 10 (retryable; dead with cause key_unavailable)."""
    o = world.a
    world.capture(o, PHONE_NY)
    with world.custody_down():
        stack.run()
        for _ in range(8):
            stack.run(minutes=70)
    assert stack.twilio.sent == [] and one(o.boss, "sms")["status"] == "dead"
    assert one(o.boss, "sms")["dead_cause"] == "key_unavailable"


def test_a_provider_refusal_ends_the_send_failed_and_an_opt_out_refusal_records_a_stop(world, stack, armed):
    """confirmations.md section 5 and 7 (non-retryable: failed with the provider code; 21610 records a stop,
    method keyword, origin consumer, recorded_by provider_refusal)."""
    o = world.a
    stack.twilio.script = [("refuse", 21610)]
    world.capture(o, PHONE_NY, channels=("sms", "voice", "artificial_voice"))
    stack.run()
    s = one(o.boss, "sms")
    assert s["status"] == "failed" and str(s["failed_code"]) == "21610" and s["dead_cause"] is None
    stop = world.sql(o, "SELECT * FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke'", (o.org_id,))
    assert len(stop) == 1 and stop[0]["method"] == "keyword" and stop[0]["origin"] == "consumer" and stop[0]["recorded_by"] == "provider_refusal"
    assert sorted(stop[0]["channels"]) == ["artificial_voice", "sms", "voice"] and list(stop[0]["purposes"]) == ["*"]
    stack.twilio.script = [("refuse", 30006)]
    world.capture(o, "+13055550143")
    stack.run()
    assert sorted(x["status"] for x in sends(o.boss, channel="sms")) == ["failed", "failed"]


def test_status_changes_update_the_record_list_and_a_delivery_report_marks_delivered(world, stack, armed, db_follows_service_clock):
    """confirmations.md section 5 (each status change calls record_index_set_confirmation) and section 2 (delivery_reports)."""
    o = world.a
    world.capture(o, PHONE_NY)
    stack.run()
    rec = o.boss.ok("GET", "/v1/records", {})["items"][0]
    assert rec["confirmation"]["last_status"] == "sent" and rec["confirmation"]["channel"] == "sms"
    stack.clock.set(datetime.now(timezone.utc))   # the rows below are stamped by the database's real clock; the fake one starts on a fixed day
    with world._get().vault.superuser() as su:   # four hours pass by the database's clock: the send stands four hours back
        su.execute("UPDATE consentvault.confirmation_send_intent SET last_attempt_at = clock_timestamp() - interval '4 hours'"
                   " WHERE org_id = %s AND channel = 'sms'", (o.org_id,))
    stack.service.run_alarm_checks()
    assert "delivery_reports_stale" in stack.alarms(o.boss)
    assert o.boss.ok("GET", "/v1/confirmations/settings")["counts"]["delivery_reports"]["stale"] is True
    msg_id = world.sql(o, "SELECT provider_message_id FROM consentvault.confirmation_send WHERE org_id = %s", (o.org_id,))[0]["provider_message_id"]
    with world._get().vault.superuser() as su:   # the report is stamped by the database's clock and this test drives time, so
        su.execute("UPDATE consentvault.confirmation_send_intent SET last_attempt_at = clock_timestamp() - interval '1 minute'"
                   " WHERE org_id = %s AND channel = 'sms'", (o.org_id,))   # the send stands one minute before the report
    stack.clock.advance(minutes=1)
    r = stack.inbound(armed.twilio_key, {"MessageSid": msg_id, "MessageStatus": "delivered", "To": PHONE_NY, "From": "+15555550100"})
    assert r.status == 200
    assert o.boss.ok("GET", "/v1/records", {})["items"][0]["confirmation"]["last_status"] == "delivered"
    stack.service.run_alarm_checks()
    assert "delivery_reports_stale" not in stack.alarms(o.boss)
    bad = stack.inbound(armed.twilio_key, {"MessageSid": msg_id, "MessageStatus": "failed", "To": PHONE_NY, "From": "+15555550999"})
    assert bad.status == 403 and bad.payload["error"] == "inbound_number_mismatch"  # a delivery report's From is our connected number
    assert one(o.boss, "sms")["status"] == "delivered"
    dr = o.boss.ok("GET", "/v1/confirmations/settings")["counts"]["delivery_reports"]
    assert dr["stale"] is False and dr["last_at"]
    assert one(o.boss, "sms")["status"] == "delivered"


def test_a_sent_message_is_one_contact_log_row_encrypted_and_retries_add_none(world, stack, armed):
    """confirmations.md section 7 and 10 (contact_log row once the provider accepts; C4: contact_ct, contact_norm null,
    ref = send_id, recorded_by confirmations, bound by field_aad); a failed or retried send writes none."""
    from consentvault.tenancy import crypto as tc
    o = world.a
    stack.twilio.script = [("retry", 503), "ok"]
    world.capture(o, PHONE_NY)
    stack.run()
    assert world.sql(o, "SELECT 1 FROM consentvault.contact_log WHERE org_id = %s AND recorded_by = 'confirmations'", (o.org_id,)) == []
    stack.run(minutes=2)
    (row,) = world.sql(o, "SELECT * FROM consentvault.contact_log WHERE org_id = %s AND recorded_by = 'confirmations'", (o.org_id,))
    assert row["outcome"] == "confirmation" and row["channel"] == "sms" and row["contact_norm"] is None and row["contact_fp"] == o.fp(PHONE_NY)
    assert abs(row["contacted_at"].timestamp() - stack.clock()) < 1  # contacted_at is stamped by the one injected clock
    assert abs(row["recorded_at"].timestamp() - __import__("time").time()) < 120  # recorded_at keeps the database default (real time)
    assert str(row["ref"]) == one(o.boss, "sms")["send_id"] and bytes(row["contact_ct"]) and PHONE_NY.encode() not in bytes(row["contact_ct"])
    key = world.vault.custody
    held = world.sql(o, "SELECT wrapped_key, key_version FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s", (o.org_id, o.fp(PHONE_NY)))[0]
    from consentvault.tenancy.keys_protocol import WrappedKey
    dk = world.crypto.open_contact_key(o.org_id and __import__("uuid").UUID(o.org_id), WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
    assert tc.decrypt_text(dk, o.org_id, str(row["contact_log_uuid"]), "contact_ct", bytes(row["contact_ct"])) == PHONE_NY
    with pytest.raises(Exception):
        tc.decrypt_field(dk, o.org_id, str(row["contact_log_uuid"]), "contact_norm", bytes(row["contact_ct"]))


def test_the_proof_lists_the_confirmation_as_recorded_and_not_sealed(world, stack, armed):
    """proof-export.md amendment (contact_log items carry recorded_by confirmations and sealed: false until sealing lands)."""
    o = world.a
    world.capture(o, PHONE_NY)
    stack.run()
    body = o.boss.ok("POST", "/v1/proof", body={"contact": PHONE_NY})
    items = [i for i in body["contact_log"]["items"] if i.get("recorded_by") == "confirmations"] if isinstance(body["contact_log"], dict) else \
        [i for i in body["contact_log"] if i.get("recorded_by") == "confirmations"]
    assert len(items) == 1 and items[0]["outcome"] == "confirmation" and items[0]["sealed"] is False


def test_a_confirmation_is_free_so_no_message_adds_to_the_metered_events(world, stack, armed):
    """confirmations.md section 10 (billing): confirmations cost nothing extra. An accepted message is recorded as one contact-log row
    (one recorded event in the proof) but adds nothing to the day's metered events; skips and retries add nothing either."""
    o = world.a

    def count(day):
        with world.vault.appconn() as c, org_transaction(c, world.admin_token(o.org_id)):
            return c.execute("SELECT consentvault.usage_events_for_day(%s) AS n", (day,)).fetchone()["n"]
    today = stack.clock.now.date()
    world.capture(o, PHONE_NY)
    stack.twilio.script = [("retry", 503), "ok"]
    stack.run()
    stack.run(minutes=2)
    assert len(world.sql(o, "SELECT 1 FROM consentvault.contact_log WHERE org_id = %s AND recorded_by = 'confirmations'", (o.org_id,))) == 1
    assert count(today) == 0
    world.capture(o, PHONE2)
    stack.run()
    assert count(today) == 0


def test_a_reply_from_a_number_with_no_record_is_kept_under_the_org_key_and_not_billed(world, stack, armed):
    """confirmations.md section 10 (C4: no contact_log row; reply and answer kept 30 days under the org key; not billed)."""
    from contract_world.confirm import text_in
    o = world.a
    assert text_in(armed, "HELP", sender="+15555550888").status == 200
    assert world.sql(o, "SELECT 1 FROM consentvault.contact_log WHERE org_id = %s AND recorded_by = 'confirmations'", (o.org_id,)) == []
    assert o.boss.ok("GET", "/v1/records", {})["items"] == []
    stack.clock.advance(days=31)
    stack.service.purge(now=stack.clock())
    assert world.sql(o, "SELECT 1 FROM consentvault.confirmation_reply WHERE org_id = %s", (o.org_id,)) == []


def test_the_sends_list_filters_masks_and_is_audited(world, stack, armed):
    """confirmations.md section 8 (filters, sort at desc, item shape, D masked null, audit sends_listed)."""
    o = world.a
    world.capture(o, PHONE_NY)
    world.capture(o, PHONE2)
    stack.run()
    items = sends(o.boss, channel="sms")
    assert {"send_id", "record_id", "contact", "channel", "source_id", "status", "skip_reason", "provider_status", "attempts", "at"} <= set(items[0])
    assert [i["at"] for i in items] == sorted((i["at"] for i in items), reverse=True)
    assert {i["status"] for i in sends(o.boss, status="sent", channel="sms")} == {"sent"}
    assert {i["skip_reason"] for i in sends(o.boss, status="skipped", channel="sms")} == {"time_zone_unknown"}
    assert {i["skip_reason"] for i in sends(o.boss, channel="email")} == {"channel_not_in_grant"}  # the email rule's intents for sms-only grants
    assert sends(o.boss, skip_reason="time_zone_unknown") and sends(o.boss, source_id=o.web_id)
    assert sends(o.boss, **{"from": "2030-01-01T00:00:00Z"}) == []
    assert items[0]["contact"]["masked"] and o.dev.ok("GET", "/v1/confirmations/sends")["items"][0]["contact"]["masked"] is None
    assert o.viewer.ok("GET", "/v1/confirmations/sends")["items"][0]["contact"]["masked"]
    assert len(world.audit(o.boss, "confirmations.sends_listed")) >= 3


def test_nothing_in_the_confirmations_code_reads_a_reply_with_a_model(world):
    """confirmations.md section 7 (a reply is never read by a model): no module of the confirm package imports a model client,
    matched on imported module names, not on substrings of the text."""
    import ast
    import importlib.util
    import pathlib
    spec = importlib.util.find_spec("consentvault.confirm")
    assert spec is not None, "not built yet: consentvault.confirm"
    banned = {"anthropic", "openai", "ollama", "litellm", "cohere", "mistralai", "transformers", "langchain", "google.generativeai"}
    seen = set()
    for path in pathlib.Path(spec.submodule_search_locations[0]).rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                seen |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                seen.add(node.module)
    assert not {m for m in seen if m in banned or m.split(".")[0] in banned}, seen & banned


def test_provider_error_text_with_a_contact_in_it_never_reaches_logs_alerts_or_lists(world, stack, armed, caplog):
    """LC-I4 and confirmations.md section 7 (a provider error whose text carries a phone number or email is scrubbed everywhere:
    logs, alarms, the sends list, the audit log, settings; only fingerprints remain)."""
    import logging
    from contract_world.world import need
    caplog.set_level(logging.DEBUG)
    o = world.a
    PE = need("consentvault.confirm", "ProviderError")

    def leaky(kind, code):
        e = PE(kind, code)
        e.args = (f"{kind} {code}: cannot deliver to {PHONE_NY} or {EMAIL} (account owner dana@example.com)",)
        return e

    def retrying(creds, **kw):
        raise leaky("retry", 503)

    def refusing(creds, **kw):
        raise leaky("refuse", 21610)
    stack.twilio.send = retrying
    world.capture(o, PHONE_NY)
    stack.run()
    stack.run(hours=3)
    stack.twilio.send = refusing
    world.capture(o, "+13055550178")
    stack.run()
    blob = " ".join([
        caplog.text, str(sends(o.boss)), str(o.boss.ok("GET", "/v1/confirmations/settings")), str(replies(o.boss)),
        str(o.boss.ok("GET", "/v1/audit", {"limit": "200"})),
        str(world.sql(o, "SELECT detail FROM consentvault.org_alarm WHERE org_id = %s", (o.org_id,))),
        str(world.sql(o, "SELECT * FROM consentvault.confirmation_send_status WHERE org_id = %s", (o.org_id,)))])
    for secret in (PHONE_NY, "3055550178", EMAIL, "dana@example.com"):
        assert secret not in blob, secret


def test_a_slow_send_to_one_contact_never_makes_an_unrelated_contact_wait(world, stack, armed):
    """LC-D5 and confirmations.md section 5 (the lock is per organization, contact and channel only; the claim skips locked rows:
    while one contact's send is in flight in one worker, another worker finishes a different contact's send)."""
    import time as _t
    o = world.a
    A, B = "+13055550181", "+13055550182"
    log = {}
    real = stack.twilio.send

    def send(creds, **kw):
        log[kw["to"] + "_start"] = _t.monotonic()
        if kw["to"] == A:
            _t.sleep(1.0)
        out = real(creds, **kw)
        log[kw["to"] + "_end"] = _t.monotonic()
        return out
    stack.twilio.send = send
    world.capture(o, A)
    world.capture(o, B)
    t1 = threading.Thread(target=stack.run)
    t1.start()
    _t.sleep(0.3)
    t2 = threading.Thread(target=stack.run)
    t2.start()
    [t.join(30) for t in (t1, t2)]
    assert set(log) == {A + "_start", A + "_end", B + "_start", B + "_end"}
    assert log[B + "_end"] < log[A + "_end"], "the unrelated contact waited for the slow send"
    assert {s["status"] for s in sends(o.boss, channel="sms")} == {"sent"}


def test_the_organization_hourly_cap_skips_the_excess_raises_one_alarm_and_is_audited(world, stack, armed):
    """confirmations.md section 5 item 9a (send_cap_per_hour 1..10000, default 500 per channel, at the top level of settings;
    fewer than the cap sends in the 60 minutes before the attempt, else org_hourly_cap; first skip in an hour raises
    send_cap_reached; changing it is audited)."""
    from contract_world.confirm import set_sender
    o = world.a
    assert o.boss.ok("GET", "/v1/confirmations/settings")["send_cap_per_hour"] == 500
    for bad in (0, 10001, "2"):
        o.boss.err("PUT", "/v1/confirmations/settings", body={"organization_name": "Acme Flooring", "postal_address": "1 Main St",
                   "help_contact": {"email": "help@acme.example"}, "send_cap_per_hour": bad}, name="validation_failed")
    before = len(world.audit(o.boss, "confirmations.settings_changed"))
    set_sender(o.boss, send_cap_per_hour=2)
    assert len(world.audit(o.boss, "confirmations.settings_changed")) == before + 1
    assert o.boss.ok("GET", "/v1/confirmations/settings")["send_cap_per_hour"] == 2
    for n in range(3):
        world.capture(o, f"+1305555015{n}")
    stack.run()
    got = sorted(s["skip_reason"] or s["status"] for s in sends(o.boss, channel="sms"))
    assert got == ["org_hourly_cap", "sent", "sent"] and len(stack.twilio.sent) == 2
    assert "send_cap_reached" in stack.alarms(o.boss)
    world.capture(o, "+13055550159")
    stack.run()
    assert len([a for a in o.boss.ok("GET", "/v1/confirmations/settings")["alarms"] if a["kind"] == "send_cap_reached"]) == 1
    stack.run(minutes=61)
    world.capture(o, "+13055550158")
    stack.run()
    assert len(stack.twilio.sent) == 3  # a new hour: the cap counts only the last 60 minutes


def test_the_cap_is_per_channel_so_a_text_cap_never_stops_email(world, stack, armed):
    """confirmations.md section 5 item 9a (for this organization and channel)."""
    from contract_world.confirm import set_sender
    o = world.a
    set_sender(o.boss, send_cap_per_hour=1)
    for n in range(2):
        world.capture(o, f"+1305555016{n}")
    world.email_grant(o, EMAIL)
    stack.run()
    assert len(stack.twilio.sent) == 1 and len(stack.email.sent) == 1


def test_a_test_message_reads_a_national_number_with_the_default_region(world, stack, armed, monkeypatch):
    """records.md phone region rule (POST /v1/confirmations:test uses the same rule: (305) 555-0123 is +13055550123)."""
    from datetime import datetime, timezone
    from consentvault.confirm import sender as S
    monkeypatch.setattr(S, "db_now", lambda conn: datetime(2026, 11, 3, 17, 0, tzinfo=timezone.utc))   # noon in Miami, whatever the real hour
    o = world.a
    o.boss.ok("POST", "/v1/confirmations:test", body={"source_id": o.web_id, "channel": "sms", "contact": "(305) 555-0123"})
    assert stack.twilio.sent[-1]["to"] == "+13055550123"


def test_a_21610_refusal_opens_the_provider_refusal_stop_alarm_and_counts_it(world, stack, armed):
    """confirmations.md sections 2, 5 and 13 (provider_refusal_stops_24h; alarm kind provider_refusal_stop)."""
    o = world.a
    stack.twilio.script = [("refuse", 21610)]
    world.capture(o, PHONE_NY)
    stack.run()
    assert o.boss.ok("GET", "/v1/confirmations/settings")["counts"]["provider_refusal_stops_24h"] == 1
    assert "provider_refusal_stop" in stack.alarms(o.boss)


def account_row(o):
    return [x for x in o.boss.ok("GET", "/v1/confirmations/settings")["sending_accounts"] if x["channel"] == "sms"][0]


def test_four_account_level_refusals_in_a_row_raise_nothing_and_a_success_resets_the_count(world, stack, armed):
    """confirmations.md section 5 Account failing (ProviderError kind account counts one refusal; an accepted send resets the
    count to 0; four leave the account connected; 4 + success + 4 never reaches 5)."""
    o = world.a
    stack.twilio.script = [("account", 20003)] * 4 + ["ok"] + [("account", 20003)] * 4
    for n in range(9):
        world.capture(o, f"+1305555017{n}")
    stack.run()
    assert len(stack.twilio.sent) == 9  # every send was attempted: nothing paused
    assert "sending_account_failing" not in stack.alarms(o.boss) and account_row(o)["status"] == "connected"


def test_five_consecutive_account_level_refusals_pause_the_account_and_skip_the_next_send_without_a_call(world, stack, armed):
    """confirmations.md section 5 Account failing (5 consecutive: status failing, one org_alarm sending_account_failing with
    detail {account_id, channel, last_code}, every later intent skipped sending_account_failing without calling the provider)."""
    o = world.a
    stack.twilio.script = [("account", 20003)] * 5
    for n in range(5):
        world.capture(o, f"+1305555018{n}")
    stack.run()
    assert len(stack.twilio.sent) == 5 and account_row(o)["status"] == "failing"
    alarm = stack.alarms(o.boss)["sending_account_failing"]
    assert alarm["detail"]["account_id"] == account_row(o)["account_id"] and alarm["detail"]["channel"] == "sms" and str(alarm["detail"]["last_code"]) == "20003"
    assert len(world.sql(o, "SELECT 1 FROM consentvault.org_alarm WHERE org_id = %s AND kind = 'sending_account_failing' AND cleared_at IS NULL", (o.org_id,))) == 1
    world.capture(o, "+13055550189")
    stack.run()
    assert len(stack.twilio.sent) == 5  # the sixth was not attempted
    assert sorted(s["skip_reason"] for s in sends(o.boss, channel="sms") if s["status"] == "skipped") == ["sending_account_failing"]


def test_a_passing_account_check_resumes_sending_and_clears_the_alarm(world, stack, armed):
    """confirmations.md section 5 Account failing (a successful :check sets the account back to connected, resets the count and
    clears the alarm; the next grant sends)."""
    o = world.a
    stack.twilio.script = [("account", 20003)] * 5
    for n in range(5):
        world.capture(o, f"+1305555019{n}")
    stack.run()
    assert account_row(o)["status"] == "failing"
    o.boss.ok("POST", f"/v1/confirmations/sending-accounts/{account_row(o)['account_id']}:check", body={})
    assert account_row(o)["status"] == "connected" and "sending_account_failing" not in stack.alarms(o.boss)
    world.capture(o, "+13055550199")
    stack.run()
    assert len(stack.twilio.sent) == 6 and sorted(s["status"] for s in sends(o.boss, channel="sms"))[-1] == "sent"
    stack.twilio.script = [("account", 20003)] * 4
    for n in range(4):
        world.capture(o, f"+1305555020{n}")
    stack.run()
    assert account_row(o)["status"] == "connected"  # the count restarted from 0 after the check


def test_a_check_against_an_unreachable_provider_answers_provider_unreachable_and_changes_nothing(world, stack, armed):
    """confirmations.md section 1 errors (provider_unreachable, 502: nothing was sent or changed)."""
    o = world.a
    before = account_row(o)
    stack.twilio.unreachable = True
    o.boss.err("POST", f"/v1/confirmations/sending-accounts/{before['account_id']}:check", body={}, name="provider_unreachable", status=502)
    assert account_row(o)["status"] == before["status"] and stack.twilio.sent == []


def test_no_retry_is_attempted_later_than_120_minutes_after_the_first(world, stack, armed):
    """confirmations.md section 5 retries (no attempt later than 120 minutes after the first: a sender that was down for three
    hours makes no late attempt; the send is dead with the last error)."""
    o = world.a
    stack.twilio.script = [("retry", 503)] * 20
    world.capture(o, PHONE_NY)
    stack.run()
    assert len(stack.twilio.sent) == 1
    stack.run(hours=3)
    assert len(stack.twilio.sent) == 1  # the 1-minute retry is now 179 minutes after the first: not attempted
    item = one(o.boss, "sms")
    assert item["status"] == "dead" and item["dead_cause"] == "retry:503"


def test_a_delivery_report_posted_to_another_organizations_inbound_address_changes_nothing(world, stack, armed):
    """LC-S4 (a callback for organization A's message reaching B's receiver does not touch A's send; B records nothing)."""
    a, b = world.a, world.b
    armed_b = arm(stack, b, email=False, host="consent.bravo.example")
    world.capture(a, PHONE_NY)
    stack.run()
    msg_id = world.sql(a, "SELECT provider_message_id FROM consentvault.confirmation_send WHERE org_id = %s", (a.org_id,))[0]["provider_message_id"]
    r = stack.inbound(armed_b.twilio_key, {"MessageSid": msg_id, "MessageStatus": "delivered", "To": PHONE_NY, "From": OUR_NUMBER})
    assert r.status in (200, 404)
    assert one(a.boss, "sms")["status"] == "sent"
    assert sends(b.boss) == []


def test_an_organization_without_voice_gets_a_stop_naming_only_the_channels_it_has(world, stack):
    """confirmations.md section 7 and 14 (an organization provisioned through the operator route with only sms and email: the
    stop names sms and nothing else; capture would refuse a channel the organization lacks)."""
    from contract_world.confirm import text_in
    o = world.extra_org("nochan", [("sms", "Text message"), ("email", "Email")])
    armed2 = arm(stack, o)
    world.capture(o, PHONE_NY, channels=("sms",))
    text_in(armed2, "STOP", sender=PHONE_NY)
    (ev,) = world.sql(o, "SELECT channels FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke'", (o.org_id,))
    assert list(ev["channels"]) == ["sms"]
