"""Reader item 5 and finding C2: the send-time checks of today's sender survive the move to intents, one test per skip.

Each test is a grant that arrived after the cutover (it exists only in history), whose pending confirmation intent must skip with
the named reason when the sender runs, send nothing, and never end in state ``sent``. The order of the checks is today's
(confirm/sender.py `_plan_confirmation`); where two checks could both fire the setup arranges only the one under test.
The reason is read where an operator reads it today, the sends list. The last test is the positive control: every check passes and
the message goes out once with the intent id as the provider's idempotency key.
"""

from datetime import datetime, timedelta, timezone

import pytest

from contract_world.confirm import mark_registered, sends, set_sender
from contract_world.world import EMAIL

from .support import PHONE, at, confirmation_intents, cut_grant, cut_stop, force, intents, need_cutover  # noqa: F401

PHONE_NY = "+13055550142"
PHONE_SPLIT = "+19065550142"
UTC = timezone.utc


def _sql_org(world, table, set_clause, extra=""):
    o = world.a
    force(world, f"UPDATE consentvault.{table} SET {set_clause} WHERE org_id = %s {extra}", (o.org_id,))


def _put_rule(o, **kw):
    o.boss.ok("PUT", f"/v1/confirmations/rules/{o.web_id}/sms", body={"enabled": True, "sending_brand_id": o.brand_id, **kw})


def _before_rule_brand(world, stack):
    o = world.a
    _put_rule(o, sending_brand_id=o.brand2_id)
    return {"brand_ids": [o.brand_id]}


def _before_test_event(world, stack):
    _put_rule(world.a, send_for_test_events=False)
    return {}


def _before_late(world, stack):
    return {"captured_at": datetime.now(UTC) - timedelta(hours=1)}


def _before_email_kind(world, stack):
    return {"channels": ("sms",), "kind": "email", "_contact": EMAIL}


def _before_email_only(world, stack):
    return {"channels": ("email",), "kind": "email", "_contact": EMAIL}


def _before_split_zone(world, stack):
    return {"_contact": PHONE_SPLIT}


def _before_quiet(world, stack):
    at(stack, 2026, 11, 4, 7, 0)   # 2 AM Eastern
    return {}


def _after_stop(world, stack):
    cut_stop(world, world.a, PHONE_NY)


def _status(w, table, status, extra=""):
    return lambda w_, s_: _sql_org(w_, table, f"status = '{status}'", extra)


def _clock_back(w, s):
    at(s, 2026, 11, 3, 15, 0)


CASES = [
    # name, reason, grant-time arrangement, change made after the grant arrived, how the condition is cleared (None: it lives in the grant)
    ("rule_off_no_row", "rule_off", None,
     lambda w, s: force(w, "DELETE FROM consentvault.confirmation_rule WHERE org_id = %s AND channel = 'sms'", (w.a.org_id,)),
     lambda w, s: _put_rule(w.a)),
    ("contact_erased", "contact_erased", None, lambda w, s: w.erase(w.a, PHONE_NY), None),
    ("channel_not_in_grant", "channel_not_in_grant", _before_email_only, None, None),
    ("contact_kind", "contact_kind", _before_email_kind, None, None),
    ("brand_not_in_grant", "brand_not_in_grant", _before_rule_brand, None, None),
    ("late", "late", _before_late, None, None),
    ("texting_not_registered", "texting_not_registered", None,
     lambda w, s: _sql_org(w, "confirmation_registration", "status = 'not_marked'"), lambda w, s: mark_registered(w.a.boss)),
    ("no_sending_account", "no_sending_account", None, _status(None, "sending_account", "disconnected", "AND channel = 'sms'"),
     _status(None, "sending_account", "connected", "AND channel = 'sms'")),
    ("inbound_not_verified", "inbound_not_verified", None, _status(None, "sending_account", "awaiting_test_reply", "AND channel = 'sms'"),
     _status(None, "sending_account", "connected", "AND channel = 'sms'")),
    ("link_host_not_verified", "link_host_not_verified", None, _status(None, "confirmation_link_host", "pending_dns"),
     _status(None, "confirmation_link_host", "verified")),
    ("link_host_failing", "link_host_failing", None, _status(None, "confirmation_link_host", "failing"), _status(None, "confirmation_link_host", "verified")),
    ("sending_account_failing", "sending_account_failing", None, _status(None, "sending_account", "failing", "AND channel = 'sms'"),
     _status(None, "sending_account", "connected", "AND channel = 'sms'")),
    ("org_not_active", "org_not_active", None, lambda w, s: w.set_status(w.a, "suspended"), lambda w, s: w.set_status(w.a, "trial")),
    ("time_zone_unknown", "time_zone_unknown", _before_split_zone, None, None),
    ("quiet_hours", "quiet_hours", _before_quiet, None, _clock_back),
    ("stop_on_record", "stop_on_record", None, _after_stop, None),
    ("rule_off_disabled", "rule_off", None, lambda w, s: _put_rule(w.a, enabled=False), lambda w, s: _put_rule(w.a)),
    ("test_event", "test_event", _before_test_event, None, lambda w, s: _put_rule(w.a, send_for_test_events=True)),
    ("sender_details_missing", "sender_details_missing", None,
     lambda w, s: force(w, "DELETE FROM consentvault.confirmation_settings WHERE org_id = %s", (w.a.org_id,)), lambda w, s: set_sender(w.a.boss)),
]


@pytest.mark.parametrize("name,reason,before,after,clear", [
    pytest.param(n, r, b, a, c, id=n, marks=pytest.mark.spec_item(*(("5." + n, "item39") if n == "stop_on_record" else ("5." + n,))))
    for n, r, b, a, c in CASES])
def test_a_pending_intent_skips_with_the_old_reason_ends_terminal_and_a_rerun_after_clearing_sends_nothing(world, stack, armed, name, reason, before, after, clear):
    need_cutover()
    o = world.a
    kw = dict(before(world, stack)) if before else {}
    contact = kw.pop("_contact", PHONE_NY)
    post = cut_grant(world, o, contact, **kw)
    pending = [i for i in confirmation_intents(world, o, post) if i["channel"] == "sms"]
    assert [i["state"] for i in pending] == ["pending"], "the grant must derive one pending sms confirmation intent"
    if after:
        after(world, stack)
    stack.run()
    (row,) = [s for s in sends(o.boss, channel="sms") if s["status"] == "skipped"]
    assert row["skip_reason"] == reason, row
    assert stack.twilio.sent == []
    sms = [i for i in confirmation_intents(world, o, post) if i["channel"] == "sms"]
    assert sms and all(i["state"].startswith("failed:") for i in sms), "the skipped intent is terminal"
    if clear:
        clear(world, stack)
    stack.run()
    stack.run(minutes=5)
    assert stack.twilio.sent == [], "a second run after the condition is cleared sends nothing for a terminal intent"
    assert [i["state"] for i in confirmation_intents(world, o, post) if i["channel"] == "sms"] == [i["state"] for i in sms]


@pytest.mark.spec_item("5.order_stop_then_quiet_hours")
def test_with_a_stop_on_record_and_quiet_hours_both_true_today_s_order_names_quiet_hours(world, stack, armed):
    need_cutover()
    o = world.a
    at(stack, 2026, 11, 4, 7, 0)   # 2 AM Eastern
    cut_grant(world, o, PHONE_NY)
    cut_stop(world, o, PHONE_NY)
    stack.run()
    (row,) = [s for s in sends(o.boss, channel="sms") if s["status"] == "skipped"]
    assert row["skip_reason"] == "quiet_hours", "quiet hours is checked before the stop on record (sender.py), and the order is kept"
    assert stack.twilio.sent == []


def _hold_first(world, stack, state):
    """Put the first intent in ``state`` without sending it: 'claimed' is a provider stub that blocks after the claim and, while it
    blocks, lets a second worker run; 'unknown' and 'sent' are set below the triggers on a first intent that never ran."""
    o = world.a
    first = cut_grant(world, o, PHONE_NY)
    if state in ("unknown", "sent"):
        force(world, "UPDATE consentvault.effect_intent SET state = %s, state_at = now() WHERE org_id = %s AND post_id = %s AND channel = 'sms'",
              (state, o.org_id, first))
    return first


def _second_run(world, stack, state, contact):
    """Returns the second intent's post. For 'claimed' the second run happens while the first send is blocked inside the provider."""
    o = world.a
    if state != "claimed":
        second = cut_grant(world, o, contact)
        stack.run()
        return second
    box = {}
    real = type(stack.twilio).send

    def blocking(self, creds, **kw):
        if "second" not in box:
            box["second"] = cut_grant(world, o, contact)
            stack.run()   # a second worker runs while the first intent is claimed and the provider call has not returned
        return real(self, creds, **{k: v for k, v in kw.items() if k != "idempotency_key"})

    type(stack.twilio).send = blocking
    try:
        stack.run()
    finally:
        type(stack.twilio).send = real
    return box["second"]


@pytest.mark.parametrize("state", [pytest.param(s, id=s, marks=pytest.mark.spec_item("5.recent_confirmation")) for s in ("claimed", "unknown", "sent")])
def test_a_second_pending_intent_for_the_same_contact_skips_while_the_first_is_claimed_unknown_or_sent(world, stack, armed, state):
    need_cutover()
    o = world.a
    first = cut_grant(world, o, PHONE_NY) if state == "claimed" else _hold_first(world, stack, state)
    second = _second_run(world, stack, state, PHONE_NY)
    assert "recent_confirmation" in {s["skip_reason"] for s in sends(o.boss, channel="sms")}
    assert all(i["state"] != "sent" for i in confirmation_intents(world, o, second) if i["channel"] == "sms")
    assert len(stack.twilio.sent) == (1 if state == "claimed" else 0), "at most the one claimed send went out"


@pytest.mark.parametrize("state", [pytest.param(s, id=s, marks=pytest.mark.spec_item("5.org_hourly_cap")) for s in ("claimed", "unknown", "sent")])
def test_the_hourly_cap_counts_claimed_unknown_and_sent_intents(world, stack, armed, state):
    need_cutover()
    o = world.a
    set_sender(o.boss, send_cap_per_hour=1)
    first = cut_grant(world, o, "+13055550150") if state == "claimed" else _hold_first_cap(world, state)
    second = _second_run(world, stack, state, "+13055550151")
    assert "org_hourly_cap" in {s["skip_reason"] for s in sends(o.boss, channel="sms")}
    assert all(i["state"] != "sent" for i in confirmation_intents(world, o, second) if i["channel"] == "sms")


def _hold_first_cap(world, state):
    o = world.a
    first = cut_grant(world, o, "+13055550150")
    force(world, "UPDATE consentvault.effect_intent SET state = %s, state_at = now() WHERE org_id = %s AND post_id = %s AND channel = 'sms'",
          (state, o.org_id, first))
    return first


@pytest.mark.spec_item("5.sends_once_with_intent_id")
def test_a_pending_intent_with_every_check_passing_is_sent_once_with_its_intent_id_as_the_idempotency_key(world, stack, armed, monkeypatch):
    need_cutover()
    o = world.a
    seen = []
    real = type(stack.twilio).send

    def spy(self, creds, **kw):
        seen.append(kw)
        return real(self, creds, **{k: v for k, v in kw.items() if k != "idempotency_key"})

    monkeypatch.setattr(type(stack.twilio), "send", spy)
    post = cut_grant(world, o, PHONE_NY)
    (intent,) = [i for i in confirmation_intents(world, o, post) if i["channel"] == "sms"]
    stack.run()
    stack.run()   # a second pass sends nothing more
    assert len(stack.twilio.sent) == 1 and len(seen) == 1
    assert seen[0]["idempotency_key"] == str(intent["intent_id"])
    (after,) = [i for i in confirmation_intents(world, o, post) if i["channel"] == "sms"]
    assert after["state"] == "sent"
