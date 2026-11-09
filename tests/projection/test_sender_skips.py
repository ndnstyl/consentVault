"""Reader item 5 and finding C2: the send-time checks of today's sender survive the move to intents, one test per skip.

Each test is a grant that arrived after the cutover (it exists only in history), whose pending confirmation intent must skip with
the named reason when the sender runs, send nothing, and never end in state ``sent``. The order of the checks is today's
(confirm/sender.py `_plan_confirmation`); where two checks could both fire the setup arranges only the one under test.
The reason is read where an operator reads it today, the sends list. The last test is the positive control: every check passes and
the message goes out once with the intent id as the provider's idempotency key.
"""

from datetime import datetime, timedelta, timezone

import pytest

from contract_world.confirm import sends, set_sender
from contract_world.world import EMAIL

from .support import PHONE, add_push_target, at, confirmation_intents, cut_grant, cut_stop, force, intents, need_cutover  # noqa: F401

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


CASES = [
    # name, reason, grant-time arrangement, change made after the grant arrived
    ("rule_off_no_row", "rule_off", None,
     lambda w, s: force(w, "DELETE FROM consentvault.confirmation_rule WHERE org_id = %s AND channel = 'sms'", (w.a.org_id,))),
    ("contact_erased", "contact_erased", None, lambda w, s: w.erase(w.a, PHONE_NY)),
    ("channel_not_in_grant", "channel_not_in_grant", _before_email_only, None),
    ("contact_kind", "contact_kind", _before_email_kind, None),
    ("brand_not_in_grant", "brand_not_in_grant", _before_rule_brand, None),
    ("late", "late", _before_late, None),
    ("texting_not_registered", "texting_not_registered", None,
     lambda w, s: _sql_org(w, "confirmation_registration", "status = 'not_marked'")),
    ("no_sending_account", "no_sending_account", None,
     lambda w, s: _sql_org(w, "sending_account", "status = 'disconnected'", "AND channel = 'sms'")),
    ("inbound_not_verified", "inbound_not_verified", None,
     lambda w, s: _sql_org(w, "sending_account", "status = 'awaiting_test_reply'", "AND channel = 'sms'")),
    ("link_host_not_verified", "link_host_not_verified", None,
     lambda w, s: _sql_org(w, "confirmation_link_host", "status = 'pending_dns'")),
    ("link_host_failing", "link_host_failing", None, lambda w, s: _sql_org(w, "confirmation_link_host", "status = 'failing'")),
    ("sending_account_failing", "sending_account_failing", None,
     lambda w, s: _sql_org(w, "sending_account", "status = 'failing'", "AND channel = 'sms'")),
    ("org_not_active", "org_not_active", None, lambda w, s: w.set_status(w.a, "suspended")),
    ("time_zone_unknown", "time_zone_unknown", _before_split_zone, None),
    ("quiet_hours", "quiet_hours", _before_quiet, None),
    ("stop_on_record", "stop_on_record", None, _after_stop),
    ("rule_off_disabled", "rule_off", None, lambda w, s: _put_rule(w.a, enabled=False)),
    ("test_event", "test_event", _before_test_event, None),
    ("sender_details_missing", "sender_details_missing", None,
     lambda w, s: force(w, "DELETE FROM consentvault.confirmation_settings WHERE org_id = %s", (w.a.org_id,))),
]


@pytest.mark.parametrize("name,reason,before,after", [
    pytest.param(n, r, b, a, id=n, marks=pytest.mark.spec_item(*(("5." + n, "item39") if n == "stop_on_record" else ("5." + n,))))
    for n, r, b, a in CASES])
def test_a_pending_intent_skips_with_the_old_reason_and_sends_nothing(world, stack, armed, name, reason, before, after):
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
    assert all(i["state"] != "sent" for i in confirmation_intents(world, o, post) if i["channel"] == "sms")
    if name not in ("channel_not_in_grant", "contact_kind"):
        assert stack.email.sent == [] or name in ("rule_off_no_row", "rule_off_disabled", "test_event", "brand_not_in_grant")


@pytest.mark.spec_item("5.recent_confirmation")
def test_a_second_intent_inside_the_dedupe_window_skips_as_recent_confirmation(world, stack, armed):
    need_cutover()
    o = world.a
    first = cut_grant(world, o, PHONE_NY)
    stack.run()
    assert [i["state"] for i in confirmation_intents(world, o, first) if i["channel"] == "sms"] == ["sent"]
    second = cut_grant(world, o, PHONE_NY)
    stack.run()
    assert len(stack.twilio.sent) == 1
    assert "recent_confirmation" in {s["skip_reason"] for s in sends(o.boss, channel="sms")}
    assert all(i["state"] != "sent" for i in confirmation_intents(world, o, second) if i["channel"] == "sms")


@pytest.mark.spec_item("5.org_hourly_cap")
def test_the_hourly_cap_counts_sent_intents_and_skips_the_excess(world, stack, armed):
    need_cutover()
    o = world.a
    set_sender(o.boss, send_cap_per_hour=2)
    posts = [cut_grant(world, o, f"+1305555015{n}") for n in range(3)]
    stack.run()
    got = sorted(s["skip_reason"] or s["status"] for s in sends(o.boss, channel="sms"))
    assert got == ["org_hourly_cap", "sent", "sent"] and len(stack.twilio.sent) == 2
    states = sorted(i["state"] for p in posts for i in confirmation_intents(world, o, p) if i["channel"] == "sms")
    assert states.count("sent") == 2


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
