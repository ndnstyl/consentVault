import threading, time
from datetime import datetime, timezone


NY = "+13055550150"


def _token_for(stack, address):
    sent = [m for m in stack.email.sent if address in str(m)]
    return sent[0]["body"].split("/c/stop/")[1].split()[0].rstrip(".")


def _phone_allowed(world, o):
    return [c for c in world.sql(o, "SELECT channel, allowed FROM consentvault.current_permission WHERE org_id = %s AND contact_fp = %s",
                                 (o.org_id, o.fp(NY))) if c["allowed"]]


def test_a1_basis_email_grant_without_a_key_then_keyed_phone(world, stack, armed):
    """Email first captured with no person key (it sends the confirmation); later the same person is keyed on email and phone."""
    o = world.a
    world.email_grant(o, "dana@example.com")
    stack.run()
    stack.advance(days=1)
    world.email_grant(o, "dana@example.com", subject_key="person-1")
    world.capture(o, NY, channels=("sms", "voice", "artificial_voice"), subject_key="person-1")
    stack.run()
    token = _token_for(stack, "dana@example.com")
    assert stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything").status == 200
    assert _phone_allowed(world, o) == []


def test_a2_more_than_200_unkeyed_events_hide_the_owner(world, stack, armed):
    o = world.a
    world.capture(o, NY, channels=("sms", "voice", "artificial_voice"), subject_key="person-1")
    world.email_grant(o, "dana@example.com", subject_key="person-1")
    stack.run()
    for _ in range(201):
        world.capture(o, NY, channels=("voice",))
    token = _token_for(stack, "dana@example.com")
    assert stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything").status == 200
    assert _phone_allowed(world, o) == []


def test_a3_clock_read_before_a_contended_lock_sends_after_eight(world, stack, armed, db_follows_service_clock):
    o = world.a
    o.boss.ok("PUT", f"/v1/confirmations/rules/{o.web_id}/email", body={"enabled": False, "sending_brand_id": o.brand_id})
    world.capture(o, NY)
    base = datetime(2026, 11, 4, 0, 59, 0, tzinfo=timezone.utc).timestamp()  # 7:59:00 PM New York
    t0 = time.time()
    stack.service._clock = lambda: base + (time.time() - t0) * 60  # one real second = one minute
    key = f"cvconfirm:{o.org_id}:{o.fp(NY)}:sms"
    held = threading.Event()

    def hold():
        with world.vault.superuser() as su:
            su.execute("SELECT pg_advisory_lock(hashtextextended(%s, 0))", (key,))
            held.set()
            time.sleep(3)
            su.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (key,))
    th = threading.Thread(target=hold); th.start(); held.wait(10)
    stack.service.run_sender()
    th.join()
    assert len(stack.twilio.sent) == 0, "a text left after 8 PM on a clock read before the lock wait"


# ---- the person link, read from the records layer ----------------------------------------------------------------------------
def _linked_counts(o):
    return {i["contact_kind"]: i["linked_record_count"] for i in o.boss.ok("GET", "/v1/records", {"state": "all"})["items"]}


def _stopped_channels(world, o, fp):
    return {c["channel"] for c in world.sql(o, "SELECT channel, allowed, reason FROM consentvault.current_permission"
                                              " WHERE org_id = %s AND contact_fp = %s", (o.org_id, fp))
            if not c["allowed"] and str(c["reason"]).startswith("stopped:")}


def test_unkeyed_events_never_break_the_records_link(world, stack, armed):
    """records.md section 1: an event with no person key of its own does not move or break a link a keyed capture made."""
    o = world.a
    world.capture(o, NY, channels=("sms", "voice"), subject_key="person-1")
    world.email_grant(o, "dana@example.com", subject_key="person-1")
    assert _linked_counts(o) == {"phone": 1, "email": 1}
    for _ in range(3):
        world.capture(o, NY, channels=("voice",))
    world.stop(o, NY, channels=("sms",))
    world.email_grant(o, "dana@example.com")
    assert _linked_counts(o) == {"phone": 1, "email": 1}


def test_a_late_link_is_made_by_the_keyed_capture_whatever_came_before(world, stack, armed):
    o = world.a
    world.email_grant(o, "dana@example.com")
    world.capture(o, NY, channels=("sms",))
    assert _linked_counts(o) == {"phone": 0, "email": 0}
    world.capture(o, NY, channels=("sms",), subject_key="person-1")
    world.email_grant(o, "dana@example.com", subject_key="person-1")
    assert _linked_counts(o) == {"phone": 1, "email": 1}


def test_a_reassigned_number_hidden_behind_unkeyed_events_is_untouched(world, stack, armed):
    o = world.a
    world.capture(o, NY, channels=("sms", "voice"), subject_key="person-X")
    world.email_grant(o, "x@example.com", subject_key="person-X")
    stack.run()
    stack.advance(days=3)
    world.capture(o, NY, channels=("sms", "voice"), subject_key="person-Y")  # the number now belongs to someone else
    for _ in range(201):
        world.capture(o, NY, channels=("voice",))
    token = _token_for(stack, "x@example.com")
    assert stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything").status == 200
    assert _stopped_channels(world, o, o.fp(NY)) == set()
    assert "email" in _stopped_channels(world, o, o.fp("x@example.com", "email"))


def test_a_household_phone_belongs_to_whoever_keyed_it_last(world, stack, armed):
    o = world.a
    world.capture(o, NY, channels=("sms", "voice"), subject_key="person-A")
    world.email_grant(o, "a@example.com", subject_key="person-A")
    world.email_grant(o, "b@example.com", subject_key="person-B")
    stack.run()
    world.capture(o, NY, channels=("sms", "voice"), subject_key="person-B")
    token_a = _token_for(stack, "a@example.com")
    assert stack.public("POST", "/c/stop/" + token_a, "consent.example.com", body=b"scope=everything").status == 200
    assert _stopped_channels(world, o, o.fp(NY)) == set()
    assert _stopped_channels(world, o, o.fp("b@example.com", "email")) == set()
    token_b = _token_for(stack, "b@example.com")
    assert stack.public("POST", "/c/stop/" + token_b, "consent.example.com", body=b"scope=everything").status == 200
    assert {"sms", "voice"} <= _stopped_channels(world, o, o.fp(NY))
    a_stops = world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s AND contact_fp = %s AND event_type = 'revoke'",
                        (o.org_id, o.fp("a@example.com", "email")))
    assert len(a_stops) == 1  # only person A's own stop; person B's stop everything never touches A's address


def test_an_erased_linked_contact_is_skipped_and_the_rest_are_stopped(world, stack, armed):
    o = world.a
    world.capture(o, NY, channels=("sms", "voice"), subject_key="person-1")
    world.email_grant(o, "dana@example.com", subject_key="person-1")
    world.email_grant(o, "dana2@example.com", subject_key="person-1")
    stack.run()
    world.erase(o, "dana2@example.com", kind="email")
    token = _token_for(stack, "dana@example.com")
    assert stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything").status == 200
    assert {"sms", "voice"} <= _stopped_channels(world, o, o.fp(NY))


# ---- quiet hours judged as the last step before the provider call ------------------------------------------------------------
def test_the_contended_send_is_skipped_for_quiet_hours_on_the_fresh_reading(world, stack, armed, db_follows_service_clock):
    test_a3_clock_read_before_a_contended_lock_sends_after_eight(world, stack, armed, db_follows_service_clock)
    rows = world.sql(world.a, "SELECT status, skip_reason FROM consentvault.confirmation_send_intent WHERE org_id = %s"
                              " AND channel = 'sms'", (world.a.org_id,))
    assert [(r["status"], r["skip_reason"]) for r in rows] == [("skipped", "quiet_hours")]
    assert world.sql(world.a, "SELECT 1 FROM consentvault.confirmation_page_token WHERE org_id = %s", (world.a.org_id,)) == []


def test_a_check_more_than_two_seconds_old_at_the_call_sends_nothing(world, stack, armed, monkeypatch, db_follows_service_clock):
    o = world.a
    o.boss.ok("PUT", f"/v1/confirmations/rules/{o.web_id}/email", body={"enabled": False, "sending_brand_id": o.brand_id})
    world.capture(o, NY)
    stack.service._clock = lambda: datetime(2026, 11, 4, 15, 0, 0, tzinfo=timezone.utc).timestamp()  # 10 AM New York
    reads = []
    monkeypatch.setattr("consentvault.confirm.sender._monotonic", lambda: (reads.append(1), 1000.0 + 3 * len(reads))[1])
    stack.service.run_sender()  # three seconds pass between the hours check and the provider call
    assert len(reads) == 2
    assert len(stack.twilio.sent) == 0
    rows = world.sql(o, "SELECT status, last_error, next_attempt_at FROM consentvault.confirmation_send_intent WHERE org_id = %s"
                        " AND channel = 'sms'", (o.org_id,))
    assert len(rows) == 1 and rows[0]["status"] == "intent" and rows[0]["last_error"] == "send_check_stale"
    assert rows[0]["next_attempt_at"] is not None


def test_a_reply_to_the_persons_own_message_is_not_held_by_the_hours_gate(world, stack, armed):
    from consentvault.confirm.sender import Plan, SenderMixin
    plan = Plan(None, "optout_reply", "sms", "twilio", None, {}, NY, "x", None, {}, None, None, "f", "phone", None, None, 1,
                datetime(2026, 11, 4, 3, 0, tzinfo=timezone.utc))
    late = datetime(2026, 11, 4, 3, 0, tzinfo=timezone.utc)  # 10 PM New York
    refused, _, _ = SenderMixin._send_gate(stack.service, plan, late)
    assert refused is None
    plan.kind, plan.zone = "confirmation", "America/New_York"
    refused, _, _ = SenderMixin._send_gate(stack.service, plan, late)
    assert refused == ("quiet_hours", None)


# ---- the email's time zone comes from a phone linked by the records layer --------------------------------------------------------
def _email_bodies(stack, address):
    return [m["body"] for m in stack.email.sent if m["to"] == address]


def test_the_email_names_the_zone_of_a_phone_linked_after_the_grant_it_confirms(world, stack, armed):
    """The confirmed grant carried no person key; the phone was linked to the same person before the send."""
    o = world.a
    world.email_grant(o, "dana@example.com")
    world.capture(o, NY, channels=("sms",), subject_key="person-1")
    world.email_grant(o, "dana@example.com", subject_key="person-1")
    stack.run()
    bodies = _email_bodies(stack, "dana@example.com")
    assert bodies and all(" ET" in b and "UTC" not in b for b in bodies), bodies


def test_the_email_names_the_linked_phones_zone_behind_more_than_200_unkeyed_events(world, stack, armed):
    o = world.a
    world.capture(o, NY, channels=("sms",), subject_key="person-1")
    for _ in range(201):
        world.capture(o, NY, channels=("voice",))
    world.capture(o, "+12135550150", channels=("voice",))  # a Pacific number of nobody's, recorded after
    world.email_grant(o, "dana@example.com", subject_key="person-1")
    stack.run()
    (body,) = _email_bodies(stack, "dana@example.com")
    assert " ET" in body and "UTC" not in body and " PT" not in body


def test_the_email_names_utc_when_the_linked_phone_now_belongs_to_someone_else(world, stack, armed):
    o = world.a
    world.capture(o, NY, channels=("sms",), subject_key="person-1")
    world.capture(o, NY, channels=("sms",), subject_key="person-2")  # reassigned
    world.email_grant(o, "dana@example.com", subject_key="person-1")
    stack.run()
    (body,) = _email_bodies(stack, "dana@example.com")
    assert "UTC" in body and " ET" not in body


def test_a_person_key_that_is_the_emails_own_hash_still_stops_the_linked_phone(world, stack, armed):
    """An integration keys the person by the hash of their email, which is also the email's own default key."""
    import hashlib
    o = world.a
    world.capture(o, NY, channels=("sms", "voice", "artificial_voice"), subject_key=hashlib.sha256(b"dana@example.com").hexdigest())
    world.email_grant(o, "dana@example.com")
    assert _linked_counts(o) == {"phone": 1, "email": 1}
    stack.run()
    token = _token_for(stack, "dana@example.com")
    assert stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything").status == 200
    assert _phone_allowed(world, o) == []
