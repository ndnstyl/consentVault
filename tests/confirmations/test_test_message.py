"""confirmations.md endpoint table (POST /v1/confirmations:test): a test message obeys a stop on record, texting hours and a cap of
5 an hour per organization."""

from datetime import datetime, timezone

from contract_world.confirm import sends
from contract_world.world import PHONE

NY = "+13055550150"


def send(o, to=NY):
    return o.boss.call("POST", "/v1/confirmations:test", body={"source_id": o.web_id, "channel": "sms", "contact": to})


def test_a_contact_with_a_stop_on_record_gets_no_test_message(world, stack, armed):
    o = world.a
    world.capture(o, NY)
    world.stop(o, NY)
    r = send(o)
    assert r.status == 422 and r.body["error"] == "validation_failed" and stack.twilio.sent == []


def test_a_test_text_outside_texting_hours_is_refused(world, stack, armed, db_follows_service_clock):
    stack.clock.set(datetime(2026, 11, 4, 8, 0, tzinfo=timezone.utc))  # 3 AM in New York
    r = send(world.a)
    assert r.status == 422 and stack.twilio.sent == []
    stack.clock.set(datetime(2026, 11, 4, 15, 0, tzinfo=timezone.utc))
    assert send(world.a).status == 200 and len(stack.twilio.sent) == 1


def test_the_sixth_test_message_in_an_hour_is_refused_and_the_cap_lifts_after_the_hour(world, stack, armed, db_follows_service_clock):
    o = world.a
    assert [send(o).status for _ in range(5)] == [200] * 5
    r = send(o)
    assert r.status == 429 and r.body["error"] == "rate_limited" and len(stack.twilio.sent) == 5
    stack.advance(minutes=61)
    assert send(o).status == 200


def test_stop_everything_from_an_email_link_also_stops_the_same_persons_phone(world, stack, armed):
    """confirmations.md section 7 (the email stop page): stopping everything stops the person, so the phone linked by the person
    key loses texts, automated calls and AI-voice calls too, and email stops."""
    o = world.a
    world.capture(o, NY, channels=("sms", "voice", "artificial_voice"), subject_key="person-1")
    world.email_grant(o, "dana@example.com", subject_key="person-1")
    stack.run()
    token = stack.email.sent[0]["body"].split("/c/stop/")[1].split()[0].rstrip(".")
    assert stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything").status == 200
    rows = {i["contact_kind"]: i for i in o.boss.ok("GET", "/v1/records", {})["items"]}
    assert rows["phone"]["has_stop"] is True and rows["email"]["has_stop"] is True
    stops = world.sql(o, "SELECT channels FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke'", (o.org_id,))
    assert sorted(sorted(s["channels"]) for s in stops) == [["artificial_voice", "email", "sms", "voice"], ["artificial_voice", "sms", "voice"]]
    before = len(stack.twilio.sent)
    stack.advance(days=2)
    world.capture(o, NY)  # a later grant of the phone is not confirmed: a stop is on record
    stack.run()
    assert len(stack.twilio.sent) == before
    again = stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything")
    assert b"Already stopped" in again.raw


def test_a_start_the_provider_does_not_confirm_leaves_the_stop_in_place_with_a_named_reason(world, stack, armed):
    from contract_world.confirm import replies, text_in
    o = world.a
    world.capture(o, NY)
    world.stop(o, NY)
    stack.twilio.unknown_messages.add("SMfake")
    text_in(armed, "START", sender=NY, sid="SMfake")
    assert [e for e in world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s AND recorded_by = 'confirmations'", (o.org_id,))] == []
    (got,) = replies(o.boss)
    assert got["state"] == "to_read" and "provider_unconfirmed" in got["reason"]
    stack.twilio.unreachable = False
    text_in(armed, "START", sender=NY, sid="SMreal")
    assert world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s AND recorded_by = 'confirmations'"
                        " AND event_type = 'grant'", (o.org_id,))
    assert ("SMreal", NY) in stack.twilio.asked_about


def test_erasing_a_contact_cancels_its_queued_sends_and_leaves_no_sealed_number_in_a_queued_reply(world, stack, armed):
    """confirmations.md section 7: in the erasure's own transaction, pending intents for the contact are skipped contact_erased and no
    reply intent keeps a sealed destination or text; what the contact wrote from an unkept number is deleted."""
    from contract_world.confirm import text_in
    o = world.a
    world.capture(o, NY)  # a confirmation waits in the queue
    stack.twilio.script = [("retry", 503)] * 5
    text_in(armed, "HELP", sender=NY, sid="SMh")  # our answer failed once and waits for its retry, its number sealed
    text_in(armed, "who is this", sender="+15555550888", sid="SMu")
    queued = world.sql(o, "SELECT dest_ct FROM consentvault.confirmation_send_intent WHERE org_id = %s AND kind = 'help_reply'", (o.org_id,))
    assert queued and queued[0]["dest_ct"] is not None
    world.erase(o, NY)
    rows = world.sql(o, "SELECT kind, status, skip_reason, dest_ct, body_ct FROM consentvault.confirmation_send_intent"
                        " WHERE org_id = %s", (o.org_id,))
    assert rows and all(r["dest_ct"] is None and r["body_ct"] is None for r in rows)
    assert {(r["kind"], r["skip_reason"]) for r in rows if r["status"] == "skipped"} >= {("confirmation", "contact_erased")}
    sent = len(stack.twilio.sent)
    stack.run(minutes=2)
    assert len(stack.twilio.sent) == sent  # nothing more goes to the erased number
    assert len(world.sql(o, "SELECT 1 FROM consentvault.confirmation_reply WHERE org_id = %s AND key_kind = 'org'", (o.org_id,))) == 1


def test_the_confirmations_token_cannot_list_search_or_reveal_records(world, stack, armed):
    """auth.md (records_read is a portal scope, never a machine's): the service's own token reads no record, mask or name, and the
    records routes refuse it."""
    import uuid
    from consentvault.db import connect
    from consentvault.tenancy.admin_routes import Request
    from consentvault.tenancy.tokens import org_transaction
    o = world.a
    world.capture(o, NY, display={"name": "Dana Cruz"})
    token = stack.service._token(uuid.UUID(o.org_id))
    with connect(world.vault.app_dsn) as c, org_transaction(c, token):
        for table in ("record", "record_index", "record_display"):
            assert c.execute(f"SELECT count(*) AS n FROM consentvault.{table}").fetchone()["n"] == 0, table
    for method, path, body in (("GET", "/v1/records", None), ("POST", "/v1/records:search", {"contact": NY}),
                               ("POST", "/v1/records:reveal", {"record_ids": [str(uuid.uuid4())]})):
        r = world.vault.app.handle(Request(method, path, {}, body, tenant_token=token, request_id="req-machine"))
        assert r.status == 401, (path, r.status, r.body)


def test_a_number_whose_zone_cannot_be_determined_gets_no_test_text_at_any_hour(world, stack, armed):
    """Fail safe: 423 is pinned as unknown (a Tennessee code split between Eastern and Central); a 555 range, and a number outside
    North America, are unknown too. Three in the morning in New York and in London are both refused."""
    from consentvault.confirm import zones
    assert zones.zone_for_phone("+14235550100") is None and "423" not in zones.AREA_ZONE
    stack.clock.set(datetime(2026, 11, 4, 8, 0, tzinfo=timezone.utc))
    for to in ("+14235550100", "+15555550100"):
        r = send(world.a, to)
        assert r.status == 422 and "time_zone_unknown" in str(r.body)
    stack.clock.set(datetime(2026, 11, 4, 3, 0, tzinfo=timezone.utc))
    assert send(world.a, "+447700900123").status == 422
    stack.clock.set(datetime(2026, 11, 4, 15, 0, tzinfo=timezone.utc))
    assert send(world.a, "+14235550100").status == 422 and stack.twilio.sent == []


def _token_for(stack, address):
    sent = [m for m in stack.email.sent if address in str(m)]
    return sent[0]["body"].split("/c/stop/")[1].split()[0].rstrip(".")


def test_a_reassigned_number_is_not_stopped_by_the_old_owners_stop_everything(world, stack, armed):
    o = world.a
    world.capture(o, NY, channels=("sms",), subject_key="person-X")
    world.email_grant(o, "x@example.com", subject_key="person-X")
    stack.run()
    stack.advance(days=3)
    world.capture(o, NY, channels=("sms",), subject_key="person-Y")
    token = _token_for(stack, "x@example.com")
    assert stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything").status == 200
    stops = world.sql(o, "SELECT channels FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke'", (o.org_id,))
    assert [s for s in stops if "sms" in s["channels"] and "email" not in s["channels"]] == []


def test_another_household_members_email_is_untouched(world, stack, armed):
    o = world.a
    world.capture(o, NY, subject_key="person-A")
    world.email_grant(o, "a@example.com", subject_key="person-A")
    world.email_grant(o, "b@example.com", subject_key="person-B")
    stack.run()
    token = _token_for(stack, "a@example.com")
    stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything")
    assert len([r for r in world.sql(o, "SELECT channels FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke'",
                                     (o.org_id,)) if "email" in r["channels"]]) == 1


def test_five_test_messages_race_to_a_cap_of_five(world, stack, armed, monkeypatch):
    import threading
    from datetime import datetime, timezone
    from consentvault.confirm import sender as S
    monkeypatch.setattr(S, "db_now", lambda conn: datetime(2026, 11, 3, 17, 0, tzinfo=timezone.utc))   # noon in Miami, whatever the real hour
    o = world.a
    results = []
    threads = [threading.Thread(target=lambda: results.append(send(o).status)) for _ in range(9)]
    [t.start() for t in threads]
    [t.join(60) for t in threads]
    assert sorted(results).count(200) == 5 and len(stack.twilio.sent) == 5


def test_a_twilio_connection_through_a_messaging_service_still_needs_the_account_sid(world, stack):
    body = {"channel": "sms", "provider": "twilio", "sender": {"messaging_service_sid": "MG" + "0" * 32}, "provider_replies_itself": False,
            "credentials": {"api_key_sid": "SKtest", "api_key_secret": stack.twilio.api_key_secret, "auth_token": stack.twilio.auth_token}}
    r = world.a.boss.call("POST", "/v1/confirmations/sending-accounts", body=body)
    assert r.status == 422 and "account_sid" in str(r.body)


def test_message_exists_rejects_odd_ids_wrong_direction_and_a_hostile_account_id():
    from consentvault.confirm import providers as p
    tw, real = p.TwilioProvider(), p._call
    creds = {"api_key_sid": "SK1", "api_key_secret": "x", "account_sid": "AC" + "0" * 32}
    calls = []
    try:
        p._call = lambda req, host: (calls.append(req.full_url), (200, b'{"direction": "outbound-api", "from": "+13055550150"}'))[1]
        assert tw.message_exists(creds, message_id="../../x", from_number=NY) is False and calls == []
        assert tw.message_exists(creds, message_id="SM1", from_number=NY) is False
        p._call = lambda req, host: (200, b'{"direction": "inbound", "from": "+13055550151"}')
        assert tw.message_exists(creds, message_id="SM1", from_number=NY) is False
        p._call = lambda req, host: (200, b"[1,2]")
        assert tw.message_exists(creds, message_id="SM1", from_number=NY) is False
        p._call = lambda req, host: (calls.append(req.full_url), (200, b"{}"))[1]
        tw.message_exists(dict(creds, account_sid="AC0/../../x@evil.com"), message_id="SM1", from_number=NY)
    finally:
        p._call = real
    assert calls[-1].split("/")[2] == "api.twilio.com" and "%2F" in calls[-1]


def test_stop_everything_still_stops_calls_after_the_person_texted_a_stop(world, stack, armed):
    """The newest event on the phone is a stop with no person key of its own; the owner is the newest event that carries one."""
    o = world.a
    world.capture(o, NY, channels=("sms", "voice", "artificial_voice"), subject_key="person-1")
    world.email_grant(o, "dana@example.com", subject_key="person-1")
    stack.run()
    world.stop(o, NY, channels=("sms",))  # the person's own text-only stop, filed under the contact's default key
    token = _token_for(stack, "dana@example.com")
    assert stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything").status == 200
    stops = world.sql(o, "SELECT channels FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke'", (o.org_id,))
    covered = {c for s in stops for c in s["channels"]}
    assert {"sms", "voice", "artificial_voice", "email"} <= covered
    phone_cells = world.sql(o, "SELECT channel, allowed FROM consentvault.current_permission WHERE org_id = %s AND contact_fp = %s",
                            (o.org_id, o.fp(NY)))
    assert phone_cells and not any(c["allowed"] for c in phone_cells)


def test_a_batch_that_starts_before_eight_pm_holds_every_message_the_clock_carries_past_eight(world, stack, armed, db_follows_service_clock):
    """The clock is read at the claim and again as the last step before the send: no text goes after 8 PM local."""
    o = world.a
    o.boss.ok("PUT", f"/v1/confirmations/rules/{o.web_id}/email", body={"enabled": False, "sending_brand_id": o.brand_id})  # texts only
    base = datetime(2026, 11, 4, 0, 59, 30, tzinfo=timezone.utc)  # 7:59:30 PM in New York: the first text's send check reads 7:59:50
    for n in range(3):
        world.capture(o, f"+1305555016{n}")
    ticks = {"n": -1}

    def clock():
        ticks["n"] += 1
        return base.timestamp() + 20 * ticks["n"]
    stack.service._clock = clock
    stack.service.run_sender()
    sent = len(stack.twilio.sent)
    reasons = sorted(s["skip_reason"] for s in sends(o.boss, channel="sms") if s["status"] == "skipped")
    assert (sent, reasons) == (1, ["quiet_hours", "quiet_hours"]), [(s["status"], s["skip_reason"], s["at"]) for s in sends(o.boss, channel="sms")]
