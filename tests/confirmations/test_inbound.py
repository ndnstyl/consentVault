"""confirmations.md sections 7 and 9: inbound webhook checks, classification, stops, START, HELP, our replies, public pages."""

import uuid

import pytest

from contract_world.confirm import OUR_NUMBER, replies, sends, text_in
from contract_world.world import EMAIL, PENDING, PHONE

P = "+13055550142"


def events(world, org, kind=None):
    q = "SELECT * FROM consentvault.event WHERE org_id = %s" + (" AND event_type = %s" if kind else "") + " ORDER BY seq"
    return world.sql(org, q, (org.org_id,) + ((kind,) if kind else ()))


def _plain_session(world, org, ev):
    """The event's session reference, read the way the vault reads it: open the contact key, decrypt session_ref_ct."""
    from consentvault.tenancy import crypto as tc
    from consentvault.tenancy.keys_protocol import WrappedKey
    import uuid
    held = world.sql(org, "SELECT wrapped_key, key_version FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                     (org.org_id, ev["contact_fp"]))[0]
    dk = world.crypto.open_contact_key(uuid.UUID(org.org_id), WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
    return tc.decrypt_text(dk, org.org_id, str(ev["event_id"]), "session_ref", bytes(ev["session_ref_ct"]))


def counts(world, org):
    return {t: len(world.sql(org, f"SELECT 1 FROM consentvault.{t} WHERE org_id = %s", (org.org_id,)))
            for t in ("event", "contact_log", "confirmation_reply")}


def test_a_signature_over_the_stored_url_is_accepted_even_with_a_forged_forwarded_host(world, stack, armed):
    """confirmations.md section 9 check 1 (signature over the stored inbound_url, never forwarded headers)."""
    r = stack.inbound(armed.twilio_key, {"From": P, "To": OUR_NUMBER, "Body": "hello", "MessageSid": "SM1"},
                      headers={"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http"})
    assert r.status == 200


def test_a_request_signed_over_another_url_or_with_a_bad_signature_is_refused_and_counted(world, stack, armed):
    """confirmations.md section 9 check 1 (401; inbound_signature_failures_1h; 5 in 10 minutes alarm naming the account)."""
    o = world.a
    for i in range(5):
        r = stack.inbound(armed.twilio_key, {"From": P, "To": OUR_NUMBER, "Body": "STOP", "MessageSid": f"SMb{i}"},
                          sign_url="https://evil.example/v1/confirmations/inbound/" + armed.twilio_key)
        assert r.status == 401
    assert counts(world, o)["confirmation_reply"] == 0 and events(world, o, "revoke") == []
    assert o.boss.ok("GET", "/v1/confirmations/settings")["counts"]["inbound_signature_failures_1h"] == 5
    alarm = stack.alarms(o.boss)["inbound_signature_failures"]
    acct = [a for a in o.boss.ok("GET", "/v1/confirmations/settings")["sending_accounts"] if a["channel"] == "sms"][0]
    assert alarm["opened_at"] and acct["account_id"] in str(alarm["detail"])  # the alarm names the account


def test_a_body_over_16_kb_is_refused_413_before_anything_is_stored_and_counted(world, stack, armed):
    """confirmations.md section 9 check 0 (16384 bytes is the limit; 16385 answers 413 inbound_too_large before the signature
    is computed; nothing stored; counted with the signature failures)."""
    o = world.a
    before = counts(world, o)
    n0 = o.boss.ok("GET", "/v1/confirmations/settings")["counts"]["inbound_signature_failures_1h"]
    r = stack.service.handle_inbound(armed.twilio_key, headers={"X-Twilio-Signature": "bad"}, body=b"a=" + b"x" * 16383,
                                     url="https://api.consentvault.ai/v1/confirmations/inbound/" + armed.twilio_key)
    assert r.status == 413 and r.payload["error"] == "inbound_too_large"
    assert counts(world, o) == before and world.sql(o, "SELECT 1 FROM consentvault.confirmation_inbound_seen WHERE org_id = %s AND provider_message_id = ''", (o.org_id,)) == []
    assert o.boss.ok("GET", "/v1/confirmations/settings")["counts"]["inbound_signature_failures_1h"] == n0 + 1
    at_limit = stack.service.handle_inbound(armed.twilio_key, headers={"X-Twilio-Signature": "bad"}, body=b"a=" + b"x" * 16382,
                                            url="https://api.consentvault.ai/v1/confirmations/inbound/" + armed.twilio_key)
    assert at_limit.status == 401  # exactly 16384 bytes passes the size check and fails the signature


def test_an_unknown_inbound_key_is_refused(world, stack, armed):
    """confirmations.md section 9 (inbound_key is random per sending account)."""
    r = stack.inbound("not-a-real-key", {"From": P, "To": OUR_NUMBER, "Body": "STOP", "MessageSid": "SMx"})
    assert r.status in (401, 404)


def test_a_message_to_a_number_that_is_not_the_connected_number_is_refused_and_records_nothing(world, stack, armed):
    """confirmations.md section 9 check 2 (403 inbound_number_mismatch, counted with signature failures, nothing recorded)."""
    o = world.a
    before = counts(world, o)
    r = stack.inbound(armed.twilio_key, {"From": P, "To": "+15555550999", "Body": "STOP", "MessageSid": "SMm"})
    assert r.status == 403 and r.payload["error"] == "inbound_number_mismatch"
    assert counts(world, o) == before
    assert o.boss.ok("GET", "/v1/confirmations/settings")["counts"]["inbound_signature_failures_1h"] >= 1


def test_the_same_provider_message_id_twice_records_once_and_audits_the_replay(world, stack, armed):
    """confirmations.md section 9 check 3 (200 with no change; one event, one reply row; confirmations.inbound_replayed row
    with the message id; event count, release rows and contact_log unchanged by the second post)."""
    o = world.a
    world.capture(o, P)
    world.stop(o, P)
    assert text_in(armed, "START", sender=P, sid="SMdup").status == 200
    after_first = counts(world, o)
    releases = len(world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s AND release_of_event_id IS NOT NULL", (o.org_id,)))
    r = text_in(armed, "START", sender=P, sid="SMdup")
    assert r.status == 200
    assert counts(world, o) == after_first
    assert len(world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s AND release_of_event_id IS NOT NULL", (o.org_id,))) == releases
    assert len([x for x in replies(o.boss)]) == 1
    (row,) = world.audit(o.boss, "confirmations.inbound_replayed")
    assert "SMdup" in str(row)


def test_a_replay_months_later_is_still_refused_and_the_seen_key_is_per_organization(world, stack, armed):
    """confirmations.md section 9 check 3 (rows kept for the organization's retention; unique per org, provider, id)."""
    o = world.a
    text_in(armed, "hello", sender=P, sid="SMold")
    stack.advance(days=200)
    stack.service.purge(now=stack.clock())  # the daily purge runs: unmatched texts go, the seen-message rows stay
    n = counts(world, o)
    seen = lambda: len(world.sql(o, "SELECT 1 FROM consentvault.confirmation_inbound_seen WHERE org_id = %s AND provider_message_id = 'SMold'", (o.org_id,)))
    assert seen() == 1
    assert text_in(armed, "hello", sender=P, sid="SMold").status == 200 and counts(world, o) == n and seen() == 1
    assert len(world.audit(o.boss, "confirmations.inbound_replayed")) == 1


def test_an_inbound_that_cannot_be_recorded_answers_503_and_the_retry_is_not_a_replay(world, stack, armed):
    """confirmations.md section 9 (503 so the provider retries; seen row in the same transaction so the retry records)."""
    o = world.a
    world.capture(o, P)
    with world.vault.superuser() as su:
        su.execute("CREATE FUNCTION public.cvt_f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'down'; END $$")
        su.execute("CREATE TRIGGER cvt_f BEFORE INSERT ON consentvault.confirmation_reply FOR EACH ROW EXECUTE FUNCTION public.cvt_f()")
    try:
        assert text_in(armed, "STOP", sender=P, sid="SMretry").status == 503
    finally:
        with world.vault.superuser() as su:
            su.execute("DROP TRIGGER cvt_f ON consentvault.confirmation_reply")
            su.execute("DROP FUNCTION public.cvt_f()")
    assert world.sql(o, "SELECT 1 FROM consentvault.confirmation_inbound_seen WHERE org_id = %s AND provider_message_id = 'SMretry'", (o.org_id,)) == []
    assert text_in(armed, "STOP", sender=P, sid="SMretry").status == 200
    assert len(events(world, o, "revoke")) == 1


@pytest.mark.parametrize("body,verdict,state,stops", [
    ("STOP", "stop", "stop", True), ("stopall", "stop", "stop", True), ("Unsubscribe", "stop", "stop", True),
    ("remove me", "stop", "stop", True), ("PARAR", "stop", "stop", True), ("QUIT", "stop", "stop", True),
    ("please stop texting me", "stop", "stop", True),
    ("don't stop", "needs_review", "to_read", False),
    ("START", "start", "start", False), ("HELP", "help", "help", False), ("INFO", "help", "help", False),
    ("bus stop", "not_stop", "to_read", False), ("thanks", "not_stop", "to_read", False), ("I will quit my job", "not_stop", "to_read", False),
])
def test_replies_are_classified_by_the_core_classifier_and_mapped_to_an_action(world, stack, armed, body, verdict, state, stops):
    """confirmations.md section 7 (classification table: stop words and phrases stop; a stop word in a longer message is a stop
    with verdict needs_review; negated and near-miss text goes to read; END and QUIT only as the whole message; everything else
    is to_read with verdict not_stop)."""
    o = world.a
    world.capture(o, P)
    assert text_in(armed, body, sender=P).status == 200
    assert len(events(world, o, "revoke")) == (1 if stops else 0)
    (got,) = replies(o.boss)
    assert (got["verdict"], got["state"]) == (verdict, state)
    assert (got["event_id"] is not None) is stops


@pytest.mark.parametrize("body", ["yes please", "Start.", "START START", "start now", "please START"])
def test_a_start_that_is_not_the_whole_message_goes_to_read_and_lifts_nothing(world, stack, armed, body):
    """confirmations.md section 7 (start words START, UNSTOP and YES count only alone: any other text, punctuation or a repeat
    is not a start and goes to the to-read list)."""
    o = world.a
    world.capture(o, P)
    world.stop(o, P)
    text_in(armed, body, sender=P)
    assert [e for e in events(world, o, "grant") if e["recorded_by"] == "confirmations"] == []
    (got,) = replies(o.boss)
    assert got["state"] == "to_read" and got["verdict"] != "start" and got["event_id"] is None


@pytest.mark.parametrize("body", ["UNSTOP", "YES", "start", "Start", "unstop", "yes"])
def test_a_whole_message_start_word_in_any_case_lifts_a_consumers_own_stop(world, stack, armed, body):
    """confirmations.md section 7 (START, UNSTOP and YES alone, case-insensitive, are a start: one keyword grant naming sms)."""
    o = world.a
    world.capture(o, P)
    world.stop(o, P)
    text_in(armed, body, sender=P)
    grants = [e for e in events(world, o, "grant") if e["recorded_by"] == "confirmations"]
    assert len(grants) == 1 and list(grants[0]["channels"]) == ["sms"] and grants[0]["method"] == "keyword"
    (got,) = replies(o.boss)
    assert (got["verdict"], got["state"]) == ("start", "start") and got["event_id"] == str(grants[0]["event_id"])


def test_a_stop_reply_is_one_revoke_across_sms_voice_and_artificial_voice_and_leaves_email(world, stack, armed):
    """confirmations.md section 7 (a stop: channels = org's own among sms, voice, artificial_voice; purposes ['*']; method
    keyword; origin consumer; source Confirmation replies; recorded_by confirmations; session_ref provider:id)."""
    o = world.a
    world.capture(o, P, channels=("sms", "voice"))
    world.email_grant(o, EMAIL, subject_key=None)
    text_in(armed, "STOP", sender=P, sid="SMs1")
    (ev,) = events(world, o, "revoke")
    assert sorted(ev["channels"]) == ["artificial_voice", "sms", "voice"] and list(ev["purposes"]) == ["*"]
    assert ev["method"] == "keyword" and ev["origin"] == "consumer" and ev["recorded_by"] == "confirmations"
    from consentvault.tenancy import crypto as tc
    assert _plain_session(world, o, ev) == "twilio:SMs1"
    src = world.sql(o, "SELECT name FROM consentvault.capture_source WHERE org_id = %s AND source_id = %s", (o.org_id, ev["source_id"]))[0]
    assert src["name"] == "Confirmation replies"
    rec = {i["contact_kind"]: i for i in o.boss.ok("GET", "/v1/records", {})["items"]}
    assert rec["phone"]["has_stop"] is True and rec["email"]["has_stop"] is False


def test_a_stop_is_pushed_to_connected_systems_like_any_stop(world, stack, armed):
    """confirmations.md section 7 (pushed to connected systems like any stop)."""
    o = world.a
    o.boss.ok("POST", "/v1/systems", body={"name": "Dialer", "kind": "dialer", "endpoint": "https://dialer.example/hook",
                                            "signature": "ed25519", "contact_form": "fingerprint"})
    world.capture(o, P)
    n = len(world.sql(o, "SELECT 1 FROM consentvault.outbox WHERE org_id = %s", (o.org_id,)))
    text_in(armed, "STOP", sender=P)
    assert len(world.sql(o, "SELECT 1 FROM consentvault.outbox WHERE org_id = %s", (o.org_id,))) > n


def test_the_inbound_text_is_stored_encrypted_under_the_contact_key_or_the_org_key(world, stack, armed):
    """confirmations.md section 7 (stored as received, encrypted; fields; no record: under the org key, kept 30 days)."""
    o = world.a
    world.capture(o, P)
    text_in(armed, "please stop texting me", sender=P)
    text_in(armed, "who is this", sender="+15555550888")
    rows = world.sql(o, "SELECT * FROM consentvault.confirmation_reply WHERE org_id = %s", (o.org_id,))
    assert len(rows) == 2 and all(b"stop" not in bytes(r["body_ct"]) and b"who is" not in bytes(r["body_ct"]) for r in rows)
    assert {"reply_id", "from_fp", "matched_record_id", "body_ct", "received_at", "provider_message_id", "verdict", "reason", "matched_words"} <= set(rows[0])
    assert sum(r["matched_record_id"] is not None for r in rows) == 1


def test_reply_reads_show_text_to_admin_and_viewer_only_and_are_audited(world, stack, armed):
    """confirmations.md section 8 (replies list: filters state/from/to; text for A and V only; D refused; audited)."""
    o = world.a
    world.capture(o, P)
    text_in(armed, "don't stop", sender=P)
    got = replies(o.boss, state="to_read")
    assert got and "don't stop" in str(got)
    assert set(got[0]) == {"reply_id", "received_at", "account_id", "channel", "from", "matched_record_id", "text", "verdict", "reason",
                           "matched_words", "state", "event_id", "our_reply", "marked_by", "marked_at", "mark_reason", "unread_hours"}
    assert got[0]["channel"] == "sms" and got[0]["verdict"] == "needs_review" and got[0]["state"] == "to_read"
    assert got[0]["from"]["fp_hint"] == world.a.fp(P)[:8] and got[0]["from"]["masked"] and got[0]["event_id"] is None
    assert got[0]["marked_by"] is None and got[0]["marked_at"] is None and got[0]["mark_reason"] is None
    assert got[0]["unread_hours"] is not None and got[0]["our_reply"] in ("sent", "skipped", "provider_replied", None)
    assert "don't stop" in str(replies(o.viewer))
    o.dev.err("GET", "/v1/confirmations/replies", name="role_not_allowed")
    assert replies(o.boss, **{"from": "2100-01-01T00:00:00Z"}) == []
    assert len(world.audit(o.boss, "confirmations.replies_listed")) >= 2
    assert "don't stop" not in str(world.audit(o.boss, "confirmations.replies_listed"))


def test_an_admin_marks_a_reply_as_a_stop_with_method_written_or_not_a_stop_with_a_reason(world, stack, armed):
    """confirmations.md section 7 (to-read: stop = method written, origin consumer, recorded_by the member, reason required)."""
    o = world.a
    world.capture(o, P)
    text_in(armed, "don't stop", sender=P, sid="SMr1")
    rid = replies(o.boss, state="to_read")[0]["reply_id"]
    o.boss.err("POST", f"/v1/confirmations/replies/{rid}:mark", body={"decision": "stop"}, name="validation_failed")
    o.dev.err("POST", f"/v1/confirmations/replies/{rid}:mark", body={"decision": "stop", "reason": "x"}, name="role_not_allowed")
    o.boss.ok("POST", f"/v1/confirmations/replies/{rid}:mark", body={"decision": "stop", "reason": "they meant stop"})
    marked = [x for x in replies(o.boss) if x["reply_id"] == rid][0]
    assert marked["state"] == "stop" and marked["event_id"] and marked["unread_hours"] is None and marked["mark_reason"] == "they meant stop"
    assert marked["marked_by"]["member_id"] == o.boss.member_id and marked["marked_at"]
    (ev,) = events(world, o, "revoke")
    assert ev["method"] == "written" and ev["origin"] == "consumer" and o.boss.member_id in str(ev["recorded_by"])
    assert len(world.audit(o.boss, "confirmations.reply_marked")) == 1
    text_in(armed, "thanks but not now", sender=P, sid="SMr2")
    r2 = [x for x in replies(o.boss) if x["reply_id"] != rid][0]["reply_id"]
    o.boss.err("POST", f"/v1/confirmations/replies/{r2}:mark", body={"decision": "not_stop"}, name="validation_failed")
    o.boss.ok("POST", f"/v1/confirmations/replies/{r2}:mark", body={"decision": "not_stop", "reason": "polite"})


def test_an_unread_reply_for_24_hours_raises_the_alarm_and_counts_show_in_settings(world, stack, armed):
    """confirmations.md section 2 and 7 (to_read, to_read_oldest_at; unread 24 hours alarms)."""
    o = world.a
    world.capture(o, P)
    text_in(armed, "don't stop", sender=P)
    c = o.boss.ok("GET", "/v1/confirmations/settings")["counts"]
    assert c["to_read"] == 1 and c["to_read_oldest_at"]
    stack.clock.advance(hours=25)
    assert "replies_unread_24h" not in stack.alarms(o.boss)
    stack.service.run_alarm_checks(now=stack.clock())
    assert "replies_unread_24h" in stack.alarms(o.boss)


# ---- START ---------------------------------------------------------------------------------------------------------------
def test_start_after_a_stop_is_a_keyword_grant_naming_texts_only_and_lifts_the_stop(world, stack, armed):
    """confirmations.md section 7 (START: tenant_capture, checked true, channels sms, method keyword, contact_verification
    inbound_keyword, session_ref, source Confirmation replies; the core release rule decides)."""
    o = world.a
    world.capture(o, P, channels=("sms", "voice"))
    world.stop(o, P, channels=("sms", "voice", "artificial_voice"))
    text_in(armed, "START", sender=P, sid="SMst")
    grants = [e for e in events(world, o, "grant") if e["recorded_by"] == "confirmations"]
    assert len(grants) == 1 and list(grants[0]["channels"]) == ["sms"] and grants[0]["method"] == "keyword"
    assert _plain_session(world, o, grants[0]) == "twilio:SMst" and grants[0]["contact_verification"] == "inbound_keyword"
    assert grants[0]["disclosure_sha256"] == o.wording
    rec = o.boss.ok("GET", "/v1/records", {})["items"][0]
    assert rec["channels"]["sms"]["counts"]["consent_record_found"] >= 1
    assert rec["channels"]["voice"]["counts"]["stop_on_record"] >= 1


def test_start_with_no_stop_on_record_changes_nothing_and_sends_no_reply(world, stack, armed):
    """confirmations.md section 7 (no stop on record: START recorded, changes nothing; no reply)."""
    o = world.a
    world.capture(o, P)
    stack.twilio.sent.clear()
    n = len(events(world, o))
    text_in(armed, "START", sender=P)
    assert stack.twilio.sent == []
    assert [e for e in events(world, o, "grant") if e["recorded_by"] == "confirmations"] == [] and len(events(world, o)) == n  # no grant, no event
    (got,) = replies(o.boss)
    assert got["verdict"] == "start" and got["event_id"] is None  # recorded as a reply only


def test_start_after_a_stop_with_no_earlier_grant_is_a_reply_only_with_the_refused_text(world, stack, armed):
    """confirmations.md section 7 (with no earlier grant there is no wording to name: no_held_disclosure, START recorded as a
    reply only, the refused text is sent and the reply goes to the to-read list with the cause)."""
    o = world.a
    world.stop(o, P)  # a stop on a contact who never granted
    stack.twilio.sent.clear()
    text_in(armed, "START", sender=P, sid="SMng1")
    assert [e for e in events(world, o, "grant") if e["recorded_by"] == "confirmations"] == []
    assert any("We could not turn texts back on from this message. Contact us at" in m["body"] for m in stack.twilio.sent)
    (got,) = replies(o.boss)
    assert got["state"] == "to_read" and "no_held_disclosure" in (got["reason"] or "")


def test_start_from_a_number_with_no_record_is_a_reply_only(world, stack, armed):
    """confirmations.md section 7 and 10 (a reply from a number with no record is kept under the org key, writes no event and no
    contact log row)."""
    o = world.a
    text_in(armed, "START", sender="+15555550888")
    assert [e for e in events(world, o) if e["recorded_by"] == "confirmations"] == []


def test_start_is_refused_when_the_stop_was_not_the_consumers_own(world, stack, armed):
    """confirmations.md section 7 (stop_not_consumers_own: a stop of origin staff is not lifted; the refused text is sent and the
    reply goes to the to-read list with the cause)."""
    o = world.a
    world.capture(o, P)
    world.stop(o, P, origin="staff", method="written")
    stack.twilio.sent.clear()
    text_in(armed, "START", sender=P, sid="SMn1")
    assert not [e for e in events(world, o, "grant") if e["recorded_by"] == "confirmations"]
    refused = [m["body"] for m in stack.twilio.sent]
    assert len(refused) == 1 and refused[0].startswith("Acme Flooring: We could not turn texts back on from this message. Contact us at ") and refused[0].endswith(" and we will help.")
    (got,) = replies(o.boss)
    assert got["state"] == "to_read" and "stop_not_consumers_own" in (got["reason"] or "")


def test_start_is_refused_when_the_wording_the_person_agreed_to_names_no_text(world, stack, armed):
    """confirmations.md section 7 (the latest grant's wording does not name sms: GrantScopeError, START recorded as a reply only,
    refused text sent, reply to read)."""
    o = world.a
    voice_only = world.register_wording(o, "Acme may call you about offers. Reply STOP to end.", ["voice"], ["marketing"])
    world.capture(o, P, channels=("voice",), wording=voice_only)
    world.stop(o, P, channels=("voice",))
    stack.twilio.sent.clear()
    text_in(armed, "START", sender=P, sid="SMn2")
    assert not [e for e in events(world, o, "grant") if e["recorded_by"] == "confirmations"]
    assert any("We could not turn texts back on from this message. Contact us at" in m["body"] for m in stack.twilio.sent)
    (got,) = replies(o.boss)
    assert got["state"] == "to_read" and "GrantScopeError" in (got["reason"] or "")


def test_start_lifts_a_stop_even_after_our_own_opt_out_reply(world, stack, armed, monkeypatch):
    """confirmations.md section 7 (C2: our own replies do not count as contact since the stop, with the release rule's
    no-contact-since-stop check switched on)."""
    monkeypatch.setenv("CONSENTVAULT_RELEASE_REQUIRE_NO_CONTACT_SINCE_STOP", "1")
    o = world.a
    world.capture(o, P)
    text_in(armed, "STOP", sender=P, sid="SMc1")
    text_in(armed, "START", sender=P, sid="SMc2")
    assert [e for e in events(world, o, "grant") if e["recorded_by"] == "confirmations"]


def test_our_replies_are_sent_per_the_table_and_suppressed_when_the_provider_replies_itself(world, stack, armed):
    """confirmations.md section 7 (opt-out text, HELP text, START texts; provider_replied skip when provider_replies true)."""
    o = world.a
    world.capture(o, P)
    stack.twilio.sent.clear()
    text_in(armed, "HELP", sender=P, sid="SMh1")
    assert stack.twilio.sent[-1]["body"] == ("Acme Flooring: Help: help@acme.example, +18135550100. Reply STOP to opt out of texts and calls. "
                                             "Msg frequency varies. Msg & data rates may apply.")
    text_in(armed, "STOP", sender=P, sid="SMh2")
    assert stack.twilio.sent[-1]["body"] == ("Acme Flooring: You are unsubscribed and will get no more texts or calls from us. "
                                             "Email is not affected. Reply START to get texts again.")
    text_in(armed, "START", sender=P, sid="SMh3")
    assert [r["our_reply"] for r in replies(o.boss)] == ["sent", "sent", "sent"]  # help, stop, start: all sent by us
    assert stack.twilio.sent[-1]["body"] == ("Acme Flooring: You will get texts from us again. Msg frequency varies. "
                                             "Msg & data rates may apply. Reply STOP to opt out, HELP for help.")


def test_help_is_answered_at_most_once_per_contact_per_hour(world, stack, armed, db_follows_service_clock):
    """confirmations.md section 7 (HELP: any hour, at most once per contact per hour)."""
    o = world.a
    world.capture(o, P)
    stack.twilio.sent.clear()
    text_in(armed, "HELP", sender=P)
    text_in(armed, "info", sender=P)
    assert len(stack.twilio.sent) == 1
    stack.clock.advance(minutes=61)
    text_in(armed, "HELP", sender=P)
    assert len(stack.twilio.sent) == 2


def test_with_the_provider_replying_itself_none_of_our_three_replies_are_sent(world, stack, world_armed=None):
    """confirmations.md sections 1 and 7 (Yes at connect: provider_replies all true; every reply recorded as a skip
    provider_replied; the START grant is still recorded)."""
    from contract_world.confirm import arm, text_in as tin
    o = world.a
    a = arm(stack, o, provider_replies_itself=True)
    world.capture(o, P)
    stack.twilio.sent.clear()
    tin(a, "HELP", sender=P, sid="SMp1")
    tin(a, "STOP", sender=P, sid="SMp2")
    tin(a, "START", sender=P, sid="SMp3")
    assert stack.twilio.sent == []
    assert [e for e in events(world, o, "grant") if e["recorded_by"] == "confirmations"]
    assert len(replies(o.boss)) == 3
    by_verdict = {r["verdict"]: r for r in replies(o.boss)}
    assert {v: by_verdict[v]["our_reply"] for v in ("help", "stop", "start")} == {"help": "provider_replied", "stop": "provider_replied", "start": "provider_replied"}


HELP_TEXT = ("Acme Flooring: Help: help@acme.example, +18135550100. Reply STOP to opt out of texts and calls. "
             "Msg frequency varies. Msg & data rates may apply.")
STOP_TEXT = ("Acme Flooring: You are unsubscribed and will get no more texts or calls from us. "
             "Email is not affected. Reply START to get texts again.")
START_TEXT = ("Acme Flooring: You will get texts from us again. Msg frequency varies. Msg & data rates may apply. "
              "Reply STOP to opt out, HELP for help.")


@pytest.mark.parametrize("status,help_sent,stop_sent,start_sent", [
    ("suspended", True, True, False), ("offboarding", False, True, False), ("closed", False, False, False)])
def test_replies_follow_the_organization_status(world, stack, armed, status, help_sent, stop_sent, start_sent):
    """confirmations.md section 7 table (opt-out sent while suspended or offboarding, not closed; HELP not when offboarding
    or closed; START not when suspended, offboarding or closed): the exact texts sent, in order."""
    o = world.a
    world.capture(o, P)
    world.set_status(o, status)
    stack.twilio.sent.clear()
    text_in(armed, "HELP", sender=P, sid="SMo1")
    text_in(armed, "STOP", sender=P, sid="SMo2")
    text_in(armed, "START", sender=P, sid="SMo3")
    expected = ([HELP_TEXT] if help_sent else []) + ([STOP_TEXT] if stop_sent else []) + ([START_TEXT] if start_sent else [])
    assert [m["body"] for m in stack.twilio.sent] == expected
    assert [r["our_reply"] for r in sorted(replies(o.boss), key=lambda r: r["received_at"])] == [
        "sent" if help_sent else "skipped", "sent" if stop_sent else "skipped", "sent" if start_sent else "skipped"]


def test_replies_are_not_sent_when_registration_is_not_marked_except_the_opt_out(world, stack, armed):
    """confirmations.md section 7 table (HELP and START: texting_not_registered; the opt-out answers a request and is sent)."""
    o = world.a
    world.capture(o, P)
    o.boss.ok("POST", "/v1/confirmations/texting-registration:withdraw", body={"reason": "x"})
    stack.twilio.sent.clear()
    text_in(armed, "HELP", sender=P, sid="SMw1")
    assert stack.twilio.sent == []
    text_in(armed, "STOP", sender=P, sid="SMw2")
    assert len(stack.twilio.sent) == 1


def test_an_opt_out_reply_that_cannot_go_in_five_minutes_is_dead_and_alarms(world, stack, armed):
    """confirmations.md section 7 (opt-out within 5 minutes; a retryable failure past 5 minutes is dead and alarms)."""
    o = world.a
    world.capture(o, P)
    stack.twilio.script = [("retry", 503)] * 10
    text_in(armed, "STOP", sender=P)
    stack.run(minutes=6)
    assert "optout_reply_dead" in stack.alarms(o.boss) and any(s["status"] == "dead" for s in sends(o.boss, channel="sms"))


def test_reply_messages_are_contact_log_rows_with_their_own_outcomes(world, stack, armed):
    """confirmations.md sections 7 and 10 (outcomes optout_reply, help_reply, start_reply, recorded_by confirmations)."""
    o = world.a
    world.capture(o, P)
    text_in(armed, "HELP", sender=P, sid="SMq1")
    text_in(armed, "STOP", sender=P, sid="SMq2")
    text_in(armed, "START", sender=P, sid="SMq3")
    got = sorted(r["outcome"] for r in world.sql(o, "SELECT outcome FROM consentvault.contact_log WHERE org_id = %s AND recorded_by = 'confirmations'", (o.org_id,)))
    assert got == ["help_reply", "optout_reply", "start_reply"]


# ---- public pages --------------------------------------------------------------------------------------------------------
def test_the_wording_page_shows_the_agreed_wording_and_never_the_contact(world, stack, armed):
    """confirmations.md section 6 (/c/r/{token}: brand, exact wording, date, channels, purposes, how to stop; never contact,
    name or company)."""
    o = world.a
    world.capture(o, P, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    stack.run()
    token = stack.twilio.sent[0]["body"].split("/c/r/")[1].split(".")[0].split(" ")[0]
    r = stack.public("GET", "/c/r/" + token, "consent.example.com")
    text = r.raw.decode() if getattr(r, "raw", None) else str(r.payload)
    assert r.status == 200 and "Acme Flooring" in text and "Reply STOP" in text
    for secret in (P, "Dana", "Cruz"):
        assert secret not in text
    assert stack.public("GET", "/c/r/" + token, "other.example.com").status == 404
    assert stack.public("GET", "/c/r/bogus", "consent.example.com").status == 404


def test_the_email_stop_page_stops_email_or_everything_and_a_repeat_records_nothing(world, stack, armed):
    """confirmations.md section 7 (/c/stop: two buttons; revoke purposes *, method checkbox, source Email stop page;
    channels email or all four; repeat says Already stopped; one-click header records the email stop)."""
    o = world.a
    world.email_grant(o, EMAIL)
    stack.run()
    token = stack.email.sent[0]["body"].split("/c/stop/")[1].split()[0].rstrip(".")
    page = stack.public("GET", "/c/stop/" + token, "consent.example.com")
    text = page.raw.decode() if getattr(page, "raw", None) else str(page.payload)
    assert "Stop email from Acme Flooring" in text and "Stop everything from Acme Flooring: email, texts and calls" in text
    r = stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=email")
    assert r.status == 200
    (ev,) = events(world, o, "revoke")
    assert list(ev["channels"]) == ["email"] and list(ev["purposes"]) == ["*"] and ev["method"] == "checkbox" and ev["origin"] == "consumer"
    again = stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=email")
    assert "Already stopped" in (again.raw.decode() if getattr(again, "raw", None) else str(again.payload))
    assert len(events(world, o, "revoke")) == 1
    r = stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=everything")
    (_, ev2) = events(world, o, "revoke")
    assert sorted(ev2["channels"]) == ["artificial_voice", "email", "sms", "voice"]
    world.email_grant(o, "lee@example.com")
    stack.run(hours=2)
    tok2 = stack.email.sent[-1]["headers"]["List-Unsubscribe"].split("/c/stop/")[1].strip("<>")
    before = len(events(world, o, "revoke"))
    r = stack.public("POST", "/c/stop/" + tok2, "consent.example.com", body=b"List-Unsubscribe=One-Click",
                     headers={"Content-Type": "application/x-www-form-urlencoded"})  # RFC 8058 one-click: no page, no button
    assert r.status == 200
    revokes = events(world, o, "revoke")
    assert len(revokes) == before + 1 and list(revokes[-1]["channels"]) == ["email"] and revokes[-1]["method"] == "checkbox"


def test_a_stop_page_that_cannot_record_says_so_and_keeps_the_buttons(world, stack, armed):
    """confirmations.md section 7 (Your request was not recorded. Please try again.)."""
    o = world.a
    world.email_grant(o, EMAIL)
    stack.run()
    token = stack.email.sent[0]["body"].split("/c/stop/")[1].split()[0].rstrip(".")
    with world.vault.superuser() as su:
        su.execute("CREATE FUNCTION public.cvt_g() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'down'; END $$")
        su.execute("CREATE TRIGGER cvt_g BEFORE INSERT ON consentvault.event FOR EACH ROW WHEN (NEW.event_type = 'revoke') EXECUTE FUNCTION public.cvt_g()")
    try:
        r = stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=email")
    finally:
        with world.vault.superuser() as su:
            su.execute("DROP TRIGGER cvt_g ON consentvault.event")
            su.execute("DROP FUNCTION public.cvt_g()")
    text = r.raw.decode() if getattr(r, "raw", None) else str(r.payload)
    assert "Your request was not recorded. Please try again." in text and "Stop email from" in text


def test_a_second_organization_sees_none_of_the_confirmations(world, stack, armed):
    """auth.md (a token carries exactly one organization; row security by org_id, records.md section 8) and LC-I3: settings, rules, sends and replies of one organization are invisible to another."""
    o, b = world.a, world.b
    world.capture(o, P)
    stack.run()
    text_in(armed, "hello", sender=P)
    assert sends(b.boss) == [] and replies(b.boss) == []
    assert b.boss.ok("GET", "/v1/confirmations/settings")["sending_accounts"] == []
    assert all(r["enabled"] is False for r in b.boss.ok("GET", "/v1/confirmations/rules")["items"])
    assert b.boss.ok("GET", "/v1/confirmations/settings")["counts"]["sent_24h"] == 0
    other = stack.inbound(armed.twilio_key, {"From": P, "To": OUR_NUMBER, "Body": "STOP", "MessageSid": "SMiso"}).status
    assert other == 200 and events(world, b, "revoke") == []


def test_a_start_from_a_different_number_never_lifts_another_numbers_stop(world, stack, armed):
    """LC-E5 (a START or YES from a number that is not the stopped contact releases nothing: the stop on P stays, the other
    number gets no grant, an unmatched number is a reply only)."""
    o = world.a
    Q = "+13055550199"
    world.capture(o, P)
    world.capture(o, Q)
    text_in(armed, "STOP", sender=P, sid="SMe1")
    for body, sender, sid in (("START", Q, "SMe2"), ("YES", Q, "SMe3"), ("START", "+15555550888", "SMe4"), ("START now please", P, "SMe5")):
        assert text_in(armed, body, sender=sender, sid=sid).status == 200
    assert [e for e in events(world, o, "grant") if e["recorded_by"] == "confirmations"] == []
    # START counts only as the whole message (confirmations.md section 7): "START now please" is not a start word
    longer = [r for r in replies(o.boss) if "now please" in (r["text"] or "")]
    assert len(longer) == 1 and longer[0]["verdict"] != "start" and longer[0]["state"] != "start" and longer[0]["event_id"] is None
    assert len(events(world, o, "revoke")) == 1
    recs = {i["contact"]["fp_hint"]: i for i in o.boss.ok("GET", "/v1/records", {})["items"]}
    assert recs[o.fp(P)[:8]]["has_stop"] is True and recs[o.fp(P)[:8]]["channels"]["sms"]["counts"]["stop_on_record"] == 2
    assert recs[o.fp(Q)[:8]]["has_stop"] is False
    assert world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s AND release_of_event_id IS NOT NULL", (o.org_id,)) == []
