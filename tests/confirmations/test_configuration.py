"""confirmations.md sections 1 to 4 and 11: sending accounts, settings, link host, texting registration, rules, templates."""

from datetime import timedelta
import pytest

from contract_world.confirm import (OUR_NUMBER, arm, connect_email, connect_twilio, enable_rule, mark_registered,
                                    set_link_host, set_sender, verify_inbound)
from contract_world.world import PENDING, PHONE



def test_connecting_a_twilio_account_answers_the_inbound_address_and_waits_for_a_test_reply(world, stack):
    """confirmations.md section 1 (object shape; inbound_url form; awaiting_test_reply; credentials never returned)."""
    a = world.a.boss
    acct = connect_twilio(stack, a)
    assert acct["status"] == "awaiting_test_reply" and acct["provider"] == "twilio" and acct["channel"] == "sms"
    assert acct["inbound_url"].startswith("https://api.consentvault.ai/v1/confirmations/inbound/")
    assert acct["from"]["number_hint"] == "***0100" and acct["inbound_verified_at"] is None
    assert acct["provider_replies"] == {"stop": False, "help": False, "start": False}
    blob = str(acct) + str(a.ok("GET", "/v1/confirmations/settings"))
    for secret in (stack.twilio.auth_token, stack.twilio.api_key_secret):
        assert secret not in blob


def test_the_admins_yes_means_all_three_provider_replies_are_suppressed(world, stack):
    """confirmations.md section 1 (provider_replies all true for Yes, all false for No)."""
    acct = connect_twilio(stack, world.a.boss, provider_replies_itself=True)
    assert acct["provider_replies"] == {"stop": True, "help": True, "start": True}


def test_secrets_are_sealed_under_the_org_key_and_the_auth_token_is_never_used_to_call_twilio(world, stack):
    """confirmations.md section 1 (two Twilio secrets; sealed; auth token only for signatures)."""
    o = world.a
    arm(stack, o)
    (row,) = [r for r in world.sql(o, "SELECT * FROM consentvault.sending_account WHERE org_id = %s", (o.org_id,)) if r["channel"] == "sms"]
    creds, token = bytes(row["credentials_ct"]), bytes(row["auth_token_ct"])
    assert stack.twilio.api_key_secret.encode() not in creds and stack.twilio.auth_token.encode() not in token  # sealed, not clear
    custody = world.vault.custody
    assert stack.twilio.api_key_secret.encode() in custody.unwrap(o.org_id, creds)  # and openable only under the organization key
    assert custody.unwrap(o.org_id, token) == stack.twilio.auth_token.encode()
    assert stack.twilio.used_auth_token_to_call == 0


def _age(world, o, table, column, delta, extra=""):
    """Time passing by the database's clock: the stamped rows stand ``delta`` further back (a sealed table is opened for it)."""
    with world._get().vault.superuser() as su:
        su.execute(f"ALTER TABLE consentvault.{table} DISABLE TRIGGER USER")
        su.execute(f"UPDATE consentvault.{table} SET {column} = {column} - %s WHERE org_id = %s {extra}", (delta, o.org_id))
        su.execute(f"ALTER TABLE consentvault.{table} ENABLE TRIGGER USER")



def test_a_text_account_is_connected_only_after_a_signed_test_reply_arrives(world, stack):
    """confirmations.md section 1 (step 4: test reply sets inbound_verified_at and status connected; stored 30 days; no record)."""
    o = world.a
    set_sender(o.boss)
    acct = connect_twilio(stack, o.boss)
    verify_inbound(stack, acct)
    got = [a for a in o.boss.ok("GET", "/v1/confirmations/settings")["sending_accounts"] if a["account_id"] == acct["account_id"]][0]
    assert got["status"] == "connected" and got["inbound_verified_at"]
    assert o.boss.ok("GET", "/v1/records", {})["items"] == []
    (t,) = world.sql(o, "SELECT * FROM consentvault.confirmation_connect_test WHERE org_id = %s", (o.org_id,))
    assert {"account_id", "provider_message_id", "received_at", "from_fp", "body_ct"} <= set(t) and b"test" not in bytes(t["body_ct"])
    assert len(world.sql(o, "SELECT 1 FROM consentvault.confirmation_inbound_seen WHERE org_id = %s AND provider_message_id = %s", (o.org_id, t["provider_message_id"]))) == 1
    assert world.sql(o, "SELECT 1 FROM consentvault.confirmation_reply WHERE org_id = %s", (o.org_id,)) == []
    assert world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s", (o.org_id,)) == []
    _age(world, o, "confirmation_connect_test", "received_at", timedelta(days=29))
    stack.service.purge()
    assert len(world.sql(o, "SELECT 1 FROM consentvault.confirmation_connect_test WHERE org_id = %s", (o.org_id,))) == 1
    _age(world, o, "confirmation_connect_test", "received_at", timedelta(days=2))
    stack.service.purge()
    assert world.sql(o, "SELECT 1 FROM consentvault.confirmation_connect_test WHERE org_id = %s", (o.org_id,)) == []
    assert len(world.audit(o.boss, "confirmations.inbound_verified")) == 1
    assert len(world.audit(o.boss, "confirmations.account_connected")) == 1


def test_account_input_refusals(world, stack):
    """confirmations.md section 1 (provider_not_supported, sender_not_verified, provider_unreachable, provider_refused)."""
    a = world.a.boss
    a.err("POST", "/v1/confirmations/sending-accounts", body={"channel": "sms", "provider": "plivo", "credentials": {}}, name="provider_not_supported", status=422)
    a.err("POST", "/v1/confirmations/sending-accounts", body={"channel": "email", "provider": "mailgun", "credentials": {}}, name="provider_not_supported")
    a.err("POST", "/v1/confirmations/sending-accounts", body={"channel": "email", "provider": "ses", "credentials": {"k": "v"},
                                                               "from": {"email_address": "x@unverified.test", "display_name": "X"}}, name="sender_not_verified", status=422)
    stack.twilio.unreachable = True
    a.err("POST", "/v1/confirmations/sending-accounts", body={"channel": "sms", "provider": "twilio", "credentials": {"auth_token": "t"},
                                                               "sender": {"number": OUR_NUMBER}}, name="provider_unreachable", status=502)
    assert a.ok("GET", "/v1/confirmations/settings")["sending_accounts"] == []
    a.err("POST", "/v1/confirmations/sending-accounts", body={"channel": "sms"}, name="validation_failed")


def test_check_reads_the_account_and_sends_no_message(world, stack):
    """confirmations.md endpoint table (:check answers the account answers; no message sent)."""
    a = world.a.boss
    acct = connect_twilio(stack, a)
    got = a.ok("POST", f"/v1/confirmations/sending-accounts/{acct['account_id']}:check", body={})
    assert got["last_check"]["result"] and stack.twilio.sent == []


def test_disconnect_is_refused_while_the_inbound_webhook_still_points_here(world, stack):
    """confirmations.md section 1 (inbound_still_pointed_here 409; provider_unreachable changes nothing)."""
    a = world.a.boss
    acct = connect_twilio(stack, a)
    stack.twilio.inbound_pointed_at = acct["inbound_url"]
    a.err("DELETE", f"/v1/confirmations/sending-accounts/{acct['account_id']}", body={"reason": "x"}, name="inbound_still_pointed_here", status=409)
    stack.twilio.unreachable = True
    a.err("DELETE", f"/v1/confirmations/sending-accounts/{acct['account_id']}", body={"reason": "x"}, name="provider_unreachable")
    assert a.ok("GET", "/v1/confirmations/settings")["sending_accounts"][0]["status"] != "disconnected"


def test_disconnect_turns_rules_off_skips_queued_sends_and_keeps_accepting_replies_for_30_days(world, stack, armed):
    """confirmations.md section 1 (rules off in the transaction, queued sends no_sending_account, credentials deleted,
    inbound keeps accepting and recording for 30 days then stops)."""
    o = world.a
    world.capture(o, PHONE)
    acct = [x for x in o.boss.ok("GET", "/v1/confirmations/settings")["sending_accounts"] if x["channel"] == "sms"][0]
    o.boss.ok("DELETE", f"/v1/confirmations/sending-accounts/{acct['account_id']}", body={"reason": "moving"})
    rules = {(r["source_id"], r["channel"]): r for r in o.boss.ok("GET", "/v1/confirmations/rules")["items"]}
    assert rules[(o.web_id, "sms")]["enabled"] is False
    stack.run()
    assert [s["skip_reason"] for s in __import__("contract_world.confirm", fromlist=["sends"]).sends(o.boss, channel="sms")] == ["no_sending_account"]
    assert len(world.audit(o.boss, "confirmations.account_removed")) == 1
    _age(world, o, "sending_account", "disconnected_at", timedelta(days=29))
    assert stack.inbound(armed.twilio_key, {"From": PHONE, "To": OUR_NUMBER, "Body": "STOP", "MessageSid": "SM-late"}).status == 200
    _age(world, o, "sending_account", "disconnected_at", timedelta(days=2))
    assert stack.inbound(armed.twilio_key, {"From": PHONE, "To": OUR_NUMBER, "Body": "STOP", "MessageSid": "SM-later"}).status in (404, 410)


def test_a_disconnect_stays_a_role_matrix_a_only_and_connect_admits_a_developer(world, stack):
    """confirmations.md endpoint table (connect: A, D; check: A, D; delete: A) and auth.md."""
    o = world.a
    acct = connect_twilio(stack, o.dev)
    o.dev.ok("POST", f"/v1/confirmations/sending-accounts/{acct['account_id']}:check", body={})
    o.dev.err("DELETE", f"/v1/confirmations/sending-accounts/{acct['account_id']}", body={"reason": "x"}, name="role_not_allowed")
    o.viewer.err("POST", "/v1/confirmations/sending-accounts", body={"channel": "sms"}, name="role_not_allowed")


def test_account_changes_are_paused_while_suspended(world, stack):
    """confirmations.md section 1 errors (org_suspended)."""
    world.set_status(world.a, "suspended")
    with pytest.raises(AssertionError):
        connect_twilio(stack, world.a.boss)
    world.a.boss.err("POST", "/v1/confirmations/sending-accounts", body={"channel": "sms", "provider": "twilio", "credentials": {"auth_token": "t"},
                                                                         "sender": {"number": OUR_NUMBER}}, name="org_suspended")


def test_settings_shape_and_a_put_makes_a_new_version_and_changes_the_sender_only(world, stack):
    """confirmations.md section 2 (settings shape; PUT changes sender only and keeps old versions; audited)."""
    a = world.a.boss
    first = a.ok("GET", "/v1/confirmations/settings")
    assert set(first) >= {"version", "sender", "link_host", "stop_scopes", "texting_registration", "sending_accounts", "counts",
                          "alarms", "fixed_text_version"} and first["alarms"] == []
    assert first["link_host"]["status"] == "unset" and first["texting_registration"]["status"] == "not_marked"
    assert first["stop_scopes"] == {"text_reply": ["sms", "voice", "artificial_voice"], "email_link": ["email"],
                                    "email_link_everything": ["sms", "voice", "artificial_voice", "email"]}
    second = set_sender(a)
    assert second["version"] == first["version"] + 1 and second["sender"]["organization_name"] == "Acme Flooring"
    assert len(world.audit(a, "confirmations.settings_changed")) == 1
    a.err("PUT", "/v1/confirmations/settings", body={"link_host": {"host": "x.example.com"}}, name="validation_failed")


def test_settings_counts_are_null_when_they_cannot_be_read_never_zero(world, stack):
    """confirmations.md section 2 and 13 (a count that could not be read is null, never 0; failed-reads switch confirmations.counts)."""
    with world.fail_reads("confirmations.counts"):
        got = world.a.boss.ok("GET", "/v1/confirmations/settings")
    assert got["counts"] is None and got["sender"]


def test_settings_roles(world, stack):
    """confirmations.md endpoint table (GET: A, D, V; PUT: A)."""
    o = world.a
    for who in o.people.values():
        who.ok("GET", "/v1/confirmations/settings")
    for who in (o.dev, o.viewer):
        who.err("PUT", "/v1/confirmations/settings", body={"organization_name": "x"}, name="role_not_allowed")


def test_link_host_is_set_then_verified_against_dns(world, stack):
    """confirmations.md section 2 (pending_dns with txt_record; link_host_dns_missing fields.expected; verified; audited)."""
    a = world.a.boss
    got = a.ok("POST", "/v1/confirmations/link-host", body={"host": "consent.acme.example"})
    assert got["status"] == "pending_dns" and got["txt_record"]
    err = a.err("POST", "/v1/confirmations/link-host:verify", body={}, name="link_host_dns_missing", status=422)
    assert err["fields"]["expected"]
    stack.dns.records[("consent.acme.example", "CNAME")] = "edge.consentvault.ai"
    stack.dns.records[("consent.acme.example", "TXT")] = got["txt_record"]
    assert a.ok("POST", "/v1/confirmations/link-host:verify", body={})["status"] == "verified"
    assert len(world.audit(a, "confirmations.link_host_set")) == 1 and len(world.audit(a, "confirmations.link_host_verified")) == 1
    a.err("POST", "/v1/confirmations/link-host", body={"host": "not a host"}, name="validation_failed")
    world.a.dev.ok("POST", "/v1/confirmations/link-host", body={"host": "consent.acme.example"})
    world.a.viewer.err("POST", "/v1/confirmations/link-host", body={"host": "x.acme.example"}, name="role_not_allowed")


def test_a_host_that_stops_resolving_fails_after_two_hourly_checks_and_sends_are_skipped(world, stack, armed):
    """confirmations.md section 2 (re-checked hourly; after 2 failures failing; sends skipped link_host_failing)."""
    from contract_world.confirm import sends
    o = world.a
    stack.dns.records.clear()
    stack.clock.advance(hours=1)
    stack.service.recheck_link_hosts(now=stack.clock())
    assert o.boss.ok("GET", "/v1/confirmations/settings")["link_host"]["status"] == "verified"
    stack.clock.advance(hours=1)
    stack.service.recheck_link_hosts(now=stack.clock())
    assert o.boss.ok("GET", "/v1/confirmations/settings")["link_host"]["status"] == "failing"
    world.capture(o, PHONE)
    stack.run()
    assert [s["skip_reason"] for s in sends(o.boss, channel="sms")] == ["link_host_failing"] and stack.twilio.sent == []
    assert "link_host_failing" in stack.alarms(o.boss)


def test_texting_registration_is_marked_with_who_when_and_the_fixed_text_version(world, stack):
    """confirmations.md section 3 (mark; accepted and samples_included both required; errors; audited)."""
    a = world.a.boss
    body = {"kind": "10dlc", "reference": "CMP1", "accepted": True, "samples_included": True}
    a.err("POST", "/v1/confirmations/texting-registration", body=body, name="no_sending_account", status=409)
    acct = connect_twilio(stack, a)
    a.err("POST", "/v1/confirmations/texting-registration", body=body, name="inbound_not_verified", status=409)
    verify_inbound(stack, acct)
    a.err("POST", "/v1/confirmations/texting-registration", body={**body, "accepted": False}, name="acknowledgement_required")
    a.err("POST", "/v1/confirmations/texting-registration", body={**body, "samples_included": False}, name="acknowledgement_required")
    a.err("POST", "/v1/confirmations/texting-registration", body={**body, "kind": "carrier_pigeon"}, name="validation_failed")
    got = a.ok("POST", "/v1/confirmations/texting-registration", body=body)
    reg = a.ok("GET", "/v1/confirmations/settings")["texting_registration"]
    assert reg["status"] == "marked" and reg["kind"] == "10dlc" and reg["reference"] == "CMP1"
    assert reg["marked_by"] == a.member_id and reg["marked_at"] and isinstance(reg["samples_statement_version"], int)
    assert len(world.audit(a, "confirmations.registration_marked")) == 1
    for who in (world.a.dev, world.a.viewer):
        who.err("POST", "/v1/confirmations/texting-registration", body=body, name="role_not_allowed")


def test_withdrawing_registration_turns_every_text_rule_off_and_skips_queued_texts(world, stack, armed):
    """confirmations.md section 3 (:withdraw sets not_marked, text rules off, queued texts skipped texting_not_registered)."""
    from contract_world.confirm import sends
    o = world.a
    world.capture(o, PHONE)
    o.boss.ok("POST", "/v1/confirmations/texting-registration:withdraw", body={"reason": "carrier asked"})
    assert o.boss.ok("GET", "/v1/confirmations/settings")["texting_registration"]["status"] == "not_marked"
    assert all(r["enabled"] is False for r in o.boss.ok("GET", "/v1/confirmations/rules")["items"] if r["channel"] == "sms")
    stack.run()
    assert [s["skip_reason"] for s in sends(o.boss, channel="sms")] == ["texting_not_registered"]
    assert len(world.audit(o.boss, "confirmations.registration_withdrawn")) == 1


def test_a_changed_fixed_text_makes_the_mark_stale_and_turns_text_rules_off(world, stack, armed, monkeypatch):
    """confirmations.md section 3 and 13 (FIXED_TEXT_VERSION in confirm/texts.py; settings return fixed_text_version;
    registration stores it as samples_statement_version; when they differ text rules are off and a new mark is asked)."""
    from contract_world.world import need
    version = need("consentvault.confirm.texts", "FIXED_TEXT_VERSION")
    assert version == 1
    o = world.a
    settings = o.boss.ok("GET", "/v1/confirmations/settings")
    assert settings["fixed_text_version"] == version and settings["texting_registration"]["samples_statement_version"] == version
    monkeypatch.setattr("consentvault.confirm.texts.FIXED_TEXT_VERSION", version + 1)
    assert all(r["enabled"] is False for r in o.boss.ok("GET", "/v1/confirmations/rules")["items"] if r["channel"] == "sms")
    o.boss.err("PUT", f"/v1/confirmations/rules/{o.web_id}/sms", body={"enabled": True, "sending_brand_id": o.brand_id}, name="texting_not_registered")
    mark_registered(o.boss)
    assert o.boss.ok("GET", "/v1/confirmations/settings")["texting_registration"]["samples_statement_version"] == version + 1


def test_the_twilio_auth_token_is_kept_30_days_after_a_disconnect_then_nulled_by_the_purge(world, stack, armed):
    """confirmations.md section 13 (sending_account.auth_token_ct nulled by purge(now) 30 days after disconnected_at:
    present at day 29, null at day 31)."""
    o = world.a
    acct = [x for x in o.boss.ok("GET", "/v1/confirmations/settings")["sending_accounts"] if x["channel"] == "sms"][0]
    o.boss.ok("DELETE", f"/v1/confirmations/sending-accounts/{acct['account_id']}", body={"reason": "moving"})
    q = "SELECT auth_token_ct, credentials_ct FROM consentvault.sending_account WHERE org_id = %s AND account_id = %s"
    _age(world, o, "sending_account", "disconnected_at", timedelta(days=29))
    stack.service.purge()
    row = world.sql(o, q, (o.org_id, acct["account_id"]))[0]
    assert row["auth_token_ct"] is not None and row["credentials_ct"] is None  # sending credentials are deleted at disconnect
    _age(world, o, "sending_account", "disconnected_at", timedelta(days=2))
    stack.service.purge()
    assert world.sql(o, q, (o.org_id, acct["account_id"]))[0]["auth_token_ct"] is None


def test_the_providers_answer_can_be_changed_after_connecting(world, stack):
    """confirmations.md section 12 (PATCH sending-accounts/{id} {provider_replies_itself}: A and D, audited settings_changed)."""
    o = world.a
    acct = connect_twilio(stack, o.boss)
    got = o.dev.ok("PATCH", f"/v1/confirmations/sending-accounts/{acct['account_id']}", body={"provider_replies_itself": True})
    assert got["provider_replies"] == {"stop": True, "help": True, "start": True}
    assert len(world.audit(o.boss, "confirmations.settings_changed")) == 1
    o.viewer.err("PATCH", f"/v1/confirmations/sending-accounts/{acct['account_id']}", body={"provider_replies_itself": False}, name="role_not_allowed")
    o.boss.err("PATCH", f"/v1/confirmations/sending-accounts/{acct['account_id']}", body={"provider_replies_itself": "yes"}, name="validation_failed")
    o.boss.err("PATCH", f"/v1/confirmations/sending-accounts/{acct['account_id']}", body={"provider_replies_itself": True, "nope": 1}, name="validation_failed")


def test_unknown_keys_in_a_configuration_body_are_refused_naming_the_key(world, stack):
    """confirmations.md section 12 (every unknown key is validation_failed naming the key)."""
    a = world.a.boss
    body = a.err("PUT", "/v1/confirmations/settings", body={"organization_name": "A", "postal_address": "1 St",
                                                           "help_contact": {"email": "h@a.example"}, "colour": "red"}, name="validation_failed")
    assert "colour" in body["fields"]
    a.err("POST", "/v1/confirmations/link-host", body={"host": "c.a.example", "extra": 1}, name="validation_failed")


def test_telnyx_is_refused_with_provider_not_supported(world, stack):
    """confirmations.md section 1 (Telnyx is out of scope until built: provider telnyx answers provider_not_supported, 422;
    nothing is stored)."""
    a = world.a.boss
    a.err("POST", "/v1/confirmations/sending-accounts", body={"channel": "sms", "provider": "telnyx",
          "credentials": {"api_key": "k", "public_key": "p"}, "sender": {"messaging_profile_id": "mp-1"},
          "provider_replies_itself": False}, name="provider_not_supported", status=422)
    assert a.ok("GET", "/v1/confirmations/settings")["sending_accounts"] == []


def test_rules_list_one_per_source_and_channel_with_defaults(world, stack):
    """confirmations.md section 4 (one rule per source and channel; defaults 24 / 10 / true)."""
    items = world.a.boss.ok("GET", "/v1/confirmations/rules")["items"]
    keys = {(r["source_id"], r["channel"]) for r in items}
    assert {(world.a.web_id, "email"), (world.a.web_id, "sms"), (world.a.import_id, "email"), (world.a.import_id, "sms")} <= keys
    r = [i for i in items if (i["source_id"], i["channel"]) == (world.a.web_id, "sms")][0]
    assert r["enabled"] is False and r["dedupe_hours"] == 24 and r["max_delay_minutes"] == 10 and r["send_for_test_events"] is True
    assert set(r) >= {"source_id", "channel", "enabled", "sending_brand_id", "template_id", "send_for_test_events", "dedupe_hours",
                      "max_delay_minutes", "updated_by", "updated_at"}
    for who in world.a.people.values():
        who.ok("GET", "/v1/confirmations/rules")


ORDER = ["account", "inbound", "registration", "sender", "host"]
EXPECT = {"account": "no_sending_account", "inbound": "inbound_not_verified", "registration": "texting_not_registered",
          "sender": "sender_details_missing", "host": "link_host_not_verified"}


@pytest.mark.parametrize("first", ORDER)
def test_a_rule_turned_on_is_refused_with_the_first_failing_prerequisite_in_the_pinned_order(world, stack, first):
    """confirmations.md section 4 (PUT refusals in order: no_sending_account, inbound_not_verified, texting_not_registered, then
    sender_details_missing, then link_host_not_verified; the first failing one is returned). Everything before `first` in the
    order is done; `sender` and `host` are the last two, so for them everything else is done and only that one is missing,
    and for the earlier ones every later prerequisite is also missing (so the order itself is proved)."""
    o, a = world.a, world.a.boss
    k = ORDER.index(first)
    done = set(ORDER[:k]) | ({"sender", "host"} - {first} if first in ("sender", "host") else set())
    if "sender" in done:
        set_sender(a)
    if "host" in done:
        set_link_host(stack, a)
    if "account" in done:
        acct = connect_twilio(stack, a)
        if "inbound" in done:
            verify_inbound(stack, acct)
            if "registration" in done:
                mark_registered(a)
    body = a.err("PUT", f"/v1/confirmations/rules/{o.web_id}/sms", body={"enabled": True, "sending_brand_id": o.brand_id}, name=EXPECT[first], status=409)
    assert body["error"] == EXPECT[first]
    a.ok("PUT", f"/v1/confirmations/rules/{o.web_id}/sms", body={"enabled": False, "sending_brand_id": o.brand_id})  # off is never refused for a prerequisite


def test_the_email_rule_needs_an_account_then_sender_then_host_and_no_texting_prerequisites(world, stack):
    """confirmations.md section 4 (email: no_sending_account; then for both channels sender_details_missing, link_host_not_verified)."""
    o, a = world.a, world.a.boss
    path = f"/v1/confirmations/rules/{o.web_id}/email"
    body = {"enabled": True, "sending_brand_id": o.brand_id}
    a.err("PUT", path, body=body, name="no_sending_account")
    connect_email(stack, a)
    a.err("PUT", path, body=body, name="sender_details_missing")
    set_sender(a)
    a.err("PUT", path, body=body, name="link_host_not_verified")
    set_link_host(stack, a)
    assert a.ok("PUT", path, body=body)["enabled"] is True  # no texting registration or inbound test needed for email


def test_a_role_beats_a_body_error_and_a_body_error_beats_a_missing_object(world, stack):
    """confirmations.md section 4 (order: role_not_allowed, validation_failed, not_found, then prerequisites)."""
    o = world.a
    ghost = "00000000-0000-4000-8000-0000000000aa"
    o.dev.err("PUT", f"/v1/confirmations/rules/{ghost}/sms", body={"dedupe_hours": 0}, name="role_not_allowed")
    o.boss.err("PUT", f"/v1/confirmations/rules/{ghost}/sms", body={"enabled": True, "sending_brand_id": o.brand_id, "dedupe_hours": 0}, name="validation_failed")
    o.boss.err("PUT", f"/v1/confirmations/rules/{ghost}/sms", body={"enabled": True, "sending_brand_id": o.brand_id}, name="not_found")


def test_rule_input_rules_and_roles_and_audit(world, stack):
    """confirmations.md section 4 (not_found, validation_failed ranges, A-only PUT, audited, applies to later grants only)."""
    o, a = world.a, world.a.boss
    arm(stack, o, text=False, email=False)
    connect_email(stack, a)
    path = f"/v1/confirmations/rules/{o.web_id}/email"
    a.err("PUT", f"/v1/confirmations/rules/00000000-0000-4000-8000-000000000001/email", body={"enabled": True, "sending_brand_id": o.brand_id}, name="not_found")
    a.err("PUT", path, body={"enabled": True, "sending_brand_id": "00000000-0000-4000-8000-000000000002"}, name="not_found")
    a.err("PUT", path, body={"enabled": True, "sending_brand_id": world.b.brand_id}, name="not_found")  # the other organization's real brand
    a.err("PUT", f"/v1/confirmations/rules/{world.b.web_id}/email", body={"enabled": True, "sending_brand_id": o.brand_id}, name="not_found")  # its real source
    foreign = world.b.boss.ok("POST", "/v1/confirmations/templates", body={"subject": "Theirs"})["template_id"]
    a.err("PUT", path, body={"enabled": True, "sending_brand_id": o.brand_id, "template_id": foreign}, name="not_found")  # its real template
    a.err("PUT", path, body={"enabled": True, "sending_brand_id": o.brand_id, "template_id": "00000000-0000-4000-8000-000000000003"}, name="not_found")
    for bad in ({"dedupe_hours": 0}, {"dedupe_hours": 169}, {"max_delay_minutes": 0}, {"max_delay_minutes": 61}):
        a.err("PUT", path, body={"enabled": True, "sending_brand_id": o.brand_id, **bad}, name="validation_failed")
    got = enable_rule(a, o.web_id, "email", o.brand_id, dedupe_hours=168, max_delay_minutes=60)
    assert got["enabled"] is True and got["dedupe_hours"] == 168 and got["updated_by"] == a.member_id
    for who in (o.dev, o.viewer):
        who.err("PUT", path, body={"enabled": False}, name="role_not_allowed")
    assert len(world.audit(a, "confirmations.rule_changed")) >= 1


def test_templates_are_versions_that_are_never_edited_in_place(world, stack):
    """confirmations.md sections 4 and 12 (POST {subject 1..80, opening_line? 0..300} answers {template_id, version}; a template
    never changes; GET list and detail; audited)."""
    a = world.a.boss
    t1 = a.ok("POST", "/v1/confirmations/templates", body={"subject": "You agreed to hear from us", "opening_line": "Thanks for signing up."})
    t2 = a.ok("POST", "/v1/confirmations/templates", body={"subject": "New subject"})
    assert set(t1) == {"template_id", "version"} and (t2["template_id"], t2["version"]) != (t1["template_id"], t1["version"])
    assert len(world.a.viewer.ok("GET", "/v1/confirmations/templates")["items"]) >= 2
    assert world.a.dev.ok("GET", f"/v1/confirmations/templates/{t1['template_id']}")["subject"] == "You agreed to hear from us"
    a.err("POST", "/v1/confirmations/templates", body={"subject": "s" * 81}, name="validation_failed")
    a.err("POST", "/v1/confirmations/templates", body={"subject": "s", "opening_line": "o" * 301}, name="validation_failed")
    a.err("POST", "/v1/confirmations/templates", body={"subject": ""}, name="validation_failed")
    world.a.dev.err("POST", "/v1/confirmations/templates", body={"subject": "s"}, name="role_not_allowed")
    assert len(world.audit(a, "confirmations.template_created")) == 2


def test_preview_renders_the_fixed_text_and_refuses_an_unknown_template_key(world, stack):
    """confirmations.md section 6 (text and email fixed wording; preview shape; only subject and opening_line are editable, so any other key is validation_failed)."""
    o, a = world.a, world.a.boss
    set_sender(a)
    arm(stack, o, text=True, email=False)
    sms = a.ok("POST", "/v1/confirmations:preview", body={"source_id": o.web_id, "channel": "sms"})
    assert set(sms) >= {"subject", "body", "segments", "characters"} and sms["subject"] is None and sms["segments"] >= 1
    assert sms["body"].startswith("Acme Flooring: on ") and " you agreed to texts and calls about " in sms["body"]
    assert "Full wording: https://consent.example.com/c/r/" in sms["body"]
    assert sms["body"].endswith("Msg frequency varies. Msg & data rates may apply. Reply STOP to opt out, HELP for help.")
    assert sms["characters"] == len(sms["body"])
    mail = a.ok("POST", "/v1/confirmations:preview", body={"source_id": o.web_id, "channel": "email",
                                                          "template": {"subject": "Hi", "opening_line": "Thanks."}})
    assert mail["subject"] == "Hi" and "you agreed to the following from" in mail["body"]
    assert "To stop email from" in mail["body"] and "Reply STOP" not in mail["body"] and "1 Main St" in mail["body"]
    err = a.err("POST", "/v1/confirmations:preview", body={"source_id": o.web_id, "channel": "email",
                                                           "template": {"subject": "Hi", "opening_line": "Thanks.", "body": "no stop link"}},
                name="validation_failed")
    assert "body" in err["fields"]  # the only editable parts are subject and opening_line, so a fixed part cannot be dropped
    for who in (o.dev, o.viewer):
        who.ok("POST", "/v1/confirmations:preview", body={"source_id": o.web_id, "channel": "sms"})


def test_the_new_error_names_and_audit_actions_exist(world, stack):
    """confirmations.md section 11 (every confirmations audit action is listed for the audit menu)."""
    want = {"confirmations.settings_changed", "confirmations.account_connected", "confirmations.account_removed", "confirmations.inbound_verified",
            "confirmations.link_host_set", "confirmations.link_host_verified", "confirmations.registration_marked",
            "confirmations.registration_withdrawn", "confirmations.rule_changed", "confirmations.template_created", "confirmations.test_sent",
            "confirmations.reply_marked", "confirmations.sends_listed", "confirmations.replies_listed", "confirmations.inbound_replayed"}
    got = {i["action"] for i in world.a.boss.ok("GET", "/v1/audit/actions", {"limit": "200"})["items"]}
    assert want <= got


def test_a_test_message_goes_to_a_contact_the_admin_controls_and_is_audited(world, stack, armed, monkeypatch):
    """confirmations.md endpoint table (POST /v1/confirmations:test, A only; audited confirmations.test_sent)."""
    from datetime import datetime, timezone
    from consentvault.confirm import sender as S
    monkeypatch.setattr(S, "db_now", lambda conn: datetime(2026, 11, 3, 17, 0, tzinfo=timezone.utc))   # noon in Miami: inside the texting hours whatever the real hour
    o = world.a
    o.boss.ok("POST", "/v1/confirmations:test", body={"channel": "sms", "contact": "+13055550123", "source_id": o.web_id})
    assert stack.twilio.sent[-1]["to"] == "+13055550123"
    assert len(world.audit(o.boss, "confirmations.test_sent")) == 1
    for who in (o.dev, o.viewer):
        who.err("POST", "/v1/confirmations:test", body={"channel": "sms", "contact": PHONE}, name="role_not_allowed")
