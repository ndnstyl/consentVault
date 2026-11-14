"""confirmations.md sections 2, 4, 6 and 12, amended after the portal build: source and brand names on rule and send rows, the
template list shape, the link-host answer with its CNAME target, and the four fixed texts with their version."""

import pytest

from contract_world.confirm import PHONE, arm, enable_rule, replies, sends, text_in
from contract_world.world import EMAIL

LIST_KEYS = {"template_id", "channel", "name", "body_version", "status", "updated_at"}


# ---- names on rules and sends (item: the compliance viewer reads names; rows carry them) -------------------------------------
def test_rule_rows_carry_the_source_name_and_the_sending_brand_name(world, stack, armed):
    """confirmations.md section 4 (a rule row carries source_name and brand_name beside the ids)."""
    o = world.a
    rows = {(r["source_id"], r["channel"]): r for r in o.viewer.ok("GET", "/v1/confirmations/rules")["items"]}
    sms = rows[(o.web_id, "sms")]
    assert sms["source_name"] == "Web form" and sms["brand_name"] == "acme Flooring" and sms["sending_brand_id"] == o.brand_id
    other = rows[(o.import_id, "sms")]  # never configured: the brand is null and so is its name
    assert other["source_name"] == "Event sign-up" and other["sending_brand_id"] is None and other["brand_name"] is None
    enable_rule(o.boss, o.web_id, "sms", o.brand2_id)
    after = {(r["source_id"], r["channel"]): r for r in o.boss.ok("GET", "/v1/confirmations/rules")["items"]}
    assert after[(o.web_id, "sms")]["brand_name"] == "acme Coatings"


def test_a_put_rule_answer_carries_the_same_names(world, stack, armed):
    """confirmations.md section 4 (PUT answers the rule object, names included)."""
    o = world.a
    got = enable_rule(o.boss, o.web_id, "email", o.brand2_id)
    assert got["source_name"] == "Web form" and got["brand_name"] == "acme Coatings"


def test_send_rows_carry_the_source_name_and_the_brand_the_message_was_sent_as(world, stack, armed):
    """confirmations.md section 5 (a send row carries source_name and brand_name; the brand is the one named when the intent was
    made, so a later rule change never rewrites an old row)."""
    o = world.a
    world.capture(o, PHONE)
    stack.run()
    (before,) = sends(o.viewer, channel="sms")
    assert before["source_name"] == "Web form" and before["brand_name"] == "acme Flooring"
    assert before["source_id"] == o.web_id
    enable_rule(o.boss, o.web_id, "sms", o.brand2_id)
    (after,) = sends(o.dev, channel="sms")
    assert after["send_id"] == before["send_id"] and after["brand_name"] == "acme Flooring"


def test_a_skipped_send_still_names_its_source_and_brand(world, stack, armed):
    """confirmations.md section 5 (skips are rows too: they carry the names)."""
    o = world.a
    world.capture(o, EMAIL, channels=("sms",), kind="email")
    stack.run()
    (row,) = sends(o.boss, channel="sms")
    assert row["status"] == "skipped" and row["source_name"] == "Web form" and row["brand_name"] == "acme Flooring"


def test_a_reply_send_has_no_source_and_so_no_names(world, stack, armed):
    """confirmations.md section 7 (an opt-out, HELP or START answer answers a reply, not a source: both names are null)."""
    o = world.a
    world.capture(o, PHONE)
    stack.run()
    text_in(armed, "HELP")
    stack.run()
    replies_sends = [s for s in sends(o.boss, channel="sms") if s["kind"] == "help_reply"]
    assert replies_sends and all(s["source_id"] is None and s["source_name"] is None and s["brand_name"] is None
                                 for s in replies_sends)


def test_other_organizations_names_never_appear(world, stack, armed):
    """The isolation rule (names come from this organization's own sources and brands)."""
    world.capture(world.a, PHONE)
    stack.run()
    assert world.b.boss.ok("GET", "/v1/confirmations/sends")["items"] == []
    assert all(r["source_name"] != "Web form" or r["source_id"] != world.a.web_id
               for r in world.b.boss.ok("GET", "/v1/confirmations/rules")["items"])


# ---- the template list ------------------------------------------------------------------------------------------------------
def test_the_template_list_has_the_ruled_shape_and_marks_the_newest_current(world, stack):
    """confirmations.md section 12 (list items: template_id, channel, name, body_version, status, updated_at)."""
    a = world.a.boss
    assert world.a.viewer.ok("GET", "/v1/confirmations/templates") == {"items": [], "next_cursor": None}
    t1 = a.ok("POST", "/v1/confirmations/templates", body={"subject": "You agreed to hear from us", "opening_line": "Thanks."})
    t2 = a.ok("POST", "/v1/confirmations/templates", body={"subject": "New subject"})
    got = world.a.viewer.ok("GET", "/v1/confirmations/templates")
    assert got["next_cursor"] is None and [i["template_id"] for i in got["items"]] == [t2["template_id"], t1["template_id"]]
    for item in got["items"]:
        assert set(item) == LIST_KEYS and item["channel"] == "email"
    new, old = got["items"]
    assert (new["name"], new["body_version"], new["status"]) == ("New subject", t2["version"], "current")
    assert (old["name"], old["body_version"], old["status"]) == ("You agreed to hear from us", t1["version"], "superseded")
    assert new["updated_at"].endswith("Z") and old["updated_at"] <= new["updated_at"]


def test_a_template_detail_has_the_list_fields_and_the_body(world, stack):
    """confirmations.md section 12 (the detail adds the editable parts, subject and opening_line, to the list fields)."""
    a = world.a.boss
    t = a.ok("POST", "/v1/confirmations/templates", body={"subject": "Hello", "opening_line": "Thanks for signing up."})
    one = world.a.dev.ok("GET", f"/v1/confirmations/templates/{t['template_id']}")
    assert set(one) >= LIST_KEYS | {"subject", "opening_line"}
    assert (one["name"], one["subject"], one["opening_line"], one["body_version"], one["status"]) == (
        "Hello", "Hello", "Thanks for signing up.", t["version"], "current")
    a.ok("POST", "/v1/confirmations/templates", body={"subject": "Later"})
    assert world.a.dev.ok("GET", f"/v1/confirmations/templates/{t['template_id']}")["status"] == "superseded"


def test_the_template_list_is_of_one_organization_only(world, stack):
    """The isolation rule."""
    world.a.boss.ok("POST", "/v1/confirmations/templates", body={"subject": "Mine"})
    assert world.b.boss.ok("GET", "/v1/confirmations/templates")["items"] == []


# ---- the link host answer ---------------------------------------------------------------------------------------------------
def test_set_link_host_answers_host_status_txt_cname_target_and_a_null_verified_at(world, stack):
    """confirmations.md section 2 (set answers {host, status, txt_record, cname_target, verified_at})."""
    got = world.a.boss.ok("POST", "/v1/confirmations/link-host", body={"host": "consent.acme.example"})
    assert set(got) == {"host", "status", "txt_record", "cname_target", "verified_at"}
    assert (got["host"], got["status"], got["cname_target"], got["verified_at"]) == (
        "consent.acme.example", "pending_dns", "edge.consentvault.ai", None)
    assert got["txt_record"]


def test_verify_link_host_answers_the_same_shape_with_verified_at(world, stack):
    """confirmations.md section 2 (verify answers the same object, verified_at set to the moment of the verifying)."""
    a = world.a.boss
    got = a.ok("POST", "/v1/confirmations/link-host", body={"host": "consent.acme.example"})
    stack.dns.records[("consent.acme.example", "CNAME")] = got["cname_target"]
    stack.dns.records[("consent.acme.example", "TXT")] = got["txt_record"]
    done = a.ok("POST", "/v1/confirmations/link-host:verify", body={})
    assert set(done) == {"host", "status", "txt_record", "cname_target", "verified_at"}
    assert done["status"] == "verified" and done["cname_target"] == got["cname_target"] and done["verified_at"].endswith("Z")
    assert a.ok("GET", "/v1/confirmations/settings")["link_host"] == done


def test_settings_link_host_carries_cname_target_and_is_null_when_no_host_is_set(world, stack):
    """confirmations.md section 2 (settings.link_host adds cname_target; unset host: null, status unset)."""
    unset = world.a.boss.ok("GET", "/v1/confirmations/settings")["link_host"]
    assert unset == {"host": None, "status": "unset", "txt_record": None, "cname_target": None, "verified_at": None}
    world.a.boss.ok("POST", "/v1/confirmations/link-host", body={"host": "consent.acme.example"})
    pending = world.a.viewer.ok("GET", "/v1/confirmations/settings")["link_host"]
    assert pending["status"] == "pending_dns" and pending["cname_target"] == "edge.consentvault.ai" and pending["verified_at"] is None


def test_setting_a_new_host_clears_verified_at(world, stack):
    """confirmations.md section 2 (a new host starts again at pending_dns with no verified_at)."""
    a = world.a.boss
    got = a.ok("POST", "/v1/confirmations/link-host", body={"host": "consent.acme.example"})
    stack.dns.records[("consent.acme.example", "CNAME")] = got["cname_target"]
    stack.dns.records[("consent.acme.example", "TXT")] = got["txt_record"]
    assert a.ok("POST", "/v1/confirmations/link-host:verify", body={})["verified_at"]
    again = a.ok("POST", "/v1/confirmations/link-host", body={"host": "links.acme.example"})
    assert again["status"] == "pending_dns" and again["verified_at"] is None


# ---- the four fixed texts ---------------------------------------------------------------------------------------------------
def test_settings_returns_the_four_fixed_texts_with_their_version(world, stack):
    """confirmations.md sections 2 and 13 (fixed_texts: {version, items: [{kind, text}]} in the order confirmation, opt-out,
    HELP, START; the top-level fixed_text_version stays and is the same number)."""
    from contract_world.confirm import set_sender
    set_sender(world.a.boss)
    got = world.a.viewer.ok("GET", "/v1/confirmations/settings")
    fixed = got["fixed_texts"]
    assert set(fixed) == {"version", "items"} and fixed["version"] == got["fixed_text_version"] == 1
    assert [i["kind"] for i in fixed["items"]] == ["confirmation", "optout_reply", "help_reply", "start_reply"]
    assert all(set(i) == {"kind", "text"} and i["text"] for i in fixed["items"])
    text = {i["kind"]: i["text"] for i in fixed["items"]}
    tail = "Msg frequency varies. Msg & data rates may apply. Reply STOP to opt out, HELP for help."
    assert text["confirmation"] == f"<Sending brand>: on <date and time> you agreed to texts and calls about <purposes>. Full wording: <link>. {tail}"
    assert text["optout_reply"] == ("<Sending brand>: You are unsubscribed and will get no more texts or calls from us. "
                                    "Email is not affected. Reply START to get texts again.")
    assert text["help_reply"] == ("<Sending brand>: Help: help@acme.example, +18135550100. Reply STOP to opt out of texts and calls. "
                                  "Msg frequency varies. Msg & data rates may apply.")
    assert text["start_reply"] == f"<Sending brand>: You will get texts from us again. Msg frequency varies. Msg & data rates may apply. Reply STOP to opt out, HELP for help."


def test_the_help_text_names_a_placeholder_until_the_sender_details_are_set(world, stack):
    """confirmations.md section 2 (fixed_texts are rendered with the organization's own help contact when it has one)."""
    text = {i["kind"]: i["text"] for i in world.a.boss.ok("GET", "/v1/confirmations/settings")["fixed_texts"]["items"]}
    assert text["help_reply"].startswith("<Sending brand>: Help: <help email>. Reply STOP")


def test_the_fixed_text_version_in_settings_is_read_from_texts_at_each_request(world, stack, monkeypatch):
    """confirmations.md section 13 (the version is read at use, never copied)."""
    monkeypatch.setattr("consentvault.confirm.texts.FIXED_TEXT_VERSION", 7)
    got = world.a.boss.ok("GET", "/v1/confirmations/settings")
    assert got["fixed_texts"]["version"] == got["fixed_text_version"] == 7


def test_the_fixed_texts_match_what_the_sender_sends(world, stack, armed):
    """The shown text and the sent text come from the same module: the HELP answer sent equals the shown HELP text with the
    brand and contact filled in."""
    o = world.a
    world.capture(o, PHONE)
    stack.run()
    shown = {i["kind"]: i["text"] for i in o.boss.ok("GET", "/v1/confirmations/settings")["fixed_texts"]["items"]}
    text_in(armed, "HELP")
    stack.run()
    sent = [m for m in stack.twilio.sent if "Help:" in str(m)]
    assert sent and shown["help_reply"].replace("<Sending brand>", "Acme Flooring") in str(sent[-1])
