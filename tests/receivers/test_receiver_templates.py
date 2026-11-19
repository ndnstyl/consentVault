"""The receiver template verifies the signature the way the webhook connector signs, orders by version, matches safely and never creates a contact."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from consentvault.sync.connectors.webhook import HEADER_IDEMPOTENCY, HEADER_SIGNATURE, sign_body

HERE = Path(__file__).parent
TEMPLATE = HERE.parent.parent / "docs" / "receivers" / "n8n-update-existing-contact.json"
SECRET = bytes(range(32))

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed; the n8n code steps cannot be run")


def body_of(**over) -> str:
    base = {"basis_event_id": "e1", "at": "2026-11-19T10:00:00.000Z", "channel": "sms", "contact": "Jane@Example.com", "org_id": "o1",
            "purpose": "marketing", "reason": "revoke", "state": "denied", "version": 3,
            "channel_state": "denied", "channel_version": 3}
    base.update(over)
    return json.dumps(base, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def run(node: str = "Verify signature", **payload) -> dict:
    payload = {"template": str(TEMPLATE), "node": node, **payload}
    done = subprocess.run(["node", str(HERE / "run_verify_node.mjs")], input=json.dumps(payload), capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def verify(body: str, headers: dict | None = None, **kw) -> dict:
    headers = {HEADER_SIGNATURE.lower(): sign_body("hmac", SECRET, body.encode())} if headers is None else headers
    return run(hmacSecretHex=SECRET.hex(), body=body, headers=headers, **kw)["out"][0]


def test_a_body_signed_by_the_connector_is_accepted_and_changed_or_unsigned_ones_are_refused():
    b = body_of()
    out = verify(b)
    assert out["valid"] is True and out["state"] == "denied" and out["version"] == 3
    assert verify(b.replace("denied", "permitted"), {HEADER_SIGNATURE.lower(): sign_body("hmac", SECRET, b.encode())})["valid"] is False
    assert verify(b, {HEADER_SIGNATURE.lower(): sign_body("hmac", bytes(32), b.encode())})["valid"] is False
    assert verify(b, {})["valid"] is False


def test_an_ed25519_signed_body_is_accepted_and_a_changed_one_refused():
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    assert pem.count("\n") >= 2  # a real multi-line key, pasted as is
    b = body_of()
    h = {HEADER_SIGNATURE.lower(): sign_body("ed25519", raw, b.encode())}
    assert run(ed25519Pem=pem, body=b, headers=h)["out"][0]["valid"] is True
    assert run(ed25519Pem=pem, body=b + " ", headers=h)["out"][0]["valid"] is False


@pytest.mark.parametrize("contact,kind,value", [("Jane@Example.com", "email", "jane@example.com"), ("(407) 555-0123", "phone", "+14075550123"),
                                                ("+14075550123", "phone", "+14075550123"), ("1-407-555-0123", "phone", "+14075550123")])
def test_the_contact_is_normalised_before_it_is_searched(contact, kind, value):
    out = verify(body_of(contact=contact))
    assert (out["contactKind"], out["contact"]) == (kind, value)


def test_a_fingerprint_only_message_is_refused_so_nothing_is_matched_on_a_scrambled_value():
    assert verify(body_of(contact="a" * 64))["refuse"]


def test_each_channel_maps_to_its_own_field_and_an_unmapped_one_is_refused_unless_a_blanket_field_is_set():
    assert verify(body_of(channel="sms"))["stateField"] != verify(body_of(channel="email"))["stateField"]
    unmapped = body_of(channel="mystery")
    assert verify(unmapped)["refuse"]
    blanket = verify(unmapped, blanket="dnc")
    assert blanket["refuse"] == "" and blanket["useBlanket"] is True


def test_a_delivery_already_applied_is_ignored():
    b = body_of()
    h = {HEADER_SIGNATURE.lower(): sign_body("hmac", SECRET, b.encode()), HEADER_IDEMPOTENCY.lower(): "k1"}
    assert run(hmacSecretHex=SECRET.hex(), body=b, headers=h, staticData={})["out"][0]["duplicate"] is False
    assert run(hmacSecretHex=SECRET.hex(), body=b, headers=h, staticData={"seenKeys": ["k1"]})["out"][0]["duplicate"] is True


def test_a_delivery_is_remembered_only_by_the_step_after_the_crm_work():
    wf = json.loads(TEMPLATE.read_text())
    before = {}
    for src, v in wf["connections"].items():
        for outs in v["main"]:
            for o in outs:
                before.setdefault(o["node"], set()).add(src)
    assert before["Remember delivery"] == {"Update every matching contact", "ALERT: stop for someone not in your CRM", "Log: no change made"}
    assert before["Answer 200"] == {"Remember delivery"}
    verify = next(n for n in wf["nodes"] if n["name"] == "Verify signature")
    assert "seenKeys =" not in verify["parameters"]["jsCode"]  # only the step after the CRM work writes the key
    r = run("Remember delivery", upstream={"Verify signature": {"idemKey": "k9"}}, items=[{}], staticData={"seenKeys": ["k1"]})
    assert r["staticData"]["seenKeys"] == ["k1", "k9"]


MSG = {"state": "denied", "version": 5, "channelState": "denied", "channelVersion": 5, "channel": "sms", "contact": "+14075550123", "stateField": "consentvault_texts",
       "versionField": "consentvault_texts_version", "useBlanket": False, "at": "t"}


def decide(contacts, **msg):
    return run("Decide", upstream={"Verify signature": {**MSG, **msg}}, items=contacts)["out"]


def hubspot_contact(cid, version=None, state=None):
    """The shape n8n's HubSpot search returns: properties are plain strings."""
    props = {}
    if version is not None:
        props["consentvault_texts_version"] = str(version)
    if state is not None:
        props["consentvault_texts"] = state
    return {"id": cid, "properties": props}


def test_every_matching_contact_is_updated_not_just_the_first():
    out = decide([hubspot_contact("1"), hubspot_contact("2"), hubspot_contact("3")])
    assert [o["id"] for o in out] == ["1", "2", "3"] and {o["action"] for o in out} == {"update"}


def grant(**over):
    return {"state": "permitted", "channelState": "permitted", **over}


def test_a_late_grant_never_overwrites_a_newer_stop():
    stopped = hubspot_contact("1", version=9, state="denied")
    assert decide([stopped], **grant(version=2, channelVersion=2))[0]["action"] == "stale"
    assert decide([stopped], **grant(version=9, channelVersion=9))[0]["action"] == "stale"
    assert decide([stopped], **grant(version=10, channelVersion=10))[0]["action"] == "update"


def test_a_denied_channel_is_always_applied_whatever_version_is_stored_and_keeps_the_highest_version():
    newer = hubspot_contact("1", version=9, state="permitted")
    out = decide([newer], state="denied", channelState="denied", version=2, channelVersion=2)[0]
    assert out["action"] == "update"
    assert out["properties"]["consentvault_texts"] == "denied" and out["properties"]["consentvault_texts_version"] == "9"


def test_a_grant_for_one_purpose_never_clears_the_channel_while_another_purpose_is_stopped():
    # reminders texts at version 5 with the CRM storing 4, marketing texts stopped at version 2, then reminders granted at version 5:
    # ConsentVault reports the channel as denied (marketing is stopped), so the field stays denied.
    contact = hubspot_contact("1", version=4, state="permitted")
    stop = decide([contact], state="denied", channelState="denied", version=2, channelVersion=2, purpose="marketing")[0]
    contact = {"id": "1", "properties": stop["properties"]}
    assert contact["properties"]["consentvault_texts"] == "denied"
    after = decide([contact], state="permitted", channelState="denied", version=5, channelVersion=5, purpose="reminders")[0]
    assert after["properties"]["consentvault_texts"] == "denied"


def test_a_message_without_the_channel_fields_is_refused_not_guessed():
    b = json.dumps({k: v for k, v in json.loads(body_of()).items() if not k.startswith("channel_")}, sort_keys=True, separators=(",", ":"))
    assert verify(b)["refuse"]


def test_nobody_matched_creates_nothing_and_a_stop_is_the_one_that_alerts():
    out = decide([{}])
    assert [o["action"] for o in out] == ["nomatch"]
    wf = json.loads(TEMPLATE.read_text())
    alert = next(n for n in wf["nodes"] if n["name"].startswith("ALERT"))
    assert "not in your CRM" in alert["parameters"]["subject"]
    cond = next(n for n in wf["nodes"] if n["name"] == "Stop for nobody in the CRM?")["parameters"]["conditions"]["conditions"]
    assert {c["rightValue"] for c in cond} == {"nomatch", "denied"}


def test_a_grant_never_lifts_the_blanket_field():
    assert decide([hubspot_contact("1")], useBlanket=True, **grant())[0]["action"] == "logged"


def test_a_phone_is_searched_on_both_the_phone_and_the_mobile_field():
    wf = json.loads(TEMPLATE.read_text())
    search = next(n for n in wf["nodes"] if n["name"] == "Find matching contacts")
    groups = search["parameters"]["filterGroupsUi"]["filterGroupsValues"]
    assert len(groups) == 2  # filter groups are OR'd by HubSpot
    assert "mobilephone" in json.dumps(groups[1])


def test_the_template_has_no_step_that_creates_a_contact():
    wf = json.loads(TEMPLATE.read_text())
    for n in wf["nodes"]:
        t, prm = n["type"], n["parameters"]
        assert not (t == "n8n-nodes-base.hubspot" and prm.get("operation") not in ("search",)), n["name"]
        if t == "n8n-nodes-base.httpRequest":
            assert prm["method"] == "PATCH" and "/contacts/{{ $json.id }}" in prm["url"], n["name"]
    assert any(n["type"] == "n8n-nodes-base.httpRequest" for n in wf["nodes"])


def test_a_grant_matched_on_one_phone_cannot_lift_a_stop_when_the_contact_holds_another_number_but_a_stop_still_applies():
    two_numbers = {"id": "1", "properties": {"mobilephone": "(407) 555-0123", "phone": "+14075559999"}}
    held = decide([two_numbers], contactKind="phone", **grant(version=5, channelVersion=5))
    assert [o["action"] for o in held] == ["held"]
    stop = decide([two_numbers], contactKind="phone", state="denied", channelState="denied", version=6, channelVersion=6)
    assert stop[0]["action"] == "update" and stop[0]["properties"]["consentvault_texts"] == "denied"
    one_number = {"id": "2", "properties": {"mobilephone": "+14075550123"}}
    assert decide([one_number], contactKind="phone", **grant(version=5, channelVersion=5))[0]["action"] == "update"
