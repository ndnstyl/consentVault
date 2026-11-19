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
            "purpose": "marketing", "reason": "revoke", "state": "denied", "version": 3}
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
    r = run("Remember delivery", upstream={"Verify signature": {"idemKey": "k9"}}, items=[{}], staticData={"seenKeys": ["k1"]})
    assert r["staticData"]["seenKeys"] == ["k1", "k9"]


MSG = {"state": "denied", "version": 5, "channel": "sms", "contact": "+14075550123", "stateField": "consentvault_texts",
       "versionField": "consentvault_texts_version", "useBlanket": False, "at": "t"}


def decide(contacts, **msg):
    return run("Decide", upstream={"Verify signature": {**MSG, **msg}}, items=contacts)["out"]


def test_every_matching_contact_is_updated_not_just_the_first():
    out = decide([{"id": "1"}, {"id": "2"}, {"id": "3"}])
    assert [o["id"] for o in out] == ["1", "2", "3"] and {o["action"] for o in out} == {"update"}


def test_a_push_that_is_not_newer_never_overwrites_a_newer_state():
    stored = lambda v: {"id": "1", "properties": {"consentvault_texts_version": {"value": str(v)}}}
    assert decide([stored(5)])[0]["action"] == "stale"
    assert decide([stored(6)])[0]["action"] == "stale"
    assert [o["id"] for o in decide([stored(4), stored(9)])] == ["1"]


def test_nobody_matched_creates_nothing_and_a_stop_is_the_one_that_alerts():
    out = decide([{}])
    assert [o["action"] for o in out] == ["nomatch"]
    wf = json.loads(TEMPLATE.read_text())
    alert = next(n for n in wf["nodes"] if n["name"].startswith("ALERT"))
    assert "not in your CRM" in alert["parameters"]["subject"]
    cond = next(n for n in wf["nodes"] if n["name"] == "Stop for nobody in the CRM?")["parameters"]["conditions"]["conditions"]
    assert {c["rightValue"] for c in cond} == {"nomatch", "denied"}


def test_a_grant_never_lifts_the_blanket_field():
    assert decide([{"id": "1"}], useBlanket=True, state="permitted")[0]["action"] == "logged"


def test_the_template_has_no_step_that_creates_a_contact():
    wf = json.loads(TEMPLATE.read_text())
    ops = [n["parameters"].get("operation") for n in wf["nodes"] if n["type"] == "n8n-nodes-base.hubspot"]
    assert set(ops) == {"search", "update"}
