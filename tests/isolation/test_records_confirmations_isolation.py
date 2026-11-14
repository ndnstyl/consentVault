"""Records, confirmations and setup across two organizations (threat model LC-I3, LC-E3): B never sees A's rows, and what B
gets for something only A holds is the same answer as for something nobody holds, so no answer hints that A exists.
Sits beside test_endpoints.py, which covers the machine API; these are the portal routes."""

import uuid

import pytest

from consentvault.tenancy.admin_routes import Request

from contract_world.confirm import arm, build_stack, text_in
from contract_world.fixtures import vault, world  # noqa: F401
from contract_world.world import PENDING, PHONE, PHONE2

pytestmark = PENDING
UNHELD = "+15555550999"


def shape(r):
    body = dict(r.body or {})
    body.pop("request_id", None)
    return r.status, body


def same(world, call):
    """The same call by B for an id A holds and for an id nobody holds answers identically."""
    held, nobody = call(True), call(False)
    assert shape(held) == shape(nobody), (shape(held), shape(nobody))
    return held


def test_search_answers_the_same_for_a_contact_only_a_holds_and_one_nobody_holds(world):
    """records.md section 5 (one response shape, found or not) and LC-I2/LC-I3: B searching a contact only A holds learns nothing."""
    world.capture(world.a, PHONE)
    r = same(world, lambda held: world.b.boss.call("POST", "/v1/records:search", body={"contact": PHONE if held else UNHELD}))
    assert r.status == 200 and r.body["items"] == []


def test_reveal_proof_and_export_answer_the_same_for_a_foreign_record_id_and_a_random_one(world):
    """records.md section 6, 7 and proof-export.md amendment (an id of another organization answers like an unknown id) and LC-I3."""
    world.capture(world.a, PHONE)
    rid_a = world.record_id(world.a, PHONE)
    rid = lambda held: rid_a if held else str(uuid.uuid4())
    same(world, lambda h: world.b.boss.call("POST", "/v1/records:reveal", body={"record_ids": [rid(h)]}))
    same(world, lambda h: world.b.boss.call("POST", "/v1/proof", body={"record_id": rid(h)}))
    same(world, lambda h: world.b.boss.call("POST", "/v1/exports", body={"record_id": rid(h)}))
    ex_a = world.a.boss.ok("POST", "/v1/records/exports", body={"contact_form": "fingerprint"})["export_id"]
    same(world, lambda h: world.b.boss.call("GET", f"/v1/records/exports/{ex_a if h else uuid.uuid4()}"))
    same(world, lambda h: world.b.boss.call("POST", f"/v1/records/exports/{ex_a if h else uuid.uuid4()}:link"))


def test_every_list_of_b_is_empty_of_a(world):
    """auth.md (one organization per token) and LC-I3: every records, confirmations and setup list of B holds nothing of A."""
    a, b = world.a, world.b
    world.capture(a, PHONE, display={"name": "Dana Cruz"})
    stack = build_stack(world)
    arm(stack, a)
    world.capture(a, PHONE2)
    stack.run()
    for path in ("/v1/records", "/v1/confirmations/sends", "/v1/confirmations/replies"):
        assert b.boss.ok("GET", path)["items"] == [], path
    assert b.boss.ok("GET", "/v1/records/summary")["total"] == 0
    assert b.boss.ok("GET", "/v1/confirmations/settings")["sending_accounts"] == []
    assert not any(r["enabled"] for r in b.boss.ok("GET", "/v1/confirmations/rules")["items"])
    assert b.boss.ok("GET", "/v1/records/exports")["items"] == []
    assert not any(s["status"] == "done" for s in b.boss.ok("GET", "/v1/setup")["steps"] if s["step"] in ("first_event", "confirmations"))
    assert "Dana" not in str(b.boss.ok("GET", "/v1/audit", {"limit": "200"}))


def test_b_cannot_mark_a_reply_or_set_a_rule_for_a_source_or_account_of_a(world):
    """LC-E3 and LC-I3 (a rule or reply of A named by B answers like an id nobody holds)."""
    a, b = world.a, world.b
    stack = build_stack(world)
    armed = arm(stack, a)
    world.capture(a, PHONE)
    text_in(armed, "don't stop", sender=PHONE)
    from contract_world.confirm import replies
    reply_a = replies(a.boss)[0]["reply_id"]
    same(world, lambda h: b.boss.call("POST", f"/v1/confirmations/replies/{reply_a if h else uuid.uuid4()}:mark", body={"decision": "stop", "reason": "x"}))
    acct = [x for x in a.boss.ok("GET", "/v1/confirmations/settings")["sending_accounts"] if x["channel"] == "sms"][0]["account_id"]
    same(world, lambda h: b.boss.call("POST", f"/v1/confirmations/sending-accounts/{acct if h else uuid.uuid4()}:check", body={}))
    same(world, lambda h: b.boss.call("DELETE", f"/v1/confirmations/sending-accounts/{acct if h else uuid.uuid4()}", body={"reason": "x"}))
    same(world, lambda h: b.boss.call("PUT", f"/v1/confirmations/rules/{a.web_id if h else uuid.uuid4()}/sms",
                                      body={"enabled": True, "sending_brand_id": b.brand_id}))
    assert len([x for x in a.boss.ok("GET", "/v1/confirmations/rules")["items"] if x["enabled"]]) == 2  # A's rules untouched


def test_b_cannot_call_a_public_stop_or_wording_page_with_a_token_of_a_on_its_own_host(world):
    """confirmations.md section 6 and 7 (public pages live on the organization's own verified link host) and LC-S4: A's token on B's host is not found."""
    a, b = world.a, world.b
    stack = build_stack(world)
    arm(stack, a)
    arm(stack, b, text=False, host="consent.bravo.example")  # B has its own verified host
    world.email_grant(a, "dana@example.com")
    stack.run()
    token = stack.email.sent[0]["body"].split("/c/stop/")[1].split()[0].rstrip(".")
    assert stack.public("GET", "/c/stop/" + token, "consent.example.com").status == 200
    assert b.boss.ok("GET", "/v1/confirmations/settings")["link_host"]["status"] == "verified"
    assert stack.public("GET", "/c/stop/" + token, "consent.bravo.example").status == 404  # A's token on B's verified host
