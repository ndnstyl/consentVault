"""The provider door as the cloud server mounts it (confirm.wiring.ConfirmationDoor, marketing/specs/confirmations-go-live):
an unsigned post and a wrongly signed post answer 401 and record nothing; a correctly signed one is taken. The edge forwards
Twilio's post with no bearer, so this signature check is the only thing that admits it. Needs PostgreSQL (the world fixture)."""

import urllib.parse
import uuid

from consentvault.confirm import wiring
from contract_world.confirm import INBOUND_BASE, OUR_NUMBER

P = "+13055550142"
BASE = "https://api.consentvault.ai"


def _counts(world, org):
    return {t: len(world.sql(org, f"SELECT 1 FROM consentvault.{t} WHERE org_id = %s", (org.org_id,)))
            for t in ("event", "contact_log", "confirmation_reply", "confirmation_inbound_seen")}


def _post(stack, key, params, signature):
    door = wiring.ConfirmationDoor(stack.service, BASE)
    headers = {"Content-Type": "application/x-www-form-urlencoded", **({"x-twilio-signature": signature} if signature is not None else {})}
    return door.handle("POST", f"/v1/confirmations/inbound/{key}", body=urllib.parse.urlencode(params).encode(), headers=headers)


def _params(body="STOP"):
    return {"From": P, "To": OUR_NUMBER, "Body": body, "MessageSid": "SM" + uuid.uuid4().hex[:30]}


def test_an_unsigned_post_through_the_door_is_refused_and_records_nothing(world, stack, armed):
    o = world.a
    before = _counts(world, o)
    r = _post(stack, armed.twilio_key, _params(), None)
    assert r.status == 401
    assert _counts(world, o) == before


def test_a_wrongly_signed_post_through_the_door_is_refused_and_records_nothing(world, stack, armed):
    o = world.a
    before = _counts(world, o)
    params = _params()
    wrong = stack.twilio.sign("https://evil.example/v1/confirmations/inbound/" + armed.twilio_key, params)
    assert _post(stack, armed.twilio_key, params, wrong).status == 401
    other_token = stack.twilio.sign(INBOUND_BASE + armed.twilio_key, {**params, "Body": "START"})  # signed over other parameters
    assert _post(stack, armed.twilio_key, params, other_token).status == 401
    assert _counts(world, o) == before


def test_a_correctly_signed_post_through_the_door_is_taken(world, stack, armed):
    params = _params("hello")
    r = _post(stack, armed.twilio_key, params, stack.twilio.sign(INBOUND_BASE + armed.twilio_key, params))
    assert r.status == 200


# ---- review of 2026-11-14 ---------------------------------------------------------------------------------------------------
FALLBACK_BASE = "https://api.consentvault.ai/v1/confirmations/inbound-fallback/"


def _raw_posts(world, org):
    return len(world.sql(org, "SELECT 1 FROM consentvault.raw_post WHERE org_id = %s", (org.org_id,)))


def _post_fallback(stack, key, params, signature):
    door = wiring.ConfirmationDoor(stack.service, BASE)
    headers = {"Content-Type": "application/x-www-form-urlencoded", "x-twilio-signature": signature}
    return door.handle("POST", f"/v1/confirmations/inbound-fallback/{key}", body=urllib.parse.urlencode(params).encode(), headers=headers)


def test_an_unsigned_or_oversized_post_stores_nothing_not_even_the_raw_request(world, stack, armed):
    o = world.a
    before = _raw_posts(world, o)
    assert _post(stack, armed.twilio_key, _params(), None).status == 401
    door = wiring.ConfirmationDoor(stack.service, BASE)
    big = door.handle("POST", f"/v1/confirmations/inbound/{armed.twilio_key}", body=b"a=" + b"x" * 16383, headers={"x-twilio-signature": "x"})
    assert big.status == 413
    assert _raw_posts(world, o) == before


def test_the_fallback_door_takes_a_post_signed_over_the_fallback_address_only(world, stack, armed):
    params = _params("hello")
    assert _post_fallback(stack, armed.twilio_key, params, stack.twilio.sign(FALLBACK_BASE + armed.twilio_key, params)).status == 200
    params = _params("hello")
    assert _post_fallback(stack, armed.twilio_key, params, stack.twilio.sign(INBOUND_BASE + armed.twilio_key, params)).status == 401


def test_a_number_added_to_the_account_after_connect_is_read_live_and_taken(world, stack, armed):
    later = "+15555550111"
    stack.twilio.numbers = stack.twilio.numbers + (later,)
    params = {**_params("hello"), "To": later}
    assert _post(stack, armed.twilio_key, params, stack.twilio.sign(INBOUND_BASE + armed.twilio_key, params)).status == 200


def test_a_stop_to_a_number_not_on_the_account_alarms_at_once(world, stack, armed):
    params = {**_params("STOP"), "To": "+15555550999"}
    r = _post(stack, armed.twilio_key, params, stack.twilio.sign(INBOUND_BASE + armed.twilio_key, params))
    assert r.status == 403
    alarm = stack.alarms(world.a.boss).get("inbound_signature_failures")
    assert alarm is not None and "stop_number_mismatch" in str(alarm["detail"])
