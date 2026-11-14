"""LC-I4 beside test_log_scrub.py: a full confirmation, reply, stop-page, reveal and export flow logged at DEBUG emits no contact
point, name, reply text, provider secret or token."""

import logging

from contract_world.confirm import arm, build_stack, text_in
from contract_world.fixtures import vault, world  # noqa: F401
from contract_world.world import PENDING, PHONE

pytestmark = PENDING
NY = "+13055550142"


def test_a_confirmation_flow_logs_no_personal_data_or_secret(world, caplog):
    """confirmations.md section 1 (credentials never logged), section 7 (message and reply text kept only encrypted) and records.md
    section 3 and 6 (no contact point or name outside the answer): LC-I4."""
    caplog.set_level(logging.DEBUG)
    o = world.a
    stack = build_stack(world)
    armed = arm(stack, o)
    world.capture(o, NY, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    world.email_grant(o, "dana@example.com")
    stack.run()
    text_in(armed, "please stop texting me, this is Dana Cruz", sender=NY, sid="SMlog1")
    token = stack.email.sent[0]["body"].split("/c/stop/")[1].split()[0].rstrip(".")
    stack.public("POST", "/c/stop/" + token, "consent.example.com", body=b"scope=email")
    rid = world.record_id(o, NY)
    from contract_world import exports as ex
    ready = ex.wait_ready(o.boss, ex.start(o.boss, contact_form="full", reason="check")["export_id"])  # built, so its logs are in the capture
    assert ready["status"] == "ready"
    o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": [rid]})
    o.boss.ok("POST", "/v1/records:search", body={"contact": NY})
    for secret in (NY, "3055550142", "dana@example.com", "Dana", "Cruz", "stop texting me", stack.twilio.auth_token,
                   stack.twilio.api_key_secret, token):
        assert secret not in caplog.text, secret
