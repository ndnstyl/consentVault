"""The Twenty webhook route as the cloud server mounts it (twenty.md 3.1, 3.2): no bearer, the raw body handed through untouched,
the timestamp in milliseconds, and the answer inside Twenty's 5-second wait."""

import json

import pytest
from datetime import timedelta

from consentvault.route_wiring import TwentyWebhookAdapter

from .support import TwentyEnv, signed


def _adapter(tw):
    return TwentyWebhookAdapter(tw.receiver)


def test_the_route_matches_only_the_receiver_path_and_post():
    a = TwentyWebhookAdapter(receiver=None)
    assert a.handles("POST", "/v1/connectors/twenty/abc_DEF-123/webhook")
    assert not a.handles("GET", "/v1/connectors/twenty/abc/webhook")
    assert not a.handles("POST", "/v1/connectors/twenty/abc/webhook/x")
    assert not a.handles("POST", "/v1/connectors/other/abc/webhook")


def test_the_raw_body_reaches_the_signature_check_untouched(env):
    tw = TwentyEnv(env, env.t.a)
    pid = tw.twenty.add(phone="+15555552001", flag=True)
    raw = tw.twenty.event("person.updated", pid)
    path = f"/v1/connectors/twenty/{tw.sys.receiver_id}/webhook"
    reply = _adapter(tw).handle("POST", path, body=raw, headers={**signed(raw, at=env.clock()), "X-Request-Id": "r"})
    assert reply.status == 202 and reply.payload == {"ok": True}
    respaced = json.dumps(json.loads(raw)).encode()            # the same JSON, other bytes: refused
    reply = _adapter(tw).handle("POST", path, body=respaced, headers=signed(raw, at=env.clock()))
    assert reply.status == 401 and reply.payload == {"error": "invalid_client"}


def test_an_unknown_receiver_is_404_with_no_detail(env):
    tw = TwentyEnv(env, env.t.a)
    raw = b'{"eventName":"person.updated","record":{"id":"x"}}'
    assert _adapter(tw).handle("POST", "/v1/connectors/twenty/nope/webhook", body=raw, headers=signed(raw)).status == 404


def test_the_timestamp_is_milliseconds_a_seconds_value_is_stale(env):
    tw = TwentyEnv(env, env.t.a)
    raw = tw.twenty.event("person.updated", tw.twenty.add(phone="+15555552001"))
    h = signed(raw, at=env.clock())
    seconds = str(int(h["X-Twenty-Webhook-Timestamp"]) // 1000)
    from consentvault.sync.connectors import twenty_api as api

    h2 = {"X-Twenty-Webhook-Timestamp": seconds, "X-Twenty-Webhook-Signature": api.sign(b"whsec-" + b"s" * 30, seconds, raw)}
    path = f"/v1/connectors/twenty/{tw.sys.receiver_id}/webhook"
    assert _adapter(tw).handle("POST", path, body=raw, headers=h2).status == 401
    assert tw.activity("stale_timestamp") == 1


def test_the_answer_leaves_inside_twentys_five_second_wait(env):
    """Twenty waits 5 seconds (read in its 2.46.0 server). The receiver's budget is 4: past it the answer is a loud 503 and the
    reconcile is asked to finish the stop, never a silent late 202."""
    from consentvault.sync.connectors.twenty_receiver import REQUEST_BUDGET_SECONDS

    assert REQUEST_BUDGET_SECONDS < 5
    tw = TwentyEnv(env, env.t.a)
    clock = [100.0]
    tw.receiver.monotonic = lambda: clock[0]
    import consentvault.sync.connectors.twenty_receiver as rcv

    real = rcv.process_signal

    def slow(*a, **k):
        clock[0] += 3.0                                          # each recorded signal takes 3 seconds
        return real(*a, **k)
    rcv.process_signal = slow
    try:
        pid = tw.twenty.add(email="ann@example.com", phone="+15555552001", flag=True)
        raw = tw.twenty.event("person.updated", pid)
        reply = _adapter(tw).handle("POST", f"/v1/connectors/twenty/{tw.sys.receiver_id}/webhook", body=raw,
                                    headers=signed(raw, at=env.clock()))
    finally:
        rcv.process_signal = real
    assert reply.status == 503
    assert env.q("SELECT reconcile_requested_at FROM consentvault.connected_system WHERE system_id = %s",
                 [tw.sys.system_id])[0]["reconcile_requested_at"] is not None


@pytest.mark.parametrize("ts", ["١٧٩٣", "１７９３４５", "+1793452584000", " 1793452584000", "1e12", "1793452584000\n",
                                "1793452584000 ", "1_793_452_584_000", "\u00b9793452584000", "\U0001d7d9793452584000"])
def test_a_timestamp_that_is_not_plain_ascii_digits_gets_the_uniform_401(env, ts):
    tw = TwentyEnv(env, env.t.a)
    raw = tw.twenty.event("person.updated", tw.twenty.add(phone="+15555552001"))
    from consentvault.sync.connectors import twenty_api as api

    h = {"X-Twenty-Webhook-Timestamp": ts, "X-Twenty-Webhook-Signature": api.sign(b"x" * 32, "1", raw)}
    reply = _adapter(tw).handle("POST", f"/v1/connectors/twenty/{tw.sys.receiver_id}/webhook", body=raw, headers=h)
    assert (reply.status, reply.payload) == (401, {"error": "invalid_client"})


_DIGITS = {"arabic_indic": 0x0660, "fullwidth": 0xFF10, "devanagari": 0x0966, "math_bold": 0x1D7CE}


@pytest.mark.parametrize("script", sorted(_DIGITS))
def test_the_current_time_in_other_digits_with_a_valid_signature_is_refused(env, script):
    """The ASCII check is the only thing that refuses this: the value is the current time in milliseconds, written in another
    script's digits (which int() reads), and the signature over it is valid. The same request in ASCII digits is accepted."""
    from consentvault.sync.connectors import twenty_api as api

    tw = TwentyEnv(env, env.t.a)
    pid = tw.twenty.add(phone="+15555552001")
    path = f"/v1/connectors/twenty/{tw.sys.receiver_id}/webhook"
    ascii_ts = str(int(env.clock().timestamp() * 1000))
    other = "".join(chr(_DIGITS[script] + int(c)) for c in ascii_ts)
    assert int(other) == int(ascii_ts)                                       # Python would read it as the same number
    raw = tw.twenty.event("person.updated", pid)
    # the verifier reads a non-ASCII timestamp as "?" per character, so this signature is valid for it
    sig = api.sign(b"whsec-" + b"s" * 30, other.encode("ascii", "replace").decode("ascii"), raw)
    h = {"X-Twenty-Webhook-Timestamp": other, "X-Twenty-Webhook-Signature": sig}
    assert api.verify_signature(b"whsec-" + b"s" * 30, other, raw, h["X-Twenty-Webhook-Signature"])
    reply = _adapter(tw).handle("POST", path, body=raw, headers=h)
    assert (reply.status, reply.payload) == (401, {"error": "invalid_client"})
    raw2 = tw.twenty.event("person.updated", pid)
    h2 = {"X-Twenty-Webhook-Timestamp": ascii_ts, "X-Twenty-Webhook-Signature": api.sign(b"whsec-" + b"s" * 30, ascii_ts, raw2)}
    assert _adapter(tw).handle("POST", path, body=raw2, headers=h2).status == 202
