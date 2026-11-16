"""A scripted post that copies a customer's public site key must not create a grant: the origin must be on the key's list, the
bot check must have succeeded with a hostname on the list, and a replay of one valid post makes no second grant. The raw post
is stored in every case."""

import json

import pytest

from isolation.harness import build_tenancy
from isolation.test_hardening_wave2 import _edge_body, _edge_post, _envelope, _events_of, _facts, _posts_of, _site_key, hw  # noqa: F401


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


def _allow(hw, co, origin="https://example.test"):
    with hw.t.superuser() as su:
        su.execute("UPDATE consentvault.capture_source SET allowed_origins = %s WHERE org_id = %s AND source_id = %s",
                   ([origin], co.org.org_id, co.org.source_id))


def _post(hw, a, key, *, token="tok-1", **env_kw):
    return _edge_post(hw, _envelope(key, _edge_body(a, key, turnstile_token=token), **env_kw))


def test_a_valid_post_from_a_real_visitor_creates_exactly_one_grant(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    _allow(hw, a)
    before = len(_events_of(hw, a.org))
    status, body = _post(hw, a, key)
    assert status == 201 and body["stored"] is True, body
    assert len(_events_of(hw, a.org)) == before + 1


def test_a_post_with_a_valid_site_key_and_the_wrong_origin_is_stored_and_makes_no_grant(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    _allow(hw, a)
    before, posts = len(_events_of(hw, a.org)), len(_posts_of(hw, a.org))
    status, body = _post(hw, a, key, origin="https://attacker.test")
    assert status == 201 and body["stored"] is True
    assert len(_posts_of(hw, a.org)) == posts + 1 and len(_events_of(hw, a.org)) == before
    assert _facts(hw, _posts_of(hw, a.org)[-1])["event_not_derived"] == "origin_not_allowed"


@pytest.mark.parametrize("facts", [
    {"bot_check_answer": None},
    {"bot_check_answer": {"success": False, "hostname": "example.test"}},
    {"bot_check_answer": {"success": True, "hostname": "attacker.test"}},
    {"bot_check_answer": {"success": True}},
])
def test_a_missing_or_failed_bot_check_is_stored_and_makes_no_grant(hw, facts):
    a = hw.cloud.a
    key = _site_key(hw, a)
    _allow(hw, a)
    before, posts = len(_events_of(hw, a.org)), len(_posts_of(hw, a.org))
    status, body = _post(hw, a, key, facts=facts)
    assert status == 201 and body["stored"] is True
    assert len(_posts_of(hw, a.org)) == posts + 1 and len(_events_of(hw, a.org)) == before
    assert _facts(hw, _posts_of(hw, a.org)[-1])["event_not_derived"].startswith("bot_check")


def test_a_missing_bot_check_fact_is_stored_and_makes_no_grant(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    _allow(hw, a)
    env = json.loads(_envelope(key, _edge_body(a, key, turnstile_token="t")))
    del env["edge_facts"]["bot_check_answer"]
    before = len(_events_of(hw, a.org))
    assert _edge_post(hw, json.dumps(env).encode())[0] == 201
    assert len(_events_of(hw, a.org)) == before


def test_a_replayed_valid_post_makes_no_second_grant_though_the_edge_gave_it_a_fresh_request_id(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    _allow(hw, a)
    before = len(_events_of(hw, a.org))
    assert _post(hw, a, key, facts={"request_id": "req-A"})[0] == 201
    assert _post(hw, a, key, facts={"request_id": "req-B"})[0] == 201
    assert len(_events_of(hw, a.org)) == before + 1
    assert _facts(hw, _posts_of(hw, a.org)[-1])["event_not_derived"] == "request_seen_before"
    assert _post(hw, a, key, token="tok-2", facts={"request_id": "req-C"})[0] == 201   # a new bot-check token is a new visit
    assert len(_events_of(hw, a.org)) == before + 2


def _site_key_facts(**over):
    base = {("vault", "tenant"): True, ("vault", "site_key_state"): "active", ("vault", "edge_timestamp"): "fresh",
            ("vault", "credential"): {"state": "verified", "credential_id": "c", "scopes": ["capture"], "via": "edge"},
            ("vault", "origin_on_list"): False, ("vault", "bot_check_hostname_on_list"): False,
            ("edge", "bot_check_answer"): None, ("vault", "request_key"): "replay:x:y"}
    base.update(over)
    return base


@pytest.mark.parametrize("event_type", ["revoke", "suppress"])
def test_a_stop_is_recorded_even_with_the_wrong_origin_and_no_bot_check(event_type):
    from consentvault import door

    facts = _site_key_facts()
    auth = door.auth_from_facts(facts)
    assert auth.reason == "origin_not_allowed" and auth.soft          # the failed checks are named on the record
    stop = door.Reading("v", "event", {"event_type": event_type, "contact": "x"})
    assert door.decide(stop, auth, set()) is None                     # and never refuse the stop
    grant = door.Reading("v", "event", {"event_type": "grant", "contact": "x"})
    assert door.decide(grant, auth, set()) == "origin_not_allowed"


def test_a_grant_in_the_same_conditions_still_makes_no_grant(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    _allow(hw, a)
    before = len(_events_of(hw, a.org))
    env = json.loads(_envelope(key, _edge_body(a, key, turnstile_token="g1"), origin="https://attacker.test"))
    env["edge_facts"]["bot_check_answer"] = None
    assert _edge_post(hw, json.dumps(env).encode())[0] == 201
    assert len(_events_of(hw, a.org)) == before
