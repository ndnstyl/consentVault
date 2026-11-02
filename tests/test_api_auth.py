"""The events route authenticates with one uniform refusal, refuses non-finite timestamps, and keeps replay memory in
the database so a second process (or a restart) cannot reopen the window."""

import json
import time

from consentvault import api

from test_api import PURPOSES, SECRET, TOKEN, VERIFIED_SECRET, _call, _grant, _post, _serve, server  # noqa: F401

import pytest


def _settings(app_dsn):
    return api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES,
                           verified_secret=VERIFIED_SECRET, default_region="US")  # gitleaks:allow (test constant)


def _refusals(server, disclosure):
    body = json.dumps(_grant(disclosure)).encode()
    now = int(time.time())
    out = {}
    out["bad_signature"] = _post(server, _grant(disclosure), secret="wrong")
    out["unsigned"] = _call(server + "/v1/events", "POST", b"{}", {"Content-Type": "application/json"})
    out["stale"] = _post(server, _grant(disclosure), ts=now - 301)
    out["nan"] = _post(server, _grant(disclosure), ts="nan")
    out["inf"] = _post(server, _grant(disclosure), ts="inf")
    out["not_a_number"] = _post(server, _grant(disclosure), ts="soon")
    ts = str(now)
    h = {api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}
    assert _call(server + "/v1/events", "POST", body, h)[0] == 201
    out["replay"] = _call(server + "/v1/events", "POST", body, h)
    return out


def test_every_authentication_failure_is_the_same_refusal(server, disclosure):
    out = _refusals(server, disclosure)
    shapes = {(s, json.dumps(b, sort_keys=True)) for s, b, _ in out.values()}
    assert len(shapes) == 1, out
    status, body = next(iter(shapes))
    assert status == 401 and json.loads(body)["error"] == "unauthenticated"


def test_a_non_finite_timestamp_is_refused_even_when_correctly_signed(server, disclosure):
    for ts in ("nan", "NaN", "inf", "-inf", "infinity"):
        status, body, _ = _post(server, _grant(disclosure), ts=ts)
        assert status == 401 and body["error"] == "unauthenticated", (ts, body)


def test_the_specific_reason_is_in_the_server_log_only(server, disclosure, caplog):
    with caplog.at_level("WARNING", logger="consentvault.api"):
        _post(server, _grant(disclosure), ts="nan")
        _post(server, _grant(disclosure), secret="wrong")
    text = caplog.text
    assert "bad_timestamp" in text and "bad_signature" in text


def test_a_second_app_instance_refuses_a_signed_request_the_first_accepted(app_dsn, disclosure):
    body = json.dumps(_grant(disclosure)).encode()
    ts = str(int(time.time()))
    h = {api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}
    gen_a, gen_b = _serve(_settings(app_dsn)), _serve(_settings(app_dsn))
    a, b = next(gen_a), next(gen_b)
    try:
        assert _call(a + "/v1/events", "POST", body, h)[0] == 201
        status, answer, _ = _call(b + "/v1/events", "POST", body, h)
        assert status == 401 and answer["error"] == "unauthenticated"
    finally:
        for g in (gen_a, gen_b):
            with pytest.raises(StopIteration):
                next(g)


def test_the_replay_window_cap_leaves_margin_under_the_databases_one_day_limit(app_dsn):
    from consentvault.errors import ConfigError

    assert 2 * api.MAX_REPLAY_WINDOW_SECONDS <= 22 * 3600
    ok = _settings(app_dsn)
    ok = type(ok)(**{**ok.__dict__, "replay_window": api.MAX_REPLAY_WINDOW_SECONDS})
    api.make_server(ok, "127.0.0.1", 0).server_close()
    for bad in (0, -1, api.MAX_REPLAY_WINDOW_SECONDS + 1, 43200):
        with pytest.raises(ConfigError):
            api.make_server(type(ok)(**{**ok.__dict__, "replay_window": bad}), "127.0.0.1", 0)
