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


def _failures(server, disclosure):
    """Every way a request can fail to authenticate; each is sent to the capture path and each is answered the same way."""
    body = json.dumps(_grant(disclosure)).encode()
    now = int(time.time())
    out = {}
    out["bad_signature"] = _post(server, _grant(disclosure), secret="wrong")
    out["unsigned"] = _call(server + "/v1/events", "POST", b"{}", {"Content-Type": "application/json"})
    out["stale_timestamp"] = _post(server, _grant(disclosure), ts=now - 301)
    out["bad_timestamp_nan"] = _post(server, _grant(disclosure), ts="nan")
    out["bad_timestamp_inf"] = _post(server, _grant(disclosure), ts="inf")
    out["bad_timestamp_text"] = _post(server, _grant(disclosure), ts="soon")
    ts = str(now)
    h = {api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}
    assert _call(server + "/v1/events", "POST", body, h)[0] == 201
    out["replay"] = _call(server + "/v1/events", "POST", body, h)
    server.settle()
    return out


def _signature_facts(conn):
    from test_api import _facts, _posts
    return [_facts(conn, p["post_id"]).get("request_signature") for p in _posts(conn)]


def test_every_authentication_failure_is_stored_and_answered_the_same_way_as_a_success(server, disclosure, conn):
    out = _failures(server, disclosure)
    for name, (status, body, _) in out.items():
        assert status == 201 and body["stored"] is True and len(body["body_sha256"]) == 64, (name, status, body)
    # the reason is a fact beside the stored post, never in the sender's answer
    facts = _signature_facts(conn)
    assert facts[:6] == ["bad_signature", "unsigned", "stale_timestamp", "bad_timestamp", "bad_timestamp", "bad_timestamp"]
    assert facts[6] == "valid"
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 1  # only the one valid, fresh post


def test_a_non_finite_timestamp_is_stored_with_the_fact_even_when_correctly_signed_and_makes_no_event(server, disclosure, conn):
    for ts in ("nan", "NaN", "inf", "-inf", "infinity"):
        status, body, _ = _post(server, _grant(disclosure), ts=ts)
        assert status == 201 and body["stored"] is True, (ts, body)
    assert set(_signature_facts(conn)) == {"bad_timestamp"}
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0


def test_the_specific_reason_is_in_the_server_log_and_in_the_post_never_in_the_answer(server, disclosure, caplog, conn):
    with caplog.at_level("WARNING", logger="consentvault.api"):
        a = _post(server, _grant(disclosure), ts="nan")
        b = _post(server, _grant(disclosure), secret="wrong")
    assert "bad_timestamp" not in json.dumps(a[1]) and "bad_signature" not in json.dumps(b[1])
    assert _signature_facts(conn) == ["bad_timestamp", "bad_signature"]


def test_a_second_app_instance_stores_a_signed_request_the_first_accepted_and_the_fold_counts_it_once(app_dsn, disclosure, conn):
    body = json.dumps(_grant(disclosure)).encode()
    ts = str(int(time.time()))
    h = {api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}
    gen_a, gen_b = _serve(_settings(app_dsn)), _serve(_settings(app_dsn))
    a, b = next(gen_a), next(gen_b)
    try:
        assert _call(a + "/v1/events", "POST", body, h)[0] == 201
        a.settle()
        status, answer, _ = _call(b + "/v1/events", "POST", body, h)
        b.settle()
        assert status == 201 and answer["stored"] is True
        from test_api import _facts, _posts
        first, second = _posts(conn)
        assert "replay" not in _facts(conn, first["post_id"]) and "replay" not in _facts(conn, second["post_id"])
        assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 1
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
