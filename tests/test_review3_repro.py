"""Reviewer reproductions (scratch only)."""
import os, subprocess, sys, time
import test_api as T
from test_api import server  # noqa: F401


def _perm(server):
    return T._call(server + "/v1/permission?contact=%2B12125550101",
                   headers={"Authorization": "Bearer test-bearer-token"})[1]


def _types(server):
    return [x["event_type"] for x in _perm(server)["history"]]


STOP = {"contact": "+12125550101", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword"}


def _last(conn):
    return {k: v for k, v in T._facts(conn, T._posts(conn)[-1]["post_id"]).items() if k.startswith("event_")}


def test_r1_form_grant_after_stop(server, disclosure, conn):
    now = int(time.time())
    assert T._post(server, T._grant(disclosure), ts=now - 60)[0] == 201
    assert T._post(server, STOP, ts=now - 40)[0] == 201
    form = T._grant(disclosure); form["session_ref"] = "reengage-1"; form["page_url"] = "site/reengage"; form["client_ip"] = "1.2.3.4"
    assert T._post(server, form, ts=now - 20)[0] == 201
    rel = conn.execute("SELECT release_outcome, release_cause FROM consentvault.event WHERE event_type='release'").fetchall()
    print("R1", _last(conn), rel, _perm(server))
    assert _types(server) == ["grant", "revoke", "grant"] and rel == [] and _perm(server)["lifts"] == []


def test_r2_signed_revoke_carrying_the_stop_text(server, disclosure, conn):
    now = int(time.time())
    assert T._post(server, T._grant(disclosure), ts=now - 60)[0] == 201
    assert T._post(server, dict(STOP, inbound_message="STOP"), ts=now - 30)[0] == 201
    print("R2", _last(conn), _perm(server))
    assert "revoke" in _types(server) and _perm(server)["stops"][0]["lifted_by_post_ids"] == []


def test_r3_reused_request_id_header_on_a_different_message(server, disclosure, conn):
    now = int(time.time())
    h = {"X-ConsentVault-Request-Id": "contact-42"}
    assert T._post(server, T._grant(disclosure), ts=now - 60, headers=h)[0] == 201
    assert T._post(server, STOP, ts=now - 30, headers=h)[0] == 201
    print("R3", _last(conn), _perm(server))
    assert "revoke" in _types(server) and _perm(server)["stops"][0]["lifted_by_post_ids"] == []


def test_r4_subprocess_imports_branch_source():
    out = subprocess.run([sys.executable, "-c", "import consentvault;print(consentvault.__file__)"], capture_output=True, text=True,
                         env=os.environ.copy()).stdout.strip()
    print("R4", out)
    assert out.startswith(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), out


def test_r6_a_failed_derive_burns_the_request_id_so_the_safe_resend_is_dropped(server, disclosure, conn, monkeypatch):
    import psycopg
    from consentvault import api
    now = int(time.time())
    assert T._post(server, T._grant(disclosure), ts=now - 60)[0] == 201
    real = api._Handler._derive_event
    calls = {"n": 0}

    def flaky(self, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise psycopg.OperationalError("connection lost mid-derive")
        return real(self, *a, **k)
    monkeypatch.setattr(api._Handler, "_derive_event", flaky)
    h = {"X-ConsentVault-Request-Id": "stop-7"}
    assert T._post(server, STOP, ts=now - 30, headers=h)[0] == 201
    assert T._post(server, STOP, ts=now - 20, headers=h)[0] == 201  # the documented safe resend
    print("R6", _last(conn), _perm(server))
    assert "revoke" in _types(server) and _perm(server)["stops"][0]["lifted_by_post_ids"] == []
