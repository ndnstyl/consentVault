"""Wave 2 hardening, item (a): the operator console has its own audience, wants a recent sign-in, and every refused
operator attempt leaves a row on the platform audit chain. Loopback only."""

import json
import time

import pytest

from consentvault import db
from consentvault.route_wiring import Authenticator, DEFAULT_OPERATOR_MAX_SIGNIN_AGE_S
from consentvault.errors import ConsentVaultError

from admin.support import FakeIdentity

from .test_route_wiring import OPERATOR, _j, wired  # noqa: F401

BODY = {"name": "Console Co", "admin_email": "boss@console.example.com"}


def _refusals(w):
    with w.t.superuser() as su:
        return su.execute("SELECT actor_id, reason, target_id, request_id FROM consentvault.audit_event"
                          " WHERE org_id IS NULL AND action = 'operator.refused' ORDER BY seq").fetchall()


def _orgs(w):
    with w.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.organization").fetchone()["n"]


def test_a_member_portal_token_never_opens_the_operator_console(wired):
    """The member provider and the operator provider are separate: a token the member IdP issued is unknown to the
    operator provider (audience mismatch in production), so it is refused and recorded."""
    member_idp = FakeIdentity()
    member_token = member_idp.issue(OPERATOR[1], "op@example.com")
    before = len(_refusals(wired))
    s, raw, _ = wired.call("POST", "/v1/orgs", BODY, token=member_token, headers={"X-Request-Id": "req-aud-1"})
    assert (s, _j(raw)["error"]) == (401, "unauthenticated")
    rows = _refusals(wired)
    assert len(rows) == before + 1 and rows[-1]["reason"].startswith("token_rejected_")
    assert rows[-1]["request_id"] == "req-aud-1" and rows[-1]["target_id"] == "POST orgs_create"


def test_an_operator_who_signed_in_long_ago_is_refused_and_recorded_and_a_fresh_one_passes(wired):
    old = wired.identity.issue(OPERATOR[1], "op@example.com", signed_in_s_ago=DEFAULT_OPERATOR_MAX_SIGNIN_AGE_S + 60)
    unproven = wired.identity.issue(OPERATOR[1], "op@example.com", signed_in_s_ago=None)
    n = _orgs(wired)
    for tok, why in ((old, "sign_in_not_recent"), (unproven, "sign_in_time_unproven")):
        s, raw, _ = wired.call("POST", "/v1/orgs", BODY, token=tok)
        assert s == 401, raw
        assert _refusals(wired)[-1]["reason"] == why
        assert _refusals(wired)[-1]["actor_id"] == "https://idp.example.com|" + OPERATOR[1]
    assert _orgs(wired) == n
    fresh = wired.identity.issue(OPERATOR[1], "op@example.com", signed_in_s_ago=30)
    s, raw, _ = wired.call("POST", "/v1/orgs", BODY, token=fresh)
    assert s == 201, raw


def test_every_kind_of_refused_operator_attempt_writes_a_row_and_a_success_writes_no_refusal(wired):
    cases = [
        (None, "no_credential"),
        (wired.portal_token(wired.t.a), "member_session_not_accepted"),
        (wired.identity.issue("someone-else", "x@example.com"), "not_on_operator_list"),
        (wired.identity.issue(OPERATOR[1], "op@example.com", mfa=False), "token_rejected_MfaRequiredError"),
        ("not-a-token", "token_rejected_TokenMalformedError"),
    ]
    for tok, why in cases:
        before = len(_refusals(wired))
        s, _raw, _ = wired.call("POST", "/v1/orgs", BODY, token=tok)
        assert s == 401
        rows = _refusals(wired)
        assert len(rows) == before + 1 and rows[-1]["reason"] == why, (why, rows[-1:])
    assert not any("sign" in str(r["reason"]) for r in _refusals(wired)[:5])
    n = len(_refusals(wired))
    s, _raw, _ = wired.call("POST", "/v1/orgs", BODY, token=wired.identity.issue(OPERATOR[1], "op@example.com"))
    assert s == 201 and len(_refusals(wired)) == n
    with wired.t.superuser() as su:  # the refusal rows sit on the one platform chain, which still verifies
        assert su.execute("SELECT count(*) AS n FROM consentvault.audit_chain_breaks WHERE org_id IS NULL").fetchone()["n"] == 0


def test_a_refusal_row_carries_no_token_text(wired):
    secret_looking = wired.identity.issue("someone-else", "x@example.com")
    wired.call("POST", "/v1/orgs", BODY, token=secret_looking)
    assert all(secret_looking not in json.dumps(r, default=str) for r in _refusals(wired))


def test_when_the_refusal_cannot_be_recorded_the_answer_is_a_loud_503_not_a_quiet_401(wired):
    from consentvault.route_wiring import AdminRoutes
    app = next(r for r in wired.routes if isinstance(r, AdminRoutes))._app
    good = app._owner_connect
    app._owner_connect = lambda: db.connect("postgresql://127.0.0.1:1/none?connect_timeout=1")
    try:
        s, raw, _ = wired.call("POST", "/v1/orgs", BODY)
    finally:
        app._owner_connect = good
    assert (s, _j(raw)["error"]) == (503, "audit_unavailable")


def test_the_signin_age_must_be_a_sane_whole_number():
    for bad in (0, -5, 86401, 1.5, True):
        with pytest.raises(ConsentVaultError):
            Authenticator(connect=lambda: None, access_tokens=None, max_signin_age_s=bad)
    a = Authenticator(connect=lambda: None, access_tokens=None, max_signin_age_s=60, clock=lambda: time.time())
    assert a.operator_decision({"Authorization": "Bearer x"}).reason == "operator_identity_not_configured"
