"""An unchecked consent box (and the other shape checks of the append) is decided in the pure phase and is final (one-door review
round 10): it repeats on the same bytes, so it is a stored reason, never an attempt retried forever that holds later grants up."""

import uuid

import pytest

from consentvault import api
from .test_door_site_key_state import _orgs, hw  # noqa: F401


def _grant(hw, a, contact, **extra):
    body = {"contact": contact, "event_type": "grant", "checked": True, "channels": ["sms"], "purposes": ["marketing"],
            "disclosure_sha256": a.wording, "brand_ids": [str(a.org.brand_id)], "method": "checkbox", "origin": "consumer",
            "client_nonce": str(uuid.uuid4()), **extra}
    return hw.cloud.call("/v1/events", body, token=hw.cloud.token(a, "capture"))


def _final_and_attempts(hw, a):
    from .cloud_harness import attempts_of, facts_of
    with hw.t.superuser() as su:
        post = su.execute("SELECT org_id, post_id, seq, intake FROM consentvault.raw_post WHERE org_id = %s AND kind = 'post'"
                          " ORDER BY seq DESC LIMIT 1", (a.org.org_id,)).fetchone()
    return facts_of(hw.t, post).get("event_not_derived"), attempts_of(hw.t, post)


def _count(hw, a, kind="grant"):
    with hw.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND event_type = %s",
                          (a.org.org_id, kind)).fetchone()["n"]


def test_an_unchecked_box_is_a_final_reason_with_no_attempt_and_holds_nobody(hw):
    a = hw.cloud.a
    before = _count(hw, a)
    st, _ = _grant(hw, a, "+12125550481", checked=False)
    assert st == 201
    outs = []
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=outs)
    final, attempts = _final_and_attempts(hw, a)
    assert final == "UncheckedConsentError" and not attempts and not [o for o in outs if o.retry]
    st, _ = _grant(hw, a, "+12125550482")   # a later grant is not held behind it
    assert st == 201 and _count(hw, a) == before + 1


@pytest.mark.parametrize("extra,name", [({"channels": []}, "EmptyConsentError"), ({"purposes": []}, "EmptyConsentError")])
def test_an_empty_grant_is_a_final_reason(hw, extra, name):
    a = hw.cloud.a
    _grant(hw, a, "+12125550483", **extra)
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    final, attempts = _final_and_attempts(hw, a)
    assert final is not None and not attempts, (final, attempts)
