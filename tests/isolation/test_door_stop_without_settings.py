"""A revoke or suppress that arrived without its settings is decided from the post alone (one-door review round 9): its channels and
purposes as sent, no source or brand check, the phone region only when the contact is already E.164 or an email. A grant in the same
state keeps the final reason settings_missing_at_arrival. (Whether a stop can reach the capture pipeline in that state through the
site-key edge today does not matter: the rule is that a stop is never lost for want of configuration.)"""

import uuid

import pytest

from consentvault import api
from consentvault.tenancy import pipeline as pl
from .test_door_site_key_state import _orgs, hw  # noqa: F401


@pytest.fixture
def no_settings(monkeypatch):
    """Every tenant post is stored with an incomplete settings fact: the state of a post stored without its settings."""
    monkeypatch.setattr(pl.CapturePipeline, "projection_settings", lambda self, conn, cid: {})


def _count(hw, a, kinds=("revoke", "suppress")):
    with hw.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND event_type = ANY(%s)",
                          (a.org.org_id, list(kinds))).fetchone()["n"]


def _stop(hw, a, contact, kind="revoke"):
    return hw.cloud.call("/v1/events", {"contact": contact, "event_type": kind, "channels": ["sms"], "purposes": ["*"],
                                        "method": "keyword", "origin": "consumer", "client_nonce": str(uuid.uuid4())},
                         token=hw.cloud.token(a, "capture"))


@pytest.mark.parametrize("kind", ["revoke", "suppress"])
def test_a_stop_without_settings_records_whatever_the_source_and_brands_do_later(hw, no_settings, kind):
    a = hw.cloud.a
    before = _count(hw, a)
    st, _ = _stop(hw, a, "+12125550461", kind)
    assert st == 201
    with hw.t.superuser() as su:
        su.execute("UPDATE consentvault.capture_source SET status = 'retired', retired_at = clock_timestamp(), brand_ids = '{}' "
                   "WHERE org_id = %s AND source_id = %s", (a.org.org_id, a.org.source_id))
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    assert _count(hw, a) == before + 1


def _final_of_last(hw, a):
    from .cloud_harness import facts_of
    with hw.t.superuser() as su:
        post = su.execute("SELECT org_id, post_id, seq, intake FROM consentvault.raw_post WHERE org_id = %s AND kind = 'post'"
                          " ORDER BY seq DESC LIMIT 1", (a.org.org_id,)).fetchone()
    return facts_of(hw.t, post).get("event_not_derived")


def test_a_grant_without_settings_is_still_final_settings_missing_at_arrival(hw, no_settings):
    a = hw.cloud.a
    before = _count(hw, a, ("grant",))
    hw.cloud.grant(a, "+12125550462")
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    assert _count(hw, a, ("grant",)) == before and _final_of_last(hw, a) == "settings_missing_at_arrival"


def test_a_stop_without_settings_for_a_national_number_has_a_final_reason_not_a_guess(hw, no_settings):
    a = hw.cloud.a
    before = _count(hw, a)
    _stop(hw, a, "(212) 555-0163")
    outs = []
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=outs)
    assert _count(hw, a) == before and not [o for o in outs if o.retry] and _final_of_last(hw, a) == "invalid_contact"
