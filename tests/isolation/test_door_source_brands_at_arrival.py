"""Source and brand checks are decided from the source's state and brand list stored beside the post when it arrived, never from the
live capture_source (one-door review round 6, gates 2 and 3): a stop told 201, a passing fault, then an admin edit of the source's
brands, and the stop still records."""

import uuid

import psycopg
import pytest

from consentvault import api
from consentvault.tenancy import pipeline as pl
from .test_door_site_key_state import _orgs, hw  # noqa: F401


def _fault_once(monkeypatch):
    real = pl.CapturePipeline.capture
    state = {"n": 0}

    def flaky(self, *a, **k):
        state["n"] += 1
        if state["n"] == 1:
            raise psycopg.OperationalError("passing fault")
        return real(self, *a, **k)

    monkeypatch.setattr(pl.CapturePipeline, "capture", flaky)


def _count(hw, a):
    with hw.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.event e WHERE e.org_id = %s AND e.source_id = %s"
                          " AND e.event_type = ANY(%s)", (a.org.org_id, a.org.source_id, ["grant", "revoke", "suppress"])).fetchone()["n"]


def _edit_brands(hw, a):
    with hw.t.superuser() as su:
        su.execute("UPDATE consentvault.capture_source SET brand_ids = ARRAY[gen_random_uuid()] WHERE org_id = %s AND source_id = %s",
                   (a.org.org_id, a.org.source_id))


@pytest.mark.parametrize("kind", ["revoke", "grant"])
def test_a_brand_edit_after_arrival_changes_nothing(hw, monkeypatch, kind):
    a = hw.cloud.a
    contact = "+12125550" + ("311" if kind == "revoke" else "312")
    before = _count(hw, a)
    _fault_once(monkeypatch)
    if kind == "grant":
        st, _ = hw.cloud.grant(a, contact)
    else:
        st, _ = hw.cloud.call("/v1/events", {"contact": contact, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
                                             "brand_ids": [str(a.org.brand_id)], "method": "keyword", "origin": "consumer",
                                             "client_nonce": str(uuid.uuid4())}, token=hw.cloud.token(a, "capture"))
    assert st in (200, 201)
    _edit_brands(hw, a)
    outs = []
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=outs)
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    assert _count(hw, a) - before == 1, [(o.reason, o.retry) for o in outs]
    assert not [o for o in outs if o.reason in ("brand_not_allowed", "source_not_allowed")]


def test_a_brand_that_was_never_on_the_source_is_still_refused_for_good(hw):
    a = hw.cloud.a
    before = _count(hw, a)
    st, body = hw.cloud.call("/v1/events", {"contact": "+12125550313", "event_type": "revoke", "channels": ["sms"],
                                            "purposes": ["marketing"], "brand_ids": [str(uuid.uuid4())], "method": "keyword",
                                            "origin": "consumer", "client_nonce": str(uuid.uuid4())}, token=hw.cloud.token(a, "capture"))
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    assert st >= 400 or _count(hw, a) == before
