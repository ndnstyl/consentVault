"""The settings a post is projected with are read inside the store, so a post is never stored without them (one-door review round 7),
and a post stored without them gets a final named reason, never a retry that reads live configuration."""

import uuid

import psycopg
import pytest

from consentvault import api, door
from consentvault.tenancy import pipeline as pl
from .test_door_site_key_state import _orgs, hw  # noqa: F401


def _raw_posts(hw, a):
    with hw.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.raw_post WHERE org_id = %s AND kind = 'post'", (a.org.org_id,)).fetchone()["n"]


def _stop(hw, a, contact):
    return hw.cloud.call("/v1/events", {"contact": contact, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
                                        "brand_ids": [str(a.org.brand_id)], "method": "keyword", "origin": "consumer",
                                        "client_nonce": str(uuid.uuid4())}, token=hw.cloud.token(a, "capture"))


def test_a_settings_read_that_fails_stores_nothing_and_the_resend_records_the_stop(hw, monkeypatch):
    a = hw.cloud.a
    real = pl.CapturePipeline.projection_settings
    calls = {"n": 0}

    def flaky(self, *x, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise psycopg.OperationalError("passing fault at the settings read")
        return real(self, *x, **k)

    monkeypatch.setattr(pl.CapturePipeline, "projection_settings", flaky)
    posts = _raw_posts(hw, a)
    st, _ = _stop(hw, a, "+12125550421")
    assert st == 503 and _raw_posts(hw, a) == posts      # told to resend; nothing stored without its settings
    st, _ = _stop(hw, a, "+12125550421")
    assert st in (200, 201) and _raw_posts(hw, a) == posts + 1
    with hw.t.superuser() as su:
        su.execute("UPDATE consentvault.capture_source SET brand_ids = ARRAY[gen_random_uuid()] WHERE org_id = %s AND source_id = %s",
                   (a.org.org_id, a.org.source_id))
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    with hw.t.superuser() as su:
        n = su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke'", (a.org.org_id,)).fetchone()["n"]
    assert n >= 1


def test_every_stored_tenant_post_carries_its_settings(hw):
    a = hw.cloud.a
    _stop(hw, a, "+12125550422")
    with hw.t.superuser() as su:
        posts = su.execute("SELECT org_id, post_id, seq, intake FROM consentvault.raw_post WHERE org_id = %s AND kind = 'post' AND intake = 'api'",
                           (a.org.org_id,)).fetchall()
    from .cloud_harness import facts_of
    assert posts and all(door.TENANT_SETTINGS_FACT in facts_of(hw.t, p) for p in posts)


@pytest.mark.parametrize("settings", [None, {}, {"region": "US", "channels": ["sms"]}])
def test_a_post_stored_without_its_settings_has_a_final_named_reason(settings):
    backend = door.TenantBackend(None, None, settings)
    payload = {"contact": "+12125550423", "event_type": "grant", "checked": True, "channels": ["sms"], "purposes": ["marketing"],
               "method": "checkbox", "origin": "consumer", "disclosure_sha256": "a" * 64}   # a grant: a stop is decided without them
    auth = door.Auth(credential={"credential_id": str(uuid.uuid4()), "scopes": ["capture"]}, org_id=str(uuid.uuid4()))
    assert backend.prepare(None, payload, b"{}", auth) == "settings_missing_at_arrival"
