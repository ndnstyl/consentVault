"""The retention in force when a post arrived is stored beside it and the evidence is kept until arrival plus that, however late the
projection runs and whatever the organisation's retention policy says by then (one-door review round 10)."""

import time
import uuid
from datetime import timedelta

import psycopg

from consentvault import api, door
from .test_door_site_key_state import _orgs, hw  # noqa: F401


def _retain_until_of_last_evidence(hw, a):
    with hw.t.superuser() as su:
        return su.execute("SELECT retain_until, created_at FROM consentvault.evidence_object WHERE org_id = %s ORDER BY created_at DESC LIMIT 1",
                          (a.org.org_id,)).fetchone()


def test_a_retention_policy_set_after_arrival_does_not_change_the_evidence_retention(hw, monkeypatch):
    a = hw.cloud.a
    real = door.TenantBackend.apply
    n = {"c": 0}

    def dies(self, *x, **k):
        n["c"] += 1
        if n["c"] == 1:
            raise psycopg.OperationalError("a passing fault")
        return real(self, *x, **k)

    monkeypatch.setattr(door.TenantBackend, "apply", dies)
    st, _ = hw.cloud.call("/v1/events", {"contact": "+12125550501", "event_type": "revoke", "channels": ["sms"], "purposes": ["*"],
                                         "method": "keyword", "origin": "consumer", "client_nonce": str(uuid.uuid4())},
                          token=hw.cloud.token(a, "capture"))
    assert st == 201
    with hw.t.superuser() as su:   # a longer retention now in force
        su.execute("INSERT INTO consentvault.retention_policy (org_id, version, evidence_years, platform_minimum_years, reason)"
                   " SELECT %s, coalesce(max(version), 0) + 1, 30, 1, 'later' FROM consentvault.retention_policy WHERE org_id = %s",
                   (a.org.org_id, a.org.org_id))
    time.sleep(1.2)
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    row = _retain_until_of_last_evidence(hw, a)
    with hw.t.superuser() as su:
        arrival = su.execute("SELECT received_at FROM consentvault.raw_post WHERE org_id = %s AND kind = 'post' ORDER BY seq DESC LIMIT 1",
                             (a.org.org_id,)).fetchone()["received_at"]
    years = (row["retain_until"] - arrival).days / 366
    assert 6.9 < years < 7.1, years      # the default in force at arrival (7 years), counted from the arrival, not 30 and not from now
