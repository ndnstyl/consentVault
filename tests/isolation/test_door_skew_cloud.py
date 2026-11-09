"""The capture-time skew check compares against the post's stored arrival on the multi-tenant path and on the single-company live
HTTP path too (one-door review round 5, gate 3): whether a post is in the history never depends on when the projection runs."""

import time
from datetime import datetime, timedelta, timezone

from consentvault import api, door, ledger
from .test_door_site_key_state import _orgs, hw  # noqa: F401


def _count(hw, a, cap):
    with hw.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id=%s AND captured_at=%s",
                          (a.org.org_id, datetime.fromisoformat(cap))).fetchone()["n"]


def test_the_cloud_skew_check_does_not_depend_on_when_the_projection_runs(hw, monkeypatch):
    monkeypatch.setattr(ledger, "MAX_CAPTURE_SKEW", timedelta(seconds=1))
    a = hw.cloud.a
    cap = (datetime.now(timezone.utc) + timedelta(seconds=1.7)).isoformat()
    hw.cloud.grant(a, "+12125550188", captured_at=cap)
    live = _count(hw, a, cap)
    time.sleep(1.5)
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    assert live == _count(hw, a, cap) == 0


def test_a_capture_time_inside_the_bound_at_arrival_is_recorded_on_the_cloud_path(hw, monkeypatch):
    monkeypatch.setattr(ledger, "MAX_CAPTURE_SKEW", timedelta(seconds=1))
    a = hw.cloud.a
    cap = (datetime.now(timezone.utc) + timedelta(seconds=0.3)).isoformat()
    hw.cloud.grant(a, "+12125550189", captured_at=cap)
    assert _count(hw, a, cap) == 1
