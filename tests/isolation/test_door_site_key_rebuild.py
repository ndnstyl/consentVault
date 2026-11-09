"""A post whose site-key lookup failed at intake is not held: the rebuild repeats the lookup. The post arrived without its settings,
so once the lookup answers it has the final reason settings_missing_at_arrival and no event (one-door review round 8: nothing of
the key's live configuration is taken in afterwards). While the lookup is still down the post stays pending and is the only thing
the command reports as unfinished."""

import psycopg
import pytest

from consentvault import api, door
from consentvault.tenancy import site_keys

from .test_hardening_wave2 import _edge_body, _edge_post, _envelope, _events_of, _facts, _posts_of, _site_key, hw  # noqa: F401


def _down(monkeypatch):
    def fail(conn, key):
        try:
            raise psycopg.OperationalError("the database did not answer")
        except psycopg.OperationalError as exc:
            raise site_keys.SiteKeyLookupError("the site key lookup failed: OperationalError") from exc
    monkeypatch.setattr(site_keys, "resolve_site_key", fail)


def _home(hw):
    with hw.t.superuser() as su:
        return su.execute("SELECT consentvault.home_org() AS h").fetchone()["h"]


def test_a_post_whose_site_key_lookup_failed_is_final_without_settings_after_the_rebuild_repeats_the_lookup(hw, monkeypatch):
    a, b = hw.cloud.a, hw.cloud.b
    key = _site_key(hw, a)
    before = len(_events_of(hw, a.org))
    with monkeypatch.context() as m:
        _down(m)
        status, body = _edge_post(hw, _envelope(key, _edge_body(a, key, event_type="revoke", method="keyword")))
    assert status == 201 and body["stored"] is True
    home = _home(hw)
    orgs = [home, a.org.org_id, b.org.org_id]
    with monkeypatch.context() as m:   # the lookup is still down: the post stays pending, nothing is refused
        _down(m)
        outcomes: list = []
        api.rebuild_cloud(hw.cloud.settings, orgs, outcomes=outcomes)
        assert [o.reason for o in outcomes if o.retry] == ["SiteKeyLookupError"]
        assert len(_events_of(hw, a.org)) == before
    outcomes = []
    api.rebuild_cloud(hw.cloud.settings, orgs, outcomes=outcomes)   # the lookup answers: the post is final, with no live settings read
    assert not [o for o in outcomes if o.retry]
    assert "settings_missing_at_arrival" in {o.reason for o in outcomes}
    assert len(_events_of(hw, a.org)) == before
    again: list = []
    api.rebuild_cloud(hw.cloud.settings, orgs, outcomes=again)       # and a second run changes nothing
    assert not [o for o in again if o.event_id or o.retry] and len(_events_of(hw, a.org)) == before
