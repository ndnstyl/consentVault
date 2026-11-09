"""A post that arrived while the site-key lookup was down has no settings stored with it (one-door review rounds 4 to 8). Nothing of
the key's live configuration is taken in afterwards: its final reason is settings_missing_at_arrival, the same whenever it is
rebuilt and whatever happens to the key, the source or the brands later. (The widget's post is always read as a grant: the body's
own event_type is ignored by the transitional derivation, so no stop is lost.) A key already revoked or a source already retired
when the post arrived keeps its arrival-time reason."""

import psycopg
import pytest

from consentvault import api, door
from consentvault.tenancy import site_keys
from isolation.test_hardening_wave2 import _edge_body, _edge_post, _envelope, _events_of, _site_key, hw  # noqa: F401


def _down(m):
    def fail(conn, key):
        try:
            raise psycopg.OperationalError("down")
        except psycopg.OperationalError as exc:
            raise site_keys.SiteKeyLookupError("down") from exc
    m.setattr(site_keys, "resolve_site_key", fail)


def _orgs(hw):
    a, b = hw.cloud.a, hw.cloud.b
    with hw.t.superuser() as su:
        home = su.execute("SELECT consentvault.home_org() AS h").fetchone()["h"]
    return [home, a.org.org_id, b.org.org_id]


def test_a_post_under_a_key_revoked_before_it_arrived_keeps_its_arrival_time_reason(hw):
    a = hw.cloud.a
    key = _site_key(hw, a, revoke=True)
    before = len(_events_of(hw, a.org))
    _edge_post(hw, _envelope(key, _edge_body(a, key)))
    first, second = [], []
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=first)
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=second)
    assert len(_events_of(hw, a.org)) == before and not second   # decided from the fact stored at arrival, and nothing re-decided


def _outage_post(hw, monkeypatch):
    a = hw.cloud.a
    key = _site_key(hw, a)
    before = len(_events_of(hw, a.org))
    with monkeypatch.context() as m:
        _down(m)
        _edge_post(hw, _envelope(key, _edge_body(a, key)))
    return a, key, before


def _reasons(outs):
    return {o.reason for o in outs if o.reason}


@pytest.mark.parametrize("later", ["nothing", "revoke", "retire", "add_brand"])
def test_a_post_stored_while_the_lookup_was_down_has_the_same_final_reason_whatever_happens_later(hw, monkeypatch, later):
    a, key, before = _outage_post(hw, monkeypatch)
    with hw.t.superuser() as su:
        if later == "revoke":
            su.execute("UPDATE consentvault.credential SET revoked_at = clock_timestamp() WHERE site_key_id = %s", (key,))
        elif later == "retire":
            su.execute("UPDATE consentvault.capture_source SET status = 'retired', retired_at = clock_timestamp() WHERE org_id = %s"
                       " AND source_id = %s", (a.org.org_id, a.org.source_id))
        elif later == "add_brand":
            b = su.execute("INSERT INTO consentvault.brand (org_id, display_name) VALUES (%s, 'late') RETURNING brand_id",
                           (a.org.org_id,)).fetchone()["brand_id"]
            su.execute("UPDATE consentvault.capture_source SET brand_ids = brand_ids || %s::uuid WHERE org_id = %s AND source_id = %s",
                       (b, a.org.org_id, a.org.source_id))
    outs, again = [], []
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=outs)
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=again)
    assert len(_events_of(hw, a.org)) == before          # never an event, however the configuration moved
    assert "settings_missing_at_arrival" in _reasons(outs) and not [o for o in outs + again if o.retry]


