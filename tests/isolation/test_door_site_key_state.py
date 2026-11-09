"""No site-key outcome read at projection time is ever the final reason of a post (one-door review round 4, gates 2 and 3). A post
that arrived while the site-key lookup was down is projected under the credential its key belongs to whatever the key's state is
when the projection runs, so the history is the same whenever it is rebuilt; the state read then is kept as a fact beside it.
(The widget's post is always read as a grant: the body's own event_type is ignored by the transitional derivation.)"""

import dataclasses

import psycopg

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


def test_a_post_stored_while_the_lookup_was_down_is_counted_after_the_key_is_revoked(hw, monkeypatch):
    a = hw.cloud.a
    key = _site_key(hw, a)
    before = len(_events_of(hw, a.org))
    with monkeypatch.context() as m:
        _down(m)
        _edge_post(hw, _envelope(key, _edge_body(a, key)))
    real = site_keys.resolve_site_key
    outs = []
    with monkeypatch.context() as m:
        m.setattr(site_keys, "resolve_site_key", lambda c, k: dataclasses.replace(real(c, k), state="revoked"))
        api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=outs)
    assert len(_events_of(hw, a.org)) == before + 1
    assert not [o for o in outs if o.reason == "no_credential"]
    outs2 = []
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=outs2)
    assert len(_events_of(hw, a.org)) == before + 1


def test_a_post_under_a_key_revoked_before_it_arrived_keeps_its_arrival_time_reason(hw):
    a = hw.cloud.a
    key = _site_key(hw, a, revoke=True)
    before = len(_events_of(hw, a.org))
    _edge_post(hw, _envelope(key, _edge_body(a, key)))
    first, second = [], []
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=first)
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=second)
    assert len(_events_of(hw, a.org)) == before and not second   # decided from the fact stored at arrival, and nothing re-decided


def test_the_same_history_whatever_the_key_state_at_projection(hw, monkeypatch):
    a = hw.cloud.a
    key = _site_key(hw, a)
    before = len(_events_of(hw, a.org))
    with monkeypatch.context() as m:
        _down(m)
        _edge_post(hw, _envelope(key, _edge_body(a, key)))
    with hw.t.superuser() as su:
        su.execute("UPDATE consentvault.credential SET revoked_at = now() WHERE site_key_id = %s", (key,))
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    assert len(_events_of(hw, a.org)) == before + 1
