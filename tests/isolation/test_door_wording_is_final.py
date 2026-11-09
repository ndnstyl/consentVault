"""The wording checks are decided from the stored wording hash, which is immutable, and are final (one-door review round 7): a wording
the organisation never registered, or a brand the wording does not name, is a stored reason and no retry, the rebuild exits clean, and
the posts behind are not held."""

import uuid

import psycopg

from consentvault import api
from .test_door_site_key_state import _orgs, hw  # noqa: F401


def _reason(hw, post):
    from .cloud_harness import attempts_of, facts_of
    return facts_of(hw.t, post).get("event_not_derived"), attempts_of(hw.t, post)


def _last_post(hw, a):
    with hw.t.superuser() as su:
        return su.execute("SELECT org_id, post_id, seq, intake FROM consentvault.raw_post WHERE org_id = %s AND kind = 'post'"
                          " ORDER BY seq DESC LIMIT 1", (a.org.org_id,)).fetchone()


def test_an_unregistered_wording_is_a_final_reason_with_no_attempt(hw):
    a = hw.cloud.a
    st, _ = hw.cloud.grant(a, "+12125550431", disclosure_sha256="ab" * 32)
    assert st == 201
    outs = []
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=outs)
    final, attempts = _reason(hw, _last_post(hw, a))
    assert final == "UnknownDisclosureError" and not attempts
    assert not [o for o in outs if o.retry]


def test_a_brand_the_wording_does_not_name_is_a_final_reason_with_no_attempt(hw):
    a = hw.cloud.a
    st0, _ = hw.cloud.grant(a, "+12125550432")   # registers nothing new; the wording is a.wording
    with hw.t.superuser() as su:
        try:
            su.execute("ALTER TABLE consentvault.disclosure DISABLE TRIGGER USER")
            su.execute("UPDATE consentvault.disclosure SET brand_ids = ARRAY[gen_random_uuid()] WHERE org_id = %s AND sha256 = %s",
                       (a.org.org_id, a.wording))
            su.execute("ALTER TABLE consentvault.disclosure ENABLE TRIGGER USER")
        except psycopg.Error:
            su.execute("ROLLBACK")
            import pytest
            pytest.skip("the wording's brand list cannot be set up here")
    st, _ = hw.cloud.grant(a, "+12125550433")
    assert st == 201
    outs = []
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=outs)
    final, attempts = _reason(hw, _last_post(hw, a))
    assert final == "brand_not_allowed" and not attempts
    assert not [o for o in outs if o.retry]
