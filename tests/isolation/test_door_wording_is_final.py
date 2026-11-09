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


def test_a_wording_registered_after_the_post_arrived_does_not_change_its_outcome(hw):
    """Unknown wording is decided as of arrival (the wording's first_seen_at against the post's stored arrival): the same bytes
    give the same answer before and after the organisation registers the wording."""
    import hashlib
    from consentvault import disclosure as disc
    from consentvault.tenancy.tokens import org_transaction

    a = hw.cloud.a
    text = "Late wording %s may text you. Reply STOP to end." % uuid.uuid4()
    sha = hashlib.sha256(text.encode()).hexdigest()
    hw.cloud.grant(a, "+12125550451", disclosure_sha256=sha)
    outs = []
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw), outcomes=outs)
    final, attempts = _reason(hw, _last_post(hw, a))
    assert final == "UnknownDisclosureError" and not attempts
    with hw.t.app() as app, org_transaction(app, hw.t.token(a.org)):
        disc.register(app, text, "late", "en", ["sms"], ["marketing"])
    from .test_door_replay_after_brand_edit import _decisions
    assert _decisions(hw, a.org.org_id)[str(_last_post(hw, a)["post_id"])] == "UnknownDisclosureError"


def test_a_wording_whose_registration_straddles_the_post_is_decided_as_the_intake_saw_it(hw):
    """The registering transaction starts before the post and commits after it: the row's first_seen_at (the transaction start)
    precedes the arrival, but the intake could not see the row. The fact stored in the store transaction says what the intake saw,
    so the live answer and a replay agree."""
    import hashlib
    from consentvault import disclosure as disc
    from consentvault.tenancy.tokens import org_transaction

    a = hw.cloud.a
    text = "Inflight wording %s may text you. Reply STOP to end." % uuid.uuid4()
    sha = hashlib.sha256(text.encode()).hexdigest()
    with hw.t.app() as app, org_transaction(app, hw.t.token(a.org)):
        disc.register(app, text, "inflight", "en", ["sms"], ["marketing"])
        hw.cloud.grant(a, "+12125550452", disclosure_sha256=sha)
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    live, attempts = _reason(hw, _last_post(hw, a))
    from .test_door_replay_after_brand_edit import _decisions
    replay = _decisions(hw, a.org.org_id)[str(_last_post(hw, a)["post_id"])]
    assert live == replay == "UnknownDisclosureError" and not attempts


def test_the_wording_fact_is_stored_with_every_grant_post(hw):
    from .cloud_harness import facts_of

    a = hw.cloud.a
    hw.cloud.grant(a, "+12125550453")
    facts = facts_of(hw.t, _last_post(hw, a))
    assert facts["wording_known_at_arrival"]["known"] is True and facts["wording_known_at_arrival"]["sha256"] == a.wording

