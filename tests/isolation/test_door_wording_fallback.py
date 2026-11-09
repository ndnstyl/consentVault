"""A post stored without the wording fact (by a build before the fact existed) is decided from when the wording was first seen
against the post's stored arrival, through one pinned security-definer lookup (one-door review round 10). The code version is door-3
so outcomes from before and after the change can be told apart."""

import hashlib
import uuid

from consentvault import api, door, disclosure as disc
from consentvault.tenancy.tokens import org_transaction
from .test_door_site_key_state import _orgs, hw  # noqa: F401


def test_the_code_version_is_door_3():
    assert door.CODE_VERSION == "door-3"


def _post_without_the_wording_fact(hw, monkeypatch, contact, sha):
    with monkeypatch.context() as m:
        m.setattr(door, "WORDING_FACT", "wording_fact_of_an_older_build")   # stored under a name this build does not read
        hw.cloud.grant(hw.cloud.a, contact, disclosure_sha256=sha)
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))


def _count(hw, a):
    with hw.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND event_type = 'grant'", (a.org.org_id,)).fetchone()["n"]


def _final(hw, a):
    from .cloud_harness import facts_of
    with hw.t.superuser() as su:
        post = su.execute("SELECT org_id, post_id, seq, intake FROM consentvault.raw_post WHERE org_id = %s AND kind = 'post' ORDER BY seq DESC LIMIT 1",
                          (a.org.org_id,)).fetchone()
    return facts_of(hw.t, post).get("event_not_derived")


def test_a_wording_registered_before_the_post_arrived_counts_without_the_fact(hw, monkeypatch):
    a = hw.cloud.a
    before = _count(hw, a)
    _post_without_the_wording_fact(hw, monkeypatch, "+12125550491", a.wording)
    assert _count(hw, a) == before + 1


def test_a_wording_registered_after_the_post_arrived_is_unknown_without_the_fact(hw, monkeypatch):
    a = hw.cloud.a
    text = "Fallback wording %s may text you. Reply STOP to end." % uuid.uuid4()
    sha = hashlib.sha256(text.encode()).hexdigest()
    before = _count(hw, a)
    _post_without_the_wording_fact(hw, monkeypatch, "+12125550492", sha)
    with hw.t.app() as app, org_transaction(app, hw.t.token(a.org)):
        disc.register(app, text, "fallback", "en", ["sms"], ["marketing"])
    api.rebuild_cloud(hw.cloud.settings, _orgs(hw))
    assert _count(hw, a) == before and _final(hw, a) == "UnknownDisclosureError"
