"""A person's permission and proof timeline are read in the order their posts arrived, whichever order the projection wrote the
events in: a grant whose projection crashed and a stop projected first leave the person stopped, and the proof shows the
posts' arrival as each event's time."""

import pytest

from consentvault import api, door
from consentvault.tenancy.pipeline import normalize
from consentvault.tenancy.tokens import org_transaction

from .cloud_harness import Cloud, raw_posts
from .test_one_door_mixed_doors import _grant, _stop_through_another_door

CONTACT = "+12125550185"


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def test_permission_and_proof_follow_arrival_when_the_stop_is_projected_first(cloud):
    co, t = cloud.a, cloud.t
    token = cloud.token(co, "capture")
    with pytest.MonkeyPatch.context() as m:
        def crash(*a, **k):
            raise RuntimeError("crash between the answer and the event")
        m.setattr(door, "project_post", crash)
        status, _ = cloud.call("/v1/events", _grant(co, CONTACT, 1), token=token, headers={"X-ConsentVault-Request-Id": "r1"})
        assert status == 201
    _stop_through_another_door(cloud, CONTACT)           # the stop arrives second and is projected first
    api.rebuild_cloud(cloud.settings, [co.org.org_id])    # the grant, which arrived first, is projected last
    kind, norm = normalize(CONTACT, "US")
    fp = t.crypto.contact_fingerprint(co.org.org_id, kind, norm)
    with t.app() as app, org_transaction(app, t.token(co.org)):
        rows = app.execute("SELECT allowed, reason FROM consentvault.current_permission WHERE contact_fp = %s"
                           " AND channel = 'sms' AND purpose = 'marketing'", (fp,)).fetchall()
    assert [(r["allowed"], r["reason"]) for r in rows] == [(False, "stopped:revoke")]
    status, answer = cloud.proof(co, CONTACT)
    assert status == 200, answer
    timeline = answer["timeline"]["items"] if isinstance(answer.get("timeline"), dict) else answer["timeline"]
    assert [i["event_type"] for i in timeline] == ["grant", "revoke"]
    with t.superuser() as su:
        arrivals = {str(r["event_id"]): r["received_at"] for r in su.execute(
            "SELECT s.event_id, p.received_at FROM consentvault.event_source_post s JOIN consentvault.raw_post p"
            " ON p.org_id = s.org_id AND p.post_id = s.post_id WHERE s.org_id = %s AND s.role = 'trigger'", (co.org.org_id,))}
    for item in timeline:
        assert item["at"] == api_iso(arrivals[item["event_id"]])


def api_iso(value):
    from consentvault.proof import _iso_z
    return _iso_z(value)
