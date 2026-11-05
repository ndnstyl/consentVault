"""A sequence through two doors: a form consent whose projection crashed, a person's stop through another door (the stop page,
as a text STOP would be) and then the next post. The person's history is read in the order the posts arrived, whichever order
the projection wrote the events in, and the next post brings every earlier post of every intake up to date."""

import uuid

import pytest

from consentvault import api, door
from consentvault.tenancy.tokens import org_transaction

from .cloud_harness import Cloud

CONTACT = "+12125550177"
OTHER = "+12125550178"


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def _grant(co, contact, n):
    return {"contact": contact, "channels": ["sms"], "purposes": ["marketing"], "session_ref": "s-%d" % n, "event_type": "grant",
            "checked": True, "disclosure_sha256": co.wording, "brand_ids": [str(co.org.brand_id)], "method": "checkbox",
            "client_nonce": str(uuid.uuid4())}


def _history(cloud, contact):
    status, answer = cloud.gate(cloud.a, contact)
    assert status == 200, answer
    return ["revoke" if x["event_type"] in ("revoke", "suppress") else "grant" for x in answer["history"]]


def _stop_through_another_door(cloud, contact):
    t, co = cloud.t, cloud.a
    with t.app() as app, org_transaction(app, t.token(co.org)):
        door.record_observed(app, t.crypto, intake="stop_page", enter=lambda c: c.transaction(), region="US", fields=dict(
            contact=contact, event_type="revoke", channels=["sms"], purposes=["*"], method="checkbox", origin="consumer",
            source_id=co.org.source_id, recorded_by="stop-page"))


def test_a_stop_through_another_door_between_a_crashed_grant_and_the_next_post_keeps_arrival_order(cloud):
    co = cloud.a
    token = cloud.token(co, "capture")
    with pytest.MonkeyPatch.context() as m:
        def crash(*a, **k):
            raise RuntimeError("crash between the answer and the event")
        m.setattr(door.TenantBackend, "apply", crash)
        status, _ = cloud.call("/v1/events", _grant(co, CONTACT, 1), token=token, headers={"X-ConsentVault-Request-Id": "r1"})
        assert status == 201
    _stop_through_another_door(cloud, CONTACT)
    status, _ = cloud.call("/v1/events", _grant(co, OTHER, 2), token=token, headers={"X-ConsentVault-Request-Id": "r2"})
    assert status == 201
    for _ in range(2):  # the rebuild is safe to run twice
        api.rebuild_cloud(cloud.settings, [co.org.org_id])
        assert _history(cloud, CONTACT) == ["grant", "revoke"]
    assert _history(cloud, OTHER) == ["grant"]
