"""The cloud pipeline projects a post with the configuration it was stored with: a stop that arrived while its source was active
still counts when the source is retired before the projection runs (and a stop is never refused for a later configuration)."""

import uuid

import pytest

from consentvault import api, door
from consentvault.tenancy.tokens import org_transaction

from .cloud_harness import Cloud, raw_posts

CONTACT = "+12125550181"


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def _stop(co):
    return {"contact": CONTACT, "channels": ["sms"], "purposes": ["marketing"], "session_ref": "s-1", "event_type": "revoke",
            "method": "keyword", "client_nonce": str(uuid.uuid4())}


def test_a_stop_stored_before_its_source_was_retired_still_counts(cloud, monkeypatch):
    co = cloud.a
    token = cloud.token(co, "capture")
    with monkeypatch.context() as m:
        def crash(*a, **k):
            raise RuntimeError("crash between the answer and the event")
        m.setattr(door, "project_post", crash)
        status, answer = cloud.call("/v1/events", _stop(co), token=token, headers={"X-ConsentVault-Request-Id": "r1"})
        assert status == 201 and answer["stored"] is True
    with cloud.t.superuser() as su:
        facts = su.execute("SELECT count(*) AS n FROM consentvault.raw_post_fact WHERE org_id = %s", (co.org.org_id,)).fetchone()["n"]
        assert facts > 0
    t = cloud.t
    with t.operator() as o, org_transaction(o, t.admin_token(co.org.org_id)):
        o.execute("UPDATE consentvault.capture_source SET status = 'retired', retired_at = now()"
                  " WHERE org_id = %s AND source_id = %s", (co.org.org_id, co.org.source_id))
    outcomes: list = []
    api.rebuild_cloud(cloud.settings, [co.org.org_id], outcomes=outcomes)
    assert [o.event_id is not None for o in outcomes] == [True], [(o.reason, o.retry) for o in outcomes]
    with cloud.t.superuser() as su:
        n = su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND contact_fp IS NOT NULL AND event_type = 'revoke'",
                       (co.org.org_id,)).fetchone()["n"]
    assert n >= 1 and len(raw_posts(cloud.t, co.org.org_id)) == 1
