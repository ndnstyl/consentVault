"""The one-door property test on the multi-tenant server (the product): the same random sequences of grant, stop, START text,
form consent, resend, duplicate and crash as tests/test_one_door_property.py, compared with the same reference fold. A crash is
the projection failing after the answer; the repair is the rebuild job (``api.rebuild_cloud``), which finds the stored posts
that have no outcome and projects them, and is run twice to show it is safe to run twice."""

import uuid

import pytest

from consentvault import api, door

from test_one_door_property import CONTACTS, SEEDS, base_kinds, make_sequence, reference_fold
from .cloud_harness import Cloud, raw_posts


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def _orphans(cloud, org_id):
    with cloud.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.event e WHERE e.org_id = %s AND NOT EXISTS ("
                          " SELECT 1 FROM consentvault.event_source_post s WHERE s.event_id = e.event_id AND s.role = 'trigger')",
                          (org_id,)).fetchone()["n"]


def _history(cloud):
    out = {}
    for i, contact in enumerate(CONTACTS):
        status, answer = cloud.gate(cloud.a, contact)
        assert status == 200, answer
        out[i] = ["revoke" if x["event_type"] in ("revoke", "suppress") else "grant" for x in answer["history"]]
    return out


@pytest.mark.parametrize("seed", SEEDS)
def test_the_multi_tenant_server_gives_the_reference_history_for_a_random_sequence(seed, cloud, monkeypatch):
    ops = make_sequence(seed, True)
    co = cloud.a
    token = cloud.token(co, "capture")
    setup_orphans = _orphans(cloud, co.org.org_id)  # events the harness wrote straight into the ledger before the test began
    sent = []
    for n, ((kind, person, ref), base) in enumerate(zip(ops, base_kinds(ops))):
        if kind == "dup":
            body, headers = sent[ref]
        else:
            body = {"contact": CONTACTS[person], "channels": ["sms"], "purposes": ["marketing"], "session_ref": "s-%d" % n}
            if base == "stop":
                body.update(event_type="revoke", method="keyword")
            else:
                body.update(event_type="grant", checked=True, disclosure_sha256=co.wording, brand_ids=[str(co.org.brand_id)],
                            method="checkbox", client_nonce=str(uuid.uuid4()))
                if base == "start":
                    body["inbound_message"] = "START"
                if base == "poison":   # a post no event can come from: its own error is its own stored reason
                    body["channels"] = 5
            headers = {"X-ConsentVault-Request-Id": "rid-%d-%s" % (n, uuid.uuid4().hex[:6])}
        sent.append((body, headers))
        if kind.startswith("crash"):
            def crash(*a, **k):
                raise RuntimeError("crash between the answer and the event")
            with pytest.MonkeyPatch.context() as m:
                m.setattr(door, "project_post", crash)
                status, answer = cloud.call("/v1/events", body, token=token, headers=headers)
        else:
            status, answer = cloud.call("/v1/events", body, token=token, headers=headers)
        assert status == 201 and answer["stored"] is True, (status, answer)
    want = reference_fold(ops)

    # 1. every request is stored whole
    assert len(raw_posts(cloud.t, co.org.org_id)) == len(ops)

    # 6. a crash, then the rebuild job: the same history; run twice, it changes nothing the second time
    api.rebuild_cloud(cloud.settings, [co.org.org_id])
    assert _history(cloud) == want
    api.rebuild_cloud(cloud.settings, [co.org.org_id])
    assert _history(cloud) == want

    # every event this test caused cites the one post it came from
    assert _orphans(cloud, co.org.org_id) == setup_orphans
