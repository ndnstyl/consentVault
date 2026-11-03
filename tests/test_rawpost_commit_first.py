"""The raw post commits on its own first: a failure queuing pushes, writing the records list or the confirmation intents can
no longer remove a capture (task T039; rows F13 to F15 of the audit)."""

import pytest

from isolation.cloud_harness import Cloud, facts_of, raw_posts

from isolation.harness import build_tenancy

X = "+15555550177"


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


@pytest.mark.parametrize("where,name", [
    ("consentvault.sync.outbox.enqueue_event_pushes", "pushes"),
    ("consentvault.records.write_event_records", "records"),
    ("consentvault.confirmations.enqueue_confirmation_intents", "confirmations"),
])
def test_a_failure_after_the_post_cannot_remove_it(cloud, monkeypatch, where, name):
    import importlib

    module, attr = where.rsplit(".", 1)

    def broken(*a, **k):
        raise RuntimeError(f"simulated: {name} down")

    from consentvault.errors import LedgerError
    from consentvault.sync.outbox import OutboxError

    def fail(*a, **k):
        raise (OutboxError if name == "pushes" else LedgerError)(f"simulated: {name} down")
    monkeypatch.setattr(importlib.import_module(module), attr, fail)
    s, r = cloud.grant(cloud.a, X)
    assert s == 201 and r["stored"] is True and "event_id" not in r
    posts = raw_posts(cloud.t, cloud.a.org.org_id)
    assert len(posts) == 1 and str(posts[0]["post_id"]) == r["post_id"]
    assert facts_of(cloud.t, posts[0])["event_not_derived"]
    with cloud.t.superuser() as su:  # and the ledger holds no half-written event for it
        assert su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND session_ref = 's-1'",
                          (cloud.a.org.org_id,)).fetchone()["n"] == 0
