"""A link failure leaves the post stored, raises capture.link_failed, and the repair run appends the missing rows (task T082)."""

import pytest

from consentvault import cmd_match_repair, extract, match
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy
from match_support import fp_of, history, make_writer, match_rows, post


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def writer(tenancy, tmp_path):
    return make_writer(tenancy, tmp_path)


def run_repair(tenancy, writer):
    return cmd_match_repair.repair_all(tenancy.app, tenancy.operator, tenancy.key, writer)


def raw_counts(tenancy):
    with tenancy.superuser() as su:
        return su.execute("SELECT (SELECT count(*) FROM consentvault.raw_post) AS posts,"
                          " (SELECT max(row_hash) FROM consentvault.raw_post) AS head").fetchone()


def broken(*a, **k):
    raise match.LinkError("simulated: the match table refused")


def test_a_link_failure_leaves_the_post_stored_raises_the_alarm_and_the_repair_appends_the_rows(tenancy, writer, monkeypatch):
    ok, _ = post(tenancy, writer, {"contact": "a@b.com", "checked": True})
    with monkeypatch.context() as m:
        m.setattr(match, "link_post", broken)
        lost, after = post(tenancy, writer, {"contact": "a@b.com", "checked": False})
    assert "capture.link_failed" in after.alarms and after.failures == ["link:LinkError"]
    assert match_rows(tenancy, lost.post_id) == []
    assert raw_counts(tenancy)["posts"] == 2
    head = raw_counts(tenancy)["head"]
    out = run_repair(tenancy, writer)
    assert out["failed"] == [] and out["linked"] == 1
    rows = match_rows(tenancy, lost.post_id)
    assert len(rows) == 1 and rows[0]["previous_post_id"] is not None and rows[0]["changed"] is True
    assert raw_counts(tenancy)["head"] == head   # the post chain is untouched
    again = run_repair(tenancy, writer)
    assert again["linked"] == 0 and again["read"] == 0 and len(match_rows(tenancy, lost.post_id)) == 1
    newest, older = history(tenancy, writer, fp_of(tenancy, "email", "a@b.com"))
    assert newest["post_id"] == lost.post_id and newest["changed_from"]["consent_values"] == ["true"]


def test_the_repair_also_writes_the_readings_a_failed_read_left_missing(tenancy, writer, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(extract, "write_readings", lambda *a, **k: (_ for _ in ()).throw(extract.ConsentVaultError("simulated")))
        m.setattr(match, "link_post", broken)
        s, after = post(tenancy, writer, {"contact": "a@b.com", "checked": True})
    assert "readings:ConsentVaultError" in after.failures
    out = run_repair(tenancy, writer)
    assert out["read"] == 1 and out["linked"] == 1
    with tenancy.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.raw_post_field WHERE post_id = %s", (s.post_id,)).fetchone()["n"] > 0


def test_the_repair_reads_an_edge_post_from_the_browser_body_inside_the_signed_envelope(tenancy, writer):
    import base64, json
    inner = json.dumps({"contact": "e@b.com", "checked": False}).encode()
    envelope = json.dumps({"method": "POST", "path": "/capture", "query": "", "headers": [["content-type", "application/json"]],
                           "body_b64": base64.b64encode(inner).decode(), "edge_facts": {}}).encode()
    from consentvault import rawpost
    req = rawpost.RawRequest(intake="edge_site_key", method="POST", path="/v1/capture", query="", headers=(), body=envelope,
                             read_body=inner, read_headers=(("content-type", "application/json"),),
                             facts=(rawpost.Fact("vault", "edge_envelope_signature", "verified"),))
    with tenancy.app() as app:
        enter = lambda c: org_transaction(c, tenancy.token(tenancy.a, ("capture",)))  # noqa: E731
        writer.write(app, enter, req)   # stored, never read: the read step never ran
    out = run_repair(tenancy, writer)
    assert out["linked"] == 1 and out["failed"] == []
    [line] = history(tenancy, writer, fp_of(tenancy, "email", "e@b.com"))
    assert line["consent"]["values"] == ["false"]


def test_a_failed_organisation_is_listed_and_the_others_still_run(tenancy, writer, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(match, "link_post", broken)
        post(tenancy, writer, {"contact": "a@b.com", "checked": True}, org=tenancy.a)
        post(tenancy, writer, {"contact": "b@b.com", "checked": True}, org=tenancy.b)
    real = match.link_post
    calls = []

    def flaky(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise match.LinkError("simulated")
        return real(*a, **k)
    monkeypatch.setattr(match, "link_post", flaky)
    out = run_repair(tenancy, writer)
    assert len(out["failed"]) == 1 and out["linked"] == 1
