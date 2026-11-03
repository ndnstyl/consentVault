"""The raw post chain is anchored with the event chain, and a changed or missing post breaks its anchor (task T026)."""

import json
import uuid

import pytest

from consentvault import rawpost
from consentvault.anchor import anchor
from consentvault.errors import ChainError
from consentvault.ledger import verify_chain
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy.pipeline import ReceiptSigner
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def writer(tenancy, tmp_path):
    return rawpost.RawPostWriter(crypto=tenancy.crypto, store=LocalAppendOnlyEvidenceStore(str(tmp_path / "ev")),
                                 receipts=ReceiptSigner.generate(key_id="k"))


def _post(tenancy, writer, org, body=b"{}"):
    req = rawpost.RawRequest(intake="api", method="POST", path="/v1/events", query="", headers=(), body=body)
    with tenancy.app() as app:
        return writer.write(app, lambda c: org_transaction(c, tenancy.token(org)), req)


def _anchor(tenancy, org, sink):
    with tenancy.app() as app, org_transaction(app, tenancy.token(org, ("gate_read",))):
        return anchor(app, sink)


def test_one_anchor_run_writes_both_heads_to_the_sink_and_the_database(tenancy, writer, tmp_path):
    first, second = _post(tenancy, writer, tenancy.a), _post(tenancy, writer, tenancy.a)
    sink = str(tmp_path / "anchors.jsonl")
    rec = _anchor(tenancy, tenancy.a, sink)
    assert rec["raw_post"]["seq"] == second.seq and rec["raw_post"]["row_hash"] == second.row_hash and rec["seq"] >= 1
    lines = [json.loads(line) for line in open(sink)]
    assert [line.get("chain") for line in lines] == [None, "raw_post"]
    with tenancy.superuser() as su:
        assert su.execute("SELECT seq, row_hash FROM consentvault.raw_post_chain_head WHERE org_id = %s",
                          (tenancy.a.org_id,)).fetchone() == {"seq": second.seq, "row_hash": second.row_hash}
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a, ("gate_read",))):
        assert rawpost.verify_raw_anchors(app, sink_file=sink) == []
        assert verify_chain(app, sink_file=sink) == []  # the event verifier reads past the raw post line
    assert first.seq == 1


def test_an_organisation_with_posts_and_no_events_is_still_anchored(tenancy, writer, tmp_path):
    req = rawpost.RawRequest(intake="edge_site_key", method="POST", path="/capture", query="", headers=(), body=b"{}")
    with tenancy.app() as app:  # the home organisation (the platform intake) holds posts and no events
        post = writer.write(app, lambda c: org_transaction(c, tenancy.token_for_home(("capture",))), req)
    sink = str(tmp_path / "anchors.jsonl")
    with tenancy.app() as app, org_transaction(app, tenancy.token_for_home(("gate_read",))):
        rec = anchor(app, sink)
    assert rec["raw_post"]["seq"] == post.seq and rec["anchor_id"] == rec["raw_post"]["anchor_id"]


def test_a_changed_post_breaks_its_anchor_and_a_new_anchor_is_refused(tenancy, writer, tmp_path):
    _post(tenancy, writer, tenancy.a)
    second = _post(tenancy, writer, tenancy.a)
    sink = str(tmp_path / "anchors.jsonl")
    _anchor(tenancy, tenancy.a, sink)
    with tenancy.superuser() as su:
        su.execute("ALTER TABLE consentvault.raw_post DISABLE TRIGGER raw_post_append_only")
        su.execute("UPDATE consentvault.raw_post SET row_hash = %s WHERE post_id = %s", ("f" * 64, uuid.UUID(second.post_id)))
        su.execute("ALTER TABLE consentvault.raw_post ENABLE TRIGGER raw_post_append_only")
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a, ("gate_read",))):
        reasons = {b["reason"] for b in rawpost.verify_raw_anchors(app, sink_file=sink)}
    assert reasons == {"anchored_post_changed:raw_post_chain_head", "anchored_post_changed:sink"}
    with pytest.raises(ChainError, match="broken raw post chain"):
        _anchor(tenancy, tenancy.a, sink)


def test_a_sink_that_names_a_post_the_chain_does_not_hold_is_a_break(tenancy, writer, tmp_path):
    _post(tenancy, writer, tenancy.a)
    last = _post(tenancy, writer, tenancy.a)
    sink = str(tmp_path / "anchors.jsonl")
    _anchor(tenancy, tenancy.a, sink)
    extra = {"chain": "raw_post", "seq": last.seq + 5, "row_hash": "a" * 64, "anchored_at": "2026-01-01T00:00:00.000000Z",
             "org_id": str(tenancy.a.org_id)}
    with open(sink, "a") as fh:
        fh.write(json.dumps(extra) + "\n")
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a, ("gate_read",))):
        assert {b["reason"] for b in rawpost.verify_raw_anchors(app, sink_file=sink)} == {"anchored_post_missing:sink"}
