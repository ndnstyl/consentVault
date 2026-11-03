"""Raw posts are sealed and their seals re-verified like events, and a seal names the columns it covered (task T026)."""

import uuid

import pytest

from consentvault import rawpost, seal_raw
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.seal import SealError
from consentvault.tenancy.pipeline import ReceiptSigner
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy
from test_seal import _tsa_server, tsa  # noqa: F401  (the suite's throwaway timestamp authority)


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def writer(tenancy, tmp_path):
    return rawpost.RawPostWriter(crypto=tenancy.crypto, store=LocalAppendOnlyEvidenceStore(str(tmp_path / "ev")),
                                 receipts=ReceiptSigner.generate(key_id="k"))


def post(tenancy, writer, body=b'{"checked": false}'):
    req = rawpost.RawRequest(intake="api", method="POST", path="/v1/events", query="", headers=(("a", "b"),), body=body)
    with tenancy.app() as app:
        return writer.write(app, lambda c: org_transaction(c, tenancy.token(tenancy.a)), req)


def worker(tenancy):
    return org_transaction(tenancy.app(), tenancy.admin_token(tenancy.a.org_id))


def test_a_raw_post_is_sealed_then_verifies_and_the_seal_names_its_columns(tenancy, writer, tsa):
    first, second = post(tenancy, writer), post(tenancy, writer)
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        assert seal_raw.seal_pending_raw(app, tsa.url, backoff=0) == [first.post_id, second.post_id]
        row = app.execute("SELECT * FROM consentvault.raw_post_seal ORDER BY created_at LIMIT 1").fetchone()
        assert row["hash_version"] == 3 and "body_sha256" in row["columns"] and "prev_hash" in row["columns"]
        assert bytes(row["digest"]).hex() == first.row_hash  # the seal digests exactly the columns the row hash covers
        assert seal_raw.verify_raw(app, first.post_id).ok
        assert app.execute("SELECT verified_at FROM consentvault.raw_post_seal ORDER BY created_at LIMIT 1").fetchone()["verified_at"]
        assert seal_raw.verify_all_raw(app) == (2, [])
        assert seal_raw.seal_pending_raw(app, tsa.url, backoff=0) == []


def test_a_post_changed_after_it_was_written_is_not_sealed_and_a_changed_sealed_post_fails_verification(tenancy, writer, tsa):
    first, second = post(tenancy, writer), post(tenancy, writer)
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        assert seal_raw.seal_pending_raw(app, tsa.url, limit=1, backoff=0) == [first.post_id]
    with tenancy.superuser() as su:
        su.execute("ALTER TABLE consentvault.raw_post DISABLE TRIGGER raw_post_append_only")
        su.execute("UPDATE consentvault.raw_post SET body_bytes = body_bytes + 1 WHERE post_id = %s", (uuid.UUID(first.post_id),))
        su.execute("UPDATE consentvault.raw_post SET body_bytes = body_bytes + 1 WHERE post_id = %s", (uuid.UUID(second.post_id),))
        su.execute("ALTER TABLE consentvault.raw_post ENABLE TRIGGER raw_post_append_only")
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        with pytest.raises(SealError, match="no longer recomputes"):
            seal_raw.seal_pending_raw(app, tsa.url, backoff=0)
        res = seal_raw.verify_raw(app, first.post_id)
        assert not res.ok and "digest mismatch" in res.reason
        count, failures = seal_raw.verify_all_raw(app)
        assert count == 1 and len(failures) == 1


def test_a_post_with_no_seal_past_the_grace_is_a_failure(tenancy, writer):
    from datetime import timedelta
    p = post(tenancy, writer)
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        count, failures = seal_raw.verify_all_raw(app, unsealed_grace=timedelta(seconds=0))
        assert count == 0 and [f.event_id for f in failures] == [p.post_id]
        assert seal_raw.verify_all_raw(app, unsealed_grace=timedelta(hours=1)) == (0, [])


def test_a_column_added_to_the_table_later_never_touches_an_existing_seal(tenancy, writer, tsa):
    p = post(tenancy, writer)
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        seal_raw.seal_pending_raw(app, tsa.url, backoff=0)
    # the seal's column list is what verification digests: dropping a later-added key from the canonical form changes nothing
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        row = app.execute("SELECT * FROM consentvault.raw_post WHERE post_id = %s", (uuid.UUID(p.post_id),)).fetchone()
        canon, _ = seal_raw._row_cts(row)
        later = {**canon, "a_column_added_later": "x"}
        stored = app.execute("SELECT columns, digest FROM consentvault.raw_post_seal").fetchone()
        assert seal_raw._digest(later, stored["columns"]) == bytes(stored["digest"])
        assert seal_raw.verify_raw(app, p.post_id).ok
