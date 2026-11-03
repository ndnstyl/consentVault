"""The raw post writer: any bytes stored exactly, fingerprinted whole, large bodies in the object store, nothing partial on
a store failure (tasks T023 to T025)."""

import hashlib
import json
import os
import uuid

import psycopg
import pytest

from consentvault import rawpost
from consentvault.providers.errors import EvidenceStoreError
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy import crypto as tc
from consentvault.tenancy.pipeline import ReceiptSigner
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy

SIGNER = ReceiptSigner.generate(key_id="rk1")


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def evidence(tmp_path):
    return LocalAppendOnlyEvidenceStore(str(tmp_path / "ev"))


@pytest.fixture
def writer(tenancy, evidence):
    return rawpost.RawPostWriter(crypto=tenancy.crypto, store=evidence, receipts=SIGNER)


def post(tenancy, writer, body, org=None, **kw):
    org = org or tenancy.a
    request = rawpost.RawRequest(intake=kw.pop("intake", "api"), method="POST", path="/v1/events", query="a=1&b=%FF",
                                 headers=(("content-type", "application/json"), ("x-a", "1"), ("x-a", "2")), body=body, **kw)
    with tenancy.app() as app:
        return writer.write(app, lambda c: org_transaction(c, tenancy.token(org)), request)


def read_back(tenancy, writer, stored, org=None):
    org = org or tenancy.a
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(org.org_id)):
        return writer.read_body(app, org.org_id, stored.post_id)


@pytest.mark.parametrize("body", [b"", b"\x00\x01\x02\xff\xfe", b"\xc3\x28 not utf8 \xa0\xa1", b'{"checked": false}',
                                  b"{ broken json", "café ☃".encode(), os.urandom(5000)])
def test_any_bytes_are_stored_exactly_and_fingerprinted(tenancy, writer, body):
    stored = post(tenancy, writer, body)
    assert stored.body_sha256 == hashlib.sha256(body).hexdigest() and stored.body_bytes == len(body)
    assert read_back(tenancy, writer, stored) == body
    with tenancy.superuser() as su:
        row = su.execute("SELECT * FROM consentvault.raw_post WHERE post_id = %s", (uuid.UUID(stored.post_id),)).fetchone()
    assert bytes(row["body_ct"]) != body or body == b""  # encrypted at rest
    assert row["body_sha256"] == stored.body_sha256 and row["body_object_id"] is None and row["encryption"] == "wrapped_post_key"


def test_a_ten_mebibyte_body_is_stored_whole_in_the_object_store_and_read_back_identical(tenancy, writer, evidence):
    body = os.urandom(10 * 1024 * 1024)
    stored = post(tenancy, writer, body)
    assert stored.body_bytes == len(body) and stored.body_sha256 == hashlib.sha256(body).hexdigest()
    with tenancy.superuser() as su:
        row = su.execute("SELECT body_ct, body_object_id, unusual_size FROM consentvault.raw_post").fetchone()
    assert row["body_ct"] is None and row["body_object_id"] is not None and row["unusual_size"] is True
    assert read_back(tenancy, writer, stored) == body
    assert body[:64] not in evidence.get(str(tenancy.a.org_id), f"raw-posts/{row['body_object_id']}")  # encrypted in the store


def test_a_body_just_over_the_inline_limit_goes_to_the_store_and_one_at_the_limit_stays_inline(tenancy, writer):
    at = post(tenancy, writer, b"a" * rawpost.INLINE_LIMIT_BYTES)
    over = post(tenancy, writer, b"a" * (rawpost.INLINE_LIMIT_BYTES + 1))
    with tenancy.superuser() as su:
        rows = su.execute("SELECT body_ct IS NOT NULL AS inline, body_object_id IS NOT NULL AS stored, unusual_size"
                          " FROM consentvault.raw_post ORDER BY seq").fetchall()
    assert [(r["inline"], r["stored"], r["unusual_size"]) for r in rows] == [(True, False, False), (False, True, False)]
    assert read_back(tenancy, writer, over) == b"a" * (rawpost.INLINE_LIMIT_BYTES + 1)


def test_headers_keep_their_order_and_repeats_and_the_query_is_kept_as_sent(tenancy, writer):
    stored = post(tenancy, writer, b"x")
    with tenancy.superuser() as su:
        row = su.execute("SELECT headers_ct, query_ct, method, path FROM consentvault.raw_post").fetchone()
        key = su.execute("SELECT post_key_wrapped, key_version FROM consentvault.raw_post_key").fetchone()
    from consentvault.tenancy.keys_protocol import WrappedKey
    data_key = tenancy.crypto.open_contact_key(tenancy.a.org_id, WrappedKey(bytes(key["post_key_wrapped"]), key["key_version"]))
    headers = json.loads(tc.decrypt_field(data_key, tenancy.a.org_id, stored.post_id, "raw_post.headers", bytes(row["headers_ct"])))
    assert headers == [["content-type", "application/json"], ["x-a", "1"], ["x-a", "2"]]
    assert tc.decrypt_field(data_key, tenancy.a.org_id, stored.post_id, "raw_post.query", bytes(row["query_ct"])) == b"a=1&b=%FF"
    assert (row["method"], row["path"]) == ("POST", "/v1/events")


def test_the_post_key_is_wrapped_by_the_organisation_key_and_kept_apart(tenancy, writer):
    stored = post(tenancy, writer, b"x")
    with tenancy.superuser() as su:
        n = su.execute("SELECT count(*) AS n FROM consentvault.raw_post_key WHERE post_id = %s",
                       (uuid.UUID(stored.post_id),)).fetchone()["n"]
        cols = [r["column_name"] for r in su.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'raw_post'")]
    assert n == 1 and "post_key_wrapped" not in cols


def test_facts_are_stored_beside_the_post_in_the_same_transaction(tenancy, writer):
    stored = post(tenancy, writer, b"x", facts=(rawpost.Fact("edge", "client_ip", "203.0.113.9"), rawpost.Fact("vault", "origin_on_list", False)))
    with tenancy.superuser() as su:
        rows = su.execute("SELECT source, name FROM consentvault.raw_post_fact WHERE post_id = %s ORDER BY name",
                          (uuid.UUID(stored.post_id),)).fetchall()
    assert [(r["source"], r["name"]) for r in rows] == [("edge", "client_ip"), ("vault", "origin_on_list")]


def test_a_store_failure_raises_store_unavailable_and_writes_nothing_partial(tenancy, writer, evidence, monkeypatch):
    def refuse(*a, **k):
        raise EvidenceStoreError("store down")
    monkeypatch.setattr(evidence, "put", refuse)
    with pytest.raises(rawpost.StoreUnavailable):
        post(tenancy, writer, os.urandom(rawpost.INLINE_LIMIT_BYTES + 10), facts=(rawpost.Fact("vault", "x", 1),))
    with tenancy.superuser() as su:
        for table in ("raw_post", "raw_post_key", "raw_post_fact"):
            assert su.execute(f"SELECT count(*) AS n FROM consentvault.{table}").fetchone()["n"] == 0


def test_a_key_provider_failure_for_a_tenant_raises_store_unavailable_and_writes_nothing(tenancy, writer, monkeypatch):
    monkeypatch.setattr(tenancy.provider, "wrap_data_key", lambda *a: (_ for _ in ()).throw(
        __import__("consentvault.tenancy.errors", fromlist=["KeyProviderError"]).KeyProviderError("down")))
    with pytest.raises(rawpost.StoreUnavailable):
        post(tenancy, writer, b"x")
    with tenancy.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"] == 0


def test_a_database_failure_raises_store_unavailable(tenancy, writer):
    request = rawpost.RawRequest(intake="api", method="POST", path="/", query="", headers=(), body=b"x")
    with tenancy.app() as app:
        with pytest.raises(rawpost.StoreUnavailable):
            writer.write(app, lambda c: org_transaction(c, "not-a-token"), request)


def test_the_platform_intake_is_stored_on_the_home_organisations_chain_as_sent_when_it_has_no_key(tenancy, writer):
    request = rawpost.RawRequest(intake="edge_site_key", method="POST", path="/capture", query="", headers=(), body=b'{"a":1}')
    with tenancy.app() as app:
        stored = writer.write(app, lambda c: org_transaction(c, tenancy.token_for_home(("capture",))), request)
    assert stored.org_id == str(tenancy.home) and stored.encryption == "none"
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.home)):
        assert writer.read_body(app, tenancy.home, stored.post_id) == b'{"a":1}'


def test_a_path_with_a_character_the_database_cannot_hold_is_still_stored(tenancy, writer):
    request = rawpost.RawRequest(intake="api", method="GET", path="/a\x00b\ud800", query="", headers=(), body=b"")
    with tenancy.app() as app:
        stored = writer.write(app, lambda c: org_transaction(c, tenancy.token(tenancy.a)), request)
    assert stored.seq == 1


def test_a_single_company_writer_with_no_key_provider_or_store_keeps_the_bytes_as_sent_and_labels_the_row(conn, app_conn):
    writer = rawpost.RawPostWriter()
    body = os.urandom(rawpost.INLINE_LIMIT_BYTES * 3)
    request = rawpost.RawRequest(intake="api_single", method="POST", path="/v1/events", query="", headers=(("a", "b"),), body=body)
    stored = writer.write(app_conn, None, request)
    assert stored.encryption == "none" and stored.receipt["signature"] is None
    assert writer.read_body(app_conn, uuid.UUID(stored.org_id), stored.post_id) == body
    assert rawpost.verify_raw_chain(app_conn) == []


# receipts (T025) ----------------------------------------------------------------------------------------------------------

def test_the_receipt_names_the_post_its_fingerprint_and_its_chain_row_and_verifies_offline(tenancy, writer):
    body = b'{"checked": false}'
    stored = post(tenancy, writer, body)
    r = stored.receipt
    assert set(r) == {"org_id", "post_id", "seq", "row_hash", "received_at", "body_sha256", "signature"}
    assert r["body_sha256"] == hashlib.sha256(body).hexdigest() and r["seq"] == 1 and r["post_id"] == stored.post_id
    assert rawpost.verify_post_receipt(r, SIGNER.public_key, "rk1")
    assert stored.answer()["receipt"] == r and stored.answer()["stored"] is True


def test_a_changed_receipt_or_the_wrong_key_does_not_verify(tenancy, writer):
    r = post(tenancy, writer, b"x").receipt
    assert not rawpost.verify_post_receipt({**r, "seq": 2}, SIGNER.public_key, "rk1")
    assert not rawpost.verify_post_receipt({**r, "body_sha256": "0" * 64}, SIGNER.public_key, "rk1")
    assert not rawpost.verify_post_receipt(r, ReceiptSigner.generate(key_id="rk1").public_key, "rk1")
    assert not rawpost.verify_post_receipt(r, SIGNER.public_key, "other")
    assert not rawpost.verify_post_receipt({k: v for k, v in r.items() if k != "seq"}, SIGNER.public_key, "rk1")
