"""The raw post store's schema: insert-only, one chain per organisation, the database's clock, exactly one body, and no
check on anything a sender posted (migration 0067, data-model.md section 1)."""

import hashlib
import os
import uuid
from pathlib import Path

import psycopg
import pytest

from consentvault import rawpost
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy.pipeline import ReceiptSigner
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy  # noqa: F401  (documented: the suite's two-organisation harness)

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"
TABLES = ("raw_post", "raw_post_key", "raw_post_chain_head", "raw_post_fact", "form_field_map", "raw_post_field",
          "raw_post_match", "raw_post_seal", "event_source_post")


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def writer(tenancy, tmp_path):
    return rawpost.RawPostWriter(crypto=tenancy.crypto, store=LocalAppendOnlyEvidenceStore(str(tmp_path / "ev")),
                                 receipts=ReceiptSigner.generate(key_id="k1"))


def req(body=b'{"checked": false}', **kw):
    return rawpost.RawRequest(intake="api", method="POST", path="/v1/events", query="", headers=(("content-type", "application/json"),),
                              body=body, **kw)


def store(tenancy, writer, org, request=None):
    with tenancy.app() as app:
        return writer.write(app, lambda c: org_transaction(c, tenancy.token(org)), request or req())


def test_every_new_table_is_in_the_schema_with_row_security_forced(tenancy):
    with tenancy.superuser() as su:
        rows = {r["relname"]: r for r in su.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = 'consentvault' AND relname = ANY(%s)", (list(TABLES),)).fetchall()}
    assert set(rows) == set(TABLES)
    assert all(r["relrowsecurity"] and r["relforcerowsecurity"] for r in rows.values())


def test_the_posts_of_one_organisation_are_chained_from_one_and_the_other_organisation_has_its_own_chain(tenancy, writer):
    a1, a2, a3 = (store(tenancy, writer, tenancy.a) for _ in range(3))
    b1 = store(tenancy, writer, tenancy.b)
    assert [a1.seq, a2.seq, a3.seq, b1.seq] == [1, 2, 3, 1]
    assert a2.prev_hash == a1.row_hash and a3.prev_hash == a2.row_hash and b1.prev_hash == "0" * 64
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        assert rawpost.verify_raw_chain(app) == []


def test_raw_post_rows_are_insert_only_even_for_the_superuser(tenancy, writer):
    store(tenancy, writer, tenancy.a, req(facts=(rawpost.Fact("vault", "origin_header", "https://x.example"),)))
    with tenancy.operator() as op, org_transaction(op, tenancy.admin_token(tenancy.a.org_id)):
        op.execute("INSERT INTO consentvault.form_field_map (org_id, map_version, body_format, consent_paths, set_by)"
                   " VALUES (%s, 1, 'json', ARRAY['/checked'], 'test')", (tenancy.a.org_id,))
    with tenancy.superuser() as su:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
            su.execute("UPDATE consentvault.raw_post SET kind = 'preflight'")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
            su.execute("DELETE FROM consentvault.raw_post")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
            su.execute("TRUNCATE consentvault.raw_post_chain_head")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
            su.execute("UPDATE consentvault.raw_post_fact SET name = 'x'")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
            su.execute("DELETE FROM consentvault.form_field_map")


def test_the_runtime_role_holds_no_update_or_delete_on_a_post(tenancy, writer):
    store(tenancy, writer, tenancy.a)
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("UPDATE consentvault.raw_post SET kind = 'preflight'")


def test_a_row_that_does_not_extend_the_head_is_refused(tenancy, writer):
    first = store(tenancy, writer, tenancy.a)
    bad = dict(org_id=tenancy.a.org_id, post_id=uuid.uuid4(), seq=5, prev_hash=first.row_hash)
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="does not extend"):
            _raw_insert(app, **bad)


def test_the_first_post_must_have_seq_one_and_the_genesis_hash(tenancy):
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="first post"):
            _raw_insert(app, org_id=tenancy.a.org_id, post_id=uuid.uuid4(), seq=2, prev_hash="0" * 64)


def test_a_tampered_row_breaks_chain_verification(tenancy, writer):
    store(tenancy, writer, tenancy.a)
    second = store(tenancy, writer, tenancy.a)
    with tenancy.superuser() as su:
        su.execute("ALTER TABLE consentvault.raw_post DISABLE TRIGGER raw_post_append_only")
        su.execute("UPDATE consentvault.raw_post SET body_bytes = body_bytes + 1 WHERE post_id = %s", (uuid.UUID(second.post_id),))
        su.execute("ALTER TABLE consentvault.raw_post ENABLE TRIGGER raw_post_append_only")
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        broken = rawpost.verify_raw_chain(app)
    assert [b["seq"] for b in broken] == [2] and "recompute" in broken[0]["reason"]


def test_received_at_is_the_databases_own_clock(tenancy):
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="receipt time"):
            _raw_insert(app, org_id=tenancy.a.org_id, post_id=uuid.uuid4(), seq=1, prev_hash="0" * 64,
                        received_at="now() - interval '2 hours'")


def test_exactly_one_of_the_inline_body_and_the_object_is_set(tenancy):
    for body_ct, obj in ((None, None), (b"x", uuid.uuid4())):
        with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
            with pytest.raises(psycopg.errors.CheckViolation, match="raw_post_one_body"):
                _raw_insert(app, org_id=tenancy.a.org_id, post_id=uuid.uuid4(), seq=1, prev_hash="0" * 64,
                            body_ct=body_ct, body_object_id=obj)


def test_there_is_no_other_check_on_raw_post_than_ids_hashes_and_the_one_body_rule(tenancy):
    with tenancy.superuser() as su:
        checks = {r["conname"]: r["def"] for r in su.execute(
            "SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint"
            " WHERE conrelid = 'consentvault.raw_post'::regclass AND contype = 'c'").fetchall()}
    text = " ".join(checks.values())
    for column in ("intake", "method", "path", "kind", "headers_presented_by", "unusual_size"):
        assert column not in text.replace("body_bytes", "").replace("unusual", ""), f"a check names {column}"
    assert len(checks) == 9  # seq, body_bytes, body_sha256, prev_hash, row_hash, hash_version, one body, the two digests' shapes


def test_an_organisation_cannot_read_or_write_the_others_posts(tenancy, writer):
    store(tenancy, writer, tenancy.a)
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.b.org_id)):
        assert app.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"] == 0
        with pytest.raises((psycopg.errors.InsufficientPrivilege, psycopg.errors.IntegrityConstraintViolation)):
            _raw_insert(app, org_id=tenancy.a.org_id, post_id=uuid.uuid4(), seq=2, prev_hash="a" * 64)


def test_a_capture_token_writes_but_cannot_read_a_post_back(tenancy, writer):
    store(tenancy, writer, tenancy.a)
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a, ("capture",))):
        assert app.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"] == 0


def test_a_key_row_is_deleted_only_by_the_erasure_function_and_the_post_stays(tenancy, writer):
    first = store(tenancy, writer, tenancy.a)
    with tenancy.superuser() as su:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="erase_raw_post_key"):
            su.execute("DELETE FROM consentvault.raw_post_key")
    with tenancy.operator() as op, org_transaction(op, tenancy.admin_token(tenancy.a.org_id)):
        assert op.execute("SELECT consentvault.erase_raw_post_key(%s) AS gone", (uuid.UUID(first.post_id),)).fetchone()["gone"]
        assert op.execute("SELECT count(*) AS n FROM consentvault.raw_post_key").fetchone()["n"] == 0
        assert op.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"] == 1
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        assert rawpost.verify_raw_chain(app) == []  # the chain does not depend on the key


def test_the_0067_down_migration_refuses_while_posts_exist_and_round_trips_when_empty(tenancy, writer, conn):
    down = (MIGRATIONS / "down" / "0067_raw_post.sql").read_text()
    up = (MIGRATIONS / "0067_raw_post.sql").read_text()
    store(tenancy, writer, tenancy.a)
    with tenancy.superuser() as su:
        with pytest.raises(psycopg.errors.RaiseException, match="refused"):
            su.execute(down)
        su.execute("ROLLBACK")


def test_the_0067_down_migration_leaves_nothing_behind_on_an_empty_vault(dsn, super_dsn, conn):
    down = (MIGRATIONS / "down" / "0067_raw_post.sql").read_text()
    with psycopg.connect(super_dsn, autocommit=True) as su:
        su.execute(down)
        assert su.execute("SELECT to_regclass('consentvault.raw_post')").fetchone()[0] is None
        assert su.execute("SELECT to_regprocedure('consentvault.raw_post_head()')").fetchone()[0] is None


def _raw_insert(app, *, org_id, post_id, seq, prev_hash, body_ct=b"x", body_object_id=None, received_at="clock_timestamp()"):
    sql = ("INSERT INTO consentvault.raw_post (org_id, post_id, seq, intake, received_at, method, path, path_ct, query_ct, headers_ct,"
           " body_ct, body_object_id, body_object_sha256, facts_sha256, body_bytes, body_sha256, unusual_size,"
           " headers_presented_by, kind, encryption, prev_hash, row_hash, hash_version)"
           f" VALUES (%s, %s, %s, 'api', {received_at}, 'POST', '/', %s, %s, %s, %s, %s, %s, %s, 1, %s,"
           " false, 'vault-http', 'post', 'none', %s, %s, 3)")
    app.execute(sql, (org_id, post_id, seq, b"/", b"", b"", body_ct, body_object_id, "c" * 64 if body_object_id else None, "d" * 64,
                      "b" * 64, prev_hash, hashlib.sha256(os.urandom(8)).hexdigest()))
