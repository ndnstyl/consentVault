"""T021: the public login can run one function and read no table; the function returns only what the link's flags allow."""

import hashlib
import json

import psycopg
import pytest

from .conftest import mint_link

TABLES = ["event", "seal", "chain_head", "disclosure", "contact_key", "organization", "raw_post", "raw_post_field", "raw_post_key",
          "proof_share", "proof_share_revocation", "proof_share_view", "proof_share_daily_count", "proof_share_reset",
          "member", "credential", "audit_event"]
FORBIDDEN_KEYS = {"client_ip_ct", "user_agent_ct", "session_ref_ct", "contact_salt", "salt_ct", "attribution_ct", "subject_key_ct",
                  "headers_ct", "query_ct", "path_ct", "note", "created_by", "contact_norm"}


def test_the_login_reads_no_table(record, public_conn):
    for table in TABLES:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with public_conn.transaction():
                public_conn.execute(f"SELECT 1 FROM consentvault.{table} LIMIT 1")
    for sql in ("INSERT INTO consentvault.proof_share_view (org_id, share_id, kind) VALUES (gen_random_uuid(), gen_random_uuid(), 'page')",
                "UPDATE consentvault.proof_share SET note = 'x'", "DELETE FROM consentvault.proof_share"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with public_conn.transaction():
                public_conn.execute(sql)


def test_the_login_can_run_one_function_and_no_other(record, public_conn):
    rows = public_conn.execute(
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'consentvault'"
        " AND has_function_privilege(current_user, p.oid, 'EXECUTE') ORDER BY 1").fetchall()
    assert [r["proname"] for r in rows] == ["public_proof_view"]


def _digest(link_id):
    return hashlib.sha256(link_id.encode()).hexdigest()


def test_the_function_returns_only_the_allowed_columns(record, public_conn):
    made = mint_link(record)
    got = public_conn.execute("SELECT consentvault.public_proof_view(%s, 'page') AS r", (_digest(made["link_id"]),)).fetchone()["r"]
    assert got["status"] == "ok"
    text = json.dumps(got)
    for key in FORBIDDEN_KEYS:
        assert f'"{key}"' not in text, key
    material = got["material"]
    assert "contact_ct_hex" not in material and "page_url_ct_hex" not in material and "body_ct_hex" not in material
    assert material["event"]["row_hash"] and material["flags"]["show_contact"] is False


def test_flags_on_add_exactly_their_ciphertext(record, public_conn):
    from consentvault import share

    made = mint_link(record, flags={"show_contact": True, "show_page_url": True}, ack=share.CONTACT_ACK)
    material = public_conn.execute("SELECT consentvault.public_proof_view(%s, 'page') AS r",
                                   (_digest(made["link_id"]),)).fetchone()["r"]["material"]
    assert material["contact_ct_hex"] and material["page_url_ct_hex"] and material["body_ct_hex"]


def test_an_unknown_digest_returns_nothing_but_the_status(record, public_conn):
    got = public_conn.execute("SELECT consentvault.public_proof_view(%s, 'page') AS r", (_digest("cvp_nothere"),)).fetchone()["r"]
    assert got == {"status": "not_found"}
    got = public_conn.execute("SELECT consentvault.public_proof_view(%s, 'page') AS r", ("not even hex",)).fetchone()["r"]
    assert got == {"status": "not_found"}
