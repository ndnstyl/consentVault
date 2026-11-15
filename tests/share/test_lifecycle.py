"""T023: a withdrawal adds a row and changes none; a withdrawn link answers 410; erasure withdraws every link for the contact in
its own transaction; a lapsed organisation's links still read; withdrawing twice is one fact."""

import psycopg
import pytest

from consentvault import share
from consentvault.tenancy.tokens import org_transaction

from export.support import PHONE

from .conftest import admin, get, mint_link


def test_withdrawal_adds_a_row_and_changes_none(record, routes):
    made = mint_link(record)
    assert get(routes, made["link_id"]).status == 200
    with record.superuser() as su:
        before = su.execute("SELECT * FROM consentvault.proof_share WHERE share_id = %s", (made["share_id"],)).fetchone()
    with admin(record) as app:
        out = share.revoke(app, made["share_id"], actor="member:test")
    assert out["revoked"] is True
    with record.superuser() as su:
        after = su.execute("SELECT * FROM consentvault.proof_share WHERE share_id = %s", (made["share_id"],)).fetchone()
        revs = su.execute("SELECT * FROM consentvault.proof_share_revocation WHERE share_id = %s", (made["share_id"],)).fetchall()
        assert after == before and len(revs) == 1 and revs[0]["reason"] == "sender"
        for sql in ("UPDATE consentvault.proof_share SET note = 'x'", "DELETE FROM consentvault.proof_share",
                    "UPDATE consentvault.proof_share_revocation SET reason = 'sender'",
                    "DELETE FROM consentvault.proof_share_revocation", "TRUNCATE consentvault.proof_share_view"):
            with pytest.raises(psycopg.Error):
                with su.transaction():
                    su.execute(sql)
    for suffix, method in (("", "GET"), (".json", "GET"), ("/record.zip", "GET"), ("/match", "POST")):
        r = get(routes, made["link_id"], suffix, method=method, body=b'{"contact": "x"}')
        assert r.status == 410 and b"withdrawn by the sender" in (r.raw or str(r.payload).encode())


def test_withdrawing_twice_is_one_fact(record):
    made = mint_link(record)
    with admin(record) as app:
        first = share.revoke(app, made["share_id"], actor="member:test")
        second = share.revoke(app, made["share_id"], actor="member:test")
    assert first["revoked"] is True and second["revoked"] is False
    with record.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.proof_share_revocation WHERE share_id = %s",
                          (made["share_id"],)).fetchone()["n"] == 1


def test_erasure_withdraws_every_link_for_the_contact_and_the_page_answers_410(record, routes):
    t = record
    one, two = mint_link(t), mint_link(t)
    other = mint_link(t, event_id=t.a.event_ids[2])  # the other contact's grant: untouched by this erasure
    fp = t.crypto.contact_fingerprint(t.a.org_id, "phone", PHONE)
    with t.operator() as o, org_transaction(o, t.admin_token(t.a.org_id)):
        o.execute("SELECT consentvault.erase_contact(%s)", (fp,))
    for made in (one, two):
        assert get(routes, made["link_id"]).status == 410
    assert get(routes, other["link_id"]).status == 200
    with t.superuser() as su:
        reasons = {r["reason"] for r in su.execute("SELECT reason FROM consentvault.proof_share_revocation").fetchall()}
    assert reasons == {"erasure"}


def test_a_failed_erasure_withdraws_nothing(record):
    t = record
    made = mint_link(t)
    fp = t.crypto.contact_fingerprint(t.a.org_id, "phone", PHONE)
    with pytest.raises(psycopg.Error):
        with t.operator() as o, org_transaction(o, t.token(t.a, ("capture",))):  # no admin scope: the erase is refused
            o.execute("SELECT consentvault.erase_contact(%s)", (fp,))
    with t.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.proof_share_revocation WHERE share_id = %s",
                          (made["share_id"],)).fetchone()["n"] == 0


def test_a_lapsed_organisation_still_reads(record, routes):
    made = mint_link(record)
    with record.superuser() as su:
        su.execute("UPDATE consentvault.organization SET status = 'suspended' WHERE org_id = %s", (record.a.org_id,))
        assert su.execute("SELECT status FROM consentvault.organization WHERE org_id = %s", (record.a.org_id,)).fetchone()["status"] == "suspended"
    assert get(routes, made["link_id"]).status == 200
