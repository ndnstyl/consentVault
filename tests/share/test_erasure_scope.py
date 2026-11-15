"""T003: what an erasure leaves readable, and what happens to a record link when its contact is erased.

The result of the first test is a fact about the product today, recorded here as an expected failure so it cannot be forgotten:
the contact's key is destroyed but the raw post keeps its own data key, so its body stays readable. The second test is the rule
this build adds: every link for the contact is withdrawn in the same transaction as the key delete."""

import uuid

import pytest

from consentvault import rawpost
from consentvault.tenancy.errors import FieldCryptoError
from consentvault.tenancy.tokens import org_transaction

from export.support import PHONE


def _erase(t, org, fp):
    with t.operator() as o, org_transaction(o, t.admin_token(org.org_id)):
        return o.execute("SELECT consentvault.erase_contact(%s) AS d", (fp,)).fetchone()["d"]


@pytest.mark.xfail(strict=True, reason="T003 result: erase_contact deletes the contact key only; the raw post keeps its own wrapped "
                   "data key, so the stored body is still readable after an erasure. Recorded as an open question for Mike; links "
                   "for the contact answer 410 regardless.")
def test_the_raw_post_body_is_unreadable_after_the_contact_key_is_destroyed(record):
    t = record
    fp = t.crypto.contact_fingerprint(t.a.org_id, "phone", PHONE)
    assert _erase(t, t.a, fp) is True
    writer = rawpost.RawPostWriter(crypto=t.crypto)
    with t.app() as app, org_transaction(app, t.token(t.a, ("proof_read",))):
        body = writer.read_body(app, t.a.org_id, t.record_post_id)
    assert PHONE not in body.decode()


def test_every_link_for_the_contact_is_withdrawn_when_the_contact_is_erased(record):
    from consentvault import share

    t = record
    fp = t.crypto.contact_fingerprint(t.a.org_id, "phone", PHONE)
    with t.app() as app, org_transaction(app, t.token(t.a, ("admin",))):
        first = share.mint(app, event_id=t.a.event_ids[0], actor="member:test", flags={}, note="one")
        second = share.mint(app, event_id=t.a.event_ids[0], actor="member:test", flags={}, note="two")
    assert _erase(t, t.a, fp) is True
    with t.superuser() as su:
        rows = su.execute("SELECT s.share_id, r.reason FROM consentvault.proof_share s JOIN consentvault.proof_share_revocation r"
                          " ON r.org_id = s.org_id AND r.share_id = s.share_id WHERE s.org_id = %s", (t.a.org_id,)).fetchall()
    assert {str(r["share_id"]) for r in rows} == {first["share_id"], second["share_id"]}
    assert {r["reason"] for r in rows} == {"erasure"}
