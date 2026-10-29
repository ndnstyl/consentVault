from datetime import datetime, timedelta, timezone

import pytest

from consentvault import disclosure as disclosure_mod
from consentvault.capture import capture
from consentvault.ledger import record_event
from consentvault.proof import lookup

PHONE = "+15550100"
PHONE_A = "+12125550101"
EMAIL = "person@example.com"


def _t(minutes):
    return datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minutes)


def test_consented_person_with_no_stop_is_allowed(conn, disclosure):
    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"], captured_at=_t(0))
    res = lookup(conn, PHONE_A)
    assert res["found"] is True
    perms = {(p["channel"], p["purpose"]): p for p in res["permissions"]}
    assert perms[("sms", "marketing")]["allowed"] is True
    assert [e["event_type"] for e in res["timeline"]] == ["grant"]
    assert res["timeline"][0]["seal_status"] == "unsealed"


def test_unknown_contact_says_no_record_after_reading_every_table(conn):
    res = lookup(conn, "+12125550199")
    assert res["found"] is False
    assert res["timeline"] == [] and res["permissions"] == []
    assert "No record" in res["message"]
    assert set(res["tables_read"]) == {"event", "seal", "disclosure", "contact_log", "review", "chain_head"}
    for table in ("event", "seal", "disclosure", "contact_log", "review", "chain_head"):
        assert table in res["message"]


def test_timeline_is_in_the_order_the_vault_received_events(conn, disclosure):
    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"], captured_at=_t(10))
    record_event(conn, contact=PHONE_A, event_type="revoke", channels=["sms"], purposes=["marketing"],
                 method="keyword", origin="consumer", captured_at=_t(20))
    # claims an earlier capture time but arrived last: it stays last, and the stop stays in force
    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"], captured_at=_t(5), contact_verification="otp")
    res = lookup(conn, PHONE_A)
    assert [e["event_type"] for e in res["timeline"]] == ["grant", "revoke", "grant"]
    assert [e["seq"] for e in res["timeline"]] == [1, 2, 3]
    perm = res["permissions"][0]
    assert perm["allowed"] is False and perm["reason"] == "stopped:revoke"
    record_event(conn, contact=PHONE_A, event_type="release", channels=["sms"], purposes=["marketing"],
                 method="checkbox", origin="consumer", captured_at=_t(30),
                 release_of_event_id=res["timeline"][2]["event_id"], release_outcome="released")
    res = lookup(conn, PHONE_A)
    assert res["permissions"][0]["allowed"] is True
    assert res["timeline"][-1]["event_type"] == "release"


def test_email_and_subject_key_find_the_same_person(conn):
    disclosure = disclosure_mod.register(conn, "Email us.", "e", "en", ["email"], ["marketing"])
    ev = capture(conn, contact=EMAIL.upper(), checked=True, disclosure_sha256=disclosure,
                 channels=["email"], purposes=["marketing"], subject_key="subject-1")
    by_email = lookup(conn, EMAIL)
    by_key = lookup(conn, "subject-1")
    assert by_email["found"] and by_key["found"]
    assert by_email["timeline"] == by_key["timeline"]
    assert by_email["timeline"][0]["event_id"] == ev.event_id


def test_subject_key_links_phone_and_email_events(conn, disclosure):
    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"], subject_key="person-9")
    record_event(conn, contact=EMAIL, event_type="suppress", channels=["email"], purposes=["marketing"],
                 method="staff", origin="staff", subject_key="person-9")
    res = lookup(conn, PHONE_A)
    assert {e["contact_kind"] for e in res["timeline"]} == {"phone", "email"}
    assert len(res["contacts"]) == 2


def test_chain_proof_reaches_the_head(conn, disclosure):
    first = capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure,
                    channels=["sms"], purposes=["marketing"])
    other = None
    for i in range(3):
        other = capture(conn, contact=f"+1212555020{i}", checked=True, disclosure_sha256=disclosure,
                        channels=["sms"], purposes=["marketing"])
    res = lookup(conn, PHONE_A)
    chain = res["chain"]
    assert chain["head"]["row_hash"] == other.row_hash
    assert chain["events"][first.event_id]["row_hash"] == first.row_hash
    assert chain["path"][0]["row_hash"] == first.row_hash
    assert chain["path"][-1]["row_hash"] == other.row_hash
    assert len(chain["path"]) == 4


def test_empty_query_is_refused(conn):
    from consentvault.errors import ConsentVaultError

    with pytest.raises(ConsentVaultError):
        lookup(conn, "  ")


def test_lookup_result_is_json_serialisable_and_stable(conn, disclosure):
    from consentvault.proof import canonical_dumps

    capture(conn, contact=PHONE_A, checked=True, disclosure_sha256=disclosure,
            channels=["sms"], purposes=["marketing"])
    assert canonical_dumps(lookup(conn, PHONE_A)) == canonical_dumps(lookup(conn, PHONE_A))
