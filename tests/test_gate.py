from datetime import datetime, timedelta, timezone

import pytest

from consentvault import db
from consentvault.capture import capture
from consentvault.gate import may_contact, record_contact
from consentvault.ledger import record_event

PHONE = "+15555550101"


def _grant(conn, disclosure, **kw):
    return capture(conn, contact=PHONE, checked=True, disclosure_sha256=disclosure,
                   channels=kw.pop("channels", ["sms"]), purposes=kw.pop("purposes", ["marketing"]), **kw)


def _stop(conn, **kw):
    kw.setdefault("method", "keyword")
    kw.setdefault("origin", "consumer")
    return record_event(conn, contact=PHONE, event_type="suppress", channels=kw.pop("channels", ["sms"]),
                        purposes=kw.pop("purposes", ["marketing"]), **kw)


def test_no_consent_is_denied_with_reason(conn):
    d = may_contact(conn, PHONE, "sms", "marketing")
    assert d.allowed is False and d.reason == "no_consent_on_record" and d.basis_event_ids == ()


def test_grant_allows_and_names_basis(conn, disclosure):
    ev = _grant(conn, disclosure)
    d = may_contact(conn, PHONE, "sms", "marketing")
    assert d.allowed and d.reason == "granted" and d.basis_event_ids == (ev.event_id,)


def test_other_channel_or_purpose_denied(conn, disclosure):
    _grant(conn, disclosure)
    assert not may_contact(conn, PHONE, "voice", "marketing").allowed
    assert not may_contact(conn, PHONE, "sms", "billing").allowed


def test_stop_denies_and_names_both_events(conn, disclosure):
    g = _grant(conn, disclosure)
    s = _stop(conn)
    d = may_contact(conn, PHONE, "sms", "marketing")
    assert not d.allowed and d.reason == "stopped:suppress"
    assert set(d.basis_event_ids) == {g.event_id, s.event_id}


def test_formatting_of_contact_does_not_matter(conn, disclosure):
    _grant(conn, disclosure)
    assert may_contact(conn, "(555) 555-0101", "sms", "marketing", region="US").allowed


@pytest.mark.parametrize("contact,channel,purpose,reason", [
    ("not a number", "sms", "marketing", "invalid_contact"),
    (PHONE, "pigeon", "marketing", "invalid_channel"),
    (PHONE, "sms", "  ", "invalid_purpose"),
])
def test_bad_input_fails_closed(conn, contact, channel, purpose, reason):
    d = may_contact(conn, contact, channel, purpose)
    assert not d.allowed and d.reason.startswith(reason)


def test_database_down_fails_closed(dsn, disclosure_unused=None):
    c = db.connect(dsn)
    c.close()
    d = may_contact(c, PHONE, "sms", "marketing")
    assert d.allowed is False and d.reason.startswith("database_unreachable")


def test_record_contact_writes_log(conn):
    cid = record_contact(conn, PHONE, "sms", "delivered", "msg-1", purpose="marketing")
    row = conn.execute("SELECT * FROM consentvault.contact_log WHERE contact_log_id = %s", (cid,)).fetchone()
    assert row["contact_norm"] == PHONE and row["channel"] == "sms" and row["outcome"] == "delivered"
    assert row["ref"] == "msg-1"


def test_record_contact_rejects_bad_channel(conn):
    with pytest.raises(Exception):
        record_contact(conn, PHONE, "pigeon", "x", None)


def test_record_contact_honours_contacted_at(conn):
    when = datetime.now(timezone.utc) - timedelta(days=2)
    cid = record_contact(conn, PHONE, "sms", "sent", None, contacted_at=when)
    row = conn.execute("SELECT contacted_at FROM consentvault.contact_log WHERE contact_log_id = %s", (cid,)).fetchone()
    assert row["contacted_at"] == when
