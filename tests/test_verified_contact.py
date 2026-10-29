"""A web-form grant shows that a box was ticked, not who owns the contact point, so it cannot lift a stop."""
import threading
import uuid

import psycopg
import pytest

from consentvault import db
from consentvault.capture import capture_and_release, capture_verified
from consentvault.errors import InvalidEventError
from consentvault.gate import may_contact
from consentvault.ledger import (compute_row_hash, contact_commitment, record_event, verify_chain)
from consentvault.release import release_after_grant

P = "+12125550101"


def _stop(conn, who=P):
    return record_event(conn, contact=who, event_type="revoke", channels=["sms"], purposes=["marketing"],
                        method="keyword", origin="consumer")


def _web_grant(conn, sha, **kw):
    return capture_and_release(conn, contact=P, checked=True, disclosure_sha256=sha, channels=["sms"],
                               purposes=["marketing"], session_ref="s1", **kw)


def test_a_web_grant_cannot_lift_the_contacts_own_stop(conn, disclosure):
    _stop(conn)
    grant, release, err = _web_grant(conn, disclosure)
    assert err is None
    assert release == {"released_channels": [], "refusals": {"contact_control_unverified": ["sms"]}}
    assert not may_contact(conn, P, "sms", "marketing").allowed
    row = conn.execute("SELECT release_outcome, release_cause FROM consentvault.event WHERE event_type = 'release'"
                       ).fetchone()
    assert (row["release_outcome"], row["release_cause"]) == ("refused", "contact_control_unverified")


def test_a_refused_release_opens_exactly_one_pending_review(conn, disclosure):
    _stop(conn)
    grant, _, _ = _web_grant(conn, disclosure)
    release_after_grant(conn, grant.event_id)  # deciding again changes nothing
    rows = conn.execute("SELECT kind, status, event_id::text AS event_id FROM consentvault.review").fetchall()
    assert [(r["kind"], r["status"], r["event_id"]) for r in rows] == [("release", "pending", grant.event_id)]


@pytest.mark.parametrize("how, message", [("otp", None), ("inbound_keyword", "START")])
def test_a_verified_grant_lifts_the_stop(conn, disclosure, how, message):
    _stop(conn)
    _, release, err = capture_verified(
        conn, verification=how, inbound_message=message, contact=P, disclosure_sha256=disclosure,
        channels=["sms"], purposes=["marketing"], session_ref="s1")
    assert err is None and release["released_channels"] == ["sms"]
    assert may_contact(conn, P, "sms", "marketing").allowed
    assert conn.execute("SELECT count(*) AS n FROM consentvault.review").fetchone()["n"] == 0


def test_the_database_refuses_a_released_row_for_an_unverified_grant(conn, app_conn, disclosure):
    _stop(conn)
    grant, _, _ = _web_grant(conn, disclosure)
    row = dict(_forged_release(app_conn, grant.event_id))
    assert row["error"], "the release insert trigger must refuse a lift on an unverified grant"
    assert not may_contact(conn, P, "sms", "marketing").allowed


def _forged_release(c, grant_event_id):
    """What a writer holding only INSERT could try: a hand-built, correctly hashed 'released' row."""
    head = c.execute("SELECT seq, row_hash FROM consentvault.event ORDER BY seq DESC LIMIT 1").fetchone()
    now = c.execute("SELECT clock_timestamp() AS n").fetchone()["n"]
    salt = c.execute("SELECT consentvault.mint_contact_salt(%s) AS s", (P,)).fetchone()["s"]
    v = dict(seq=head["seq"] + 1, event_id=uuid.uuid4(), subject_key="k" * 64, contact_kind="phone", contact_norm=P,
             contact_salt=salt, contact_commit=contact_commitment(salt, P), event_type="release", channels=["sms"],
             purposes=["marketing"], disclosure_sha256=None, method="checkbox", origin="consumer", captured_at=now,
             received_at=now, edge_received_at=None, page_url=None, client_ip=None, user_agent=None,
             session_ref=None, bot_check=None, payload_sha256=None, source=None, recorded_by=None,
             release_of_event_id=uuid.UUID(grant_event_id), release_outcome="released", release_cause=None,
             contact_verification="none", hash_version=1)
    rh = compute_row_hash(head["row_hash"], v, 1)
    cols = list(v) + ["prev_hash", "row_hash"]
    try:
        c.execute(f"INSERT INTO consentvault.event ({','.join(cols)}) VALUES ({','.join(['%s'] * len(cols))})",
                  list(v.values()) + [head["row_hash"], rh])
    except psycopg.Error as exc:
        c.rollback()
        return {"error": str(exc)}
    return {"error": None}


def test_contact_verification_is_part_of_the_row_hash(conn, disclosure):
    grant, _, _ = _web_grant(conn, disclosure)
    row = dict(conn.execute("SELECT * FROM consentvault.event WHERE event_id = %s::uuid", (grant.event_id,)).fetchone())
    assert compute_row_hash(row["prev_hash"], row, 1) == row["row_hash"]
    assert compute_row_hash(row["prev_hash"], {**row, "contact_verification": "otp"}, 1) != row["row_hash"]


def test_only_a_consumer_grant_can_claim_a_verified_contact(conn, disclosure):
    with pytest.raises(InvalidEventError):
        record_event(conn, contact=P, event_type="revoke", channels=["sms"], purposes=["marketing"],
                     method="keyword", origin="consumer", contact_verification="otp")
    with pytest.raises(InvalidEventError):
        record_event(conn, contact=P, event_type="grant", channels=["sms"], purposes=["marketing"], method="staff",
                     origin="staff", disclosure_sha256=disclosure, contact_verification="otp")
    with pytest.raises(InvalidEventError):
        record_event(conn, contact=P, event_type="grant", channels=["sms"], purposes=["marketing"],
                     method="checkbox", origin="consumer", disclosure_sha256=disclosure,
                     contact_verification="phone_call")


def test_the_table_refuses_a_verification_on_anything_but_a_grant(conn):
    salt = "c" * 64
    conn.execute("INSERT INTO consentvault.contact_salt (contact_norm, salt) VALUES (%s, decode(%s, 'hex'))", (P, salt))
    with pytest.raises(psycopg.errors.CheckViolation, match="event_verification_only_on_grant"):
        conn.execute(
            "INSERT INTO consentvault.event (seq, event_id, subject_key, contact_kind, contact_norm, contact_salt,"
            " contact_commit, event_type, channels, purposes, method, origin, captured_at, received_at,"
            " contact_verification, hash_version, prev_hash, row_hash)"
            " VALUES (1, gen_random_uuid(), 'k', 'phone', %s, %s, encode(sha256(convert_to(%s, 'UTF8')), 'hex'),"
            " 'revoke', ARRAY['sms'], ARRAY['marketing'], 'keyword', 'consumer', now(), now(), 'otp', 1,"
            " repeat('0', 64), repeat('b', 64))", (P, salt, salt + P))


def test_an_inbound_keyword_grant_needs_a_start_message(conn, disclosure):
    base = dict(contact=P, disclosure_sha256=disclosure, channels=["sms"], purposes=["marketing"], session_ref="s")
    for message in (None, "", "what is this", "STOP", "yes stop"):
        with pytest.raises(InvalidEventError):
            capture_verified(conn, verification="inbound_keyword", inbound_message=message, **base)
    with pytest.raises(InvalidEventError):
        capture_verified(conn, verification="otp", inbound_message="START", **base)
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0


# salt minting -------------------------------------------------------------------------------------------------

def test_the_runtime_role_cannot_plant_a_salt(app_conn):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app_conn.execute("INSERT INTO consentvault.contact_salt (contact_norm, salt) VALUES (%s, %s)", (P, b"\x00" * 32))
    assert app_conn.execute("SELECT count(*) AS n FROM consentvault.contact_salt").fetchone()["n"] == 0


def test_a_salt_is_minted_in_the_database_and_is_stable(app_conn):
    first = app_conn.execute("SELECT consentvault.mint_contact_salt(%s) AS s", (P,)).fetchone()["s"]
    again = app_conn.execute("SELECT consentvault.mint_contact_salt(%s) AS s", (P,)).fetchone()["s"]
    other = app_conn.execute("SELECT consentvault.mint_contact_salt(%s) AS s", ("+12125550102",)).fetchone()["s"]
    assert first == again and len(first) == 64 and first != other and first != "0" * 64


def test_the_app_role_cannot_pick_the_salt_the_function_mints(app_conn):
    with pytest.raises(psycopg.Error):
        app_conn.execute("SELECT consentvault.mint_contact_salt(%s, %s)", (P, "00" * 32))


def test_concurrent_first_events_for_one_contact_share_one_salt(app_dsn):
    errors = []

    def go():
        try:
            with db.connect(app_dsn) as c:
                record_event(c, contact="+12125550199", event_type="revoke", channels=["sms"],
                             purposes=["marketing"], method="keyword", origin="consumer")
        except Exception as exc:  # noqa: BLE001 - collected and asserted below
            errors.append(exc)

    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors, errors
    with db.connect(app_dsn) as c:
        row = c.execute("SELECT count(DISTINCT contact_salt) AS salts, count(*) AS n FROM consentvault.event").fetchone()
        assert (row["salts"], row["n"]) == (1, 8)
        assert verify_chain(c) == []
