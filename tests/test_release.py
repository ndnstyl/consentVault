import uuid
from datetime import datetime, timedelta, timezone

import pytest

from consentvault import disclosure as disc
from consentvault.errors import GrantScopeError, InvalidEventError
from consentvault.gate import may_contact, record_contact
from consentvault.ledger import record_event
from consentvault.release import release_after_grant

PHONE = "+15555550102"
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def at(days):
    return T0 + timedelta(days=days)


def ev(conn, event_type, days, *, channels=("sms",), purposes=("marketing",), method="checkbox", origin="consumer",
       disclosure=None, session_ref="sess-1", verification=None):
    if verification is None:
        verification = "otp" if event_type == "grant" and origin == "consumer" else "none"
    return record_event(
        conn, contact=PHONE, event_type=event_type, channels=list(channels), purposes=list(purposes),
        method=method, origin=origin, disclosure_sha256=disclosure, captured_at=at(days), session_ref=session_ref,
        contact_verification=verification,
    )


def stop(conn, days, **kw):
    kw.setdefault("method", "keyword")
    kw.setdefault("session_ref", None)
    return ev(conn, "suppress", days, **kw)


def allowed(conn, channel="sms"):
    return may_contact(conn, PHONE, channel, "marketing")


@pytest.fixture
def d_sms(conn):
    return disc.register(conn, "Texts from us. Reply STOP to end.", "f", "en", ["sms"], ["marketing"])


@pytest.fixture
def d_both(conn):
    return disc.register(conn, "Texts and calls from us.", "f2", "en", ["sms", "voice"], ["marketing"])


def test_consumer_stop_is_released_by_later_grant(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    assert not allowed(conn).allowed
    g = ev(conn, "grant", 2, disclosure=d_sms)
    assert not allowed(conn).allowed  # a grant alone never beats a stop
    res = release_after_grant(conn, g.event_id)
    assert res.released and res.released_channels == ("sms",) and not res.refusals
    d = allowed(conn)
    assert d.allowed and d.reason == "granted"
    row = conn.execute("SELECT * FROM consentvault.event WHERE event_id = %s::uuid", (res.event_ids[0],)).fetchone()
    assert row["event_type"] == "release" and row["hash_version"] == 1
    assert (str(row["release_of_event_id"]), row["release_outcome"], row["release_cause"]) == (g.event_id, "released", None)


def test_staff_stop_is_never_released(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1, method="staff", origin="staff")
    g = ev(conn, "grant", 2, disclosure=d_sms)
    res = release_after_grant(conn, g.event_id)
    assert not res.released and "stop_not_consumers_own" in res.refusals
    assert not allowed(conn).allowed


@pytest.mark.parametrize("method,origin", [("import", "import"), ("staff", "regulatory"), ("verbal", "consumer"),
                                            ("keyword", "regulatory"), ("checkbox", "staff")])
def test_regulatory_imported_and_other_stops_never_released(conn, d_sms, method, origin):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1, method=method, origin=origin)
    g = ev(conn, "grant", 2, disclosure=d_sms)
    res = release_after_grant(conn, g.event_id)
    assert not res.released and res.refusals
    assert not allowed(conn).allowed


def test_a_grant_cannot_name_a_channel_its_disclosure_does_not(conn, d_sms):
    with pytest.raises(GrantScopeError):
        ev(conn, "grant", 0, channels=("sms", "voice"), disclosure=d_sms)
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0


def test_release_does_not_touch_channel_it_did_not_name(conn, d_both):
    ev(conn, "grant", 0, channels=("sms", "voice"), disclosure=d_both)
    stop(conn, 1, channels=("sms", "voice"))
    g = ev(conn, "grant", 2, channels=("sms",), disclosure=d_both)
    release_after_grant(conn, g.event_id)
    assert allowed(conn, "sms").allowed
    assert not allowed(conn, "voice").allowed


def test_stop_after_release_suppresses_again(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    g = ev(conn, "grant", 2, disclosure=d_sms)
    release_after_grant(conn, g.event_id)
    assert allowed(conn).allowed
    stop(conn, 3)
    d = allowed(conn)
    assert not d.allowed and d.reason.startswith("stopped")


def test_second_stop_then_old_release_does_not_revive(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    g = ev(conn, "grant", 2, disclosure=d_sms)
    release_after_grant(conn, g.event_id)
    stop(conn, 3)
    again = release_after_grant(conn, g.event_id)  # idempotent: reads the existing decision
    assert again.released and not allowed(conn).allowed


def test_missing_session_ref_refused_and_logged(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    g = ev(conn, "grant", 2, disclosure=d_sms, session_ref=None)
    res = release_after_grant(conn, g.event_id)
    assert res.refusals == {"no_session_ref": ("sms",)}
    row = conn.execute("SELECT * FROM consentvault.event WHERE event_id = %s::uuid", (res.event_ids[0],)).fetchone()
    assert row["event_type"] == "release"
    assert (str(row["release_of_event_id"]), row["release_outcome"], row["release_cause"]) == (g.event_id, "refused", "no_session_ref")
    assert not allowed(conn).allowed


def test_refused_decision_never_lifts_a_stop(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1, method="staff", origin="staff")
    g = ev(conn, "grant", 2, disclosure=d_sms)
    release_after_grant(conn, g.event_id)
    row = conn.execute("SELECT reason FROM consentvault.current_permission WHERE channel = 'sms'").fetchone()
    assert row["reason"] == "stopped:suppress"


def test_release_without_explicit_columns_is_refused_at_write(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    with pytest.raises(InvalidEventError):
        record_event(conn, contact=PHONE, event_type="release", channels=["sms"], purposes=["marketing"],
                     method="checkbox", origin="consumer", captured_at=at(2), source="release:released:x")
    assert not allowed(conn).allowed


def test_refused_release_row_never_lifts_a_stop(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    g = ev(conn, "grant", 2, disclosure=d_sms)
    record_event(conn, contact=PHONE, event_type="release", channels=["sms"], purposes=["marketing"],
                 method="checkbox", origin="consumer", captured_at=at(2), release_of_event_id=g.event_id,
                 release_outcome="refused", release_cause="no_session_ref")
    assert not allowed(conn).allowed


def test_release_columns_refused_on_a_non_release_event(conn, d_sms):
    with pytest.raises(InvalidEventError):
        record_event(conn, contact=PHONE, event_type="grant", channels=["sms"], purposes=["marketing"],
                     method="checkbox", origin="consumer", disclosure_sha256=d_sms, release_outcome="released")


def test_no_prior_stop_writes_nothing(conn, d_sms):
    g = ev(conn, "grant", 0, disclosure=d_sms)
    res = release_after_grant(conn, g.event_id)
    assert not res.released and not res.refusals and res.event_ids == ()
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type = 'release'").fetchone()["n"] == 0


def test_require_no_contact_since_stop(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    record_contact(conn, PHONE, "sms", "sent", "m1", purpose="marketing")
    g = ev(conn, "grant", 2, disclosure=d_sms)
    res = release_after_grant(conn, g.event_id, require_no_contact_since_stop=True)
    assert res.refusals == {"contact_since_stop": ("sms",)}
    assert not allowed(conn).allowed


def test_contact_check_off_by_default(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    record_contact(conn, PHONE, "sms", "sent", "m1")
    g = ev(conn, "grant", 2, disclosure=d_sms)
    assert release_after_grant(conn, g.event_id).released


def test_quiet_since_stop_releases(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    record_contact(conn, PHONE, "sms", "sent", "m1")  # before the stop
    stop(conn, 1)
    g = ev(conn, "grant", 2, disclosure=d_sms)
    assert release_after_grant(conn, g.event_id, require_no_contact_since_stop=True).released


def test_env_flag_enables_contact_check(conn, d_sms, monkeypatch):
    monkeypatch.setenv("CONSENTVAULT_RELEASE_REQUIRE_NO_CONTACT_SINCE_STOP", "1")
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    record_contact(conn, PHONE, "sms", "sent", None)
    g = ev(conn, "grant", 2, disclosure=d_sms)
    assert not release_after_grant(conn, g.event_id).released


def test_grant_from_staff_refused(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    g = ev(conn, "grant", 2, disclosure=d_sms, method="staff", origin="staff")
    res = release_after_grant(conn, g.event_id)
    assert "grant_not_from_consumer" in res.refusals and not allowed(conn).allowed
    assert res.event_ids == ()  # a release row decides only a consumer grant, so nothing is stored for this one


def test_stop_by_other_purpose_not_released_by_unrelated_grant(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1, purposes=("billing",))
    g = ev(conn, "grant", 2, disclosure=d_sms)
    res = release_after_grant(conn, g.event_id)
    assert not res.released and res.event_ids == ()


def test_rejects_non_grant_and_unknown_event(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    s = stop(conn, 1)
    with pytest.raises(InvalidEventError):
        release_after_grant(conn, s.event_id)
    with pytest.raises(InvalidEventError):
        release_after_grant(conn, "00000000-0000-0000-0000-000000000000")


def test_chain_still_verifies_with_release_events(conn, d_sms):
    from consentvault.ledger import verify_chain

    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1)
    g = ev(conn, "grant", 2, disclosure=d_sms)
    release_after_grant(conn, g.event_id)
    assert verify_chain(conn) == []


def test_database_down_fails_closed_after_release(dsn, d_sms=None):
    from consentvault import db

    c = db.connect(dsn)
    c.close()
    d = may_contact(c, PHONE, "sms", "marketing")
    assert not d.allowed and d.reason.startswith("database_unreachable")


def test_a_stop_for_every_purpose_is_released_only_for_the_purpose_the_grant_names(conn, d_sms):
    ev(conn, "grant", 0, disclosure=d_sms)
    stop(conn, 1, purposes=("*",))
    g = ev(conn, "grant", 2, disclosure=d_sms)
    assert not allowed(conn).allowed
    assert release_after_grant(conn, g.event_id).released
    assert allowed(conn).allowed
