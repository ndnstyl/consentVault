"""A stop is lifted only by the person: a later consent post from them on the same contact point (the ruling that nobody else
consents, refuses or lifts). The lift is a link from the stop to the post; no admin, operator, customer, staff member,
connector or review queue can write one, and a text, START included, lifts nothing."""

import pathlib
import re
import uuid

import psycopg
import pytest

from consentvault import extract, gate, lift, rawpost
from consentvault.errors import InvalidEventError, LedgerError
from consentvault.ledger import record_event, record_tenant_event
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy.pipeline import ReceiptSigner
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import PHONE, build_tenancy

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "consentvault"
SCOPES = ("capture", "gate_read")


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])  # each organisation holds a grant and then a stop for PHONE


@pytest.fixture
def writer(tenancy, tmp_path):
    return rawpost.RawPostWriter(crypto=tenancy.crypto, store=LocalAppendOnlyEvidenceStore(str(tmp_path / "ev")),
                                 receipts=ReceiptSigner.generate(key_id="k1"))


def _post(tenancy, writer, org, *, contact=PHONE, consent: bytes | None = b"true", intake="api", body=b'{"checked": true}',
          state=extract.SENT, values=None, match=True):
    """A stored post, its reading of the consent box and (like the matcher) its link to a contact point."""
    req = rawpost.RawRequest(intake=intake, method="POST", path="/v1/events", query="",
                             headers=(("content-type", "application/json"),), body=body)
    token = tenancy.token(org, scopes=SCOPES)
    with tenancy.app() as app:
        stored = writer.write(app, lambda c: org_transaction(c, token), req)
        reading = extract.Reading("consent", state, tuple(values if values is not None else ([consent] if consent else [])))
        extract.write_readings(app, lambda c: org_transaction(c, token), org=org.org_id, post_id=stored.post_id, map_version=0,
                               readings=[reading], data_key=stored.data_key)
        if match:
            fp = tenancy.crypto.contact_fingerprint(org.org_id, "phone", contact)
            with org_transaction(app, token):
                app.execute("INSERT INTO consentvault.raw_post_match (org_id, post_id, match_id, map_version, status, contact_kind,"
                            " contact_fp) VALUES (%s, %s, %s, 0, 'matched', 'phone', %s)",
                            (org.org_id, stored.post_id, uuid.uuid4(), fp))
    return stored


def _lift(tenancy, writer, org, stored, ticked="true"):
    with tenancy.app() as app, org_transaction(app, tenancy.token(org, scopes=SCOPES)):
        return lift.lift_stops_for_post(app, writer, org=org.org_id, post_id=stored.post_id, ticked_value=ticked)


def _facts(tenancy, org, contact=PHONE):
    fp = tenancy.crypto.contact_fingerprint(org.org_id, "phone", contact)
    with tenancy.app() as app, org_transaction(app, tenancy.token(org, scopes=SCOPES)):
        return gate.tenant_facts(app, "phone", fp)


def test_a_later_post_carrying_the_ticked_value_lifts_the_stop_and_the_stop_stays_on_the_record(tenancy, writer):
    org = tenancy.a
    stop_id = org.event_ids[1]
    before = _facts(tenancy, org)
    assert [s["lifted_by_post_ids"] for s in before.stops] == [[]]
    stored = _post(tenancy, writer, org)
    res = _lift(tenancy, writer, org, stored)
    assert res.linked == (stop_id,) and res.reason is None
    after = _facts(tenancy, org)
    assert after.event_ids == before.event_ids  # the stop is still a line of the history; nothing was added or removed
    assert after.stops[0]["lifted_by_post_ids"] == [stored.post_id]
    assert [(x["stop_event_id"], x["lifting_post_id"]) for x in after.lifts] == [(stop_id, stored.post_id)]


def test_the_lift_is_idempotent(tenancy, writer):
    stored = _post(tenancy, writer, tenancy.a)
    first = _lift(tenancy, writer, tenancy.a, stored)
    second = _lift(tenancy, writer, tenancy.a, stored)
    assert first.linked and second.linked == () and second.already == first.linked
    assert len(_facts(tenancy, tenancy.a).lifts) == 1


@pytest.mark.parametrize("consent,values,state,why", [
    (b"false", None, extract.SENT, lift.SKIP_DIFFERENT_VALUE),
    (b'"on"', None, extract.SENT, lift.SKIP_DIFFERENT_VALUE),
    (b"TRUE", None, extract.SENT, lift.SKIP_DIFFERENT_VALUE),  # bytes are compared, never read for meaning
    (None, [], extract.NOT_SENT, lift.SKIP_NOT_ONE_VALUE),
    (None, [b"true", b"true"], extract.MANY, lift.SKIP_NOT_ONE_VALUE),
])
def test_only_the_exact_ticked_value_lifts(tenancy, writer, consent, values, state, why):
    stored = _post(tenancy, writer, tenancy.a, consent=consent, values=values, state=state)
    res = _lift(tenancy, writer, tenancy.a, stored)
    assert res.linked == () and res.reason == why
    assert _facts(tenancy, tenancy.a).lifts == ()


def test_a_form_whose_map_names_no_ticked_value_lifts_nothing(tenancy, writer):
    res = _lift(tenancy, writer, tenancy.a, _post(tenancy, writer, tenancy.a), ticked=None)
    assert res.linked == () and res.reason == lift.SKIP_NO_TICKED_VALUE


def test_a_text_reply_lifts_nothing_whatever_it_says(tenancy, writer):
    for text in (b"START", b"YES", b"UNSTOP", b'{"checked": true}'):
        stored = _post(tenancy, writer, tenancy.a, intake="sms_reply", body=text, consent=None, state=extract.NOT_SENT, values=[])
        res = _lift(tenancy, writer, tenancy.a, stored)
        assert res.linked == () and res.reason == lift.SKIP_NOT_ONE_VALUE
    assert _facts(tenancy, tenancy.a).lifts == ()


def test_a_post_not_matched_to_a_contact_point_lifts_nothing(tenancy, writer):
    res = _lift(tenancy, writer, tenancy.a, _post(tenancy, writer, tenancy.a, match=False))
    assert res.linked == () and res.reason == lift.SKIP_NO_MATCH


def test_a_post_from_another_person_lifts_nothing_for_this_contact_point(tenancy, writer):
    other = "+15555550177"
    res = _lift(tenancy, writer, tenancy.a, _post(tenancy, writer, tenancy.a, contact=other))
    assert res.linked == () and res.reason == lift.SKIP_NO_STOP
    assert _facts(tenancy, tenancy.a).stops[0]["lifted_by_post_ids"] == []


def test_a_post_in_another_organisation_lifts_nothing_here(tenancy, writer):
    stored = _post(tenancy, writer, tenancy.b)
    assert _lift(tenancy, writer, tenancy.b, stored).linked == (tenancy.b.event_ids[1],)
    assert _facts(tenancy, tenancy.a).lifts == ()


def test_a_stop_after_the_lifting_post_is_not_lifted_by_it(tenancy, writer):
    org = tenancy.a
    stored = _post(tenancy, writer, org)
    with tenancy.app() as app, org_transaction(app, tenancy.token(org, scopes=SCOPES)):
        later = record_tenant_event(app, tenancy.crypto, contact=PHONE, event_type="suppress", channels=["sms"],
                                    purposes=["marketing"], method="keyword", origin="consumer")
    res = _lift(tenancy, writer, org, stored)
    assert res.linked == (org.event_ids[1],) and later.event_id not in res.linked
    stops = {s["event_id"]: s["lifted_by_post_ids"] for s in _facts(tenancy, org).stops}
    assert stops[later.event_id] == []


# the database refuses every lift that is not a later matched post, from any caller --------------------------------------------

def _insert_lift(conn, org, stop_event_id, post_id, fp):
    conn.execute("INSERT INTO consentvault.stop_lift (org_id, stop_event_id, lifting_post_id, contact_fp) VALUES (%s, %s, %s, %s)",
                 (org.org_id, stop_event_id, post_id, fp))


def test_the_database_refuses_a_lift_by_a_post_not_matched_to_the_stops_contact_point(tenancy, writer):
    org = tenancy.a
    stored = _post(tenancy, writer, org, match=False)
    fp = tenancy.crypto.contact_fingerprint(org.org_id, "phone", PHONE)
    with tenancy.app() as app, org_transaction(app, tenancy.token(org, scopes=SCOPES)):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="not matched to the same contact point"):
            _insert_lift(app, org, org.event_ids[1], stored.post_id, fp)


def test_the_database_refuses_a_lift_of_something_that_is_not_a_stop(tenancy, writer):
    org = tenancy.a
    stored = _post(tenancy, writer, org)
    fp = tenancy.crypto.contact_fingerprint(org.org_id, "phone", PHONE)
    with tenancy.app() as app, org_transaction(app, tenancy.token(org, scopes=SCOPES)):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="not a stop of this contact point"):
            _insert_lift(app, org, org.event_ids[0], stored.post_id, fp)  # the grant


def test_the_database_refuses_a_lift_by_a_post_that_arrived_before_the_stop(tenancy, writer):
    org = tenancy.a
    early = _post(tenancy, writer, org)
    fp = tenancy.crypto.contact_fingerprint(org.org_id, "phone", PHONE)
    with tenancy.app() as app, org_transaction(app, tenancy.token(org, scopes=SCOPES)):
        later_stop = record_tenant_event(app, tenancy.crypto, contact=PHONE, event_type="revoke", channels=["sms"],
                                         purposes=["marketing"], method="keyword", origin="consumer")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="did not arrive after the stop"):
            _insert_lift(app, org, later_stop.event_id, early.post_id, fp)


@pytest.mark.parametrize("sql", ["UPDATE consentvault.stop_lift SET contact_fp = repeat('a', 64)",
                                 "DELETE FROM consentvault.stop_lift", "TRUNCATE consentvault.stop_lift"])
def test_a_lift_is_never_changed_or_removed_not_even_by_the_superuser(tenancy, writer, sql):
    _lift(tenancy, writer, tenancy.a, _post(tenancy, writer, tenancy.a))
    with tenancy.superuser() as su, pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
        su.execute(sql)


def test_the_operator_console_and_other_organisations_cannot_write_a_lift(tenancy, writer):
    org = tenancy.a
    stored = _post(tenancy, writer, org)
    fp = tenancy.crypto.contact_fingerprint(org.org_id, "phone", PHONE)
    with tenancy.operator() as op, org_transaction(op, tenancy.admin_token(org.org_id)):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _insert_lift(op, org, org.event_ids[1], stored.post_id, fp)
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.b, scopes=SCOPES)):
        with pytest.raises(psycopg.Error):
            _insert_lift(app, org, org.event_ids[1], stored.post_id, fp)  # another organisation's token


# no release path remains -------------------------------------------------------------------------------------------------

def test_the_release_module_and_every_caller_are_gone():
    assert not (SRC / "release.py").exists()
    offenders = [f"{p.name}: {m}" for p in SRC.rglob("*.py")
                 for m in re.findall(r"release_after\w*|staff_release\w*|capture_and_release|RELEASER|ReleaseFailedError|"
                                     r"ALARM_RELEASE_NOT_WRITTEN", p.read_text())]
    assert offenders == []


def test_no_release_event_can_be_written_in_the_single_company_ledger(conn, disclosure):
    g = record_event(conn, contact="+15555550101", event_type="grant", channels=["sms"], purposes=["marketing"],
                     method="checkbox", origin="consumer", disclosure_sha256=disclosure, session_ref="s")
    with pytest.raises((LedgerError, InvalidEventError, psycopg.Error)):
        record_event(conn, contact="+15555550101", event_type="release", channels=["sms"], purposes=["marketing"],
                     method="checkbox", origin="consumer", disclosure_sha256=disclosure, release_of_event_id=g.event_id,
                     release_outcome="released")
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type = 'release'").fetchone()["n"] == 0


def test_no_release_event_can_be_written_in_an_organisations_ledger(tenancy):
    org = tenancy.a
    with tenancy.app() as app, org_transaction(app, tenancy.token(org, scopes=SCOPES)):
        with pytest.raises((LedgerError, InvalidEventError, psycopg.Error)):
            record_tenant_event(app, tenancy.crypto, contact=PHONE, event_type="release", channels=["sms"],
                                purposes=["marketing"], method="checkbox", origin="consumer",
                                disclosure_sha256=org.disclosure, release_of_event_id=org.event_ids[0],
                                release_outcome="released")


def test_an_inbound_text_in_the_confirmation_service_creates_no_consent_and_lifts_no_stop():
    src = (SRC / "confirm" / "inbound.py").read_text()
    assert "tenant_capture" in src  # the stop path still records
    assert not re.search(r"event_type\s*=\s*[\"']grant[\"']", src.split("elif action == \"start\"")[1].split("\n\n")[0])


def test_the_contact_check_writes_no_raw_post_and_touches_none(tenancy, writer):
    org = tenancy.a
    stored = _post(tenancy, writer, org)

    def posts():
        with tenancy.superuser() as su:
            return su.execute("SELECT post_id, row_hash FROM consentvault.raw_post ORDER BY org_id, seq").fetchall()

    before = posts()
    with tenancy.app() as app, org_transaction(app, tenancy.token(org, scopes=SCOPES)):
        checker = gate.TenantGate(app, tenancy.crypto, org=org.org_id, requested_by="test")
        checker.channels, checker.purposes = {"sms"}, {"marketing"}  # this harness organisation configures none
        status, answer = checker.check(gate.GateItem(PHONE, "sms", "marketing"))
    assert status == 200 and answer["status"] == "records_found"
    assert posts() == before and str(stored.post_id) in {str(r["post_id"]) for r in before}
