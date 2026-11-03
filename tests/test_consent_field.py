"""Consent is the box value as sent, read from the stored post with the form's field map; the decision time and the wording
are kept as sent beside the arrival time (tasks T062, T063, T070, T071, T072)."""

import json
import uuid
from datetime import datetime, timezone

import pytest

from consentvault import extract, intake, rawpost
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy.pipeline import ReceiptSigner
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def writer(tenancy, tmp_path):
    return rawpost.RawPostWriter(crypto=tenancy.crypto, store=LocalAppendOnlyEvidenceStore(str(tmp_path / "ev")),
                                 receipts=ReceiptSigner.generate(key_id="k"))


def store_and_read(tenancy, writer, body: bytes, *, intake_name="edge_site_key", headers=(("content-type", "application/json"),), org=None, source_id=None):
    org = org or tenancy.a
    enter = lambda c: org_transaction(c, tenancy.token(org))  # noqa: E731
    req = rawpost.RawRequest(intake=intake_name, method="POST", path="/capture", query="", headers=tuple(headers), body=body)
    with tenancy.app() as app:
        stored = writer.write(app, enter, req)
        after = intake.read_after_commit(writer, app, enter, stored, req, source_id=source_id)
    return stored, after


def readings(tenancy, writer, stored, field, org=None):
    org = org or tenancy.a
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(org.org_id)):
        key = writer.open_key(app, org.org_id, stored.post_id)
        return extract.read_stored_values(app, org.org_id, stored.post_id, field, data_key=key)


@pytest.mark.parametrize("sent,texts", [(b"true", ["true"]), (b"false", ["false"]), (b'"on"', ['"on"']), (b'"yes"', ['"yes"']),
                                         (b"1", ["1"]), (b"null", ["null"])])
def test_the_box_value_is_stored_as_the_exact_text_sent(tenancy, writer, sent, texts):
    stored, _ = store_and_read(tenancy, writer, b'{"contact": "a@b.com", "checked": ' + sent + b"}")
    r = readings(tenancy, writer, stored, "consent")
    assert (r["state"], r["values"], r["occurrences"]) == ("sent", texts, 1)


def test_an_absent_box_reads_not_sent_and_raises_the_alarm_and_nothing_is_filled(tenancy, writer):
    stored, after = store_and_read(tenancy, writer, b'{"contact": "a@b.com"}')
    r = readings(tenancy, writer, stored, "consent")
    assert (r["state"], r["values"], r["occurrences"]) == ("not_sent", [], 0)
    assert "capture.consent_not_sent" in after.alarms


def test_a_form_with_no_map_reads_unmapped_raises_the_alarm_and_the_post_stays(tenancy, writer):
    stored, after = store_and_read(tenancy, writer, b'{"checked": true}', intake_name="twenty")
    assert readings(tenancy, writer, stored, "consent")["state"] == "unmapped"
    assert after.alarms == ["capture.field_map_missing"] and after.map_label is None
    with tenancy.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.raw_post WHERE post_id = %s", (uuid.UUID(stored.post_id),)).fetchone()["n"] == 1


def test_a_repeated_box_reads_every_occurrence_in_byte_order(tenancy, writer):
    stored, _ = store_and_read(tenancy, writer, b'{"checked": true, "checked": false}')
    r = readings(tenancy, writer, stored, "consent")
    assert (r["state"], r["values"]) == ("sent_more_than_once", ["true", "false"])


def test_a_stored_map_is_used_for_its_source_and_a_new_version_never_edits_the_old(tenancy, writer):
    org = tenancy.a
    with tenancy.operator() as op, org_transaction(op, tenancy.admin_token(org.org_id)):
        v1 = extract.add_field_map(op, set_by="member:test", source_id=org.source_id, body_format="form_urlencoded",
                                   consent_paths=["agree"], decision_time_path="when", wording_path="words",
                                   contact_paths=[("email", "email")])
        v2 = extract.add_field_map(op, set_by="member:test", source_id=org.source_id, body_format="form_urlencoded",
                                   consent_paths=["agree", "agree2"], decision_time_path="when")
        versions = extract.list_field_maps(op, org.source_id)
    assert (v1, v2) == (1, 2) and [m["map_version"] for m in versions] == [1, 2]
    assert versions[0]["consent_paths"] == ["agree"] and versions[0]["set_by"] == "member:test"
    body = b"email=a%40b.com&agree=on&agree2=true&when=2026-10-20+09%3A12&words=I+agree"
    stored, after = store_and_read(tenancy, writer, body, headers=(("content-type", "application/x-www-form-urlencoded"),),
                                   source_id=org.source_id)
    assert after.map_label == "row:2"
    r = readings(tenancy, writer, stored, "consent")
    assert (r["map_version"], r["state"], r["values"]) == (2, "sent_more_than_once", ["on", "true"])
    assert readings(tenancy, writer, stored, "decision_time")["values"] == ["2026-10-20+09%3A12"]
    with tenancy.superuser() as su:
        with pytest.raises(Exception, match="append-only"):
            su.execute("UPDATE consentvault.form_field_map SET set_by = 'x'")
    # a source with no map of its own, and no organisation default, reads with the built-in map of its intake
    with tenancy.operator() as op, org_transaction(op, tenancy.admin_token(org.org_id)):
        assert extract.load_field_map(op, uuid.uuid4(), "edge_site_key").label == "built_in:widget"


def test_the_decision_time_is_kept_as_sent_beside_the_arrival_time_and_never_filled(tenancy, writer):
    sent = b'"2026-10-20 09:12"'  # no zone: kept exactly, sorted by nothing
    stored, _ = store_and_read(tenancy, writer, b'{"checked": true, "decided_at": ' + sent + b"}")
    r = readings(tenancy, writer, stored, "decision_time")
    assert r["values"] == ['"2026-10-20 09:12"'] and r["decision_time_parsed"] is None
    assert stored.received_at.tzinfo is not None and isinstance(stored.received_at, datetime)  # arrival time, its own column
    stored2, _ = store_and_read(tenancy, writer, b'{"checked": true, "decided_at": "2026-10-20T09:12:00-04:00"}')
    r2 = readings(tenancy, writer, stored2, "decision_time")
    assert r2["values"] == ['"2026-10-20T09:12:00-04:00"']
    assert r2["decision_time_parsed"] == datetime(2026, 10, 20, 13, 12, tzinfo=timezone.utc)
    assert stored2.received_at != r2["decision_time_parsed"]
    stored3, _ = store_and_read(tenancy, writer, b'{"checked": true}')
    r3 = readings(tenancy, writer, stored3, "decision_time")
    assert (r3["state"], r3["values"], r3["decision_time_parsed"]) == ("not_sent", [], None)


def test_the_wording_is_kept_byte_for_byte_and_a_hash_only_form_reads_not_sent_with_an_alarm(tenancy, writer):
    text = "  I agree to texts ☃\n\t\"quoted\" \\ back​  "
    stored, after = store_and_read(tenancy, writer, json.dumps({"checked": True, "disclosure_text": text, "disclosure_sha256": "a" * 64},
                                                                ensure_ascii=False).encode("utf-8"))
    r = readings(tenancy, writer, stored, "wording")
    assert r["state"] == "sent" and json.loads(r["values"][0]) == text and "capture.wording_not_sent" not in after.alarms
    only_hash, after2 = store_and_read(tenancy, writer, json.dumps({"checked": True, "disclosure_sha256": "b" * 64}).encode())
    assert readings(tenancy, writer, only_hash, "wording")["state"] == "not_sent"
    assert readings(tenancy, writer, only_hash, "wording_hash")["values"] == ['"' + "b" * 64 + '"']
    assert "capture.wording_not_sent" in after2.alarms


def test_registered_wording_never_appears_in_the_wording_as_sent_field(tenancy, writer):
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
        registered = app.execute("SELECT body FROM consentvault.disclosure LIMIT 1").fetchone()
    stored, _ = store_and_read(tenancy, writer, json.dumps({"checked": True, "disclosure_sha256": tenancy.a.disclosure}).encode())
    r = readings(tenancy, writer, stored, "wording")
    assert r["state"] == "not_sent" and r["values"] == []  # the library's text is never put in where the sender sent none
    assert registered is None or "body" not in r


def test_an_unreadable_body_reads_body_unreadable_for_the_fields_and_the_post_stays(tenancy, writer):
    stored, after = store_and_read(tenancy, writer, b"{ this is not json")
    for field in ("consent", "decision_time", "wording"):
        assert readings(tenancy, writer, stored, field)["state"] == "body_unreadable"
    assert after.alarms == ["capture.body_unreadable"]


def test_the_same_post_read_twice_with_the_same_map_gives_the_same_readings(tenancy, writer):
    body = b'{"checked": "on", "decided_at": "2026-10-20T09:12:00Z", "disclosure_text": "x", "contact": "a@b.com"}'
    assert extract.read_fields(body, None, extract.WIDGET_MAP) == extract.read_fields(body, None, extract.WIDGET_MAP)
