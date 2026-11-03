"""The capture alarms: each fires for the thing it names, names an operator's concern and never the sender, and an alarm that
cannot be written is reported and never touches the stored post (task T027)."""

import json
import re
import uuid

import pytest

from consentvault import intake, rawpost
from consentvault.alarms import AlarmWriteError
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
from consentvault.tenancy.pipeline import ReceiptSigner
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


def make_writer(tenancy, tmp_path, **kw):
    return rawpost.RawPostWriter(crypto=tenancy.crypto, store=LocalAppendOnlyEvidenceStore(str(tmp_path / "ev")),
                                 receipts=ReceiptSigner.generate(key_id="k"), **kw)


def run(tenancy, writer, body: bytes, intake_name="edge_site_key"):
    enter = lambda c: org_transaction(c, tenancy.token(tenancy.a))  # noqa: E731
    req = rawpost.RawRequest(intake=intake_name, method="POST", path="/capture", query="", headers=(), body=body)
    with tenancy.app() as app:
        stored = writer.write(app, enter, req)
        return stored, intake.read_after_commit(writer, app, enter, stored, req, request_id="req-1")


def alarm_rows(tenancy):
    with tenancy.superuser() as su:
        return su.execute("SELECT name, ref_kind, ref_id, error_class FROM consentvault.operator_alarm WHERE org_id = %s"
                          " ORDER BY raised_at", (tenancy.a.org_id,)).fetchall()


def test_every_alarm_name_is_registered_and_fits_the_alarm_table(tenancy):
    assert len(set(intake.CAPTURE_ALARMS)) == len(intake.CAPTURE_ALARMS)
    pattern = re.compile(r"^[a-z][a-z0-9_]{0,40}(\.[a-z][a-z0-9_]{0,40}){0,3}$")
    assert all(pattern.match(n) and n.startswith("capture.") for n in intake.CAPTURE_ALARMS)
    for name in intake.CAPTURE_ALARMS:
        with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
            from consentvault.alarms import raise_operator_alarm
            raise_operator_alarm(app, name=name, error_class="Probe")
    assert {r["name"] for r in alarm_rows(tenancy)} == set(intake.CAPTURE_ALARMS)


@pytest.mark.parametrize("body,intake_name,alarm", [
    (b'{"checked": true}', "twenty", "capture.field_map_missing"),
    (b'{"contact": "a@b.com"}', "edge_site_key", "capture.consent_not_sent"),
    (b'{"checked": true, "disclosure_sha256": "' + b"a" * 64 + b'"}', "edge_site_key", "capture.wording_not_sent"),
    (b"{ not json", "edge_site_key", "capture.body_unreadable"),
])
def test_each_alarm_fires_for_what_it_names_and_names_the_post_never_the_sender(tenancy, tmp_path, body, intake_name, alarm):
    stored, after = run(tenancy, make_writer(tenancy, tmp_path), body, intake_name)
    assert alarm in after.alarms
    rows = [r for r in alarm_rows(tenancy) if r["name"] == alarm]
    assert len(rows) == 1 and rows[0]["ref_kind"] == "raw_post" and str(rows[0]["ref_id"]) == stored.post_id
    assert not any(b"a@b.com" in json.dumps(dict(r), default=str).encode() for r in alarm_rows(tenancy))


def test_an_unusual_size_alarm_fires_above_the_level_and_the_post_is_stored_whole(tenancy, tmp_path):
    writer = make_writer(tenancy, tmp_path, unusual_size=1000)
    body = b'{"checked": true, "pad": "' + b"x" * 5000 + b'"}'
    stored, after = run(tenancy, writer, body)
    assert stored.unusual_size is True and "capture.unusual_size" in after.alarms
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        assert writer.read_body(app, tenancy.a.org_id, stored.post_id) == body


def test_a_post_that_raises_no_alarm_leaves_no_alarm_row(tenancy, tmp_path):
    writer = make_writer(tenancy, tmp_path)
    body = json.dumps({"checked": True, "decided_at": "2026-10-20T09:12:00Z", "disclosure_text": "x",
                       "disclosure_sha256": "a" * 64, "contact": "a@b.com"}).encode()
    stored, after = run(tenancy, writer, body)
    assert after.alarms == [] and after.failures == [] and alarm_rows(tenancy) == []


def test_an_alarm_that_cannot_be_written_is_reported_and_never_touches_the_stored_post(tenancy, tmp_path, monkeypatch, caplog):
    def refuse(*a, **k):
        raise AlarmWriteError("simulated: the alarm table refused")
    monkeypatch.setattr(intake, "raise_operator_alarm", refuse)
    writer = make_writer(tenancy, tmp_path)
    with caplog.at_level("CRITICAL"):
        stored, after = run(tenancy, writer, b'{"contact": "x"}')
    assert after.alarms == [] and after.failures == ["alarm:capture.consent_not_sent:AlarmWriteError",
                                                     "alarm:capture.wording_not_sent:AlarmWriteError"]
    assert "capture alarm NOT written" in caplog.text
    with tenancy.superuser() as su:
        row = su.execute("SELECT body_sha256 FROM consentvault.raw_post WHERE post_id = %s", (uuid.UUID(stored.post_id),)).fetchone()
    assert row["body_sha256"] == stored.body_sha256


def test_a_failure_reading_the_field_map_is_reported_and_the_post_stays(tenancy, tmp_path, monkeypatch, caplog):
    from consentvault import extract

    def broken(*a, **k):
        raise rawpost.ConsentVaultError("simulated: the map table is unreadable")
    monkeypatch.setattr(extract, "load_field_map", broken)
    with caplog.at_level("ERROR"):
        stored, after = run(tenancy, make_writer(tenancy, tmp_path), b"{}")
    assert after.failures == ["field_map:ConsentVaultError"] and "field map could not be read" in caplog.text
    with tenancy.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"] == 1
