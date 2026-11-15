"""A certificate URL (TrustedForm) or token (Jornaya LeadiD) the form sent is stored whole with the post and read as sent, not sent
or sent more than once; never fetched, checked or judged. Names: tests/fixtures/certificates/SOURCE.md."""

import json

import pytest

from consentvault import cmd_match_repair, extract
from consentvault.extract import MANY, NOT_SENT, SENT, WIDGET_MAP, read_fields, values_json
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy
from match_support import make_writer, post

TF = "xxTrustedFormCertUrl"
LEADID = "universal_leadid"
URL = "https://cert.trustedform.com/454a35b802f3e7b63ffabb4efedb7c6ebe67886c"
CERTS = ("trustedform_cert", "jornaya_token")


def widget_body(third_party=None, **extra):
    body = {"contact": "+15555550100", "checked": True, "decided_at": "2026-11-15T10:00:00.000-05:00",
            "disclosure_text": "I agree.", "disclosure_sha256": "0" * 64, "page_url": "https://x.example.com/", "session": "s"}
    if third_party is not None:
        body["third_party"] = third_party
    body.update(extra)
    return json.dumps(body).encode()


def readings(body):
    return {r.field: r for r in read_fields(body, "application/json", WIDGET_MAP)}


def test_both_certificates_are_read_as_sent_with_their_exact_bytes():
    r = readings(widget_body([{"name": TF, "value": URL}, {"name": LEADID, "value": "tok"}]))
    assert (r["trustedform_cert"].state, r["trustedform_cert"].values) == (SENT, (f'"{URL}"'.encode(),))
    assert (r["jornaya_token"].state, r["jornaya_token"].values) == (SENT, (b'"tok"',))


def test_a_post_with_no_third_party_reads_not_sent_for_both():
    r = readings(widget_body())
    assert [(c, r[c].state, r[c].values) for c in CERTS] == [(c, NOT_SENT, ()) for c in CERTS]


def test_the_same_name_twice_reads_sent_more_than_once_in_byte_order():
    r = readings(widget_body([{"name": TF, "value": "first"}, {"name": TF, "value": "second"}]))
    assert (r["trustedform_cert"].state, r["trustedform_cert"].values) == (MANY, (b'"first"', b'"second"'))


def test_a_forged_url_is_read_as_sent_nothing_judges_it():
    r = readings(widget_body([{"name": TF, "value": "http://evil.example/not-a-cert"}]))
    assert r["trustedform_cert"].state == SENT and r["trustedform_cert"].values == (b'"http://evil.example/not-a-cert"',)


def test_escapes_spaces_and_a_script_tag_are_kept_exactly_as_the_sender_wrote_them():
    body = b'{"checked": true, "third_party": [{"name": "xxTrustedFormCertUrl", "value": "  a\\u0041\\n<script>x</script> "}]}'
    assert readings(body)["trustedform_cert"].values == (b'"  a\\u0041\\n<script>x</script> "',)


def test_a_one_megabyte_value_is_read_whole():
    big = "x" * 1_000_000
    assert readings(widget_body([{"name": TF, "value": big}]))["trustedform_cert"].values == (f'"{big}"'.encode(),)


def test_a_third_party_value_that_is_not_a_list_reads_not_sent_and_the_post_is_still_read():
    r = readings(widget_body("nonsense"))
    assert r["trustedform_cert"].state == NOT_SENT and r["consent"].state == SENT


def test_an_entry_with_another_name_gets_no_named_reading():
    assert readings(widget_body([{"name": "my_own_field", "value": "v"}]))["trustedform_cert"].state == NOT_SENT


def test_the_same_body_gives_the_same_readings_twice():
    body = widget_body([{"name": TF, "value": URL}, {"name": LEADID, "value": "t"}])
    assert read_fields(body, None, WIDGET_MAP) == read_fields(body, None, WIDGET_MAP)


def test_a_map_with_no_third_party_path_writes_no_certificate_readings():
    fmap = extract.FieldMap(consent_paths=("/checked",))
    assert not any(r.field in CERTS for r in read_fields(widget_body([{"name": TF, "value": URL}]), None, fmap))


def test_the_extractor_version_is_two_and_the_widget_map_reads_third_party():
    assert extract.EXTRACTOR_VERSION == 2 and WIDGET_MAP.third_party_path == "/third_party"


# Stored posts --------------------------------------------------------------------------------------------------------------

@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def writer(tenancy, tmp_path):
    return make_writer(tenancy, tmp_path)


def stored_reading(tenancy, writer, post_id, field):
    org = tenancy.a
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(org.org_id)):
        return extract.read_stored_values(app, org.org_id, post_id, field, data_key=writer.open_key(app, org.org_id, post_id))


def test_a_widget_shaped_post_stores_the_body_whole_and_both_readings_are_sent(tenancy, writer):
    body = widget_body([{"name": TF, "value": URL}, {"name": LEADID, "value": "tok-1"}])
    stored, _ = post(tenancy, writer, body, source_id=tenancy.a.source_id)
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(tenancy.a.org_id)):
        assert writer.read_body(app, tenancy.a.org_id, stored.post_id) == body   # the whole body, byte for byte
    tf = stored_reading(tenancy, writer, stored.post_id, "trustedform_cert")
    assert (tf["state"], tf["values"], tf["extractor_version"]) == (SENT, [f'"{URL}"'], 2)
    assert stored_reading(tenancy, writer, stored.post_id, "jornaya_token")["values"] == ['"tok-1"']


def snapshot(tenancy, post_id):
    with tenancy.superuser() as su:
        return su.execute("SELECT map_version, field, state, values_ct, extractor_version, extracted_at FROM"
                          " consentvault.raw_post_field WHERE post_id = %s ORDER BY map_version, field", (post_id,)).fetchall()


def test_a_re_read_under_version_two_appends_the_certificate_readings_and_leaves_version_one_rows_unchanged(
        tenancy, writer, monkeypatch):
    body = widget_body([{"name": TF, "value": URL}])
    real = extract.read_fields
    monkeypatch.setattr(extract, "EXTRACTOR_VERSION", 1)
    monkeypatch.setattr(extract, "read_fields", lambda *a: [r for r in real(*a) if r.field not in CERTS])
    stored, _ = post(tenancy, writer, body, source_id=tenancy.a.source_id)
    monkeypatch.undo()
    before = snapshot(tenancy, stored.post_id)
    assert {r["extractor_version"] for r in before} == {1} and not [r for r in before if r["field"] in CERTS]
    out = cmd_match_repair.repair_all(tenancy.app, tenancy.operator, tenancy.key, writer)
    assert out["failed"] == []
    after = snapshot(tenancy, stored.post_id)
    assert all(r in after for r in before)                      # every version-1 row is untouched
    added = [r for r in after if r not in before]
    assert sorted(r["field"] for r in added) == sorted(CERTS) and {r["extractor_version"] for r in added} == {2}
    assert stored_reading(tenancy, writer, stored.post_id, "trustedform_cert")["values"] == [f'"{URL}"']
    again = cmd_match_repair.repair_all(tenancy.app, tenancy.operator, tenancy.key, writer)
    assert again["read"] == 0 and snapshot(tenancy, stored.post_id) == after


def test_a_stored_post_without_a_third_party_key_reads_not_sent(tenancy, writer):
    stored, _ = post(tenancy, writer, widget_body(), source_id=tenancy.a.source_id)
    r = stored_reading(tenancy, writer, stored.post_id, "trustedform_cert")
    assert (r["state"], r["values"]) == (NOT_SENT, [])


def test_values_json_keeps_the_exact_text():
    assert json.loads(values_json([b'"a b"'])) == ['"a b"']
