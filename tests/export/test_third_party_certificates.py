"""The signed evidence export carries the certificate values the form sent with each event, beside the record, labelled as not
checked with the issuer (kit: competitive builds, certificate pass-through)."""

import json
import uuid

from consentvault.evidence import CERTIFICATE_LABEL, LocalEcdsaSigner, export_tenant, third_party_certificates
from consentvault.tenancy.tokens import org_transaction

from match_support import make_writer, post

from .support import PHONE, token

URL = "https://cert.trustedform.com/454a35b802f3e7b63ffabb4efedb7c6ebe67886c"


def widget_post(t, tmp_path, third_party):
    body = {"contact": PHONE, "checked": True, "decided_at": "2026-11-15T10:00:00.000-05:00", "disclosure_text": "I agree.",
            "disclosure_sha256": "0" * 64, "page_url": "https://alpha.example.com/", "session": "s"}
    if third_party is not None:
        body["third_party"] = third_party
    stored, _ = post(t, make_writer(t, tmp_path), body, org=t.a, source_id=t.a.source_id)
    return stored


def link(t, event_id, post_id):
    with t.superuser() as su:
        su.execute("INSERT INTO consentvault.event_source_post (org_id, event_id, post_id, role) VALUES (%s, %s, %s, 'trigger')",
                   (t.a.org_id, event_id, uuid.UUID(str(post_id))))


def test_export_carries_values(world, tmp_path):
    t = world
    grant = t.a.event_ids[0]
    stored = widget_post(t, tmp_path, [{"name": "xxTrustedFormCertUrl", "value": URL}, {"name": "universal_leadid", "value": "tok"}])
    link(t, grant, stored.post_id)
    out = tmp_path / "bundle"
    with t.app() as app, org_transaction(app, token(t, t.a)):
        export_tenant(app, t.crypto, PHONE, out, signer=LocalEcdsaSigner.generate("evidence-test", 3))
    data = json.loads((out / "evidence.json").read_text())
    by_event = {e["event_id"]: e for e in data["timeline"]}
    certs = {c["reading"]: c for c in by_event[str(grant)]["third_party_certificates"]}
    assert certs["trustedform_cert"]["values"] == [f'"{URL}"'] and certs["jornaya_token"]["values"] == ['"tok"']
    assert certs["trustedform_cert"]["state"] == "sent" and certs["trustedform_cert"]["label"] == CERTIFICATE_LABEL
    assert "has not checked it with the issuer" in CERTIFICATE_LABEL
    others = [e for eid, e in by_event.items() if eid != str(grant)]
    assert others and all(e["third_party_certificates"] == [] for e in others)


def test_a_post_that_sent_no_certificate_exports_not_sent(world, tmp_path):
    t = world
    stored = widget_post(t, tmp_path, None)
    link(t, t.a.event_ids[0], stored.post_id)
    with t.app() as app, org_transaction(app, token(t, t.a)):
        got = third_party_certificates(app, t.crypto, t.a.org_id, [str(t.a.event_ids[0])])
    assert {c["reading"]: (c["state"], c["values"]) for c in got[str(t.a.event_ids[0])]} == {
        "trustedform_cert": ("not_sent", []), "jornaya_token": ("not_sent", [])}


def test_the_other_organisation_sees_none_of_it(world, tmp_path):
    t = world
    stored = widget_post(t, tmp_path, [{"name": "universal_leadid", "value": "tok"}])
    link(t, t.a.event_ids[0], stored.post_id)
    with t.app() as app, org_transaction(app, token(t, t.b)):
        assert third_party_certificates(app, t.crypto, t.b.org_id, [str(t.a.event_ids[0])]) == {}
