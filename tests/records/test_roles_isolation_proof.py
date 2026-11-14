"""records.md and auth.md: roles on every records route, a second organization sees nothing, proof by record id,
the audit actions and the detail field."""

import pytest

from consentvault.tenancy.admin_routes import Request

from contract_world.world import EMAIL, PHONE, PHONE2

ROUTES = [  # method, path template, query, body, roles allowed
    ("GET", "/v1/records", {}, None, {"admin", "developer", "compliance_viewer"}),
    ("GET", "/v1/records/summary", {}, None, {"admin", "developer", "compliance_viewer"}),
    ("POST", "/v1/records:search", {}, {"contact": PHONE}, {"admin", "compliance_viewer"}),
    ("POST", "/v1/records:reveal", {}, {"record_ids": ["{rid}"]}, {"admin", "compliance_viewer"}),
    ("POST", "/v1/records/exports", {}, {"contact_form": "masked"}, {"admin", "compliance_viewer"}),
    ("GET", "/v1/records/exports", {}, None, {"admin", "compliance_viewer"}),
]


def test_every_records_route_admits_exactly_its_roles(world):
    """records.md endpoint table and auth.md (A, V, D columns; role_not_allowed elsewhere)."""
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    for method, path, query, body, allowed in ROUTES:
        body = None if body is None else {k: ([rid] if v == ["{rid}"] else v) for k, v in body.items()}
        for role, person in o.people.items():
            r = person.call(method, path, query, body)
            if role in allowed:
                assert r.status < 300, (method, path, role, r.status, r.body)
            else:
                assert (r.status, r.body["error"]) == (403, "role_not_allowed"), (method, path, role, r.body)


def test_every_records_route_needs_a_session(world):
    """README section 1 and auth.md (no credential: unauthenticated)."""
    for method, path, query, body, _ in ROUTES:
        r = world.vault.app.handle(Request(method, path, query, body, request_id="r-none"))
        assert (r.status, r.body["error"]) == (401, "unauthenticated"), (method, path, r.body)


def test_a_second_organization_sees_nothing_and_cannot_reach_anothers_records(world):
    """auth.md (a token carries exactly one organization; row security by org_id, records.md section 8) and LC-I3: list, summary, search, reveal, export and cursors of org A are invisible to org B."""
    a, b = world.a, world.b
    world.capture(a, PHONE, display={"name": "Dana"})
    world.capture(b, PHONE2)
    rid_a = world.record_id(a, PHONE)
    assert [i["contact"]["fp_hint"] for i in b.boss.ok("GET", "/v1/records", {})["items"]] == [b.fp(PHONE2)[:8]]
    assert b.boss.ok("POST", "/v1/records:search", body={"contact": PHONE})["items"] == []
    b.boss.err("POST", "/v1/records:reveal", body={"record_ids": [rid_a]}, name="validation_failed")
    b.boss.err("POST", "/v1/proof", body={"record_id": rid_a}, name="not_found")
    b.boss.err("GET", "/v1/records", {"source_id": a.web_id}, name="not_found")
    assert PHONE not in str(a.boss.ok("GET", "/v1/records", {})) and PHONE2 not in str(a.boss.ok("GET", "/v1/records", {}))
    world.capture(a, "+15555550301")
    cursor = a.boss.ok("GET", "/v1/records", {"limit": "1"})["next_cursor"]
    b.boss.err("GET", "/v1/records", {"limit": "1", "cursor": cursor}, name="invalid_cursor")
    assert world.audit(b.boss, "records.listed") == [] or all(PHONE not in str(r) for r in world.audit(b.boss, "records.listed"))
    ex = b.boss.ok("POST", "/v1/records/exports", body={"contact_form": "fingerprint"})
    assert b.boss.ok("GET", "/v1/records/exports")["items"][0]["export_id"] == ex["export_id"]
    a.boss.err("GET", f"/v1/records/exports/{ex['export_id']}", name="not_found")


def test_the_same_contact_in_two_organizations_is_two_unrelated_records(world):
    """records.md section 1 (record_id random, not derived from the contact; per organization)."""
    world.capture(world.a, PHONE)
    world.capture(world.b, PHONE)
    ia = world.a.boss.ok("GET", "/v1/records", {})["items"][0]
    ib = world.b.boss.ok("GET", "/v1/records", {})["items"][0]
    assert ia["record_id"] != ib["record_id"] and ia["contact"]["fp_hint"] != ib["contact"]["fp_hint"]


def test_proof_by_record_id_adds_the_masked_contact_and_the_person_and_never_the_full_contact(world):
    """proof-export.md amendment (record_id in place of contact; adds record_id, contact {masked, fp_hint}, person; A and V)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    rid = world.record_id(o, PHONE)
    for who in (o.boss, o.viewer):
        body = who.ok("POST", "/v1/proof", body={"record_id": rid})
        assert body["record_id"] == rid and body["contact"] == {"masked": "(555) ***-0142", "fp_hint": o.fp(PHONE)[:8]}
        assert body["person"] == {"name": "Dana Cruz", "company": "Cruz Tile"}
        assert PHONE not in str(body)
    by_contact = o.boss.ok("POST", "/v1/proof", body={"contact": PHONE})
    assert "record_id" not in by_contact and "person" not in by_contact


def test_proof_and_export_accept_exactly_one_of_contact_or_record_id(world):
    """proof-export.md amendment (exactly one of the two, else validation_failed; unknown record_id is not_found)."""
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    for path in ("/v1/proof", "/v1/exports"):
        o.boss.err("POST", path, body={"contact": PHONE, "record_id": rid}, name="validation_failed")
        o.boss.err("POST", path, body={}, name="validation_failed")
        o.boss.err("POST", path, body={"record_id": "00000000-0000-4000-8000-0000000000aa"}, name="not_found")
    assert o.boss.call("POST", "/v1/exports", body={"record_id": rid}).status < 300


def test_proof_by_record_id_shows_a_developer_nothing_and_audits_as_proof_read(world):
    """proof-export.md amendment (A and V; audit proof.read with target contact and the fingerprint hint)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana"})
    rid = world.record_id(o, PHONE)
    o.boss.ok("POST", "/v1/proof", body={"record_id": rid})
    rows = world.audit(o.boss, "proof.read")
    assert rows and rows[0]["target"] == {"kind": "contact", "id": o.fp(PHONE)[:8]}
    r = o.dev.call("POST", "/v1/proof", body={"record_id": rid})
    assert r.status == 403 and r.body["error"] == "role_not_allowed"


def test_the_new_audit_actions_are_all_listed_for_the_filter_menu(world):
    """members.md amendment (every new action listed by GET /v1/audit/actions)."""
    want = {"records.listed", "records.searched", "records.reveal_requested", "records.revealed", "records.export_requested",
            "records.export_built", "records.export_downloaded"}
    got, cursor = set(), None
    while True:
        page = world.a.boss.ok("GET", "/v1/audit/actions", {"limit": "200", **({"cursor": cursor} if cursor else {})})
        got |= {i["action"] for i in page["items"]}
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert want <= got


def test_an_audit_detail_never_holds_a_contact_point_name_company_or_reply_text(world):
    """members.md amendment (detail never holds personal data; asserted for every records action)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    world.email_grant(o, EMAIL, display={"name": "Lee Park"})
    rid = world.record_id(o, PHONE)
    o.boss.ok("GET", "/v1/records", {})
    o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": [rid]})
    o.boss.ok("POST", "/v1/records/exports", body={"contact_form": "full", "reason": "check", "include_person": True})
    for action in ("records.listed", "records.searched", "records.reveal_requested", "records.revealed", "records.export_requested"):
        for row in world.audit(o.boss, action):
            text = str(row.get("detail")) + str(row.get("target")) + str(row.get("reason"))
            for secret in (PHONE, EMAIL, "Dana", "Cruz", "Lee Park", "5550142"):
                assert secret not in text, (action, secret)


def test_a_records_list_does_not_audit_a_viewer_reading_the_summary(world):
    """records.md section 4 (not audited) next to section 3 (audited): the two differ for the same viewer."""
    world.capture(world.a, PHONE)
    world.a.viewer.ok("GET", "/v1/records/summary")
    world.a.viewer.ok("GET", "/v1/records")
    assert len(world.audit(world.a.boss, "records.listed")) == 1
