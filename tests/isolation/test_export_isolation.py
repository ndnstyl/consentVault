"""Evidence export isolation: the same phone number is a contact of two organizations; one organization's package, job,
link, cache and anchor never carry or reach the other's data. The export reads are not owner-rights functions: each
filters on current_org() itself, and the superuser tests below prove that by running them where row security is off."""

import json
import os
import uuid

import pytest

from consentvault import db
from consentvault.evidence import (LocalEcdsaSigner, NoRecordsError, ScopeRefusedError, build_tenant_files,
                                   contact_fingerprint_of, contact_has_records, gather_tenant)
from consentvault.evidence_routes import Principal, Request, handle
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from export.support import PHONE, build_empty_tenancy, make_service, pinned_migrations, populate, token


@pytest.fixture
def two_orgs(raw_dsn, pg_server, tmp_path):
    with db.connect(raw_dsn) as c:
        db.migrate(c, pinned_migrations(tmp_path / "pinned"))
    t = build_empty_tenancy(raw_dsn, pg_server["port"])
    populate(t, t.a)
    populate(t, t.b)
    return t


def fp_of(t, org):
    return t.crypto.contact_fingerprint(org.org_id, "phone", PHONE)


def others_markers(t, org, other):
    """Everything that identifies the other organization's records."""
    with t.superuser() as su:
        rows = su.execute("SELECT event_id, row_hash, contact_commit, subject_commit, contact_fp, subject_fp"
                          " FROM consentvault.event WHERE org_id = %s", (other.org_id,)).fetchall()
    marks = [str(other.org_id), other.disclosure, f"{other.name}-fall", f"{other.name}-other", f"{other.name}.example.com",
             f"s-{other.name}", other.name + " Brand"]
    for r in rows:
        marks += [str(r["event_id"]), r["row_hash"], r["contact_commit"], r["subject_commit"], r["contact_fp"], r["subject_fp"]]
    return marks


@pytest.mark.parametrize("mine,theirs", [("a", "b"), ("b", "a")])
def test_an_export_carries_nothing_of_the_other_organization(two_orgs, mine, theirs):
    t = two_orgs
    org, other = getattr(t, mine), getattr(t, theirs)
    with t.app() as app, org_transaction(app, token(t, org)):
        result, tokens = gather_tenant(app, t.crypto, fp_of(t, org))
    files = build_tenant_files(result, tokens, LocalEcdsaSigner.generate())
    blob = b"\n".join(files.values()).decode("utf-8", "replace")
    for mark in others_markers(t, org, other):
        assert mark not in blob, mark
    own = {str(r) for r in org.event_ids}
    assert {e["event_id"] for e in result["timeline"]} <= own
    assert {p["seq"] for p in result["chain"]["path"]} == {1, 2, 3}  # only this organization's own chain
    assert all(e["org_id"] == str(org.org_id) for e in result["timeline"])
    assert [d["sha256"] for d in result["disclosures"]] == [org.disclosure]
    assert {a["row_hash"] for a in result["chain"]["anchors"]} == set()


def test_only_a_proof_scope_builds_a_package(two_orgs):
    t = two_orgs
    for scopes in (("capture",), ("gate_read",), ("worker:anchor",), ("gate_read", "capture")):
        with t.app() as app, org_transaction(app, token(t, t.a, scopes)):
            with pytest.raises(ScopeRefusedError):
                gather_tenant(app, t.crypto, fp_of(t, t.a))
            with pytest.raises(ScopeRefusedError):
                contact_has_records(app, t.crypto, fp_of(t, t.a))
    for scopes in (("proof_read",), ("admin",)):
        with t.app() as app, org_transaction(app, token(t, t.a, scopes)):
            assert contact_has_records(app, t.crypto, fp_of(t, t.a))


def test_the_contact_fingerprint_of_one_organization_finds_nothing_in_the_other(two_orgs):
    t = two_orgs
    with t.app() as app, org_transaction(app, token(t, t.b)):
        assert contact_has_records(app, t.crypto, fp_of(t, t.a)) is False
        with pytest.raises(NoRecordsError):
            gather_tenant(app, t.crypto, fp_of(t, t.a))


def test_the_reads_filter_on_current_org_themselves_where_row_security_is_off(two_orgs):
    """A superuser bypasses row-level security, so only the export's own org_id filters keep the other organization out."""
    t = two_orgs
    with t.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 6  # both are really there
        with org_transaction(su, token(t, t.a)):
            result, tokens = gather_tenant(su, t.crypto, fp_of(t, t.a))
            assert contact_has_records(su, t.crypto, fp_of(t, t.a))
            assert contact_has_records(su, t.crypto, fp_of(t, t.b)) is False or fp_of(t, t.a) != fp_of(t, t.b)
    blob = json.dumps(result)
    for mark in others_markers(t, t.a, t.b):
        assert mark not in blob, mark
    assert {e["event_id"] for e in result["timeline"]} <= set(t.a.event_ids)
    assert {p["seq"] for p in result["chain"]["path"]} == {1, 2, 3}
    assert [d["sha256"] for d in result["disclosures"]] == [t.a.disclosure]
    assert len(result["contact_log"]) == 1 and len(result["reviews"]) == 1


def test_another_organizations_job_package_and_link_are_unreachable(two_orgs, tmp_path):
    t = two_orgs
    svc = make_service(t, tmp_path)
    pa = Principal(t.a.org_id, uuid.uuid4(), "portal", role="admin")
    pb = Principal(t.b.org_id, uuid.uuid4(), "portal", role="admin")

    def call(method, path, p=None, body=None, query=None):
        return handle(svc, Request(method, path, query or {}, body, p, request_id="r"))

    eid = call("POST", "/v1/exports", pa, {"contact": PHONE}).body["export_id"]
    own = call("POST", "/v1/exports", pb, {"contact": PHONE}).body["export_id"]
    assert call("GET", f"/v1/exports/{eid}", pb).body["error"] == "not_found"
    assert call("POST", f"/v1/exports/{eid}:link", pb).body["error"] == "not_found"
    assert call("POST", f"/v1/exports/{eid}:resume", pb).body["error"] == "not_found"
    assert [i["export_id"] for i in call("GET", "/v1/exports", pb).body["items"]] == [own]
    url = call("POST", f"/v1/exports/{eid}:link", pa).body["download_url"]
    link = url.split("link=")[1]
    # a link for A's package presented against B's package id, or with its organization swapped, is refused
    assert call("GET", f"/v1/exports/{own}/download", None, query={"link": link}).body["error"] == "export_link_invalid"
    body_b64, sig = link.split(".")
    import base64

    pad = lambda s: s + "=" * (-len(s) % 4)
    fields = json.loads(base64.urlsafe_b64decode(pad(body_b64)))
    fields["o"] = str(t.b.org_id)
    forged = base64.urlsafe_b64encode(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()).decode().rstrip("=")
    assert call("GET", f"/v1/exports/{eid}/download", None, query={"link": f"{forged}.{sig}"}).body["error"] == "export_link_invalid"
    # A's package is stored under A's prefix only, and B's own package is a different object
    stored = sorted(p.relative_to(tmp_path / "store").parts[0] for p in (tmp_path / "store").rglob("*.pkg"))
    assert stored == sorted([str(t.a.org_id), str(t.b.org_id)])
    got = call("GET", f"/v1/exports/{eid}/download", None, query={"link": link})
    assert got.status == 200
    assert str(t.b.org_id).encode() not in got.raw and b"bravo" not in got.raw


def test_audit_rows_stay_with_the_organization_that_acted(two_orgs, tmp_path):
    t = two_orgs
    svc = make_service(t, tmp_path)
    handle(svc, Request("POST", "/v1/exports", {}, {"contact": PHONE},
                        Principal(t.a.org_id, uuid.uuid4(), "portal", role="admin"), "r"))
    with t.superuser() as su:
        rows = su.execute("SELECT org_id, action FROM consentvault.audit_event").fetchall()
    assert rows and {r["org_id"] for r in rows} == {t.a.org_id}


def test_export_jobs_are_invisible_across_organizations_in_the_database(two_orgs, tmp_path):
    t = two_orgs
    svc = make_service(t, tmp_path)
    handle(svc, Request("POST", "/v1/exports", {}, {"contact": PHONE},
                        Principal(t.a.org_id, uuid.uuid4(), "portal", role="admin"), "r"))
    with t.app() as app, org_transaction(app, token(t, t.b)):
        assert app.execute("SELECT count(*) AS n FROM consentvault.export_job").fetchone()["n"] == 0
    with t.app() as app, org_transaction(app, token(t, t.a)):
        assert app.execute("SELECT count(*) AS n FROM consentvault.export_job").fetchone()["n"] == 1
    with t.app() as app, org_transaction(app, token(t, t.a, ("capture",))):  # no read scope: no job rows either
        assert app.execute("SELECT count(*) AS n FROM consentvault.export_job").fetchone()["n"] == 0
