"""POST /v1/exports, status, list, links, resume and the one-time proxied download, through the route handler."""

import hashlib
import json
import uuid
from urllib.parse import parse_qs, urlsplit

import pytest

from consentvault.evidence import ExportService, LocalEcdsaSigner
from consentvault.evidence_routes import Principal, Request, handle
from consentvault.providers.errors import EvidenceStoreError
from consentvault.tenancy.tokens import org_transaction

from .support import PHONE, FailingOnce, make_service, run_verifier, token, unzip


def admin(org):
    return Principal(org.org_id, uuid.uuid4(), "portal", role="admin")


def call(svc, method, path, p=None, body=None, query=None):
    return handle(svc, Request(method, path, query or {}, body, p, request_id=f"req-{uuid.uuid4()}"))


def create(svc, org, contact=PHONE, p=None):
    return call(svc, "POST", "/v1/exports", p or admin(org), {"contact": contact})


def link_query(resp_url):
    return {k: v[0] for k, v in parse_qs(urlsplit(resp_url).query).items()}


def audits(t):
    with t.superuser() as su:
        return [r["action"] for r in su.execute("SELECT action FROM consentvault.audit_event ORDER BY at")]


def test_a_build_runs_to_ready_and_downloads_once(world, throwaway_tsa, tmp_path):
    t, svc = world, make_service(world, tmp_path)
    p = admin(t.a)
    r = create(svc, t.a, p=p)
    assert r.status == 202 and r.body["status"] == "building"
    eid = r.body["export_id"]
    s = call(svc, "GET", f"/v1/exports/{eid}", p)
    assert s.status == 200 and s.body["status"] == "ready" and s.body["progress"] == {"done": 4, "total": 4}
    assert s.body["sha256"] and s.body["signature"] and s.body["expires_at"] and s.body["downloaded_at"] is None
    url = s.body["download_url"]
    assert url.startswith(f"/v1/exports/{eid}/download?link=")

    d = call(svc, "GET", f"/v1/exports/{eid}/download", None, query=link_query(url))
    assert d.status == 200 and d.headers["Content-Type"] == "application/zip" and d.headers["Cache-Control"] == "no-store"
    assert hashlib.sha256(d.raw).hexdigest() == d.headers["X-Package-Sha256"] == s.body["sha256"]

    again = call(svc, "GET", f"/v1/exports/{eid}/download", None, query=link_query(url))
    assert again.status == 410 and again.body["error"] == "export_link_used"
    after = call(svc, "GET", f"/v1/exports/{eid}", p)
    assert after.body["download_url"] is None and after.body["downloaded_at"] is not None

    fresh = call(svc, "POST", f"/v1/exports/{eid}:link", p)
    assert fresh.status == 200 and fresh.body["expires_at"]
    d2 = call(svc, "GET", f"/v1/exports/{eid}/download", None, query=link_query(fresh.body["download_url"]))
    assert d2.status == 200 and d2.raw == d.raw
    assert audits(t).count("export.download") == 2 and "export.create" in audits(t) and "export.link" in audits(t)

    # the downloaded package verifies offline with the published key, the authority's root and an anchor
    bundle = unzip(d.raw, tmp_path / "pkg")
    pub = tmp_path / "pub.pem"
    pub.write_bytes(svc._signer.public_key_pem())
    from .support import head_anchor

    proc = run_verifier(bundle, throwaway_tsa.ca, pub, t_anchor=head_anchor(t, t.a))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_second_link_is_dead_once_the_package_was_downloaded_after_it_was_issued(world, tmp_path):
    t, svc = world, make_service(world, tmp_path)
    p = admin(t.a)
    eid = create(svc, t.a, p=p).body["export_id"]
    first = call(svc, "POST", f"/v1/exports/{eid}:link", p).body["download_url"]
    second = call(svc, "POST", f"/v1/exports/{eid}:link", p).body["download_url"]
    assert call(svc, "GET", f"/v1/exports/{eid}/download", None, query=link_query(first)).status == 200
    late = call(svc, "GET", f"/v1/exports/{eid}/download", None, query=link_query(second))
    assert late.status == 410 and late.body["error"] == "export_link_used"


def test_an_expired_or_forged_link_is_refused(world, tmp_path):
    t = world
    now = [1_800_000_000.0]
    from datetime import datetime, timezone

    clock = lambda: datetime.fromtimestamp(now[0], timezone.utc)
    svc = make_service(t, tmp_path, clock=clock)
    p = admin(t.a)
    eid = create(svc, t.a, p=p).body["export_id"]
    url = call(svc, "POST", f"/v1/exports/{eid}:link", p).body["download_url"]
    q = link_query(url)
    forged = {"link": q["link"][:-4] + ("AAAA" if not q["link"].endswith("AAAA") else "BBBB")}
    assert call(svc, "GET", f"/v1/exports/{eid}/download", None, query=forged).body["error"] == "export_link_invalid"
    assert call(svc, "GET", f"/v1/exports/{eid}/download", None, query={}).body["error"] == "export_link_invalid"
    other = str(uuid.uuid4())
    assert call(svc, "GET", f"/v1/exports/{other}/download", None, query=q).body["error"] == "export_link_invalid"
    now[0] += 901
    gone = call(svc, "GET", f"/v1/exports/{eid}/download", None, query=q)
    assert gone.status == 403 and gone.body["error"] == "export_link_invalid"


def test_the_cache_is_encrypted_under_the_contact_key(world, tmp_path):
    t, svc = world, make_service(world, tmp_path)
    eid = create(svc, t.a).body["export_id"]
    objs = list((tmp_path / "store").rglob("*.pkg"))
    assert len(objs) == 1
    raw = objs[0].read_bytes()
    assert PHONE.encode() not in raw and b"PK\x03\x04" not in raw and b"evidence.json" not in raw
    # erasing the contact (its key row) makes the cached package unreadable
    with t.superuser() as su:
        su.execute("DELETE FROM consentvault.contact_key WHERE org_id = %s", (t.a.org_id,))
    p = admin(t.a)
    r = call(svc, "POST", f"/v1/exports/{eid}:link", p)
    assert r.status == 410 and r.body["error"] == "export_expired"
    assert create(svc, t.a, p=p).body["error"] == "no_records"


def test_roles_and_scopes(world, tmp_path):
    t, svc = world, make_service(world, tmp_path)
    org = t.a
    dev = Principal(org.org_id, uuid.uuid4(), "portal", role="developer")
    viewer = Principal(org.org_id, uuid.uuid4(), "portal", role="compliance_viewer")
    proof = Principal(org.org_id, uuid.uuid4(), "machine", scopes=frozenset({"proof_read"}))
    gate = Principal(org.org_id, uuid.uuid4(), "machine", scopes=frozenset({"gate_read", "capture"}))
    r = create(svc, org, p=dev)
    assert r.status == 403 and r.body["error"] == "role_not_allowed" and r.body["fields"] == {"role": "developer"}
    assert create(svc, org, p=gate).status == 403
    assert create(svc, org, p=viewer).status == 202
    ok = create(svc, org, p=proof)
    assert ok.status == 202
    eid = ok.body["export_id"]
    # second-wave review: the creating credential reads its own export's status and link; list and resume stay portal
    for method, path in (("GET", "/v1/exports"), ("POST", f"/v1/exports/{eid}:resume")):
        assert call(svc, method, path, proof).status == 403, path
    assert call(svc, "GET", "/v1/exports", None).body["error"] == "unauthenticated"
    assert call(svc, "GET", "/v1/exports", dev).status == 403
    assert call(svc, "GET", "/v1/other", viewer) is None


def test_validation_and_named_refusals(world, tmp_path):
    t, svc = world, make_service(world, tmp_path)
    p = admin(t.a)
    assert call(svc, "POST", "/v1/exports", p, None).body["error"] == "invalid_request"
    assert call(svc, "POST", "/v1/exports", p, {}).body["error"] == "validation_failed"
    r = create(svc, t.a, "not a phone", p)
    assert r.status == 422 and r.body["error"] == "invalid_contact" and "not a phone" not in json.dumps(r.body)
    n = create(svc, t.a, "+15555550123", p)
    assert n.status == 404 and n.body["error"] == "no_records" and "5555550123" not in json.dumps(n.body)
    assert call(svc, "GET", f"/v1/exports/{uuid.uuid4()}", p).body["error"] == "not_found"
    assert call(svc, "DELETE", "/v1/exports", p).status == 405
    with t.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.export_job").fetchone()["n"] == 0


def test_a_suspended_organization_pauses_exports(world, tmp_path):
    t, svc = world, make_service(world, tmp_path)
    p = admin(t.a)
    eid = create(svc, t.a, p=p).body["export_id"]
    with t.superuser() as su:
        su.execute("UPDATE consentvault.organization SET status = 'suspended' WHERE org_id = %s", (t.a.org_id,))
    for r in (create(svc, t.a, p=p), call(svc, "POST", f"/v1/exports/{eid}:link", p),
              call(svc, "POST", f"/v1/exports/{eid}:resume", p)):
        assert r.status == 403 and r.body["error"] == "org_suspended"
    assert call(svc, "GET", f"/v1/exports/{eid}", p).body["download_url"] is None
    with t.superuser() as su:
        su.execute("UPDATE consentvault.organization SET status = 'closed' WHERE org_id = %s", (t.a.org_id,))
    assert create(svc, t.a, p=p).body["error"] == "org_not_active"


def test_an_unavailable_organization_key_creates_nothing(world, tmp_path):
    t, svc = world, make_service(world, tmp_path)
    t.provider.fp_secrets.pop(t.a.org_id)
    t.crypto.forget(t.a.org_id)
    r = create(svc, t.a)
    assert r.status == 503 and r.body["error"] == "key_unavailable"
    with t.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.export_job").fetchone()["n"] == 0


def test_progress_is_visible_while_building_and_a_failed_build_resumes(world, tmp_path):
    t = world
    held = []
    store_inner = make_service(t, tmp_path).__dict__["_store"]
    failing = FailingOnce(store_inner, EvidenceStoreError("disk full"))
    svc = make_service(t, tmp_path, store=failing, dispatch=held.append)
    p = admin(t.a)
    eid = create(svc, t.a, p=p).body["export_id"]
    s = call(svc, "GET", f"/v1/exports/{eid}", p)
    assert s.body["status"] == "building" and s.body["progress"] == {"done": 0, "total": 4}
    assert s.body["download_url"] is None
    assert call(svc, "POST", f"/v1/exports/{eid}:resume", p).body["error"] == "export_not_resumable"
    held.pop()()  # the build runs and the store refuses the write
    f = call(svc, "GET", f"/v1/exports/{eid}", p)
    assert f.body["status"] == "failed" and f.body["failed_cause"] == "export_storage_failed"
    assert f.body["progress"]["done"] == 3 and f.body["download_url"] is None
    assert call(svc, "POST", f"/v1/exports/{eid}:link", p).body["error"] == "export_not_ready"
    r = call(svc, "POST", f"/v1/exports/{eid}:resume", p)
    assert r.status == 202 and r.body == {"export_id": eid, "status": "building"}
    held.pop()()
    done = call(svc, "GET", f"/v1/exports/{eid}", p)
    assert done.body["status"] == "ready" and done.body["failed_cause"] is None
    assert "export.resume" in audits(t)


def test_a_signer_that_fails_marks_the_job_failed_by_name(world, tmp_path):
    class Broken:
        key_id, key_version = "broken", 1

        def sign(self, message):
            raise RuntimeError("kms is down")

    svc = make_service(world, tmp_path, signer=Broken())
    p = admin(world.a)
    eid = create(svc, world.a, p=p).body["export_id"]
    f = call(svc, "GET", f"/v1/exports/{eid}", p).body
    assert f["status"] == "failed" and f["failed_cause"] == "signing_unavailable"


def test_a_crash_after_the_cache_write_resumes_from_the_stored_copy(world, tmp_path):
    t = world
    svc = make_service(t, tmp_path)
    p = admin(t.a)
    eid = create(svc, t.a, p=p).body["export_id"]
    with t.superuser() as su:  # the job row is marked failed again, as if finalize had never run
        su.execute("UPDATE consentvault.export_job SET status = 'failed', failed_cause = 'internal_error',"
                   " package_sha256 = NULL, package_object_key = NULL, signature = NULL, expires_at = NULL,"
                   " completed_at = now() WHERE export_id = %s", (eid,))
    assert call(svc, "POST", f"/v1/exports/{eid}:resume", p).status == 202
    done = call(svc, "GET", f"/v1/exports/{eid}", p).body
    assert done["status"] == "ready"
    d = call(svc, "GET", f"/v1/exports/{eid}/download", None, query=link_query(done["download_url"]))
    assert d.status == 200 and hashlib.sha256(d.raw).hexdigest() == done["sha256"]


def test_the_list_pages_filters_and_shows_no_contact_point(world, tmp_path):
    t, svc = world, make_service(world, tmp_path)
    p = admin(t.a)
    ids = [create(svc, t.a, p=p).body["export_id"] for _ in range(3)]
    page1 = call(svc, "GET", "/v1/exports", p, query={"limit": "2"}).body
    assert len(page1["items"]) == 2 and page1["next_cursor"]
    page2 = call(svc, "GET", "/v1/exports", p, query={"limit": "2", "cursor": page1["next_cursor"]}).body
    assert len(page2["items"]) == 1 and page2["next_cursor"] is None
    seen = [i["export_id"] for i in page1["items"] + page2["items"]]
    assert sorted(seen) == sorted(ids)
    times = [i["created_at"] for i in page1["items"] + page2["items"]]
    assert times == sorted(times, reverse=True)
    blob = json.dumps(page1) + json.dumps(page2)
    assert "5555550142" not in blob and all(len(i["contact_fp_hint"]) == 8 for i in page1["items"])
    assert call(svc, "GET", "/v1/exports", p, query={"status": "failed"}).body["items"] == []
    assert call(svc, "GET", "/v1/exports", p, query={"status": "bogus"}).body["error"] == "validation_failed"
    assert call(svc, "GET", "/v1/exports", p, query={"limit": "500"}).status == 422
    assert call(svc, "GET", "/v1/exports", p, query={"cursor": "garbage"}).body["error"] == "invalid_cursor"
    assert call(svc, "GET", "/v1/exports", p, query={"from": "yesterday"}).body["error"] == "validation_failed"



def test_the_machine_credential_that_created_an_export_reads_its_status_and_link(world, tmp_path):
    t, svc = world, make_service(world, tmp_path)
    org = t.a
    mine = Principal(org.org_id, uuid.uuid4(), "machine", scopes=frozenset({"proof_read"}))
    other = Principal(org.org_id, uuid.uuid4(), "machine", scopes=frozenset({"proof_read"}))
    foreign = Principal(t.b.org_id, mine.actor_id, "machine", scopes=frozenset({"proof_read"}))
    eid = create(svc, org, p=mine).body["export_id"]
    got = call(svc, "GET", f"/v1/exports/{eid}", mine)
    assert got.status == 200 and got.body["status"] == "ready", got.body
    link = call(svc, "POST", f"/v1/exports/{eid}:link", mine)
    assert link.status == 200 and link.body["download_url"]
    for p in (other, foreign):  # another credential of the same org, or the same id in another org: absent
        for method, path in (("GET", f"/v1/exports/{eid}"), ("POST", f"/v1/exports/{eid}:link")):
            r = call(svc, method, path, p)
            assert (r.status, r.body["error"]) == (404, "not_found"), (path, r.body)
    portal = call(svc, "GET", f"/v1/exports/{eid}", admin(org))
    assert portal.status == 200  # portal readers still see every export of their org


def test_no_request_line_or_query_string_reaches_a_log():
    """The download link is the credential and rides in the query string: the vault logs no request line and the
    edge logs nothing at all (contracts/README.md, proxies: scrub the query string)."""
    import inspect
    from pathlib import Path as _P

    from consentvault import api
    src = inspect.getsource(api._CloudHandler.log_message)
    assert src.rstrip().endswith("pass")
    edge = _P(__file__).resolve().parents[2] / "edge" / "src"
    for f in edge.glob("*.ts"):
        assert "console." not in f.read_text(), f
