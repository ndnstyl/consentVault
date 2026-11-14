"""Cross-lane closure: the one-time final-export link gates key destruction, operator routes name the organisation in the
path, lifecycle actions go through audit.py, an organisation closes only after its destruction record exists, hold
reasons are sealed under the organisation key, and a held erasure reads as held."""

import io
import json
import os
import re
import uuid
import zipfile

import pytest

from consentvault import db
from consentvault.evidence import ExportService
from consentvault.tenancy import audit, erasure, holds, offboard
from consentvault.tenancy.admin import set_org_status
from consentvault.tenancy.admin_base import ApiError
from consentvault.tenancy.erasure import LifecycleError, audit_org
from consentvault.tenancy.lifecycle_routes import LifecycleApp, LifecycleRoutes
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from .support import OPERATOR


def _links(env):
    t = env.t
    return ExportService(connect=lambda: db.connect(t.app_dsn),
                         mint_token=lambda o, s: mint_org_token(t.key, o, s, credential_id=None), crypto=t.crypto,
                         signer=env.signer, store=env.archive, link_secret=os.urandom(32), clock=env.clock)


def _run(env, links, org):
    with env.operator() as c:
        return offboard.run_offboard(c, token_key=env.t.key, custody=env.custody, crypto=env.t.crypto,
                                     signer=env.signer, store=env.archive, notifier=env.notifier, operator_id=OPERATOR,
                                     request_id="req-off", org_id=org.org_id, reason="contract ended", clock=env.clock,
                                     links=links)


def _db(env, sql, *args):
    with env.t.superuser() as su:
        return su.execute(sql, args).fetchall()


def _app(env, links):
    t = env.t
    return LifecycleApp(connect=lambda: db.connect(t.app_dsn), owner_connect=lambda: db.connect(t.operator_dsn),
                        token_key=t.key, crypto=t.crypto, custody=env.custody, ledger=env.ledger, store=env.archive,
                        signer=env.signer, notifier=env.notifier, links=links)


def test_destruction_waits_for_the_admin_to_download_the_final_export_once(env):
    t, links = env.t, _links(env)
    out = _run(env, links, t.a)
    assert out["steps"]["key_destruction"] == {"status": "awaiting_delivery"}
    assert out["steps"]["final_export_link"]["status"] == "sent" and "final_export_delivered" not in out["steps"]
    assert env.custody.status(str(t.a.org_id)).state == "active"
    [(template, to, variables)] = env.notifier.sent
    assert to == "admin@alpha.example.com"
    rid = out["request_id"]
    m = re.match(rf"^/v1/offboarding/{rid}/final-export\?link=(.+)$", variables["review_url"])
    assert m, variables

    again = _run(env, links, t.a)  # a link still valid is not replaced, and nobody is mailed twice
    assert again["steps"]["key_destruction"] == {"status": "awaiting_delivery"} and len(env.notifier.sent) == 1

    routes = LifecycleRoutes(_app(env, links), auth=None)
    path = f"/v1/offboarding/{rid}/final-export"
    h = {"X-Request-Id": "req-dl", "Authorization": f"Bearer {env.portal_token(t.a)}"}  # a signed-in admin, and the link
    r = routes.handle("GET", path, headers=h, query={"link": m.group(1)})
    assert r.status == 200 and r.headers["Content-Type"] == "application/zip"
    assert "manifest.json" in zipfile.ZipFile(io.BytesIO(r.raw)).namelist()
    assert r.headers["X-Package-Sha256"] == out["steps"]["final_export"]["sha256"]
    spent = routes.handle("GET", path, headers=h, query={"link": m.group(1)})
    assert (spent.status, spent.payload["error"]) == (410, "export_link_used")
    bad = routes.handle("GET", path, headers=h, query={"link": m.group(1)[:-4] + "AAAA"})
    assert (bad.status, bad.payload["error"]) == (403, "export_link_invalid")
    assert routes.handle("GET", path, headers=h, query={}).payload["error"] == "export_link_invalid"
    assert routes.handle("GET", path, headers={}, query={"link": m.group(1)}).status == 401
    other = routes.handle("GET", f"/v1/offboarding/{uuid.uuid4()}/final-export", headers=h, query={"link": m.group(1)})
    assert other.payload["error"] == "export_link_invalid"  # a link names its own request
    ok = routes.handle("POST", f"/v1/offboarding/{rid}/final-export:confirm", headers=h,
                       body=json.dumps({"sha256": r.headers["X-Package-Sha256"]}).encode())
    assert ok.status == 200  # the delivery is the admin's confirmation of the body received

    done = _run(env, links, t.a)
    assert done["steps"]["final_export_delivered"]["status"] == "done"
    assert done["steps"]["key_destruction"]["status"] == "scheduled"
    assert env.custody.status(str(t.a.org_id)).state == "pending"


def test_operator_lifecycle_routes_name_the_organisation_in_the_path(env):
    routes = LifecycleRoutes(_app(env, None), auth=None)
    org = env.t.a.org_id
    for method, path in (("POST", f"/v1/orgs/{org}/erasures/{uuid.uuid4()}:confirm"),
                         ("POST", f"/v1/orgs/{org}/legal-holds"),
                         ("POST", f"/v1/orgs/{org}/legal-holds/{uuid.uuid4()}:release"),
                         ("POST", f"/v1/orgs/{org}/operator-access"),
                         ("POST", f"/v1/orgs/{org}/operator-access/{uuid.uuid4()}:close")):
        assert routes.handles(method, path), path
    for method, path in (("POST", f"/v1/erasures/{uuid.uuid4()}:confirm"), ("POST", "/v1/operator-access"),
                         ("POST", f"/v1/operator-access/{uuid.uuid4()}:close")):
        assert not routes.handles(method, path), path  # the old paths, which took the organisation from a body, are gone
    assert routes.handles("POST", "/v1/legal-holds")  # a client admin's hold, organisation from its session


def test_every_lifecycle_action_is_in_the_audit_list_and_an_unlisted_one_is_refused(env):
    for action in ("erasure.requested", "erasure.confirmed", "erasure.completed", "erasure.declined", "erasure.held",
                   "legal_hold.set", "legal_hold.released", "legal_process.logged", "legal_process.closed",
                   "legal_process.customer_notified", "legal_process.notice_prohibited", "operator_access.opened",
                   "operator_access.closed", "offboarding.requested", "offboarding.run", "offboarding.final_export",
                   "offboarding.export_link_issued", "offboarding.export_delivered", "offboarding.credentials_revoked",
                   "offboarding.destruction_scheduled", "offboarding.destruction_held", "offboarding.key_destroyed",
                   "restore.begun", "restore.reconciled", "restore.gap", "restore.erasure_replayed",
                   "restore.stop_reingested"):
        assert action in audit.ACTIONS, action
    with env.operator() as c, org_transaction(c, env.t.admin_token(env.t.a.org_id)):
        with pytest.raises(LifecycleError, match=r"AuditError \(code audit_action_unlisted\)"):
            audit_org(c, actor_kind="operator", actor_id="op", action="erasure.invented", target_kind="erasure",
                      target_id=None, reason=None, request_id="req-x")


def test_an_organisation_closes_only_after_its_destruction_record_and_the_job_closes_it(env):
    t = env.t
    env.open_access(t.a)
    with env.operator() as c:
        offboard.run_offboard(c, token_key=t.key, custody=env.custody, crypto=t.crypto, signer=env.signer,
                              store=env.archive, notifier=env.notifier, operator_id=OPERATOR, request_id="req-off",
                              org_id=t.a.org_id, clock=env.clock, deliver=lambda *a: None)
    with env.operator() as c, pytest.raises(ApiError) as e:  # a 'scheduled' record is not a destruction record
        set_org_status(c, token_key=t.key, operator_id=OPERATOR, request_id="req-c", org_id=t.a.org_id,
                       status="closed", reason="early")
    assert e.value.name == "validation_failed" and "destruction record" in e.value.detail
    with env.operator() as c, pytest.raises(ApiError) as e2:  # and an organisation that is not offboarding cannot close
        set_org_status(c, token_key=t.key, operator_id=OPERATOR, request_id="req-c", org_id=t.b.org_id,
                       status="closed", reason="no")
    assert e2.value.name == "validation_failed"
    env.clock.advance(31)
    with env.operator() as c:
        assert offboard.complete_destructions(c, token_key=t.key, custody=env.custody,
                                              request_id="job")["destroyed"] == [str(t.a.org_id)]
    assert _db(env, "SELECT status FROM consentvault.organization WHERE org_id = %s", t.a.org_id)[0]["status"] == "closed"
    assert _db(env, "SELECT status FROM consentvault.organization WHERE org_id = %s", t.b.org_id)[0]["status"] == "active"


def test_hold_reasons_are_sealed_under_the_organisation_key_everywhere_they_are_written(env):
    t = env.t
    secret = "subpoena from the Harbor County court, case 7731"
    with env.operator() as c:
        hold = holds.place_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto,
                                         operator_id=OPERATOR, request_id="req-h", org_id=t.a.org_id, scope="org",
                                         reason=secret)
    row = _db(env, "SELECT hold_id, reason FROM consentvault.legal_hold WHERE org_id = %s", t.a.org_id)[0]
    assert row["reason"].startswith(holds.SEALED_PREFIX) and "subpoena" not in row["reason"]
    assert holds.open_reason(t.crypto, t.a.org_id, row["hold_id"], "legal_hold.reason", row["reason"]) == secret
    with pytest.raises(Exception):  # bound to its organisation and column
        holds.open_reason(t.crypto, t.b.org_id, row["hold_id"], "legal_hold.reason", row["reason"])
    with pytest.raises(Exception):
        holds.open_reason(t.crypto, t.a.org_id, row["hold_id"], "legal_hold.release_reason", row["reason"])
    ledger = json.dumps(env.ledger.entries(t.a.org_id))
    assert "subpoena" not in ledger and holds.SEALED_PREFIX in ledger
    audits = json.dumps(_db(env, "SELECT reason FROM consentvault.audit_event WHERE action = 'legal_hold.set'"))
    assert "subpoena" not in audits and "encrypted under the organization key" in audits
    with env.operator() as c:
        holds.release_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto,
                                    operator_id=OPERATOR, request_id="req-r", org_id=t.a.org_id,
                                    hold_id=hold["hold_id"], reason="matter withdrawn by the court")
    rel = _db(env, "SELECT release_reason FROM consentvault.legal_hold WHERE org_id = %s", t.a.org_id)[0]["release_reason"]
    assert rel.startswith(holds.SEALED_PREFIX) and "withdrawn" not in rel
    assert "withdrawn" not in json.dumps(env.ledger.entries(t.a.org_id))
    with pytest.raises(LifecycleError):  # no key service, no reason: never plaintext
        holds.seal_reason(None, t.a.org_id, uuid.uuid4(), "legal_hold.reason", "x")


def test_an_erasure_a_hold_covers_reads_as_held_naming_only_the_clients_own_hold(env):
    """Gag safety: the client's own hold is named; an operator's hold reads as a neutral held state (no id, no reason)."""
    t = env.t
    with env.admin(t.a) as ctx:
        req = erasure.request_erasure(ctx, {"contact": "+15555550142", "reason": "asked"}, crypto=t.crypto)
    with env.operator() as c:
        hold = holds.place_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto,
                                         operator_id=OPERATOR, request_id="req-h", org_id=t.a.org_id, scope="org",
                                         reason="preserve")
    with env.t.superuser() as su:
        su.execute("UPDATE consentvault.erasure_request SET held_by = %s, held_since = now() WHERE erasure_id = %s",
                   (hold["hold_id"], req["erasure_id"]))
    with env.admin(t.a) as ctx:
        got = erasure.get_erasure(ctx, req["erasure_id"])
    assert got["status"] == "held" and got["held_by"] is None and got["held_reason"] is None
    with env.admin(t.a) as ctx:
        own = holds.place_hold_member(ctx, {"scope": "org", "reason": "keep"}, ledger=env.ledger, crypto=t.crypto)
    with env.t.superuser() as su:
        su.execute("UPDATE consentvault.erasure_request SET held_by = %s WHERE erasure_id = %s",
                   (own["hold_id"], req["erasure_id"]))
    with env.admin(t.a) as ctx:
        got = erasure.get_erasure(ctx, req["erasure_id"])
    assert got["status"] == "held" and got["held_by"] == own["hold_id"] and got["held_reason"] == "legal_hold"
