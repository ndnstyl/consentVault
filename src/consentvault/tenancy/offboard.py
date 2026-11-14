"""Offboarding: final export, credential revoke, organisation key destruction scheduled at least 30 days out, tenant
admins notified, destruction record.

Order, each step guarding the next (``run_offboard``):
1. the organisation moves to ``offboarding`` through ``admin.set_org_status`` (capture and gate credentials stop), and
   an open key rotation is cancelled first (``key_rotation.cancel_open_rotation``: the rotation reads ``cancelled``, a
   ``rotation_cancelled`` step names it, and the rotation job never picks it up again; every version is then scheduled
   for destruction with the rest);
2. the final export of every person's evidence is built, sealed under a fresh data key wrapped by the organisation key
   (so it dies with that key), written to the archive store, and its digest recorded. Only from here does the
   organisation leave the sync and anchor jobs (``consentvault.evidence_org_ids``);
3. every credential is revoked;
3b. the final export is delivered and the delivery recorded. The key provider makes the organisation key unusable the
   moment destruction is scheduled, so an export not delivered by then could never be read. Either the operator hands
   it over (``deliver``; the operator's read of the package needs an open, unexpired operator access record), or the
   admins get a one-time link (``links``): the download needs a signed-in admin of the organisation with the link, and
   the delivery is recorded only when that admin confirms the digest of the full body they received
   (``confirm_final_export``). A link spent without a confirmed delivery is replaced on the next run. Until a delivery
   is recorded the run stops with the visible step ``awaiting_delivery`` and schedules nothing;
4. under the lifecycle lock, any active legal hold queues the destruction (a visible ``held`` step and a ``held``
   destruction record); otherwise the key provider schedules destruction with a window of at least 30 days and the
   database records ``scheduled_destroy`` (the database refuses it under a hold);
5. a destruction record is written; the tenant admins are notified. A notice that cannot be sent is a named error and
   a ``failed`` step, with the destruction still cancellable inside its window.

``complete_destructions`` is the job that cancels any scheduled destruction a hold now covers, lets the provider destroy
what is due, and records each destruction.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import uuid
import zipfile
from datetime import datetime, timedelta
from typing import Any, Callable, Optional

import psycopg
from psycopg import sql
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import dbclock
from ..safelog import describe
from . import admin
from .admin_base import ROLE_ADMIN, ApiError, Ctx, body_dict, iso, need_text, to_uuid
from .erasure import LifecycleError, audit_org, audit_platform, held_note, operator_org
from .tokens import TokenKey

MIN_WINDOW_DAYS = 30
FINAL_EXPORT_RETAIN_DAYS = 400
EXPORT_STATEMENT = ("Evidence held for this organization at the time of offboarding: records and their integrity data. "
                    "It is evidence, not a legal determination about any contact.")


class OffboardNoticeError(LifecycleError):
    """The tenant admins could not be told; the step is recorded as failed and the destruction stays cancellable."""


class DestructionError(LifecycleError):
    """The key provider and the database disagree about a destruction; the message names what each holds."""


# ---- client admin: ask -------------------------------------------------------------------------------------------------------
def request_offboarding(ctx: Ctx, body: Any) -> dict:
    """POST /v1/offboarding-requests (admin): asks the operator to begin; changes nothing else."""
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    reason = need_text(b, "reason", max_len=500)
    name = need_text(b, "org_name", max_len=200)
    org = ctx.conn.execute("SELECT name FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())"
                           ).fetchone()
    if org is None or org["name"] != name:
        raise ApiError("org_name_mismatch", "the typed organization name does not match")
    rid = uuid.uuid4()
    try:
        with ctx.conn.transaction():
            row = ctx.conn.execute(
                "INSERT INTO consentvault.offboarding_request (org_id, request_id, reason, requested_by)"
                " VALUES ((SELECT consentvault.current_org()), %s, %s, %s) RETURNING requested_at",
                (rid, reason, ctx.actor.member_uuid)).fetchone()
    except psycopg.errors.UniqueViolation:
        raise ApiError("offboarding_already_requested", "an offboarding request is already open") from None
    audit_org(ctx.conn, actor_kind=ctx.actor.kind, actor_id=ctx.actor.id, action="offboarding.requested",
              target_kind="offboarding", target_id=rid, reason=reason, request_id=ctx.request_id)
    return {"request_id": str(rid), "state": "requested", "requested_at": iso(row["requested_at"])}


def restore_scheduled_versions(conn) -> None:
    """Inside the entered organisation: a cancelled destruction puts every version back as offboarding found it (an
    active version active, a version a rotation retired or kept for the ledger as it was)."""
    conn.execute("UPDATE consentvault.org_key SET status = coalesce(pre_schedule_status, 'active'), destroy_after = pre_schedule_destroy_after, pre_schedule_status = NULL, pre_schedule_destroy_after = NULL WHERE org_id = (SELECT consentvault.current_org()) AND status = 'scheduled_destroy'")


def cancel_open_rotation(conn, *, actor_id: str, request_id: str) -> Optional[str]:
    """Inside the entered organisation: cancel its open key rotation for offboarding (``key_rotation``, imported here
    because key_rotation reads holds, which reads this module)."""
    from .key_rotation import cancel_open_rotation as cancel

    return cancel(conn, actor_id=actor_id, request_id=request_id)


def _open_request(conn, *, lock: bool = True) -> Optional[dict]:
    return conn.execute("SELECT * FROM consentvault.offboarding_request WHERE org_id = (SELECT consentvault.current_org())"
                        " AND state <> 'complete'" + (" FOR UPDATE" if lock else "")).fetchone()


def _step_sql(cols) -> sql.Composed:
    sets = sql.SQL("").join(sql.SQL(", {} = %s").format(sql.Identifier(c)) for c in cols)
    return sql.SQL("UPDATE consentvault.offboarding_request SET steps = steps || jsonb_build_object(%s::text, %s::jsonb)"
                   "{} WHERE org_id = (SELECT consentvault.current_org()) AND request_id = %s").format(sets)


def _step(conn, request_id, name: str, value: dict, **cols) -> None:
    conn.execute(_step_sql(cols), (name, json.dumps(value), *cols.values(), request_id))


def _record_sql(cols) -> sql.Composed:
    names = sql.SQL("").join(sql.SQL(", {}").format(sql.Identifier(c)) for c in cols)
    marks = sql.SQL("").join(sql.SQL(", %s") for _ in cols)
    return sql.SQL("INSERT INTO consentvault.destruction_record (org_id, record_id, request_id, kind{})"
                   " VALUES ((SELECT consentvault.current_org()), %s, %s, %s{})").format(names, marks)


def _record(conn, request_id, kind: str, **cols) -> str:
    rid = uuid.uuid4()
    conn.execute(_record_sql(cols),
                 (rid, request_id, kind, *[json.dumps(v) if isinstance(v, dict) else v for v in cols.values()]))
    return str(rid)


def any_hold(conn) -> Optional[str]:
    """Any active hold of the entered organisation (contact-scope holds block the organisation key too)."""
    row = conn.execute("SELECT hold_id FROM consentvault.legal_hold WHERE org_id = (SELECT consentvault.current_org())"
                       " AND released_at IS NULL ORDER BY set_at, hold_id LIMIT 1").fetchone()
    return None if row is None else str(row["hold_id"])


# ---- the final export --------------------------------------------------------------------------------------------------------
def build_final_export(conn, crypto, signer, *, now: datetime) -> tuple[bytes, dict]:
    """Every person's evidence package for the entered organisation (admin scope), one folder per fingerprint.
    Erased contacts are counted, never silently left out."""
    from ..evidence import NoRecordsError, build_tenant_files, gather_tenant

    fps = [r["contact_fp"] for r in conn.execute(
        "SELECT DISTINCT contact_fp FROM consentvault.event WHERE org_id = (SELECT consentvault.current_org())"
        " AND contact_fp IS NOT NULL ORDER BY contact_fp")]
    buf, counts = io.BytesIO(), {"contacts": 0, "erased": 0}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for fp in fps:
            try:
                result, tokens = gather_tenant(conn, crypto, fp)
            except NoRecordsError:  # loud-failure-exempt: an erased contact has no readable records; it is counted
                counts["erased"] += 1
                continue
            for name, data in sorted(build_tenant_files(result, tokens, signer, generated_at=now).items()):
                z.writestr(f"contacts/{fp}/{name}", data)
            counts["contacts"] += 1
        z.writestr("manifest.json", json.dumps({"generated_at": now.isoformat(), **counts,
                                                "statement": EXPORT_STATEMENT}, sort_keys=True))
    return buf.getvalue(), counts


def _seal_export(custody, org, request_id, package: bytes) -> tuple[bytes, bytes]:
    from ..providers.errors import KeyProviderError

    dk = os.urandom(32)
    try:
        wrapped = custody.wrap(str(org), dk)
    except KeyProviderError as exc:
        raise ApiError("key_unavailable", f"the organization key could not seal the final export ({type(exc).__name__})"
                       ) from exc
    nonce = os.urandom(12)
    return wrapped, nonce + AESGCM(dk).encrypt(nonce, package, f"{org}:{request_id}:final_export".encode())


def read_final_export(conn, *, token_key: TokenKey, custody, store, org_id, operator_id: str) -> bytes:
    """The operator's delivery read of the final export (before the key is destroyed). Needs the operator's open,
    unexpired access record in the organisation (``legal_process.require_open_access``)."""
    from .legal_process import require_open_access

    with operator_org(conn, token_key, org_id) as org:
        require_open_access(conn, operator_id)
    return _read_export(conn, token_key=token_key, custody=custody, store=store, org_id=org)


def _read_export(conn, *, token_key: TokenKey, custody, store, org_id) -> bytes:
    from ..providers.errors import KeyProviderError, ProviderError

    with operator_org(conn, token_key, org_id) as org:
        r = conn.execute("SELECT request_id, final_export_key, final_export_wrapped, final_export_sha256"
                         " FROM consentvault.offboarding_request WHERE org_id = (SELECT consentvault.current_org())"
                         " AND final_export_at IS NOT NULL ORDER BY requested_at DESC LIMIT 1").fetchone()
    if r is None:
        raise ApiError("not_found", "no final export has been taken for this organization")
    try:
        blob = store.get(str(org), r["final_export_key"])
        dk = custody.unwrap(str(org), bytes(r["final_export_wrapped"]))
    except KeyProviderError as exc:
        raise ApiError("key_unavailable", "the organization key could not open the final export") from exc
    except ProviderError as exc:
        raise LifecycleError(f"the final export could not be read from the archive store: {type(exc).__name__}") from exc
    package = AESGCM(dk).decrypt(blob[:12], blob[12:], f"{org}:{r['request_id']}:final_export".encode())
    if not hmac.compare_digest(hashlib.sha256(package).hexdigest(), str(r["final_export_sha256"])):
        raise LifecycleError("the final export does not match the digest recorded when it was taken")
    return package


# ---- notices -----------------------------------------------------------------------------------------------------------------
def admin_emails(conn) -> list[str]:
    return [r["email_norm"] for r in conn.execute(
        "SELECT email_norm FROM consentvault.member WHERE org_id = (SELECT consentvault.current_org())"
        " AND role = 'admin' AND email_norm IS NOT NULL ORDER BY email_norm")]


def notify_admins(conn, notifier, *, event: str, review_url: str) -> int:
    """Send ``security_alert`` to every admin of the entered organisation. Raises ``OffboardNoticeError`` by name."""
    from ..notify.errors import NotifyRefused, SendFailed

    if notifier is None:
        raise OffboardNoticeError("no notifier is configured; the tenant admins cannot be told")
    to = admin_emails(conn)
    if not to:
        raise OffboardNoticeError("the organization has no admin with an email address on record")
    company = conn.execute("SELECT name FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())"
                           ).fetchone()["name"]
    for addr in to:
        try:
            notifier.send("security_alert", addr, {"company": company, "event": event,
                                                    "when": dbclock.now(conn).strftime("%Y-%m-%d %H:%M UTC"),
                                                    "review_url": review_url})
        except (SendFailed, NotifyRefused) as exc:
            raise OffboardNoticeError(f"a tenant admin notice could not be sent ({type(exc).__name__})") from exc
    return len(to)


# ---- key destruction ---------------------------------------------------------------------------------------------------------
def schedule_key_destruction(conn, *, custody, request: dict, window_days: int, actor_kind: str, actor_id: str,
                             request_id: str) -> dict:
    """Inside the entered organisation: queue under a hold, or schedule with the provider and record it."""
    from ..providers.errors import ProviderError

    conn.execute("SELECT consentvault.lifecycle_lock()")
    org = conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"]
    held = any_hold(conn)
    if held is not None:
        # the step and the audit row are tenant-readable: a neutral held state; the record keeps the hold id
        _step(conn, request["request_id"], "key_destruction", {"status": "held", "at": iso(dbclock.now(conn))})
        rec = _record(conn, request["request_id"], "held", hold_id=uuid.UUID(held),
                      export_sha256=request["final_export_sha256"])
        audit_org(conn, actor_kind=actor_kind, actor_id=actor_id, action="offboarding.destruction_held",
                  target_kind="offboarding", target_id=request["request_id"], reason=held_note(conn, held),
                  request_id=request_id)
        return {"status": "held", "hold_id": held, "record_id": rec}
    window = max(MIN_WINDOW_DAYS, int(window_days))
    try:
        st = custody.status(str(org))
        if st.state == "destroyed":
            raise DestructionError(f"the provider reports the key of {org} already destroyed")
        # pending with no date: a provider that records its schedule before asking KMS crashed in between; scheduling
        # again finishes it (the provider resumes what it recorded) and returns the real date
        if st.state != "pending" or st.destroy_at is None:
            st = custody.schedule_destruction(str(org), window_days=window)
        if st.destroy_at is None:
            raise DestructionError(f"the provider scheduled destruction of {org} but returned no destruction date")
    except ProviderError as exc:  # a refusal, a throttle, an unreachable service or a missing setting alike
        raise ApiError("key_unavailable", f"the key provider did not schedule destruction ({type(exc).__name__})") from exc
    try:
        with conn.transaction():
            refs = [r["kms_key_ref"] for r in conn.execute(
                "UPDATE consentvault.org_key SET"
                " pre_schedule_status = CASE WHEN status = 'scheduled_destroy' THEN pre_schedule_status ELSE status END,"
                " pre_schedule_destroy_after = CASE WHEN status = 'scheduled_destroy' THEN pre_schedule_destroy_after"
                "  ELSE destroy_after END, status = 'scheduled_destroy', destroy_after = %s"
                " WHERE org_id = (SELECT consentvault.current_org())"
                " AND status IN ('active', 'retired', 'retained_for_ledger', 'retained_for_backup', 'scheduled_destroy')"
                " RETURNING kms_key_ref", (st.destroy_at,))]
    except psycopg.Error as exc:
        try:
            custody.cancel_destruction(str(org))
        except ProviderError as cexc:
            raise DestructionError(f"the provider scheduled destruction of {org} but the database refused to record it "
                                   f"({type(exc).__name__}) and the cancel failed ({type(cexc).__name__}): cancel it "
                                   f"by hand before {iso(st.destroy_at)}") from exc
        raise DestructionError(f"the database refused to record the destruction ({type(exc).__name__}); the provider "
                               "schedule was cancelled") from exc
    rec = _record(conn, request["request_id"], "scheduled", key_refs=refs, destroy_after=st.destroy_at,
                  export_sha256=request["final_export_sha256"], detail={"window_days": window})
    _step(conn, request["request_id"], "key_destruction", {"status": "scheduled", "destroy_after": iso(st.destroy_at),
                                                           "window_days": window})
    _step(conn, request["request_id"], "destruction_record", {"status": "done", "record_id": rec},
          destroy_after=st.destroy_at)
    audit_org(conn, actor_kind=actor_kind, actor_id=actor_id, action="offboarding.destruction_scheduled",
              target_kind="offboarding", target_id=request["request_id"],
              reason=f"destroy after {iso(st.destroy_at)}", request_id=request_id)
    return {"status": "scheduled", "destroy_after": iso(st.destroy_at), "record_id": rec}


def run_offboard(conn: psycopg.Connection, *, token_key: TokenKey, custody, crypto, signer, store, notifier,
                 operator_id: str, request_id: str, org_id, reason: Optional[str] = None,
                 window_days: int = MIN_WINDOW_DAYS, review_url: str = "https://app.consentvault.ai/settings",
                 clock: Optional[Callable[[], datetime]] = None,
                 deliver: Optional[Callable[[Any, Any, bytes, str], None]] = None, links=None) -> dict:
    """POST /v1/orgs/{id}/offboard (operator). Re-runnable: each step that is done is not repeated.

    ``deliver(org_id, request_id, package, sha256)`` hands the final export to the tenant admin (a one-time link in the
    managed service); it must raise on failure. With ``links`` (the evidence ``ExportService``) instead, the run mails the
    admins a one-time download link and stops at ``awaiting_delivery``; the delivery record is written when the admin
    downloads the package (``download_final_export``), and a later run then schedules destruction."""
    from ..providers.errors import ProviderError

    with operator_org(conn, token_key, org_id) as org:
        status = conn.execute("SELECT status FROM consentvault.organization"
                              " WHERE org_id = (SELECT consentvault.current_org())").fetchone()
    if status is None:
        raise ApiError("not_found", "no such organization")
    if status["status"] == "closed":
        raise ApiError("org_not_active", "the organization is closed")
    if status["status"] != "offboarding":
        admin.set_org_status(conn, token_key=token_key, operator_id=operator_id, request_id=request_id, org_id=org,
                             status="offboarding", reason=(reason or "offboarding run")[:500])

    with operator_org(conn, token_key, org):
        req = _open_request(conn)
        if req is None:
            conn.execute("INSERT INTO consentvault.offboarding_request (org_id, request_id, reason, requested_by_operator)"
                         " VALUES ((SELECT consentvault.current_org()), %s, %s, %s)",
                         (uuid.uuid4(), (reason or "operator offboarding")[:500], operator_id))
            req = _open_request(conn)
        conn.execute("UPDATE consentvault.offboarding_request SET state = 'in_progress'"
                     " WHERE org_id = (SELECT consentvault.current_org()) AND request_id = %s", (req["request_id"],))
        # first: an open key rotation is cancelled (visibly), so no job pass re-wraps or destroys under an offboarding
        cancelled = cancel_open_rotation(conn, actor_id=operator_id, request_id=request_id)
        if cancelled is not None:
            _step(conn, req["request_id"], "rotation_cancelled", {"status": "done", "at": iso(dbclock.now(conn)),
                                                                  "rotation_id": cancelled})
        audit_platform(conn, operator_id=operator_id, action="offboarding.run", target_kind="org", target_id=org,
                       reason=reason, request_id=request_id)
    rid = req["request_id"]

    if clock is None:
        clock = lambda: dbclock.now(conn)   # noqa: E731  the database's clock; tests inject a pinned one
    if req["final_export_at"] is None:  # step 2
        now = clock()
        with operator_org(conn, token_key, org):
            package, counts = build_final_export(conn, crypto, signer, now=now)
        digest = hashlib.sha256(package).hexdigest()
        wrapped, blob = _seal_export(custody, org, rid, package)
        key = f"offboarding/{rid}/final-export-{uuid.uuid4()}.bin"
        try:
            store.put(str(org), key, blob, retain_until=now + timedelta(days=FINAL_EXPORT_RETAIN_DAYS))
        except ProviderError as exc:
            raise LifecycleError(f"the final export could not be written to the archive store ({type(exc).__name__}); "
                                 "nothing was revoked or scheduled") from exc
        with operator_org(conn, token_key, org):
            _step(conn, rid, "final_export", {"status": "done", "at": iso(now), "sha256": digest, **counts},
                  final_export_at=now, final_export_sha256=digest, final_export_key=key, final_export_wrapped=wrapped)
            audit_org(conn, actor_kind="operator", actor_id=operator_id, action="offboarding.final_export",
                      target_kind="offboarding", target_id=rid, reason=f"sha256 {digest}", request_id=request_id)

    with operator_org(conn, token_key, org):  # step 3
        revoked = conn.execute(
            "UPDATE consentvault.credential SET revoked_at = clock_timestamp(), revoke_reason = 'organization offboarding'"
            " WHERE org_id = (SELECT consentvault.current_org()) AND revoked_at IS NULL RETURNING credential_id").fetchall()
        _step(conn, rid, "credentials_revoked", {"status": "done", "at": iso(dbclock.now(conn)), "count": len(revoked)})
        audit_org(conn, actor_kind="operator", actor_id=operator_id, action="offboarding.credentials_revoked",
                  target_kind="offboarding", target_id=rid, reason=f"{len(revoked)} revoked", request_id=request_id)

    with operator_org(conn, token_key, org):
        req = _open_request(conn)
    if "final_export_delivered" not in req["steps"]:  # step 3b: no destruction without the delivery record
        if deliver is None:
            with operator_org(conn, token_key, org):
                if links is not None:
                    _ensure_link(conn, links, notifier, req, org, review_url=review_url, operator_id=operator_id,
                                 request_id=request_id, clock=clock)
                _step(conn, rid, "key_destruction", {"status": "awaiting_delivery"})
                return _answer(_open_request(conn, lock=False), org)
        package = read_final_export(conn, token_key=token_key, custody=custody, store=store, org_id=org,
                                    operator_id=operator_id)
        deliver(org, rid, package, req["final_export_sha256"])
        with operator_org(conn, token_key, org):
            _step(conn, rid, "final_export_delivered", {"status": "done", "at": iso(dbclock.now(conn)),
                                                        "sha256": req["final_export_sha256"]})
            audit_org(conn, actor_kind="operator", actor_id=operator_id, action="offboarding.export_delivered",
                      target_kind="offboarding", target_id=rid, reason=None, request_id=request_id)

    with operator_org(conn, token_key, org):  # steps 4 and 5
        req = _open_request(conn)
        done = (req["steps"].get("key_destruction") or {}).get("status") == "scheduled"
        dest = req["steps"]["key_destruction"] if done else schedule_key_destruction(
            conn, custody=custody, request=req, window_days=window_days, actor_kind="operator", actor_id=operator_id,
            request_id=request_id)

    event = ("Offboarding: the final export was taken; destruction of the organization key is on hold"
             if dest["status"] == "held" else
             f"Offboarding: the final export was taken; the organization key is scheduled for destruction after "
             f"{str(dest['destroy_after'])[:10]}")
    failed: Optional[str] = None
    with operator_org(conn, token_key, org):
        try:
            sent = notify_admins(conn, notifier, event=event, review_url=review_url)
        except OffboardNoticeError as exc:  # loud-failure-exempt: recorded as a failed step below and re-raised after commit
            failed, sent = describe(exc), 0
        _step(conn, rid, "admin_notified", {"status": "failed", "cause": failed} if failed else
              {"status": "done", "at": iso(dbclock.now(conn)), "count": sent})
        out = _answer(_open_request(conn, lock=False) or {}, org)
    if failed:
        raise OffboardNoticeError(f"{failed}; the offboarding steps are recorded and the destruction stays cancellable")
    return out


def _ensure_link(conn, links, notifier, req: dict, org, *, review_url: str, operator_id: str, request_id: str,
                 clock) -> None:
    """Inside the entered organisation: issue the one-time download link and mail it to the admins, unless a link is
    already out, unspent and still valid (an expired or spent one is replaced). A notice that cannot be sent is a named
    error."""
    current = req["steps"].get("final_export_link")
    if current and current.get("status") == "sent" and \
            datetime.fromisoformat(current["expires_at"].replace("Z", "+00:00")) > clock():
        return
    link = links.issue_final_export_link(org, req["request_id"])
    notify_admins(conn, notifier, event="Offboarding: your final export is ready. The link below downloads it once; "
                  "after the organization key is destroyed it can never be read again", review_url=link["download_url"])
    _step(conn, req["request_id"], "final_export_link", {"status": "sent", "at": iso(dbclock.now(conn)),
                                                        "expires_at": link["expires_at"]})
    audit_org(conn, actor_kind="operator", actor_id=operator_id, action="offboarding.export_link_issued",
              target_kind="offboarding", target_id=req["request_id"], reason=f"expires {link['expires_at']}",
              request_id=request_id)


def download_final_export(conn: psycopg.Connection, *, links, token_key: TokenKey, custody, store, request_id_str: str,
                          link: str, rid: str, session_org) -> tuple[bytes, str]:
    """The one-time download of the final export by a signed-in admin of the organisation (``session_org``, from the
    verified session) holding the link. The link must name that organisation before it is spent, so another
    organisation's admin can neither read it nor burn it. Spending is recorded at once (step ``final_export_link``:
    ``spent``), so a download that fails is replaced on the next run. The delivery is not recorded here: the admin
    confirms the digest of the full body (``confirm_final_export``); the serve is recorded as
    ``final_export_downloaded`` only once the package was read and matched its recorded digest."""
    from ..evidence import ExportLinkInvalidError

    named = links._read_link(link)  # checks signature and expiry, spends nothing
    if str(named["org"]) != str(session_org) or str(named["export_id"]) != str(request_id_str):
        raise ExportLinkInvalidError("the download link is not for this organization's final export")
    org, nonce = links.claim_final_export_link(request_id_str, link)
    with operator_org(conn, token_key, org):
        req = conn.execute("SELECT request_id, steps FROM consentvault.offboarding_request"
                           " WHERE org_id = (SELECT consentvault.current_org()) AND request_id = %s",
                           (request_id_str,)).fetchone()
        if req is None:
            raise LifecycleError("the link names no offboarding request of this organization")
        sent = req["steps"].get("final_export_link") or {}
        _step(conn, req["request_id"], "final_export_link", {**sent, "status": "spent", "spent_at": iso(dbclock.now(conn)),
                                                             "via": f"link {nonce[:8]}"})
    package = _read_export(conn, token_key=token_key, custody=custody, store=store, org_id=org)
    sha = hashlib.sha256(package).hexdigest()
    with operator_org(conn, token_key, org):
        want = conn.execute("SELECT final_export_sha256 FROM consentvault.offboarding_request"
                            " WHERE org_id = (SELECT consentvault.current_org()) AND request_id = %s",
                            (request_id_str,)).fetchone()
        if want is None or want["final_export_sha256"] != sha:
            raise LifecycleError("the final export does not match the request the link names")
        _step(conn, req["request_id"], "final_export_downloaded", {"status": "served", "at": iso(dbclock.now(conn)),
                                                                   "sha256": sha, "via": f"link {nonce[:8]}"})
    return package, sha


def confirm_final_export(conn: psycopg.Connection, *, token_key: TokenKey, session_org, request_id_str: str, sha256,
                         actor_kind: str, actor_id: str, rid: str) -> dict:
    """POST /v1/offboarding/{id}/final-export:confirm (signed-in admin of the organisation): the admin states the sha256
    of the body they received. The delivery is recorded only when it matches the export taken and the package was
    served through a link."""
    if not isinstance(sha256, str) or len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        raise ApiError("validation_failed", "the sha256 of the downloaded file, 64 lowercase hex", {"sha256": "64 hex"})
    with operator_org(conn, token_key, session_org):
        req = conn.execute("SELECT * FROM consentvault.offboarding_request WHERE org_id ="
                           " (SELECT consentvault.current_org()) AND request_id = %s AND state <> 'complete' FOR UPDATE",
                           (to_uuid(request_id_str, "offboarding request"),)).fetchone()
        if req is None:
            raise ApiError("not_found", "no open offboarding request with that id in this organization")
        if "final_export_delivered" in req["steps"]:
            return {"request_id": str(req["request_id"]), "final_export_delivered": req["steps"]["final_export_delivered"]}
        served = req["steps"].get("final_export_downloaded") or {}
        if served.get("status") != "served":
            raise ApiError("validation_failed", "the final export has not been downloaded with its link yet",
                           {"final_export": "not downloaded"})
        if sha256 != req["final_export_sha256"]:
            raise ApiError("validation_failed", "the digest does not match the final export; download it again with "
                           "a new link", {"sha256": "mismatch"})
        done = {"status": "done", "at": iso(dbclock.now(conn)), "sha256": sha256, "via": served.get("via"),
                "confirmed_by": actor_id}
        _step(conn, req["request_id"], "final_export_delivered", done)
        audit_org(conn, actor_kind=actor_kind, actor_id=actor_id, action="offboarding.export_delivered",
                  target_kind="offboarding", target_id=req["request_id"], reason=f"sha256 {sha256} confirmed",
                  request_id=rid)
    return {"request_id": str(req["request_id"]), "final_export_delivered": done}


def _answer(req: dict, org) -> dict:
    return {"org_id": str(org), "request_id": str(req.get("request_id")), "state": req.get("state"),
            "steps": req.get("steps") or {}, "destroy_after": iso(req.get("destroy_after"))}


def complete_destructions(conn: psycopg.Connection, *, token_key: TokenKey, custody, request_id: str,
                          notifier=None, review_url: str = "https://app.consentvault.ai/settings") -> dict:
    """The destruction job. Cancels every pending destruction a hold now covers (before the provider runs), lets the
    provider destroy what is due, then records each destruction and completes the request."""
    from ..providers.errors import KeyProviderError

    held, destroyed = [], []
    orgs = [r["o"] for r in conn.execute("SELECT o FROM consentvault.restore_org_ids() AS o")]
    for org in orgs:
        with operator_org(conn, token_key, org):
            req = _open_request(conn)
            if req is None or (req["steps"].get("key_destruction") or {}).get("status") != "scheduled":
                continue
            hold = any_hold(conn)
            if hold is None:
                continue
            try:
                custody.cancel_destruction(str(org))
            except KeyProviderError as exc:
                raise DestructionError(f"a legal hold covers {org} but its scheduled key destruction could not be "
                                       f"cancelled ({type(exc).__name__}); cancel it by hand now") from exc
            restore_scheduled_versions(conn)
            _step(conn, req["request_id"], "key_destruction", {"status": "held", "at": iso(dbclock.now(conn))})
            _record(conn, req["request_id"], "held", hold_id=uuid.UUID(hold))
            audit_org(conn, actor_kind="system", actor_id="destruction-job", action="offboarding.destruction_held",
                      target_kind="offboarding", target_id=req["request_id"], reason=held_note(conn, hold),
                      request_id=request_id)
            held.append(str(org))
    try:
        due = custody.process_destructions()
    except KeyProviderError as exc:
        raise DestructionError(f"the key provider could not process due destructions ({type(exc).__name__})") from exc
    for org in due:
        with operator_org(conn, token_key, org):
            req = _open_request(conn)
            if req is None:
                raise DestructionError(f"the key of {org} was destroyed with no open offboarding request on record")
            if not custody.is_destroyed(str(org)):
                raise DestructionError(f"the provider listed {org} as destroyed but its key still reads as present")
            refs = [r["kms_key_ref"] for r in conn.execute(
                "UPDATE consentvault.org_key SET status = 'destroyed' WHERE org_id = (SELECT consentvault.current_org())"
                " AND status = 'scheduled_destroy' RETURNING kms_key_ref")]
            rec = _record(conn, req["request_id"], "destroyed", key_refs=refs, export_sha256=req["final_export_sha256"],
                          detail={"provider_reports_destroyed": True, "backups": "unreadable from key deletion; copies "
                                  "age out on their own schedule"})
            _step(conn, req["request_id"], "destroyed", {"status": "done", "at": iso(dbclock.now(conn)), "record_id": rec})
            conn.execute("UPDATE consentvault.offboarding_request SET state = 'complete'"
                         " WHERE org_id = (SELECT consentvault.current_org()) AND request_id = %s", (req["request_id"],))
            audit_org(conn, actor_kind="system", actor_id="destruction-job", action="offboarding.key_destroyed",
                      target_kind="offboarding", target_id=req["request_id"], reason=None, request_id=request_id)
            if notifier is not None:
                notify_admins(conn, notifier, event="Offboarding complete: the organization key was destroyed",
                              review_url=review_url)
        destroyed.append(str(org))
        admin.set_org_status(conn, token_key=token_key, operator_id="destruction-job", request_id=request_id, org_id=org,
                             status="closed", reason="the organization key was destroyed and its destruction record exists")
    return {"held": held, "destroyed": destroyed}
