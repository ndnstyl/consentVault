"""Stop notices in the portal: the pop-up an admin sees on sign-in, its acknowledgement, and the extra recipients.

ConsentVault only notifies. The pop-up lists every stop this admin has not acknowledged (masked contact, channels, purposes, time,
the delivery status of each connected system, a link to the records). It cannot be dismissed without acknowledging: the
acknowledgement is the only call that removes a notice, it removes it for the caller alone, and it is one audit row naming who
and which notices. Notices cannot be switched off: an admin may add recipients, and removing one never removes an admin.
"""

from __future__ import annotations

from typing import Any

import psycopg

from ..notify.stop_notice import read_mask
from ..safelog import describe
from .admin_base import (ROLE_ADMIN, ApiError, Ctx, body_dict, clean_email, email_hint, iso, need_list, require_not_closed,
                         to_uuid)

ACK_MAX = 500
PAGE_LIMIT = 500
RECIPIENTS_MAX = 20
_ORG = "(SELECT consentvault.current_org())"
NOTE = "ConsentVault has recorded this stop. Acting on it in your own systems is up to you."


def _delivery(ctx: Ctx, ids: list) -> dict:
    out: dict = {i: [] for i in ids}
    if ids:
        for r in ctx.conn.execute("SELECT * FROM consentvault.stop_notice_delivery(%s)", (ids,)).fetchall():
            out[r["notice_id"]].append({"system": r["system_name"], "status": r["status"]})
    return out


def list_unacknowledged(ctx: Ctx, crypto) -> dict:
    """At most ``PAGE_LIMIT`` of the signed-in admin's unacknowledged stops (only those recorded after the admin joined), oldest
    first; ``remaining`` counts them all, so the pop-up asks again after each acknowledgement until it is clear."""
    ctx.actor.require(ROLE_ADMIN)
    rows = ctx.conn.execute("SELECT * FROM consentvault.stop_notice_unacknowledged(%s)", (PAGE_LIMIT,)).fetchall()
    org = ctx.org_id()
    delivery = _delivery(ctx, [r["notice_id"] for r in rows])
    return {"note": NOTE, "remaining": rows[0]["total"] if rows else 0, "notices": [
        {"notice_id": str(r["notice_id"]), "contact": read_mask(crypto, org, r["notice_id"], r["masked_ct"]),
         "channels": list(r["channels"]), "purposes": list(r["purposes"]), "stopped_at": iso(r["stopped_at"]),
         "delivery": delivery[r["notice_id"]] or [{"system": None, "status": "none_connected"}],
         "records_path": "/records?has_stop=true"} for r in rows]}


def acknowledge(ctx: Ctx, body: Any) -> dict:
    """Acknowledge the named notices for the signed-in admin (the database reads who that is from the session token)."""
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    ids = [to_uuid(x, "notice") for x in need_list(b, "notice_ids", min_items=1, max_items=ACK_MAX)]
    try:
        done = ctx.conn.execute("SELECT consentvault.stop_notice_acknowledge(%s) AS done", (ids,)).fetchone()["done"]
    except psycopg.Error as exc:
        raise ApiError("service_unavailable", f"the acknowledgement could not be written; nothing was changed ({describe(exc)})") from exc
    if done:
        ctx.audit("stop_notice.acknowledged", "stop_notice", None, detail={"count": len(done), "notice_ids": [str(d) for d in done]})
    left = ctx.conn.execute("SELECT coalesce(max(total), 0) AS n FROM consentvault.stop_notice_unacknowledged(1)").fetchone()["n"]
    return {"acknowledged": len(done), "remaining": left}


def list_recipients(ctx: Ctx) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    rows = ctx.conn.execute(f"SELECT recipient_id, email_norm, created_at FROM consentvault.stop_notice_recipient"
                            f" WHERE org_id = {_ORG} AND removed_at IS NULL ORDER BY created_at, recipient_id").fetchall()
    admins = ctx.conn.execute(f"SELECT count(*) AS n FROM consentvault.member WHERE org_id = {_ORG} AND role = 'admin'").fetchone()["n"]
    return {"admins_always_receive": True, "admin_count": admins,
            "recipients": [{"recipient_id": str(r["recipient_id"]), "email_hint": email_hint(r["email_norm"]),
                            "created_at": iso(r["created_at"])} for r in rows]}


def add_recipient(ctx: Ctx, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    require_not_closed(ctx)
    email = clean_email(body_dict(body).get("email"))
    live = ctx.conn.execute(f"SELECT count(*) AS n FROM consentvault.stop_notice_recipient WHERE org_id = {_ORG}"
                            " AND removed_at IS NULL").fetchone()["n"]
    if live >= RECIPIENTS_MAX:
        raise ApiError("validation_failed", f"at most {RECIPIENTS_MAX} extra recipients", {"email": "too many recipients"})
    try:
        row = ctx.conn.execute(f"INSERT INTO consentvault.stop_notice_recipient (org_id, email_norm, added_by)"
                               f" VALUES ({_ORG}, %s, %s) RETURNING recipient_id", (email, ctx.actor.member_uuid)).fetchone()
    except psycopg.errors.UniqueViolation:
        raise ApiError("validation_failed", "that address already receives stop notices", {"email": "already a recipient"}) from None
    ctx.audit("stop_notice.recipient_added", "stop_notice_recipient", str(row["recipient_id"]))
    return {"recipient_id": str(row["recipient_id"]), "email_hint": email_hint(email)}


def remove_recipient(ctx: Ctx, recipient_id) -> None:
    ctx.actor.require(ROLE_ADMIN)
    require_not_closed(ctx)
    rid = to_uuid(recipient_id, "recipient")
    n = ctx.conn.execute(f"UPDATE consentvault.stop_notice_recipient SET removed_at = clock_timestamp()"
                         f" WHERE org_id = {_ORG} AND recipient_id = %s AND removed_at IS NULL", (rid,)).rowcount
    if not n:
        raise ApiError("not_found", "no such recipient")
    ctx.audit("stop_notice.recipient_removed", "stop_notice_recipient", str(rid))
