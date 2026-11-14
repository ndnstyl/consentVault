"""Reads and the one write a person makes by hand (confirmations.md sections 7 and 8): the sends list, the replies list and
marking a reply as a stop or not a stop.

A list is audited before its answer is built; when the audit row cannot be written the answer is ``audit_unavailable`` and nothing is
returned. The audit rows hold filters and counts, never a reply text or a contact point. A developer sees a contact only by its
fingerprint; a reply's text opens only for an admin or a compliance viewer.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from ..ledger import record_tenant_event
from ..records import mask_contact
from ..tenancy import crypto as tc
from ..tenancy.admin_base import (ROLE_ADMIN, ROLE_DEVELOPER, ApiError, Ctx, iso, need_iso_time, need_text, paginate, parse_limit,
                                  want_enum)
from ..tenancy.errors import FieldCryptoError
from ..tenancy.records_admin import audited
from .config import strict, uuid_text
from .core import KEY_ERRORS, RECORDED_BY, SYSTEM_REPLIES

SEND_STATUSES = ("sent", "delivered", "failed", "dead", "skipped")
REPLY_STATES = ("to_read", "stop", "not_stop", "help", "start")
SEND_QUERY_KEYS = {"status", "skip_reason", "channel", "source_id", "from", "to", "limit", "cursor"}
REPLY_QUERY_KEYS = {"state", "from", "to", "limit", "cursor"}


def _window(q: dict, col: str) -> tuple[list[str], list, dict]:
    where, params, echo = [], [], {}
    for key, op in (("from", ">="), ("to", "<")):
        if q.get(key):
            when = need_iso_time({key: q[key]}, key)
            where.append(f"{col} {op} %s")
            params.append(when)
            echo[key] = iso(when)
    return where, params, echo


class ReadsMixin:
    # ---- the sends list --------------------------------------------------------------------------------------------------------
    def list_sends(self, ctx: Ctx, q: dict) -> dict:
        unknown = sorted(set(q) - SEND_QUERY_KEYS)
        if unknown:
            raise ApiError("validation_failed", f"unknown query parameters: {unknown}", {u: "not a filter" for u in unknown})
        q = {k: v for k, v in q.items() if v not in (None, "")}
        org, role = ctx.org_id(), ctx.actor.role
        where, params, echo = ["i.org_id = %s"], [org], {}
        if "status" in q:
            where.append("i.status = %s")
            params.append(want_enum(q["status"], "status", SEND_STATUSES))
            echo["status"] = q["status"]
        if "skip_reason" in q:
            where.append("i.skip_reason = %s")
            params.append(str(q["skip_reason"])[:60])
            echo["skip_reason"] = str(q["skip_reason"])[:60]
        if "channel" in q:
            where.append("i.channel = %s")
            params.append(want_enum(q["channel"], "channel", ("email", "sms")))
            echo["channel"] = q["channel"]
        if "source_id" in q:
            src = uuid_text(q["source_id"])
            if src is None:
                raise ApiError("not_found", "no such source")
            where.append("i.source_id = %s")
            params.append(src)
            echo["source_id"] = str(src)
        w2, p2, e2 = _window(q, "i.at")
        where += w2
        params += p2
        echo.update(e2)
        person = role != ROLE_DEVELOPER
        sql = ("SELECT i.send_id, i.kind, i.contact_fp, i.channel, i.source_id, i.brand_id, i.status, i.skip_reason, i.dead_cause, i.failed_code,"
               " i.provider_status, i.attempts, i.first_attempt_at, i.last_attempt_at, i.at,"
               " (SELECT s.name FROM consentvault.capture_source s WHERE s.org_id = i.org_id AND s.source_id = i.source_id) AS source_name,"
               " (SELECT b.display_name FROM consentvault.brand b WHERE b.org_id = i.org_id AND b.brand_id = i.brand_id) AS brand_name,"
               " (SELECT r.record_id FROM consentvault.record r WHERE r.org_id = i.org_id AND r.contact_fp = i.contact_fp"
               "   AND r.erased_at IS NULL ORDER BY r.first_seq DESC LIMIT 1) AS record_id,"
               + (" (SELECT x.mask_ct FROM consentvault.record_index x JOIN consentvault.record r ON r.org_id = x.org_id"
                  "   AND r.record_id = x.record_id WHERE r.org_id = i.org_id AND r.contact_fp = i.contact_fp"
                  "   AND r.erased_at IS NULL ORDER BY r.first_seq DESC LIMIT 1) AS mask_ct"
                  if person else " NULL::bytea AS mask_ct")
               + " FROM consentvault.confirmation_send_intent i WHERE " + " AND ".join(where))
        key = self._display_key_or_none(org) if person else None
        partial: set = set()

        def shape(r: dict) -> dict:
            masked = None
            if person and r["mask_ct"] is not None:
                if key is None:
                    partial.add("contact_mask")
                else:
                    try:
                        masked = tc.decrypt_text(key, org, str(r["record_id"]), "mask_ct", bytes(r["mask_ct"]))
                    except FieldCryptoError:  # loud-failure-exempt: the field is null and named in partial
                        partial.add("contact_mask")
            return {"send_id": str(r["send_id"]), "record_id": str(r["record_id"]) if r["record_id"] else None,
                    "contact": {"masked": masked, "fp_hint": r["contact_fp"][:8]}, "channel": r["channel"],
                    "source_id": str(r["source_id"]) if r["source_id"] else None, "source_name": r["source_name"],
                    "brand_id": str(r["brand_id"]) if r["brand_id"] else None, "brand_name": r["brand_name"],
                    "kind": r["kind"], "status": r["status"],
                    "skip_reason": r["skip_reason"], "dead_cause": r["dead_cause"], "failed_code": r["failed_code"],
                    "provider_status": r["provider_status"], "attempts": r["attempts"], "first_attempt_at": iso(r["first_attempt_at"]),
                    "last_attempt_at": iso(r["last_attempt_at"]), "at": iso(r["at"])}

        out = paginate(ctx, endpoint=f"GET /v1/confirmations/sends:{org}", select_sql=sql, params=params, key_cols=("at", "send_id"),
                       key_types=("timestamptz", "uuid"), descending=True, limit=q.get("limit"), cursor=q.get("cursor"), shape=shape)
        audited(ctx, "confirmations.sends_listed", "confirmations", None, None, {"filters": echo, "count": len(out["items"])})
        out["partial"] = sorted(partial)
        return out

    def _display_key_or_none(self, org) -> Optional[bytes]:
        try:
            return self.crypto.display_key(org)
        except KEY_ERRORS:  # loud-failure-exempt: the masked contacts are null and named in partial
            return None

    # ---- the replies list -------------------------------------------------------------------------------------------------------
    @staticmethod
    def _our_reply(status: Optional[str], skip: Optional[str]) -> Optional[str]:
        if status is None or status in ("intent", "sending"):
            return None
        if status in ("sent", "delivered"):
            return "sent"
        return "provider_replied" if skip == "provider_replied" else "skipped"

    def list_replies(self, ctx: Ctx, q: dict) -> dict:
        unknown = sorted(set(q) - REPLY_QUERY_KEYS)
        if unknown:
            raise ApiError("validation_failed", f"unknown query parameters: {unknown}", {u: "not a filter" for u in unknown})
        q = {k: v for k, v in q.items() if v not in (None, "")}
        org, conn = ctx.org_id(), ctx.conn
        where, params, echo = ["r.org_id = %s"], [org], {}
        if "state" in q:
            where.append("r.state = %s")
            params.append(want_enum(q["state"], "state", REPLY_STATES))
            echo["state"] = q["state"]
        w2, p2, e2 = _window(q, "r.received_at")
        where += w2
        params += p2
        echo.update(e2)
        sql = ("SELECT r.*, i.status AS our_status, i.skip_reason AS our_skip, m.display_name AS marked_name, x.mask_ct"
               " FROM consentvault.confirmation_reply r"
               " LEFT JOIN LATERAL (SELECT status, skip_reason FROM consentvault.confirmation_send_intent i"
               "   WHERE i.org_id = r.org_id AND i.reply_id = r.reply_id ORDER BY i.created_at LIMIT 1) i ON true"
               " LEFT JOIN consentvault.member m ON m.org_id = r.org_id AND m.member_id = r.marked_by"
               " LEFT JOIN consentvault.record_index x ON x.org_id = r.org_id AND x.record_id = r.matched_record_id"
               " WHERE " + " AND ".join(where))
        key, now, partial = self._display_key_or_none(org), self._dt(ctx.now()), set()

        def shape(r: dict) -> dict:
            return self._reply_item(conn, org, r, key, now, partial)

        out = paginate(ctx, endpoint=f"GET /v1/confirmations/replies:{org}", select_sql=sql, params=params,
                       key_cols=("received_at", "reply_id"), key_types=("timestamptz", "uuid"), descending=True,
                       limit=q.get("limit"), cursor=q.get("cursor"), shape=shape)
        audited(ctx, "confirmations.replies_listed", "confirmations", None, None, {"filters": echo, "count": len(out["items"])})
        out["partial"] = sorted(partial)
        return out

    def _reply_item(self, conn, org, r: dict, key: Optional[bytes], now: datetime, partial: set) -> dict:
        text = masked = None
        rid = str(r["reply_id"])
        try:
            if r["key_kind"] == "org":
                text = self._unseal(org, rid, "body_ct", r["body_ct"])
                masked = mask_contact("phone", self._unseal(org, rid, "from_ct", r["from_ct"]))
            else:
                data_key = self._contact_key(conn, org, r["from_fp"])
                text = tc.decrypt_text(data_key, org, rid, "body_ct", bytes(r["body_ct"])) if data_key is not None else None
                if r["mask_ct"] is not None and key is not None:
                    masked = tc.decrypt_text(key, org, str(r["matched_record_id"]), "mask_ct", bytes(r["mask_ct"]))
        except (*KEY_ERRORS, FieldCryptoError):  # loud-failure-exempt: the fields are null and named in partial
            partial.update({"text", "contact_mask"})
        unread = round((now - r["received_at"]).total_seconds() / 3600, 1) if r["state"] == "to_read" else None
        return {"reply_id": rid, "received_at": iso(r["received_at"]), "account_id": str(r["account_id"]), "channel": "sms",
                "from": {"masked": masked, "fp_hint": r["from_fp"][:8]},
                "matched_record_id": str(r["matched_record_id"]) if r["matched_record_id"] else None, "text": text,
                "verdict": r["verdict"], "reason": r["reason"], "matched_words": list(r["matched_words"] or []), "state": r["state"],
                "event_id": str(r["event_id"]) if r["event_id"] else None,
                "our_reply": self._our_reply(r["our_status"], r["our_skip"]),
                "marked_by": {"member_id": str(r["marked_by"]), "display_name": r["marked_name"]} if r["marked_by"] else None,
                "marked_at": iso(r["marked_at"]), "mark_reason": r["mark_reason"], "unread_hours": unread}

    # ---- marking a reply ---------------------------------------------------------------------------------------------------------
    def mark_reply(self, ctx: Ctx, reply_id: str, body: Any) -> dict:
        b = strict(body, {"decision", "reason"})
        bad = {}
        if b.get("decision") not in ("stop", "not_stop"):
            bad["decision"] = "stop or not_stop"
        if not isinstance(b.get("reason"), str) or not 1 <= len(b["reason"].strip()) <= 200:
            bad["reason"] = "required, 1 to 200 characters"
        if bad:
            raise ApiError("validation_failed", "a field is missing or malformed", bad)
        reason = need_text(b, "reason", max_len=200)
        org, conn, now = ctx.org_id(), ctx.conn, self._dt(ctx.now())
        rid = uuid_text(reply_id)
        rep = conn.execute("SELECT * FROM consentvault.confirmation_reply WHERE org_id = %s AND reply_id = %s FOR UPDATE",
                           (org, rid)).fetchone() if rid else None
        if rep is None:
            raise ApiError("not_found", "no such reply")
        if rep["state"] != "to_read":
            raise ApiError("validation_failed", "that reply was already read", {"reply": "already read"})
        state, event_id = "not_stop", None
        if b["decision"] == "stop":
            try:
                if rep["key_kind"] == "org":
                    number = self._unseal(org, str(rid), "from_ct", rep["from_ct"])
                else:
                    held = conn.execute("SELECT event_id FROM consentvault.event WHERE org_id = %s AND contact_fp = %s"
                                        " ORDER BY seq DESC LIMIT 1", (org, rep["from_fp"])).fetchone()
                    if held is None:
                        raise ApiError("contact_already_erased", "that contact was erased")
                    _, number, _ = self._contact_of_event(conn, org, held["event_id"])
                ev = record_tenant_event(conn, self.crypto, contact=number, event_type="revoke", channels=self._stop_channels(conn),
                                         purposes=["*"], method="written", origin="consumer",
                                         source_id=self._system_source(conn, SYSTEM_REPLIES),
                                         session_ref=f"twilio:{rep['provider_message_id']}"[:200], recorded_by=f"member:{ctx.actor.id}")
            except KEY_ERRORS as exc:
                raise ApiError("key_unavailable", "the contact key could not be used; nothing was recorded") from exc
            state, event_id = "stop", ev.event_id
        conn.execute("UPDATE consentvault.confirmation_reply SET state = %s, event_id = %s, marked_by = %s, marked_at = %s,"
                     " mark_reason = %s WHERE org_id = %s AND reply_id = %s", (state, event_id, ctx.actor.member_uuid, now, reason, org, rid))
        ctx.audit("confirmations.reply_marked", "confirmation_reply", str(rid), detail={"decision": b["decision"]})
        page = self.list_replies_one(ctx, rid)
        return page

    def list_replies_one(self, ctx: Ctx, rid: uuid.UUID) -> dict:
        """The reply as the list shows it (without writing a listing audit row)."""
        org, conn = ctx.org_id(), ctx.conn
        r = conn.execute(
            "SELECT r.*, i.status AS our_status, i.skip_reason AS our_skip, m.display_name AS marked_name, x.mask_ct"
            " FROM consentvault.confirmation_reply r"
            " LEFT JOIN LATERAL (SELECT status, skip_reason FROM consentvault.confirmation_send_intent i"
            "   WHERE i.org_id = r.org_id AND i.reply_id = r.reply_id ORDER BY i.created_at LIMIT 1) i ON true"
            " LEFT JOIN consentvault.member m ON m.org_id = r.org_id AND m.member_id = r.marked_by"
            " LEFT JOIN consentvault.record_index x ON x.org_id = r.org_id AND x.record_id = r.matched_record_id"
            " WHERE r.org_id = %s AND r.reply_id = %s", (org, rid)).fetchone()
        return self._reply_item(conn, org, r, self._display_key_or_none(org), self._dt(ctx.now()), set())
