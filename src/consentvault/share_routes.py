"""The record link routes, in two route objects the server mounts beside the others.

``PublicRecordLinks``: no bearer, answered from the origin only through the gateway on the verify host.

    GET  /v1/public/record-link/{id}              the page (HTML)
    GET  /v1/public/record-link/{id}.json         the same view as data
    GET  /v1/public/record-link/{id}/record.zip   the one-record file
    POST /v1/public/record-link/{id}/match        a typed contact point: same fingerprint, yes or no (JSON or the form field ``contact``)

  Answers: 200; 404 with one fixed body for an unknown id and a malformed id alike (a malformed id makes the same database call as a
  well-formed one that no link carries, so the two cost the same); 410 "withdrawn by the sender"; 429 when the match box is locked;
  503 loudly when the page cannot be built (the key service or the database did not answer). The id is never logged.

``RecordLinkRoutes``: the sender's side, for an admin of the organisation (a portal session); the existing session check.

    POST /v1/record-links                    make a link (event_id, the five settings, contact_ack, note); the link is returned once
    POST /v1/record-links/preview            the exact page for the same body; writes nothing
    GET  /v1/record-links                    the links, with how often each was opened
    POST /v1/record-links/{share_id}/revoke
    POST /v1/record-links/{share_id}/reset-match
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Callable, Mapping

import psycopg

from . import safelog, share, share_bundle, share_render
from .errors import ConfigError, ConsentVaultError
from .safelog import caller_detail
from .route_wiring import Reply, _json_body, _lower, _rid
from .share_render import NOT_FOUND_BODY, WITHDRAWN_BODY

_log = safelog.get("consentvault.share_routes")

PUBLIC_PREFIX = "/v1/public/record-link/"
_PUBLIC = re.compile(r"^/v1/public/record-link/([^/]{1,200}?)(\.json|/record\.zip|/match)?$")
_PROBE_ID = "cvp_" + "a" * 26
_MAX_MATCH_BODY = 2048
ENV_DSN = "CONSENTVAULT_PUBLIC_VERIFY_DSN"
ENV_HOST = "CONSENTVAULT_PUBLIC_VERIFY_HOST"
DEFAULT_HOST = "verify.consentvault.ai"
_HOST = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

_PRIVACY = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow",
            "X-Content-Type-Options": "nosniff"}


def public_settings(env: Mapping[str, str]) -> tuple[str, str] | None:
    """``(dsn, host)`` when record links are on, None when they are off (the default). The login's address is the setting that turns
    them on; the host the links are shown under is Mike's to name (default verify.consentvault.ai). A malformed host refuses the start."""
    dsn = (env.get(ENV_DSN) or "").strip()
    host = (env.get(ENV_HOST) or DEFAULT_HOST).strip().lower()
    if not dsn:
        if env.get(ENV_HOST):
            raise ConfigError(f"{ENV_HOST} is set but {ENV_DSN} is not: set both, or neither; nothing was started")
        return None
    if not _HOST.match(host) or len(host) > 253:
        raise ConfigError(f"{ENV_HOST} must be a host name (for example {DEFAULT_HOST}); nothing was started")
    return dsn, host


def _not_found() -> Reply:
    return Reply(404, raw=NOT_FOUND_BODY, headers={"Content-Type": "text/plain; charset=utf-8", **_PRIVACY})


def _withdrawn() -> Reply:
    return Reply(410, raw=WITHDRAWN_BODY, headers={"Content-Type": "text/plain; charset=utf-8", **_PRIVACY})


class PublicRecordLinks:
    wants_query = False

    def __init__(self, connect: Callable[[], psycopg.Connection], crypto, *, region: str | None = None) -> None:
        self._public = share.PublicVerify(connect, crypto, region=region)

    def handles(self, method: str, path: str) -> bool:
        return (path or "").startswith(PUBLIC_PREFIX)

    def handle(self, method, path, *, body=b"", headers=None, caller=None, query=None) -> Reply:
        m = _PUBLIC.match(path or "")
        suffix = (m.group(2) or "") if m else ""
        wanted = m is not None and ((method == "GET" and suffix != "/match") or (method == "POST" and suffix == "/match"))
        link_id = m.group(1) if m else ""
        well_formed = wanted and bool(share.LINK_ID.match(link_id))
        try:
            if not well_formed:
                self._public.read(_PROBE_ID, "page")  # the same call a real link costs, whatever was sent
                return _not_found()
            if suffix == "/match":
                return self._match(link_id, body, headers)
            outcome = self._public.read(link_id, "file" if suffix == "/record.zip" else "page")
        except (psycopg.Error, ConsentVaultError) as exc:
            _log.error("a record link could not be answered", error=type(exc).__name__)
            return Reply(503, {"error": "service_unavailable", "detail": "the record could not be read just now; try again shortly"},
                         dict(_PRIVACY))
        if outcome.status == "withdrawn":
            return _withdrawn()
        if outcome.status != "ok":
            return _not_found()
        view = outcome.view
        if suffix == ".json":
            return Reply(200, raw=share_render.render_json(view), headers={"Content-Type": "application/json", **_PRIVACY})
        if suffix == "/record.zip":
            return Reply(200, raw=share_bundle.build_record_zip(view), headers={
                "Content-Type": "application/zip", "Content-Disposition": 'attachment; filename="record.zip"', **_PRIVACY})
        page = share_render.render_page(view)
        return Reply(200, raw=page.html, headers={"Content-Type": "text/html; charset=utf-8",
                                                  "Content-Security-Policy": page.csp, **_PRIVACY})

    def _match(self, link_id: str, body: bytes, headers) -> Reply:
        typed = _typed_contact(body or b"", _lower(headers).get("content-type", ""))
        if typed is None:
            self._public.read(_PROBE_ID, "page")
            return _not_found()
        outcome = self._public.match(link_id, typed)
        if outcome.status == "withdrawn":
            return _withdrawn()
        if outcome.status == "locked":
            return Reply(429, {"error": "locked", "statement": share_render.LOCKED_STATEMENT}, {"Retry-After": "3600", **_PRIVACY})
        if outcome.status != "ok":
            return _not_found()
        yes = outcome.match == "yes"
        return Reply(200, {"result": "yes" if yes else "no",
                           "statement": share_render.MATCH_STATEMENT_YES if yes else share_render.MATCH_STATEMENT_NO,
                           "code_version": share.CODE_VERSION, "rule_set": share.RULE_SET}, dict(_PRIVACY))


def _typed_contact(body: bytes, content_type: str) -> str | None:
    """The one field ``contact`` from a JSON body or a form body; None for anything else or anything too long."""
    if len(body) > _MAX_MATCH_BODY:
        return None
    ctype = content_type.split(";")[0].strip().lower()
    try:
        text = body.decode("utf-8")
        if ctype == "application/x-www-form-urlencoded":
            vals = urllib.parse.parse_qs(text, keep_blank_values=True).get("contact", [])
            return vals[0] if len(vals) == 1 and vals[0].strip() else None
        doc = json.loads(text)
    except (UnicodeDecodeError, ValueError) as exc:
        _log.info("a match request body was not the one field", error=type(exc).__name__)  # answered as the fixed 404
        return None
    value = doc.get("contact") if isinstance(doc, dict) else None
    return value if isinstance(value, str) and value.strip() and len(value) <= 320 else None


# ---- the sender's side ----------------------------------------------------------------------------------------------------------

_ADMIN = re.compile(r"^/v1/record-links(?:/(preview)|/([0-9a-fA-F-]{36})/(revoke|reset-match))?$")


def _err(status: int, name: str, detail: str, rid: str, fields: dict | None = None) -> Reply:
    body = {"error": name, "detail": detail, "request_id": rid}
    if fields:
        body["fields"] = fields
    return Reply(status, body, {"Cache-Control": "no-store"})


class RecordLinkRoutes:
    wants_query = True

    def __init__(self, connect: Callable[[], psycopg.Connection], crypto, auth, *, public_host: str) -> None:
        self._connect, self._crypto, self._auth, self._host = connect, crypto, auth, public_host

    def handles(self, method: str, path: str) -> bool:
        return _ADMIN.match(path or "") is not None

    def _settings(self, parsed) -> tuple[dict, str | None, str, str]:
        if not isinstance(parsed, dict):
            raise share.ShareError("the body must be a JSON object")
        event_id = parsed.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise share.ShareError("event_id is required")
        flags = {k: parsed[k] for k in share.FLAG_DEFAULTS if k in parsed}
        note = parsed.get("note") or ""
        if not isinstance(note, str) or len(note) > 500:
            raise share.ShareError("note must be text of at most 500 characters")
        ack = parsed.get("contact_ack")
        if ack is not None and not isinstance(ack, str):
            raise share.ShareError("contact_ack must be text")
        return flags, ack, note, event_id

    def handle(self, method, path, *, body=b"", headers=None, caller=None, query=None) -> Reply:
        rid = _rid(headers)
        m = _ADMIN.match(path or "")
        principal = self._auth.portal(headers)
        if principal is None:
            return _err(401, "unauthenticated", "a session is required", rid)
        if principal.role != "admin":
            return _err(403, "role_not_allowed", "only an admin of the organization may use record links", rid, {"role": principal.role})
        from .tenancy.tokens import org_transaction

        actor = f"member:{principal.member_id}"
        try:
            parsed = _json_body(body) if method == "POST" else None
            limit = 100
            if method == "GET":
                limit = int((query or {}).get("limit", 100))
            with self._connect() as conn, org_transaction(conn, principal.token):
                if m.group(1) == "preview" and method == "POST":
                    flags, _, _, event_id = self._settings(parsed)
                    material = share.preview_material(conn, event_id=event_id, flags=flags, contact_ack=None)
                    page = share_render.render_page(share.build_view(material, self._crypto))
                    return Reply(200, raw=page.html, headers={"Content-Type": "text/html; charset=utf-8",
                                                              "Content-Security-Policy": page.csp, "Cache-Control": "no-store"})
                if m.group(2) and method == "POST":
                    act = share.revoke if m.group(3) == "revoke" else share.reset_match
                    return Reply(200, act(conn, m.group(2), actor=actor), {"Cache-Control": "no-store"})
                if method == "POST" and not m.group(1) and not m.group(2):
                    flags, ack, note, event_id = self._settings(parsed)
                    made = share.mint(conn, event_id=event_id, actor=actor, flags=flags, contact_ack=ack, note=note)
                    return Reply(201, {"share_id": made["share_id"], "event_id": made["event_id"], "flags": made["flags"],
                                       "link": f"https://{self._host}/p/{made['link_id']}"}, {"Cache-Control": "no-store"})
                if method == "GET" and not m.group(1) and not m.group(2):
                    return Reply(200, {"items": share.list_shares(conn, limit=limit), "next_cursor": None}, {"Cache-Control": "no-store"})
        except share.AckRequired as exc:
            _log.warning("a record link request was refused", reason=type(exc).__name__)
            return _err(422, "validation_failed", caller_detail(exc), rid, {"contact_ack": "required"})
        except (share.UnknownRecord, share.UnknownShare) as exc:
            _log.warning("a record link request was refused", reason=type(exc).__name__)
            return _err(404, "not_found", caller_detail(exc), rid)
        except share.ShareError as exc:
            _log.warning("a record link request was refused", reason=type(exc).__name__)
            return _err(422, "validation_failed", caller_detail(exc), rid)
        except ValueError as exc:
            _log.warning("a record link request was refused", reason=type(exc).__name__)
            return _err(422, "validation_failed", "limit is not a number", rid, {"limit": "not a number"})
        return _err(405, "invalid_request", f"{method} is not allowed here", rid)
