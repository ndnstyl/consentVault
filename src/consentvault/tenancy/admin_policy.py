"""Wording, policies, attestation, checklists and rule references (contracts/policy.md).

Nothing here states a legal conclusion. An evidence status describes the records; a policy is the client's own mapping
from evidence status to proceed or hold, approved by a named admin who accepts the drafted attestation; a checklist
result is documentation completeness. A template is a starting point that is copied into a draft and is never in force
by itself. A rule reference is a citation, an official link and a review date, nothing more.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from typing import Any

import psycopg
from psycopg import sql

from ..safelog import caller_detail
from .admin_base import (ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER, ApiError, Ctx, body_dict, invalid, iso, need_iso_time,
                         need_list, need_text, opt_text, page_list, paginate, to_uuid, want_enum)

READERS = (ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER)
EVIDENCE_STATUSES = ("consent_record_found", "stop_on_record", "no_record", "record_incomplete", "unavailable")
POLICY_ACTIONS = ("proceed", "hold")
_SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_WORDING_CHARS = 20000


# ======================================================================================================================
# Channels and purposes (configured by the operator; read-only here)
# ======================================================================================================================
def list_channels(ctx: Ctx, *, limit=None, cursor=None) -> dict:
    ctx.actor.require(*READERS)
    return paginate(ctx, endpoint="GET /v1/channels",
                    select_sql=("SELECT channel, label, lower(label) AS _k1, channel AS _k2 FROM consentvault.channel"
                                " WHERE org_id = (SELECT consentvault.current_org())"),
                    params=[], key_cols=("_k1", "_k2"), key_types=("text", "text"), descending=False, limit=limit,
                    cursor=cursor, shape=lambda r: {"channel": r["channel"], "label": r["label"]})


def list_purposes(ctx: Ctx, *, limit=None, cursor=None) -> dict:
    ctx.actor.require(*READERS)
    return paginate(ctx, endpoint="GET /v1/purposes",
                    select_sql=("SELECT purpose, label, description, lower(label) AS _k1, purpose AS _k2"
                                " FROM consentvault.purpose WHERE org_id = (SELECT consentvault.current_org())"),
                    params=[], key_cols=("_k1", "_k2"), key_types=("text", "text"), descending=False, limit=limit,
                    cursor=cursor, shape=lambda r: {"purpose": r["purpose"], "label": r["label"],
                                                    "description": r["description"]})


def _org_channels(ctx: Ctx) -> list[str]:
    return [r["channel"] for r in ctx.conn.execute("SELECT channel FROM consentvault.channel"
                                                   " WHERE org_id = (SELECT consentvault.current_org()) ORDER BY channel")]


def _org_purposes(ctx: Ctx) -> list[str]:
    return [r["purpose"] for r in ctx.conn.execute("SELECT purpose FROM consentvault.purpose"
                                                   " WHERE org_id = (SELECT consentvault.current_org()) ORDER BY purpose")]


# ======================================================================================================================
# Wording (disclosure versions)
# ======================================================================================================================
def _wording_obj(r: dict, *, with_body: bool = False) -> dict:
    out = {"sha256": r["sha256"], "label": r["label"], "version_label": r["version_label"],
           "channels": list(r["channels"]), "purposes": list(r["purposes"]), "brand_ids": [str(b) for b in r["brand_ids"]],
           "supersedes_sha256": r["supersedes_sha256"], "superseded_by_sha256": r["superseded_by_sha256"],
           "effective_from": iso(r["effective_from"]), "registered_by": str(r["registered_by"]) if r["registered_by"] else None,
           "registered_at": iso(r["first_seen_at"])}
    if with_body:
        out["body"] = r["body"]
    return out


_WORDING_SELECT = ("SELECT d.*, (SELECT n.sha256 FROM consentvault.disclosure n WHERE n.org_id = d.org_id"
                   " AND n.supersedes_sha256 = d.sha256) AS superseded_by_sha256, d.first_seen_at AS _k1, d.sha256 AS _k2"
                   " FROM consentvault.disclosure d WHERE d.org_id = (SELECT consentvault.current_org())")


def list_wording(ctx: Ctx, *, brand_id=None, channel=None, purpose=None, state=None, limit=None, cursor=None) -> dict:
    ctx.actor.require(*READERS)
    where, params = [], []
    if brand_id:
        where.append("%s = ANY (brand_ids)")
        params.append(to_uuid(brand_id, "brand"))
    if channel:
        where.append("%s = ANY (channels)")
        params.append(channel)
    if purpose:
        where.append("%s = ANY (purposes)")
        params.append(str(purpose).lower())
    if state:
        want_enum(state, "state", ("current", "superseded"))
        where.append("superseded_by_sha256 IS NOT NULL" if state == "superseded" else "superseded_by_sha256 IS NULL")
    sql = "SELECT * FROM (" + _WORDING_SELECT + ") w" + (" WHERE " + " AND ".join(where) if where else "")
    return paginate(ctx, endpoint="GET /v1/disclosures", select_sql=sql, params=params, key_cols=("_k1", "_k2"),
                    key_types=("timestamptz", "text"), descending=True, limit=limit, cursor=cursor, shape=_wording_obj)


def get_wording(ctx: Ctx, sha256: str) -> dict:
    ctx.actor.require(*READERS)
    if not isinstance(sha256, str) or not _SHA.match(sha256):
        raise ApiError("not_found", "no such wording in this organization")
    row = ctx.conn.execute("SELECT * FROM (" + _WORDING_SELECT + ") w WHERE sha256 = %s", (sha256,)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such wording in this organization")
    return _wording_obj(row, with_body=True)


def register_wording(ctx: Ctx, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    text = b.get("body")
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_WORDING_CHARS:
        raise invalid(body=f"required text, up to {MAX_WORDING_CHARS} characters")
    label = need_text(b, "label")
    version_label = opt_text(b, "version_label", max_len=100)
    effective_from = need_iso_time(b, "effective_from")
    channels = sorted({str(c) for c in need_list(b, "channels", min_items=1, max_items=20)})
    purposes = sorted({str(p).strip().lower() for p in need_list(b, "purposes", min_items=1, max_items=50)})
    brand_in = need_list(b, "brand_ids", min_items=1, max_items=100)
    if set(channels) - set(_org_channels(ctx)):
        raise ApiError("invalid_channel", "a channel is not one this organization has")
    if set(purposes) - set(_org_purposes(ctx)):
        raise ApiError("UnknownPurposeError", "a purpose is not in this organization's configured list")
    from .admin import _check_brands
    brand_ids = _check_brands(ctx, brand_in)
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    org = ctx.org_id()
    if ctx.conn.execute("SELECT 1 FROM consentvault.disclosure WHERE org_id = %s AND sha256 = %s", (org, sha)).fetchone():
        raise ApiError("disclosure_exists", "this exact wording is already registered", {"sha256": sha})
    supersedes = b.get("supersedes_sha256")
    if supersedes is not None:
        if not isinstance(supersedes, str) or not _SHA.match(supersedes) or not ctx.conn.execute(
                "SELECT 1 FROM consentvault.disclosure WHERE org_id = %s AND sha256 = %s", (org, supersedes)).fetchone():
            raise ApiError("not_found", "the wording this one supersedes is not registered in this organization")
    locale = opt_text(b, "locale", max_len=16) or "en"
    try:
        ctx.conn.execute(
            "INSERT INTO consentvault.disclosure (org_id, sha256, body, label, locale, channels, purposes, version_label,"
            " supersedes_sha256, effective_from, registered_by, brand_ids) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,"
            " %s, %s)", (org, sha, text, label, locale, channels, purposes, version_label, supersedes, effective_from,
                         ctx.actor.member_uuid, brand_ids))
    except psycopg.errors.UniqueViolation:
        raise invalid(supersedes_sha256="that wording already has a newer version") from None
    except psycopg.errors.CheckViolation:
        raise ApiError("invalid_channel", "a channel is not one the vault can record") from None
    ctx.audit("wording.registered", "wording", sha)
    return get_wording(ctx, sha)


# ======================================================================================================================
# Attestation
# ======================================================================================================================
def current_attestation(ctx: Ctx) -> dict:
    ctx.actor.require(*READERS)
    r = _attestation_row(ctx)
    return {"version": r["version"], "text": r["text"], "sha256": r["sha256"], "published_at": iso(r["published_at"])}


def _attestation_row(ctx: Ctx) -> dict:
    r = ctx.conn.execute("SELECT version, text, sha256, published_at FROM consentvault.attestation_text"
                         " ORDER BY version DESC LIMIT 1").fetchone()
    if r is None:
        raise ApiError("not_found", "no attestation text is published; policies cannot be approved")
    if not hmac.compare_digest(hashlib.sha256(r["text"].encode("utf-8")).hexdigest(), str(r["sha256"])):
        raise ApiError("attestation_mismatch", "the published attestation does not match its digest; nothing was approved")
    return r


# ======================================================================================================================
# Policies
# ======================================================================================================================
def _cells(channels: list[str], purposes: list[str], action_for) -> dict:
    return {"schema_version": 1, "purposes": {
        p: {"cells": [{"evidence_status": s, "channel": c, "action": action_for(s)}
                      for c in channels for s in EVIDENCE_STATUSES], "checklist_version": None} for p in purposes}}


POLICY_TEMPLATES = (
    ("proceed_on_consent_record", "Proceed only when a consent record is found",
     "Proceeds when the records show a consent record and no later stop; every other evidence status holds.",
     lambda s: "proceed" if s == "consent_record_found" else "hold"),
    ("hold_everything", "Hold every contact",
     "Nothing proceeds. Useful while a policy is still being worked out.", lambda s: "hold"),
)


def list_policy_templates(ctx: Ctx, *, limit=None, cursor=None) -> dict:
    ctx.actor.require(*READERS)
    channels, purposes = _org_channels(ctx), _org_purposes(ctx)
    rows = sorted(POLICY_TEMPLATES, key=lambda t: t[1].lower())
    return page_list(ctx, endpoint="GET /v1/policy-templates", rows=rows, key=lambda t: t[0], limit=limit, cursor=cursor,
                     shape=lambda t: {"template_ref": t[0], "label": t[1], "description": t[2],
                                      "rules": _cells(channels, purposes, t[3])})


def _approved_checklists(ctx: Ctx) -> set[int]:
    return {r["version"] for r in ctx.conn.execute("SELECT version FROM consentvault.doc_checklist"
                                                   " WHERE org_id = (SELECT consentvault.current_org())"
                                                   " AND status = 'approved'")}


def validate_rules(ctx: Ctx, rules: Any) -> dict:
    """Check a policy's rules and return them in the stored (canonical) form."""
    if not isinstance(rules, dict) or rules.get("schema_version") != 1 or not isinstance(rules.get("purposes"), dict):
        raise invalid(rules="needs schema_version 1 and a purposes object")
    channels, purposes = _org_channels(ctx), _org_purposes(ctx)
    extra = sorted(set(rules["purposes"]) - set(purposes))
    if extra:
        raise ApiError("UnknownPurposeError", "a purpose is not in this organization's configured list",
                       {"purposes": extra})
    approved = _approved_checklists(ctx)
    out_purposes: dict = {}
    stop_proceed: list[str] = []
    unavailable_proceed: list[str] = []
    missing: list[str] = []
    for p in purposes:
        spec = rules["purposes"].get(p)
        if spec is None:
            missing += [f"{p}/{c}/{s}" for c in channels for s in EVIDENCE_STATUSES]
            continue
        if not isinstance(spec, dict) or not isinstance(spec.get("cells"), list):
            raise invalid(**{f"rules.purposes.{p}": "needs a cells list"})
        seen: dict = {}
        for cell in spec["cells"]:
            if not isinstance(cell, dict):
                raise invalid(**{f"rules.purposes.{p}": "every cell is an object"})
            s, c, a = cell.get("evidence_status"), cell.get("channel"), cell.get("action")
            if s not in EVIDENCE_STATUSES or a not in POLICY_ACTIONS:
                raise invalid(**{f"rules.purposes.{p}": "a cell needs a known evidence_status and an action of proceed or hold"})
            if c not in channels:
                raise ApiError("invalid_channel", "a channel is not one this organization has", {"channel": str(c)[:64]})
            if (c, s) in seen:
                raise invalid(**{f"rules.purposes.{p}": f"{c}/{s} appears twice"})
            seen[(c, s)] = a
            if s == "stop_on_record" and a == "proceed":
                stop_proceed.append(f"{p}/{c}")
            if s == "unavailable" and a == "proceed":
                unavailable_proceed.append(f"{p}/{c}")
        missing += [f"{p}/{c}/{s}" for c in channels for s in EVIDENCE_STATUSES if (c, s) not in seen]
        cv = spec.get("checklist_version")
        if cv is not None and (isinstance(cv, bool) or not isinstance(cv, int) or cv not in approved):
            raise invalid(**{f"rules.purposes.{p}.checklist_version": "must name an approved checklist version"})
        out_purposes[p] = {"cells": [{"evidence_status": s, "channel": c, "action": seen[(c, s)]}
                                     for c in channels for s in EVIDENCE_STATUSES if (c, s) in seen],
                           "checklist_version": cv}
    if stop_proceed:
        raise ApiError("stop_cannot_proceed", "a stop on record can only hold", {"cells": stop_proceed})
    if unavailable_proceed:  # a failed read never proceeds (contracts/gate.md)
        raise ApiError("unavailable_cannot_proceed", "when the records cannot be read the answer can only hold",
                       {"cells": unavailable_proceed})
    if missing:
        raise ApiError("policy_incomplete", "the policy lacks a cell for an evidence status, channel and purpose",
                       {"missing": missing})
    unknown = sorted(set(rules) - {"schema_version", "purposes", "narrowing"})
    if unknown:
        raise invalid(rules=f"unknown keys {unknown}")
    out = {"schema_version": 1, "purposes": out_purposes}
    if "narrowing" in rules:  # kept, never dropped: a narrowing rule the client wrote is a hold the gate must apply
        from ..gate_rules.engine import PolicyRuleError, check_narrowing
        try:
            out["narrowing"] = check_narrowing(rules["narrowing"])
        except PolicyRuleError as exc:
            raise invalid(**{"rules.narrowing": caller_detail(exc)}) from None
        bad = sorted({c for r in out["narrowing"] for c in (r.get("channels") or []) if c not in channels})
        if bad:
            raise ApiError("invalid_channel", "a channel is not one this organization has", {"channel": bad[0][:64]})
    return out


def _policy_obj(r: dict) -> dict:
    return {"version": r["version"], "status": r["status"], "template_ref": r["template_ref"],
            "based_on_version": r["based_on_version"], "created_by": str(r["created_by"]) if r["created_by"] else None,
            "created_at": iso(r["created_at"]), "approved_by": str(r["approved_by"]) if r["approved_by"] else None,
            "approved_at": iso(r["approved_at"]), "retired_at": iso(r["retired_at"]),
            "retired_by_version": r["retired_by_version"]}


def list_policies(ctx: Ctx, *, status=None, limit=None, cursor=None) -> dict:
    ctx.actor.require(*READERS)
    where, params = ["p.org_id = (SELECT consentvault.current_org())"], []
    if status:
        where.append("p.status = %s")
        params.append(want_enum(status, "status", ("draft", "approved", "retired")))
    sql = ("SELECT p.*, p.created_at AS _k1, p.version::text AS _k2 FROM consentvault.policy p WHERE " + " AND ".join(where))
    return paginate(ctx, endpoint="GET /v1/policies", select_sql=sql, params=params, key_cols=("_k1", "_k2"),
                    key_types=("timestamptz", "text"), descending=True, limit=limit, cursor=cursor, shape=_policy_obj)


def get_policy(ctx: Ctx, version) -> dict:
    ctx.actor.require(*READERS)
    v = _version(version)
    row = ctx.conn.execute("SELECT * FROM consentvault.policy WHERE org_id = (SELECT consentvault.current_org())"
                           " AND version = %s", (v,)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such policy version in this organization")
    out = _policy_obj(row)
    out["rules"] = row["rules"]
    if row["status"] != "draft":
        a = ctx.conn.execute("SELECT attestation_version, attestation_sha256 FROM consentvault.policy_attestation"
                             " WHERE org_id = (SELECT consentvault.current_org()) AND version = %s", (v,)).fetchone()
        out["attestation"] = {"version": a["attestation_version"], "sha256": a["attestation_sha256"]} if a else None
    return out


def _version(value) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ApiError("not_found", "no such version in this organization") from None
    if v < 1:
        raise ApiError("not_found", "no such version in this organization")
    return v


def _next_version_sql(table: str) -> sql.Composed:
    return sql.SQL("SELECT coalesce(max(version), 0) + 1 AS v FROM consentvault.{}"
                   " WHERE org_id = (SELECT consentvault.current_org())").format(sql.Identifier(table))


def _next_version(ctx: Ctx, table: str, lock: str) -> int:
    ctx.conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s || (SELECT consentvault.current_org())::text))", (lock,))
    return ctx.conn.execute(_next_version_sql(table)).fetchone()["v"]


def create_policy(ctx: Ctx, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    rules = validate_rules(ctx, b.get("rules"))
    template_ref = b.get("template_ref")
    if template_ref is not None and template_ref not in {t[0] for t in POLICY_TEMPLATES}:
        raise invalid(template_ref="not a known template")
    based_on = b.get("based_on_version")
    if based_on is not None:
        based_on = _version(based_on)
        if ctx.conn.execute("SELECT 1 FROM consentvault.policy WHERE org_id = (SELECT consentvault.current_org())"
                            " AND version = %s", (based_on,)).fetchone() is None:
            raise ApiError("not_found", "the policy this one is based on does not exist")
    v = _next_version(ctx, "policy", "consentvault.policy:")
    ctx.conn.execute("INSERT INTO consentvault.policy (org_id, version, rules, template_ref, based_on_version, created_by)"
                     " VALUES ((SELECT consentvault.current_org()), %s, %s::jsonb, %s, %s, %s)",
                     (v, json.dumps(rules), template_ref, based_on, ctx.actor.member_uuid))
    ctx.audit("policy.drafted", "policy", str(v))
    return {"version": v, "status": "draft"}


def update_policy(ctx: Ctx, version, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    v = _version(version)
    rules_in = body_dict(body).get("rules")
    cur = ctx.conn.execute("SELECT status FROM consentvault.policy WHERE org_id = (SELECT consentvault.current_org())"
                           " AND version = %s FOR UPDATE", (v,)).fetchone()
    if cur is None:
        raise ApiError("not_found", "no such policy version in this organization")
    if cur["status"] != "draft":
        raise ApiError("version_not_draft", "an approved or retired policy version cannot change")
    rules = validate_rules(ctx, rules_in)
    ctx.conn.execute("UPDATE consentvault.policy SET rules = %s::jsonb WHERE org_id = (SELECT consentvault.current_org())"
                     " AND version = %s", (json.dumps(rules), v))
    ctx.audit("policy.updated", "policy", str(v))
    return {"version": v, "status": "draft"}


def approve_policy(ctx: Ctx, version, body: Any) -> dict:
    """Approve a draft with the attestation: the previous policy in force is retired in the same transaction."""
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    if b.get("accepted") is not True:
        raise ApiError("acknowledgement_required", "the attestation was not accepted")
    v = _version(version)
    att = _attestation_row(ctx)
    if b.get("attestation_version") != att["version"] or b.get("attestation_sha256") != att["sha256"]:
        raise ApiError("attestation_mismatch", "the attestation version or digest sent is not the current one")
    ctx.conn.execute("SELECT pg_advisory_xact_lock(hashtext('consentvault.policy:' || (SELECT consentvault.current_org())::text))")
    row = ctx.conn.execute("SELECT * FROM consentvault.policy WHERE org_id = (SELECT consentvault.current_org())"
                           " AND version = %s FOR UPDATE", (v,)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such policy version in this organization")
    if row["status"] != "draft":
        raise ApiError("version_not_draft", "an approved or retired policy version cannot change")
    in_force = ctx.conn.execute("SELECT version FROM consentvault.policy WHERE org_id = (SELECT consentvault.current_org())"
                                " AND status = 'approved'").fetchone()
    if row["based_on_version"] is not None and (in_force is None or in_force["version"] != row["based_on_version"]):
        raise ApiError("policy_superseded", "another policy was approved first",
                       {"newer_version": in_force["version"] if in_force else None})
    validate_rules(ctx, row["rules"])
    retired = None
    if in_force is not None:
        r = ctx.conn.execute("UPDATE consentvault.policy SET status = 'retired', retired_at = now(), retired_by_version = %s"
                             " WHERE org_id = (SELECT consentvault.current_org()) AND version = %s RETURNING retired_at",
                             (v, in_force["version"])).fetchone()
        retired = {"version": in_force["version"], "retired_at": iso(r["retired_at"])}
    me = ctx.actor.member_uuid
    done = ctx.conn.execute("UPDATE consentvault.policy SET status = 'approved', approved_by = %s, approved_at = now()"
                            " WHERE org_id = (SELECT consentvault.current_org()) AND version = %s RETURNING approved_at",
                            (me, v)).fetchone()
    ctx.conn.execute("INSERT INTO consentvault.policy_attestation (org_id, version, attestation_version, attestation_text,"
                     " attestation_sha256, approved_by, approved_at) VALUES ((SELECT consentvault.current_org()), %s, %s,"
                     " %s, %s, %s, %s)", (v, att["version"], att["text"], att["sha256"], me, done["approved_at"]))
    ctx.conn.execute("INSERT INTO consentvault.policy_approval (org_id, version, approved_by, approved_at, attestation_version,"
                     " attestation_sha256) VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s, %s)",
                     (v, me, done["approved_at"], att["version"], att["sha256"]))
    ctx.audit("policy.approved", "policy", str(v))
    return {"version": v, "status": "approved", "approved_by": str(me), "approved_at": iso(done["approved_at"]),
            "retired": retired}


# ======================================================================================================================
# Checklists
# ======================================================================================================================
def _rule_reference_ids(ctx: Ctx) -> set[str]:
    return {str(r["ref_id"]) for r in ctx.conn.execute("SELECT DISTINCT ref_id FROM consentvault.rule_reference")}


def _clean_elements(ctx: Ctx, elements: Any) -> list[dict]:
    if not isinstance(elements, list) or not 1 <= len(elements) <= 100:
        raise invalid(elements="a list of 1 to 100 elements")
    refs = _rule_reference_ids(ctx)
    out = []
    for i, e in enumerate(elements):
        if not isinstance(e, dict):
            raise invalid(**{f"elements[{i}]": "must be an object"})
        name = need_text(e, "name", max_len=200) if isinstance(e.get("name"), str) else None
        if name is None:
            raise invalid(**{f"elements[{i}].name": "required text"})
        desc = e.get("description", "")
        if not isinstance(desc, str) or len(desc) > 500:
            raise invalid(**{f"elements[{i}].description": "text up to 500 characters"})
        req = e.get("required", True)
        if not isinstance(req, bool):
            raise invalid(**{f"elements[{i}].required": "true or false"})
        ref = e.get("rule_reference_id")
        if ref is not None:
            if str(ref) not in refs:
                raise invalid(**{f"elements[{i}].rule_reference_id": "not a known rule reference"})
            ref = str(ref)
        eid = e.get("element_id")
        try:
            eid = str(uuid.UUID(str(eid))) if eid is not None else str(uuid.uuid4())
        except ValueError:
            raise invalid(**{f"elements[{i}].element_id": "must be an id"}) from None
        out.append({"element_id": eid, "name": name, "description": desc, "required": req, "rule_reference_id": ref})
    if len({e["element_id"] for e in out}) != len(out):
        raise invalid(elements="element ids repeat")
    return out


def _checklist_obj(r: dict, *, with_elements: bool = False) -> dict:
    out = {"version": r["version"], "kind": r["kind"], "label": r["label"], "status": r["status"],
           "element_count": len(r["elements"]), "created_at": iso(r["created_at"]),
           "approved_by": str(r["approved_by"]) if r["approved_by"] else None, "approved_at": iso(r["approved_at"])}
    if with_elements:
        out["elements"] = r["elements"]
    return out


def list_checklists(ctx: Ctx, *, kind=None, status=None, limit=None, cursor=None) -> dict:
    ctx.actor.require(*READERS)
    where, params = ["c.org_id = (SELECT consentvault.current_org())"], []
    if kind:
        where.append("c.kind = %s")
        params.append(want_enum(kind, "kind", ("pewc", "custom")))
    if status:
        where.append("c.status = %s")
        params.append(want_enum(status, "status", ("draft", "approved")))
    sql = ("SELECT c.*, c.created_at AS _k1, c.version::text AS _k2 FROM consentvault.doc_checklist c WHERE "
           + " AND ".join(where))
    return paginate(ctx, endpoint="GET /v1/checklists", select_sql=sql, params=params, key_cols=("_k1", "_k2"),
                    key_types=("timestamptz", "text"), descending=True, limit=limit, cursor=cursor, shape=_checklist_obj)


def get_checklist(ctx: Ctx, version) -> dict:
    ctx.actor.require(*READERS)
    row = ctx.conn.execute("SELECT * FROM consentvault.doc_checklist WHERE org_id = (SELECT consentvault.current_org())"
                           " AND version = %s", (_version(version),)).fetchone()
    if row is None:
        raise ApiError("not_found", "no such checklist version in this organization")
    return _checklist_obj(row, with_elements=True)


def create_checklist(ctx: Ctx, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    kind = want_enum(b.get("kind"), "kind", ("pewc", "custom"))
    label = need_text(b, "label")
    elements = _clean_elements(ctx, b.get("elements"))
    v = _next_version(ctx, "doc_checklist", "consentvault.checklist:")
    ctx.conn.execute("INSERT INTO consentvault.doc_checklist (org_id, version, kind, label, elements, created_by)"
                     " VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s::jsonb, %s)",
                     (v, kind, label, json.dumps(elements), ctx.actor.member_uuid))
    ctx.audit("checklist.drafted", "checklist", str(v))
    return {"version": v, "status": "draft"}


def update_checklist(ctx: Ctx, version, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    b = body_dict(body)
    v = _version(version)
    cur = ctx.conn.execute("SELECT status, label FROM consentvault.doc_checklist WHERE org_id = (SELECT consentvault.current_org())"
                           " AND version = %s FOR UPDATE", (v,)).fetchone()
    if cur is None:
        raise ApiError("not_found", "no such checklist version in this organization")
    if cur["status"] != "draft":
        raise ApiError("version_not_draft", "an approved checklist version cannot change")
    label = need_text(b, "label") if "label" in b else cur["label"]
    elements = _clean_elements(ctx, b.get("elements"))
    ctx.conn.execute("UPDATE consentvault.doc_checklist SET label = %s, elements = %s::jsonb"
                     " WHERE org_id = (SELECT consentvault.current_org()) AND version = %s", (label, json.dumps(elements), v))
    ctx.audit("checklist.updated", "checklist", str(v))
    return {"version": v, "status": "draft"}


def approve_checklist(ctx: Ctx, version, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN)
    if body_dict(body).get("acknowledged_documentation_only") is not True:
        raise ApiError("acknowledgement_required", "the acknowledgement that a checklist measures documentation completeness "
                                                   "only was not accepted")
    v = _version(version)
    cur = ctx.conn.execute("SELECT status FROM consentvault.doc_checklist WHERE org_id = (SELECT consentvault.current_org())"
                           " AND version = %s FOR UPDATE", (v,)).fetchone()
    if cur is None:
        raise ApiError("not_found", "no such checklist version in this organization")
    if cur["status"] != "draft":
        raise ApiError("version_not_draft", "an approved checklist version cannot change")
    me = ctx.actor.member_uuid
    row = ctx.conn.execute("UPDATE consentvault.doc_checklist SET status = 'approved', approved_by = %s, approved_at = now()"
                           " WHERE org_id = (SELECT consentvault.current_org()) AND version = %s RETURNING approved_at",
                           (me, v)).fetchone()
    ctx.audit("checklist.approved", "checklist", str(v))
    return {"version": v, "status": "approved", "approved_by": str(me), "approved_at": iso(row["approved_at"])}


def record_doc_checks(ctx: Ctx, body: Any) -> dict:
    """POST /v1/doc-checks: store, per record, which elements of an approved checklist version the record shows.

    The caller names the elements the record shows (``present``); the vault derives ``missing`` as every required
    element not shown. Documentation completeness only. A re-check is a new row and the latest one answers."""
    ctx.actor.require(ROLE_ADMIN)
    results = need_list(body_dict(body), "results", min_items=1, max_items=100)
    out = []
    versions: dict[int, dict] = {}
    for i, item in enumerate(results):
        if not isinstance(item, dict):
            raise invalid(**{f"results[{i}]": "must be an object"})
        try:
            event_id = uuid.UUID(str(item.get("event_id")))
        except ValueError:
            raise invalid(**{f"results[{i}].event_id": "must be a record id"}) from None
        v = item.get("checklist_version")
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise invalid(**{f"results[{i}].checklist_version": "a whole number from 1"})
        present = item.get("present")
        if not isinstance(present, list) or len(present) > 100 or not all(isinstance(p, str) for p in present):
            raise invalid(**{f"results[{i}].present": "a list of element ids"})
        if v not in versions:
            row = ctx.conn.execute("SELECT status, elements FROM consentvault.doc_checklist"
                                   " WHERE org_id = (SELECT consentvault.current_org()) AND version = %s", (v,)).fetchone()
            if row is None:
                raise ApiError("not_found", "no such checklist version in this organization")
            if row["status"] != "approved":
                raise invalid(**{f"results[{i}].checklist_version": "must be an approved version"})
            versions[v] = row["elements"]
        elements = versions[v]
        ids = {e["element_id"] for e in elements}
        shown = sorted(set(present))
        if set(shown) - ids:
            raise invalid(**{f"results[{i}].present": "names an element that is not on the checklist"})
        missing = [e["element_id"] for e in elements if e.get("required", True) and e["element_id"] not in shown]
        try:
            check_id = ctx.conn.execute("SELECT consentvault.record_doc_check_stored(%s, %s, %s, %s, %s) AS id",
                                        (event_id, v, shown, missing, ctx.actor.member_uuid)).fetchone()["id"]
        except psycopg.errors.NoDataFound:
            raise ApiError("not_found", "no such record in this organization") from None
        ctx.audit("checklist.checked", "checklist", str(v), f"record {event_id}")
        out.append({"check_id": str(check_id), "event_id": str(event_id), "checklist_version": v, "present": shown,
                    "missing": missing})
    return {"items": out}


def list_checklist_templates(ctx: Ctx, *, limit=None, cursor=None) -> dict:
    """The PEWC example: documentation elements, each pointing at a rule reference (citation and link), never quoting it."""
    ctx.actor.require(*READERS)
    ref = ctx.conn.execute("SELECT ref_id FROM consentvault.rule_reference WHERE citation = '47 CFR 64.1200'"
                           " ORDER BY version DESC LIMIT 1").fetchone()
    ref_id = str(ref["ref_id"]) if ref else None
    names = (("Seller named", "The wording shown names the seller."),
             ("Channels named", "The wording shown names the channels it covers."),
             ("Automated or artificial voice named", "The wording shown says whether automated or artificial voice is used."),
             ("Agreement captured", "The record shows the person's agreement action and when it happened."),
             ("Consent not a condition of purchase stated", "The wording shown says whether agreement is a condition of purchase."))
    elements = [{"name": n, "description": d, "required": True, "rule_reference_id": ref_id} for n, d in names]
    rows = [("pewc_example", "pewc", "PEWC documentation example", elements)]
    return page_list(ctx, endpoint="GET /v1/checklist-templates", rows=rows, key=lambda t: t[0], limit=limit, cursor=cursor,
                     shape=lambda t: {"template_ref": t[0], "kind": t[1], "label": t[2], "elements": t[3]})


# ======================================================================================================================
# Rule references
# ======================================================================================================================
def list_rule_references(ctx: Ctx, *, jurisdiction=None, limit=None, cursor=None) -> dict:
    ctx.actor.require(*READERS)
    where, params = [], []
    if jurisdiction:
        where.append("jurisdiction = %s")
        params.append(str(jurisdiction))
    sql = ("SELECT * FROM (SELECT DISTINCT ON (ref_id) ref_id, version, jurisdiction, citation, source_url, last_reviewed_on,"
           " lower(citation) AS _k1, ref_id::text AS _k2 FROM consentvault.rule_reference ORDER BY ref_id, version DESC) r"
           + (" WHERE " + " AND ".join(where) if where else ""))
    return paginate(ctx, endpoint="GET /v1/rule-references", select_sql=sql, params=params, key_cols=("_k1", "_k2"),
                    key_types=("text", "text"), descending=False, limit=limit, cursor=cursor,
                    shape=lambda r: {"ref_id": str(r["ref_id"]), "version": r["version"], "jurisdiction": r["jurisdiction"],
                                     "citation": r["citation"], "source_url": r["source_url"],
                                     "last_reviewed_on": r["last_reviewed_on"].isoformat() if r["last_reviewed_on"] else None})
