"""Setup progress (setup.md): eight steps whose done state is derived from facts on every read; only a skip is stored.

No personal data is read or returned: each fact is a count, an id or a time. Not audited on read (configuration only);
a skip and an un-skip are audited."""

from __future__ import annotations

from typing import Any, Callable, Optional

import psycopg

from .. import testing
from .admin_base import (ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER, ApiError, Ctx, body_dict, iso, opt_text,
                         require_not_closed)

ORDER = ("brand", "source", "wording", "credential", "first_event", "policy", "system", "confirmations")
REQUIRED = {s: s not in ("system", "confirmations") for s in ORDER}
ROLES = {
    "brand": ["admin"], "source": ["admin", "developer"], "wording": ["admin"], "credential": ["admin", "developer"],
    "first_event": ["admin", "developer"], "policy": ["admin"], "system": ["admin", "developer"], "confirmations": ["admin"],
}
SKIPPABLE = ("system", "confirmations")
_ORG = "(SELECT consentvault.current_org())"


# ---- the facts: each returns (kind, id, at) when the step is done, None when it is not -----------------------------------
def _brand(conn):
    r = conn.execute(f"SELECT brand_id, created_at FROM consentvault.brand WHERE org_id = {_ORG}"
                     " ORDER BY created_at, brand_id LIMIT 1").fetchone()
    return ("brand", str(r["brand_id"]), r["created_at"]) if r else None


def _source(conn):
    r = conn.execute("SELECT source_id, created_at FROM consentvault.capture_source"
                     f" WHERE org_id = {_ORG} AND kind <> 'system' AND status = 'active'"
                     " ORDER BY created_at, source_id LIMIT 1").fetchone()
    return ("source", str(r["source_id"]), r["created_at"]) if r else None


def _wording(conn):
    r = conn.execute(f"SELECT sha256, first_seen_at FROM consentvault.disclosure WHERE org_id = {_ORG}"
                     " ORDER BY first_seen_at, sha256 LIMIT 1").fetchone()
    return ("wording", r["sha256"], r["first_seen_at"]) if r else None


def _credential(conn):
    r = conn.execute("SELECT credential_id, created_at FROM consentvault.credential"
                     f" WHERE org_id = {_ORG} AND revoked_at IS NULL AND 'capture' = ANY (scope)"
                     " ORDER BY created_at, credential_id LIMIT 1").fetchone()
    return ("credential", str(r["credential_id"]), r["created_at"]) if r else None


def _first_event(conn):
    r = conn.execute("SELECT first_event_at FROM consentvault.health_counts()").fetchone()
    return ("event", None, r["first_event_at"]) if r and r["first_event_at"] else None


def _policy(conn):
    r = conn.execute(f"SELECT version, approved_at FROM consentvault.policy WHERE org_id = {_ORG} AND status = 'approved'"
                     " ORDER BY version DESC LIMIT 1").fetchone()
    return ("policy", str(r["version"]), r["approved_at"]) if r else None


def _system(conn):
    r = conn.execute("SELECT system_id, coalesce((last_test->>'at')::timestamptz, created_at) AS at"
                     f" FROM consentvault.connected_system WHERE org_id = {_ORG} AND status = 'active'"
                     " AND jsonb_typeof(last_test->'http_status') = 'number'"
                     " AND (last_test->>'http_status')::numeric >= 200 AND (last_test->>'http_status')::numeric < 300"
                     " ORDER BY 2 DESC, system_id LIMIT 1").fetchone()
    return ("system", str(r["system_id"]), r["at"]) if r else None


def _confirmations(conn):
    r = conn.execute("SELECT source_id, channel, updated_at FROM consentvault.confirmation_rule"
                     f" WHERE org_id = {_ORG} AND enabled ORDER BY updated_at, source_id, channel LIMIT 1").fetchone()
    return ("confirmation_rule", f"{r['source_id']}:{r['channel']}", r["updated_at"]) if r else None


FACTS: dict[str, Callable] = {"brand": _brand, "source": _source, "wording": _wording, "credential": _credential,
                              "first_event": _first_event, "policy": _policy, "system": _system,
                              "confirmations": _confirmations}


def _read_fact(ctx: Ctx, step: str):
    """(True, fact) when the fact was read, (False, None) when it could not be: the switch or a database error."""
    if "setup.fact." + step in testing.fail_reads:
        return False, None
    try:
        with ctx.conn.transaction():
            return True, FACTS[step](ctx.conn)
    except psycopg.Error:  # loud-failure-exempt: the step answers status null and is named in partial; never to_do or done
        return False, None


def _skips(ctx: Ctx) -> dict:
    return {r["step"]: r for r in ctx.conn.execute(
        f"SELECT step, skipped_by, skipped_at, reason FROM consentvault.setup_step_skip WHERE org_id = {_ORG}")}


def _step_obj(step: str, status: Optional[str], fact, skip, blocked_reason: Optional[str]) -> dict:
    return {"step": step, "status": status, "required": REQUIRED[step],
            "evidence": {"kind": fact[0], "id": fact[1], "at": iso(fact[2])} if fact else None,
            "blocked_reason": blocked_reason if status == "blocked" else None,
            "skipped_by": str(skip["skipped_by"]) if skip and skip["skipped_by"] else None,
            "skipped_at": iso(skip["skipped_at"]) if skip else None,
            "skip_reason": skip["reason"] if skip else None, "roles": list(ROLES[step])}


def _org_suspended(ctx: Ctx) -> bool:
    r = ctx.conn.execute(f"SELECT status FROM consentvault.organization WHERE org_id = {_ORG}").fetchone()
    return bool(r) and r["status"] == "suspended"


def _all(ctx: Ctx) -> tuple[dict, list]:
    facts, partial = {}, []
    for step in ORDER:
        ok, fact = _read_fact(ctx, step)
        facts[step] = (ok, fact)
        if not ok:
            partial.append(step)
    skips = _skips(ctx)
    suspended = _org_suspended(ctx)
    steps = {}
    for step in ORDER:
        ok, fact = facts[step]
        skip = skips.get(step)
        if not ok:
            steps[step] = _step_obj(step, None, None, skip, None)
            continue
        reason = None
        if step in ("credential", "system") and suspended:
            reason = "org_suspended"
        elif step == "first_event" and facts["wording"][0] and facts["wording"][1] is None:
            reason = "needs:wording"
        if fact:
            status = "done"
        elif skip:
            status = "skipped"
        elif reason:
            status = "blocked"
        else:
            status = "to_do"
        steps[step] = _step_obj(step, status, fact, skip, reason)
    return steps, partial


def get_setup(ctx: Ctx) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER, ROLE_VIEWER)
    steps, partial = _all(ctx)
    ordered = [steps[s] for s in ORDER]
    current = next((s["step"] for s in ordered if s["status"] not in ("done", "skipped")), None)
    complete = all(s["status"] == "done" for s in ordered if s["required"])
    return {"steps": ordered, "current_step": current, "complete": complete, "partial": partial}


def _check_step(ctx: Ctx, step: str) -> None:
    if step not in SKIPPABLE:
        raise ApiError("step_not_skippable", "only the connected system and confirmation steps can be skipped", {"step": step})
    if step == "confirmations":
        ctx.actor.require(ROLE_ADMIN)


def skip_step(ctx: Ctx, step: str, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    _check_step(ctx, step)
    reason = opt_text(body_dict(body), "reason", max_len=200)
    require_not_closed(ctx)
    ok, fact = _read_fact(ctx, step)
    if not ok:
        raise ApiError("service_unavailable", "the fact behind this step could not be read; nothing was changed")
    if fact:
        raise ApiError("validation_failed", "a step that is already done cannot be skipped", {"step": "already done"})
    ctx.conn.execute(
        "INSERT INTO consentvault.setup_step_skip (org_id, step, skipped_by, reason)"
        f" VALUES ({_ORG}, %s, %s, %s) ON CONFLICT (org_id, step) DO UPDATE SET skipped_by = EXCLUDED.skipped_by,"
        " skipped_at = clock_timestamp(), reason = EXCLUDED.reason", (step, ctx.actor.member_uuid, reason))
    ctx.audit("setup.step_skipped", "setup_step", step, reason=reason)
    return _one(ctx, step)


def unskip_step(ctx: Ctx, step: str, body: Any) -> dict:
    ctx.actor.require(ROLE_ADMIN, ROLE_DEVELOPER)
    _check_step(ctx, step)
    body_dict(body)
    require_not_closed(ctx)
    n = ctx.conn.execute(f"DELETE FROM consentvault.setup_step_skip WHERE org_id = {_ORG} AND step = %s", (step,)).rowcount
    if n:
        ctx.audit("setup.step_unskipped", "setup_step", step)
    return _one(ctx, step)


def _one(ctx: Ctx, step: str) -> dict:
    steps, _ = _all(ctx)
    return steps[step]
