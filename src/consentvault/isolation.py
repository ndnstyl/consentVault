"""The tenant-table registry and the nightly isolation self-test (``consentvault isolation-self-test``).

The registry (``tenant_tables``, ``tenant_views``, ``PLATFORM_TABLES``) is the one list the isolation test suite and this
job both read: every ordinary or partitioned table in the schema with an ``org_id`` column (partitions are reached
through their parent), minus the platform tables that carry an org_id but belong to no tenant, read from the catalog, so
a table added later is covered without editing either.

The self-test runs as its own login, a member of ``consentvault_isolation_self_test`` (migration 0059): SELECT on every
tenant table and view and nothing else, and a token for the two canary organisations only (``isolation_canary_token``),
never for a real one. One run:

1. takes the canary pair (``isolation_canary_pair``: two closed organisations with an organisation row, a brand and a
   capture source each, made on the first run and kept);
2. checks each table's shape: row security enabled and forced, and a tenant policy whose read and write conditions are
   bound to ``current_org()``;
3. with no token, reads every table and view: nothing may be visible;
4. under each canary's token, reads every table and view: no row of any other organisation may be visible (the other
   canary's and every real organisation's rows are the other side), and the canary's own seeded rows must be (a probe
   that sees nothing proves nothing).

Any finding (a row read across organisations, a shape that is not bound, a table the login cannot read, a blind probe)
fails the run with ``IsolationLeak``; the command exits 3, sends no heartbeat and writes the count as ``IsolationLeaks``.
Findings name tables, canary labels and counts only, never a row.
"""

from __future__ import annotations

from typing import Callable

import psycopg
from psycopg import sql

from .errors import ConsentVaultError

GROUP = "consentvault_isolation_self_test"
# Platform tables that carry an org_id but belong to no tenant: owner-only, no grant to any runtime role, reached only
# through owner-rights functions. replay_guard holds nonces before a tenant is entered; billing_event holds Stripe
# webhooks that arrive before the organisation is known. Any other org_id table without row-level security fails.
PLATFORM_TABLES = frozenset({"replay_guard", "billing_event"})
# What each canary is seeded with, so each probe has rows of its own to see.
SEEDED = ("organization", "brand", "capture_source")
LABELS = ("a", "b")


class IsolationLeak(ConsentVaultError):
    """The self-test found a finding. ``report`` is the whole run's answer, ``report["findings"]`` the list."""

    def __init__(self, message: str, report: dict) -> None:
        super().__init__(message)
        self.report = report


class SelfTestLoginRefused(ConsentVaultError):
    """The login is not a member of the self-test group: it holds no canary token and would prove nothing."""


def tenant_tables(conn) -> tuple[str, ...]:
    """Every ordinary or partitioned table in the schema with an org_id column, minus the named platform tables.

    Partitions are left out: they inherit the parent's policies and are reached through it.
    """
    rows = conn.execute(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'org_id' AND NOT a.attisdropped"
        " WHERE n.nspname = 'consentvault' AND c.relkind IN ('r', 'p') AND NOT c.relispartition"
        " ORDER BY c.relname").fetchall()
    return tuple(r["relname"] for r in rows if r["relname"] not in PLATFORM_TABLES)


def tenant_views(conn) -> tuple[str, ...]:
    """Every view in the schema with an org_id column."""
    rows = conn.execute(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'org_id' AND NOT a.attisdropped"
        " WHERE n.nspname = 'consentvault' AND c.relkind = 'v' ORDER BY c.relname").fetchall()
    return tuple(r["relname"] for r in rows)


def is_self_test_login(conn) -> bool:
    row = conn.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = %s"
                       " AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')) AS member", (GROUP,)).fetchone()
    return bool(row["member"])


def require_self_test_login(conn) -> None:
    from .job_logins import privileged

    why = privileged(conn)
    if why:
        raise SelfTestLoginRefused(f"{why}: it would read past row security and prove nothing. Run this job as the "
                                   "isolation self-test login", code='selftest_login_privileged')
    if is_self_test_login(conn):
        return
    who = conn.execute("SELECT current_user AS u").fetchone()["u"]
    raise SelfTestLoginRefused(f"login {who} is not a member of {GROUP}: it holds no canary token and would prove nothing. "
                               "Run this job as the isolation self-test login", code='selftest_login_not_in_group')


def _reason(exc: BaseException) -> str:
    # A database error's text can quote a value; only its class and code are kept.
    return f"{type(exc).__name__} (SQLSTATE {getattr(exc, 'sqlstate', None)})"


# The one tenant binding the schema's policies use, as PostgreSQL prints it back.
BOUND = "(org_id = ( SELECT consentvault.current_org() AS current_org))"


def _bound(expr) -> bool:
    """The expression is the tenant binding, alone or narrowed by AND (never widened: PostgreSQL prints an OR at the top
    with its own outer parentheses, so it never starts with the binding)."""
    return expr is not None and (expr == BOUND or expr.startswith(f"({BOUND} AND "))


def _shape(conn, tables: tuple[str, ...], views: tuple[str, ...]) -> list[dict]:
    """Row security enabled and forced on every tenant table; a tenant policy (``*_tenant``) on each; and every permissive
    policy on it, for any role and any command, bound to current_org() in each expression it has (a permissive policy
    widens what a role reads, so one left open lets that role read every organisation). Every tenant view runs with its
    reader's rights (security_invoker)."""
    found = []
    flags = {r["relname"]: r for r in conn.execute(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, c.reloptions FROM pg_class c JOIN pg_namespace n"
        " ON n.oid = c.relnamespace WHERE n.nspname = 'consentvault' AND c.relname = ANY(%s)", (list(tables + views),))}
    policies: dict[str, list] = {}
    for r in conn.execute("SELECT tablename, policyname, permissive, roles::text AS roles, cmd, qual, with_check"
                          " FROM pg_catalog.pg_policies WHERE schemaname = 'consentvault'"):
        policies.setdefault(r["tablename"], []).append(r)
    for t in tables:
        f = flags.get(t)
        if f is None or not f["relrowsecurity"]:
            found.append({"table": t, "kind": "row_security_off"})
            continue
        if not f["relforcerowsecurity"]:
            found.append({"table": t, "kind": "row_security_not_forced"})
        ps = policies.get(t, [])
        if not any(p["policyname"].endswith("_tenant") for p in ps):
            found.append({"table": t, "kind": "no_tenant_policy"})
        for p in ps:
            if p["permissive"] != "PERMISSIVE":
                continue  # a restrictive policy only narrows
            exprs = [e for e in (p["qual"], p["with_check"]) if e is not None]
            if not exprs or not all(_bound(e) for e in exprs) or (p["cmd"] == "ALL" and len(exprs) < 2):
                found.append({"table": t, "kind": "policy_not_bound_to_tenant", "policy": p["policyname"],
                              "roles": p["roles"]})
    for v in views:
        f = flags.get(v)
        if f is None or "security_invoker=true" not in (f["reloptions"] or []):
            found.append({"table": v, "kind": "view_not_security_invoker"})
    return found


def _count(conn, rel: str, where: sql.Composable) -> int:
    q = sql.SQL("SELECT count(*) AS n FROM {}.{} WHERE ").format(sql.Identifier("consentvault"), sql.Identifier(rel)) + where
    return int(conn.execute(q).fetchone()["n"])


def _probe_without_token(conn, rels: tuple[str, ...], found: list, unprobed: set) -> None:
    for rel in rels:
        try:
            with conn.transaction():
                n = _count(conn, rel, sql.SQL("true"))
        except psycopg.Error as exc:  # loud-failure-exempt: a table that cannot be read is a finding, never a skip
            found.append({"table": rel, "kind": "not_probed", "reason": _reason(exc)})
            unprobed.add(rel)
            continue
        if n:
            found.append({"table": rel, "kind": "reads_without_a_tenant", "rows": n})


def _probe_as(conn, label: str, rels: tuple[str, ...], found: list, unprobed: set, controls: dict) -> None:
    from .tenancy.tokens import org_transaction

    token = conn.execute("SELECT consentvault.isolation_canary_token(%s) AS t", (label,)).fetchone()["t"]
    controls[label] = {}
    with org_transaction(conn, token):
        for rel in rels:
            if rel in unprobed:
                continue
            try:
                with conn.transaction():
                    other = _count(conn, rel, sql.SQL("org_id IS DISTINCT FROM (SELECT consentvault.current_org())"))
                    own = _count(conn, rel, sql.SQL("org_id = (SELECT consentvault.current_org())")) if rel in SEEDED else None
            except psycopg.Error as exc:  # loud-failure-exempt: a table that cannot be read is a finding, never a skip
                found.append({"table": rel, "kind": "not_probed", "canary": label, "reason": _reason(exc)})
                continue
            if other:
                found.append({"table": rel, "kind": "reads_other_organisations", "canary": label, "rows": other})
            if own is not None:
                controls[label][rel] = own
                if own < 1:
                    found.append({"table": rel, "kind": "probe_blind", "canary": label})


def run(connect: Callable[[], psycopg.Connection]) -> dict:
    """One self-test (see the module text). Returns the report on a clean run; raises ``IsolationLeak`` with it on any
    finding, and ``SelfTestLoginRefused`` before anything is read when the login is wrong."""
    with connect() as conn:
        require_self_test_login(conn)
        try:
            pair = {r["label"]: str(r["org_id"]) for r in conn.execute(
                "SELECT label, org_id FROM consentvault.isolation_canary_pair()")}
        except psycopg.Error as exc:  # its text can quote a row; only the class and SQLSTATE travel
            finding = {"table": None, "kind": "no_canary_pair", "reason": _reason(exc)}
            raise IsolationLeak(f"the canary pair could not be taken: {finding['reason']}",
                                {"findings": [finding], "canaries": {}}) from None
        if set(pair) != set(LABELS):
            raise IsolationLeak(f"the canary pair answered {sorted(pair)}, expected {list(LABELS)}",
                                {"findings": [{"table": None, "kind": "no_canary_pair"}], "canaries": pair})
        tables, views = tenant_tables(conn), tenant_views(conn)
        rels = tables + views
        found = _shape(conn, tables, views)
        # a test cluster's clock role on this server (api.TEST_CLOCK_ROLE): refused at start, and raised here every night
        if conn.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname OPERATOR(pg_catalog.=)"
                        " 'consentvault_test_clock') AS present").fetchone()["present"]:
            found.append({"table": None, "kind": "test_clock_role_present"})
        unprobed: set = set()
        _probe_without_token(conn, rels, found, unprobed)
        controls: dict = {}
        for label in LABELS:
            _probe_as(conn, label, rels, found, unprobed, controls)
    report = {"canaries": pair, "probed": [r for r in rels if r not in unprobed], "positive_controls": controls,
              "findings": found}
    if found:
        raise IsolationLeak(f"the isolation self-test found {len(found)} finding(s): "
                            + "; ".join(f"{f['table']}: {f['kind']}" + (f" (canary {f['canary']})" if f.get("canary") else "")
                                        for f in found[:50]), report)
    return report
