"""The guarded security surface, and the manifest of it that ships with this build.

The vault's guarantees are database objects: the trigger functions and the functions they call, the triggers, row-level
security and every policy, the grants, and the trigger guard's event triggers. The manifest
(``data/security_manifest.sha256``) holds a SHA-256 of each of them as a clean apply of the shipped migrations leaves them
(``scripts/build_security_manifest.py`` builds it; the checkpoint fails while it is stale). At start the multi-tenant API
reads the same surface from the live database straight from the system catalogs (no vault function is trusted to report
on itself) and refuses to serve on any drift, naming every object that was added, removed or changed.

Covered: the schemas ``consentvault`` and ``consentvault_guard`` (owner and grants); every function in them (its whole
definition: body, SECURITY DEFINER or INVOKER, volatility and search_path; owner; grants); every table, view and sequence
(kind, owner, row security enabled and forced, grants, options, every column with its type, default and grants, view
definition); every trigger, policy, rule, constraint and index on them; and every event trigger the vault's guard
installs. Partitions made month by month after the migration (gate decisions) collapse into one entry per parent: the
set of distinct partition shapes, with each partition's own name read as ``<partition>``. Every other child of a vault
table, in any schema (a partition outside the vault schemas, an inheritance child anywhere), is its own entry
``child <table> of <parent>``, so a child the shipped migrations did not make is drift. Role names are normalised so the manifest does
not depend on a deployment's names: the schema owner reads ``<owner>``, any superuser (or managed-service master user)
``<superuser>``.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import psycopg
from psycopg.rows import tuple_row

from .safelog import describe
from .errors import ConsentVaultError

FORMAT = "consentvault-security-manifest/1"
MANIFEST_PATH = Path(__file__).resolve().parent / "data" / "security_manifest.sha256"
SCHEMAS = ("consentvault", "consentvault_guard")
_LINE = re.compile(r"^([0-9a-f]{64})  (\S.*)$")


class ManifestError(ConsentVaultError):
    """The security manifest is missing or is not a manifest this build reads."""


_SURFACE_SQL = r"""
WITH RECURSIVE ns AS (
    SELECT n.oid, n.nspname, n.nspowner, n.nspacl FROM pg_catalog.pg_namespace n
     WHERE n.nspname = ANY (%(schemas)s::text[])
), owner AS (
    SELECT n.nspowner AS oid FROM pg_catalog.pg_namespace n WHERE n.nspname = 'consentvault'
), rl AS (
    SELECT r.oid,
           CASE WHEN r.oid = (SELECT oid FROM owner) THEN '<owner>'
                WHEN r.rolsuper OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname = 'rds_superuser'
                                            AND pg_catalog.pg_has_role(r.oid, g.oid, 'MEMBER')) THEN '<superuser>'
                ELSE r.rolname::text END AS label
      FROM pg_catalog.pg_roles r
    UNION ALL SELECT 0::oid, 'PUBLIC'
), fns AS (
    SELECT p.oid, p.proowner, p.proacl, p.prokind FROM pg_catalog.pg_proc p JOIN ns ON ns.oid = p.pronamespace
), allrels AS (
    SELECT c.oid, c.relname, c.relkind, c.relowner, c.relacl, c.relrowsecurity, c.relforcerowsecurity, c.reloptions,
           c.relispartition,
           (SELECT i.inhparent FROM pg_catalog.pg_inherits i WHERE i.inhrelid = c.oid AND c.relispartition) AS parent
      FROM pg_catalog.pg_class c JOIN ns ON ns.oid = c.relnamespace
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
), shape AS (
    -- one relation's whole security shape; a partition's own name reads <partition>, so partitions made month by month
    -- collapse into one entry per parent
    SELECT r.oid, r.relispartition, r.parent,
           'kind=' || r.relkind::text || ' owner=' || (SELECT label FROM rl WHERE rl.oid = r.relowner)
           || ' rowsecurity=' || r.relrowsecurity::text || ' force=' || r.relforcerowsecurity::text
           || ' options=' || coalesce(array_to_string(r.reloptions, ','), '')
           || ' acl=' || coalesce((SELECT string_agg(x, ',' ORDER BY x) FROM (
                   SELECT (SELECT label FROM rl WHERE rl.oid = a.grantee) || ':' || a.privilege_type
                          || CASE WHEN a.is_grantable THEN '*' ELSE '' END AS x
                     FROM pg_catalog.aclexplode(r.relacl) a) s), 'default')
           || E'\ncolumns=' || coalesce((SELECT string_agg(x, ';' ORDER BY n) FROM (
                   SELECT att.attnum AS n, att.attname::text || ' ' || pg_catalog.format_type(att.atttypid, att.atttypmod)
                          || CASE WHEN att.attnotnull THEN ' not null' ELSE '' END
                          || coalesce(' default ' || pg_catalog.pg_get_expr(d.adbin, d.adrelid), '')
                          || CASE WHEN att.attgenerated <> '' THEN ' generated ' || att.attgenerated::text ELSE '' END
                          || CASE WHEN att.attidentity <> '' THEN ' identity ' || att.attidentity::text ELSE '' END
                          || coalesce(' acl ' || (SELECT string_agg(y, ',' ORDER BY y) FROM (
                                 SELECT (SELECT label FROM rl WHERE rl.oid = a.grantee) || ':' || a.privilege_type
                                        || CASE WHEN a.is_grantable THEN '*' ELSE '' END AS y
                                   FROM pg_catalog.aclexplode(att.attacl) a) t), '') AS x
                     FROM pg_catalog.pg_attribute att
                     LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = att.attrelid AND d.adnum = att.attnum
                    WHERE att.attrelid = r.oid AND att.attnum > 0 AND NOT att.attisdropped) s), '')
           || CASE WHEN r.relkind IN ('v', 'm') THEN E'\nview=' || pg_catalog.pg_get_viewdef(r.oid) ELSE '' END
           || CASE WHEN r.relispartition THEN
                  E'\ntriggers=' || coalesce((SELECT string_agg(x, E'\n' ORDER BY x) FROM (
                      SELECT replace(pg_catalog.pg_get_triggerdef(t.oid), r.oid::pg_catalog.regclass::text, '<partition>')
                             || ' enabled=' || t.tgenabled::text AS x
                        FROM pg_catalog.pg_trigger t WHERE t.tgrelid = r.oid AND NOT t.tgisinternal) s), '')
                  || E'\npolicies=' || coalesce((SELECT string_agg(x, E'\n' ORDER BY x) FROM (
                      SELECT p.polname::text || ' ' || p.polpermissive::text || ' ' || p.polcmd::text || ' '
                             || coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '') || ' '
                             || coalesce(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '') AS x
                        FROM pg_catalog.pg_policy p WHERE p.polrelid = r.oid) s), '')
                  || E'\nrules=' || coalesce((SELECT string_agg(x, E'\n' ORDER BY x) FROM (
                      SELECT replace(pg_catalog.pg_get_ruledef(w.oid), r.oid::pg_catalog.regclass::text, '<partition>') AS x
                        FROM pg_catalog.pg_rewrite w WHERE w.ev_class = r.oid AND w.rulename <> '_RETURN') s), '')
              ELSE '' END AS canon
      FROM allrels r
), rels AS (
    SELECT * FROM allrels WHERE NOT relispartition
), kids(rel, parent) AS (
    -- every table in any schema that inherits from a vault-schema table, directly or through another child
    SELECT i.inhrelid, i.inhparent FROM pg_catalog.pg_inherits i
      JOIN pg_catalog.pg_class p ON p.oid = i.inhparent
     WHERE p.relnamespace IN (SELECT oid FROM ns) AND p.relkind IN ('r', 'p', 'f')
    UNION
    SELECT i.inhrelid, i.inhparent FROM pg_catalog.pg_inherits i JOIN kids k ON i.inhparent = k.rel
)
SELECT 'schema ' || ns.nspname AS key,
       'owner=' || (SELECT label FROM rl WHERE rl.oid = ns.nspowner)
       || ' acl=' || coalesce((SELECT string_agg(x, ',' ORDER BY x) FROM (
               SELECT (SELECT label FROM rl WHERE rl.oid = a.grantee) || ':' || a.privilege_type
                      || CASE WHEN a.is_grantable THEN '*' ELSE '' END AS x
                 FROM pg_catalog.aclexplode(ns.nspacl) a) s), 'default') AS canon
  FROM ns
UNION ALL
SELECT 'function ' || f.oid::pg_catalog.regprocedure::text,
       CASE WHEN f.prokind = 'a' THEN 'aggregate' ELSE pg_catalog.pg_get_functiondef(f.oid) END
       || E'\nowner=' || (SELECT label FROM rl WHERE rl.oid = f.proowner)
       || ' acl=' || coalesce((SELECT string_agg(x, ',' ORDER BY x) FROM (
               SELECT (SELECT label FROM rl WHERE rl.oid = a.grantee) || ':' || a.privilege_type
                      || CASE WHEN a.is_grantable THEN '*' ELSE '' END AS x
                 FROM pg_catalog.aclexplode(f.proacl) a) s), 'default')
  FROM fns f
UNION ALL
SELECT 'relation ' || s.oid::pg_catalog.regclass::text, s.canon FROM shape s WHERE NOT s.relispartition
UNION ALL
SELECT 'partitions of ' || s.parent::pg_catalog.regclass::text, string_agg(DISTINCT s.canon, E'\n---\n')
  FROM shape s WHERE s.relispartition GROUP BY s.parent
UNION ALL
SELECT 'child ' || k.rel::pg_catalog.regclass::text || ' of ' || k.parent::pg_catalog.regclass::text,
       'kind=' || c.relkind::text || ' partition=' || c.relispartition::text || ' schema=' || n.nspname::text
       || ' owner=' || coalesce((SELECT label FROM rl WHERE rl.oid = c.relowner), '?')
  FROM kids k
  JOIN pg_catalog.pg_class c ON c.oid = k.rel
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r', 'p', 'f') AND NOT (c.relispartition AND c.relnamespace IN (SELECT oid FROM ns))
UNION ALL
SELECT 'trigger ' || t.tgname::text || ' on ' || t.tgrelid::pg_catalog.regclass::text,
       pg_catalog.pg_get_triggerdef(t.oid) || ' enabled=' || t.tgenabled::text
  FROM pg_catalog.pg_trigger t JOIN rels r ON r.oid = t.tgrelid
 WHERE NOT t.tgisinternal
UNION ALL
SELECT 'policy ' || p.polname::text || ' on ' || p.polrelid::pg_catalog.regclass::text,
       'permissive=' || p.polpermissive::text || ' cmd=' || p.polcmd::text
       || ' roles=' || coalesce((SELECT string_agg(l, ',' ORDER BY l) FROM (
               SELECT (SELECT label FROM rl WHERE rl.oid = o) AS l FROM unnest(p.polroles) o) s), '')
       || E'\nusing=' || coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), '')
       || E'\ncheck=' || coalesce(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
  FROM pg_catalog.pg_policy p JOIN rels r ON r.oid = p.polrelid
UNION ALL
SELECT 'rule ' || w.rulename::text || ' on ' || w.ev_class::pg_catalog.regclass::text, pg_catalog.pg_get_ruledef(w.oid)
  FROM pg_catalog.pg_rewrite w JOIN rels r ON r.oid = w.ev_class
 WHERE w.rulename <> '_RETURN'
UNION ALL
SELECT 'constraint ' || k.conname::text || ' on ' || k.conrelid::pg_catalog.regclass::text,
       k.contype::text || ' ' || pg_catalog.pg_get_constraintdef(k.oid)
       || CASE WHEN k.condeferrable THEN ' deferrable' ELSE '' END || CASE WHEN k.convalidated THEN '' ELSE ' not valid' END
  FROM pg_catalog.pg_constraint k JOIN rels r ON r.oid = k.conrelid
 WHERE k.conparentid = 0
UNION ALL
SELECT 'index ' || x.indexrelid::pg_catalog.regclass::text, pg_catalog.pg_get_indexdef(x.indexrelid)
       || CASE WHEN x.indisvalid THEN '' ELSE ' invalid' END
  FROM pg_catalog.pg_index x JOIN rels r ON r.oid = x.indrelid
UNION ALL
SELECT 'event trigger ' || e.evtname::text,
       'event=' || e.evtevent::text || ' function=' || e.evtfoid::pg_catalog.regprocedure::text
       || ' enabled=' || e.evtenabled::text || ' owner=' || (SELECT label FROM rl WHERE rl.oid = e.evtowner)
       || ' tags=' || coalesce((SELECT string_agg(t, ',' ORDER BY t) FROM unnest(e.evttags) t), '')
  FROM pg_catalog.pg_event_trigger e
  JOIN pg_catalog.pg_proc p ON p.oid = e.evtfoid
 WHERE e.evtname::text LIKE 'consentvault%%' OR p.pronamespace IN (SELECT oid FROM ns)
"""


def live_surface(conn: psycopg.Connection) -> dict:
    """The security surface of the database ``conn`` is on: {"postgres_major": int, "objects": {name: sha256}}.

    Read from the system catalogs with the search path pinned to pg_catalog, so names print schema-qualified and the
    result does not depend on the session. Any role can read it; the API reads it as its runtime login."""
    try:
        with conn.transaction():
            cur = conn.cursor(row_factory=tuple_row)
            cur.execute("SELECT pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true)")
            major = int(cur.execute("SELECT pg_catalog.current_setting('server_version_num')").fetchone()[0]) // 10000
            rows = cur.execute(_SURFACE_SQL, {"schemas": list(SCHEMAS)}).fetchall()
    except psycopg.Error as exc:
        raise ManifestError(f"the security surface could not be read from the database: "
                            f"{describe(exc)}") from exc
    objects: dict[str, str] = {}
    for key, canon in rows:
        if canon is None:
            raise ManifestError(f"the security surface could not describe {key}")
        if key in objects:
            raise ManifestError(f"the security surface names {key} twice")
        objects[key] = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    return {"postgres_major": major, "objects": objects}


def render(surface: dict) -> bytes:
    """The manifest file's bytes for a surface: the same surface always renders the same bytes. Two header lines (format,
    PostgreSQL major version), then one line per object, "<sha256>  <object>", sorted by object (the sha256sum layout)."""
    lines = [f"# {FORMAT}", f"# postgres_major {surface['postgres_major']}"]
    lines += [f"{v}  {k}" for k, v in sorted(surface["objects"].items())]
    return ("\n".join(lines) + "\n").encode("utf-8")


def load_manifest(path: Path | None = None) -> dict:
    """The committed manifest. A missing or malformed file is a named error, never an empty manifest."""
    p = Path(path) if path else MANIFEST_PATH
    if not p.is_file():
        raise ManifestError(f"the security manifest is missing at {p}: build it with scripts/build_security_manifest.py")
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ManifestError(f"the security manifest at {p} cannot be read: {describe(exc)}") from exc
    return parse_manifest(data, str(p))


def parse_manifest(data: bytes, source: str) -> dict:
    """A manifest's bytes as {"format", "postgres_major", "objects"}; anything else is a named error."""
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ManifestError(f"the security manifest at {source} is not UTF-8: {describe(exc)}") from exc
    if len(lines) < 3 or lines[0] != f"# {FORMAT}":
        raise ManifestError(f"the security manifest at {source} is not format {FORMAT}")
    m = re.fullmatch(r"# postgres_major (\d+)", lines[1])
    if m is None:
        raise ManifestError(f"the security manifest at {source} names no postgres_major on its second line")
    objects: dict[str, str] = {}
    for line in lines[2:]:
        hit = _LINE.match(line)
        if hit is None:
            raise ManifestError(f"the security manifest at {source} has a line that is not '<sha256>  <object>': {line!r}")
        if hit.group(2) in objects:
            raise ManifestError(f"the security manifest at {source} names {hit.group(2)} twice")
        objects[hit.group(2)] = hit.group(1)
    return {"format": FORMAT, "postgres_major": int(m.group(1)), "objects": objects}


def drift(live: dict, manifest: dict) -> list[str]:
    """Every difference between a live surface and the manifest, one line per object: added, changed, removed."""
    if live["postgres_major"] != manifest["postgres_major"]:
        return [f"postgres major version {live['postgres_major']} is not the manifest's {manifest['postgres_major']}: "
                "rebuild the manifest on this major version and ship it"]
    have, want = live["objects"], manifest["objects"]
    out = [f"added: {k}" for k in sorted(set(have) - set(want))]
    out += [f"changed: {k}" for k in sorted(set(have) & set(want)) if have[k] != want[k]]
    out += [f"removed: {k}" for k in sorted(set(want) - set(have))]
    return out
