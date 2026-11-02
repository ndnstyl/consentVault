"""The records export worker's own login (migration 0050, group consentvault_records_jobs): the exact privilege set, the
refusal of any other login in multi-tenant mode, and an export built end to end as that login."""

import psycopg
import pytest

from consentvault import db, records_exports
from consentvault.cli import EXIT_BROKEN

from contract_world import exports as ex
from contract_world.world import PHONE, PHONE2

GROUP = "consentvault_records_jobs"

FUNCTIONS = {
    "dispatch_org_ids(text)", "dispatch_org_token(text, uuid)", "enter_org(text)", "current_org()", "current_token_scopes()",
    "may_read_evidence()", "may_read_names()", "may_read_records()", "may_read_display_key()", "may_read_record_exports()", "contact_key_of(text)",
    "append_audit(text, text, text, text, text, text, text)", "append_audit_detailed(text, text, text, text, text, text, text, jsonb)"}
TABLES = {("record", "SELECT"), ("record_index", "SELECT"), ("record_display", "SELECT"), ("org_display_key", "SELECT"),
          ("record_export", "SELECT"), ("channel", "SELECT"), ("purpose", "SELECT"),
          ("record_export_record", "SELECT"), ("record_export_record", "INSERT"),
          ("record_export_key", "SELECT"), ("record_export_key", "INSERT")}
COLUMNS = {("capture_source", "SELECT", frozenset({"org_id", "source_id", "name"})),
           ("brand", "SELECT", frozenset({"org_id", "brand_id"})),
           ("organization", "SELECT", frozenset({"org_id", "name"})),
           ("event", "SELECT", frozenset({"org_id", "event_id", "seq", "contact_fp", "contact_ct"})),
           ("record_export_key", "UPDATE", frozenset({"wrapped", "destroyed_at", "object_state"})),
           ("record_export", "UPDATE", frozenset({"status", "row_count", "progress_done", "completed_at", "expires_at",
                                                  "sha256", "failed_cause"}))}


def test_the_group_holds_exactly_the_privileges_building_an_export_needs(world):
    with world.vault.superuser() as su:
        fn = {r["sig"] for r in su.execute(
            "SELECT p.proname || '(' || oidvectortypes(p.proargtypes) || ')' AS sig FROM pg_proc p"
            " WHERE p.pronamespace = 'consentvault'::regnamespace AND p.proacl IS NOT NULL"
            " AND EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = %s::regrole)", (GROUP,))}
        assert fn == FUNCTIONS, fn ^ FUNCTIONS
        tables = {(r["t"], r["priv"]) for r in su.execute(
            "SELECT c.relname AS t, a.privilege_type AS priv FROM pg_class c, aclexplode(c.relacl) a"
            " WHERE c.relnamespace = 'consentvault'::regnamespace AND a.grantee = %s::regrole", (GROUP,))}
        assert tables == TABLES, tables ^ TABLES
        cols: dict = {}
        for r in su.execute(
                "SELECT c.relname AS t, a.privilege_type AS priv, att.attname AS col FROM pg_class c"
                " JOIN pg_attribute att ON att.attrelid = c.oid, aclexplode(att.attacl) a"
                " WHERE c.relnamespace = 'consentvault'::regnamespace AND a.grantee = %s::regrole AND att.attacl IS NOT NULL",
                (GROUP,)):
            cols.setdefault((r["t"], r["priv"]), set()).add(r["col"])
        assert {(t, p, frozenset(c)) for (t, p), c in cols.items()} == COLUMNS


def test_the_group_cannot_call_erase_reveal_admin_or_billing_functions_or_write_anything_else(world):
    with db.connect(world.vault.records_jobs_dsn) as c:
        assert c.execute("SELECT count(*) AS n FROM consentvault.record").fetchone()["n"] == 0  # no token, no rows
        forbidden = (
            "SELECT consentvault.erase_contact(repeat('a', 64))",
            "SELECT consentvault.sign_org_token(gen_random_uuid(), ARRAY['admin'], NULL, 60)",
            "SELECT consentvault.record_reveal_note('m', ARRAY[gen_random_uuid()])",
            "SELECT consentvault.record_call_take('m', 30, 600)",
            "SELECT consentvault.record_index_rebuild(gen_random_uuid())",
            "SELECT consentvault.org_alarm_clear('reveal_volume')",
            "SELECT * FROM consentvault.contact_key", "SELECT * FROM consentvault.member", "SELECT * FROM consentvault.credential",
            "INSERT INTO consentvault.record_export_link (org_id, export_id, minted_by, minted_at, expires_at)"
            " VALUES (gen_random_uuid(), gen_random_uuid(), 'x', now(), now())",
            "DELETE FROM consentvault.record_export", "UPDATE consentvault.record_export SET requested_by = 'x'")
        for sql in forbidden:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(sql)


def test_a_login_outside_the_group_is_refused_in_multi_tenant_mode_with_exit_3(world):
    with world.vault.operator() as console:
        with pytest.raises(records_exports.JobLoginRefused):
            records_exports.require_jobs_login(console)
    with db.connect(world.vault.records_jobs_dsn) as jobs:
        records_exports.require_jobs_login(jobs)  # the group's own login passes
    rc = records_exports.main(env={"CONSENTVAULT_DSN": world.vault.operator_dsn})
    assert rc == EXIT_BROKEN


def test_an_export_is_built_end_to_end_by_the_records_jobs_login(world):
    """a full export held while building, then built by a pass that runs only as the group's login: the file opens, the audit
    rows name the worker, and the worker could read names only for this organization's token."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz"})
    world.capture(o, PHONE2)
    with world.hold_steps("records.export.build"):
        started = ex.start(o.boss, contact_form="full", reason="end to end")
    assert o.boss.ok("GET", f"/v1/records/exports/{started['export_id']}")["status"] == "building"
    assert records_exports.run_export_builds(now=world.vault.app._clock()) == 1
    ready = ex.wait_ready(o.boss, started["export_id"])
    z, rows, manifest = ex.open_zip(ex.download(world, o.boss, ready["download_url"]).body)
    assert {PHONE, PHONE2} <= {v for r in rows for v in r.values()} and manifest["row_count"] == 2
    (built,) = world.audit(o.boss, "records.export_built")
    assert built["actor"]["id"] == records_exports.WORKER and built["actor"]["kind"] == "system"
    assert world.audit(world.b.boss, "records.export_built") == []
