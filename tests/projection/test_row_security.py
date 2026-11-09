"""'Row security on every new table' (finding M6): each table this spec creates, except replay_target, has ENABLE and FORCE row
security and one tenant policy; five of them also carry the restrictive read-scope policy; the tables the fold fills are proved by a
session entered as organisation A reading zero rows of organisation B and being refused a B row."""

import psycopg
import pytest

from consentvault.tenancy.tokens import org_transaction

from .support import PHONE, PHONE2, door_post, grant_fields, need_cutover, need_table, sql

spec = pytest.mark.spec_item

TENANT_TABLES = ["raw_post_reroute", "post_history", "projection_outcome", "post_history_seal", "post_history_chain_head",
                 "retrieval_log", "history_stop_lift", "effect_intent", "effect_watermark"]
READ_SCOPED = ["post_history", "post_history_seal", "post_history_chain_head", "retrieval_log", "history_stop_lift"]
FOLD_FILLED = ["post_history", "projection_outcome"]


@pytest.mark.parametrize("table", [pytest.param(t, id=t, marks=spec("M6.catalog." + t)) for t in TENANT_TABLES])
def test_the_table_forces_row_security_with_one_tenant_policy(world, table):
    need_table(table)
    rel = sql(world, "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass", (f"consentvault.{table}",))[0]
    assert rel == {"relrowsecurity": True, "relforcerowsecurity": True}
    pols = sql(world, "SELECT policyname, permissive, cmd, qual, with_check FROM pg_policies WHERE schemaname = 'consentvault' AND tablename = %s", (table,))
    org_col = "from_org" if table == "raw_post_reroute" else "org_id"
    tenant = [p for p in pols if p["permissive"] == "PERMISSIVE"]
    assert len(tenant) == 1, "one tenant policy"
    assert org_col in tenant[0]["qual"] and "current_org" in tenant[0]["qual"]
    assert org_col in tenant[0]["with_check"] and "current_org" in tenant[0]["with_check"]


@pytest.mark.parametrize("table", [pytest.param(t, id=t, marks=spec("M6.read_scope." + t)) for t in READ_SCOPED])
def test_the_evidence_tables_also_carry_the_restrictive_read_scope_policy(world, table):
    need_table(table)
    pols = sql(world, "SELECT permissive, cmd, qual FROM pg_policies WHERE schemaname = 'consentvault' AND tablename = %s AND permissive = 'RESTRICTIVE'", (table,))
    assert pols and all("may_read_evidence" in p["qual"] for p in pols)


@pytest.mark.spec_item("M6.effects_tenant_only")
def test_the_effect_tables_carry_the_tenant_policy_only(world):
    for table in ("effect_intent", "effect_watermark"):
        need_table(table)
        assert sql(world, "SELECT 1 FROM pg_policies WHERE schemaname = 'consentvault' AND tablename = %s AND permissive = 'RESTRICTIVE'", (table,)) == []


@pytest.mark.parametrize("table", [pytest.param(t, id=t, marks=spec("M6.behaviour." + t)) for t in FOLD_FILLED])
def test_a_session_entered_as_one_organisation_reads_none_of_the_others_rows_and_cannot_insert_one(world, table):
    need_cutover()
    a, b = world.a, world.b
    door_post(world, a, grant_fields(a, PHONE))
    door_post(world, b, grant_fields(b, PHONE2))
    assert sql(world, f"SELECT 1 FROM consentvault.{table} WHERE org_id = %s", (b.org_id,)), "organisation B has a row to protect"
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(a.org_id)):
        assert c.execute(f"SELECT count(*) AS n FROM consentvault.{table} WHERE org_id = %s", (b.org_id,)).fetchone()["n"] == 0
        assert c.execute(f"SELECT count(*) AS n FROM consentvault.{table} WHERE org_id = %s", (a.org_id,)).fetchone()["n"] >= 1
        with pytest.raises(psycopg.Error):
            c.execute(f"INSERT INTO consentvault.{table} SELECT * FROM jsonb_populate_record(NULL::consentvault.{table},"
                      f" (SELECT to_jsonb(t) || jsonb_build_object('org_id', %s::text) FROM consentvault.{table} t WHERE org_id = %s LIMIT 1))",
                      (b.org_id, a.org_id))
