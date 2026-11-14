"""records.md sections 8 and 9: tables, owner-rights writers, the display key, the index, rollback, the manifest."""

import re
import uuid
from pathlib import Path

import psycopg
import pytest

from consentvault.tenancy.tokens import org_transaction

from contract_world.world import PHONE, PHONE2, need

REPO = Path(__file__).resolve().parents[2]
NEW_TABLES = ("record", "record_index", "record_display", "org_display_key")
FUNCTIONS = ("record_upsert", "record_index_refresh", "record_display_write", "record_index_set_confirmation",
             "record_index_rebuild")


def test_the_four_tables_exist_with_the_contracted_columns_and_row_security(world):
    """records.md section 8 (tables and columns), section 9 (row security by org_id like every tenant table)."""
    cols = {}
    for r in world.sql(world.a, "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'consentvault'"
                                " AND table_name = ANY(%s)", (list(NEW_TABLES),)):
        cols.setdefault(r["table_name"], set()).add(r["column_name"])
    assert set(cols) == set(NEW_TABLES), cols.keys()
    assert {"org_id", "record_id", "contact_fp", "contact_kind", "first_recorded_at", "erased_at"} <= cols["record"]
    assert {"org_id", "record_id", "subject_fp", "last_event_at", "first_source_id", "source_ids", "brand_ids", "status_by_cell",
            "has_stop", "last_stop_at", "first_in_trial", "last_confirmation", "mask_ct"} <= cols["record_index"]
    assert {"org_id", "record_id", "name_ct", "company_ct", "updated_at"} <= cols["record_display"]
    assert {"org_id", "wrapped", "key_version", "created_at"} <= cols["org_display_key"]
    for r in world.sql(world.a, "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relnamespace = 'consentvault'::regnamespace"
                                " AND relname = ANY(%s)", (list(NEW_TABLES),)):
        assert r["relrowsecurity"] and r["relforcerowsecurity"], r["relname"]


def test_a_second_organization_cannot_read_the_records_tables(world):
    """records.md section 8 and the isolation rule (row security by org_id)."""
    world.capture(world.a, PHONE, display={"name": "Dana"})
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(world.b.org_id)):
        for t in ("record", "record_index", "org_display_key"):
            assert c.execute(f"SELECT count(*) AS n FROM consentvault.{t}").fetchone()["n"] == 0, t


def test_owner_rights_functions_are_security_definer_with_a_pinned_search_path(world):
    """records.md section 8 (SECURITY DEFINER, SET search_path = pg_catalog, pg_temp)."""
    got = {r["proname"]: r for r in world.sql(world.a, "SELECT proname, prosecdef, proconfig FROM pg_proc WHERE pronamespace = 'consentvault'::regnamespace"
                                                      " AND proname = ANY(%s)", (list(FUNCTIONS),))}
    assert set(got) == set(FUNCTIONS)
    for name, r in got.items():
        assert r["prosecdef"] and any("search_path=pg_catalog, pg_temp" in c for c in r["proconfig"]), name


def test_the_security_manifest_lists_the_new_functions_and_tables(world):
    """records.md section 9 (the committed security manifest is rebuilt in the same change)."""
    text = (REPO / "src/consentvault/data/security_manifest.sha256").read_text()
    for name in FUNCTIONS:
        assert f"function consentvault.{name}(" in text, name
    assert "function consentvault.erase_contact(text)" in text


def test_record_upsert_returns_the_active_record_and_refuses_another_organizations_event(world):
    """records.md section 8 (record_upsert: active record_id for the fingerprint; checks the event belongs to the org)."""
    o = world.a
    ev = world.capture(o, PHONE)
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        a = c.execute("SELECT consentvault.record_upsert(%s, %s, 'phone') AS r", (ev.event_id, o.fp(PHONE))).fetchone()["r"]
        b = c.execute("SELECT consentvault.record_upsert(%s, %s, 'phone') AS r", (ev.event_id, o.fp(PHONE))).fetchone()["r"]
    assert a == b and str(a) == world.record_id(o, PHONE)
    other = world.capture(world.b, PHONE)
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)), pytest.raises(psycopg.Error):
        c.execute("SELECT consentvault.record_upsert(%s, %s, 'phone')", (other.event_id, o.fp(PHONE)))


def test_the_writers_take_only_capture_capture_verified_or_admin_scopes_and_rebuild_only_admin(world):
    """records.md section 8 (sync_org scopes; record_index_rebuild is operator and admin only)."""
    o = world.a
    ev = world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id, ("gate_read",))), pytest.raises(psycopg.Error):
        c.execute("SELECT consentvault.record_upsert(%s, %s, 'phone')", (ev.event_id, o.fp(PHONE)))
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id, ("capture",))), pytest.raises(psycopg.Error):
        c.execute("SELECT consentvault.record_index_rebuild(%s)", (rid,))
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(o.org_id)):
        c.execute("SELECT consentvault.record_index_rebuild(%s)", (rid,))


def test_the_index_is_rebuilt_from_the_ledger_and_never_touches_record_or_display(world):
    """records.md section 8 (record_index_rebuild recomputes derived columns; record and record_display untouched)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana", "company": "Cruz"})
    world.stop(o, PHONE)
    before = o.boss.ok("GET", "/v1/records", {})["items"][0]
    rid = before["record_id"]
    with world.vault.superuser() as su:
        su.execute("UPDATE consentvault.record_index SET has_stop = false, status_by_cell = '{}'::jsonb, last_stop_at = NULL WHERE org_id = %s", (o.org_id,))
    assert o.boss.ok("GET", "/v1/records", {})["items"][0]["has_stop"] is False
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(o.org_id)):
        c.execute("SELECT consentvault.record_index_rebuild(%s)", (rid,))
    after = o.boss.ok("GET", "/v1/records", {})["items"][0]
    assert after["record_id"] == rid and after["has_stop"] is True and after["channels"] == before["channels"]
    assert after["person"] == before["person"] and after["first_recorded_at"] == before["first_recorded_at"]


def test_the_confirmation_writer_sets_last_confirmation_and_refuses_other_statuses(world):
    """records.md section 8 (record_index_set_confirmation: sent, delivered, failed, dead, skipped)."""
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    for status in ("sent", "delivered", "failed", "dead", "skipped"):
        with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id, ("capture_verified",))):
            c.execute("SELECT consentvault.record_index_set_confirmation(%s, 'sms', %s, now())", (rid, status))
        assert o.boss.ok("GET", "/v1/records", {})["items"][0]["confirmation"]["last_status"] == status
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id, ("capture_verified",))), pytest.raises(psycopg.Error):
        c.execute("SELECT consentvault.record_index_set_confirmation(%s, 'sms', 'intent', now())", (rid,))


def test_a_failure_in_the_records_writers_rolls_the_event_back(world):
    """records.md section 9 (R1: a failure in any of them rolls the event back, as an outbox failure does)."""
    o = world.a
    need("consentvault.records")
    with world.vault.superuser() as su:
        su.execute("CREATE FUNCTION public.cvt_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'records down (test)'; END $$")
        su.execute("CREATE TRIGGER cvt_fail BEFORE INSERT ON consentvault.record_index FOR EACH ROW EXECUTE FUNCTION public.cvt_fail()")
    try:
        with pytest.raises(Exception):
            world.capture(o, PHONE)
        assert world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s", (o.org_id,)) == []
    finally:
        with world.vault.superuser() as su:
            su.execute("DROP TRIGGER cvt_fail ON consentvault.record_index")
            su.execute("DROP FUNCTION public.cvt_fail()")


def test_creating_an_organization_makes_a_display_key_wrapped_by_the_org_key(world):
    """records.md section 8 and admin.md amendment (org_display_key made beside the fingerprint secret, wrapped by the org key)."""
    o = world.a
    (row,) = world.sql(o, "SELECT wrapped, key_version FROM consentvault.org_display_key WHERE org_id = %s", (o.org_id,))
    (fp,) = world.sql(o, "SELECT wrapped FROM consentvault.org_fingerprint_secret WHERE org_id = %s", (o.org_id,))
    key = world.vault.custody.unwrap(o.org_id, bytes(row["wrapped"]))
    assert len(key) == 32 and key != world.vault.custody.unwrap(o.org_id, bytes(fp["wrapped"]))
    (other,) = world.sql(world.b, "SELECT wrapped FROM consentvault.org_display_key WHERE org_id = %s", (world.b.org_id,))
    assert world.vault.custody.unwrap(world.b.org_id, bytes(other["wrapped"])) != key


def test_the_key_adapter_gives_display_keys_and_the_rotation_census_covers_them(world):
    """records.md section 8 (new_display_key, display_key, loader scope worker:display_key; CENSUS_KINDS gains display_key)."""
    adapter = world.adapter
    for name in ("new_display_key", "display_key"):
        assert hasattr(adapter, name), f"not built yet: CustodyKeyAdapter.{name}"
    assert len(adapter.display_key(uuid.UUID(world.a.org_id))) == 32
    assert adapter.display_key(uuid.UUID(world.a.org_id)) != adapter.display_key(uuid.UUID(world.b.org_id))
    kr = need("consentvault.tenancy.key_rotation")
    assert "display_key" in kr.CENSUS_KINDS
    assert need("consentvault.tenancy.keys_adapter", "DISPLAY_LOADER_SCOPE") == "worker:display_key"


def test_a_stored_name_is_ciphertext_bound_to_its_org_record_and_column(world):
    """records.md section 8 (encrypt_field with field_aad binds org, record_id and column; nothing in clear)."""
    from consentvault.tenancy import crypto as tc
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    world.capture(o, PHONE2, display={"name": "Lee Park", "company": "Park Co"})
    rid, rid2 = world.record_id(o, PHONE), world.record_id(o, PHONE2)
    rows = {str(r["record_id"]): r for r in world.sql(o, "SELECT record_id, name_ct, company_ct FROM consentvault.record_display WHERE org_id = %s", (o.org_id,))}
    assert b"Dana" not in bytes(rows[rid]["name_ct"]) and b"Cruz" not in bytes(rows[rid]["company_ct"])
    key = world.adapter.display_key(uuid.UUID(o.org_id))
    assert tc.decrypt_text(key, o.org_id, rid, "name_ct", bytes(rows[rid]["name_ct"])) == "Dana Cruz"
    for bad in ((o.org_id, rid2, "name_ct"), (o.org_id, rid, "company_ct"), (world.b.org_id, rid, "name_ct")):
        with pytest.raises(Exception):
            tc.decrypt_field(key, *bad, bytes(rows[rid]["name_ct"]))


def test_the_mask_is_written_once_on_the_first_event_and_is_ciphertext(world):
    """records.md section 8 (mask_ct computed by the caller in Python, written only on the record's first event)."""
    from consentvault.tenancy import crypto as tc
    o = world.a
    world.capture(o, PHONE)
    (first,) = world.sql(o, "SELECT mask_ct FROM consentvault.record_index WHERE org_id = %s", (o.org_id,))
    world.capture(o, PHONE)
    (row,) = world.sql(o, "SELECT mask_ct, record_id FROM consentvault.record_index WHERE org_id = %s", (o.org_id,))
    # sealing uses a fresh nonce each time, so a second write of the mask would change the stored bytes
    assert bytes(row["mask_ct"]) == bytes(first["mask_ct"]), "the mask was written again on a later event"
    assert b"0142" not in bytes(row["mask_ct"])
    key = world.adapter.display_key(uuid.UUID(o.org_id))
    assert tc.decrypt_text(key, o.org_id, str(row["record_id"]), "mask_ct", bytes(row["mask_ct"])) == "(555) ***-0142"


def test_each_migration_ships_with_a_down_that_removes_its_tables(world):
    """records.md section 9 (the migration ships with its down file; renumber if taken)."""
    up = [p for p in (REPO / "migrations").glob("*.sql") if "CREATE TABLE consentvault.record_index" in p.read_text()]
    assert len(up) == 1, "no migration creates record_index yet"
    down = REPO / "migrations" / "down" / up[0].name
    assert down.exists()
    with world.vault.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM pg_class WHERE relnamespace = 'consentvault'::regnamespace AND relname = ANY(%s)",
                          (list(NEW_TABLES),)).fetchone()["n"] == len(NEW_TABLES)  # they exist before the down runs
        # a later migration that redefines this one's functions is unwound first, newest first, as a real rollback would be
        later = sorted((q for q in (REPO / "migrations").glob("*.sql") if q.name > up[0].name
                        and any(f in q.read_text() for f in ("record_index_derive", "record_call_take", "record_reveal_note"))),
                       reverse=True)
        for q in later:
            su.execute((REPO / "migrations" / "down" / q.name).read_text())
        su.execute(down.read_text())
        left = su.execute("SELECT count(*) AS n FROM pg_class WHERE relnamespace = 'consentvault'::regnamespace AND relname = ANY(%s)",
                          (list(NEW_TABLES),)).fetchone()["n"]
    assert left == 0


def test_a_database_outage_answers_service_unavailable(world):
    """records.md Testability (service_unavailable is produced only by a database outage; the suite's database-down
    pattern: the app's connection is refused)."""
    from consentvault.tenancy.admin_routes import AdminApp
    v = world.vault
    world.capture(world.a, PHONE)
    p = world.a.boss

    def down():
        raise psycopg.OperationalError("database down (test)")
    real = v.app._connect
    v.app._connect = down
    try:
        r = p.call("GET", "/v1/records", {})
    finally:
        v.app._connect = real
    assert (r.status, r.body["error"]) == (503, "service_unavailable")
