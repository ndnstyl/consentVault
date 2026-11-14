"""records.md sections 1 and 8: erasure of a record and a capture of the same contact after it."""

from contract_world.world import PHONE, PHONE2


def rows(p, **q):
    return p.ok("GET", "/v1/records", {"state": "all", **q})["items"]


def test_erasing_a_contact_marks_the_record_erased_and_keeps_its_row(world):
    """records.md section 1 and 8 (erase_contact deletes the display row, nulls mask_ct, sets erased_at; record survives)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    rid = world.record_id(o, PHONE)
    world.erase(o, PHONE)
    (item,) = rows(o.boss)
    assert item["record_id"] == rid and item["state"] == "erased"
    assert item["contact"]["masked"] is None and item["person"] is None and item["contact"]["fp_hint"]
    (rec,) = world.sql(o, "SELECT erased_at FROM consentvault.record WHERE org_id = %s", (o.org_id,))
    assert rec["erased_at"] is not None
    assert world.sql(o, "SELECT 1 FROM consentvault.record_display WHERE org_id = %s", (o.org_id,)) == []
    (idx,) = world.sql(o, "SELECT mask_ct FROM consentvault.record_index WHERE org_id = %s", (o.org_id,))
    assert idx["mask_ct"] is None


def test_a_capture_after_erasure_mints_a_new_record_and_carries_nothing_over_but_the_stop(world):
    """records.md section 1 (captured again after erasure: new record_id, new first_recorded_at, old stop still read)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"}, source_id=o.import_id)
    world.stop(o, PHONE)
    old = world.record_id(o, PHONE)
    world.erase(o, PHONE)
    world.capture(o, PHONE, source_id=o.web_id)
    items = rows(o.boss)
    assert len(items) == 2
    erased = [i for i in items if i["state"] == "erased"][0]
    fresh = [i for i in items if i["state"] == "active"][0]
    assert erased["record_id"] == old and fresh["record_id"] != old
    assert fresh["person"] is None and fresh["first_source"]["name"] == "Web form" and fresh["source_ids"] == [o.web_id]
    assert fresh["first_recorded_at"] >= erased["first_recorded_at"]
    assert fresh["contact"]["masked"] == "(555) ***-0142"
    assert fresh["has_stop"] is True and fresh["channels"]["sms"]["counts"]["stop_on_record"] == 2
    assert len(world.sql(o, "SELECT 1 FROM consentvault.record WHERE org_id = %s", (o.org_id,))) == 2


def test_the_record_row_is_never_deleted_and_one_active_record_per_fingerprint(world):
    """records.md section 8 (record: never deleted; unique on org and fingerprint where erased_at is null)."""
    import psycopg
    import pytest
    o = world.a
    world.capture(o, PHONE)
    with world.vault.appconn() as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        from consentvault.tenancy.tokens import org_transaction
        with org_transaction(c, world.admin_token(o.org_id)):
            c.execute("DELETE FROM consentvault.record")
    with world.vault.superuser() as su, pytest.raises(psycopg.errors.UniqueViolation):
        su.execute("INSERT INTO consentvault.record (org_id, record_id, contact_fp, contact_kind, first_recorded_at)"
                   " SELECT org_id, gen_random_uuid(), contact_fp, contact_kind, now() FROM consentvault.record WHERE org_id = %s", (o.org_id,))


def test_an_erased_records_stop_is_still_listed_through_the_proof(world):
    """proof-export.md amendment (an erased record answers found: true, contact.masked null, person null, its stops)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana"})
    world.stop(o, PHONE)
    rid = world.record_id(o, PHONE)
    world.erase(o, PHONE)
    cloud_proof = o.boss.call("POST", "/v1/proof", body={"record_id": rid})
    assert cloud_proof.status == 200, cloud_proof.body
    body = cloud_proof.body
    assert body["found"] is True and body["contact"]["masked"] is None and body["person"] is None
    assert body["record_id"] == rid
