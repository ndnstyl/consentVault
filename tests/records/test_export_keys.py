"""records.md section 7 and the erasure review: a list export is sealed under a data key of its own, so erasing a person who is in
it, or the 24 hours running out, destroys the key and the stored file (which may sit under retention) can no longer be opened."""

import pytest

from consentvault import records_exports
from consentvault.tenancy import crypto as tc
from consentvault.tenancy.errors import FieldCryptoError

from contract_world import exports as ex
from contract_world.world import EMAIL, PHONE, PHONE2


def keys(world, org):
    return world.sql(org, "SELECT export_id::text AS export_id, wrapped, destroyed_at, object_state"
                          " FROM consentvault.record_export_key WHERE org_id = %s", (org.org_id,))


def seeded(world):
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    world.capture(o, PHONE2)
    world.email_grant(o, EMAIL, display={"name": "Lee Park"})
    return o


def test_erasing_a_person_in_a_built_export_destroys_its_key_and_refuses_every_link(world):
    o = seeded(world)
    built = ex.wait_ready(o.boss, ex.start(o.boss, contact_form="full", reason="check")["export_id"])
    standing = built["download_url"]
    assert [bool(k["wrapped"]) for k in keys(world, o)] == [True]
    blob = world.store.get(o.org_id, "records-exports/" + built["export_id"])
    world.erase(o, PHONE)
    (key,) = keys(world, o)
    assert key["wrapped"] is None and key["destroyed_at"] is not None
    r = o.boss.call("POST", f"/v1/records/exports/{built['export_id']}:link")
    assert (r.status, r.body["error"]) == (410, "export_expired")
    old = ex.download(world, o.boss, standing)  # a link minted before the erasure is revoked with it
    assert (old.status, old.body["error"]) == (410, "export_expired")
    got = o.boss.ok("GET", f"/v1/records/exports/{built['export_id']}")
    assert got["status"] == "expired" and got["download_url"] is None
    # the stored object is still there, and nothing the system holds opens it: not the display key, and the data key is gone
    with pytest.raises(FieldCryptoError):
        tc.decrypt_field(world.adapter.display_key(__import__("uuid").UUID(o.org_id)), o.org_id, built["export_id"], "records_export", blob)
    assert PHONE.encode() not in blob and b"Dana" not in blob


def test_the_24_hour_expiry_destroys_the_key_the_same_way(world):
    o = seeded(world)
    built = ex.wait_ready(o.boss, ex.start(o.boss, contact_form="masked")["export_id"])
    assert keys(world, o)[0]["wrapped"] is not None
    world.advance_clock(25 * 3600)
    assert records_exports.run_export_builds(now=world.vault.app._clock()) == 0  # nothing to build; the pass sweeps
    (key,) = keys(world, o)
    assert key["wrapped"] is None and key["destroyed_at"] is not None and key["object_state"] == "retained"
    assert o.boss.ok("GET", f"/v1/records/exports/{built['export_id']}")["status"] == "expired"
    assert world.sql(o, "SELECT status FROM consentvault.record_export WHERE export_id = %s", (built["export_id"],))[0]["status"] == "expired"


def test_an_export_that_does_not_hold_the_erased_record_is_untouched(world):
    o = seeded(world)
    email_only = ex.wait_ready(o.boss, ex.start(o.boss, contact_form="masked", filters={"contact_kind": "email"})["export_id"])
    everyone = ex.wait_ready(o.boss, ex.start(o.boss, contact_form="masked")["export_id"])
    world.erase(o, PHONE)
    by_export = {k["export_id"]: k for k in keys(world, o)}
    assert by_export[everyone["export_id"]]["wrapped"] is None
    assert by_export[email_only["export_id"]]["wrapped"] is not None
    assert o.boss.ok("GET", f"/v1/records/exports/{email_only['export_id']}")["status"] == "ready"
    link = o.boss.ok("POST", f"/v1/records/exports/{email_only['export_id']}:link")
    z, rows, _ = ex.open_zip(ex.download(world, o.boss, link["download_url"]).body)
    assert len(rows) == 1


def test_a_key_rotation_moves_the_export_keys_to_the_new_version_and_the_export_still_opens(world, tmp_path):
    """migration 0055 (the census counts export keys and the re-wrap moves them): rotate while an export is held; no export key
    stays wrapped under the old version, which is destroyed, and the export still downloads."""
    from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore
    from consentvault.providers.keys import wrapped_version
    from consentvault.tenancy import key_rotation as kr
    from consentvault import db, dbclock
    from consentvault.tenancy.erasure import LifecycleLedger

    o = seeded(world)
    built = ex.wait_ready(o.boss, ex.start(o.boss, contact_form="full", reason="check")["export_id"])
    (before,) = keys(world, o)
    assert wrapped_version(bytes(before["wrapped"])) == 1
    v = world.vault
    with v.operator() as c:
        kr.start_rotation(c, token_key=v.key, custody=v.custody, operator_id="op-1", request_id="req-rot", org_id=o.org_id,
                          reason="annual")
    with v.operator() as c:
        state = kr.run_rotation(c, token_key=v.key, custody=v.custody, crypto=world.crypto,
                                ledger=LifecycleLedger(LocalAppendOnlyEvidenceStore(tmp_path / "ledger"),
                                                    clock=dbclock.datetime_clock(lambda: db.connect(v.app_dsn))),
                                operator_id="op-1", request_id="req-job", org_id=o.org_id, backup_retention_days=0)
    assert state["old_version_destroyed"] is True
    (after,) = keys(world, o)
    assert wrapped_version(bytes(after["wrapped"])) == 2
    world.adapter._load_display.forget(__import__("uuid").UUID(o.org_id))
    link = o.boss.ok("POST", f"/v1/records/exports/{built['export_id']}:link")
    _, rows, _ = ex.open_zip(ex.download(world, o.boss, link["download_url"]).body)
    assert {PHONE, PHONE2, EMAIL} <= {v for r in rows for v in r.values()}
