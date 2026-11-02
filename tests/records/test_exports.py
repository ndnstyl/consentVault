"""records.md section 7: list exports (zip file, forms, audit rows, expiry, links)."""

import hashlib

from contract_world import exports as ex
from contract_world.world import EMAIL, PHONE, PHONE2


def build(world, person, **body):
    started = ex.start(person, **body)
    assert started["status"] == "building" and "export_id" in started and "row_estimate" in started
    return ex.wait_ready(person, started["export_id"])


def fetch(world, person, ready):
    r = ex.download(world, person, ready["download_url"])
    assert r.status == 200, (r.status, r.body)
    body = r.body if isinstance(r.body, (bytes, bytearray)) else r.body["bytes"]
    return ex.open_zip(bytes(body))


def seed(world):
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "=HYPERLINK(1)"})
    world.capture(o, PHONE2)
    world.stop(o, PHONE2)
    world.email_grant(o, EMAIL, display={"name": "@evil", "company": "Lee Co"})
    return o


def test_an_export_builds_a_zip_with_the_csv_manifest_and_readme(world):
    """records.md section 7 (records.csv, manifest.json fields, README.txt text, sha256 of records.csv)."""
    o = seed(world)
    ready = build(world, o.boss, contact_form="masked")
    z, rows, manifest = fetch(world, o.boss, ready)
    assert sorted(z.namelist()) == ["README.txt", "manifest.json", "records.csv"]
    assert z.read("README.txt").decode().strip() == ("This file lists the records ConsentVault holds for your organization on "
                                                    "the date shown. It is not a legal determination.")
    assert set(manifest) >= {"org_name", "filters", "as_of", "row_count", "contact_form", "requested_by", "sha256"}
    assert manifest["row_count"] == len(rows) == 3 and manifest["contact_form"] == "masked"
    assert manifest["sha256"] == hashlib.sha256(z.read("records.csv")).hexdigest() == ready["sha256"]
    assert {"record_id", "contact_kind", "first_recorded_at", "last_event_at", "first_source", "sources", "has_stop",
            "last_stop_at", "last_confirmation", "recorded_during_trial"} <= set(rows[0])


def test_the_three_contact_forms_and_the_person_default(world):
    """records.md section 7 (contact_form masked, full, fingerprint; include_person default true except fingerprint)."""
    o = seed(world)
    _, masked, _ = fetch(world, o.boss, build(world, o.boss, contact_form="masked"))
    cells = {v for r in masked for v in r.values()}
    assert {"(555) ***-0142", "(555) ***-0199", "d***@example.com"} <= cells  # masked, not E.164, so unprefixed text
    assert any("Dana Cruz" in str(r) for r in masked)
    _, full, _ = fetch(world, o.boss, build(world, o.boss, contact_form="full", reason="audit request"))
    assert {PHONE, PHONE2, EMAIL} <= {v for r in full for v in r.values()}
    _, fp, _ = fetch(world, o.boss, build(world, o.boss, contact_form="fingerprint"))
    assert all("Dana" not in str(r) and PHONE not in str(r) for r in fp)
    assert {o.fp(PHONE)[:8]} <= {v for r in fp for v in r.values()}


def test_a_fingerprint_export_with_names_and_a_full_export_without_a_reason_are_refused(world):
    """records.md section 7 (include_person true with fingerprint, and full with no reason, are validation_failed)."""
    seed(world)
    world.a.boss.err("POST", "/v1/records/exports", body={"contact_form": "fingerprint", "include_person": True}, name="validation_failed")
    world.a.boss.err("POST", "/v1/records/exports", body={"contact_form": "full"}, name="validation_failed")
    world.a.boss.err("POST", "/v1/records/exports", body={"contact_form": "everything"}, name="validation_failed")
    assert ex.start(world.a.boss, contact_form="masked", include_person=False)["status"] == "building"


FORMULA_NAMES = {"=1+1": "'=1+1", "+1 ok": "'+1 ok", "-x": "'-x", "@a": "'@a", "\tx": "'\tx", "\rx": "'\rx",
                 "+15555550142": "+15555550142", "+1555555014a": "'+1555555014a", "plain": "plain"}


def test_cells_that_start_with_a_formula_character_are_prefixed_except_an_exact_e164_number(world):
    """records.md section 7 (first character = + - @ tab or carriage return is prefixed with a single quote; a value matching
    ^\\+[0-9]{7,15}$ exactly is written as is; +1555555014a is prefixed). Names are the carried values."""
    o = world.a
    for n, name in enumerate(FORMULA_NAMES):
        world.capture(o, f"+155555506{n:02d}", display={"name": name, "company": "Co"})
    _, rows, _ = fetch(world, o.boss, build(world, o.boss, contact_form="masked", include_person=True))
    cells = {v for r in rows for v in r.values()}
    for raw, written in FORMULA_NAMES.items():
        assert written in cells, (raw, written)
        if written != raw:
            assert raw not in cells, f"{raw!r} was written unprefixed"
    _, full, _ = fetch(world, o.boss, build(world, o.boss, contact_form="full", reason="check"))
    assert any(v.startswith("+155555506") for r in full for v in r.values())  # E.164 contact cells are written as is


def test_a_second_export_while_one_is_building_is_refused_and_a_new_one_starts_after(world):
    """records.md section 7 (one build at a time per organization: 409 export_in_progress naming the running one; the build
    is held with consentvault.testing.hold_steps "records.export.build": it stays building with progress {done: 0, total}
    and the pass returns 0; removing the name and running the pass finishes it)."""
    o = seed(world)
    with world.hold_steps("records.export.build"):
        first = ex.start(o.boss, contact_form="masked", include_person=True)
        assert ex.run_builds(o.boss) == 0
        body = o.boss.err("POST", "/v1/records/exports", body={"contact_form": "masked"}, name="export_in_progress", status=409)
        assert body["fields"]["export_id"] == first["export_id"]
        held = o.boss.ok("GET", f"/v1/records/exports/{first['export_id']}")
        assert held["status"] == "building" and held["progress"]["done"] == 0 and held["progress"]["total"] >= 1
        assert ex.start(world.b.boss, contact_form="fingerprint")["status"] == "building"  # another organization is not blocked
    assert ex.run_builds(o.boss) >= 1
    ex.wait_ready(o.boss, first["export_id"])
    assert ex.start(o.boss, contact_form="masked")["status"] == "building"


def test_an_export_takes_the_list_filters(world):
    """records.md section 7 (filters as section 3; row_count; has_stop)."""
    o = seed(world)
    _, rows, manifest = fetch(world, o.boss, build(world, o.boss, contact_form="fingerprint", filters={"has_stop": "true"}))
    assert manifest["row_count"] == len(rows) == 1 and manifest["filters"]["has_stop"] in ("true", True)


def test_export_audit_rows_and_the_ids_they_carry(world):
    """records.md section 7 (export_requested before the build; export_built record_ids for full and masked with names,
    count only for fingerprint; export_downloaded on each download)."""
    o = seed(world)
    full = build(world, o.boss, contact_form="full", reason="subpoena prep")
    masked = build(world, o.boss, contact_form="masked", include_person=True)
    plain = build(world, o.boss, contact_form="fingerprint")
    requested = world.audit(o.boss, "records.export_requested")
    assert len(requested) == 3 and any(r["reason"] == "subpoena prep" or "subpoena prep" in str(r) for r in requested)
    assert all({"contact_form", "include_person"} <= set(r["detail"]) for r in requested)
    built = {r["target"]["id"]: r for r in world.audit(o.boss, "records.export_built")}
    ids = sorted(i["record_id"] for i in o.boss.ok("GET", "/v1/records", {})["items"])
    assert sorted(built[full["export_id"]]["detail"]["record_ids"]) == ids
    assert sorted(built[masked["export_id"]]["detail"]["record_ids"]) == ids
    assert built[plain["export_id"]]["detail"] == {"count": 3}
    fetch(world, o.boss, full)
    link = o.boss.ok("POST", f"/v1/records/exports/{full['export_id']}:link")
    assert ex.download(world, o.boss, link["download_url"]).status == 200
    assert len(world.audit(o.boss, "records.export_downloaded")) == 2
    for r in requested + list(built.values()):
        assert PHONE not in str(r) and "Dana" not in str(r)


def test_a_download_link_is_good_once(world):
    """records.md section 7 (download_url one use, 15 minutes; :link gives a new one while the file is kept)."""
    o = seed(world)
    ready = build(world, o.boss, contact_form="masked")
    assert ex.download(world, o.boss, ready["download_url"]).status == 200
    again = ex.download(world, o.boss, ready["download_url"])
    assert (again.status, again.body["error"]) == (410, "export_link_used")
    link = o.boss.ok("POST", f"/v1/records/exports/{ready['export_id']}:link")
    assert set(link) >= {"download_url", "expires_at"} and link["download_url"] != ready["download_url"]
    assert ex.download(world, o.boss, link["download_url"]).status == 200


def test_a_link_is_good_for_15_minutes_and_a_new_one_can_be_minted_while_the_file_is_kept(world):
    """records.md section 7 (410 export_link_expired after 15 minutes by the AdminApp clock; :link mints a new link within 24 hours)."""
    o = seed(world)
    ready = build(world, o.boss, contact_form="masked")
    world.advance_clock(14 * 60)
    link = o.boss.ok("POST", f"/v1/records/exports/{ready['export_id']}:link")
    world.advance_clock(2 * 60)  # the first link is now 16 minutes old, the new one 2
    old = ex.download(world, o.boss, ready["download_url"])
    assert (old.status, old.body["error"]) == (410, "export_link_expired") and "15 minutes" in old.body["detail"]
    assert ex.download(world, o.boss, link["download_url"]).status == 200


def test_the_file_is_kept_24_hours_then_it_reads_expired_and_the_link_answers_410(world):
    """records.md section 7 (24 hours from completed_at: GET answers 200 status expired with download_url null; :link 410 export_expired)."""
    o = seed(world)
    ready = build(world, o.boss, contact_form="masked")
    assert ready["expires_at"]
    world.advance_clock(25 * 3600)
    got = o.boss.ok("GET", f"/v1/records/exports/{ready['export_id']}")
    assert got["status"] == "expired" and got["download_url"] is None
    assert o.boss.ok("GET", "/v1/records/exports")["items"][0]["status"] == "expired"
    r = o.boss.call("POST", f"/v1/records/exports/{ready['export_id']}:link")
    assert (r.status, r.body["error"]) == (410, "export_expired")


def test_the_file_is_stored_encrypted_under_the_org_key_in_the_evidence_store(world):
    """records.md section 7 (evidence store key records-exports/<export_id>, encrypt_field under the organization key,
    no clear contact point in the stored object)."""
    store = world.store
    o = seed(world)
    ready = build(world, o.boss, contact_form="full", reason="check")
    blob = store.get(o.org_id, "records-exports/" + ready["export_id"])
    assert blob and PHONE.encode() not in blob and b"PK" != blob[:2] and EMAIL.encode() not in blob


def test_export_list_and_detail_shapes(world):
    """records.md section 7 (list item fields incl. status building|ready|failed|expired; detail adds progress and download_url)."""
    o = seed(world)
    ready = build(world, o.boss, contact_form="masked")
    (item,) = o.viewer.ok("GET", "/v1/records/exports")["items"]
    assert set(item) == {"export_id", "status", "contact_form", "row_count", "requested_by", "created_at", "completed_at",
                         "expires_at", "downloaded_at", "sha256", "failed_cause"}
    assert item["status"] == "ready" and item["row_count"] == 3 and item["failed_cause"] is None
    detail = o.boss.ok("GET", f"/v1/records/exports/{ready['export_id']}")
    assert "progress" in detail and "download_url" in detail


def test_a_build_whose_built_audit_row_cannot_be_written_is_failed_and_the_file_deleted(world):
    """records.md section 7 (records.export_built unwritable: file deleted, failed with audit_unavailable)."""
    o = seed(world)
    with world.audit_refused("records.export_built"):
        started = ex.start(o.boss, contact_form="masked")
        failed = ex.wait_ready(o.boss, started["export_id"], want="failed")
    assert failed["failed_cause"] == "audit_unavailable" and failed.get("download_url") is None
    o.boss.err("POST", f"/v1/records/exports/{started['export_id']}:link", name="export_not_ready")


def test_the_requested_audit_row_is_committed_before_the_build_starts(world):
    """records.md section 7 (records.export_requested committed before the build starts)."""
    o = seed(world)
    with world.audit_refused("records.export_requested"):
        r = o.boss.call("POST", "/v1/records/exports", body={"contact_form": "masked"})
    assert r.status == 503 and r.body["error"] == "audit_unavailable"
    assert o.boss.ok("GET", "/v1/records/exports")["items"] == []


def test_an_export_is_paused_while_suspended(world):
    """records.md section 7 (paused while suspended: org_suspended)."""
    o = seed(world)
    world.set_status(o, "suspended")
    o.boss.err("POST", "/v1/records/exports", body={"contact_form": "masked"}, name="org_suspended")


def test_export_roles(world):
    """records.md section 7 and auth.md (A and V build and link; D refused on every export route)."""
    o = seed(world)
    o.dev.err("POST", "/v1/records/exports", body={"contact_form": "fingerprint"}, name="role_not_allowed")
    o.dev.err("GET", "/v1/records/exports", name="role_not_allowed")
    ready = build(world, o.viewer, contact_form="masked")
    o.dev.err("GET", f"/v1/records/exports/{ready['export_id']}", name="role_not_allowed")
    o.dev.err("POST", f"/v1/records/exports/{ready['export_id']}:link", name="role_not_allowed")
    assert o.boss.ok("POST", f"/v1/records/exports/{ready['export_id']}:link")["download_url"]


def test_the_export_ceiling_is_250000_rows(world):
    """records.md section 7 (refused above the ceiling with export_too_large, fields.count and fields.max; the ceiling is the
    setting CONSENTVAULT_RECORDS_EXPORT_MAX_ROWS, default 250000, read on every request)."""
    o = seed(world)
    with world.override("records.export_max_rows", 2):
        body = o.boss.err("POST", "/v1/records/exports", body={"contact_form": "masked"}, name="export_too_large", status=422)
        assert body["fields"]["count"] == 3 and body["fields"]["max"] == 2
    assert ex.start(o.boss, contact_form="masked")["status"] == "building"
