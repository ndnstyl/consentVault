"""records.md sections 5 to 8 and the review conditions: the shared call limit, the order of audit and store, the display key
that a stop does not need, the read scope on the record tables, NUL refusal, and the backfill of organizations that predate
the tables."""

import uuid

import psycopg
import pytest

from consentvault.providers.errors import EvidenceStoreError
from consentvault.records_backfill import backfill
from consentvault.tenancy.tokens import org_transaction

from contract_world import exports as ex
from contract_world.world import PHONE, PHONE2


def test_the_call_limit_is_one_counter_in_the_database_shared_by_every_process(world):
    """records.md section 5 (30 calls per member per 10 minutes, search and reveal in one bucket): a second app instance,
    which shares no memory with the first, sees the same count."""
    o = world.a
    world.capture(o, PHONE)
    with world.override("records.reveal_rate_limit", 2):
        o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE})
        rid = o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE})["items"][0]["record_id"]
        other = world.app_with_store(world.store)  # a fresh app: its own memory, the same database
        assert other is not None
        r = o.boss.call("POST", "/v1/records:reveal", body={"record_ids": [rid]})
        assert (r.status, r.body["error"]) == (429, "rate_limited") and int(r.headers["Retry-After"]) >= 1
        world.advance_clock(11 * 60)  # the window is the injected clock's
        o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": [rid]})


def test_a_refused_call_still_counts_against_the_limit(world):
    """records.md section 5 (the count is committed on its own, so a call that later fails cannot be retried for free)."""
    o = world.a
    with world.override("records.reveal_rate_limit", 1):
        o.boss.err("POST", "/v1/records:reveal", body={"record_ids": [str(uuid.uuid4())]}, name="validation_failed")
        world.capture(o, PHONE)  # validation runs before the take, so nothing was counted yet
        o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE})
        o.boss.err("POST", "/v1/records:search", body={"contact": PHONE}, name="rate_limited")


class FailingStore:
    """An evidence store that refuses every write, after checking that the built row is already visible to other sessions."""

    def __init__(self, inner, probe):
        self.inner, self.probe, self.seen_built = inner, probe, None

    def put(self, *a, **kw):
        self.seen_built = self.probe()
        raise EvidenceStoreError("store down (test)")

    def get(self, *a, **kw):
        return self.inner.get(*a, **kw)


def test_the_built_audit_row_is_committed_before_the_file_is_stored_and_a_failed_store_has_its_own_row(world):
    """records.md section 7 (audit first, then store; a store that fails after a committed audit row gets its own named
    failure row and the export reads failed with store_unavailable)."""
    o = world.a
    world.capture(o, PHONE)
    from consentvault import records_exports
    worker = records_exports._current[0]
    real = worker.store
    worker.store = FailingStore(real, lambda: len(world.audit(o.boss, "records.export_built")))
    try:
        started = ex.start(o.boss, contact_form="masked")
        failed = ex.wait_ready(o.boss, started["export_id"], want="failed")
    finally:
        failing, worker.store = worker.store, real
    assert failing.seen_built == 1, "the built row was not committed when the store was asked to write"
    assert failed["failed_cause"] == "store_unavailable" and failed["download_url"] is None
    (row,) = world.audit(o.boss, "records.export_store_failed")
    assert row["target"]["id"] == started["export_id"]
    with pytest.raises(Exception):
        real.get(o.org_id, "records-exports/" + started["export_id"])  # nothing was stored


def test_a_stop_is_recorded_when_the_display_key_cannot_be_used_and_a_name_is_not(world):
    """records.md section 8 (an event that carries no name or company does not need the display key; one that does is
    refused and nothing is written)."""
    o = world.a
    world.capture(o, PHONE)  # warms the fingerprint secret
    with world.custody_down():
        world.stop(o, PHONE2)
        with pytest.raises(Exception):
            world.capture(o, "+15555550311", display={"name": "Dana"})
    assert world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s", (o.org_id,)).__len__() == 2
    items = {i["contact"]["fp_hint"]: i for i in o.boss.ok("GET", "/v1/records", {})["items"]}
    assert items[o.fp(PHONE2)[:8]]["has_stop"] is True and items[o.fp(PHONE2)[:8]]["contact"]["masked"] is None
    body = o.boss.ok("GET", "/v1/records", {})
    assert "contact_mask" in body["partial"]
    world.capture(o, PHONE2)  # the next event fills the mask
    assert {i["contact"]["masked"] for i in o.boss.ok("GET", "/v1/records", {})["items"]} == {"(555) ***-0142", "(555) ***-0199"}


def test_a_capture_token_cannot_read_the_record_tables(world):
    """0044 (a restrictive read scope on record and record_index: an admin, a developer or a viewer reads them; a capture
    token reads nothing)."""
    o = world.a
    world.capture(o, PHONE)
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id)):
        for t in ("record", "record_index", "record_display"):
            assert c.execute(f"SELECT count(*) AS n FROM consentvault.{t}").fetchone()["n"] == 0, t
    with world.vault.appconn() as c, org_transaction(c, world.admin_token(o.org_id)):
        assert c.execute("SELECT count(*) AS n FROM consentvault.record").fetchone()["n"] == 1


def test_a_nul_character_is_refused_with_422_everywhere_a_contact_is_not_the_field(world):
    """review: a NUL byte in a query or a body field is validation_failed, never a 500."""
    o = world.a
    r = o.boss.call("GET", "/v1/brands", {"x": "a\x00b"})
    assert (r.status, r.body["error"]) == (422, "validation_failed")
    r = o.boss.call("POST", "/v1/brands", body={"display_name": "a\x00b"})
    assert (r.status, r.body["error"]) == (422, "validation_failed")


def test_the_viewer_holds_the_records_read_scope_and_no_machine_credential_can(world):
    """auth.md (records_read is a portal scope for compliance_viewer; never issued to a machine credential)."""
    from consentvault.tenancy.oauth import NEVER_ISSUED
    assert "records_read" in NEVER_ISSUED
    with world.vault.appconn() as c, org_transaction(c, world.a.viewer.token):
        scopes = c.execute("SELECT scopes FROM consentvault.current_token_claims()").fetchone()["scopes"]
    assert sorted(scopes) == ["audit_read", "proof_read", "records_read"]


def test_the_backfill_makes_the_display_key_and_the_records_of_an_organization_that_predates_them(world):
    """the backfill (record rows and masks for contacts with events and no record, the display key for an organization with
    none, an erased contact marked erased, nothing run twice)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana"})
    world.capture(o, PHONE2)
    world.erase(o, PHONE2)
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")  # a DBA's view of a database from before the tables
        for t in ("record_display", "record_index", "record", "org_display_key"):
            su.execute(f"DELETE FROM consentvault.{t} WHERE org_id = %s", (o.org_id,))
    world.adapter._load_display.forget(uuid.UUID(o.org_id))  # this process held the deleted key's wrap; a real backfill starts cold
    v = world.vault
    first = backfill(v.operator, v.key, v.custody, world.crypto)
    assert first["failed"] == [] and first["display_keys"] >= 1 and first["records"] == 2 and first["erased"] == 1
    items = {i["contact"]["fp_hint"]: i for i in o.boss.ok("GET", "/v1/records", {"state": "all"})["items"]}
    assert items[o.fp(PHONE)[:8]]["contact"]["masked"] == "(555) ***-0142" and items[o.fp(PHONE)[:8]]["person"] is None
    assert items[o.fp(PHONE2)[:8]]["state"] == "erased" and items[o.fp(PHONE2)[:8]]["contact"]["masked"] is None
    again = backfill(v.operator, v.key, v.custody, world.crypto)
    assert again["records"] == 0 and again["display_keys"] == 0 and again["failed"] == []
    world.capture(o, PHONE)  # the live path works on the backfilled record
    assert len(o.boss.ok("GET", "/v1/records", {})["items"]) == 1


def test_one_failing_organization_fails_the_export_pass_after_the_others_ran(world, monkeypatch):
    """the job (records-exports): every organization is attempted; the run then raises naming each failed one, so the job
    exits non-zero and sends no heartbeat."""
    from consentvault import records_exports as re_
    world.capture(world.a, PHONE)
    world.capture(world.b, PHONE)
    with world.hold_steps("records.export.build"):
        ea = ex.start(world.a.boss, contact_form="masked")
        eb = ex.start(world.b.boss, contact_form="masked")
    real = re_._build_one

    def build(app, org, export_id, now):
        if str(org) == world.a.org_id:
            raise psycopg.OperationalError("down (test)")
        return real(app, org, export_id, now)
    monkeypatch.setattr(re_, "_build_one", build)
    with pytest.raises(re_.ExportRunError) as e:
        re_.run_export_builds()
    assert [o for o, _ in e.value.failures] == [world.a.org_id] and e.value.done == 1
    assert world.b.boss.ok("GET", f"/v1/records/exports/{eb['export_id']}")["status"] == "ready"
    assert world.a.boss.ok("GET", f"/v1/records/exports/{ea['export_id']}")["status"] == "building"


def test_the_list_and_the_search_write_their_audit_row_before_any_name_or_mask_is_opened(world):
    """records.md sections 3 and 5 (audit first): with the audit row unwritable the answer is audit_unavailable and the display
    key was never unwrapped, so nothing was decrypted."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz"})
    o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE})  # warms the fingerprint secret
    o.boss.ok("GET", "/v1/records", {})
    for action, call in (("records.listed", lambda: o.boss.call("GET", "/v1/records", {})),
                         ("records.searched", lambda: o.boss.call("POST", "/v1/records:search", body={"contact": PHONE}))):
        with world.audit_refused(action), world.custody_counting() as calls:
            r = call()
        assert (r.status, r.body["error"]) == (503, "audit_unavailable"), action
        assert calls["n"] == 0, f"{action} unwrapped a key before its audit row was written"


def test_every_call_is_counted_in_the_database_not_in_the_process(world):
    """records.md section 5 (one shared counter): the rows are in record_call, whichever app instance took the call."""
    o = world.a
    world.capture(o, PHONE)

    def taken():
        return world.sql(o, "SELECT count(*) AS n FROM consentvault.record_call WHERE org_id = %s AND member_id = %s",
                         (o.org_id, o.boss.member_id))[0]["n"]
    with world.override("records.reveal_rate_limit", 5):
        o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE})
        world.app_with_store(world.store)  # a second app instance in this same process
        o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE})
        assert taken() == 2


def test_two_overlapping_passes_build_an_export_once(world):
    """records.md section 7 (one builder per organization): a second pass that starts while the first is storing the file
    does nothing, so there is one built row, no store-failed row and a ready export."""
    import threading
    from consentvault import records_exports
    o = world.a
    world.capture(o, PHONE)
    with world.hold_steps("records.export.build"):
        started = ex.start(o.boss, contact_form="masked")
    worker = records_exports._current[0]
    real, entered, release = worker.store, threading.Event(), threading.Event()

    class Slow:
        def put(self, *a, **kw):
            entered.set()
            assert release.wait(30)
            return real.put(*a, **kw)

        def get(self, *a, **kw):
            return real.get(*a, **kw)
    worker.store = Slow()
    first = []
    t = threading.Thread(target=lambda: first.append(records_exports.run_export_builds(now=world.vault.app._clock())))
    t.start()
    try:
        assert entered.wait(30)
        assert records_exports.run_export_builds(now=world.vault.app._clock()) == 0  # the organization is being built
    finally:
        release.set()
        t.join(30)
        worker.store = real
    assert first == [1]
    assert len(world.audit(o.boss, "records.export_built")) == 1 and world.audit(o.boss, "records.export_store_failed") == []
    assert o.boss.ok("GET", f"/v1/records/exports/{started['export_id']}")["status"] == "ready"


def test_a_developer_token_reads_no_export_rows_and_a_download_link_is_for_its_own_export(world):
    """0046 (a read scope on record_export: an admin or viewer reads it, a developer does not) and the download route (the
    link's export must be the export in the path; a mismatch is 404 and does not use the link)."""
    o = world.a
    world.capture(o, PHONE)
    first = ex.wait_ready(o.boss, ex.start(o.boss, contact_form="masked", reason=None)["export_id"])
    second = ex.wait_ready(o.boss, ex.start(o.boss, contact_form="fingerprint")["export_id"])
    for t in ("record_export", "record_export_link"):
        with world.vault.appconn() as c, org_transaction(c, o.dev.token):
            assert c.execute(f"SELECT count(*) AS n FROM consentvault.{t}").fetchone()["n"] == 0, t
        with world.vault.appconn() as c, org_transaction(c, o.viewer.token):
            assert c.execute(f"SELECT count(*) AS n FROM consentvault.{t}").fetchone()["n"] >= 2, t
    url = first["download_url"]
    wrong = url.replace(first["export_id"], second["export_id"], 1)
    r = ex.download(world, o.boss, wrong)
    assert (r.status, r.body["error"]) == (404, "not_found")
    assert ex.download(world, o.boss, url).status == 200  # the refused attempt did not use the link


def test_an_export_failed_while_its_file_is_being_stored_stays_failed_and_the_finish_is_named(world):
    """records.md section 7 (the mark-ready step applies only to a building export): the store is held, the export is failed
    meanwhile, the store is released; the export stays failed and the pass names the lost finish instead of reporting done."""
    import threading
    from consentvault import records_exports
    o = world.a
    world.capture(o, PHONE)
    with world.hold_steps("records.export.build"):
        started = ex.start(o.boss, contact_form="masked")
    worker = records_exports._current[0]
    real, entered, release = worker.store, threading.Event(), threading.Event()

    class Held:
        def put(self, *a, **kw):
            entered.set()
            assert release.wait(30)
            return real.put(*a, **kw)

        def get(self, *a, **kw):
            return real.get(*a, **kw)
    worker.store = Held()
    outcome = []

    def run():
        try:
            outcome.append(records_exports.run_export_builds(now=world.vault.app._clock()))
        except records_exports.ExportRunError as e:
            outcome.append(e)
    t = threading.Thread(target=run)
    t.start()
    try:
        assert entered.wait(30)
        with world.vault.superuser() as su:
            su.execute("UPDATE consentvault.record_export SET status = 'failed', failed_cause = 'failed elsewhere'"
                       " WHERE export_id = %s", (started["export_id"],))
    finally:
        release.set()
        t.join(30)
        worker.store = real
    (err,) = outcome
    assert isinstance(err, records_exports.ExportRunError) and err.failures == [(o.org_id, "ExportFinishLost")]
    got = o.boss.ok("GET", f"/v1/records/exports/{started['export_id']}")
    assert got["status"] == "failed" and got["failed_cause"] == "failed elsewhere" and got["download_url"] is None


def test_the_backfill_relinks_an_index_written_before_the_default_subject_was_kept(world):
    """records.md section 1: an index from before migration 0058 took its subject from the newest event of any kind, so an
    unkeyed event after a keyed one broke the link. The backfill re-derives it with the contact's default subject."""
    from contract_world.world import EMAIL
    o = world.a
    world.capture(o, PHONE, subject_key="person-1")
    world.email_grant(o, EMAIL, subject_key="person-1")
    world.capture(o, PHONE)
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        su.execute("UPDATE consentvault.record_index i SET default_subject_fp = NULL, subject_fp = (SELECT e.subject_fp FROM"
                   " consentvault.event e JOIN consentvault.record r ON r.org_id = e.org_id AND r.contact_fp = e.contact_fp"
                   " WHERE r.org_id = i.org_id AND r.record_id = i.record_id ORDER BY e.seq DESC LIMIT 1) WHERE i.org_id = %s",
                   (o.org_id,))
    linked = lambda: sorted(i["linked_record_count"] for i in o.boss.ok("GET", "/v1/records", {"state": "all"})["items"])
    assert linked() == [0, 0]  # the old rule: the phone's newest event carried no person key
    v = world.vault
    out = backfill(v.operator, v.key, v.custody, world.crypto)
    assert out["failed"] == [] and out["relinked"] == 2
    assert linked() == [1, 1]
    assert backfill(v.operator, v.key, v.custody, world.crypto)["relinked"] == 0


def test_an_erased_contact_now_under_a_legal_hold_is_counted_held_on_every_run_and_never_fails_the_organization(world):
    o = world.a
    world.capture(o, PHONE)
    world.capture(o, PHONE2)
    world.erase(o, PHONE2)
    with world.vault.superuser() as su, su.transaction():
        su.execute("SET LOCAL session_replication_role = replica")
        for t in ("record_display", "record_index", "record"):
            su.execute(f"DELETE FROM consentvault.{t} WHERE org_id = %s", (o.org_id,))
        su.execute("INSERT INTO consentvault.legal_hold (org_id, scope, contact_fps, set_by_kind, set_by, reason)"
                   " VALUES (%s, 'contacts', ARRAY[%s], 'operator', 'test', 'a hold placed after the erasure')", (o.org_id, o.fp(PHONE2)))
    v = world.vault
    for _ in range(2):
        out = backfill(v.operator, v.key, v.custody, world.crypto)
        assert out["failed"] == [] and out["held"] == 1
        assert out["held_contacts"] == [{"org_id": o.org_id, "contact": o.fp(PHONE2)[:8]}]
