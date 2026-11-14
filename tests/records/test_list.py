"""records.md sections 1 to 3: the record object, the list, its filters, paging, masks, names, and its audit row."""

from datetime import datetime, timedelta, timezone

import pytest

from contract_world.world import EMAIL, EMAIL2, PHONE, PHONE2

RECORD_KEYS = {"record_id", "contact_kind", "contact", "person", "state", "first_recorded_at", "last_event_at",
               "first_source", "source_ids", "source_count", "brand_ids", "channels", "has_stop", "last_stop_at",
               "confirmation", "recorded_during_trial", "linked_record_count"}


def listing(p, **q):
    return p.ok("GET", "/v1/records", {k: (v if isinstance(v, list) else str(v)) for k, v in q.items()})


def by_hint(world, org, body):
    return {i["contact"]["fp_hint"]: i for i in body["items"]}


def test_a_listed_record_has_exactly_the_contract_fields(world):
    """records.md section 2 (record object), section 3 (answer shape)."""
    world.capture(world.a, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    body = listing(world.a.boss)
    assert set(body) >= {"as_of", "items", "next_cursor", "prev_cursor", "total", "partial"}
    assert body["total"] == 1 and body["partial"] == [] and body["next_cursor"] is None
    (item,) = body["items"]
    assert set(item) == RECORD_KEYS
    assert item["contact_kind"] == "phone" and item["state"] == "active"
    assert item["contact"] == {"masked": "(555) ***-0142", "fp_hint": world.a.fp(PHONE)[:8]}
    assert item["person"] == {"name": "Dana Cruz", "company": "Cruz Tile"}
    assert item["first_source"] == {"source_id": world.a.web_id, "name": "Web form"}
    assert item["source_ids"] == [world.a.web_id] and item["source_count"] == 1
    assert item["brand_ids"] == [world.a.brand_id]
    assert item["has_stop"] is False and item["last_stop_at"] is None and item["confirmation"] is None
    assert item["linked_record_count"] == 0 and item["recorded_during_trial"] is True  # 0 for a lone record


def test_an_email_record_is_masked_with_its_first_letter(world):
    """records.md section 2 (contact.masked example for email)."""
    world.email_grant(world.a, EMAIL)
    (item,) = listing(world.a.boss)["items"]
    assert item["contact_kind"] == "email" and item["contact"]["masked"] == "d***@example.com"


def test_a_record_id_is_a_random_uuid_that_reveals_nothing_about_the_contact(world):
    """records.md section 1 (record_id)."""
    import uuid
    world.capture(world.a, PHONE)
    (item,) = listing(world.a.boss)["items"]
    assert str(uuid.UUID(item["record_id"])) == item["record_id"]
    assert uuid.UUID(item["record_id"]).version == 4
    flat = item["record_id"].replace("-", "")
    assert "5555550142" not in flat and item["contact"]["fp_hint"] not in flat and flat[:8] != item["contact"]["fp_hint"]
    world.capture(world.b, PHONE)
    assert world.b.boss.ok("GET", "/v1/records", {})["items"][0]["record_id"] != item["record_id"]  # nothing derived from the contact


def test_a_person_who_gave_an_email_and_a_phone_is_two_records_that_link(world):
    """records.md section 1 (two records; subject_fp; linked_record_count)."""
    world.capture(world.a, PHONE, subject_key="person-1")
    world.email_grant(world.a, EMAIL, subject_key="person-1")
    world.capture(world.a, PHONE2)
    items = listing(world.a.boss)["items"]
    assert len(items) == 3
    linked = {i["contact_kind"]: i["linked_record_count"] for i in items if i["contact"]["fp_hint"] in
              (world.a.fp(PHONE)[:8], world.a.fp(EMAIL, "email")[:8])}
    assert linked == {"phone": 1, "email": 1}
    lone = [i for i in items if i["contact"]["fp_hint"] == world.a.fp(PHONE2)[:8]][0]
    assert lone["linked_record_count"] == 0


def test_the_same_contact_captured_twice_is_one_record_with_a_moving_last_event(world):
    """records.md section 1 (one record per contact point), section 8 (record_upsert returns the active record)."""
    world.capture(world.a, PHONE)
    first = listing(world.a.boss)["items"][0]
    world.capture(world.a, PHONE, source_id=world.a.import_id)
    items = listing(world.a.boss)["items"]
    assert len(items) == 1 and items[0]["record_id"] == first["record_id"]
    assert items[0]["first_recorded_at"] == first["first_recorded_at"]
    assert items[0]["source_count"] == 2 and items[0]["first_source"]["name"] == "Web form"
    assert items[0]["last_event_at"] >= first["last_event_at"]


def test_every_channel_the_organization_has_appears_with_every_purpose(world):
    """records.md section 2 (channels: one key per channel; purposes per status)."""
    world.capture(world.a, PHONE)
    (item,) = listing(world.a.boss)["items"]
    assert set(item["channels"]) == {"sms", "voice", "artificial_voice", "email"}
    sms = item["channels"]["sms"]
    assert sms["counts"] == {"consent_record_found": 1, "stop_on_record": 0, "no_record": 1}
    assert sorted((p["purpose"], p["evidence_status"]) for p in sms["purposes"]) == [
        ("billing", "no_record"), ("marketing", "consent_record_found")]
    assert item["channels"]["email"]["counts"] == {"consent_record_found": 0, "stop_on_record": 0, "no_record": 2}


def test_a_stop_on_every_purpose_reads_stop_on_record_for_the_cells_that_have_no_grant(world):
    """records.md section 2 (status mapping: a '*' row whose reason starts with stopped: is stop_on_record)."""
    world.capture(world.a, PHONE)
    world.stop(world.a, PHONE, channels=("sms",))
    (item,) = listing(world.a.boss)["items"]
    assert item["has_stop"] is True and item["last_stop_at"]
    sms = item["channels"]["sms"]
    assert sms["counts"]["stop_on_record"] == 2 and sms["counts"]["consent_record_found"] == 0
    assert item["channels"]["voice"]["counts"]["stop_on_record"] == 0


def test_record_incomplete_is_not_a_list_status(world):
    """records.md section 2 and 3 (record_incomplete is refused with validation_failed)."""
    world.capture(world.a, PHONE)
    body = world.a.boss.err("GET", "/v1/records", {"status": "record_incomplete"}, name="validation_failed")
    assert "status" in body["fields"]


@pytest.mark.parametrize("params,expect", [
    ({"channel": "sms", "status": "consent_record_found"}, {"sms-grant"}),
    ({"channel": "sms", "status": "stop_on_record"}, {"sms-stopped"}),
    ({"channel": "sms", "status": "no_record"}, {"sms-grant", "email-only", "voice-grant"}),  # any purpose: billing is no_record on sms-grant
    ({"channel": "email", "status": "consent_record_found"}, {"email-only"}),
    ({"channel": "call", "status": "consent_record_found"}, {"voice-grant"}),
    ({"status": "stop_on_record"}, {"sms-stopped"}),
    ({"channel": "sms", "purpose": "billing", "status": "no_record"}, {"sms-grant", "email-only", "voice-grant"}),
    ({"has_stop": "true"}, {"sms-stopped"}),
    ({"has_stop": "false"}, {"sms-grant", "email-only", "voice-grant"}),
    ({"contact_kind": "email"}, {"email-only"}),
    ({"contact_kind": "phone"}, {"sms-grant", "sms-stopped", "voice-grant"}),
])
def test_status_channel_purpose_stop_and_kind_filters(world, params, expect):
    """records.md section 3 (channel incl. call = voice or artificial_voice, status, purpose, has_stop, contact_kind)."""
    o = world.a
    world.capture(o, PHONE)
    world.capture(o, PHONE2)
    world.stop(o, PHONE2)
    world.capture(o, "+15555550111", channels=("artificial_voice",))
    world.email_grant(o, EMAIL)
    names = {o.fp(PHONE)[:8]: "sms-grant", o.fp(PHONE2)[:8]: "sms-stopped", o.fp("+15555550111")[:8]: "voice-grant",
             o.fp(EMAIL, "email")[:8]: "email-only"}
    got = {names[i["contact"]["fp_hint"]] for i in listing(o.boss, **params)["items"]}
    assert got == expect


def test_source_and_brand_filters_and_their_refusals(world):
    """records.md section 3 (source_id repeatable up to 20; brand_id; not_found for an unknown source or brand)."""
    o = world.a
    world.capture(o, PHONE, source_id=o.web_id, brand_ids=[o.brand_id])
    world.capture(o, PHONE2, source_id=o.import_id, brand_ids=[o.brand2_id])
    assert [i["contact"]["fp_hint"] for i in listing(o.boss, source_id=o.web_id)["items"]] == [o.fp(PHONE)[:8]]
    assert len(listing(o.boss, source_id=[o.web_id, o.import_id])["items"]) == 2
    assert [i["contact"]["fp_hint"] for i in listing(o.boss, brand_id=o.brand2_id)["items"]] == [o.fp(PHONE2)[:8]]
    o.boss.err("GET", "/v1/records", {"source_id": "00000000-0000-4000-8000-000000000001"}, name="not_found")
    o.boss.err("GET", "/v1/records", {"brand_id": "00000000-0000-4000-8000-000000000002"}, name="not_found")
    o.boss.err("GET", "/v1/records", {"source_id": [o.web_id] * 21}, name="validation_failed")


def test_unknown_purpose_and_unknown_channel_are_named_errors(world):
    """records.md section 3 (errors UnknownPurposeError, invalid_channel, validation_failed naming the param)."""
    world.capture(world.a, PHONE)
    world.a.boss.err("GET", "/v1/records", {"purpose": "nonsense", "status": "no_record"}, name="UnknownPurposeError")
    world.a.boss.err("GET", "/v1/records", {"channel": "carrier_pigeon"}, name="invalid_channel")
    body = world.a.boss.err("GET", "/v1/records", {"state": "banana"}, name="validation_failed")
    assert "state" in body["fields"]


def test_a_contact_point_is_never_a_filter(world):
    """README section 1 (a contact point is never a query parameter or filter)."""
    world.capture(world.a, PHONE)
    for name in ("contact", "phone", "email", "q", "name", "company"):
        body = world.a.boss.err("GET", "/v1/records", {name: PHONE}, name="validation_failed")
        assert name in body["fields"]


def test_date_filters_pick_the_date_field_with_from_inclusive_and_to_exclusive(world):
    """records.md section 3 (date_field, from inclusive, to exclusive, from later than to is validation_failed)."""
    o = world.a
    world.capture(o, PHONE)
    world.capture(o, PHONE2)
    d1, d2 = datetime(2026, 3, 1, 12, tzinfo=timezone.utc), datetime(2026, 3, 5, 12, tzinfo=timezone.utc)
    world.backdate(o, PHONE, first=d1, last=d2)
    world.backdate(o, PHONE2, first=d2, last=d2 + timedelta(days=10))
    fp1, fp2 = o.fp(PHONE)[:8], o.fp(PHONE2)[:8]
    got = lambda **q: {i["contact"]["fp_hint"] for i in listing(o.boss, **q)["items"]}
    assert got(**{"from": "2026-03-01T12:00:00Z", "to": "2026-03-05T12:00:00Z"}) == {fp1}
    assert got(**{"from": "2026-03-05T12:00:00Z", "to": "2026-03-06T00:00:00Z"}) == {fp2}
    assert got(**{"date_field": "last_event", "from": "2026-03-05T12:00:00Z", "to": "2026-03-05T12:00:01Z"}) == {fp1}
    body = o.boss.err("GET", "/v1/records", {"from": "2026-04-01T00:00:00Z", "to": "2026-03-01T00:00:00Z"}, name="validation_failed")
    assert body["fields"]


def test_state_default_active_and_trial_filters(world):
    """records.md section 3 (state active default, erased, all; trial include, exclude, only; recorded_during_trial)."""
    o = world.a
    world.capture(o, PHONE)
    world.set_status(o, "active")
    world.capture(o, PHONE2)
    world.erase(o, PHONE)
    fp = lambda c: o.fp(c)[:8]
    got = lambda **q: {i["contact"]["fp_hint"]: i for i in listing(o.boss, **q)["items"]}
    assert set(got()) == {fp(PHONE2)} and set(got(state="active")) == {fp(PHONE2)}
    assert set(got(state="erased")) == {fp(PHONE)} and got(state="erased")[fp(PHONE)]["state"] == "erased"
    assert set(got(state="all")) == {fp(PHONE), fp(PHONE2)}
    assert got(state="all")[fp(PHONE2)]["recorded_during_trial"] is False
    assert set(got(state="all", trial="only")) == {fp(PHONE)} and set(got(state="all", trial="exclude")) == {fp(PHONE2)}
    assert set(got(state="all", trial="include")) == {fp(PHONE), fp(PHONE2)}


def test_sort_orders_are_stable_with_ties_broken_by_record_id(world):
    """records.md section 3 (sort last_event_desc default, first_recorded_desc, first_recorded_asc; ties by record_id)."""
    o = world.a
    contacts = [f"+155555501{n:02d}" for n in range(5)]
    for c in contacts:
        world.capture(o, c)
    same = datetime(2026, 3, 1, tzinfo=timezone.utc)
    for c in contacts[:3]:
        world.backdate(o, c, first=same, last=same)
    ids = lambda **q: [i["record_id"] for i in listing(o.boss, **q)["items"]]
    default = ids()
    assert default == ids(sort="last_event_desc") and len(default) == 5
    tied = [i for i in listing(o.boss, sort="first_recorded_asc")["items"] if i["first_recorded_at"].startswith("2026-03-01")]
    assert [t["record_id"] for t in tied] == sorted(t["record_id"] for t in tied)
    asc, desc = ids(sort="first_recorded_asc"), ids(sort="first_recorded_desc")
    assert asc != desc and sorted(asc) == sorted(desc)
    o.boss.err("GET", "/v1/records", {"sort": "name_asc"}, name="validation_failed")


def test_paging_walks_every_record_once_forward_and_back_and_total_counts_all(world):
    """records.md section 3 (limit 1 to 200, default 50, cursor, prev_cursor, total)."""
    o = world.a
    contacts = [f"+155555502{n:02d}" for n in range(7)]
    for c in contacts:
        world.capture(o, c)
    seen, cursor, pages = [], None, 0
    while True:
        q = {"limit": 3, **({"cursor": cursor} if cursor else {})}
        page = listing(o.boss, **q)
        assert page["total"] == 7 and len(page["items"]) <= 3
        seen += [i["record_id"] for i in page["items"]]
        pages += 1
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert pages == 3 and len(seen) == 7 == len(set(seen))
    second = listing(o.boss, limit=3, cursor=listing(o.boss, limit=3)["next_cursor"])
    assert second["prev_cursor"] and [i["record_id"] for i in listing(o.boss, limit=3, cursor=second["prev_cursor"])["items"]] == seen[:3]
    assert len(listing(o.boss)["items"]) == 7
    for bad in (0, 201):
        o.boss.err("GET", "/v1/records", {"limit": str(bad)}, name="validation_failed")
    o.boss.err("GET", "/v1/records", {"cursor": "not-a-cursor"}, name="invalid_cursor")


def test_a_cursor_expires_after_24_hours(world):
    """README section 1 (a cursor expires after 24 hours: invalid_cursor)."""
    for c in (PHONE, PHONE2):
        world.capture(world.a, c)
    cursor = listing(world.a.boss, limit=1)["next_cursor"]
    assert cursor
    world.advance_clock(25 * 3600)
    world.a.boss.err("GET", "/v1/records", {"limit": "1", "cursor": cursor}, name="invalid_cursor")


def test_the_list_reads_masks_from_the_index_with_one_key_use_per_page(world):
    """records.md section 3 (masks never from contact_ct), section 8 (one key use per page)."""
    o = world.a
    for n in range(6):
        world.capture(o, f"+155555503{n:02d}", display={"name": f"P{n}", "company": "C"})
    with world.custody_counting() as calls:
        items = listing(o.boss)["items"]
    assert len(items) == 6 and all(i["contact"]["masked"] and i["person"]["name"] for i in items)
    assert calls["n"] <= 2


def test_a_display_key_failure_nulls_masks_and_names_but_never_hides_a_stop(world):
    """records.md section 3 (partial names contact_mask and person; statuses never depend on a key)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana", "company": "Cruz"})
    world.stop(o, PHONE)
    with world.custody_down():
        body = listing(o.boss)
    (item,) = body["items"]
    assert item["contact"]["masked"] is None and item["person"] is None and item["contact"]["fp_hint"]
    assert set(body["partial"]) >= {"contact_mask", "person"}
    assert item["has_stop"] is True and item["channels"]["sms"]["counts"]["stop_on_record"] == 2


def test_person_name_and_company_are_the_latest_captured_and_each_can_be_absent(world):
    """records.md section 2 (person: latest captured values; each field null alone; null when never captured)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana"})
    world.capture(o, PHONE2)
    got = {i["contact"]["fp_hint"]: i["person"] for i in listing(o.boss)["items"]}
    assert got[o.fp(PHONE)[:8]] == {"name": "Dana", "company": None} and got[o.fp(PHONE2)[:8]] is None
    world.capture(o, PHONE, display={"name": "Dana C.", "company": "Cruz Tile"})
    got = {i["contact"]["fp_hint"]: i["person"] for i in listing(o.boss)["items"]}
    assert got[o.fp(PHONE)[:8]] == {"name": "Dana C.", "company": "Cruz Tile"}


def test_a_name_is_never_a_filter_sort_key_or_search_term(world):
    """records.md section 1 (never a filter, sort key or search term, because encrypted)."""
    world.capture(world.a, PHONE, display={"name": "Dana", "company": "Cruz"})
    assert listing(world.a.boss)["items"]
    world.a.boss.err("GET", "/v1/records", {"sort": "name_asc"}, name="validation_failed")
    world.a.boss.err("POST", "/v1/records:search", body={"contact": "Dana"}, name="invalid_contact")


def test_a_developer_gets_fingerprints_only_and_never_a_name_company_or_mask(world):
    """records.md section 3 (D: fingerprint only), section 1 (a developer never sees them in any answer)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    body = listing(o.dev)
    (item,) = body["items"]
    assert item["contact"] == {"masked": None, "fp_hint": o.fp(PHONE)[:8]} and item["person"] is None
    text = str(body)
    assert "Dana" not in text and "Cruz" not in text and "0142" not in text
    viewer = listing(o.viewer)["items"][0]
    assert viewer["contact"]["masked"] == "(555) ***-0142" and viewer["person"]["name"] == "Dana Cruz"


def test_a_list_call_writes_a_records_listed_audit_row_before_the_answer(world):
    """records.md section 3 (audit records.listed: filters, limit, count, request id, detail.person_shown_record_ids)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    world.capture(o, PHONE2)
    world.stop(o, PHONE2)
    o.boss.call("GET", "/v1/records", {"has_stop": "false", "limit": "10"})
    rows = world.audit(o.boss, "records.listed")
    assert len(rows) == 1
    row = rows[0]
    shown = row["detail"]["person_shown_record_ids"]
    assert shown == [world.record_id(o, PHONE)] and row["request_id"]
    text = str(row)
    for forbidden in (PHONE, PHONE[-4:], "Dana", "Cruz"):
        assert forbidden not in text
    assert "has_stop" in text and "10" in text


def test_a_developers_list_call_audits_an_empty_person_shown_list(world):
    """records.md section 3 (person_shown_record_ids is empty for D)."""
    world.capture(world.a, PHONE, display={"name": "Dana"})
    listing(world.a.dev)
    (row,) = world.audit(world.a.boss, "records.listed")
    assert row["detail"]["person_shown_record_ids"] == []


def test_when_the_audit_row_cannot_be_written_no_rows_are_returned(world):
    """records.md section 3 (audit_unavailable 503, no rows returned; the row is committed before the answer is built)."""
    world.capture(world.a, PHONE)
    with world.audit_refused("records.listed"):
        r = world.a.boss.call("GET", "/v1/records", {})
    assert r.status == 503 and r.body["error"] == "audit_unavailable" and "items" not in r.body


def test_confirmation_filter_reads_the_last_confirmation_outcome(world):
    """records.md section 3 (confirmation filter incl. none; record object confirmation)."""
    o = world.a
    world.capture(o, PHONE)
    assert len(listing(o.boss, confirmation="none")["items"]) == 1
    assert listing(o.boss, confirmation="sent")["items"] == []
    for bad in ("maybe",):
        o.boss.err("GET", "/v1/records", {"confirmation": bad}, name="validation_failed")


def test_a_failed_total_read_is_null_never_zero(world):
    """records.md section 3 (total null when the count did not finish, never 0; failed-reads switch records.total)."""
    world.capture(world.a, PHONE)
    with world.fail_reads("records.total"):
        body = listing(world.a.boss)
    assert body["total"] is None and len(body["items"]) == 1 and body["partial"] == []


def test_failed_mask_and_person_reads_null_those_fields_and_are_named_in_partial(world):
    """records.md section 3 (partial names contact_mask and person; failed-reads switch records.contact_mask, records.person)."""
    world.capture(world.a, PHONE, display={"name": "Dana"})
    with world.fail_reads("records.contact_mask"):
        body = listing(world.a.boss)
    assert body["partial"] == ["contact_mask"] and body["items"][0]["contact"]["masked"] is None and body["items"][0]["person"]["name"] == "Dana"
    with world.fail_reads("records.person"):
        body = listing(world.a.boss)
    assert body["partial"] == ["person"] and body["items"][0]["person"] is None and body["items"][0]["contact"]["masked"]


def test_a_later_send_replaces_an_earlier_skip_in_the_records_confirmation_column(world):
    """records.md section 2 (confirmation is the latest send status on any channel; the latest fact wins). The sends
    themselves are driven in the confirmations suite; here the writer is called directly."""
    from consentvault.tenancy.tokens import org_transaction
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    for status in ("skipped", "sent"):
        with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id, ("capture_verified",))):
            c.execute("SELECT consentvault.record_index_set_confirmation(%s, 'sms', %s, now())", (rid, status))
    assert listing(o.boss)["items"][0]["confirmation"]["last_status"] == "sent"
    with world.vault.appconn() as c, org_transaction(c, world.capture_token(o.org_id, ("capture_verified",))):
        c.execute("SELECT consentvault.record_index_set_confirmation(%s, 'email', 'failed', now())", (rid,))
    assert listing(o.boss)["items"][0]["confirmation"]["last_status"] == "failed"


_D = "DR" + "OP TA" + "BLE"
INJECTIONS = ["'; " + _D + " consentvault.record; --", "' OR '1'='1", "1; SELECT pg_sleep(5)", "%00", "\u0000", "../../etc/passwd",
              "x' UNION SELECT contact_ct FROM consentvault.contact_key --", "‮", "a" * 5000]


def test_injection_strings_are_inert_and_a_foreign_cursor_is_refused(world):
    """LC-T3, records.md section 3 and README section 1 (enumerated filters; a string that is not a value is a named 4xx, never a
    500 and never executed; row security and cursors keep one organization's rows from another)."""
    a, b = world.a, world.b
    world.capture(a, PHONE)
    world.capture(b, PHONE2)
    names = ("channel", "status", "purpose", "source_id", "brand_id", "date_field", "from", "to", "contact_kind", "state",
             "confirmation", "trial", "sort", "limit", "cursor", "has_stop")
    for name in names:
        for bad in INJECTIONS:
            r = a.boss.call("GET", "/v1/records", {name: bad})
            assert 400 <= r.status < 500 and r.body["error"] in (
                "validation_failed", "invalid_channel", "UnknownPurposeError", "not_found", "invalid_cursor"), (name, bad[:20], r.status, r.body)
    for bad in INJECTIONS:
        r = a.boss.call("GET", "/v1/records/summary", {"tz": bad})
        assert r.status == 422 and r.body["error"] == "validation_failed"
        r = a.boss.call("POST", "/v1/records:search", body={"contact": bad})
        assert 400 <= r.status < 500 and r.body["error"] == "invalid_contact"
    assert a.boss.ok("GET", "/v1/records", {})["total"] == 1 and PHONE2 not in str(a.boss.ok("GET", "/v1/records", {}))
    world.capture(a, "+15555550301")
    cursor = a.boss.ok("GET", "/v1/records", {"limit": "1"})["next_cursor"]
    b.boss.err("GET", "/v1/records", {"limit": "1", "cursor": cursor}, name="invalid_cursor")
    forged = cursor[:-4] + ("AAAA" if not cursor.endswith("AAAA") else "BBBB")
    a.boss.err("GET", "/v1/records", {"limit": "1", "cursor": forged}, name="invalid_cursor")


def test_names_come_back_as_plain_json_strings_unaltered(world):
    """LC-I9 (the API returns names as JSON strings, unaltered; the content-type header is set by the transport and the rendering half is the portal's)."""
    import json
    nasty = {"name": "<script>alert(1)</script> & \"Dana\" O'Hara", "company": "<img src=x onerror=alert(1)>"}
    world.capture(world.a, PHONE, display=nasty)
    r = world.a.boss.call("GET", "/v1/records", {})
    assert r.body["items"][0]["person"] == nasty  # not HTML-escaped, not stripped
    assert json.loads(json.dumps(r.body))["items"][0]["person"] == nasty
    proof = world.a.boss.ok("POST", "/v1/proof", body={"record_id": world.record_id(world.a, PHONE)})
    assert proof["person"] == nasty
