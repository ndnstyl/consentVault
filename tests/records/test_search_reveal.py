"""records.md sections 5 and 6: exact search, audited reveal, the shared rate limit."""

import pytest

from contract_world.world import EMAIL, PHONE, PHONE2


def test_search_finds_the_one_record_for_an_exact_contact_however_it_is_formatted(world):
    """records.md section 5 (exact match after normalisation; answer {items: [record]})."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana", "company": "Cruz"})
    for typed in (PHONE, "(555) 555-0142", "555-555-0142", "+1 555 555 0142"):  # national format uses the default region US
        items = o.boss.ok("POST", "/v1/records:search", body={"contact": typed})["items"]
        assert len(items) == 1 and items[0]["contact"]["fp_hint"] == o.fp(PHONE)[:8]
        assert items[0]["person"] == {"name": "Dana", "company": "Cruz"}
    assert o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE2})["items"] == []
    world.email_grant(o, EMAIL)
    assert len(o.viewer.ok("POST", "/v1/records:search", body={"contact": "DANA@Example.com"})["items"]) == 1


def test_search_refuses_what_is_not_a_contact_point_and_partial_matches_cannot_exist(world):
    """records.md section 5 (invalid_contact; partial matches cannot exist)."""
    world.capture(world.a, PHONE)
    world.a.boss.err("POST", "/v1/records:search", body={"contact": "not a contact"}, name="invalid_contact")
    world.a.boss.err("POST", "/v1/records:search", body={}, name="invalid_contact")
    assert world.a.boss.ok("POST", "/v1/records:search", body={"contact": "+15555550143"})["items"] == []


def test_search_audits_found_or_not_with_a_fingerprint_hint_and_never_the_contact(world):
    """records.md section 5 (audit records.searched: target contact, fp hint when found, found bool)."""
    o = world.a
    world.capture(o, PHONE)
    o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE})
    o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE2})
    rows = world.audit(o.boss, "records.searched")
    assert len(rows) == 2
    found = [r for r in rows if r["detail"]["found"]]
    missed = [r for r in rows if not r["detail"]["found"]]
    assert len(found) == len(missed) == 1
    assert found[0]["target"] == {"kind": "contact", "id": o.fp(PHONE)[:8]}
    for r in rows:
        assert PHONE not in str(r) and PHONE2 not in str(r)


def test_search_and_reveal_share_one_bucket_of_30_calls_per_member_per_10_minutes(world):
    """records.md section 5 and 6 (30 calls per member per 10 minutes, one shared bucket, Retry-After set)."""
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)  # one call
    for _ in range(14):
        o.boss.ok("POST", "/v1/records:search", body={"contact": PHONE})
    for _ in range(15):
        o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": [rid]})
    r = o.boss.call("POST", "/v1/records:search", body={"contact": PHONE})
    assert r.status == 429 and r.body["error"] == "rate_limited" and int(r.headers["Retry-After"]) > 0
    r = o.boss.call("POST", "/v1/records:reveal", body={"record_ids": [rid]})
    assert r.status == 429 and r.body["error"] == "rate_limited"
    other = o.viewer.call("POST", "/v1/records:search", body={"contact": PHONE})
    assert other.status == 200  # the bucket is per member


def test_search_and_reveal_are_closed_to_a_developer(world):
    """records.md section 5 and 6 (roles A, V), auth.md (a developer may not read, search or reveal)."""
    world.capture(world.a, PHONE)
    rid = world.record_id(world.a, PHONE)
    world.a.dev.err("POST", "/v1/records:search", body={"contact": PHONE}, name="role_not_allowed")
    world.a.dev.err("POST", "/v1/records:reveal", body={"record_ids": [rid]}, name="role_not_allowed")
    assert world.a.viewer.ok("POST", "/v1/records:reveal", body={"record_ids": [rid]})["items"][0]["contact"] == PHONE


def test_reveal_returns_full_contacts_with_the_audit_rows_in_order(world):
    """records.md section 6 (steps 1 to 4: requested row, unwrap, revealed row, answer; same reveal_id)."""
    o = world.a
    world.capture(o, PHONE)
    world.email_grant(o, EMAIL)
    ids = [world.record_id(o, PHONE), world.record_id(o, EMAIL)]
    body = o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": ids, "reason": "customer called"})
    assert body["reveal_id"]
    assert {i["record_id"]: (i["contact"], i["cause"]) for i in body["items"]} == {ids[0]: (PHONE, None), ids[1]: (EMAIL, None)}
    (req,) = world.audit(o.boss, "records.reveal_requested")
    (done,) = world.audit(o.boss, "records.revealed")
    assert req["target"] == {"kind": "contact_set", "id": body["reveal_id"]} == done["target"]
    assert req["detail"]["requested"] == ids and req["detail"]["fp_hints"] and req["reason"] == "customer called"
    assert done["detail"] == {"revealed": ids, "not_revealed": []}
    assert req["at"] <= done["at"]
    for row in (req, done):
        assert PHONE not in str(row) and EMAIL not in str(row)


def test_a_failed_first_audit_row_means_nothing_is_unwrapped(world):
    """records.md section 6 (step 1: audit_unavailable, nothing unwrapped)."""
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    with world.audit_refused("records.reveal_requested"), world.custody_counting() as calls:
        r = o.boss.call("POST", "/v1/records:reveal", body={"record_ids": [rid]})
    assert r.status == 503 and r.body["error"] == "audit_unavailable" and calls["n"] == 0
    assert world.audit(o.boss, "records.revealed") == []


def test_a_failed_second_audit_row_discards_the_decrypted_values(world):
    """records.md section 6 (step 3: audit_unavailable, nothing returned; requested without revealed means nothing shown)."""
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    with world.audit_refused("records.revealed"):
        r = o.boss.call("POST", "/v1/records:reveal", body={"record_ids": [rid]})
    assert r.status == 503 and r.body["error"] == "audit_unavailable" and PHONE not in str(r.body)
    assert len(world.audit(o.boss, "records.reveal_requested")) == 1 and world.audit(o.boss, "records.revealed") == []


def test_an_erased_record_reveals_nothing_with_cause_erased(world):
    """records.md section 6 (items: contact null with cause erased)."""
    o = world.a
    world.capture(o, PHONE)
    world.capture(o, PHONE2)
    rid, rid2 = world.record_id(o, PHONE), world.record_id(o, PHONE2)
    world.erase(o, PHONE)
    body = o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": [rid, rid2]})
    got = {i["record_id"]: i for i in body["items"]}
    assert got[rid]["contact"] is None and got[rid]["cause"] == "erased" and got[rid2]["contact"] == PHONE2
    (done,) = world.audit(o.boss, "records.revealed")
    assert done["detail"]["not_revealed"] == [{"record_id": rid, "cause": "erased"}]


def test_an_unavailable_contact_key_reveals_nothing_with_cause_key_unavailable(world):
    """records.md section 6 (a key that cannot be opened is always a per-item cause key_unavailable, never a request error)."""
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    with world.custody_down():
        r = o.boss.call("POST", "/v1/records:reveal", body={"record_ids": [rid]})
    assert r.status == 200  # always a per-item cause, never a request error
    assert r.body["items"][0]["cause"] == "key_unavailable" and r.body["items"][0]["contact"] is None and PHONE not in str(r.body)
    (done,) = world.audit(o.boss, "records.revealed")
    assert done["detail"]["not_revealed"] == [{"record_id": rid, "cause": "key_unavailable"}]


def test_reveal_input_rules(world):
    """records.md section 6 (1 to 200 ids; unknown id and more than 200 are validation_failed; reason at most 200)."""
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    o.boss.err("POST", "/v1/records:reveal", body={"record_ids": []}, name="validation_failed")
    o.boss.err("POST", "/v1/records:reveal", body={"record_ids": ["00000000-0000-4000-8000-000000000003"]}, name="validation_failed")
    o.boss.err("POST", "/v1/records:reveal", body={"record_ids": [rid] * 201}, name="validation_failed")
    o.boss.err("POST", "/v1/records:reveal", body={"record_ids": [rid], "reason": "x" * 201}, name="validation_failed")
    assert o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": [rid], "reason": "x" * 200})["items"]


def test_reveal_of_up_to_200_records_in_one_call(world):
    """records.md section 6 (up to 200 listed records)."""
    o = world.a
    for n in range(12):
        world.capture(o, f"+155555504{n:02d}")
    ids = [i["record_id"] for i in o.boss.ok("GET", "/v1/records", {"limit": "200"})["items"]]
    body = o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": ids})
    assert sorted(i["contact"] for i in body["items"]) == sorted(f"+155555504{n:02d}" for n in range(12))


def alarms(world, org, kind="reveal_volume"):
    return world.sql(org, "SELECT * FROM consentvault.org_alarm WHERE org_id = %s AND kind = %s AND cleared_at IS NULL", (org.org_id, kind))


def reveal_n(person, ids, calls):
    for _ in range(calls):
        person.ok("POST", "/v1/records:reveal", body={"record_ids": ids})


def all_ids(person, total):
    ids, cursor = [], None
    while len(ids) < total:
        page = person.ok("GET", "/v1/records", {"limit": "200", **({"cursor": cursor} if cursor else {})})
        ids += [i["record_id"] for i in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    return ids


def chunks(ids, n=200):
    return [ids[i:i + n] for i in range(0, len(ids), n)]


def test_one_member_passing_1000_distinct_records_in_an_hour_opens_exactly_one_alarm(world):
    """records.md section 6 reveal volume alarm (distinct records count, repeats once; more than 1,000 in 60 minutes by one
    member: one org_alarm row of kind reveal_volume, detail {member_id, count, window}, at most one open; the reveal still
    answers; no contact points in the alarm; an alarm row only and no email)."""
    o = world.a
    sent_before = len(world.vault.mailer.sent)
    world.capture_many(o, 1001)
    ids = all_ids(o.boss, 1001)
    assert len(ids) == 1001
    for chunk in chunks(ids[:1000]):
        o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": chunk})  # 1,000 distinct: not past the line
    for _ in range(3):
        reveal_n(o.boss, ids[:200], 1)  # repeats of records already revealed count once
    assert alarms(world, o) == []
    body = o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": ids[1000:]})  # the 1,001st distinct: the reveal still answers
    assert body["items"][0]["contact"]
    (alarm,) = alarms(world, o)
    assert alarm["detail"]["member_id"] == o.boss.member_id and alarm["detail"]["count"] == 1001 and "window" in alarm["detail"]
    assert "+1305" not in str(alarm["detail"])
    reveal_n(o.boss, ids[:200], 1)
    assert len(alarms(world, o)) == 1  # at most one open per member
    assert alarms(world, world.b) == []
    assert len(world.vault.mailer.sent) == sent_before  # an alarm row only: the reveal alarm sends no email


def test_repeat_reveals_of_the_same_records_never_open_the_alarm(world):
    """records.md section 6 (repeats count once: 10 reveals of the same 200 records are 200 distinct)."""
    o = world.a
    world.capture_many(o, 200)
    ids = all_ids(o.boss, 200)
    reveal_n(o.boss, ids, 10)
    assert alarms(world, o) == []


def test_the_organization_reveal_alarm_opens_past_5000_distinct_records_in_24_hours_across_members(world):
    """records.md section 6 reveal volume alarm (5,000 distinct records in 24 hours for the organization: detail member_id
    null). Each member stays at 1,000 an hour, so only the organization line is crossed."""
    o = world.a
    world.capture_many(o, 5001)
    ids = all_ids(o.boss, 5001)
    assert len(ids) == 5001
    people = (o.boss, o.viewer)
    for hour, block in enumerate(chunks(ids, 1000)):
        for chunk in chunks(block):
            people[hour % 2].ok("POST", "/v1/records:reveal", body={"record_ids": chunk})
        if hour < 4:
            assert alarms(world, o) == []
        world.advance_clock(3700)
    org_alarms = alarms(world, o)
    assert len(org_alarms) == 1 and org_alarms[0]["detail"]["member_id"] is None and org_alarms[0]["detail"]["count"] == 5001


def test_a_national_number_is_read_with_the_organizations_default_region(world):
    """records.md phone region rule (default_region ISO alpha-2, default US, on GET /v1/org, set at provisioning; national
    format normalised with it; a number starting with + ignores it; search and reveal use the same rule; 555-01 invalid)."""
    us = world.a
    assert us.boss.ok("GET", "/v1/org")["default_region"] == "US"
    world.capture(us, PHONE)
    by_national = us.boss.ok("POST", "/v1/records:search", body={"contact": "(555) 555-0142"})["items"]
    assert by_national == us.boss.ok("POST", "/v1/records:search", body={"contact": PHONE})["items"] and len(by_national) == 1
    us.boss.err("POST", "/v1/records:search", body={"contact": "555-01"}, name="invalid_contact")
    gb = world.extra_org("britco", default_region="GB")
    assert gb.boss.ok("GET", "/v1/org")["default_region"] == "GB"
    world.capture(gb, "+15555550142")  # a US number in the GB organization: a national-format US string must not find it
    world.capture(gb, "+442079460018")
    found = gb.boss.ok("POST", "/v1/records:search", body={"contact": "020 7946 0018"})["items"]
    assert len(found) == 1 and found[0]["contact"]["fp_hint"] == gb.fp("+442079460018")[:8]
    assert gb.boss.ok("POST", "/v1/records:search", body={"contact": "+442079460018"})["items"] == found  # + ignores the region
    r = gb.boss.call("POST", "/v1/records:search", body={"contact": "(555) 555-0142"})
    assert (r.status == 200 and r.body["items"] == []) or r.body["error"] == "invalid_contact"  # read with GB, never as the US number
    assert gb.boss.ok("POST", "/v1/records:reveal", body={"record_ids": [found[0]["record_id"]]})["items"][0]["contact"] == "+442079460018"
