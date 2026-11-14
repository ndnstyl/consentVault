"""records.md section 4: the summary counts, the daily series, the per-channel shares."""

from datetime import datetime, timedelta, timezone

from contract_world.world import EMAIL, PHONE, PHONE2


def summary(p, **q):
    return p.ok("GET", "/v1/records/summary", {k: str(v) for k, v in q.items()})


def test_summary_counts_totals_stops_and_new_records_in_range(world):
    """records.md section 4 (total, with_stop, new_in_range, as_of, tz)."""
    o = world.a
    world.capture(o, PHONE)
    world.capture(o, PHONE2)
    world.stop(o, PHONE2)
    world.email_grant(o, EMAIL)
    body = summary(o.boss)
    assert set(body) >= {"as_of", "tz", "total", "with_stop", "new_in_range", "new_per_day", "by_channel", "partial"}
    assert (body["total"], body["with_stop"], body["tz"], body["partial"]) == (3, 1, "UTC", [])
    assert body["new_in_range"] == 3


def test_summary_series_lists_every_day_in_range_with_zero_days_as_zero(world):
    """records.md section 4 (new_per_day: every day in range, zero days included as 0)."""
    o = world.a
    world.capture(o, PHONE)
    world.capture(o, PHONE2)
    d1, d2 = datetime(2026, 3, 1, 12, tzinfo=timezone.utc), datetime(2026, 3, 4, 12, tzinfo=timezone.utc)
    world.backdate(o, PHONE, first=d1)
    world.backdate(o, PHONE2, first=d2)
    body = summary(o.boss, **{"from": "2026-03-01T00:00:00Z", "to": "2026-03-05T00:00:00Z"})
    assert body["new_per_day"] == [{"date": "2026-03-01", "count": 1}, {"date": "2026-03-02", "count": 0},
                                   {"date": "2026-03-03", "count": 0}, {"date": "2026-03-04", "count": 1}]
    assert body["new_in_range"] == 2


def test_summary_day_buckets_follow_the_requested_time_zone(world):
    """records.md section 4 (tz: IANA zone the day buckets use)."""
    o = world.a
    world.capture(o, PHONE)
    world.backdate(o, PHONE, first=datetime(2026, 3, 2, 3, 30, tzinfo=timezone.utc))
    q = {"from": "2026-03-01T00:00:00Z", "to": "2026-03-03T00:00:00Z"}
    utc = {r["date"]: r["count"] for r in summary(o.boss, **q)["new_per_day"]}
    ny = {r["date"]: r["count"] for r in summary(o.boss, tz="America/New_York", **q)["new_per_day"]}
    assert utc["2026-03-02"] == 1 and ny["2026-03-01"] == 1 and ny.get("2026-03-02", 0) == 0


def test_summary_series_span_is_at_most_400_days_and_bad_zone_is_refused(world):
    """records.md section 4 (span at most 400 days for the series; validation_failed beyond)."""
    world.capture(world.a, PHONE)
    summary(world.a.boss, **{"from": "2025-01-01T00:00:00Z", "to": "2026-01-05T00:00:00Z"})
    world.a.boss.err("GET", "/v1/records/summary", {"from": "2025-01-01T00:00:00Z", "to": "2026-03-01T00:00:00Z"}, name="validation_failed")
    world.a.boss.err("GET", "/v1/records/summary", {"tz": "Mars/Olympus"}, name="validation_failed")


def test_summary_by_channel_counts_each_record_once_under_its_most_protective_status(world):
    """records.md section 4 (by_channel: stop_on_record if any purpose stopped, else consent_record_found, else no_record)."""
    o = world.a
    world.capture(o, PHONE, purposes=("marketing",))
    world.capture(o, PHONE2)
    world.stop(o, PHONE2)
    world.capture(o, "+15555550111", channels=("voice",))
    sms = {r["channel"]: r for r in summary(o.boss)["by_channel"]}["sms"]
    assert (sms["consent_record_found"], sms["stop_on_record"], sms["no_record"]) == (1, 1, 1)
    assert {r["channel"] for r in summary(o.boss)["by_channel"]} == {"sms", "voice", "artificial_voice", "email"}


def test_summary_takes_the_list_filters(world):
    """records.md section 4 (same filters as section 3)."""
    o = world.a
    world.capture(o, PHONE)
    world.email_grant(o, EMAIL)
    assert summary(o.boss, contact_kind="email")["total"] == 1
    assert summary(o.boss, has_stop="true")["total"] == 0
    assert summary(o.boss, source_id=o.web_id)["total"] == 2


def test_summary_is_counts_only_open_to_every_role_and_never_audited(world):
    """records.md section 4 (counts only, no personal data; not audited; roles A, V, D)."""
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    for who in o.people.values():
        body = summary(who)
        text = str({k: v for k, v in body.items() if k != "as_of"})  # as_of has microseconds that can read "0142"
        assert body["total"] == 1 and "Dana" not in text and "0142" not in text
    assert world.audit(o.boss, "records.listed") == []
    with world.audit_refused("records.listed"):
        assert summary(o.boss)["total"] == 1


def test_summary_of_one_organization_ignores_the_other(world):
    """records.md section 4 and the isolation rule (a second organization sees nothing)."""
    world.capture(world.a, PHONE)
    assert summary(world.b.boss)["total"] == 0 and summary(world.a.boss)["total"] == 1


def test_each_failed_summary_read_is_null_and_named_in_partial(world):
    """records.md section 4 (a field that could not be read is null and named in partial; failed-reads switch
    records.summary.<field>, one at a time)."""
    world.capture(world.a, PHONE)
    for name in ("total", "with_stop", "new_in_range", "new_per_day", "by_channel"):
        with world.fail_reads("records.summary." + name):
            body = summary(world.a.boss)
        assert body[name] is None and body["partial"] == [name], name
        assert all(body[k] is not None for k in ("total", "with_stop", "new_in_range", "new_per_day", "by_channel") if k != name)
