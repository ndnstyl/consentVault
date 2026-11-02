"""records.md sections 4 and 6, amended after the portal build: the default 30-day series in the requested zone, the server-side
call total (voice plus artificial voice), and reveal returning revealed_at from its own audit row."""

from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from contract_world.world import PHONE, PHONE2


def summary(p, **q):
    return p.ok("GET", "/v1/records/summary", {k: str(v) for k, v in q.items()})


PHONE3 = "+15555550111"
PHONE4 = "+15555550112"
PHONE5 = "+15555550113"


def _local(day: date, tz: str, hour: int) -> datetime:
    return datetime.combine(day, time(hour), tzinfo=ZoneInfo(tz))


def test_without_from_the_series_is_the_last_30_days_ending_today_in_the_requested_zone(world):
    """records.md section 4 (new_per_day defaults to the last 30 days in the zone: 30 buckets, today last)."""
    o = world.a
    tz = "America/New_York"
    world.capture(o, PHONE)
    world.capture(o, PHONE2)
    body = summary(o.boss, tz=tz)
    today = datetime.fromisoformat(body["as_of"]).astimezone(ZoneInfo(tz)).date()
    days = [r["date"] for r in body["new_per_day"]]
    assert len(days) == 30 and days[-1] == today.isoformat() and days[0] == (today - timedelta(days=29)).isoformat()
    world.backdate(o, PHONE, first=_local(today - timedelta(days=29), tz, 1))   # the first local hour of the window
    world.backdate(o, PHONE2, first=_local(today - timedelta(days=30), tz, 23))  # the last local hour before it
    body = summary(o.boss, tz=tz)
    assert body["new_per_day"][0] == {"date": (today - timedelta(days=29)).isoformat(), "count": 1}
    assert sum(r["count"] for r in body["new_per_day"]) == 1 and body["new_in_range"] == 1 and body["total"] == 2


def test_without_from_the_utc_series_is_also_30_buckets(world):
    """records.md section 4 (the zone defaults to UTC; the default series is 30 buckets either way)."""
    world.capture(world.a, PHONE)
    body = summary(world.a.boss)
    today = datetime.fromisoformat(body["as_of"]).astimezone(timezone.utc).date()
    assert len(body["new_per_day"]) == 30 and body["new_per_day"][-1]["date"] == today.isoformat()
    assert body["new_per_day"][0]["date"] == (today - timedelta(days=29)).isoformat()


def test_without_from_a_given_to_ends_the_30_day_series_on_the_local_day_of_to(world):
    """records.md section 4 (the default window is counted back from `to` when only `to` is given)."""
    world.capture(world.a, PHONE)
    body = summary(world.a.boss, to="2026-03-10T12:00:00Z")
    days = [r["date"] for r in body["new_per_day"]]
    assert len(days) == 30 and days[0] == "2026-02-09" and days[-1] == "2026-03-10"


def test_a_given_from_still_wins_over_the_default_window(world):
    """records.md section 4 (the default applies only when `from` is absent)."""
    world.capture(world.a, PHONE)
    body = summary(world.a.boss, **{"from": "2026-03-01T00:00:00Z", "to": "2026-03-03T00:00:00Z"})
    assert [r["date"] for r in body["new_per_day"]] == ["2026-03-01", "2026-03-02"]


def test_the_call_total_counts_each_record_once_across_voice_and_artificial_voice(world):
    """records.md section 4 (call: every record once, most protective status across voice and artificial_voice, any purpose)."""
    o = world.a
    world.capture(o, PHONE, channels=("voice",))                                    # consent on voice only
    world.capture(o, PHONE2, channels=("voice", "artificial_voice"))                # consent on both: one record, not two
    world.capture(o, PHONE3, channels=("voice", "artificial_voice"))
    world.stop(o, PHONE3, channels=("artificial_voice",))                           # stopped on one call channel: stop, once
    world.capture(o, PHONE4, channels=("sms",))                                     # no call consent: no_record, as in by_channel
    body = summary(o.boss)
    assert body["call"] == {"consent_record_found": 2, "stop_on_record": 1, "no_record": 1}
    rows = {r["channel"]: r for r in body["by_channel"]}
    assert rows["voice"]["consent_record_found"] + rows["voice"]["stop_on_record"] == 3
    assert rows["artificial_voice"]["consent_record_found"] + rows["artificial_voice"]["stop_on_record"] == 2
    assert body["partial"] == []


def test_the_call_total_is_zero_when_there_are_no_call_records_and_follows_the_filters(world):
    """records.md section 4 (same filters as the list apply to the call total)."""
    o = world.a
    assert summary(o.boss)["call"] == {"consent_record_found": 0, "stop_on_record": 0, "no_record": 0}
    world.capture(o, PHONE, channels=("voice",))
    world.capture(o, PHONE5, channels=("voice",))
    world.stop(o, PHONE5, channels=("voice",))
    assert summary(o.boss)["call"] == {"consent_record_found": 1, "stop_on_record": 1, "no_record": 0}
    assert summary(o.boss, has_stop="true")["call"] == {"consent_record_found": 0, "stop_on_record": 1, "no_record": 0}


def test_the_call_total_is_open_to_every_role_and_of_one_organization_only(world):
    """records.md section 4 (counts only, roles A, V, D; a second organization sees nothing)."""
    world.capture(world.a, PHONE, channels=("voice",))
    for who in world.a.people.values():
        assert summary(who)["call"]["consent_record_found"] == 1
    assert summary(world.b.boss)["call"] == {"consent_record_found": 0, "stop_on_record": 0, "no_record": 0}


def test_a_failed_call_total_read_is_null_and_named_in_partial_alone(world):
    """records.md section 4 and confirmations.md section 13 (failed-reads switch records.summary.call)."""
    world.capture(world.a, PHONE, channels=("voice",))
    with world.fail_reads("records.summary.call"):
        body = summary(world.a.boss)
    assert body["call"] is None and body["partial"] == ["call"]
    assert body["by_channel"] is not None and body["total"] == 1


def test_reveal_returns_revealed_at_taken_from_its_revealed_audit_row(world):
    """records.md section 6 (revealed_at is the `at` of the records.revealed audit row of the same reveal_id)."""
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    body = o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": [rid]})
    (done,) = world.audit(o.boss, "records.revealed")
    assert done["target"]["id"] == body["reveal_id"]
    assert body["revealed_at"] == done["at"]
    (req,) = world.audit(o.boss, "records.reveal_requested")
    assert req["at"] <= body["revealed_at"]


def test_revealed_at_is_present_even_when_every_item_failed(world):
    """records.md section 6 (a key failure is a per-item cause; the revealed row is still written, so revealed_at is set)."""
    o = world.a
    world.capture(o, PHONE)
    rid = world.record_id(o, PHONE)
    with world.custody_down():
        body = o.boss.ok("POST", "/v1/records:reveal", body={"record_ids": [rid]})
    (done,) = world.audit(o.boss, "records.revealed")
    assert body["items"][0]["cause"] == "key_unavailable" and body["revealed_at"] == done["at"]
