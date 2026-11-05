import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from consentvault import db
from consentvault.capture import capture
from consentvault.errors import NormalizationError
from consentvault.gate import contact_facts, record_contact
from consentvault.ledger import record_event

PHONE = "+15555550101"


def _grant(conn, disclosure, **kw):
    return capture(conn, contact=PHONE, checked=True, disclosure_sha256=disclosure,
                   channels=kw.pop("channels", ["sms"]), purposes=kw.pop("purposes", ["marketing"]), **kw)


def _stop(conn, **kw):
    kw.setdefault("method", "keyword")
    kw.setdefault("origin", "consumer")
    return record_event(conn, contact=PHONE, event_type="suppress", channels=kw.pop("channels", ["sms"]),
                        purposes=kw.pop("purposes", ["marketing"]), **kw)


VERDICT_WORDS = {"allowed", "denied", "proceed", "hold", "policy_action", "policy_version", "permitted"}


def _no_verdict(answer: dict) -> None:
    flat = json.dumps(answer)
    assert not VERDICT_WORDS & set(answer), answer
    for word in ("allowed", "proceed", "hold", "deny", "denied"):
        assert f'"{word}"' not in flat, (word, flat)


def test_no_record_is_the_fact_no_record_found(conn):
    f = contact_facts(conn, PHONE)
    assert f.status == "no_record_found" and f.history == () and f.stops == () and f.lifts == ()
    _no_verdict(f.as_dict())


def test_a_grant_is_a_history_line_and_nothing_more(conn, disclosure):
    ev = _grant(conn, disclosure)
    f = contact_facts(conn, PHONE)
    assert f.status == "records_found" and f.event_ids == (ev.event_id,) and f.stops == ()
    line = f.history[0]
    assert line["event_type"] == "grant" and line["channels"] == ["sms"] and line["purposes"] == ["marketing"]
    assert line["method"] == "checkbox" and line["origin"] == "consumer" and line["disclosure_sha256"] == disclosure
    _no_verdict(f.as_dict())


def test_the_check_answers_for_the_contact_point_whatever_channel_or_purpose(conn, disclosure):
    _grant(conn, disclosure)
    f = contact_facts(conn, PHONE)
    assert [line["channels"] for line in f.history] == [["sms"]]  # one answer: every line of the contact point, unfiltered


def test_a_stop_is_listed_with_its_source_and_beside_the_grant_it_followed(conn, disclosure):
    g = _grant(conn, disclosure)
    s = _stop(conn, source="sms_reply")
    f = contact_facts(conn, PHONE)
    assert f.event_ids == (g.event_id, s.event_id)
    assert [x["event_id"] for x in f.stops] == [s.event_id]
    stop = f.stops[0]
    assert stop["event_type"] == "suppress" and stop["method"] == "keyword" and stop["source"] == "sms_reply"
    assert stop["lifted_by_post_ids"] == []
    assert f.lifts == ()
    _no_verdict(f.as_dict())


def test_a_grant_after_a_stop_lifts_nothing_it_is_only_the_next_line(conn, disclosure):
    _stop(conn)
    g = _grant(conn, disclosure)
    f = contact_facts(conn, PHONE)
    assert [line["event_type"] for line in f.history] == ["suppress", "grant"] and f.event_ids[-1] == g.event_id
    assert f.stops[0]["lifted_by_post_ids"] == [] and f.lifts == ()


def test_formatting_of_contact_does_not_matter(conn, disclosure):
    _grant(conn, disclosure)
    assert contact_facts(conn, "(555) 555-0101", region="US").status == "records_found"


def test_another_contact_point_is_untouched(conn, disclosure):
    _grant(conn, disclosure)
    assert contact_facts(conn, "+15555550199").status == "no_record_found"


def test_a_contact_that_is_not_a_phone_or_email_is_a_bad_request_not_a_verdict(conn):
    with pytest.raises(NormalizationError):
        contact_facts(conn, "not a number")


def test_a_record_that_cannot_be_read_is_unavailable_with_the_cause_and_nothing_else(dsn):
    c = db.connect(dsn)
    c.close()
    f = contact_facts(c, PHONE)
    assert f.status == "unavailable" and f.reason.startswith("database_unreachable") and not f.read
    assert f.history == () and f.stops == () and f.label.startswith("unavailable:database_unreachable")
    _no_verdict(f.as_dict())


def test_the_check_writes_nothing(conn, disclosure):
    _grant(conn, disclosure)
    before = conn.execute("SELECT (SELECT count(*) FROM consentvault.event) AS e,"
                          " (SELECT count(*) FROM consentvault.contact_log) AS c").fetchone()
    contact_facts(conn, PHONE)
    after = conn.execute("SELECT (SELECT count(*) FROM consentvault.event) AS e,"
                         " (SELECT count(*) FROM consentvault.contact_log) AS c").fetchone()
    assert before == after


def test_the_module_has_no_verdict_code():
    import ast

    import consentvault.gate as g
    tree = ast.parse(pathlib.Path(g.__file__).read_text())
    tokens = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            tokens.add(node.id)
        elif isinstance(node, ast.Attribute):
            tokens.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            tokens.add(node.name)
        elif isinstance(node, ast.keyword) and node.arg:
            tokens.add(node.arg)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node is not tree.body[0].value:
            tokens.add(node.value)
    banned = {"allowed", "Decision", "_deny", "REASON_NO_CONSENT", "REASON_GRANTED", "policy_action", "proceed", "hold",
              "may_contact"}
    assert not banned & {t for t in tokens if len(t) < 40}, banned & tokens
    assert not any("policy_action" in t or " proceed" in t for t in tokens), "a verdict word in a string of the module"


def test_record_contact_writes_log(conn):
    cid = record_contact(conn, PHONE, "sms", "delivered", "msg-1", purpose="marketing")
    row = conn.execute("SELECT * FROM consentvault.contact_log WHERE contact_log_id = %s", (cid,)).fetchone()
    assert row["contact_norm"] == PHONE and row["channel"] == "sms" and row["outcome"] == "delivered"
    assert row["ref"] == "msg-1"


def test_record_contact_rejects_bad_channel(conn):
    with pytest.raises(Exception):
        record_contact(conn, PHONE, "pigeon", "x", None)


def test_record_contact_honours_contacted_at(conn):
    when = datetime.now(timezone.utc) - timedelta(days=2)
    cid = record_contact(conn, PHONE, "sms", "sent", None, contacted_at=when)
    row = conn.execute("SELECT contacted_at FROM consentvault.contact_log WHERE contact_log_id = %s", (cid,)).fetchone()
    assert row["contacted_at"] == when
