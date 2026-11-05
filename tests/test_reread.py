"""A field map added later re-reads that source's posts and appends extraction and link rows; earlier rows stay and history lists
the re-read apart from the arrival-time reading (task T092)."""

import pytest

from consentvault import cmd_match_repair, extract
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy
from match_support import fp_of, history, make_writer, match_rows, post

FORM = (("content-type", "application/x-www-form-urlencoded"),)


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def writer(tenancy, tmp_path):
    return make_writer(tenancy, tmp_path)


def add_map(tenancy):
    org = tenancy.a
    with tenancy.operator() as op, org_transaction(op, tenancy.admin_token(org.org_id)):
        return extract.add_field_map(op, set_by="member:test", source_id=org.source_id, body_format="form_urlencoded",
                                     consent_paths=["agree"], decision_time_path="when", contact_paths=[("email", "email")])


def snapshot(tenancy, post_id):
    with tenancy.superuser() as su:
        fields = su.execute("SELECT map_version, field, state, values_ct, extracted_at FROM consentvault.raw_post_field"
                            " WHERE post_id = %s ORDER BY map_version, field", (post_id,)).fetchall()
    return fields, match_rows(tenancy, post_id)


def test_a_map_added_later_re_reads_the_posts_of_its_source_and_appends_only(tenancy, writer):
    org = tenancy.a
    body = b"email=a%40b.com&agree=on&when=2026-10-20+09%3A12"
    s, after = post(tenancy, writer, body, headers=FORM, source_id=org.source_id)
    assert after.map_label == "built_in:widget"
    fields0, matches0 = snapshot(tenancy, s.post_id)
    assert [m["unmatched_reason"] for m in matches0] == ["body_unreadable"] and {f["map_version"] for f in fields0} == {0}
    assert add_map(tenancy) == 1
    out = cmd_match_repair.repair_all(tenancy.app, tenancy.operator, tenancy.key, writer)
    assert out["failed"] == [] and out["read"] == 1 and out["linked"] == 1
    fields1, matches1 = snapshot(tenancy, s.post_id)
    assert fields1[:len(fields0)] == fields0 and matches1[:len(matches0)] == matches0   # earlier rows untouched
    assert {f["map_version"] for f in fields1} == {0, 1} and [m["map_version"] for m in matches1] == [0, 1]
    assert matches1[1]["status"] == "matched" and matches1[1]["contact_fp"] == fp_of(tenancy, "email", "a@b.com")
    again = cmd_match_repair.repair_all(tenancy.app, tenancy.operator, tenancy.key, writer)
    assert (again["read"], again["linked"]) == (0, 0)


def test_history_shows_the_arrival_time_reading_and_lists_the_re_read_apart(tenancy, writer):
    org = tenancy.a
    s, _ = post(tenancy, writer, b"email=a%40b.com&agree=on&when=2026-10-20+09%3A12", headers=FORM, source_id=org.source_id)
    add_map(tenancy)
    cmd_match_repair.repair_all(tenancy.app, tenancy.operator, tenancy.key, writer)
    [line] = history(tenancy, writer, fp_of(tenancy, "email", "a@b.com"))
    assert line["map_version"] == 0 and line["consent"]["state"] == "body_unreadable"      # the arrival-time reading
    [reread] = line["rereads"]
    assert reread["map_version"] == 1 and reread["consent"]["values"] == ["on"]
    assert reread["decision_time"]["values"] == ["2026-10-20+09%3A12"] and reread["matched_at"] is not None


def test_a_post_of_another_source_is_not_re_read_for_a_map_it_does_not_use(tenancy, writer):
    other, _ = post(tenancy, writer, {"contact": "x@y.com", "checked": True}, source_id=None)
    add_map(tenancy)
    out = cmd_match_repair.repair_all(tenancy.app, tenancy.operator, tenancy.key, writer)
    assert (out["read"], out["linked"]) == (0, 0)
