"""Posts that carry no contact point are stored, filed as unmatched with a plain reason and counted by an alarm
(tasks T090, T091)."""

import os

import pytest

from consentvault import extract, match
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy
from match_support import JSON, make_writer, match_rows, post

FORM = (("content-type", "application/x-www-form-urlencoded"),)


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def writer(tenancy, tmp_path):
    return make_writer(tenancy, tmp_path)


def unmatched(tenancy, org):
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(org.org_id)):
        return match.unmatched_posts(app, org.org_id), match.unmatched_count(app, org.org_id)


def test_random_bytes_are_stored_and_filed_unmatched_because_the_body_cannot_be_read(tenancy, writer):
    junk = os.urandom(300)
    s, after = post(tenancy, writer, junk)
    assert after.failures == [] and "capture.unmatched_post" in after.alarms
    [row] = match_rows(tenancy, s.post_id)
    assert (row["status"], row["unmatched_reason"], row["contact_fp"]) == ("unmatched", "body_unreadable", None)
    with tenancy.superuser() as su:
        assert su.execute("SELECT body_sha256 FROM consentvault.raw_post WHERE post_id = %s", (s.post_id,)).fetchone()["body_sha256"] == s.body_sha256


def test_a_phone_field_that_is_not_a_phone_is_unmatched_with_that_reason(tenancy, writer):
    s, after = post(tenancy, writer, {"phone": "call me", "checked": True}, source_id=_phone_map(tenancy))
    assert "capture.unmatched_post" in after.alarms
    assert match_rows(tenancy, s.post_id)[0]["unmatched_reason"] == "contact_unreadable_as_phone"


def _phone_map(tenancy):
    org = tenancy.a
    with tenancy.operator() as op, org_transaction(op, tenancy.admin_token(org.org_id)):
        extract.add_field_map(op, set_by="member:test", source_id=org.source_id, body_format="json", consent_paths=["/checked"],
                              contact_paths=[("/phone", "phone")])
    return org.source_id


def test_an_email_field_that_is_not_an_email_is_unmatched_with_that_reason(tenancy, writer):
    org = tenancy.a
    with tenancy.operator() as op, org_transaction(op, tenancy.admin_token(org.org_id)):
        extract.add_field_map(op, set_by="member:test", source_id=org.source_id, body_format="json", consent_paths=["/checked"],
                              contact_paths=[("/email", "email")])
    s, _ = post(tenancy, writer, {"email": "not an email", "checked": True}, source_id=org.source_id)
    assert match_rows(tenancy, s.post_id)[0]["unmatched_reason"] == "contact_unreadable_as_email"


def test_a_form_with_no_field_map_is_stored_and_unmatched_for_want_of_a_map(tenancy, writer):
    s, after = post(tenancy, writer, {"contact": "a@b.com", "checked": True}, intake_name="twenty")
    assert after.map_label is None and "capture.unmatched_post" in after.alarms
    assert match_rows(tenancy, s.post_id)[0]["unmatched_reason"] == "no_map"


def test_a_map_that_names_no_contact_field_and_a_post_without_the_field_each_say_so(tenancy, writer):
    org = tenancy.a
    with tenancy.operator() as op, org_transaction(op, tenancy.admin_token(org.org_id)):
        extract.add_field_map(op, set_by="member:test", source_id=org.source_id, body_format="json", consent_paths=["/checked"])
    s1, _ = post(tenancy, writer, {"checked": True}, source_id=org.source_id)
    assert match_rows(tenancy, s1.post_id)[0]["unmatched_reason"] == "no_contact_path"
    s2, _ = post(tenancy, writer, {"contact": "a@b.com", "checked": True})   # the built-in map, the contact key absent below
    s3, _ = post(tenancy, writer, {"checked": True})
    assert match_rows(tenancy, s2.post_id)[0]["status"] == "matched"
    assert match_rows(tenancy, s3.post_id)[0]["unmatched_reason"] == "contact_not_sent"


def test_a_platform_intake_post_is_stored_and_unmatched_with_a_plain_reason(tenancy, writer):
    s, after = post(tenancy, writer, b'{"anything": 1}', intake_name="twenty", home=True)
    assert s.org_id == str(tenancy.home) and "capture.unmatched_post" in after.alarms and after.failures == []
    with tenancy.superuser() as su:
        [row] = su.execute("SELECT * FROM consentvault.raw_post_match WHERE org_id = %s", (tenancy.home,)).fetchall()
    assert (row["unmatched_reason"], row["status"]) == ("no_map", "unmatched")


def test_the_unmatched_list_and_count_carry_the_plain_reason_and_leave_matched_posts_out(tenancy, writer):
    post(tenancy, writer, {"checked": True})
    post(tenancy, writer, {"contact": "a@b.com", "checked": True})
    post(tenancy, writer, b"\x00\x01 not json")
    rows, count = unmatched(tenancy, tenancy.a)
    assert count == 2 and [r["unmatched_reason"] for r in rows] == ["body_unreadable", "contact_not_sent"]
    assert rows[0]["reason_text"] == match.REASON_TEXT["body_unreadable"]
    assert unmatched(tenancy, tenancy.b)[1] == 0


def test_every_reason_the_writer_can_give_is_one_the_table_allows_and_has_plain_words(tenancy):
    assert set(match.REASONS) == set(match.REASON_TEXT)
    assert match.REASONS == ("no_map", "no_contact_path", "contact_not_sent", "contact_unreadable_as_phone",
                             "contact_unreadable_as_email", "body_unreadable")
