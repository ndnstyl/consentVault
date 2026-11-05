"""Matching and change history: a person's posts are linked by the contact fingerprint and a change in consent is shown with
both values and both decision times as sent; nothing stored is altered (tasks T080, T081, T083)."""

import uuid

import pytest

from consentvault import extract, match
from consentvault.ledger import record_tenant_event
from consentvault.records import write_event_records
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import build_tenancy
from match_support import at, fp_of, history, make_writer, match_rows, post

EMAIL = "pat@example.com"


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.fixture
def writer(tenancy, tmp_path):
    return make_writer(tenancy, tmp_path)


def widget(contact, checked, decided_at, **more):
    return {"contact": contact, "checked": checked, "decided_at": decided_at, **more}


def test_yes_then_no_across_two_forms_then_the_same_no_again_gives_three_links_and_one_change(tenancy, writer):
    form_one, form_two = tenancy.a.source_id, uuid.uuid4()
    s1, a1 = post(tenancy, writer, widget("Pat@Example.com", True, "2026-10-02T14:03:11-04:00"), source_id=form_one)
    no = widget(" pat@example.com ", False, "2026-10-20T09:12:00-04:00", disclosure_text="Text me offers")
    s2, a2 = post(tenancy, writer, no, source_id=form_two)
    s3, a3 = post(tenancy, writer, no, source_id=form_two)
    assert a1.failures == a2.failures == a3.failures == []
    fp = fp_of(tenancy, "email", EMAIL)
    rows = [r for r in match_rows(tenancy) if r["contact_fp"] == fp]
    assert len(rows) == 3 and {r["status"] for r in rows} == {"matched"} and {r["contact_kind"] for r in rows} == {"email"}
    assert sum(1 for r in rows if r["changed"]) == 1 and sum(1 for r in rows if r["same_fingerprint_as_previous"]) == 1
    third, second, first = history(tenancy, writer, fp)
    assert [ln["post_id"] for ln in (third, second, first)] == [s3.post_id, s2.post_id, s1.post_id]
    assert second["changed"] is True and second["changed_from"]["post_id"] == s1.post_id
    assert second["changed_from"]["consent_values"] == ["true"] and second["consent"]["values"] == ["false"]
    assert second["changed_from"]["decision_time_values"] == ['"2026-10-02T14:03:11-04:00"']
    assert second["decision_time"]["values"] == ['"2026-10-20T09:12:00-04:00"']
    assert third["changed"] is False and third["changed_from"] is None and third["byte_identical_to"] == s2.post_id
    assert first["previous_post_id"] is None and first["changed_from"] is None and first["byte_identical_to"] is None
    assert second["byte_identical_to"] is None


def test_the_previous_post_from_the_same_source_is_named(tenancy, writer):
    form_one, form_two = tenancy.a.source_id, uuid.uuid4()
    s1, _ = post(tenancy, writer, widget(EMAIL, True, "2026-10-02T14:03:11-04:00"), source_id=form_one)
    s2, _ = post(tenancy, writer, widget(EMAIL, False, "2026-10-03T14:03:11-04:00"), source_id=form_two)
    s3, _ = post(tenancy, writer, widget(EMAIL, True, "2026-10-04T14:03:11-04:00"), source_id=form_one)
    s4, _ = post(tenancy, writer, widget(EMAIL, True, "2026-10-05T14:03:11-04:00"), source_id=form_two)
    l4, l3, l2, l1 = history(tenancy, writer, fp_of(tenancy, "email", EMAIL))
    assert (l1["previous_same_source_post_id"], l2["previous_same_source_post_id"]) == (None, None)
    assert l3["previous_same_source_post_id"] == s1.post_id and l4["previous_same_source_post_id"] == s2.post_id
    assert l4["previous_post_id"] == s3.post_id


def test_a_queued_no_delivered_after_a_later_yes_keeps_its_edge_arrival_order(tenancy, writer):
    yes, _ = post(tenancy, writer, widget(EMAIL, True, "2026-10-20T09:00:02-04:00"), edge_at=at(2))
    no, _ = post(tenancy, writer, widget(EMAIL, False, "2026-10-20T09:00:01-04:00"), edge_at=at(1))  # delivered later, arrived earlier
    later_yes, _ = post(tenancy, writer, widget(EMAIL, True, "2026-10-20T09:00:03-04:00"), edge_at=at(3))
    l3, l2, l1 = history(tenancy, writer, fp_of(tenancy, "email", EMAIL))
    assert [ln["post_id"] for ln in (l1, l2, l3)] == [no.post_id, yes.post_id, later_yes.post_id]   # edge order, not storage order
    assert l1["previous_post_id"] is None and l2["previous_post_id"] == no.post_id and l3["previous_post_id"] == yes.post_id
    assert l2["changed"] is True and (l2["changed_from"]["consent_values"], l2["consent"]["values"]) == (["false"], ["true"])
    assert l3["changed"] is False
    # the row the yes was first given stays; the new row beside it names the no as its previous
    first_rows = match_rows(tenancy, yes.post_id)
    assert len(first_rows) == 2 and first_rows[0]["previous_post_id"] is None and first_rows[1]["previous_post_id"] is not None


def test_a_post_with_a_phone_and_an_email_links_twice(tenancy, writer):
    org = tenancy.a
    with tenancy.operator() as op, org_transaction(op, tenancy.admin_token(org.org_id)):
        extract.add_field_map(op, set_by="member:test", source_id=org.source_id, body_format="json", consent_paths=["/ok"],
                              contact_paths=[("/email", "email"), ("/phone", "phone")])
    s, after = post(tenancy, writer, {"email": "A@B.com", "phone": "+15555550142", "ok": True}, source_id=org.source_id)
    assert after.failures == [] and after.alarms == []
    rows = match_rows(tenancy, s.post_id)
    assert sorted((r["contact_kind"], r["contact_fp"]) for r in rows) == sorted([
        ("email", fp_of(tenancy, "email", "a@b.com")), ("phone", fp_of(tenancy, "phone", "+15555550142"))])
    s2, _ = post(tenancy, writer, {"email": "a@b.com", "ok": False}, source_id=org.source_id)
    assert [ln["post_id"] for ln in history(tenancy, writer, fp_of(tenancy, "email", "a@b.com"))] == [s2.post_id, s.post_id]
    assert [ln["post_id"] for ln in history(tenancy, writer, fp_of(tenancy, "phone", "+15555550142"))] == [s.post_id]


def test_a_missing_consent_field_is_a_value_to_compare_not_a_gap_to_fill(tenancy, writer):
    s1, _ = post(tenancy, writer, widget(EMAIL, True, "2026-10-02T14:03:11-04:00"))
    s2, _ = post(tenancy, writer, {"contact": EMAIL})
    second, first = history(tenancy, writer, fp_of(tenancy, "email", EMAIL))
    assert second["consent"] == {"state": "not_sent", "values": [], "parsed_derived": None}
    assert second["changed"] is True and second["changed_from"]["consent_values"] == ["true"]


def test_the_stored_rows_are_never_altered_by_linking(tenancy, writer):
    s1, _ = post(tenancy, writer, widget(EMAIL, True, "2026-10-02T14:03:11-04:00"))
    with tenancy.superuser() as su:
        before = su.execute("SELECT post_id, row_hash, body_sha256 FROM consentvault.raw_post ORDER BY seq").fetchall()
    post(tenancy, writer, widget(EMAIL, False, "2026-10-03T14:03:11-04:00"))
    with tenancy.superuser() as su:
        after = su.execute("SELECT post_id, row_hash, body_sha256 FROM consentvault.raw_post ORDER BY seq").fetchall()
        assert after[:len(before)] == before
        with pytest.raises(Exception, match="append-only"):
            su.execute("UPDATE consentvault.raw_post_match SET changed = NOT changed")
        with pytest.raises(Exception, match="append-only"):
            su.execute("DELETE FROM consentvault.raw_post_match")


def test_a_capture_token_cannot_read_the_rows_it_wrote(tenancy, writer):
    post(tenancy, writer, widget(EMAIL, True, "2026-10-02T14:03:11-04:00"))
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a, ("capture",))):
        assert app.execute("SELECT count(*) AS n FROM consentvault.raw_post_match").fetchone()["n"] == 0


def test_another_organisations_posts_are_never_linked(tenancy, writer):
    post(tenancy, writer, widget(EMAIL, True, "2026-10-02T14:03:11-04:00"), org=tenancy.a)
    s, _ = post(tenancy, writer, widget(EMAIL, False, "2026-10-03T14:03:11-04:00"), org=tenancy.b)
    assert match_rows(tenancy, s.post_id, org=tenancy.b)[0]["previous_post_id"] is None


def test_the_person_roll_up_reads_every_contact_point_tied_to_one_person(tenancy, writer):
    org = tenancy.a
    sms_email = "+15555550143"
    with tenancy.app() as app, org_transaction(app, tenancy.token(org)):
        for contact, kind, channels in ((sms_email, "phone", ["sms"]), (EMAIL, "email", ["sms"])):
            ev = record_tenant_event(app, tenancy.crypto, contact=contact, event_type="grant", channels=channels,
                                     purposes=["marketing"], method="checkbox", origin="consumer",
                                     disclosure_sha256=org.disclosure, subject_key="person-1", source_id=org.source_id,
                                     brand_ids=[org.brand_id])
            write_event_records(app, tenancy.crypto, org=org.org_id, event_id=ev.event_id,
                                contact_fp=fp_of(tenancy, kind, contact), contact_kind=kind, contact_norm=contact)
    pe, _ = post(tenancy, writer, widget(EMAIL, True, "2026-10-02T14:03:11-04:00"))
    pp, _ = post(tenancy, writer, widget(sms_email, False, "2026-10-03T14:03:11-04:00"))
    other, _ = post(tenancy, writer, widget("someone@else.com", True, "2026-10-04T14:03:11-04:00"))
    with tenancy.app() as app, org_transaction(app, tenancy.admin_token(org.org_id)):
        fps = match.person_fps(app, org.org_id, contact_fp=fp_of(tenancy, "email", EMAIL))
        lines = match.person_history(writer, app, org.org_id, subject_fp=app.execute(
            "SELECT i.subject_fp FROM consentvault.record r JOIN consentvault.record_index i USING (org_id, record_id)"
            " WHERE r.contact_fp = %s", (fp_of(tenancy, "email", EMAIL),)).fetchone()["subject_fp"])
    assert set(fps) == {fp_of(tenancy, "email", EMAIL), fp_of(tenancy, "phone", sms_email)}
    assert [(ln["post_id"], ln["contact_kind"]) for ln in lines] == [(pp.post_id, "phone"), (pe.post_id, "email")]
    # the existing record of the contact is the link's record
    assert {r["record_id"] for r in match_rows(tenancy, pe.post_id)} != {None}
