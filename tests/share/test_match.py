"""T025: the match box answers yes or no, locks on the 11th try in 24 hours, leaks nothing, and the owner can reopen it."""

import json

from consentvault import share

from export.support import OTHER_PHONE, PHONE

from .conftest import admin, get, mint_link, text_of


def _match(routes, link_id, contact):
    return get(routes, link_id, "/match", method="POST", body=json.dumps({"contact": contact}).encode(),
               headers={"Content-Type": "application/json"})


def test_yes_and_no(record, routes):
    made = mint_link(record)
    yes, no = _match(routes, made["link_id"], PHONE), _match(routes, made["link_id"], OTHER_PHONE)
    assert (yes.status, yes.payload["result"]) == (200, "yes")
    assert (no.status, no.payload["result"]) == (200, "no")
    assert "the same fingerprint" in yes.payload["statement"]


def test_a_form_post_works_and_a_typed_format_is_normalised(record, routes):
    made = mint_link(record)
    r = get(routes, made["link_id"], "/match", method="POST", body=b"contact=%2B1+555+555+0142",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status == 200
    assert b"yes" in (r.raw or json.dumps(r.payload).encode())


def test_the_eleventh_attempt_in_a_day_is_locked(record, routes):
    made = mint_link(record)
    answers = [_match(routes, made["link_id"], OTHER_PHONE) for _ in range(10)]
    assert {a.status for a in answers} == {200}
    locked = _match(routes, made["link_id"], PHONE)
    assert locked.status == 429 and "locked until the sender resets it" in text_of(locked)
    assert _match(routes, made["link_id"], PHONE).status == 429  # the right answer does not get past the lock


def test_the_answer_never_carries_the_salt_or_a_commitment(record, routes):
    made = mint_link(record)
    got = _match(routes, made["link_id"], PHONE)
    event = json.loads(get(routes, made["link_id"], ".json").raw)["event"]
    shown = text_of(got)
    for secret in (event["contact_commit"], event["contact_fp"], event["subject_commit"]):
        assert secret not in shown


def test_attempts_are_fact_rows_with_no_contact_and_no_address(record, routes):
    made = mint_link(record)
    _match(routes, made["link_id"], PHONE)
    _match(routes, made["link_id"], OTHER_PHONE)
    with record.superuser() as su:
        rows = su.execute("SELECT * FROM consentvault.proof_share_view WHERE share_id = %s ORDER BY viewed_at, view_id",
                          (made["share_id"],)).fetchall()
    assert [r["kind"] for r in rows] == ["match_yes", "match_no"]
    assert set(rows[0]) == {"org_id", "view_id", "share_id", "viewed_at", "kind"}
    assert PHONE not in str(rows) and "5555550142" not in str(rows)


def test_the_owner_reset_opens_the_box(record, routes):
    made = mint_link(record)
    for _ in range(10):
        _match(routes, made["link_id"], OTHER_PHONE)
    assert _match(routes, made["link_id"], PHONE).status == 429
    with admin(record) as app:
        share.reset_match(app, made["share_id"], actor="member:test")
    assert _match(routes, made["link_id"], PHONE).payload["result"] == "yes"
    with record.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.proof_share_reset WHERE share_id = %s", (made["share_id"],)).fetchone()["n"] == 1


def test_a_link_with_the_box_off_has_no_match_route(record, routes):
    made = mint_link(record, flags={"allow_contact_match": False})
    assert _match(routes, made["link_id"], PHONE).status == 404
    assert 'name="contact"' not in text_of(get(routes, made["link_id"]))
