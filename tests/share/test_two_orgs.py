"""T024: one organisation can never create, list, withdraw or read another's links."""

import psycopg
import pytest

from consentvault import share

from .conftest import admin, get, mint_link, text_of


def test_org_b_cannot_share_org_a_record(record):
    with admin(record, record.b) as app:
        with pytest.raises(share.UnknownRecord):
            share.mint(app, event_id=record.a.event_ids[0], actor="member:b", flags={}, contact_ack=None, note="")


def test_org_b_cannot_list_or_withdraw_org_a_links(record):
    made = mint_link(record)
    with admin(record, record.b) as app:
        assert share.list_shares(app) == []
        with pytest.raises(share.UnknownShare):
            share.revoke(app, made["share_id"], actor="member:b")
        with pytest.raises(share.UnknownShare):
            share.reset_match(app, made["share_id"], actor="member:b")
    with admin(record) as app:
        assert [s["share_id"] for s in share.list_shares(app)] == [made["share_id"]]


def test_a_share_row_cannot_point_across_organisations(record):
    with record.superuser() as su:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            su.execute("INSERT INTO consentvault.proof_share (org_id, share_id, link_digest, event_id, created_by, code_version)"
                       " VALUES (%s, gen_random_uuid(), repeat('a', 64), %s, 'x', 'x')",
                       (record.b.org_id, record.a.event_ids[0]))


def test_a_link_of_a_renders_nothing_of_b(record, routes):
    made = mint_link(record)
    shown = text_of(get(routes, made["link_id"])) + text_of(get(routes, made["link_id"], ".json"))
    assert "bravo" not in shown
    assert str(record.b.org_id) not in shown
    for event_id in record.b.event_ids:
        assert str(event_id) not in shown
