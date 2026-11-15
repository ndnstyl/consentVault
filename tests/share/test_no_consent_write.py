"""T030: making, reading, matching and withdrawing a link never writes a consent event or changes an answer to "may we contact"."""

import json

from consentvault import share

from export.support import PHONE

from .conftest import admin, get, mint_link


def _state(t):
    with t.superuser() as su:
        head = su.execute("SELECT count(*) AS n, max(seq) AS seq FROM consentvault.event WHERE org_id = %s", (t.a.org_id,)).fetchone()
        last = su.execute("SELECT row_hash FROM consentvault.event WHERE org_id = %s ORDER BY seq DESC LIMIT 1", (t.a.org_id,)).fetchone()
        perm = su.execute("SELECT contact_fp, channel, purpose, allowed, reason, deciding_event_id FROM consentvault.current_permission"
                          " WHERE org_id = %s ORDER BY contact_fp, channel, purpose", (t.a.org_id,)).fetchall()
        raw = su.execute("SELECT count(*) AS n FROM consentvault.raw_post WHERE org_id = %s", (t.a.org_id,)).fetchone()
    return head["n"], head["seq"], last["row_hash"], json.dumps(perm, default=str, sort_keys=True), raw["n"]


def test_the_chain_and_the_permission_answer_do_not_move(record, routes):
    before = _state(record)
    made = mint_link(record)
    get(routes, made["link_id"])
    get(routes, made["link_id"], ".json")
    get(routes, made["link_id"], "/record.zip")
    get(routes, made["link_id"], "/match", method="POST", body=json.dumps({"contact": PHONE}).encode())
    with admin(record) as app:
        share.reset_match(app, made["share_id"], actor="member:test")
        share.revoke(app, made["share_id"], actor="member:test")
    get(routes, made["link_id"])
    assert _state(record) == before
