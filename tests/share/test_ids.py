"""T022: link ids are 128 random bits from the platform source; only a digest is stored; the id is never logged or audited."""

import hashlib
import logging
import re
import secrets

from consentvault import share

from .conftest import admin, get, mint_link


def test_the_id_shape_and_the_source(record, monkeypatch):
    seen = []
    real = secrets.token_bytes

    def spy(n=None):
        seen.append(n)
        return real(n)

    monkeypatch.setattr(share.secrets, "token_bytes", spy)
    made = mint_link(record)
    assert re.fullmatch(r"cvp_[a-z2-7]{26}", made["link_id"])
    assert seen == [16]


def test_two_links_for_one_record_differ_and_only_the_digest_is_stored(record):
    one, two = mint_link(record), mint_link(record)
    assert one["link_id"] != two["link_id"] and one["share_id"] != two["share_id"]
    with record.superuser() as su:
        rows = su.execute("SELECT * FROM consentvault.proof_share WHERE org_id = %s ORDER BY created_at", (record.a.org_id,)).fetchall()
    assert {r["link_digest"] for r in rows} == {hashlib.sha256(one["link_id"].encode()).hexdigest(),
                                                hashlib.sha256(two["link_id"].encode()).hexdigest()}
    for r in rows:
        assert one["link_id"] not in str(dict(r)) and two["link_id"] not in str(dict(r))


def test_the_id_is_in_no_log_line_and_no_audit_detail(record, routes, caplog):
    caplog.set_level(logging.DEBUG)
    made = mint_link(record)
    get(routes, made["link_id"])
    get(routes, made["link_id"], ".json")
    get(routes, made["link_id"], "/match", method="POST", body=b'{"contact": "+15555550142"}')
    with admin(record) as app:
        share.revoke(app, made["share_id"], actor="member:test")
    get(routes, made["link_id"])
    assert made["link_id"] not in caplog.text
    with record.superuser() as su:
        audit = su.execute("SELECT * FROM consentvault.audit_event WHERE org_id = %s", (record.a.org_id,)).fetchall()
    assert audit and all(made["link_id"] not in str(dict(r)) for r in audit)
