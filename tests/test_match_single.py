"""A single-company vault links a person's posts exactly as the cloud path does: it has its own fingerprint secret, made once on
first use or taken from a setting, and a missing secret raises the link-failed alarm, never a silent skip (ruling 5)."""

import hashlib
import hmac

import pytest

from consentvault import api, match
from test_api import PURPOSES, SECRET, TOKEN, VERIFIED_SECRET, _post, _serve


def settings(app_dsn):
    return api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES,
                           verified_secret=VERIFIED_SECRET, default_region="US")  # gitleaks:allow (test constant)


@pytest.fixture
def server(dsn, app_dsn):
    match._single_cache.clear()
    yield from _serve(settings(app_dsn))


def widget(contact, checked, when):
    return {"contact": contact, "checked": checked, "decided_at": when}


def rows(conn):
    return conn.execute("SELECT * FROM consentvault.raw_post_match ORDER BY matched_at, match_id").fetchall()


def test_the_secret_is_made_once_and_the_same_person_links_across_posts(server, conn):
    _post(server, widget("Pat@Example.com", True, "2026-10-02T14:03:11-04:00"))
    _post(server, widget("pat@example.com", False, "2026-10-03T14:03:11-04:00"))
    first, second = rows(conn)
    assert first["status"] == second["status"] == "matched" and first["contact_fp"] == second["contact_fp"]
    assert second["previous_post_id"] == first["post_id"] and second["changed"] is True
    assert conn.execute("SELECT count(*) AS n FROM consentvault.single_fingerprint_secret").fetchone()["n"] == 1
    assert conn.execute("SELECT count(*) AS n FROM consentvault.raw_post_fact WHERE name = 'link_skipped'").fetchone()["n"] == 0


def test_a_secret_from_the_setting_is_used_instead_of_a_made_one(dsn, app_dsn, conn, monkeypatch):
    monkeypatch.setenv(match.ENV_FINGERPRINT_SECRET, "ab" * 32)
    match._single_cache.clear()
    for s in _serve(settings(app_dsn)):
        _post(s, widget("a@b.com", True, "2026-10-02T14:03:11-04:00"))
    [row] = rows(conn)
    msg = b"\x00".join((b"consentvault/contact-fp/v1", b"email", b"a@b.com"))
    assert row["contact_fp"] == hmac.new(bytes.fromhex("ab" * 32), msg, hashlib.sha256).hexdigest()


def test_a_missing_secret_raises_the_link_failed_alarm_and_the_post_stays(server, conn, monkeypatch):
    def none(*a, **k):
        raise match.LinkError("simulated: no fingerprint secret")
    monkeypatch.setattr(match, "single_secret", none)
    _post(server, widget("a@b.com", True, "2026-10-02T14:03:11-04:00"))
    assert conn.execute("SELECT count(*) AS n FROM consentvault.raw_post").fetchone()["n"] == 1 and rows(conn) == []
    assert conn.execute("SELECT count(*) AS n FROM consentvault.operator_alarm WHERE name = 'capture.link_failed'").fetchone()["n"] == 1
