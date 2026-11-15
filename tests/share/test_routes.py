"""The sender's routes: admin only, the link returned once, the preview equal to the public page byte for byte."""

import json

import pytest

from consentvault import share_routes
from consentvault.route_wiring import PortalPrincipal

from .conftest import PUBLIC, get, mint_link


class _Auth:
    def __init__(self, t, org, role="admin"):
        self.t, self.org, self.role = t, org, role

    def portal(self, headers):
        if headers.get("x-anonymous"):
            return None
        return PortalPrincipal(self.org.org_id, "00000000-0000-0000-0000-000000000009", self.role, ("admin",),
                               self.t.token(self.org, ("admin",)))


@pytest.fixture
def admin_routes(record):
    from consentvault import db

    return share_routes.RecordLinkRoutes(lambda: db.connect(record.app_dsn), record.crypto, _Auth(record, record.a),
                                         public_host="verify.example.com")


def _post(r, path, doc, headers=None):
    return r.handle("POST", path, body=json.dumps(doc).encode(), headers=headers or {}, query={})


def test_create_returns_the_link_once_and_the_list_never_shows_it(admin_routes, record, routes):
    made = _post(admin_routes, "/v1/record-links", {"event_id": str(record.a.event_ids[0]), "show_org_name": True, "note": "for the buyer"})
    assert made.status == 201 and made.payload["link"].startswith("https://verify.example.com/p/cvp_")
    link_id = made.payload["link"].rsplit("/", 1)[1]
    assert get(routes, link_id).status == 200
    listed = admin_routes.handle("GET", "/v1/record-links", headers={}, query={"limit": "10"})
    assert listed.status == 200 and listed.payload["next_cursor"] is None
    item = listed.payload["items"][0]
    assert item["share_id"] == made.payload["share_id"] and item["view_count"] == 1 and item["note"] == "for the buyer"
    assert link_id not in json.dumps(listed.payload) and item["withdrawn_at"] is None


def test_the_preview_is_the_public_page_byte_for_byte(admin_routes, record, routes):
    for flags in ({}, {"show_org_name": False}, {"show_contact": True, "show_page_url": True}):
        body = {"event_id": str(record.a.event_ids[0]), **flags}
        if flags.get("show_contact"):
            body["contact_ack"] = share_routes.share.CONTACT_ACK
        preview = _post(admin_routes, "/v1/record-links/preview", body)
        made = _post(admin_routes, "/v1/record-links", body)
        page = get(routes, made.payload["link"].rsplit("/", 1)[1])
        assert preview.status == 200 and preview.raw == page.raw
        assert preview.headers["Content-Security-Policy"] == page.headers["Content-Security-Policy"]


def test_a_preview_writes_nothing(admin_routes, record):
    _post(admin_routes, "/v1/record-links/preview", {"event_id": str(record.a.event_ids[0])})
    with record.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.proof_share").fetchone()["n"] == 0


def test_the_contact_acknowledgement_is_required_to_create(admin_routes, record):
    r = _post(admin_routes, "/v1/record-links", {"event_id": str(record.a.event_ids[0]), "show_contact": True})
    assert r.status == 422 and r.payload["fields"] == {"contact_ack": "required"}


def test_withdraw_and_reset_by_route(admin_routes, record, routes):
    made = _post(admin_routes, "/v1/record-links", {"event_id": str(record.a.event_ids[0])})
    sid, link_id = made.payload["share_id"], made.payload["link"].rsplit("/", 1)[1]
    assert _post(admin_routes, f"/v1/record-links/{sid}/reset-match", {}).payload["reset"] is True
    assert _post(admin_routes, f"/v1/record-links/{sid}/revoke", {}).payload["revoked"] is True
    assert get(routes, link_id).status == 410
    items = admin_routes.handle("GET", "/v1/record-links", headers={}, query={}).payload["items"]
    assert items[0]["withdrawn_at"]


def test_only_an_admin_with_a_session(record):
    from consentvault import db

    no_session = share_routes.RecordLinkRoutes(lambda: db.connect(record.app_dsn), record.crypto, _Auth(record, record.a), public_host="v.example.com")
    assert no_session.handle("GET", "/v1/record-links", headers={"x-anonymous": "1"}, query={}).status == 401
    viewer = share_routes.RecordLinkRoutes(lambda: db.connect(record.app_dsn), record.crypto, _Auth(record, record.a, "compliance_viewer"),
                                           public_host="v.example.com")
    assert viewer.handle("GET", "/v1/record-links", headers={}, query={}).status == 403


def test_an_unknown_record_and_an_unknown_link_are_404(admin_routes, record):
    assert _post(admin_routes, "/v1/record-links", {"event_id": str(record.b.event_ids[0])}).status == 404
    assert _post(admin_routes, "/v1/record-links/00000000-0000-0000-0000-000000000001/revoke", {}).status == 404


def test_a_public_request_for_anything_else_is_the_one_fixed_answer(routes):
    fixed = None
    for method, path in (("GET", f"{PUBLIC}/not-an-id"), ("GET", f"{PUBLIC}/cvp_" + "z" * 26), ("GET", f"{PUBLIC}/cvp_" + "b" * 26),
                         ("POST", f"{PUBLIC}/cvp_" + "b" * 26), ("GET", f"{PUBLIC}/cvp_" + "b" * 26 + "/other"), ("DELETE", f"{PUBLIC}/cvp_" + "b" * 26)):
        r = routes.handle(method, path, body=b"{}", headers={})
        assert r.status == 404
        fixed = fixed or r.raw
        assert r.raw == fixed


def test_the_settings_for_turning_record_links_on():
    assert share_routes.public_settings({}) is None
    assert share_routes.public_settings({"CONSENTVAULT_PUBLIC_VERIFY_DSN": "postgresql://x"}) == ("postgresql://x", "verify.consentvault.ai")
    from consentvault.errors import ConfigError

    with pytest.raises(ConfigError):
        share_routes.public_settings({"CONSENTVAULT_PUBLIC_VERIFY_HOST": "verify.consentvault.ai"})
    with pytest.raises(ConfigError):
        share_routes.public_settings({"CONSENTVAULT_PUBLIC_VERIFY_DSN": "postgresql://x", "CONSENTVAULT_PUBLIC_VERIFY_HOST": "bad host"})
