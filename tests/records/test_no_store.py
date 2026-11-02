"""records.md section 1 and confirmations.md section 8, ruled 2026-10-31: every /v1 admin response carries Cache-Control: no-store
and Pragma: no-cache, so names, masks and contact points never sit in a browser or proxy cache."""

import pytest

from contract_world import exports as ex
from contract_world.world import EMAIL, PHONE

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def held(r, what):
    got = {k: r.headers.get(k) for k in NO_STORE}
    assert got == NO_STORE, (what, got)


def test_records_list_summary_search_reveal_and_export_routes_forbid_caching(world):
    o = world.a
    world.capture(o, PHONE, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    rid = world.record_id(o, PHONE)
    for method, path, query, body in (
            ("GET", "/v1/records", {}, None),
            ("GET", "/v1/records/summary", {}, None),
            ("POST", "/v1/records:search", None, {"contact": PHONE}),
            ("POST", "/v1/records:reveal", None, {"record_ids": [rid]}),
            ("POST", "/v1/records/exports", None, {"contact_form": "masked"}),
            ("GET", "/v1/records/exports", {}, None)):
        r = o.boss.call(method, path, query, body)
        assert r.status < 300, (path, r.status, r.body)
        held(r, path)
    export = ex.start(o.boss)
    ex.wait_ready(o.boss, export["export_id"])
    link = o.boss.call("POST", f"/v1/records/exports/{export['export_id']}:link")
    held(link, "export link")
    held(o.boss.call("GET", f"/v1/records/exports/{export['export_id']}"), "export detail")
    held(ex.download(world, o.boss, link.body["download_url"]), "export download")


def test_refusals_forbid_caching_too(world):
    o = world.a
    held(o.boss.call("POST", "/v1/records:search", body={"contact": "nope"}), "invalid_contact")
    held(o.boss.call("GET", "/v1/records", {"sort": "bogus"}), "validation_failed")
    held(o.dev.call("POST", "/v1/records:reveal", body={"record_ids": []}), "role_not_allowed")
    held(o.boss.call("GET", "/v1/no-such-route"), "not_found")


def test_every_role_and_org_get_the_headers_on_the_name_lookups(world):
    for who in world.a.people.values():
        for path in ("/v1/brand-names", "/v1/source-names", "/v1/org", "/v1/health"):
            held(who.call("GET", path), path)
