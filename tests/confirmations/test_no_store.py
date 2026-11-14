"""confirmations.md section 8, ruled 2026-10-31: confirmation reads carry Cache-Control: no-store and Pragma: no-cache."""

from contract_world.confirm import PHONE as CPHONE

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def held(r, what):
    got = {k: r.headers.get(k) for k in NO_STORE}
    assert got == NO_STORE, (what, got)


def test_confirmation_replies_and_sends_forbid_caching(world, stack, armed):
    from contract_world.confirm import text_in
    o = world.a
    world.capture(o, CPHONE)
    stack.run()
    text_in(armed, "hello there")
    for path in ("/v1/confirmations/replies", "/v1/confirmations/sends", "/v1/confirmations/rules",
                 "/v1/confirmations/settings", "/v1/confirmations/templates"):
        for who in (o.boss, o.viewer):
            r = who.call("GET", path)
            assert r.status == 200, (path, r.status)
            held(r, path)
