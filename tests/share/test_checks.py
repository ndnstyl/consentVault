"""T026: each recomputation shows its input, its output and whether it equals the stored value; a change breaks exactly the checks
it touches; no string on the page carries a verdict word."""

import copy
import hashlib
import json
import re

from consentvault import share, share_render
from consentvault.tenancy.tokens import org_transaction

from .conftest import BANNED, admin, mint_link, text_of, get


def _material_and_view(t, flags=None):
    made = mint_link(t, flags=flags or {})
    with admin(t) as app:
        material = share.preview_material(app, event_id=t.a.event_ids[0], flags=made["flags"])
    return material, share.build_view(material, t.crypto)


def _by_name(view):
    return {c["name"]: c for c in view["checks"]}


def test_every_check_with_a_stored_value_shows_input_output_and_equal(record):
    _, view = _material_and_view(record)
    checks = _by_name(view)
    assert {"content hash", "row hash", "seal digest", "seal signing time", "wording hash", "raw post row hash",
            "raw post seal digest"} <= set(checks)
    for name, c in checks.items():
        assert c["input"] and c["output"], name
        if name != "content hash":
            assert c["equal"] is True and c["stored"], name
    assert checks["content hash"]["equal"] is None and "feeds the row hash" in checks["content hash"]["stored_note"]
    assert checks["row hash"]["output"] == view["event"]["row_hash"]
    assert checks["content hash"]["output"] == hashlib.sha256(checks["content hash"]["input"].encode()).hexdigest()


def test_one_byte_in_the_wording_breaks_the_wording_check_and_only_it(record):
    material, _ = _material_and_view(record)
    bad = copy.deepcopy(material)
    body = bad["disclosure"]["body"]
    bad["disclosure"]["body"] = body[:-1] + chr(ord(body[-1]) ^ 1)
    checks = _by_name(share.build_view(bad, record.crypto))
    assert [n for n, c in checks.items() if c["equal"] is False] == ["wording hash"]


def test_a_changed_sealed_column_breaks_the_row_hash_and_the_seal_digest_and_nothing_else(record):
    material, _ = _material_and_view(record)
    bad = copy.deepcopy(material)
    bad["event"]["source"] = (bad["event"].get("source") or "") + "x"
    checks = _by_name(share.build_view(bad, record.crypto))
    assert sorted(n for n, c in checks.items() if c["equal"] is False) == ["row hash", "seal digest"]


def test_a_changed_signing_time_breaks_only_the_time_check(record):
    material, _ = _material_and_view(record)
    bad = copy.deepcopy(material)
    bad["seals"][0]["gen_time"] = "2000-01-01T00:00:00.000000Z"
    checks = _by_name(share.build_view(bad, record.crypto))
    assert [n for n, c in checks.items() if c["equal"] is False] == ["seal signing time"]


def test_a_withheld_bot_check_column_is_named_not_guessed(record):
    material, _ = _material_and_view(record)
    withheld = copy.deepcopy(material)
    withheld["event"]["bot_check"] = "turnstile:pass"
    withheld["flags"]["show_bot_check"] = False
    view = share.build_view(withheld, record.crypto)
    checks = _by_name(view)
    assert view["event"]["bot_check"] is None and view["withheld"] == ["bot_check"]
    for name in ("content hash", "row hash", "seal digest"):
        assert checks[name]["equal"] is None and "withholds the bot-check column" in checks[name]["stored_note"]


def test_the_page_names_the_code_and_rule_set_beside_every_derived_line(record):
    _, view = _material_and_view(record)
    html = share_render.render_page(view).html.decode()
    assert html.count(share.CODE_VERSION) >= 1 and share.RULE_SET in html
    assert "This page shows one record and the time it was sealed. It does not show what happened to this contact afterward." in html
    assert "This page recomputes checks on the stored record. It is not an opinion about the record." in html


def test_no_string_on_the_page_carries_a_verdict_word(record, routes):
    made = mint_link(record)
    page = text_of(get(routes, made["link_id"]))
    body = re.sub(r"<script.*?</script>|<style.*?</style>", " ", page, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", body)
    for pattern in BANNED:
        assert not re.search(pattern, text, re.I), (pattern, re.search(pattern, text, re.I).group())
