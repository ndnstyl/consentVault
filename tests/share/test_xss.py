"""T029: every string a visitor controlled renders as escaped text; a certificate value is a link only for the exact issuer pattern."""

import re

import pytest

from consentvault import share

from .conftest import CERT_URL, attach_post, get, mint_link, text_of

NASTY = "<script>alert(1)</script><img src=x onerror=alert(2)>\"'`&amp;\x01\x07‮"


@pytest.fixture
def nasty(record, tmp_path):
    t = record
    attach_post(t, tmp_path, t.a.event_ids[2], disclosure_text=NASTY, page_url=NASTY,
                third_party=[{"name": "xxTrustedFormCertUrl", "value": NASTY}, {"name": "universal_leadid", "value": "javascript:alert(3)"}])
    return t


def _page(nasty, routes, **flags):
    made = mint_link(nasty, event_id=nasty.a.event_ids[2], flags=flags, note=NASTY)
    return text_of(get(routes, made["link_id"])), made


def test_nothing_visitor_controlled_reaches_the_page_unescaped(nasty, routes):
    page, _ = _page(nasty, routes, show_page_url=True)
    assert "<script>alert" not in page and "<img src=x" not in page and "onerror=alert" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "\x01" not in page and "\x07" not in page and "‮" not in page
    assert len(re.findall(r"<script\b", page)) == 1  # only the one recompute script of ours


def test_the_private_note_is_never_public(nasty, routes):
    page, made = _page(nasty, routes)
    assert "alert(1)" not in page
    assert "alert(1)" not in text_of(get(routes, made["link_id"], ".json"))


def test_a_certificate_value_is_a_link_only_for_the_exact_pattern(record, tmp_path, routes):
    t = record
    page = text_of(get(routes, mint_link(t)["link_id"]))
    assert f'<a href="{CERT_URL}"' in page and 'rel="noreferrer noopener"' in page


def test_other_certificate_values_are_plain_text(nasty, routes):
    page, _ = _page(nasty, routes)
    assert 'href="javascript' not in page and "<a href=\"&lt;" not in page
    assert "javascript:alert(3)" in page
    for value in ("https://cert.trustedform.com/ABC", "http://cert.trustedform.com/" + "a" * 40,
                  "https://cert.trustedform.com.evil.example/" + "a" * 40, "https://cert.trustedform.com/" + "a" * 40 + "/x"):
        assert share.certificate_link(value) is None
    assert share.certificate_link("https://cert.trustedform.com/" + "a" * 40) == "https://cert.trustedform.com/" + "a" * 40


def test_the_csp_lists_only_hashes_of_our_own_style_and_script(record, routes):
    made = mint_link(record)
    csp = get(routes, made["link_id"]).headers["Content-Security-Policy"]
    assert csp.startswith("default-src 'none'") and "frame-ancestors 'none'" in csp
    assert re.search(r"script-src 'sha256-[A-Za-z0-9+/=]+'", csp) and re.search(r"style-src 'sha256-[A-Za-z0-9+/=]+'", csp)
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
