"""T020: a link shows exactly the fields the sender opted in, and nothing else."""

import json
import zipfile
import io

import pytest

from consentvault import share
from consentvault.evidence import _open_contact_key

from export.support import OTHER_PHONE, PHONE

from .conftest import admin, get, mint_link, text_of

EVENT_URL = "https://alpha.example.com/signup"


def test_defaults():
    assert share.FLAG_DEFAULTS == {"show_org_name": True, "show_contact": False, "allow_contact_match": True,
                                   "show_page_url": False, "show_bot_check": False}


def test_a_link_made_with_no_flags_carries_the_defaults(record):
    assert mint_link(record)["flags"] == share.FLAG_DEFAULTS


def test_showing_the_contact_needs_the_typed_acknowledgement(record):
    with pytest.raises(share.AckRequired):
        mint_link(record, flags={"show_contact": True})
    with pytest.raises(share.AckRequired):
        mint_link(record, flags={"show_contact": True}, ack="yes")
    assert mint_link(record, flags={"show_contact": True}, ack=share.CONTACT_ACK)["flags"]["show_contact"] is True


def test_an_unknown_flag_is_refused(record):
    with pytest.raises(share.ShareError):
        mint_link(record, flags={"show_everything": True})


def _private(t):
    with admin(t) as app:
        _, salt = _open_contact_key(app, t.crypto, t.a.org_id, t.crypto.contact_fingerprint(t.a.org_id, "phone", PHONE))
    others = [str(e) for e in t.a.event_ids[1:]]
    return {"the phone number": PHONE, "its digits": "5555550142", "the other contact": OTHER_PHONE, "the click id": "CANARYCLICKID",
            "the address": "203.0.113.7", "the browser": "Mozilla/5.0 test", "the session": "s-alpha", "the posted session": "s-canary",
            "the salt": salt, **{f"another event {i}": e for i, e in enumerate(others)}}


def _everything_public(routes, link_id):
    """Every byte a stranger can pull from one link: the page, the JSON and every file inside the one-record file."""
    parts = [text_of(get(routes, link_id)), text_of(get(routes, link_id, ".json"))]
    zipped = get(routes, link_id, "/record.zip")
    assert zipped.status == 200
    with zipfile.ZipFile(io.BytesIO(zipped.raw)) as zf:
        parts += [zf.read(n).decode("utf-8", "replace") for n in zf.namelist()]
    return "\n".join(parts)


def test_a_page_with_every_flag_off_carries_none_of_the_private_fields(record, routes):
    made = mint_link(record, flags={k: False for k in share.FLAG_DEFAULTS})
    everything = _everything_public(routes, made["link_id"])
    for what, canary in _private(record).items():
        assert canary not in everything, f"{what} reached a public byte"
    assert "Seller" not in text_of(get(routes, made["link_id"]))


def test_each_flag_shows_only_what_it_names(record, routes):
    t = record
    off = {k: False for k in share.FLAG_DEFAULTS}
    contact = mint_link(t, flags={**off, "show_contact": True}, ack=share.CONTACT_ACK)["link_id"]
    page = mint_link(t, flags={**off, "show_page_url": True})["link_id"]
    org = mint_link(t, flags={**off, "show_org_name": True})["link_id"]
    shown_contact, shown_page, shown_org = (_everything_public(routes, i) for i in (contact, page, org))
    assert PHONE in shown_contact and "CANARYCLICKID" not in shown_contact
    assert EVENT_URL in shown_page and PHONE not in shown_page and "CANARYCLICKID" not in shown_page
    assert "alpha" in text_of(get(routes, org)) and "Seller" in text_of(get(routes, org))
    assert PHONE not in shown_org and "CANARYCLICKID" not in shown_org
    for shown in (shown_contact, shown_page, shown_org):
        for what in ("203.0.113.7", "Mozilla/5.0 test", "s-alpha", "s-canary"):
            assert what not in shown


def test_the_json_carries_the_same_fields_as_the_page(record, routes):
    made = mint_link(record)
    doc = json.loads(get(routes, made["link_id"], ".json").raw)
    assert doc["flags"] == share.FLAG_DEFAULTS
    assert doc["contact"] is None and doc["page_url"] is None
