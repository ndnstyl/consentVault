"""records.md section 9 (core change P1, capture.md amendment): display is split off before anything is hashed."""

import json

import pytest

from consentvault.tenancy import crypto as tc
from consentvault.tenancy.keys_protocol import WrappedKey

from contract_world.world import need

X = "+15555550177"


def _unb64(text):
    """body_b64 is unpadded base64url (restore.py reads it the same way)."""
    import base64
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parse(payload, body=None, scopes=("capture",)):
    from consentvault.tenancy.pipeline import parse_capture
    body = json.dumps(payload).encode() if body is None else body
    return parse_capture(payload, body, scopes)


BASE = {"contact": X, "event_type": "grant", "channels": ["sms"], "purposes": ["marketing"], "checked": True,
        "disclosure_sha256": "a" * 64, "brand_ids": ["00000000-0000-4000-8000-0000000000b1"]}


def test_parse_capture_removes_display_before_the_unknown_field_check():
    """records.md section 9 (P1: display removed before the unknown-field check, returned as CaptureRequest.display)."""
    req = parse({**BASE, "display": {"name": "Dana", "company": "Cruz"}})
    assert "display" not in req.fields and getattr(req, "display", None) == {"name": "Dana", "company": "Cruz"}


def test_with_display_the_body_is_the_canonical_json_of_the_rest():
    """records.md section 9 (canonical bytes: sort_keys, compact separators, ensure_ascii False, UTF-8)."""
    payload = {"purposes": ["marketing"], "event_type": "grant", "contact": X, "channels": ["sms"], "checked": True,
               "disclosure_sha256": "a" * 64, "brand_ids": BASE["brand_ids"],
               "page_url": "https://example.test/é", "display": {"name": "Dana"}}
    rest = {k: v for k, v in payload.items() if k != "display"}
    want = json.dumps(rest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert parse(payload, body=b' {"received":  "bytes"} ').body == want


def test_without_display_the_received_bytes_are_kept_byte_for_byte():
    """records.md section 9 (display absent: CaptureRequest.body is the received bytes, unchanged)."""
    received = b'{ "contact" : "+15555550177",  "event_type":"grant","channels":["sms"],"purposes":["marketing"],"checked":true,"disclosure_sha256":"%s","brand_ids":["00000000-0000-4000-8000-0000000000b1"]}' % (b"a" * 64)
    req = parse(json.loads(received), body=received)
    assert req.body == received and hasattr(req, "display") and req.display is None


@pytest.mark.parametrize("bad", [{"age": 40}, {"name": "x", "age": 4}, {"name": ""}, {"name": "n" * 201}, {"company": "c" * 201},
                                 {"name": 5}, "Dana", ["Dana"], {}])
def test_display_is_an_object_of_name_and_company_strings_of_1_to_200_characters(bad):
    """records.md section 9 and capture.md (any other key, empty, too long or non-string is validation_failed fields.display)."""
    assert parse({**BASE, "display": {"name": "Dana"}}).display == {"name": "Dana"}  # the good shape is accepted first
    with pytest.raises(Exception) as e:
        parse({**BASE, "display": bad})
    assert getattr(e.value, "name", None) == "validation_failed" and "display" in e.value.fields


def test_display_at_the_limits_is_accepted():
    """records.md section 9 (1 to 200 characters each)."""
    assert parse({**BASE, "display": {"name": "n", "company": "c" * 200}}).display == {"name": "n", "company": "c" * 200}


@pytest.fixture
def cloud(tenancy, tmp_path):
    from isolation.cloud_harness import Cloud
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def evidence(cloud, event_id):
    with cloud.t.superuser() as su:
        obj = su.execute("SELECT * FROM consentvault.evidence_object WHERE event_id = %s", (event_id,)).fetchone()
        k = su.execute("SELECT wrapped_key, key_version FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                       (obj["org_id"], obj["contact_fp"])).fetchone()
    blob = cloud.store.get(str(obj["org_id"]), obj["object_key"])
    dk = cloud.t.crypto.open_contact_key(obj["org_id"], WrappedKey(bytes(k["wrapped_key"]), k["key_version"]))
    return json.loads(tc.decrypt_field(dk, obj["org_id"], str(obj["object_id"]), "evidence_object", blob))


def test_a_capture_with_display_stores_no_name_in_the_event_the_evidence_or_the_chain(cloud):
    """records.md section 9 and capture.md (never in the event, the evidence object or the chain; body_b64 is canonical)."""
    import base64
    s, r = cloud.grant(cloud.a, X, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    assert s == 201, r
    ev = evidence(cloud, r["event_id"])
    assert "display" not in json.dumps(ev) and "Dana" not in json.dumps(ev) and "Cruz" not in json.dumps(ev)
    stored = _unb64(ev["body_b64"])
    assert "display" not in json.loads(stored)
    assert stored == json.dumps(json.loads(stored), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with cloud.t.superuser() as su:
        row = su.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (r["event_id"],)).fetchone()
        shown = su.execute("SELECT name_ct FROM consentvault.record_display WHERE org_id = %s", (cloud.a.org.org_id,)).fetchall()
    assert len(shown) == 1  # the name is held, in the display table only, so its absence from the event is meaningful
    flat = b"".join(bytes(v) for v in row.values() if isinstance(v, (bytes, memoryview))) + str({k: v for k, v in row.items()}).encode()
    assert b"Dana" not in flat and b"Cruz" not in flat


def test_a_capture_with_a_bad_display_is_stored_whole_and_makes_no_event(cloud):
    """A display that is not {name, company} is a reason the transitional event is not made (a fact), never a refusal:
    the post, with the display exactly as sent, is stored."""
    def tally():
        with cloud.t.superuser() as su:
            return su.execute("SELECT (SELECT count(*) FROM consentvault.event WHERE org_id = %s) AS e,"
                              " (SELECT count(*) FROM consentvault.evidence_object WHERE org_id = %s) AS o,"
                              " (SELECT count(*) FROM consentvault.raw_post WHERE org_id = %s) AS p",
                              (cloud.a.org.org_id,) * 3).fetchone()
    from isolation.cloud_harness import facts_of, post_body, raw_posts
    before = tally()
    s, r = cloud.grant(cloud.a, X, display={"name": "Dana", "age": 40})
    assert s == 201 and r["stored"] is True
    after = tally()
    assert (after["e"], after["o"], after["p"]) == (before["e"], before["o"], before["p"] + 1)  # a post, no event, no evidence object
    post = raw_posts(cloud.t, cloud.a.org.org_id)[-1]
    assert json.loads(post_body(cloud.t, post))["display"] == {"name": "Dana", "age": 40}
    assert facts_of(cloud.t, post)["event_not_derived"] == "validation_failed"
    s2, r2 = cloud.grant(cloud.a, X, display={"name": "Dana"})
    assert s2 == 201 and tally()["e"] == before["e"] + 1


def test_a_capture_without_display_stores_the_received_bytes(cloud):
    """records.md section 9 (display absent: today's behaviour, received bytes stored as body_b64)."""
    import base64
    s, r = cloud.grant(cloud.a, X)
    assert s == 201
    stored = _unb64(evidence(cloud, r["event_id"])["body_b64"])
    assert json.loads(stored)["contact"] == X
    s, r = cloud.grant(cloud.a, "+15555550178", display={"name": "N"})
    assert s == 201 and "display" not in _unb64(evidence(cloud, r["event_id"])["body_b64"]).decode()


def test_a_capture_with_display_writes_the_display_row_under_the_display_key(cloud, tenancy):
    """capture.md amendment (written to record_display under the display key)."""
    s, r = cloud.grant(cloud.a, X, display={"name": "Dana Cruz", "company": "Cruz Tile"})
    assert s == 201
    with cloud.t.superuser() as su:
        rows = su.execute("SELECT * FROM consentvault.record_display WHERE org_id = %s", (cloud.a.org.org_id,)).fetchall()
    assert len(rows) == 1 and b"Dana" not in bytes(rows[0]["name_ct"])


def test_every_event_updates_the_records_tables_in_the_same_transaction(cloud):
    """capture.md amendment and records.md section 9 (R1: record and index written beside the event)."""
    def tally():
        with cloud.t.superuser() as su:
            return su.execute("SELECT (SELECT count(*) FROM consentvault.record WHERE org_id = %s) AS r,"
                              " (SELECT count(*) FROM consentvault.record_index WHERE org_id = %s) AS i",
                              (cloud.a.org.org_id, cloud.a.org.org_id)).fetchone()
    before = tally()
    s, r = cloud.grant(cloud.a, X)
    assert s == 201
    after = tally()
    assert (after["r"] - before["r"], after["i"] - before["i"]) == (1, 1)


def test_a_records_failure_leaves_the_post_stored_and_no_event(cloud):
    """A failure writing the records list refuses the transitional event as a whole (nothing of the event written); the
    post itself is already stored and the sender was told so."""
    with cloud.t.superuser() as su:
        su.execute("CREATE FUNCTION public.cvt_fail2() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'records down (test)'; END $$")
        su.execute("CREATE TRIGGER cvt_fail2 BEFORE INSERT ON consentvault.record FOR EACH ROW EXECUTE FUNCTION public.cvt_fail2()")
    try:
        s, r = cloud.grant(cloud.a, X)
        assert s == 201 and r["stored"] is True
        with cloud.t.superuser() as su:
            assert su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND session_ref = 's-1'",
                              (cloud.a.org.org_id,)).fetchone()["n"] == 0
            assert su.execute("SELECT count(*) AS n FROM consentvault.raw_post WHERE org_id = %s", (cloud.a.org.org_id,)).fetchone()["n"] == 1
    finally:
        with cloud.t.superuser() as su:
            su.execute("DROP TRIGGER cvt_fail2 ON consentvault.record")
            su.execute("DROP FUNCTION public.cvt_fail2()")
