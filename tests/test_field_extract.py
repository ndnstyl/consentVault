"""The tokenising reader and the readings it makes: values copied as written, every occurrence, nothing filled
(tasks T060, T063, T070, T071)."""

import json
import os
import time

import pytest

from consentvault import extract
from consentvault.extract import (EVENTS_API_MAP, FieldMap, MANY, NOT_SENT, SENT, UNMAPPED, UNREADABLE, WIDGET_MAP, Reading,
                                  form_occurrences, json_occurrences, multipart_occurrences, read_fields, values_json)


def one(body, pointer):
    return json_occurrences(body, [pointer])[pointer]


@pytest.mark.parametrize("body,expected", [
    (b'{"checked": true}', [b"true"]), (b'{"checked":false}', [b"false"]), (b'{ "checked" :  "on" }', [b'"on"']),
    (b'{"checked": 1}', [b"1"]), (b'{"checked": null}', [b"null"]), (b'{"checked": "true"}', [b'"true"']),
    (b'{"checked": ""}', [b'""']), (b'{"checked": "\\u006fn"}', [b'"\\u006fn"']), (b'{"checked": [true, false]}', [b"[true, false]"]),
    (b'{"checked": {"a": 1}}', [b'{"a": 1}']), (b'{"other": 1}', []), (b"{}", []), (b'{"checked": 1.50e+2}', [b"1.50e+2"]),
])
def test_json_values_are_copied_as_the_token_was_written(body, expected):
    assert one(body, "/checked") == expected


def test_a_repeated_key_gives_every_occurrence_in_byte_order():
    assert one(b'{"checked": true, "x": 1, "checked": false, "checked": "on"}', "/checked") == [b"true", b"false", b'"on"']


def test_nested_paths_and_array_indices_and_escaped_pointer_tokens():
    body = b'{"form": {"box": {"state": "on"}, "list": [{"v": 1}, {"v": 2}]}, "a/b": 7, "m~n": 8, "": 9}'
    got = json_occurrences(body, ["/form/box/state", "/form/list/1/v", "/a~1b", "/m~0n", "/"])
    assert got == {"/form/box/state": [b'"on"'], "/form/list/1/v": [b"2"], "/a~1b": [b"7"], "/m~0n": [b"8"], "/": [b"9"]}


def test_a_key_written_with_escapes_matches_its_decoded_name():
    assert one(b'{"che\\u0063ked": true}', "/checked") == [b"true"]


def test_the_whole_value_of_a_container_is_the_exact_span():
    assert one(b'{"a": {"b": [1, {"c": "}"}]}, "z": 0}', "/a") == [b'{"b": [1, {"c": "}"}]}']


@pytest.mark.parametrize("body", [b"", b"not json", b'{"a": }', b'{"a": 1', b'{"a" 1}', b'{"a": 1}{"b": 2}', b'["a": 1]', b"{'a': 1}",
                                  b'{"a": tru}', b'{"a": "unterminated}', b"\xff\xfe\x00"])
def test_a_body_that_is_not_json_is_unreadable(body):
    with pytest.raises(extract.Unreadable):
        json_occurrences(body, ["/a"])


def test_a_byte_order_mark_is_skipped_and_the_value_is_still_exact():
    assert one(b'\xef\xbb\xbf{"checked": false}', "/checked") == [b"false"]


def test_invalid_utf8_inside_a_string_value_is_copied_whole():
    assert one(b'{"checked": "\xff\xfe"}', "/checked") == [b'"\xff\xfe"']


def test_very_deep_nesting_does_not_crash_the_reader():
    deep = b"[" * 5000 + b"]" * 5000
    assert json_occurrences(deep, ["/0"])["/0"] == [deep[1:-1]]  # skipped without recursion
    with pytest.raises(extract.Unreadable):
        json_occurrences(deep, ["/" + "/".join(["0"] * 1000)])  # followed all the way down: past the reader's depth


def test_a_field_deep_inside_a_fifty_mebibyte_body_is_found():
    filler = b'{"k": "' + b"x" * 1000 + b'"},'
    body = b'{"junk": [' + filler * (50 * 1024) + b'{}], "form": {"checked": false}}'
    assert len(body) > 50 * 1000 * 1000
    started = time.monotonic()
    assert one(body, "/form/checked") == [b"false"]
    assert time.monotonic() - started < 60


def test_form_bodies_keep_repeated_names_and_the_encoded_value():
    body = b"contact=a%40b.com&checked=on&checked=&flag&n%61me=x+y"
    got = form_occurrences(body, ["checked", "flag", "name", "absent"])
    assert got == {"checked": [b"on", b""], "flag": [b""], "name": [b"x+y"], "absent": []}


def test_multipart_parts_by_name():
    body = (b'--B\r\nContent-Disposition: form-data; name="checked"\r\n\r\non\r\n'
            b'--B\r\nContent-Disposition: form-data; name="note"\r\n\r\nhello\r\nworld\r\n--B--\r\n')
    assert multipart_occurrences(body, "multipart/form-data; boundary=B", ["checked", "note", "x"]) == \
        {"checked": [b"on"], "note": [b"hello\r\nworld"], "x": []}
    with pytest.raises(extract.Unreadable):
        multipart_occurrences(body, "multipart/form-data", ["checked"])


# readings ---------------------------------------------------------------------------------------------------------------

def readings(body, fmap=WIDGET_MAP, content_type="application/json"):
    return {r.field: r for r in read_fields(body, content_type, fmap)}


def test_box_true_false_on_absent_and_an_unmapped_form():
    assert readings(b'{"checked": true}')["consent"] == Reading("consent", SENT, (b"true",))
    assert readings(b'{"checked": false}')["consent"].values == (b"false",)
    assert readings(b'{"checked": "on"}')["consent"].values == (b'"on"',)
    absent = readings(b'{"contact": "a@b.com"}')["consent"]
    assert (absent.state, absent.values) == (NOT_SENT, ())
    assert [(r.field, r.state) for r in read_fields(b"{}", None, None)] == [("consent", UNMAPPED)]
    assert readings(b'{"checked": true, "checked": false}')["consent"].state == MANY


def test_the_box_value_is_never_rewritten_or_ranked():
    for sent in (b"true", b"false", b'"on"', b'"yes"', b"0", b"null", b'"false"'):
        assert readings(b'{"checked": ' + sent + b"}")["consent"].values == (sent,)


def test_a_form_with_its_own_map_reads_its_own_paths_and_form_encoding():
    fmap = FieldMap(body_format="form_urlencoded", consent_paths=("agree",), decision_time_path="when", wording_path="words",
                    contact_paths=(("email", "email"),))
    r = readings(b"email=a%40b.com&agree=on&when=2026-10-20+09%3A12&words=I+agree", fmap)
    assert r["consent"].values == (b"on",) and r["decision_time"].values == (b"2026-10-20+09%3A12",)
    assert r["wording"].values == (b"I+agree",) and r["contact"].values == (b"a%40b.com",)


def test_an_unreadable_body_reads_body_unreadable_for_each_mapped_field():
    r = readings(b"{ broken")
    assert {f: x.state for f, x in r.items()} == {"consent": UNREADABLE, "decision_time": UNREADABLE, "wording": UNREADABLE,
                                                  "wording_hash": UNREADABLE, "contact": UNREADABLE}


def test_decision_time_with_no_zone_with_an_offset_far_in_the_future_and_unparseable_is_kept_as_sent():
    for sent, parsed in ((b'"2026-10-20 09:12"', False), (b'"2026-10-20T09:12:00-04:00"', True), (b'"2999-01-01T00:00:00Z"', True),
                         (b'"yesterday afternoon"', False), (b"1730000000", False), (b'"2026-13-45T99:99:99Z"', False)):
        d = readings(b'{"decided_at": ' + sent + b"}")["decision_time"]
        assert d.values == (sent,) and (d.decision_time_parsed is not None) is parsed
    missing = readings(b'{"checked": true}')["decision_time"]
    assert (missing.state, missing.values, missing.decision_time_parsed) == (NOT_SENT, (), None)


def test_wording_with_odd_whitespace_and_characters_reads_back_byte_for_byte():
    text = "  I agree to texts ☃\n\t\"quoted\" \\ back​  "
    body = json.dumps({"disclosure_text": text, "checked": True}, ensure_ascii=False).encode("utf-8")
    r = readings(body)["wording"]
    assert json.loads(r.values[0]) == text
    stored = json.loads(values_json(r.values))
    assert json.loads(stored[0]) == text


def test_a_hash_only_form_reads_the_hash_as_sent_and_the_wording_as_not_sent():
    r = readings(json.dumps({"checked": True, "disclosure_sha256": "a" * 64}).encode())
    assert r["wording"].state == NOT_SENT and r["wording"].values == ()
    assert r["wording_hash"].values == (b'"' + b"a" * 64 + b'"',)


def test_invalid_utf8_values_are_stored_exactly_as_base64_never_replaced():
    r = readings(b'{"checked": "\xff"}')["consent"]
    assert json.loads(values_json(r.values)) == [{"b64": "Iv8i"}]
    assert r.values == (b'"\xff"',)


def test_the_same_bytes_and_map_give_the_same_readings_every_time():
    body = os.urandom(200) + b'{"checked": false}'
    assert read_fields(body, None, WIDGET_MAP) == read_fields(body, None, WIDGET_MAP)
    ok = b'{"checked": false, "contact": "x"}'
    assert read_fields(ok, None, WIDGET_MAP) == read_fields(ok, None, WIDGET_MAP)


def test_the_events_api_map_reads_the_event_fields():
    r = {x.field: x for x in read_fields(b'{"contact": "+15555550100", "checked": true, "captured_at": "2026-10-20T09:12:00Z",'
                                         b' "disclosure_sha256": "' + b"b" * 64 + b'"}', None, EVENTS_API_MAP)}
    assert r["consent"].values == (b"true",) and r["decision_time"].values == (b'"2026-10-20T09:12:00Z"',)
