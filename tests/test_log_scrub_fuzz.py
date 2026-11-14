"""The log scrubber against generated input (hypothesis is not a dev dependency here, so a seeded generator stands in).

Every US and international phone number, in every separator style (whitespace of every kind, line breaks, every Unicode dash,
underscore, comma, slash, dot, parentheses), in ASCII, full-width or Arabic-Indic digits, plain, JSON-escaped or URL-encoded, and
glued to random letters, hyphens, underscores and hex, is redacted. Every email address (non-ASCII local parts, international
domains, plus tags, the full-width @, escaped forms) is redacted. Every protected token (UUID, ISO 8601 date and time, AWS trace id,
hex hash, epoch timestamp, ts=, id= and job_id= values) survives, unless it holds 10 digits in a row or a contact shape, and then it
does not. A 40 KB line scrubs in under 50 ms, and so does every pathological 64 KB shape from the review.

Prefixes and suffixes are 0 to 8 characters, so a phone glued to hex never forms a 32-character hex run that is free of a 10-digit
run; a hex run holding 10 digits in a row is never protected."""

import random
import re
import string
import time
import unicodedata
import uuid

import pytest

from consentvault.tenancy.logscrub import MAX_CHARS, REDACTED, scrub

SEEDS = range(60)
GLUE = string.ascii_letters + "-_" + "0123456789abcdefABCDEF"
SEPARATORS = [" ", ".", "-", "–", "/", "", "\n", "\r\n", "\t", " ", "_", ",", "‑", "−", "—", "‐",
              "‒", "﹣", "－", " - ", "　"]
TEN_DIGITS = re.compile(r"\d{10}")
MAX_DRAWS = 1000


def _ascii_digits(text):
    return "".join(str(unicodedata.decimal(c)) for c in text if c.isdecimal())


def _digits(rng, n):
    return "".join(rng.choice("0123456789") for _ in range(n))


def _style_digits(rng, shown):
    """Write the digits as ASCII, full-width or Arabic-Indic."""
    style = rng.choice(["ascii", "ascii", "ascii", "fullwidth", "arabic"])
    if style == "ascii":
        return shown
    base = 0xFF10 if style == "fullwidth" else 0x0660
    return "".join(chr(base + int(c)) if c.isdigit() else c for c in shown)


def _encode(rng, shown):
    """Plain, JSON-escaped (a digit as \\u00XX, a line break as \\n) or URL-encoded."""
    how = rng.choice(["plain", "plain", "plain", "json", "url"])
    if how == "json":
        return "".join("\\u%04x" % ord(c) if (c.isdigit() and rng.random() < 0.5) else ("\\n" if c == "\n" else c) for c in shown)
    if how == "url":
        return "".join("%%%02X" % ord(c) if (c.isascii() and not c.isalnum() and rng.random() < 0.7) else c for c in shown)
    return shown


def _us(rng):
    area, ex, line = str(rng.randint(201, 989)), _digits(rng, 3), _digits(rng, 4)
    sep = rng.choice(SEPARATORS)
    shapes = [f"{area}{sep}{ex}{sep}{line}", f"({area}) {ex}-{line}", f"({area}){ex}{sep}{line}", f"+1{area}{ex}{line}",
              f"+1 {area}{sep}{ex}{sep}{line}", f"1{sep}{area}{sep}{ex}{sep}{line}", f"+1 ({area}) {ex}-{line}",
              f"1 ({area}) {ex}{sep}{line}", f"{area}{sep}{ex}{sep}\n{line}", f"({area}) {ex}\r\n{line}"]
    return rng.choice(shapes), area + ex + line


def _international(rng):
    country = rng.choice(["44", "49", "33", "61", "91", "86", "52", "34", "81", "55", "353", "972"])
    total = rng.randint(max(10, len(country) + 7), 15)
    rest = _digits(rng, total - len(country))
    sep = rng.choice(SEPARATORS)
    groups, k = [], 0
    while k < len(rest):
        size = rng.randint(2, 4)
        groups.append(rest[k:k + size])
        k += size
    body = sep.join(groups)
    shape = rng.choice([f"+{country}{sep}{body}", f"+{country} ({groups[0]}) {sep.join(groups[1:])}", f"00{country}{sep}{body}",
                        f"+{country}{rest}"])
    return shape, rest


def _email(rng):
    local = rng.choice(["dana", "jörg.meyer", "john+tag", "li.wei_88", "zoë", "oneil", "ana-maria"])
    local += str(rng.randint(0, 99)) if rng.random() < 0.5 else ""
    domain = rng.choice(["example.com", "méxico.mx", "mail.example.co.uk", "bücher.de", "пример.рф", "example.org"])
    at = rng.choice(["@", "@", "＠", "\\u0040", "%40"])
    return f"{local}{at}{domain}", unicodedata.normalize("NFKC", local)


def _glue(rng):
    return "".join(rng.choice(GLUE) for _ in range(rng.randint(0, 8)))


def _hex(rng, n):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _draw_token(rng):
    kind = rng.randrange(6)
    if kind == 0:
        return str(uuid.UUID(int=rng.getrandbits(128)))
    if kind == 1:
        when = f"{rng.randint(1990, 2099)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
        tail = rng.choice(["", f"T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"])
        if tail:
            tail += rng.choice(["", "Z", f".{_digits(rng, rng.randint(1, 9))}Z", f"+{rng.randint(0, 14):02d}:00", "-0500"])
        return when + tail
    if kind == 2:
        return f"Root=1-{rng.getrandbits(32):08x}-{rng.getrandbits(96):024x}"
    if kind == 3:
        tok = _hex(rng, rng.choice([40, 64, 128]))
        return tok if re.search("[a-f]", tok) else "a" + tok[1:]
    if kind == 4:
        return str(rng.randint(1_420_070_400, 1_999_999_999) * (1000 if rng.random() < 0.5 else 1))
    return rng.choice(["ts=", "id=", "job_id="]) + rng.choice([str(rng.randint(1_420_070_400, 1_999_999_999)),
                                                               f"job-{rng.randint(1, 999999)}", _hex(rng, 8)])


def _protected(rng):
    """A protected token. Epochs and key values hold 10 digits by design; a UUID, date, trace id or hash holding 10 digits in a row
    is never protected, by rule, so it is drawn again."""
    for _ in range(MAX_DRAWS):
        tok = _draw_token(rng)
        if (tok.isdigit() and len(tok) in (10, 13)) or tok.startswith(("ts=", "id=", "job_id=")) or not TEN_DIGITS.search(tok):
            return tok
    raise AssertionError(f"no protected token drawn in {MAX_DRAWS} tries")


def _line(rng, n=30):
    parts, phones, emails, tokens = [], [], [], []
    for _ in range(n):
        r = rng.random()
        if r < 0.45:
            shown, digits = (_us if rng.random() < 0.5 else _international)(rng)
            parts.append(_glue(rng) + _encode(rng, _style_digits(rng, shown)) + _glue(rng))
            phones.append((shown, digits))
        elif r < 0.6:
            shown, local = _email(rng)
            parts.append(rng.choice(["", "<", "mailto:", "x_"]) + shown + rng.choice(["", ">", ".", ","]))
            emails.append(local)
        else:
            tok = _protected(rng)
            parts.append(tok)
            tokens.append(tok)
    return " ".join(parts), phones, emails, tokens


def _check(text, phones, emails, tokens):
    out = scrub(text)
    for tok in tokens:
        assert tok in out, (tok, out)
    rest = out
    for tok in tokens:
        rest = rest.replace(tok, " ")
    rest_digits = _ascii_digits(rest)
    for shown, digits in phones:
        assert digits[-7:] not in rest_digits, (shown, out)
    for local in emails:
        assert local not in out, (local, out)
    return out


@pytest.mark.parametrize("seed", SEEDS)
def test_every_generated_contact_is_redacted_and_every_protected_token_survives(seed):
    rng = random.Random(seed)
    _check(*_line(rng))


# ---- the review's cases, every one ----------------------------------------------------------------------------------------------
LEAKS = {
    "uuid as a local part": ("57116397-0e91-4287-aa19-c3b91592ca8d@example.com", "57116397"),
    "epoch as a local part": ("1730390400@example.com", "1730390400"),
    "newline split": ("call 813-555-\n1234 now", "1234"),
    "crlf split": ("call (813) 555\r\n1234", "1234"),
    "tab sep": ("813\t555\t1234", "1234"),
    "nbsp sep": ("813 555 1234", "1234"),
    "underscore": ("813_555_1234", "1234"),
    "comma": ("813,555,1234", "1234"),
    "nb hyphen": ("813‑555‑1234", "1234"),
    "minus sign": ("813−555−1234", "1234"),
    "em dash": ("813—555—1234", "1234"),
    "en dash": ("call 305–555–0150 back", "0150"),
    "slash": ("call 305/555/0150 back", "0150"),
    "fullwidth digits": ("８１３５５５１２３４", "1234"),
    "arabic-indic": ("٨١٣٥٥٥١٢٣٤", "١٢٣٤"),
    "phone word": ("1-813-FLOORS-1", "FLOORS"),
    "url query": ("GET /x?to=%2B18135551234&a=1", "5551234"),
    "url query plain": ("https://h/x?phone=813.555.1234&y=2", "1234"),
    "plus tag email": ("john+tag@example.com", "john"),
    "idn email": ("jose@méxico.mx", "jose"),
    "unicode local": ("jörg.meyer@example.de", "meyer"),
    "fullwidth at": ("john＠example.com", "john"),
    "json escaped digits": (r'{"p":"8135551234"}', "u0034"),
    "json escaped at": (r'{"e":"john@example.com"}', "john"),
    "json escaped newline": (r'{"p":"813-555\n1234"}', "1234"),
    "fake uuid": ("req 12345678-1234-1234-1234-008135551234 done", "8135551234"),
    "fake uuid2": ("81355512-3400-0000-0000-000000000000", "81355512"),
    "fake trace": ("1-81355512-348135551234000000000000", "8135551234"),
    "hex hash smuggle": ("sha a8135551234000000000000000000000000", "8135551234"),
    "date then phone": ("2026-10-31 8135551234", "8135551234"),
    "date-glued": ("2026-10-31-8135551234", "8135551234"),
    "reviewer phone-": ("phone-3055550150 failed", "3055550150"),
    "reviewer lead-": ("lead-18135550199", "8135550199"),
    "retry suffix": ("job +15551234567-retry failed", "5551234567"),
    "sms prefix": ("queue sms-18135550199 done", "8135550199"),
    "date then offset phone": ("at 2026-10-31T08:23:52+13055550150", "3055550150"),
    "grouped like a date": ("0123-45-67-89 dialled", "4567"),
    "id holding a phone": ("id=8135551234 x", "8135551234"),
    "ts holding a phone": ("ts=+18135551234 x", "8135551234"),
    "job_id holding an email": ("job_id=a@example.com", "a@example"),
}


@pytest.mark.parametrize("name", sorted(LEAKS))
def test_each_leak_from_the_review_is_redacted(name):
    line, hidden = LEAKS[name]
    out = scrub(line)
    assert hidden not in out and REDACTED in out, out


KEPT = [
    "trace Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1",
    "at 2026-10-31T08:23:52.123456Z and 2026-10-31 08:23:52,123 and 2026-10-31T08:23:52+05:00 and 2026-10-31",
    "org 3f2c8a1e-7b1a-4c3e-9f6e-2a1b3c4d5e6f run 57116397-0e91-4287-aa19-c3b91592ca8d",
    "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "epoch_ms=1730390400000",
    "ts=1730390400",
    "at 1730390400 done",
    "id=job-77 job_id=a1b2c3 ts=1730390400123",
    "migration 040 port 5432",
    "amount $1,234,567.89",
    "pid 12345 tid 67890",
    "git abc1234def5678",
    "call [redacted] Root=1-5759e988-bd862e3fe1be46a994272793",
]


@pytest.mark.parametrize("line", KEPT)
def test_ordinary_values_from_the_review_survive(line):
    assert scrub(line) == line


def test_a_capital_word_after_a_phone_is_not_read_as_a_letter_phone_number():
    assert scrub("call 813 555 1234 Root=1-5759e988-bd862e3fe1be46a994272793").endswith(" Root=1-5759e988-bd862e3fe1be46a994272793")
    assert scrub("813-555-1234 OK") == REDACTED + " OK"


# ---- the cap -------------------------------------------------------------------------------------------------------------------
def test_a_phone_cut_by_the_cap_never_survives_in_part():
    out = scrub("x " * ((MAX_CHARS - 6) // 2) + "813555" + "1234")
    assert "813555" not in out and "1234" not in out and out.endswith(REDACTED)


def test_an_email_cut_by_the_cap_never_survives_in_part():
    pad = "x " * ((MAX_CHARS - 15) // 2)
    out = scrub(pad + "john.smith@exam" + "ple.com")
    assert "john" not in out and "smith" not in out and out.endswith(REDACTED)


@pytest.mark.parametrize("contact", ["+1 (813) 555-0199", "dana.smith@example.com", "813—555—0199", "jörg＠bücher.de"])
@pytest.mark.parametrize("cut", range(1, 17))
def test_a_contact_cut_at_any_point_by_the_cap_leaves_no_part(contact, cut):
    pad = ("word " * (MAX_CHARS // 5 + 1))[:MAX_CHARS - cut]
    out = scrub(pad + contact + " tail")
    assert out.endswith(REDACTED)
    body = " ".join(out[:-len(REDACTED)].replace(REDACTED, " ").split())
    assert " ".join(pad.split()).startswith(body), body[-60:]  # nothing but padding survives: no part of the contact


def test_exactly_the_cap_is_scrubbed_whole_and_one_more_is_marked():
    assert not scrub("y" * MAX_CHARS).endswith(REDACTED)
    assert scrub("y" * (MAX_CHARS + 1)).endswith(REDACTED)


def test_input_past_64_kb_is_redacted_whole():
    head = "x " * ((MAX_CHARS - 10) // 2)
    out = scrub(head + " safe text then +13055550150 " + "y" * 100)
    assert "3055550150" not in out and "yyy" not in out and out.endswith(REDACTED)
    assert len(out) <= MAX_CHARS + len(REDACTED)


def test_a_placeholder_character_in_the_input_cannot_restore_anything():
    out = scrub("a +13055550150 b")
    assert "3055550150" not in out and "" not in out


# ---- time ----------------------------------------------------------------------------------------------------------------------
def _timed(text):
    t0 = time.perf_counter()
    scrub(text)
    return time.perf_counter() - t0


def test_a_40_kb_line_scrubs_in_under_50_ms():
    rng = random.Random(7)
    text = ""
    while len(text) < 40 * 1024:
        text += " " + _line(rng)[0]
    text = text[:40 * 1024]
    scrub(text)
    assert min(_timed(text) for _ in range(5)) < 0.050


PATHOLOGICAL = {"eyJ- repeat": "eyJ-" * 16384, "eyJa nodot": " eyJ" + "a" * 65000, "v1 token": "v1.a." + "0" * 65000,
                "at storm": "a@" * 32768, "at domain": ("@" + "a." * 30) * 1000, "digits+seps": "1 " * 32768,
                "hex run g": "a" * 65535 + "g", "ipv6 colons": ":" * 65536, "ipv6 mix": "1:" * 32768, "token kv": "token " * 10000,
                "basic ws": "basic" + " " * 65000, "dates": "2026-10-31-" * 5900, "pct": "%25" * 21845, "bearer": "bearer " * 9000,
                "postmark": "server_token " * 5000, "email backscan": "a" * 32000 + "@" + "b" * 32000,
                "email k-loop": "a@" + "b1" * 32000, "json escapes": "\\u0031" * 10900, "nbsp digits": "1 " * 32768,
                "dashes": "1—" * 32768, "glued tokens": "token" * 13000 + "=x", "letters": "a" * 65536,
                "letter phone": "1-813-FLOORS-" * 5000, "capitals": "1-" + "AB-" * 21000}


@pytest.mark.parametrize("name", sorted(PATHOLOGICAL))
def test_a_pathological_64_kb_line_scrubs_in_under_50_ms(name):
    text = PATHOLOGICAL[name][:MAX_CHARS]
    scrub(text)
    assert min(_timed(text) for _ in range(5)) < 0.050, name
