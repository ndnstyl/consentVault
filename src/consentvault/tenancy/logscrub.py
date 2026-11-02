"""Log scrubber: the backstop that keeps contact points, IP addresses and tokens out of a log line.

The control is allowlist logging (consentvault/safelog.py): a log call carries a constant message and registered fields, and a
value that is not a safe kind is hashed before it is written. This module is the second line, for text that reaches a log by
another road (an exception, a library's own message). ``install()`` puts a filter on the handlers of a logger (the root logger by
default) that rewrites each record's final message, args included, and its exception and stack text.

One call, in this order:

1. **Cap.** At most ``MAX_CHARS`` characters are read. A longer input is cut there, and a contact-shaped tail at the cut (part of
   a number or an address) is removed with it, so a partial phone or email never survives; one redaction marker ends the line.
2. **Decode** to a fixed point (at most ``MAX_DECODES`` rounds): URL escapes, JSON string escapes (``\\uXXXX``, ``\\n``), and
   Unicode NFKC, so full-width digits and the full-width @ read as their plain forms.
3. **Secrets**: tenant tokens, JWTs, bearer and basic credentials, ``name=value`` secrets, provider credentials.
4. **Protect** the known non-personal tokens behind placeholders: complete UUIDs, AWS trace ids, ISO 8601 dates and times, hex
   hashes of 32 or more characters, epoch timestamps, and the values of ``ts=``, ``id=`` and ``job_id=``. A token holding 10 or
   more digits in a row, or a contact shape, is never protected.
5. **Contact points**: every email address (non-ASCII letters allowed on both sides), IPv4 and IPv6 addresses, and every run of
   10 or more digits (any Unicode decimal digit) with up to four separators between digits: any whitespace, any Unicode dash or
   hyphen, the minus sign, and ``. / ( ) + _ ,``. A letter phone number (1-813-FLOORS-1) counts its capitals once three digits
   lead the run.
6. **Restore** the protected tokens.

Every pattern is flat (no quantifier inside a quantified group) and each scanner visits a character a bounded number of times, so a
call is linear in its input. A false redaction costs a reader a value; a missed one leaks personal data into a store that is never
shredded.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import unicodedata
import urllib.parse

REDACTED = "[redacted]"
MAX_DECODES = 5
MAX_CHARS = 64 * 1024
MIN_PHONE_DIGITS = 10

# ---- characters --------------------------------------------------------------------------------------------------------------------
_ASCII_SEPARATORS = frozenset(" \t\n\r\v\f.-/()+_,")
_EXTRA_DASHES = frozenset("\u2212\u00ad\u2043\u2010\u2011\ufe63\uff0d\u02d7\u2796\u2e3a\u2e3b")


def _is_digit(ch: str) -> bool:
    return "0" <= ch <= "9" or (ch > "\x7f" and ch.isdecimal())


def _is_separator(ch: str) -> bool:
    if ch < "\x80":
        return ch in _ASCII_SEPARATORS
    return ch.isspace() or ch in _EXTRA_DASHES or unicodedata.category(ch) == "Pd"


def _is_local_char(ch: str) -> bool:
    return ch.isalnum() or ch in "._%+-"


def _is_domain_char(ch: str) -> bool:
    return ch.isalnum() or ch in ".-"


# ---- 1. cap ------------------------------------------------------------------------------------------------------------------------
def _trim_contact_tail(text: str) -> str:
    """Remove a contact-shaped tail: a run of digits and separators holding a digit, and the word before a cut (an address or an
    encoded one may have no space in it). At most three rounds: a tail is a number, an address, or one of each."""
    for _ in range(3):
        before = len(text)
        k = len(text)
        while k > 0 and (_is_digit(text[k - 1]) or _is_separator(text[k - 1])):
            k -= 1
        if any(_is_digit(c) for c in text[k:]):
            text = text[:k]
        k = len(text)
        while k > 0 and not text[k - 1].isspace() and (_is_local_char(text[k - 1]) or text[k - 1] in "@\uff20\\"):
            k -= 1
        text = text[:k]
        if len(text) == before:
            break
    return text


# ---- 2. decode ---------------------------------------------------------------------------------------------------------------------
_JSON_ESCAPE = re.compile(r"\\u([0-9A-Fa-f]{4})|\\([nrtbf\"\\/])")
_JSON_SIMPLE = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", '"': '"', "\\": "\\", "/": "/"}


def _json_unescape(m: re.Match[str]) -> str:
    if m.group(1):
        cp = int(m.group(1), 16)
        return "\ufffd" if 0xD800 <= cp <= 0xDFFF else chr(cp)
    return _JSON_SIMPLE[m.group(2)]


# every invisible formatting character (Unicode category Cf: zero-width space and joiners, the word joiner, bidi controls, the byte
# order mark, the soft hyphen, tag characters), the Hangul fillers, the combining grapheme joiner and the variation selectors
_INVISIBLE = re.compile(
    "[\u00ad\u0600-\u0605\u061c\u06dd\u070f\u0890-\u0891\u08e2\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064"
    "\u2066-\u206f\ufeff\ufff9-\ufffb\U000110bd\U000110cd\U00013430-\U0001343f\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    "\U000e0001\U000e0020-\U000e007f\u115f\u1160\u3164\uffa0\u034f\ufe00-\ufe0f\U000e0100-\U000e01ef]")


def _decode(text: str) -> str:
    for _ in range(MAX_DECODES):  # a contact point hidden as %2B1813..., \u0040, a full-width digit, a zero-width space, encoded twice
        decoded = _INVISIBLE.sub("", unicodedata.normalize("NFKC", _JSON_ESCAPE.sub(_json_unescape, urllib.parse.unquote(text))))
        if decoded == text:
            break
        text = decoded
    return text


# ---- 3. secrets --------------------------------------------------------------------------------------------------------------------
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bv1\.[a-z0-9_-]{1,32}\.[0-9a-f]++\.[0-9a-f]{64}\b"),                     # a tenant token
    re.compile(r"(?i)\b(?:bearer|basic)\s++[A-Za-z0-9._~+/=-]{8,}"),
)
# provider credentials (confirmations.md section 1): Twilio account and API key ids and the 32-hex auth token, AWS access key ids and
# their 40-character secrets, and a Postmark token in a header or a field
_PROVIDER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:AC|SK)[0-9a-fA-F]{32}\b"),
    re.compile(r"(?<![0-9A-Za-z-])[0-9a-f]{32}(?![0-9A-Za-z-])"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(?:x-postmark-(?:server|account)-token|(?:server|account)[_-]token)\b\W{0,4}[0-9a-f-]{20,}"),
)
_AWS_SECRET = re.compile(r"(?<![A-Za-z0-9/+=-])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=-])")
_HEX_ONLY = re.compile(r"[0-9A-Fa-f]+")
_JWT_RUN = re.compile(r"[A-Za-z0-9_.-]+")
# no word boundary before the key name: api_key_secret=..., aws_secret_access_key=... and x-postmark-server-token: ... all match
_WORD_TAIL = re.compile(r"[\w-]*+")
_SECRET_NAME = re.compile(r"(?i)password|passwd|secret|api[_-]?key|token|authorization")
_SECRET_VALUE = re.compile(r"\s*+[=:]\s*+\S+")


def _aws_secret(m: re.Match[str]) -> str:
    return m.group(0) if _HEX_ONLY.fullmatch(m.group(0)) else REDACTED  # a 40-hex value is a SHA-1, protected below


def _jwt_in(run: str) -> tuple[int, int] | None:
    """The span of a JWT (eyJ<segment>.<segment>.<segment?>) inside one run of token characters, or None. Linear in the run."""
    i = run.find("eyJ")
    while i != -1:
        if i == 0 or run[i - 1] in "-.":
            d1 = run.find(".", i)
            if d1 == -1:
                return None  # no dot after this one, so none after any later one either
            d2 = run.find(".", d1 + 1)
            if d1 > i + 3 and d2 > d1 + 1:
                d3 = run.find(".", d2 + 1)
                return i, (len(run) if d3 == -1 else d3)
        i = run.find("eyJ", i + 3)
    return None


def _jwts(text: str) -> str:
    if "eyJ" not in text:
        return text
    out, last = [], 0
    for m in _JWT_RUN.finditer(text):
        span = _jwt_in(m.group(0))
        if span is not None:
            out.append(text[last:m.start() + span[0]])
            out.append(REDACTED)
            last = m.start() + span[1]
    return "".join(out) + text[last:] if out else text


def _secret_kv(text: str) -> str:
    out, last, word_end = [], 0, -1
    for name in _SECRET_NAME.finditer(text):  # each secret name, then the whole word around it (each word read once)
        if name.start() < max(last, word_end):
            continue
        start = name.start()
        while start > 0 and (text[start - 1].isalnum() or text[start - 1] in "_-"):
            start -= 1
        word_end = _WORD_TAIL.match(text, name.end()).end()
        if start < last:
            continue
        v = _SECRET_VALUE.match(text, word_end)
        if v is None:
            continue
        out.append(text[last:start])
        out.append(REDACTED)
        last = v.end()
    return "".join(out) + text[last:] if out else text


def _secrets(text: str) -> str:
    text = _SECRET_PATTERNS[0].sub(REDACTED, text)
    text = _jwts(text)
    text = _SECRET_PATTERNS[1].sub(REDACTED, text)
    text = _secret_kv(text)
    for pattern in _PROVIDER_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return _AWS_SECRET.sub(_aws_secret, text)


# ---- 4. protected tokens -----------------------------------------------------------------------------------------------------------
_H = "[0-9A-Fa-f]"
_TRACE, _UUID, _ISO, _HASH, _EPOCH, _KEYED = range(6)
# no protected token touches an @ on either side: a token that is the local part or the domain of an address is that address
_PROTECT: tuple[re.Pattern[str], ...] = (
    re.compile(rf"(?<![0-9A-Za-z@])1-{_H}{{8}}-{_H}{{24}}(?![0-9A-Za-z@])"),
    re.compile(rf"(?<![0-9A-Za-z@]){_H}{{8}}-{_H}{{4}}-{_H}{{4}}-{_H}{{4}}-{_H}{{12}}(?![0-9A-Za-z@])"),
    re.compile(r"(?<![\d@])\d\d\d\d-\d\d-\d\d(?:[T ]\d\d:\d\d:\d\d|[T ]\d\d:\d\d)?(?![\d@])"),
    re.compile(r"(?<![0-9A-Za-z_@])[0-9A-Fa-f]{32,}(?![0-9A-Za-z_@])"),
    re.compile(r"(?<![\w+(@])1[4-9]\d{8}(?:\d{3})?(?![\w@])"),
    re.compile(r"(?<![\w.])(?:ts|id|job_id)=([A-Za-z0-9_.:-]{1,64})(?![^\s&,;)\]}\"'])"),
)
_HEX_LETTER = re.compile(r"[A-Fa-f]")
_TEN_DIGITS = re.compile(r"\d{10}")
_GROUP_JOINERS = frozenset("-\u2013/._,")
_EPOCH_S = (1_420_070_400, 1_999_999_999)            # 2015-01-01 to 2033: no 10-digit North American number starts with 1
_EPOCH_MS = (1_420_070_400_000, 1_999_999_999_999)    # 13 digits starting with 1 is never a valid E.164 number
_OPEN, _CLOSE = "\ue000", "\ue001"  # private-use characters; any in the input are dropped first, so a placeholder is always ours
_PLACEHOLDER = re.compile(_OPEN + "([a-z]+)" + _CLOSE)


def _label(i: int) -> str:
    out = ""
    while True:
        out = chr(ord("a") + i % 26) + out
        i = i // 26 - 1
        if i < 0:
            return out


def _iso_tail(text: str, end: int) -> int:
    """Extend an ISO 8601 time over a fraction of 1 to 9 digits and an offset (Z, +hh:mm, +hhmm), never into a longer digit run."""
    n = len(text)
    if end < n and text[end] in ".,":
        k = end + 1
        while k < n and k - end <= 10 and "0" <= text[k] <= "9":
            k += 1
        if 2 <= k - end <= 10 and not (k < n and "0" <= text[k] <= "9"):
            end = k
    if end < n and text[end] == "Z":
        return end + 1
    if end < n and text[end] in "+-":
        seg6, seg5 = text[end + 1:end + 6], text[end + 1:end + 5]
        if len(seg6) == 5 and seg6[:2].isdigit() and seg6[2] == ":" and seg6[3:].isdigit() and \
                not (end + 6 < n and _is_digit(text[end + 6])):
            return end + 6
        if len(seg5) == 4 and seg5.isdigit() and not (end + 5 < n and _is_digit(text[end + 5])):
            return end + 5
    return end


def _stands_alone(text: str, start: int, end: int) -> bool:
    """Not joined to another digit group by a dash, slash, dot, underscore or comma, as a number written in groups would be."""
    if end + 1 < len(text) and text[end] in _GROUP_JOINERS and _is_digit(text[end + 1]):
        return False
    return not (start >= 2 and text[start - 1] in _GROUP_JOINERS and _is_digit(text[start - 2]))


def _plausible_date(text: str, start: int, end: int) -> bool:
    y, mo, d = int(text[start:start + 4]), int(text[start + 5:start + 7]), int(text[start + 8:start + 10])
    if not (1900 <= y <= 2199 and 1 <= mo <= 12 and 1 <= d <= 31):
        return False
    if end - start >= 16 and not (int(text[start + 11:start + 13]) < 24 and int(text[start + 14:start + 16]) < 60):
        return False
    return _stands_alone(text, start, end)


def _contact_shaped(value: str) -> bool:
    return "@" in value or _numbers(value) != value


def _protect(text: str) -> tuple[str, list[str]]:
    kept: list[str] = []
    for kind, pattern in enumerate(_PROTECT):
        out, last = [], 0
        for m in pattern.finditer(text):
            start, end = m.start(), m.end()
            if start < last:
                continue
            if kind == _ISO:
                if end - start > 10:
                    end = _iso_tail(text, end)
                if not _plausible_date(text, start, end):
                    continue
            elif kind == _EPOCH:
                value, lo_hi = int(m.group(0)), (_EPOCH_S if end - start == 10 else _EPOCH_MS)
                if not (lo_hi[0] <= value <= lo_hi[1] and _stands_alone(text, start, end)):
                    continue
            elif kind == _KEYED:
                start = m.start(1)
                if _contact_shaped(m.group(1)) or not _stands_alone(text, start, end):
                    continue
            elif _TEN_DIGITS.search(m.group(0)) is not None:
                continue  # a UUID, trace id or hash holding 10 digits in a row may be a number dressed as one: never protected
            if kind == _HASH and _HEX_LETTER.search(m.group(0)) is None:
                continue
            out.append(text[last:start])
            kept.append(text[start:end])
            out.append(_OPEN + _label(len(kept) - 1) + _CLOSE)
            last = end
        text = "".join(out) + text[last:]
    return text, kept


def _restore(text: str, kept: list[str]) -> str:
    def back(m: re.Match[str]) -> str:
        i = -1
        for ch in m.group(1):
            i = (i + 1) * 26 + ord(ch) - ord("a")
        return kept[i] if 0 <= i < len(kept) else REDACTED
    return _PLACEHOLDER.sub(back, text)


# ---- 5. contact points -------------------------------------------------------------------------------------------------------------
_MAX_SEPARATOR_RUN = 4  # a spaced hyphen and a line break (" - \n") is four
_WORD_DASHES = frozenset("-\u2010\u2011\u2012\u2013\u2014\u2212\uff0d")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d.])")
_IPV6_CANDIDATE = re.compile(r"[0-9A-Fa-f:.]+")


# a one-letter class per character, built by four C-speed passes so the scan below compares letters only: d digit (any Unicode
# decimal), s separator, U capital letter, x anything else. Each pass maps one character to one, so positions stay aligned.
_PD_DASHES = ("\u058a\u05be\u1400\u1806\u2010\u2011\u2012\u2013\u2014\u2015\u2e17\u2e1a\u2e3a\u2e3b\u2e40\u2e5d\u301c\u3030"
              "\u30a0\ufe31\ufe32\ufe58\ufe63\uff0d\U00010ead")  # every Unicode dash (category Pd) past ASCII, Unicode 15
_SEPARATOR_CLASS = r"\s.\-/()+_," + re.escape("".join(sorted(_EXTRA_DASHES))) + re.escape(_PD_DASHES)
_CLASS_OTHER = re.compile(rf"[^\dA-Z{_SEPARATOR_CLASS}]")
_CLASS_CAPITAL = re.compile(r"[A-Z]")
_CLASS_DIGIT = re.compile(r"\d")
_CLASS_SEPARATOR = re.compile(r"[^xUd]")


def _classes(text: str) -> str:
    c = _CLASS_OTHER.sub("x", text)
    c = _CLASS_CAPITAL.sub("U", c)
    c = _CLASS_DIGIT.sub("d", c)
    return _CLASS_SEPARATOR.sub("s", c)


def _numbers(text: str) -> str:
    """Redact every run of 10 or more digits, whatever comes before or after it. A run longer than 15 digits is redacted as well:
    it may be two numbers written together."""
    c = _classes(text)
    out, last, n = [], 0, len(c)
    i = c.find("d")
    while i != -1:
        start, digits, real, end, k, seps = i, 0, 0, i, i, 0
        while k < n:
            ch = c[k]
            if ch == "d":
                digits, real, end, seps = digits + 1, real + 1, k + 1, 0
            elif ch == "U" and real >= 3 and (c[k - 1] == "d" or text[k - 1] in _WORD_DASHES):
                # a letter phone number (1-813-FLOORS-1): a group of 2 to 7 capitals after a digit or a dash, ending at a digit,
                # a separator or the end; a capital that starts an ordinary word (... 1234 Root=) is not one
                j = k
                while j < n and c[j] == "U":
                    j += 1
                if not (2 <= j - k <= 7 and (j == n or c[j] in "ds")):
                    break
                digits, end, seps, k = digits + (j - k), j, 0, j
                continue
            elif ch == "s" and seps < _MAX_SEPARATOR_RUN:
                seps += 1
            else:
                break
            k += 1
        if digits >= MIN_PHONE_DIGITS:
            while start > last and start > i - 2 and text[start - 1] in "+(":
                start -= 1
            out.append(text[last:start])
            out.append(REDACTED)
            last = end
        i = c.find("d", end)
    return "".join(out) + text[last:] if out else text


_MAX_QUOTED_LOCAL = 64


def _emails(text: str) -> str:
    """Redact every address: a local part, an @, and a domain ending in a dot and two or more letters, whatever is around it."""
    out, last, at, n = [], 0, text.find("@"), len(text)
    while at != -1:
        left = at
        if at > 0 and text[at - 1] == '"':  # a quoted local part: "john smith"@example.com
            q = text.rfind('"', max(last, at - 1 - _MAX_QUOTED_LOCAL), at - 1)
            if q != -1 and "\n" not in text[q:at]:
                left = q
        while left > last and _is_local_char(text[left - 1]):
            left -= 1
        right = at + 1
        while right < n and _is_domain_char(text[right]):
            right += 1
        end, k = -1, right
        while k > at + 1:  # the last dot followed by two or more letters ends the address
            letters = 0
            while k > at + 1 and text[k - 1].isalpha():
                k -= 1
                letters += 1
            if k > at + 2 and text[k - 1] == "." and letters >= 2:
                end = k + letters
                break
            if letters == 0:
                k -= 1
        if left < at and end != -1:
            out.append(text[last:left])
            out.append(REDACTED)
            last = end
        at = text.find("@", max(at + 1, last))
    return "".join(out) + text[last:] if out else text


def _ipv4(m: re.Match[str]) -> str:
    return REDACTED if all(int(p) <= 255 for p in m.group(0).split(".")) else m.group(0)


def _ipv6(m: re.Match[str]) -> str:
    value = m.group(0)
    if value.count(":") < 2 or len(value) > 45:
        return value
    try:
        ipaddress.IPv6Address(value)
    except ValueError:  # loud-failure-exempt: not an IPv6 address is the answer, and the text is kept as it is
        return value
    return REDACTED


# ---- the call ----------------------------------------------------------------------------------------------------------------------
def scrub(text: str) -> str:
    """Replace every contact point, IP address and token in ``text``. At most ``MAX_CHARS`` characters are scrubbed per call; the rest
    is replaced by one redaction marker, never passed through, and a contact-shaped tail at the cut goes with it."""
    over = len(text) > MAX_CHARS
    if over:
        text = _trim_contact_tail(text[:MAX_CHARS])
    text = _decode(text)
    if len(text) > MAX_CHARS:  # normalisation can lengthen a line; the cap holds after it too
        text, over = _trim_contact_tail(text[:MAX_CHARS]), True
    text = text.replace(_OPEN, "").replace(_CLOSE, "")
    text = _secrets(text)
    text, kept = _protect(text)
    text = _emails(text)
    text = _IPV4.sub(_ipv4, text)
    text = _IPV6_CANDIDATE.sub(_ipv6, text)
    text = _numbers(text)
    text = _restore(text, kept)
    return text + REDACTED if over else text


_WARNING_HEAD = re.compile(r"[^\n]*?:\d+: [A-Za-z_][A-Za-z0-9_]*")


def _warning_head(message: str) -> str:
    """A captured warning keeps where it came from and its category (file:line: Category); its text can carry a value."""
    m = _WARNING_HEAD.match(message)
    return (m.group(0) if m else "a warning") + ": [text withheld]"


class SafeLine(str):
    """A line the allowlist logger rendered (consentvault/safelog.py): a constant message and checked fields, so its text is kept."""


WITHHELD = "[text withheld]"


def _record_text(record: logging.LogRecord) -> str:
    """The text a record may keep. A line from the allowlist logger keeps its text. A captured warning keeps where it came from and
    its category. Any other logger (a library) keeps its constant format string and loses its arguments; a line built before it was
    logged (no arguments) is withheld whole, because a name in it cannot be told from any other word."""
    if isinstance(record.msg, SafeLine):
        return str(record.msg)
    if record.name == "py.warnings":
        return _warning_head(record.getMessage())
    if record.args:
        return str(record.msg) + " [arguments withheld]"
    return WITHHELD


_STANDARD = frozenset(logging.LogRecord("n", 0, "p", 0, "m", None, None).__dict__) | {"message", "asctime", "taskName"}


class ScrubFilter(logging.Filter):
    """Rewrites the record in place, every time it runs, never trusting an earlier pass: the message, any extra field (from extra=,
    a LoggerAdapter, or makeLogRecord), the exception and the stack. Never drops the record (a dropped line is a silent failure).
    An exception is written as its class and the frames it passed through, never its message or a local. An extra field is free
    text from the caller, so its value is withheld."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = SafeLine(scrub(_record_text(record)))
        record.args = None
        for name in list(record.__dict__):
            if name not in _STANDARD and record.__dict__[name] != WITHHELD:
                record.__dict__[name] = WITHHELD
        if record.exc_info:
            from ..safelog import frames
            exc_type, _exc, tb = record.exc_info
            record.exc_text = SafeLine(f"{getattr(exc_type, '__name__', 'exception')} at {frames(tb)}")
            record.exc_info = None
        elif record.exc_text and not isinstance(record.exc_text, SafeLine):
            record.exc_text = WITHHELD
        if record.stack_info:
            record.stack_info = scrub(record.stack_info)
        return True


def install(logger: logging.Logger | None = None) -> ScrubFilter:
    """Attach one scrub filter to the logger and to each of its handlers. Idempotent."""
    target = logger if logger is not None else logging.getLogger()
    existing = [f for f in target.filters if isinstance(f, ScrubFilter)]
    filt = existing[0] if existing else ScrubFilter()
    if not existing:
        target.addFilter(filt)
    for handler in target.handlers:
        if not any(isinstance(f, ScrubFilter) for f in handler.filters):
            handler.addFilter(filt)
    return filt
