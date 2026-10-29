"""Log scrubber: no contact point, IP address, tenant token, bearer token or JWT reaches a log line.

``install()`` puts a filter on the handlers of a logger (the root logger by default) that rewrites each record's
final message, args included, and drops its exception text into a scrubbed form. Patterns are deliberately broad:
a false redaction costs a log reader a value; a missed one leaks personal data into a store that is never shredded.
"""

from __future__ import annotations

import ipaddress
import logging
import re

REDACTED = "[redacted]"

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("tenant_token", re.compile(r"\bv1\.[a-z0-9_-]{1,32}\.[0-9a-f]+\.[0-9a-f]{64}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")),
    ("bearer", re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("secret_kv", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token|authorization)\b\s*[=:]\s*\S+")),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("ipv4", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")),
    # not inside a UUID or another hyphenated identifier
    ("phone", re.compile(r"(?<![\w-])\+?\(?\d[\d\s().-]{7,}\d(?![\w-])")),
)


_IPV6_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f:.])[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?![0-9A-Fa-f:.])")


def _ipv6(match: re.Match[str]) -> str:
    try:
        ipaddress.IPv6Address(match.group(0).split("%")[0])
    except ValueError:
        return match.group(0)
    return REDACTED


def scrub(text: str) -> str:
    """Replace every contact point, IP address and token in ``text``."""
    for _name, pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    return _IPV6_CANDIDATE.sub(_ipv6, text)


class ScrubFilter(logging.Filter):
    """Rewrites the record in place; never drops it (a dropped line is a silent failure)."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = scrub(record.getMessage())
        record.args = None
        if record.exc_info:
            record.exc_text = scrub(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
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
