"""The fixed text of every message the confirmation service sends (confirmations.md sections 6 and 7).

Nothing here is editable by an organization: an email template may change only its subject and its opening line. The
organization's texting registration records which version of this text it filed with the carrier (``FIXED_TEXT_VERSION``);
change any fixed sentence below and the version must go up, which turns every text rule off until the organization marks
a new registration. The version is read from this module at each use, never copied.
"""

from __future__ import annotations

import math

FIXED_TEXT_VERSION = 1

TEXT_TAIL = "Msg frequency varies. Msg & data rates may apply. Reply STOP to opt out, HELP for help."
CHANNEL_WORDS = {"sms": "texts", "voice": "calls", "artificial_voice": "automated calls"}
DEFAULT_SUBJECT = "What you agreed to receive"
DEFAULT_SUBJECT_MAX = 80
SAMPLE_PURPOSES = "offers and billing"

_GSM7 = set("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà")
_GSM7_EXT = set("^{}\\[~]|€\f")


def words(items: list[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def channel_words(channels) -> str:
    """The channels a grant names, in plain words, for a text message: texts and calls (email is not named in a text)."""
    named = [CHANNEL_WORDS[c] for c in ("sms", "voice", "artificial_voice") if c in set(channels)]
    return words(named) if named else "texts"


def email_channel_words(channels) -> str:
    names = {**CHANNEL_WORDS, "email": "email"}
    return words([names[c] for c in ("email", "sms", "voice", "artificial_voice") if c in set(channels)])


def sms_confirmation(brand: str, when: str, what: str, purposes: str, link: str) -> str:
    return f"{brand}: on {when} you agreed to {what} about {purposes}. Full wording: {link}. {TEXT_TAIL}"


def optout_reply(brand: str) -> str:
    return (f"{brand}: You are unsubscribed and will get no more texts or calls from us. "
            "Email is not affected. Reply START to get texts again.")


def help_contact(help_email: str, help_phone: str | None) -> str:
    return help_email + (f", {help_phone}" if help_phone else "")


def help_reply(brand: str, help_email: str, help_phone: str | None) -> str:
    return (f"{brand}: Help: {help_contact(help_email, help_phone)}. Reply STOP to opt out of texts and calls. "
            "Msg frequency varies. Msg & data rates may apply.")


def start_reply(brand: str) -> str:
    return (f"{brand}: You will get texts from us again. Msg frequency varies. Msg & data rates may apply. "
            "Reply STOP to opt out, HELP for help.")


def start_refused_reply(brand: str, help_email: str, help_phone: str | None) -> str:
    reach = help_email + (f" or {help_phone}" if help_phone else "")
    return f"{brand}: We could not turn texts back on from this message. Contact us at {reach} and we will help."


def email_subject(template_subject: str | None, brand: str) -> str:
    return template_subject or f"{DEFAULT_SUBJECT} from {brand}"[:DEFAULT_SUBJECT_MAX]


def email_body(*, opening_line: str | None, brand: str, when: str, source_name: str, wording: str, channels: str,
               purposes: str, stop_link: str, org_name: str, postal_address: str, help_email: str,
               help_phone: str | None) -> str:
    parts = []
    if opening_line:
        parts.append(opening_line)
    parts.append(f"On {when} you agreed to the following from {brand} at {source_name}:")
    parts.append(wording)
    parts.append(f"Channels: {channels}. Purposes: {purposes}.")
    parts.append(f"To stop email from {brand}, use this link: {stop_link}. The page also lets you stop texts and calls. "
                 "Texts and calls are not affected unless you choose that.")
    parts.append(f"{org_name}\n{postal_address}\nQuestions: {help_contact(help_email, help_phone)}")
    return "\n\n".join(parts)


def segments(body: str) -> int:
    """How many text segments a body takes: 160 (153 when joined) characters of the GSM alphabet, else 70 (67)."""
    gsm = all(ch in _GSM7 or ch in _GSM7_EXT for ch in body)
    size = sum(2 if ch in _GSM7_EXT else 1 for ch in body) if gsm else len(body)
    single, joined = (160, 153) if gsm else (70, 67)
    return 1 if size <= single else math.ceil(size / joined)
