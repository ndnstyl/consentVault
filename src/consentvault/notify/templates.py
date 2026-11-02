"""Four transactional templates, plain text and simple HTML, and the personal-data refusal."""

from __future__ import annotations

import re
from html import escape

from .base import TEMPLATE_TYPES
from .errors import NotifyRefused

# Variable names each template accepts. Anything else is refused.
VARIABLES = {
    "invite": ("company", "inviter_name", "accept_url", "expires_at"),
    "security_alert": ("company", "event", "when", "review_url"),
    "delivery_failure": ("company", "failed_count", "period", "details_url"),
    "billing_notice": ("company", "notice", "amount", "invoice_url"),
}

_EMAIL = re.compile(r"[^\s@<>]+@[^\s@<>]+\.[A-Za-z]{2,}")
_PHONE_FORMATTED = re.compile(r"(?<![\w-])\+?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\w)")
_PHONE_BARE = re.compile(r"\+?\d{10,15}")
_URL = re.compile(r"https?://\S+")


# C0 controls (CR, LF and TAB included), DEL, C1 controls and the Unicode line and paragraph separators: none may reach a
# subject or a header field, where a line break starts a new header. Every variable is a single-line value.
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def refuse_control(what: str, value: str, error: type[Exception] = NotifyRefused) -> str:
    """``value`` unchanged, or ``error`` naming ``what`` when it holds a control character (CR and LF included)."""
    if _CONTROL.search(str(value)):
        raise error(f"{what} contains a control character (a line break or another); refused before any send")
    return value


def check_variable(name: str, value: str) -> None:
    text = str(value)
    refuse_control(f"template variable '{name}'", text)
    if _URL.fullmatch(text):
        return
    if _EMAIL.search(text):
        raise NotifyRefused(f"template variable '{name}' looks like an email address", code='notify_variable_looks_like_email')
    if _PHONE_BARE.fullmatch(text.replace(" ", "")) or _PHONE_FORMATTED.search(text):
        raise NotifyRefused(f"template variable '{name}' looks like a phone number", code='notify_variable_looks_like_phone')


def _inv_check(template: str, variables: dict) -> dict[str, str]:
    if template not in TEMPLATE_TYPES:
        raise NotifyRefused(f"unknown template '{template}'", code='notify_unknown_template')
    allowed = VARIABLES[template]
    extra = sorted(set(variables) - set(allowed))
    if extra:
        raise NotifyRefused(f"template '{template}' does not take variable '{extra[0]}'", code='notify_unexpected_variable')
    missing = [k for k in allowed if k not in variables or str(variables[k]).strip() == ""]
    if missing:
        raise NotifyRefused(f"template '{template}' is missing variable '{missing[0]}'", code='notify_missing_variable')
    clean = {k: str(v) for k, v in variables.items()}
    for k, v in clean.items():
        check_variable(k, v)
    return clean


_SUBJECT = {
    "invite": "You have been invited to {company} on ConsentVault",
    "security_alert": "Security alert for {company} on ConsentVault",
    "delivery_failure": "Delivery failures for {company}: {failed_count} this {period}",
    "billing_notice": "Billing notice for {company}",
}

_TEXT = {
    "invite": (
        "{inviter_name} invited you to join {company} on ConsentVault.\n\n"
        "Accept the invite: {accept_url}\n"
        "This invite expires {expires_at}.\n\n"
        "If you were not expecting it, ignore this email and nothing happens.\n"
    ),
    "security_alert": (
        "We noticed something on the {company} account: {event}.\n"
        "When: {when}\n\n"
        "Review it: {review_url}\n\n"
        "If this was you, no action is needed. If not, review access right away.\n"
    ),
    "delivery_failure": (
        "{failed_count} deliveries to your systems failed for {company} this {period}.\n\n"
        "Details: {details_url}\n\n"
        "Your records are safe. Failed deliveries are kept and can be retried.\n"
    ),
    "billing_notice": (
        "{notice}\n"
        "Account: {company}\n"
        "Amount: {amount}\n\n"
        "Invoice: {invoice_url}\n"
    ),
}

_FOOT = "ConsentVault, consentvault.ai. This is a service message about your account."


def render(template: str, variables: dict) -> tuple[str, str, str]:
    """Return (subject, text, html). Raises NotifyRefused on any bad template or variable."""
    clean = _inv_check(template, variables)
    subject = refuse_control("the subject", _SUBJECT[template].format(**clean))
    text = _TEXT[template].format(**clean) + "\n" + _FOOT + "\n"
    esc = {k: escape(v, quote=True) for k, v in clean.items()}
    body = _TEXT[template].format(**esc)
    paras = "".join(
        f"<p>{p.replace(chr(10), '<br>')}</p>" for p in body.strip().split("\n\n")
    )
    for k in ("accept_url", "review_url", "details_url", "invoice_url"):
        if k in esc:
            paras = paras.replace(esc[k], f'<a href="{esc[k]}">{esc[k]}</a>')
    html = (
        '<div style="font-family:Arial,sans-serif;font-size:15px;color:#1a1a1a;max-width:560px">'
        f"{paras}<p style=\"color:#666;font-size:12px\">{escape(_FOOT)}</p></div>"
    )
    return subject, text, html
