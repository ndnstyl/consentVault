"""The record link page and its JSON: one renderer, so the public page and the sender's preview are the same bytes.

``render_page(view)`` is pure: the same view gives the same bytes, with nothing in them that belongs to the request or to the
moment (no id of the link, no clock). Every string that came from outside (the wording, a certificate value, the contact, the page
address, the organisation's name) is escaped text, and a certificate value becomes a link only through ``share.certificate_link``.
The page loads nothing from anywhere: its one style block and its one script are inline, and the response's content-security
policy names the SHA-256 of each, so a script that is not ours cannot run.

The script (``edge/public-verify/recompute.js``) does two small things with values already on the page: it recomputes each
SHA-256 in the visitor's browser, and it gives the match box and the file link the address of this page. With scripts off, the
page reads in full; only the in-browser recompute and the match box need them.

No string here is a verdict. The page states what was recomputed, from what, and whether it equals the stored value.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
from dataclasses import dataclass
from pathlib import Path

from .errors import ConsentVaultError
from .ledger import canonical_dumps
from .share import CODE_VERSION, RULE_SET

ASSET_DIRS = (Path(__file__).resolve().parent / "_public_verify", Path(__file__).resolve().parents[2] / "edge" / "public-verify")
NOT_FOUND_BODY = b"This record link was not found."
WITHDRAWN_BODY = b"This record link was withdrawn by the sender."
LOCKED_STATEMENT = "The match box is locked until the sender resets it."
MATCH_STATEMENT_YES = "The contact you typed gives the same fingerprint as this record: yes."
MATCH_STATEMENT_NO = "The contact you typed gives the same fingerprint as this record: no."


class AssetMissing(ConsentVaultError):
    """A page asset (the style or the script) is not where the renderer looks. The page is never served without them."""


def _asset(name: str) -> str:
    for d in ASSET_DIRS:
        p = d / name
        if p.is_file():
            return p.read_text(encoding="utf-8")
    raise AssetMissing(f"the public page asset {name} was not found in {[str(d) for d in ASSET_DIRS]}; the page is not served without it")


def _csp_hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"


@dataclass(frozen=True)
class Rendered:
    html: bytes
    csp: str


def e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _yes_no(flag) -> str:
    return "not recomputed here" if flag is None else ("yes" if flag else "no")


def _check_block(c: dict) -> str:
    expect = c["stored"] or (c["output"] if c["equal"] is None and c["output"] else "")
    recompute = (c["algorithm"] == "sha256" and c["output"] and c["input"] != "(withheld input)"
                 and c["input"] != "(columns the post does not have)")
    pre = (f'<pre data-recompute="sha256" data-expect="{e(expect)}">{e(c["input"])}</pre><p class="small browser"></p>'
           if recompute else f"<pre>{e(c['input'])}</pre>")
    stored = (f"<span class=\"label\">Stored value</span><pre>{e(c['stored'])}</pre>" if c["stored"]
              else f'<span class="label">Stored value</span><p class="small">{e(c["stored_note"] or "none")}</p>')
    note = f'<p class="small">{e(c["stored_note"])}</p>' if c["stored"] and c["stored_note"] else ""
    return (f'<div class="check"><h3>{e(c["name"].capitalize())}</h3><p class="small">{e(c["what"])}</p>'
            f'<span class="label">Input</span>{pre}<span class="label">Output</span><pre>{e(c["output"])}</pre>{stored}{note}'
            f'<p><span class="label">Equal to the stored value: {e(_yes_no(c["equal"]))}</span></p></div>')


def _values(r) -> str:
    if r is None:
        return "not read"
    if r["state"] in ("not_sent", "unmapped", "body_unreadable", "erased"):
        return {"not_sent": "not sent", "unmapped": "not read: the form has no field map",
                "body_unreadable": "not read: the body could not be read", "erased": "not readable"}[r["state"]]
    return " | ".join(f"<code>{e(v)}</code>" for v in r["values"]) or "not sent"


def _page_body(v: dict) -> str:
    ev, f = v["event"], v["flags"]
    out = ['<h1>Consent record</h1>']
    if v["org_name"]:
        out.append(f'<p class="stmt"><strong>Seller:</strong> {e(v["org_name"])}</p>')
    out.append(f'<p class="stmt">{e(v["statements"]["one_record"])}</p>')
    out.append(f'<p class="stmt">{e(v["statements"]["not_an_opinion"])}</p>')
    out.append(f'<p class="stmt">{e(v["statements"]["chain"])}</p>')

    out.append("<h2>What the form sent</h2><dl>")
    out.append(f'<dt>Consent box, as sent by the form</dt><dd>{_values(v["consent_box"])}</dd>')
    out.append(f'<dt>Decision time, as sent</dt><dd>{_values(v["decision_time_sent"])}</dd>')
    out.append(f'<dt>Arrival time at the vault</dt><dd><code>{e(v["arrival_time"])}</code></dd>')
    for s in v["seals"]:
        out.append(f'<dt>Timestamp authority signing time</dt><dd><code>{e(s["gen_time"])}</code></dd>')
    if f["show_contact"] and v["contact"] is not None:
        out.append(f'<dt>Contact point</dt><dd><code>{e(v["contact"])}</code></dd>')
    if f["show_page_url"] and v["page_url"] is not None:
        out.append(f'<dt>Page address</dt><dd><code>{e(v["page_url"])}</code></dd>')
    if f["show_bot_check"] and ev.get("bot_check") is not None:
        out.append(f'<dt>Bot check, as recorded</dt><dd><code>{e(ev["bot_check"])}</code></dd>')
    out.append("</dl>")

    out.append("<h2>Wording</h2>")
    reg = v["wording_registered"]
    if reg:
        out.append(f'<p class="small">Wording text registered by the sender, as stored (label {e(reg["label"])}, language {e(reg["locale"])}).</p>'
                   f'<blockquote>{e(reg["text"])}</blockquote><dl><dt>SHA-256 of this text</dt><dd><code>{e(reg["computed_sha256"])}</code></dd>'
                   f'<dt>Wording hash the row carries</dt><dd><code>{e(ev["disclosure_sha256"])}</code></dd></dl>')
    else:
        out.append("<p>The row carries no wording.</p>")
    sent = v["wording_sent"]
    if sent:
        out.append(f'<p class="small">Wording text as sent in the post.</p><blockquote>{e(sent["text"])}</blockquote><dl>'
                   f'<dt>SHA-256 of this text</dt><dd><code>{e(sent["sha256"])}</code></dd>'
                   f'<dt>Same hash as the wording the row carries</dt><dd>{_yes_no(sent["equals_event_wording_hash"])}</dd>'
                   + (f'<dt>Wording hash the form sent</dt><dd><code>{e(sent["sent_hash"])}</code></dd>'
                      f'<dt>Same hash as the wording hash the form sent</dt><dd>{_yes_no(sent["equals_sent_hash"])}</dd>'
                      if sent["sent_hash"] is not None else "") + "</dl>")

    out.append("<h2>Certificates the form sent</h2>")
    for c in v["certificates"]:
        shown = []
        for item in c["values"]:
            link = item["link"]
            shown.append(f'<a href="{e(link)}" rel="noreferrer noopener">{e(item["text"])}</a>' if link else f'<code>{e(item["text"])}</code>')
        state = {"sent": "", "not_sent": "not sent", "sent_more_than_once": "sent more than once", "not_read": "not read",
                 "erased": "not readable", "unmapped": "not read", "body_unreadable": "not read"}.get(c["state"], c["state"])
        out.append(f'<p><strong>{e(c["label"])}</strong>: {" | ".join(shown) if shown else e(state)}'
                   f'<br><span class="small">{e(c["note"])}. This page does not fetch it.</span></p>')

    out.append("<h2>The sealed row</h2><dl>")
    out.append(f'<dt>Sequence number</dt><dd>{e(ev["seq"])}</dd><dt>Row hash</dt><dd><code>{e(ev["row_hash"])}</code></dd>'
               f'<dt>Previous hash</dt><dd><code>{e(ev["prev_hash"])}</code></dd><dt>Hash version</dt><dd>{e(ev["hash_version"])}</dd>')
    for s in v["seals"]:
        out.append(f'<dt>Seal digest</dt><dd><code>{e(s["digest"])}</code></dd><dt>Seal authority</dt><dd>{e(s["tsa_url"])}</dd>')
    for a in v["anchors"]:
        out.append(f'<dt>Anchor at or after this row</dt><dd>sequence {e(a["seq"])}, <code>{e(a["row_hash"])}</code>, written {e(a["anchored_at"])}</dd>')
    out.append("</dl>")
    if v["post"]:
        p = v["post"]
        out.append(f'<h2>The stored post</h2><dl><dt>Post sequence number</dt><dd>{e(p["seq"])}</dd><dt>Post row hash</dt><dd><code>{e(p["row_hash"])}</code></dd>'
                   f'<dt>Body SHA-256</dt><dd><code>{e(p["body_sha256"])}</code></dd><dt>Body size in bytes</dt><dd>{e(p["body_bytes"])}</dd></dl>')
        if p["body_withheld"]:
            out.append("<p>The body of the post is withheld on this link. Its hash and its seal are shown above and in the file.</p>")

    out.append("<h2>Recomputed checks</h2>")
    out.append('<p class="small">Each check shows what went in, what came out and whether it equals the value the vault stored. '
               f'Code version {e(v["code_version"])}, rule set {e(v["rule_set"])}.</p>')
    if v["withheld"]:
        out.append(f'<p class="small">This link withholds the column {e(", ".join(v["withheld"]))}, which is an input of three of the checks below.</p>')
    out.extend(_check_block(c) for c in v["checks"])

    out.append('<h2>The one-record file</h2><p id="file">To download the one-record file, add <code>/record.zip</code> to the address of this page. '
               'The JSON form of this page is the address of this page followed by <code>.json</code>.</p>'
               '<p class="small">The file holds the row, the seals and a small program that recomputes the checks with Python and openssl on your own machine, '
               'against a timestamp authority root certificate you obtain yourself. It does not check where this record sits in the whole chain.</p>')
    if f["allow_contact_match"]:
        out.append('<h2>Check a contact</h2><p class="small">Type a phone number or email address. The page answers only whether it gives the same fingerprint '
                   'as this record. Nothing you type is stored. The sender sets a limit on tries a day. This needs scripts on.</p>'
                   '<form id="match" method="post" action="#"><label for="contact" class="label">Phone number or email address</label>'
                   '<input id="contact" name="contact" type="text" autocomplete="off" required><button type="submit">Check</button></form>'
                   '<p id="match-result" aria-live="polite"></p>')
    out.append(f'<p class="small">Page code {e(CODE_VERSION)}. Rule set {e(RULE_SET)}. The sender is responsible for what this record means; '
               'this page does not decide it.</p>')
    return "".join(out)


def render_page(view: dict) -> Rendered:
    css, js = _asset("page.css"), _asset("recompute.js")
    doc = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"><title>Consent record</title>'
           f'<style>{css}</style></head><body>{_page_body(view)}<script>{js}</script></body></html>')
    csp = ("default-src 'none'; style-src " + _csp_hash(css) + "; script-src " + _csp_hash(js) +
           "; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
    return Rendered(doc.encode("utf-8"), csp)


def public_json(view: dict) -> dict:
    """The page as data: the same view without the bytes behind it. Nothing here the page does not show."""
    return {k: v for k, v in view.items() if k != "_raw"}


def render_json(view: dict) -> bytes:
    return (canonical_dumps(public_json(view)) + "\n").encode("utf-8")
