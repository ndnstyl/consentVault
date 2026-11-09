"""The two public pages on an organization's own wording link host (confirmations.md sections 6 and 7).

* ``GET /c/r/{token}``  the agreed-wording page a text links to: the brand, the exact wording, the date and time, the channels and
  purposes and how to stop. Never the contact point, a name or a company.
* ``GET /c/stop/{token}`` and ``POST /c/stop/{token}``  the email stop page: stop email, or stop everything. The same POST carries
  the one-click unsubscribe of the email's ``List-Unsubscribe-Post`` header (RFC 8058), which stops email only.

A token belongs to one organization and is looked up on that organization's own verified host only: a token presented on any other
host is not found. Only a hash of a token is stored.
"""

from __future__ import annotations

import hashlib
import html
import re
import urllib.parse
from datetime import datetime

from .. import door
from ..tenancy import crypto as tc
from . import basis, zones
from .core import ALL_CHANNELS, KEY_ERRORS, STOP_CHANNELS, RECORDED_BY, Reply, SYSTEM_STOP_PAGE, log
from .inbound import RECORD_ERRORS

PATH = re.compile(r"^/c/(r|stop)/([A-Za-z0-9_-]{8,128})$")
HEADERS = {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
           "Referrer-Policy": "no-referrer",
           "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"}
STYLE = ("body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5}"
         "button{display:block;width:100%;margin:.75rem 0;padding:.9rem;font-size:1rem}blockquote{border-left:3px solid #999;margin:1rem 0;"
         "padding:.25rem 1rem;white-space:pre-wrap}")


def _page(title: str, body_html: str, status: int = 200) -> Reply:
    doc = (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,"
           f"initial-scale=1\"><title>{html.escape(title)}</title><style>{STYLE}</style></head><body>{body_html}</body></html>")
    return Reply(status, raw=doc.encode("utf-8"), headers=dict(HEADERS))


class PublicMixin:
    def handle_public(self, method: str, path: str, host: str, headers: dict, body: bytes = b"") -> Reply:
        match = PATH.match(path or "")
        if match is None or method not in ("GET", "POST"):
            return _page("Not found", "<p>Not found.</p>", 404)
        what, token = match.groups()
        if what == "r" and method != "GET":
            return _page("Not allowed", "<p>Not allowed.</p>", 405)
        conn = self._connect()
        try:
            org = conn.execute("SELECT consentvault.confirmation_host_lookup(%s) AS o", ((host or "").split(":")[0].lower(),)).fetchone()["o"]
        finally:
            conn.close()
        if org is None:
            return _page("Not found", "<p>Not found.</p>", 404)
        digest = hashlib.sha256(token.encode()).hexdigest()
        try:
            with self.tx(org) as conn:
                tok = conn.execute("SELECT * FROM consentvault.confirmation_page_token WHERE org_id = %s AND token_hash = %s",
                                   (org, digest)).fetchone()
                if tok is None or tok["kind"] != ("wording" if what == "r" else "stop"):
                    return _page("Not found", "<p>Not found.</p>", 404)
                settings = self._settings_row(conn)
                brand = settings["organization_name"] if settings else "this organization"
                if what == "r":
                    return self._wording_page(conn, org, tok, brand, settings)
                if method == "GET":
                    return self._stop_form(brand)
                return self._stop(conn, org, tok, brand, headers or {}, body or b"")
        except RECORD_ERRORS as exc:
            log.error("a public confirmation page could not be answered", error=type(exc).__name__)
            brand = self._brand_of(org)
            if what == "stop" and method == "POST":
                return self._stop_form(brand, notice="Your request was not recorded. Please try again.", status=503)
            return _page("Try again", "<p>This page could not be shown. Please try again.</p>", 503)

    # ---- the wording page ---------------------------------------------------------------------------------------------------
    def _wording_page(self, conn, org, tok: dict, brand: str, settings) -> Reply:
        how_to_stop = ("<p>To stop, reply STOP to any text from us. Reply STOP to opt out of texts and calls. "
                       "To stop email, use the link in any email we send.</p>")
        if tok["is_test"]:
            return _page(f"{brand}: test message", f"<h1>{html.escape(brand)}</h1><p>This page was linked from a test message. In a real "
                         f"message it shows the exact wording the person agreed to.</p>{how_to_stop}")
        it = conn.execute("SELECT basis_event_id, basis_history_event_id, contact_fp FROM consentvault.confirmation_send_intent"
                          " WHERE org_id = %s AND send_id = %s", (org, tok["send_id"])).fetchone()
        ev = basis.event_like(conn, org, it["basis_event_id"] or it["basis_history_event_id"])
        wording = conn.execute("SELECT body FROM consentvault.disclosure WHERE org_id = %s AND sha256 = %s",
                               (org, ev["disclosure_sha256"])).fetchone()["body"]
        zone = None
        try:
            key = self._contact_key(conn, org, ev["contact_fp"])
            if key is not None:
                zone = zones.zone_for_phone(tc.decrypt_text(key, org, str(ev["event_id"]), "contact_norm", bytes(ev["contact_ct"])))
        except KEY_ERRORS:
            zone = None  # the page names UTC when the zone cannot be worked out
        labels = self._purpose_labels(conn, org, ev["purposes"])
        names = {"sms": "texts", "voice": "calls", "artificial_voice": "automated calls", "email": "email"}
        channels = ", ".join(names[c] for c in ALL_CHANNELS if c in ev["channels"])
        return _page(f"{brand}: what you agreed to",
                     f"<h1>{html.escape(brand)}</h1><p>On {html.escape(zones.format_when(ev['received_at'], zone))} you agreed to the "
                     f"following:</p><blockquote>{html.escape(wording)}</blockquote><p>Channels: {html.escape(channels)}. "
                     f"Purposes: {html.escape(labels)}.</p>{how_to_stop}")

    # ---- the email stop page ------------------------------------------------------------------------------------------------
    def _stop_form(self, brand: str, notice: str = "", status: int = 200) -> Reply:
        b = html.escape(brand)
        note = f"<p role=\"alert\">{html.escape(notice)}</p>" if notice else ""
        return _page(f"{brand}: stop messages",
                     f"<h1>{b}</h1>{note}<p>Choose what to stop.</p><form method=\"post\">"
                     f"<button type=\"submit\" name=\"scope\" value=\"email\">Stop email from {b}</button>"
                     f"<button type=\"submit\" name=\"scope\" value=\"everything\">Stop everything from {b}: email, texts and calls</button>"
                     f"</form>", status)

    def _stop(self, conn, org, tok: dict, brand: str, headers: dict, body: bytes) -> Reply:
        params = dict(urllib.parse.parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
        one_click = params.get("List-Unsubscribe") == "One-Click"
        scope = "email" if one_click else params.get("scope")
        if scope not in ("email", "everything"):
            return _page("Not understood", "<p>That request was not understood.</p>", 400)
        it = conn.execute("SELECT basis_event_id, basis_history_event_id, contact_fp FROM consentvault.confirmation_send_intent"
                          " WHERE org_id = %s AND send_id = %s", (org, tok["send_id"])).fetchone()
        kind, norm, _ = self._contact_of_event(conn, org, it["basis_event_id"] or it["basis_history_event_id"])
        have = self._org_channels(conn)
        channels = ["email"] if scope == "email" else [c for c in ALL_CHANNELS if c in have]
        # "Stop everything" means the person, not the one address. Who the person is comes from the records layer's link
        # (records.md section 1), never from scanning events: every other contact point whose current record belongs to the same
        # person as this address's current record is stopped too, on the channels that fit it. A number since reassigned (its
        # current record is another person's) is not this person's to stop. Anything that cannot be stopped fails the request.
        todo = []
        if not all(self._stop_on_record(conn, org, it["contact_fp"], ch) for ch in channels):
            todo.append((norm, channels, None))
        if scope == "everything":
            for other in conn.execute("SELECT contact_fp, contact_kind, event_id FROM consentvault.confirmation_person_contacts(%s)",
                                      (it["contact_fp"],)).fetchall():
                other_channels = [c for c in STOP_CHANNELS if c in have] if other["contact_kind"] == "phone" else ["email"]
                if not other_channels or all(self._stop_on_record(conn, org, other["contact_fp"], ch) for ch in other_channels):
                    continue
                _, other_norm, _ = self._contact_of_event(conn, org, other["event_id"])
                todo.append((other_norm, other_channels, other["contact_fp"]))
        if not todo:
            return Reply(200, raw=b"Already stopped.", headers=dict(HEADERS)) if one_click else \
                _page("Already stopped", f"<h1>{html.escape(brand)}</h1><p>Already stopped.</p>")
        source = self._system_source(conn, SYSTEM_STOP_PAGE)
        for contact, chans, _ in todo:
            door.record_observed(conn, self.crypto, intake="stop_page", fields=dict(
                contact=contact, event_type="revoke", channels=chans, purposes=["*"], method="checkbox", origin="consumer",
                source_id=source, recorded_by=RECORDED_BY))
        if one_click:
            return Reply(200, raw=b"Stopped.", headers=dict(HEADERS))
        what = "email" if scope == "email" else "email, texts and calls"
        return _page("Stopped", f"<h1>{html.escape(brand)}</h1><p>Done. We have recorded your request to stop {what} "
                     f"from {html.escape(brand)}.</p>")

    def _brand_of(self, org) -> str:
        try:
            with self.tx(org) as conn:
                s = self._settings_row(conn)
            return s["organization_name"] if s else "this organization"
        except RECORD_ERRORS:  # loud-failure-exempt: the page then names no organization; the failure itself was logged above
            return "this organization"
