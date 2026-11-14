"""The providers a confirmation goes out through, and the one error they share.

Every adapter object has the shape confirmations.md section 13 names: ``read_sender(creds)`` (text), ``send(creds, ...)`` and,
for email, ``domain_verified(creds, domain)``. An adapter raises ``ProviderError(kind, code)`` where ``kind`` is
``"retry"`` (a timeout, 429 or 5xx: try again), ``"refuse"`` (this message is refused) or ``"account"`` (the account itself is
refused: authentication failed or the account is suspended), or ``TimeoutError`` when the provider did not answer.

Every call leaves through ``urlguard.open_no_redirect``: https only, the provider's own host, no redirect followed. A provider's
error text is never carried into an exception: only its kind and code, so a number or address the provider echoes back cannot
reach a log, an alarm or a list.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from ..safelog import http_error_response
from ..urlguard import open_no_redirect

TIMEOUT_SECONDS = 15.0
TWILIO_HOST = r"(api|messaging)\.twilio\.com"
SES_HOST = r"email\.[a-z0-9-]+\.amazonaws\.com"
POSTMARK_HOST = r"api\.postmarkapp\.com"
DNS_HOST = r"cloudflare-dns\.com"


class ProviderError(Exception):
    """A provider answered, and the answer is a refusal or a request to try again. Carries ``kind`` and ``code`` only."""

    def __init__(self, kind: str, code):
        if kind not in ("retry", "refuse", "account"):
            raise ValueError(f"a provider error is retry, refuse or account, not {kind!r}")
        super().__init__(f"{kind} {code}")
        self.kind, self.code = kind, code


def _call(req: urllib.request.Request, host: str) -> tuple[int, bytes]:
    try:
        resp = open_no_redirect(req, timeout=TIMEOUT_SECONDS, host_pattern=host, loopback_http=False)
        return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, _headers, body = http_error_response(exc)
        return status, body
    except urllib.error.URLError as exc:  # no answer at all: the caller treats it as unreachable
        raise TimeoutError("the provider could not be reached") from exc


def _json(raw: bytes) -> dict:
    try:
        out = json.loads(raw.decode("utf-8")) if raw else {}
    except (ValueError, UnicodeDecodeError):
        return {}
    return out if isinstance(out, dict) else {}


def _fail(status: int, code, *, account_statuses=(401, 403)) -> ProviderError:
    if status in account_statuses:
        return ProviderError("account", code if code is not None else status)
    if status == 429 or status >= 500:
        return ProviderError("retry", code if code is not None else status)
    return ProviderError("refuse", code if code is not None else status)


class TwilioProvider:
    """Twilio: a Messaging Service or a single number, sent with an API key. The account auth token is never used here."""

    ACCOUNT_CODES = {20003, 20005, 20008, 20404}

    def _auth(self, creds: dict) -> dict:
        sid, secret = creds.get("api_key_sid"), creds.get("api_key_secret")
        if not sid or not secret:
            raise ProviderError("refuse", "credentials_incomplete")
        token = base64.b64encode(f"{sid}:{secret}".encode()).decode()
        return {"Authorization": f"Basic {token}", "Accept": "application/json"}

    def _account_sid(self, creds: dict) -> str:
        sid = creds.get("account_sid")
        if not sid:
            raise ProviderError("refuse", "account_sid_required")
        return urllib.parse.quote(sid, safe="")

    def _get(self, creds: dict, url: str) -> dict:
        status, raw = _call(urllib.request.Request(url, headers=self._auth(creds), method="GET"), TWILIO_HOST)
        body = _json(raw)
        if status != 200:
            raise _fail(status, body.get("code"))
        return body

    def read_sender(self, creds: dict) -> dict:
        sender = creds.get("sender") or {}
        service = sender.get("messaging_service_sid")
        if service:
            svc = urllib.parse.quote(service, safe="")
            info = self._get(creds, f"https://messaging.twilio.com/v1/Services/{svc}")
            numbers = self._get(creds, f"https://messaging.twilio.com/v1/Services/{svc}/PhoneNumbers")
            return {"numbers": [n["phone_number"] for n in numbers.get("phone_numbers", []) if n.get("phone_number")],
                    "inbound_webhook": info.get("inbound_request_url")}
        number = sender.get("number")
        if not number:
            raise ProviderError("refuse", "sender_required")
        query = urllib.parse.urlencode({"PhoneNumber": number})
        found = self._get(creds, f"https://api.twilio.com/2010-04-01/Accounts/{self._account_sid(creds)}"
                                 f"/IncomingPhoneNumbers.json?{query}")
        mine = [n for n in found.get("incoming_phone_numbers", []) if n.get("phone_number") == number]
        if not mine:
            raise ProviderError("refuse", "number_not_on_account")
        return {"numbers": [number], "inbound_webhook": mine[0].get("sms_url")}

    def message_exists(self, creds: dict, *, message_id: str, from_number: str) -> bool:
        """Whether the provider holds this inbound message from this number (a START is confirmed here before it lifts a stop)."""
        if not isinstance(message_id, str) or not message_id.isalnum():
            return False
        url = f"https://api.twilio.com/2010-04-01/Accounts/{self._account_sid(creds)}/Messages/{message_id}.json"
        status, raw = _call(urllib.request.Request(url, headers=self._auth(creds), method="GET"), TWILIO_HOST)
        if status == 404:
            return False
        body = _json(raw)
        if status != 200:
            raise _fail(status, body.get("code"))
        return str(body.get("direction", "")).startswith("inbound") and body.get("from") == from_number

    def send(self, creds: dict, *, to: str, body: str, sender: str, status_callback: str) -> dict:
        form = {"To": to, "Body": body, "StatusCallback": status_callback}
        form["MessagingServiceSid" if sender.startswith("MG") else "From"] = sender
        req = urllib.request.Request(
            f"https://api.twilio.com/2010-04-01/Accounts/{self._account_sid(creds)}/Messages.json",
            data=urllib.parse.urlencode(form).encode(), headers={**self._auth(creds),
                                                                "Content-Type": "application/x-www-form-urlencoded"},
            method="POST")
        status, raw = _call(req, TWILIO_HOST)
        out = _json(raw)
        if status in (200, 201) and out.get("sid"):
            return {"provider_message_id": out["sid"], "status": out.get("status")}
        code = out.get("code")
        if code in self.ACCOUNT_CODES:
            raise ProviderError("account", code)
        raise _fail(status, code)


class SesProvider:
    """Amazon SES (the v2 API), signed with the organization's own access key."""

    def _signed(self, creds: dict, method: str, path: str, body: bytes) -> tuple[str, dict]:
        from ..notify.ses import sign_v4

        region = creds.get("region") or "us-east-1"
        host = f"email.{region}.amazonaws.com"
        headers = sign_v4(method=method, host=host, path=path, body=body, region=region, service="ses",
                          access_key=creds.get("access_key", ""), secret_key=creds.get("secret", ""),
                          now=datetime.now(timezone.utc))
        return f"https://{host}{path}", headers

    def domain_verified(self, creds: dict, domain: str) -> bool:
        if not creds.get("access_key") or not creds.get("secret"):
            raise ProviderError("refuse", "credentials_incomplete")
        url, headers = self._signed(creds, "GET", "/v2/email/identities/" + urllib.parse.quote(domain, safe=""), b"")
        status, raw = _call(urllib.request.Request(url, headers=headers, method="GET"), SES_HOST)
        if status == 404:
            return False
        if status != 200:
            raise _fail(status, _json(raw).get("__type") or _json(raw).get("message_code"))
        return bool(_json(raw).get("VerifiedForSendingStatus"))

    def send(self, creds: dict, *, to: str, subject: str, body: str, headers: dict, sender: dict) -> dict:
        from_addr = f'"{sender["display_name"]}" <{sender["email_address"]}>' if sender.get("display_name") else sender["email_address"]
        payload = json.dumps({
            "FromEmailAddress": from_addr, "Destination": {"ToAddresses": [to]},
            "Content": {"Simple": {"Subject": {"Data": subject, "Charset": "UTF-8"},
                                   "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
                                   "Headers": [{"Name": k, "Value": v} for k, v in headers.items()]}}}).encode()
        url, signed = self._signed(creds, "POST", "/v2/email/outbound-emails", payload)
        status, raw = _call(urllib.request.Request(url, data=payload, headers=signed, method="POST"), SES_HOST)
        out = _json(raw)
        if status == 200 and out.get("MessageId"):
            return {"provider_message_id": out["MessageId"]}
        kind = (out.get("__type") or "").split("#")[-1]
        if kind in ("AccountSuspendedException", "SendingPausedException", "UnrecognizedClientException",
                    "InvalidSignatureException", "AccessDeniedException"):
            raise ProviderError("account", kind)
        raise _fail(status, kind or None)


class PostmarkProvider:
    """Postmark: a server token sends. Whether a sender domain is verified is read only with an account token, which the
    organization may add to its credentials; without one the domain cannot be shown verified and the connection is refused."""

    def domain_verified(self, creds: dict, domain: str) -> bool:
        token = creds.get("account_token")
        if not creds.get("server_token"):
            raise ProviderError("refuse", "credentials_incomplete")
        if not token:
            return False
        req = urllib.request.Request("https://api.postmarkapp.com/domains?count=500&offset=0",
                                     headers={"Accept": "application/json", "X-Postmark-Account-Token": token})
        status, raw = _call(req, POSTMARK_HOST)
        if status != 200:
            raise _fail(status, _json(raw).get("ErrorCode"))
        for item in _json(raw).get("Domains", []):
            if str(item.get("Name", "")).lower() == domain.lower():
                detail = urllib.request.Request(f"https://api.postmarkapp.com/domains/{int(item['ID'])}",
                                                headers={"Accept": "application/json", "X-Postmark-Account-Token": token})
                st2, raw2 = _call(detail, POSTMARK_HOST)
                if st2 != 200:
                    raise _fail(st2, _json(raw2).get("ErrorCode"))
                d = _json(raw2)
                return bool(d.get("DKIMVerified")) and bool(d.get("ReturnPathDomainVerified"))
        return False

    def send(self, creds: dict, *, to: str, subject: str, body: str, headers: dict, sender: dict) -> dict:
        from_addr = f'"{sender["display_name"]}" <{sender["email_address"]}>' if sender.get("display_name") else sender["email_address"]
        payload = json.dumps({"From": from_addr, "To": to, "Subject": subject, "TextBody": body,
                              "Headers": [{"Name": k, "Value": v} for k, v in headers.items()],
                              "MessageStream": "outbound"}).encode()
        req = urllib.request.Request("https://api.postmarkapp.com/email", data=payload, method="POST", headers={
            "Accept": "application/json", "Content-Type": "application/json",
            "X-Postmark-Server-Token": creds.get("server_token", "")})
        status, raw = _call(req, POSTMARK_HOST)
        out = _json(raw)
        if status == 200 and out.get("ErrorCode") == 0 and out.get("MessageID"):
            return {"provider_message_id": out["MessageID"]}
        code = out.get("ErrorCode")
        if code in (10, 100):
            raise ProviderError("account", code)
        raise _fail(status, code)


class DohResolver:
    """DNS lookups of CNAME and TXT answered over https by a public resolver (the vault holds no DNS library)."""

    def lookup(self, host: str, kind: str):
        if kind not in ("CNAME", "TXT"):
            raise ValueError("kind is CNAME or TXT")
        query = urllib.parse.urlencode({"name": host, "type": kind})
        req = urllib.request.Request(f"https://cloudflare-dns.com/dns-query?{query}", headers={"Accept": "application/dns-json"})
        status, raw = _call(req, DNS_HOST)
        if status != 200:
            raise TimeoutError("the resolver did not answer")
        want = 5 if kind == "CNAME" else 16
        for answer in _json(raw).get("Answer", []):
            if answer.get("type") == want:
                value = str(answer.get("data", "")).strip()
                return value.strip('"') if kind == "TXT" else value.rstrip(".")
        return None


def default_providers() -> dict:
    ses, postmark = SesProvider(), PostmarkProvider()
    return {"twilio": TwilioProvider(), "ses": ses, "postmark": postmark}
