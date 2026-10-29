"""Amazon SESv2 SendEmail sender, hand-signed with SigV4. No boto3; the HTTP transport is injected."""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from .base import Message
from .errors import NotifyConfigError, SendFailed


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: dict
    body: bytes


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes


def urllib_transport(request: HttpRequest, timeout: float = 20.0) -> HttpResponse:
    req = urllib.request.Request(request.url, data=request.body, headers=request.headers, method=request.method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return HttpResponse(resp.status, resp.read())
    except urllib.error.HTTPError as exc:
        return HttpResponse(exc.code, exc.read())


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sign_v4(*, method: str, host: str, path: str, body: bytes, region: str, service: str,
            access_key: str, secret_key: str, now: datetime, session_token: str | None = None) -> dict:
    amz = now.strftime("%Y%m%dT%H%M%SZ")
    day = now.strftime("%Y%m%d")
    headers = {"content-type": "application/json", "host": host, "x-amz-date": amz}
    if session_token:
        headers["x-amz-security-token"] = session_token
    names = sorted(headers)
    canonical_headers = "".join(f"{n}:{headers[n]}\n" for n in names)
    signed = ";".join(names)
    payload = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([method, path, "", canonical_headers, signed, payload])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + secret_key).encode(), day), region), service), "aws4_request")
    sig = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    out = {k: v for k, v in headers.items() if k != "host"}
    out["Authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return out


class SesSender:
    provider = "ses"

    def __init__(self, *, region: str, access_key: str, secret_key: str, sender: str,
                 session_token: str | None = None, transport=urllib_transport, clock=None) -> None:
        if not (region and access_key and secret_key and sender):
            raise NotifyConfigError("SES sender needs region, access key, secret key and a from address")
        self.region, self.sender = region, sender
        self._ak, self._sk, self._tok = access_key, secret_key, session_token
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def send(self, message: Message) -> str:
        host = f"email.{self.region}.amazonaws.com"
        path = "/v2/email/outbound-emails"
        body = json.dumps({
            "FromEmailAddress": self.sender,
            "Destination": {"ToAddresses": [message.to]},
            "Content": {"Simple": {
                "Subject": {"Data": message.subject, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": message.text, "Charset": "UTF-8"},
                         "Html": {"Data": message.html, "Charset": "UTF-8"}},
            }},
        }).encode()
        headers = sign_v4(method="POST", host=host, path=path, body=body, region=self.region, service="ses",
                          access_key=self._ak, secret_key=self._sk, now=self._clock(), session_token=self._tok)
        try:
            resp = self._transport(HttpRequest("POST", f"https://{host}{path}", headers, body))
        except (OSError, TimeoutError) as exc:
            raise SendFailed("ses", type(exc).__name__) from None
        if resp.status != 200:
            raise SendFailed("ses", "refused", resp.status)  # the body can quote the address; never carried
        try:
            return json.loads(resp.body)["MessageId"]
        except (ValueError, KeyError) as exc:
            raise SendFailed("ses", "no_message_id", 200) from None
