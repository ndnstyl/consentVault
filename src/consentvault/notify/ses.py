"""Amazon SESv2 SendEmail sender, hand-signed with SigV4. No boto3; the HTTP transport is injected."""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from ..safelog import http_error_response
from ..errors import ConsentVaultError
from .base import Message
from .errors import NotifyConfigError, NotifyRefused, SendFailed
from .templates import refuse_control
from ..urlguard import require_url, open_no_redirect


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
    require_url(request.url, host_pattern=r"email\.[a-z0-9-]+\.amazonaws\.com")
    req = urllib.request.Request(request.url, data=request.body, headers=request.headers, method=request.method)
    try:
        with open_no_redirect(req, timeout=timeout, host_pattern=r"email\.[a-z0-9-]+\.amazonaws\.com", loopback_http=False) as resp:
            return HttpResponse(resp.status, resp.read())
    except urllib.error.HTTPError as exc:
        status, _headers, body = http_error_response(exc)
        return HttpResponse(status, body)


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

    def __init__(self, *, region: str, sender: str, access_key: str | None = None, secret_key: str | None = None,
                 session_token: str | None = None, credentials=None, configuration_set: str | None = None,
                 transport=urllib_transport, clock=None) -> None:
        """Static keys, or ``credentials``: an object whose ``get()`` returns the current keys (the task role's,
        ``providers.rds_iam.ContainerCredentials``), read for every send."""
        if credentials is not None and (access_key or secret_key or session_token):
            raise NotifyConfigError("SES sender takes static keys or a credential source, never both")
        if credentials is not None and not callable(getattr(credentials, "get", None)):
            raise NotifyConfigError("SES sender's credential source must offer get()")
        if not (region and sender and (credentials is not None or (access_key and secret_key))):
            raise NotifyConfigError("SES sender needs region, a from address and an access key and secret key or a "
                                    "credential source")
        refuse_control("the From address", sender, NotifyConfigError)
        self.region, self.sender = region, sender
        self._ak, self._sk, self._tok = access_key, secret_key, session_token
        self._creds = credentials
        # Sends through this SES configuration set (its bounce and complaint events reach the alarm relay), each tagged
        # cv_template=<template type> so the event names the template.
        self.configuration_set = configuration_set
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def send(self, message: Message) -> str:
        for what, value in (("the subject", message.subject), ("the recipient", message.to), ("the From address", self.sender)):
            refuse_control(what, value, NotifyRefused)
        host = f"email.{self.region}.amazonaws.com"
        path = "/v2/email/outbound-emails"
        request = {
            "FromEmailAddress": self.sender,
            "Destination": {"ToAddresses": [message.to]},
            "Content": {"Simple": {
                "Subject": {"Data": message.subject, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": message.text, "Charset": "UTF-8"},
                         "Html": {"Data": message.html, "Charset": "UTF-8"}},
            }},
        }
        if self.configuration_set:
            request["ConfigurationSetName"] = self.configuration_set
        if message.template:
            request["EmailTags"] = [{"Name": "cv_template", "Value": message.template}]
        body = json.dumps(request).encode()
        ak, sk, tok = self._ak, self._sk, self._tok
        if self._creds is not None:
            try:
                c = self._creds.get()
            except (ConsentVaultError, OSError) as exc:  # the task role's keys could not be read: a failed send, named
                raise SendFailed("ses", "credentials_unavailable", type(exc).__name__) from None
            ak, sk, tok = c.access_key, c.secret_key, c.session_token
        headers = sign_v4(method="POST", host=host, path=path, body=body, region=self.region, service="ses",
                          access_key=ak, secret_key=sk, now=self._clock(), session_token=tok)
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
