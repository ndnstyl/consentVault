"""Bounces and complaints for the cloud's product email, read from the SES events queue by the alarm-relay job.

SES publishes the BOUNCE and COMPLAINT events of the configuration set the vault sends through to a private SNS topic,
which delivers them raw to a private SQS queue (``CONSENTVAULT_SES_EVENTS_QUEUE_URL``). ``drain`` reads that queue until it
is empty. For each recipient of an event it calls ``Notifier.record_bounce``: one ``bounced`` send-log row (template type
from the send's ``cv_template`` tag, the recipient's domain, the SES message id, the bounce or complaint type), then an
alarm (``notify.bounce`` or ``notify.complaint``). The queue message is deleted only after every recipient's row and alarm
were written; a row or an alarm that cannot be written raises and leaves the message for the next run. An event that
cannot be read (not JSON, an unknown template, no recipient, an event type other than the two) raises
``notify.event_unreadable`` and is deleted, so one malformed message never blocks the queue. SES's own account-level
suppression list keeps a bounced or complaining address from being sent to again.

The queue is reached with the task role's access over SQS's JSON protocol, SigV4-signed, through ``urlguard`` (https to the
exact regional SQS host, no redirect followed). Every refusal is ``EventsError`` with a code; the provider's text, which can
quote an address, is never carried.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Mapping

from ..errors import ConfigError, ConsentVaultError
from .base import TEMPLATE_TYPES

ENV_QUEUE = "CONSENTVAULT_SES_EVENTS_QUEUE_URL"
ALARM_COMPLAINT = "notify.complaint"
ALARM_EVENT_UNREADABLE = "notify.event_unreadable"
SQS_HOST_PATTERN = r"sqs\.[a-z0-9-]+\.amazonaws\.com"
BATCH = 10
MAX_BATCHES = 500  # 5,000 events in one run at most; the rest wait for the next run, five minutes later
TIMEOUT_S = 10.0
CREDENTIAL_URIS = ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI")
_QUEUE = re.compile(r"^https://sqs\.(?P<region>[a-z]{2}(-[a-z]+)+-\d+)\.amazonaws\.com/\d{12}/[A-Za-z0-9_-]{1,80}$")


class EventsError(ConsentVaultError):
    """The events queue could not be read or emptied, or an alarm about an event could not be published."""


class UnreadableEvent(ConsentVaultError):
    """One queue message is not a bounce or complaint this product sent."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _urllib_transport(timeout_s: float = TIMEOUT_S):
    from ..urlguard import open_no_redirect

    def send(method, url, headers, body):
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
        try:
            with open_no_redirect(req, timeout=timeout_s, host_pattern=SQS_HOST_PATTERN, loopback_http=False) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:  # loud-failure-exempt: a non-2xx answer is returned to _call, which raises on it
            return e.code, {}, b""  # the status only: the body can quote a queue or an address, and is never carried
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise EventsError(f"SQS could not be reached ({type(exc).__name__})", code="sqs_unreachable") from exc

    return send


class SqsQueue:
    """``receive()`` up to ten messages (no wait), ``delete(receipt_handle)``. SigV4 with the given credential source."""

    def __init__(self, queue_url: str, region: str, credentials, *, transport=None,
                 clock: Callable[[], datetime] = _utcnow) -> None:
        self.url, self._region, self._creds = queue_url, region, credentials
        self._host = f"sqs.{region}.amazonaws.com"
        self._send = transport or _urllib_transport()
        self._clock = clock

    def _call(self, action: str, params: dict) -> dict:
        from ..providers.evidence import sigv4_headers

        body = json.dumps({"QueueUrl": self.url, **params}, separators=(",", ":")).encode()
        try:
            c = self._creds.get()
        except (ConsentVaultError, OSError) as exc:
            raise EventsError(f"the task role's keys could not be read ({type(exc).__name__})",
                              code="credentials_unavailable") from exc
        signed = sigv4_headers(method="POST", host=self._host, path="/",
                               headers={"content-type": "application/x-amz-json-1.0", "x-amz-target": f"AmazonSQS.{action}"},
                               payload_sha256=hashlib.sha256(body).hexdigest(), access_key=c.access_key,
                               secret_key=c.secret_key, region=self._region, service="sqs",
                               amz_date=self._clock().astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
                               session_token=c.session_token)
        status, _, raw = self._send("POST", f"https://{self._host}/", {k: v for k, v in signed.items() if k != "host"}, body)
        if status != 200:
            raise EventsError(f"SQS {action} answered HTTP {status}", code="sqs_refused")  # the body is never carried
        try:
            return json.loads(raw) if raw else {}
        except ValueError as exc:
            raise EventsError(f"SQS {action} answered a body that is not JSON", code="sqs_unreadable") from exc

    def receive(self) -> list[dict]:
        msgs = self._call("ReceiveMessage", {"MaxNumberOfMessages": BATCH, "WaitTimeSeconds": 0}).get("Messages") or []
        if not isinstance(msgs, list) or not all(isinstance(m, dict) and m.get("ReceiptHandle") for m in msgs):
            raise EventsError("SQS ReceiveMessage answered messages without receipt handles", code="sqs_unreadable")
        return msgs

    def delete(self, receipt_handle: str) -> None:
        self._call("DeleteMessage", {"ReceiptHandle": receipt_handle})


def parse_event(body: str) -> list[tuple[str, str, str, str, str]]:
    """[(kind, template, recipient, SES message id, reason)] for one raw SES event, or ``UnreadableEvent``."""
    try:
        ev = json.loads(body)
    except (TypeError, ValueError) as exc:
        raise UnreadableEvent("the event is not JSON", code="not_json") from exc
    if not isinstance(ev, dict):
        raise UnreadableEvent("the event is not an object", code="not_an_object")
    kind = ev.get("eventType") or ev.get("notificationType")
    mail = ev.get("mail") if isinstance(ev.get("mail"), dict) else {}
    mid = mail.get("messageId")
    tags = mail.get("tags") if isinstance(mail.get("tags"), dict) else {}
    template = (tags.get("cv_template") or [None])[0] if isinstance(tags.get("cv_template"), list) else None
    if kind == "Bounce":
        detail = ev.get("bounce") if isinstance(ev.get("bounce"), dict) else {}
        people, label = detail.get("bouncedRecipients"), "bounce"
        reason = " ".join(str(x) for x in ("bounce", detail.get("bounceType"), detail.get("bounceSubType")) if x)
    elif kind == "Complaint":
        detail = ev.get("complaint") if isinstance(ev.get("complaint"), dict) else {}
        people, label = detail.get("complainedRecipients"), "complaint"
        reason = " ".join(str(x) for x in ("complaint", detail.get("complaintFeedbackType")) if x)
    else:
        raise UnreadableEvent("the event is neither a bounce nor a complaint", code="other_event_type")
    if template not in TEMPLATE_TYPES:
        raise UnreadableEvent("the event names no template this product sends", code="unknown_template")
    if not isinstance(mid, str) or not mid:
        raise UnreadableEvent("the event carries no SES message id", code="no_message_id")
    if not isinstance(people, list) or not people:
        raise UnreadableEvent("the event names no recipient", code="no_recipient")
    out = []
    for p in people:
        addr = p.get("emailAddress") if isinstance(p, dict) else None
        if not isinstance(addr, str) or "@" not in addr:
            raise UnreadableEvent("a recipient in the event has no address", code="no_recipient")
        out.append((label, template, addr, mid, reason[:200]))
    return out


def drain(queue: SqsQueue, notifier) -> dict:
    """Empty the queue (at most ``MAX_BATCHES`` batches). Answers ``{messages, bounces, complaints, unreadable}``."""
    from ..notify.errors import NotifyRefused
    from .service import ALARM_BOUNCE

    out = {"messages": 0, "bounces": 0, "complaints": 0, "unreadable": 0}
    for _ in range(MAX_BATCHES):
        batch = queue.receive()
        if not batch:
            return out
        for msg in batch:
            out["messages"] += 1
            try:
                found = parse_event(msg.get("Body"))
                for label, template, addr, mid, reason in found:
                    notifier.record_bounce(template, addr, mid, reason,
                                           alarm=ALARM_COMPLAINT if label == "complaint" else ALARM_BOUNCE)
                    out["bounces" if label == "bounce" else "complaints"] += 1
            except (UnreadableEvent, NotifyRefused) as exc:  # loud-failure-exempt: raised as its own alarm just below and counted; a publish failure raises
                notifier.alarm.raise_alarm(ALARM_EVENT_UNREADABLE, f"{type(exc).__name__} {getattr(exc, 'code', '')}")
                out["unreadable"] += 1
            queue.delete(msg["ReceiptHandle"])
    return out


def events_queue(env: Mapping[str, str], *, cloud: bool):
    """The events queue for the alarm relay: required in the cloud (``db_auth = iam``), absent in the self-host (its SMTP
    sender has no events). Refused by name while missing, a placeholder, or not an SQS queue URL in ``AWS_REGION``."""
    from ..providers.rds_iam import ContainerCredentials

    value = (env.get(ENV_QUEUE) or "").strip()
    if not cloud and not value:
        return None
    if not value or value.split(":", 1)[0] == "UNSET":
        raise ConfigError(f"the cloud's alarm relay drains product-email bounces from {ENV_QUEUE}, which is not set; "
                          "nothing was run")
    region = (env.get("AWS_REGION") or "").strip()
    m = _QUEUE.match(value)
    if not m or m.group("region") != region:
        raise ConfigError(f"{ENV_QUEUE} must be an https SQS queue URL in AWS_REGION ({region or 'unset'})")
    if not any((env.get(n) or "").strip() for n in CREDENTIAL_URIS):
        raise ConfigError(f"{ENV_QUEUE} is read with the task role's access, and neither {CREDENTIAL_URIS[0]} nor "
                          f"{CREDENTIAL_URIS[1]} is set; nothing was run")
    return SqsQueue(value, region, ContainerCredentials(env=env))


class StrictTopicAlarm:
    """``Alarm`` for the relay: the alarm's name and source on the alerts topic; a publish that fails raises
    ``EventsError`` (the event stays queued), unlike the vault's alarm, which must not hide the send failure it is about."""

    def __init__(self, topic) -> None:
        self._topic = topic

    def raise_alarm(self, name: str, detail: str) -> None:  # noqa: ARG002 - the detail can name a recipient's domain
        try:
            self._topic.publish(f"ConsentVault alarm {name}", json.dumps({"alarm": name, "source": "consentvault.notify"},
                                                                         sort_keys=True))
        except (ConsentVaultError, OSError) as exc:
            raise EventsError(f"the {name} alarm could not be published ({type(exc).__name__})",
                              code="alarm_unpublished") from exc


class ProviderOnly:
    """The sender seat of the relay's ``Notifier``: it names the provider for the log rows and never sends."""

    provider = "ses"

    def send(self, message) -> str:
        raise EventsError("the bounce relay never sends email", code="relay_never_sends")
