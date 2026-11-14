"""The cloud's product email: Amazon SES with the vault task role's own access, the send log, and the platform alerts topic.

Two classes the cloud names in its settings (``module:Class`` with ``from_environment``):

- ``SesMailer`` (``CONSENTVAULT_MAILER``): sends invitations. The link is ``<CONSENTVAULT_PORTAL_URL>/invite?token=<token>``,
  the dashboard's invitation page.
- ``SesNotifier`` (``CONSENTVAULT_NOTIFIER``): the ``Notifier`` the lifecycle routes use for security alerts, delivery
  failures and billing notices.

Both send through SES SendEmail from ``CONSENTVAULT_MAIL_FROM``, through the configuration set
``CONSENTVAULT_SES_CONFIGURATION_SET`` (its bounces and complaints reach the alarm relay, ``notify.events``), with the task
role's keys (read for every send, so a rotated
key is picked up), write one row per attempt to the send log (``consentvault.notify_send_log``: type, recipient domain,
outcome, provider id; never a body or an address), and on a failed send or a bounce publish an alarm to the platform
alerts topic ``CONSENTVAULT_ALERTS_TOPIC_ARN``. The alarm message is the alarm's name and its source only: the recipient,
its domain and the provider's text stay out of it (the send log row carries the domain and the provider code). An alarm
that cannot be published is logged as an error by its class; the failed send it was about is still raised.

Every setting is required: a missing value, a blank, or a placeholder (``UNSET:...``) refuses to build with a
``ConfigError`` naming the setting, so the vault never starts with email it cannot send.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Mapping

from .. import safelog
from ..errors import ConfigError, ConsentVaultError
from .base import Alarm, SendLog, Sender
from .service import Notifier

ENV_MAIL_FROM = "CONSENTVAULT_MAIL_FROM"
ENV_PORTAL_URL = "CONSENTVAULT_PORTAL_URL"
ENV_ALERTS_TOPIC = "CONSENTVAULT_ALERTS_TOPIC_ARN"
ENV_CONFIGURATION_SET = "CONSENTVAULT_SES_CONFIGURATION_SET"
_CONFIG_SET = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ENV_REGION = "AWS_REGION"
CREDENTIAL_URIS = ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI")
PLACEHOLDER = "UNSET"
ALARM_SOURCE = "consentvault.notify"

_FROM = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")
_TOPIC = re.compile(r"^arn:aws:sns:(?P<region>[a-z]{2}(-[a-z]+)+-\d+):\d{12}:[A-Za-z0-9_-]{1,256}$")
_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")

log = safelog.get("consentvault.notify.cloud")


def setting(env: Mapping[str, str], name: str) -> str:
    """The value of ``name``, or a ``ConfigError`` naming it when it is missing, blank or still a placeholder."""
    value = (env.get(name) or "").strip()
    if not value:
        raise ConfigError(f"the cloud's product email needs {name}; nothing was started")
    if value.split(":", 1)[0] == PLACEHOLDER:
        raise ConfigError(f"{name} is still a placeholder ({PLACEHOLDER}:...); set the real value. Nothing was started")
    return value


def _from_address(env: Mapping[str, str]) -> str:
    value = setting(env, ENV_MAIL_FROM)
    if not _FROM.match(value):
        raise ConfigError(f"{ENV_MAIL_FROM} must be a bare address on a verified SES domain (name@example.com)")
    return value


def _portal_url(env: Mapping[str, str]) -> str:
    value = setting(env, ENV_PORTAL_URL)
    u = urllib.parse.urlsplit(value)
    if (u.scheme != "https" or not _HOST.match(u.hostname or "") or u.username or u.password or u.port
            or u.path not in ("", "/") or u.query or u.fragment):
        raise ConfigError(f"{ENV_PORTAL_URL} must be the dashboard's https origin only (https://app.example.com)")
    return f"https://{u.hostname}"


def _topic(env: Mapping[str, str], region: str) -> str:
    value = setting(env, ENV_ALERTS_TOPIC)
    m = _TOPIC.match(value)
    if not m or m.group("region") != region:
        raise ConfigError(f"{ENV_ALERTS_TOPIC} must be an SNS topic ARN in {ENV_REGION} ({region})")
    return value


class SnsAlarm:
    """``Alarm`` on the platform alerts topic: the alarm's name and source only, never its detail."""

    def __init__(self, topic) -> None:
        self._topic = topic

    def raise_alarm(self, name: str, detail: str) -> None:  # noqa: ARG002 - the detail can name a recipient's domain
        try:
            self._topic.publish(f"ConsentVault alarm {name}", json.dumps({"alarm": name, "source": ALARM_SOURCE},
                                                                         sort_keys=True))
        except (ConsentVaultError, OSError) as exc:
            # The send this alarm is about is raised by the caller; replacing it with this error would hide it.
            log.error("the alarm could not be published to the alerts topic", alarm=name, error=type(exc).__name__)


def mail_parts(env: Mapping[str, str]) -> tuple[Sender, SendLog, Alarm, str]:
    """(SES sender, send log, alarm, portal origin) from the settings. Calls nothing: credentials are read at the first
    send and the database is opened at the first log row."""
    from .. import db
    from ..alarm_relay import SnsTopic
    from ..config import load_config
    from ..providers.rds_iam import ContainerCredentials
    from .pg_log import PostgresSendLog
    from .ses import SesSender

    region = setting(env, ENV_REGION)
    sender_address = _from_address(env)
    portal = _portal_url(env)
    topic = _topic(env, region)
    if not any((env.get(name) or "").strip() for name in CREDENTIAL_URIS):
        raise ConfigError(f"the cloud's product email sends with the task role's access, and neither {CREDENTIAL_URIS[0]} "
                          f"nor {CREDENTIAL_URIS[1]} is set; nothing was started")
    config_set = setting(env, ENV_CONFIGURATION_SET)
    if not _CONFIG_SET.match(config_set):
        raise ConfigError(f"{ENV_CONFIGURATION_SET} must be an SES configuration set name")
    creds = ContainerCredentials(env=env)
    sender = SesSender(region=region, sender=sender_address, credentials=creds, configuration_set=config_set)
    send_log = PostgresSendLog(db.connect_factory(load_config(env=env)))
    return sender, send_log, SnsAlarm(SnsTopic(topic, region, creds)), portal


class SesNotifier(Notifier):
    """The cloud ``Notifier``: SES, the Postgres send log and the alerts topic."""

    @classmethod
    def from_environment(cls, env: Mapping[str, str]) -> "SesNotifier":
        sender, send_log, alarm, _portal = mail_parts(env)
        return cls(sender, send_log, alarm)


class SesMailer:
    """Invitations through a ``Notifier`` (template ``invite``): logged, alarmed and refused like every other message."""

    def __init__(self, notifier: Notifier, *, portal_url: str) -> None:
        self._notifier = notifier
        self._portal = portal_url.rstrip("/")

    @classmethod
    def from_environment(cls, env: Mapping[str, str]) -> "SesMailer":
        sender, send_log, alarm, portal = mail_parts(env)
        return cls(Notifier(sender, send_log, alarm), portal_url=portal)

    def send_invite(self, *, to: str, org_name: str, role: str, token: str, expires_at: datetime,
                    invited_by_name: str) -> None:
        del role  # the role is shown on the invitation page, read from the invitation itself
        when = expires_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        accept = f"{self._portal}/invite?token={urllib.parse.quote(token, safe='')}"
        self._notifier.send("invite", to, {"company": org_name, "inviter_name": invited_by_name, "accept_url": accept,
                                           "expires_at": when})
