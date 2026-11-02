"""``consentvault alarm-relay``: publish operator alarms to the platform alerts channel (scheduled every 5 minutes).

Cloud (``db_auth = iam``): ``CONSENTVAULT_ALERTS_TOPIC_ARN``, an SNS topic, published with the task role's own AWS access; a
local log file is refused. Self-host: ``CONSENTVAULT_ALERTS_LOG``, a file one JSON line is appended to. Exactly one is set.
The login is the worker group's (``CONSENTVAULT_DSN``): it can read and mark alarms only through two functions and
nothing else. Exit 2 names every alarm that could not be published, or a heartbeat that could not be sent; exit 3 says an
alarm waited past the heartbeat limit. A run that finds another run holding the relay lock does nothing and exits 0 with a
line saying so. In the cloud every run that published everything sends one heartbeat metric (a missing one is an alarm).

In the cloud the relay also drains the SES events queue (``CONSENTVAULT_SES_EVENTS_QUEUE_URL``, required there): each
product-email bounce or complaint becomes a send-log row and an alarm on the same topic (``notify.events``). A row or an
alarm that cannot be written leaves the event queued, exits 2 and sends no heartbeat.
"""

from __future__ import annotations

import json
import os
import sys

from .safelog import describe
from .cli import EXIT_BROKEN, EXIT_ERROR, EXIT_OK, register
from .errors import ConfigError

ENV_TOPIC = "CONSENTVAULT_ALERTS_TOPIC_ARN"
ENV_LOG = "CONSENTVAULT_ALERTS_LOG"


def alert_sink(env, *, cloud: bool):
    from .alarm_relay import LogSink, SnsTopic
    from .providers.rds_iam import ContainerCredentials as TaskRoleAccess

    topic, path = env.get(ENV_TOPIC), env.get(ENV_LOG)
    if topic and path:
        raise ConfigError(f"set one alert sink, not both: {ENV_TOPIC} (cloud) or {ENV_LOG} (self-host); nothing was run")
    if cloud and path:
        raise ConfigError(f"{ENV_LOG} is a local file and is refused in cloud mode (db_auth = iam): set {ENV_TOPIC}; "
                          "nothing was run")
    if path:
        return LogSink(path)
    if not topic:
        raise ConfigError(f"alarm-relay needs {ENV_TOPIC} (cloud) or {ENV_LOG} (self-host); nothing was run")
    region = env.get("AWS_REGION")
    if not region:
        raise ConfigError(f"alarm-relay needs AWS_REGION for {ENV_TOPIC}; nothing was run")
    return SnsTopic(topic, region, TaskRoleAccess(env=env))


def heartbeat_for(env):
    """The cloud's heartbeat (CloudWatch, the task role's access) when the sink is the SNS topic; the self-host has none."""
    from .alarm_relay import CloudWatchHeartbeat
    from .providers.rds_iam import ContainerCredentials as TaskRoleAccess

    if not env.get(ENV_TOPIC):
        return None
    region = env.get("AWS_REGION")
    if not region:
        raise ConfigError("alarm-relay needs AWS_REGION for its heartbeat; nothing was run")
    return CloudWatchHeartbeat(region, TaskRoleAccess(env=env))


def events_queue_for(env, *, cloud: bool):
    """The SES events queue the cloud relay drains (product-email bounces and complaints); none in the self-host."""
    from .notify.events import events_queue

    return events_queue(env, cloud=cloud)


def _send_log_connect(dsn: str):
    from .db import connect

    return connect(dsn)


def _drain_mail_events(queue, sink, dsn: str) -> dict:
    """Each bounce or complaint: a send-log row as this login (the worker group appends), then an alarm on the same sink."""
    from .notify import Notifier, PostgresSendLog
    from .notify.events import ProviderOnly, StrictTopicAlarm, drain

    return drain(queue, Notifier(ProviderOnly(), PostgresSendLog(lambda: _send_log_connect(dsn)), StrictTopicAlarm(sink)))


def _run_alarm_relay(args, cfg) -> int:
    from .alarm_relay import RelayPublishError, relay_once
    from .db import connect
    from .notify.errors import SendLogError
    from .notify.events import EventsError

    cloud = cfg.db_auth == "iam"
    sink = alert_sink(os.environ, cloud=cloud)
    beat = heartbeat_for(os.environ)
    queue = events_queue_for(os.environ, cloud=cloud)  # refused here, before anything runs, when the cloud lacks it
    dsn = cfg.require_dsn()
    with connect(dsn) as conn:
        done = relay_once(conn, sink)
    if done["already_running"]:
        print(json.dumps(done, sort_keys=True))
        print("consentvault: alarm-relay already running in another process; this run did nothing", file=sys.stderr)
        return EXIT_OK
    if done["failed"]:
        print(json.dumps(done, sort_keys=True))
        names = ", ".join(f"{f['name']} {f['alarm_id']}" for f in done["failed"])
        print(f"consentvault: alarm-relay could not publish: {names}"
              + (f"; {done['skipped']} more left for the next run" if done["skipped"] else ""), file=sys.stderr)
        return EXIT_ERROR
    if queue is not None:
        try:
            done["mail_events"] = _drain_mail_events(queue, sink, dsn)
        except (EventsError, SendLogError) as exc:
            print(json.dumps(done, sort_keys=True))
            print(f"consentvault: alarm-relay could not record the product-email bounces; they stay queued: "
                  f"{describe(exc)}", file=sys.stderr)
            return EXIT_ERROR
    print(json.dumps(done, sort_keys=True))
    try:
        if beat is not None:
            beat.beat()
    except RelayPublishError as exc:
        print(f"consentvault: alarm-relay heartbeat could not be sent: {describe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    if done["stale"]:
        worst = max(s["age_minutes"] for s in done["stale"])
        print(f"consentvault: alarm-relay heartbeat failure: {len(done['stale'])} alarm(s) waited past 15 minutes "
              f"(oldest {worst} minutes) before this run; they are relayed now", file=sys.stderr)
        return EXIT_BROKEN
    return EXIT_OK


register("alarm-relay", "publish operator alarms to the alerts channel (SNS topic in the cloud, a log file in the self-host)",
         _run_alarm_relay)
