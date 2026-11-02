"""The alarm relay: operator alarms reach the platform alerts channel.

``relay_once`` reads the alarms not yet relayed (``consentvault.alarm_relay_pending``: kind, organisation id, counts and
times only), publishes each one, and marks it relayed (``alarm_relay_mark``) only after the publish succeeded. A publish
is retried with backoff; an alarm that still cannot be published stays unrelayed, is named in the answer, and the job
exits non-zero, and the batch stops there (the channel is down; the rest wait for the next run). An alarm older than the
heartbeat limit that is still unrelayed when the job starts is its own failure (the relay was down or failing). The message
carries no reference id, request id or personal field.

One run at a time: a run takes a session advisory lock first; a run that finds it held does nothing and says so. In the
cloud each run that published everything sends a heartbeat metric (``ConsentVault``/``Heartbeat``, dimension
``Job=alarm-relay``, value 1, nothing else); a missing heartbeat is an alarm in the ops repo, so a relay that never runs
is loud too.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping

from .safelog import describe, http_error_response
from .errors import ConsentVaultError
from .urlguard import open_no_redirect

HEARTBEAT_LIMIT = timedelta(minutes=15)
RETRY_DELAYS_S = (1.0, 2.0, 4.0)
BATCH = 200
RELAY_LOCK_SQL = "SELECT pg_try_advisory_lock(hashtext('consentvault.alarm_relay')) AS got"
RELAY_UNLOCK_SQL = "SELECT pg_advisory_unlock(hashtext('consentvault.alarm_relay')) AS released"
HEARTBEAT_NAMESPACE = "ConsentVault/Heartbeat/alarm-relay"  # one namespace per job: IAM scopes PutMetricData by namespace
HEARTBEAT_JOB = "alarm-relay"
HEARTBEAT_NAMESPACE_PREFIX = "ConsentVault/Heartbeat/"


def heartbeat_namespace(job: str) -> str:
    """Each job's own CloudWatch namespace; its task role may write that one and no other."""
    return HEARTBEAT_NAMESPACE_PREFIX + job


class RelayPublishError(ConsentVaultError):
    """A message could not be published after every retry."""


def message_for(row: Mapping) -> str:
    """The published text: alarm kind, organisation id, counts and times. Nothing else leaves the database."""
    return json.dumps({"alarm": row["name"], "error_class": row["error_class"], "ref_kind": row["ref_kind"],
                       "org_id": str(row["org_id"]), "alarm_id": str(row["alarm_id"]),
                       "raised_at": row["raised_at"].astimezone(timezone.utc).isoformat(),
                       "unrelayed_in_org": int(row["unrelayed_in_org"])}, sort_keys=True)


class LogSink:
    """Self-host: one JSON line per alarm appended to a file the operator tails or ships."""

    def __init__(self, path: str):
        self._path = path

    def publish(self, subject: str, message: str) -> None:
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(message + "\n")
        except OSError as exc:
            raise RelayPublishError(f"the alert log {self._path} could not be written: {type(exc).__name__}") from exc


SNS_HOST_PATTERN = r"sns\.[a-z0-9-]+\.amazonaws\.com"
MONITORING_HOST_PATTERN = r"monitoring\.[a-z0-9-]+\.amazonaws\.com"
PUBLISH_TIMEOUT_S = 10.0


def _urllib_transport(timeout_s: float = PUBLISH_TIMEOUT_S, host_pattern: str = SNS_HOST_PATTERN):
    """The only way the relay reaches AWS: ``urlguard.open_no_redirect`` (https to an exact SNS or CloudWatch host, no
    redirect followed, one overall deadline, the environment proxy honoured)."""
    def send(method, url, headers, body):
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
        try:
            with open_no_redirect(req, timeout=timeout_s, host_pattern=host_pattern, loopback_http=False) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:  # loud-failure-exempt: a non-2xx or redirect answer is returned to publish(), which raises on it
            return http_error_response(e)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise RelayPublishError(f"{urllib.parse.urlsplit(url).hostname} could not be reached: {type(exc).__name__}") from exc

    return send


class SnsTopic:
    """Cloud: an SNS topic, published with the task role's own AWS access (SigV4, no SDK)."""

    def __init__(self, topic_arn: str, region: str, aws_access, *, transport=None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self._arn, self._region, self._aws = topic_arn, region, aws_access
        self._host = f"sns.{region}.amazonaws.com"
        self._send = transport or _urllib_transport()
        self._clock = clock

    def publish(self, subject: str, message: str) -> None:
        from .providers.evidence import _sha256_hex, sigv4_headers

        body = urllib.parse.urlencode({"Action": "Publish", "Version": "2010-03-31", "TopicArn": self._arn,
                                       "Subject": subject[:100], "Message": message}).encode("utf-8")
        c = self._aws.get()
        signed = sigv4_headers(method="POST", host=self._host, path="/", headers={
            "content-type": "application/x-www-form-urlencoded"}, payload_sha256=_sha256_hex(body),
            access_key=c.access_key, secret_key=c.secret_key, region=self._region, service="sns",
            amz_date=self._clock().astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), session_token=c.session_token)
        headers = {k: v for k, v in signed.items() if k != "host"}
        status, _, answer = self._send("POST", f"https://{self._host}/", headers, body)
        if status != 200:
            raise RelayPublishError(f"SNS answered HTTP {status}: {answer[:200].decode('utf-8', 'replace')}")


class CloudWatchHeartbeat:
    """Cloud: one ``PutMetricData`` per successful run, with the task role's own AWS access (SigV4, no SDK). The metric
    is ``Heartbeat`` with one dimension, ``Job``, in the job's own namespace; it carries nothing else."""

    def __init__(self, region: str, aws_access, *, job: str = HEARTBEAT_JOB, transport=None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self._region, self._aws, self._job = region, aws_access, job
        self._host = f"monitoring.{region}.amazonaws.com"
        self._send = transport or _urllib_transport(host_pattern=MONITORING_HOST_PATTERN)
        self._clock = clock

    def beat(self) -> None:
        from .providers.evidence import _sha256_hex, sigv4_headers

        body = urllib.parse.urlencode({"Action": "PutMetricData", "Version": "2010-08-01",
                                       "Namespace": heartbeat_namespace(self._job),
                                       "MetricData.member.1.MetricName": "Heartbeat", "MetricData.member.1.Value": "1",
                                       "MetricData.member.1.Unit": "Count",
                                       "MetricData.member.1.Dimensions.member.1.Name": "Job",
                                       "MetricData.member.1.Dimensions.member.1.Value": self._job}).encode("utf-8")
        c = self._aws.get()
        signed = sigv4_headers(method="POST", host=self._host, path="/", headers={
            "content-type": "application/x-www-form-urlencoded"}, payload_sha256=_sha256_hex(body),
            access_key=c.access_key, secret_key=c.secret_key, region=self._region, service="monitoring",
            amz_date=self._clock().astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), session_token=c.session_token)
        headers = {k: v for k, v in signed.items() if k != "host"}
        status, _, answer = self._send("POST", f"https://{self._host}/", headers, body)
        if status != 200:
            raise RelayPublishError(f"CloudWatch answered HTTP {status} to the heartbeat: "
                                    f"{answer[:200].decode('utf-8', 'replace')}")


def _publish_with_retry(sink, subject: str, message: str, sleep: Callable[[float], None]) -> None:
    errors: list[str] = []
    for delay in (0.0, *RETRY_DELAYS_S):
        if delay:
            sleep(delay)
        try:
            sink.publish(subject, message)
            return
        except RelayPublishError as exc:  # loud-failure-exempt: kept in `errors`; exhausting the retries raises them below
            errors.append(describe(exc))
    spent = RelayPublishError(f"after {len(errors)} attempts: {errors[-1]}", code="publish_retries_spent")
    spent.attempts = len(errors)
    raise spent


def relay_once(conn, sink, *, sleep: Callable[[float], None] = time.sleep,
               now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> dict:
    """Relay every pending alarm. Answers ``{relayed, failed: [{alarm_id, name, error}], stale: [{alarm_id, ...}], skipped,
    already_running}``. ``already_running`` is true (nothing was read or published) when another run holds the relay lock.
    The first publish that exhausts its retries stops the batch; ``skipped`` counts the alarms left for the next run. The
    lock is a session lock: released here after the run, and by the connection's close if the run raised."""
    if not conn.execute(RELAY_LOCK_SQL).fetchone()["got"]:
        return {"relayed": 0, "failed": [], "stale": [], "skipped": 0, "already_running": True}
    out = _relay_locked(conn, sink, sleep, now)
    if not conn.execute(RELAY_UNLOCK_SQL).fetchone()["released"]:
        raise RelayPublishError("the alarm relay lock was not held at the end of the run")
    return out


def _relay_locked(conn, sink, sleep, now) -> dict:
    rows = conn.execute("SELECT * FROM consentvault.alarm_relay_pending(%s)", (BATCH,)).fetchall()
    started = now()
    out: dict = {"relayed": 0, "failed": [], "skipped": 0, "already_running": False, "stale": [
        {"alarm_id": str(r["alarm_id"]), "name": r["name"],
         "age_minutes": int((started - r["raised_at"]).total_seconds() // 60)}
        for r in rows if started - r["raised_at"] > HEARTBEAT_LIMIT]}
    for i, r in enumerate(rows):
        try:
            _publish_with_retry(sink, f"consentvault alarm {r['name']}", message_for(r), sleep)
        except RelayPublishError as exc:  # loud-failure-exempt: recorded in out["failed"], which the command turns into exit 2 naming the alarm
            out["failed"].append({"alarm_id": str(r["alarm_id"]), "name": r["name"], "error": describe(exc),
                                  "attempts": getattr(exc, "attempts", None)})
            out["skipped"] = len(rows) - i - 1  # the channel is down: the rest stay unrelayed for the next run
            break
        # marked only now, after the publish succeeded; a failed mark leaves it unrelayed and it is published again
        marked = conn.execute("SELECT consentvault.alarm_relay_mark(%s, %s) AS m", (r["org_id"], r["alarm_id"])).fetchone()
        if not marked["m"]:
            out["failed"].append({"alarm_id": str(r["alarm_id"]), "name": r["name"], "error": "published but not marked"})
            continue
        out["relayed"] += 1
    return out
