"""Anchoring: write the current head of the chain somewhere the database owner cannot quietly rewrite.

``anchor`` records (seq, row_hash, time) in ``chain_head`` and in an external sink, a file path (one JSON
record appended per line) or an http(s) webhook that receives the same record as a JSON POST. ``verify_chain``
then fails when any row up to an anchor is missing or changed, which is what a truncated tail looks like.

The cloud's sink is ``s3://<bucket>``: the log-archive account's anchor bucket, where each head becomes one write-once object
``anchors/<org id>/anchors/<seq>-<hash>.json`` under Object Lock (COMPLIANCE, seven years), written with the anchor job's own task
role access (``providers.anchors.S3ObjectLockAnchorSink``). Writing the same head again is a no-op; a different head at the
same key is refused. In the cloud a file path is refused: a task's disk is lost when the task stops.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import psycopg

from .safelog import describe
from .errors import AnchorError, ChainError, ConfigError
from .ledger import verify_chain
from .urlguard import require_url, open_no_redirect

HTTP_TIMEOUT_S = 20
ENV_ANCHOR_SINK = "CONSENTVAULT_ANCHOR_SINK"
ANCHOR_RETAIN_DAYS = 365 * 7
ANCHOR_PREFIX = "anchors"
CREDENTIAL_URIS = ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_S3_SINKS: dict = {}


def _is_url(sink: str) -> bool:
    return urllib.parse.urlparse(sink).scheme in ("http", "https")


def is_s3(sink: str) -> bool:
    return urllib.parse.urlsplit(sink or "").scheme == "s3"


def cloud_sink(cfg, env=None) -> str:
    """The configured sink. In the cloud (``db_auth = iam``) only an ``s3://`` bucket or an https webhook: a file path is on
    the task's own disk, which is lost when the task stops. An ``s3://`` sink is built here, so a malformed one, or one
    missing its region or task role, stops the run before any organisation is worked."""
    sink = cfg.require_anchor_sink()
    if cfg.db_auth == "iam" and not (is_s3(sink) or urllib.parse.urlsplit(sink).scheme == "https"):
        raise ConfigError(f"{ENV_ANCHOR_SINK} names a file or a plain http address, which the cloud loses when a task "
                          "stops; set it to s3://<anchor bucket>. Nothing was anchored")
    if is_s3(sink) and sink not in _S3_SINKS:
        _S3_SINKS[sink] = s3_sink(sink, env=env)
    return sink


def s3_sink(sink: str, *, env=None, transport=None, clock=None, credentials=None):
    """The Object Lock sink for ``s3://<bucket>`` (no prefix, query or user part), in ``AWS_REGION`` with the task role's
    access. A ``ConfigError`` names what is wrong; nothing is called here."""
    from .providers.anchors import S3ObjectLockAnchorSink
    from .providers.evidence import S3ObjectLockEvidenceStore
    from .providers.rds_iam import ContainerCredentials

    env = os.environ if env is None else env
    u = urllib.parse.urlsplit(sink)
    if (u.scheme != "s3" or not _BUCKET.match(u.netloc or "") or u.path not in ("", "/") or u.query or u.fragment):
        raise ConfigError(f"{ENV_ANCHOR_SINK} must be s3://<bucket> with a lowercase bucket name and nothing after it")
    region = (env.get("AWS_REGION") or "").strip()
    if not region:
        raise ConfigError(f"the s3 anchor sink needs AWS_REGION for {ENV_ANCHOR_SINK}; nothing was anchored")
    if credentials is None:
        if not any((env.get(n) or "").strip() for n in CREDENTIAL_URIS):
            raise ConfigError(f"the s3 anchor sink writes with the task role's access, and neither {CREDENTIAL_URIS[0]} "
                              f"nor {CREDENTIAL_URIS[1]} is set; nothing was anchored")
        credentials = ContainerCredentials(env=env)
    extra = {"clock": clock} if clock is not None else {}
    # Every object under anchors/: the bucket also holds the erasure ledger, and the anchor job's role may write this
    # prefix only, never overwriting (tofu/data iam.tf and the org stack's bucket policy).
    store = S3ObjectLockEvidenceStore(endpoint="https" + f"://s3.{region}.amazonaws.com", bucket=u.netloc, region=region,
                                      credentials=credentials, transport=transport, prefix=ANCHOR_PREFIX, **extra)
    return S3ObjectLockAnchorSink(store, retain_days=ANCHOR_RETAIN_DAYS, label=f"s3://{u.netloc}", **extra)


def publish_s3(target: str, org_id: str, record: dict, *, sink=None) -> None:
    """Write one head to ``target`` (``s3://<bucket>``); the sink is built once per process from the environment."""
    from .providers.errors import ProviderError

    if sink is None:
        sink = _S3_SINKS.get(target)
        if sink is None:
            sink = _S3_SINKS[target] = s3_sink(target)
    try:
        sink.publish(org_id, record)
    except ProviderError as exc:
        raise AnchorError(f"the anchor object could not be written to {sink_label(target)}: {describe(exc)}",
                          code="s3_write_refused") from exc


def sink_label(sink: str) -> str:
    """What is stored in chain_head.sink: the path, or the URL without credentials or query string."""
    if not _is_url(sink):
        return sink
    u = urllib.parse.urlsplit(sink)
    host = u.hostname or ""
    if u.port:
        host += f":{u.port}"
    return f"{u.scheme}://{host}{u.path}"


def _write_file(path: str, line: str) -> None:
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        raise AnchorError(f"cannot append to the anchor file {path}: {describe(exc)}") from exc


def _post(url: str, body: str) -> None:
    require_url(url, loopback_http=True)
    req = urllib.request.Request(
        url, data=body.encode("utf-8"), method="POST", headers={"Content-Type": "application/json"})
    try:
        with open_no_redirect(req, timeout=HTTP_TIMEOUT_S) as resp:
            if not 200 <= resp.status < 300:
                raise AnchorError(f"anchor webhook {sink_label(url)} answered HTTP {resp.status}", code=f"http_{int(resp.status)}")
    except urllib.error.HTTPError as exc:
        raise AnchorError(f"anchor webhook {sink_label(url)} answered HTTP {exc.code}", code=f"http_{int(exc.code)}") from exc
    except OSError as exc:
        raise AnchorError(f"anchor webhook {sink_label(url)} unreachable: {describe(exc)}") from exc


def _anchor_raw_posts(conn: psycopg.Connection, sink: str, when: datetime, org: str, tenant: bool) -> dict | None:
    """Anchor the head of the organisation's raw-post chain the way the event head is anchored: verified first, written to the
    sink (a file, a webhook or an S3 object lock bucket), then recorded in raw_post_chain_head.
    None when the organisation has no raw post yet."""
    from .rawpost import verify_raw_chain

    breaks = verify_raw_chain(conn)
    if breaks:
        raise ChainError(f"refusing to anchor a broken raw post chain: {len(breaks)} break(s), first at seq {breaks[0]['seq']}")
    head = conn.execute("SELECT seq, row_hash FROM consentvault.raw_post WHERE org_id = consentvault.current_org()"
                        " ORDER BY seq DESC LIMIT 1").fetchone()
    if head is None:
        return None
    record = {"chain": "raw_post", "seq": head["seq"], "row_hash": head["row_hash"],
              "anchored_at": when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
    if tenant:
        record["org_id"] = org
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    if is_s3(sink):
        publish_s3(sink, org, record)  # a write-once object under its own folder, so the outside record exists for raw heads too
    elif _is_url(sink):
        _post(sink, line)
    else:
        _write_file(sink, line)
    try:
        row = conn.execute(
            "INSERT INTO consentvault.raw_post_chain_head (seq, row_hash, sink, anchored_at) VALUES (%s, %s, %s, %s)"
            " RETURNING head_uuid", (head["seq"], head["row_hash"], sink_label(sink), when)).fetchone()
    except psycopg.Error as exc:
        raise AnchorError(f"the raw post head was written to the sink but raw_post_chain_head refused it: {describe(exc)}") from exc
    return {**record, "sink": sink_label(sink), "anchor_id": str(row["head_uuid"])}


def anchor(conn: psycopg.Connection, sink: str, *, now: datetime | None = None) -> dict:
    """Anchor the current head of both chains (the events and the raw posts). Refuses an empty or broken ledger; the sink is
    written before the database row. The answer is the event head's record, with the raw post head's under ``raw_post``."""
    if not sink:
        raise AnchorError("no anchor sink configured", code="no_anchor_sink")
    breaks = verify_chain(conn)
    if breaks:
        raise ChainError(f"refusing to anchor a broken chain: {len(breaks)} break(s), first at seq {breaks[0].seq}")
    head = conn.execute("SELECT seq, row_hash FROM consentvault.event WHERE org_id = consentvault.current_org()"
                        " ORDER BY seq DESC LIMIT 1").fetchone()
    when = now or datetime.now(timezone.utc)
    orgs = conn.execute("SELECT consentvault.current_org() AS org, consentvault.home_org() AS home").fetchone()
    tenant = orgs["org"] != orgs["home"]  # a tenant's sink record names its organisation (verify_chain reads it)
    result: dict = {}
    if head is not None:
        record = {"seq": head["seq"], "row_hash": head["row_hash"],
                  "anchored_at": when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
        if tenant:
            record["org_id"] = str(orgs["org"])
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        if is_s3(sink):
            publish_s3(sink, str(orgs["org"]), record)
        elif _is_url(sink):
            _post(sink, line)
        else:
            _write_file(sink, line)
        try:
            row = conn.execute(
                "INSERT INTO consentvault.chain_head (seq, row_hash, sink, anchored_at) VALUES (%s, %s, %s, %s)"
                " RETURNING head_uuid",
                (head["seq"], head["row_hash"], sink_label(sink), when),
            ).fetchone()
        except psycopg.Error as exc:
            raise AnchorError(
                f"the head was written to the sink but chain_head refused it: {describe(exc)}") from exc
        result = {**record, "sink": sink_label(sink), "anchor_id": str(row["head_uuid"])}
    raw = _anchor_raw_posts(conn, sink, when, str(orgs["org"]), tenant)
    if head is None and raw is None:
        raise AnchorError("the ledger is empty; there is no head to anchor")
    if raw is not None:
        result["raw_post"] = raw
        result.setdefault("anchor_id", raw["anchor_id"])
        result.setdefault("sink", raw["sink"])
    return result
