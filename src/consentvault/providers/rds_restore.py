"""The cloud restore drill's scratch target: the newest RDS snapshot of the vault's database, restored to one scratch
instance, reached with a password the drill sets and never stores, and deleted afterwards.

The RDS Query API is called with the task role's own AWS access (Signature Version 4, no SDK), and only for the scratch
instance by its fixed name (``cv-restore-drill``): its task role may restore, change and delete that one instance and
nothing else (ops ``tofu/data/iam.tf``). The snapshot is read, never changed.

``restore_latest``:
1. lists the vault instance's available snapshots (``automated`` and ``awsbackup``) and takes the newest; its creation time
   is the restore point;
2. removes a scratch instance an earlier drill left behind once that drill's lease on it (tag ``cv-drill-lease-until``,
   written when the instance is made) is past; an instance still under lease belongs to a running drill, which this one
   never touches: it stops with ``DrillBusy`` instead;
3. restores the snapshot into the scratch instance in the database's own subnet group and security group, private, single
   zone, without deletion protection, tagged ``cv-purpose = restore-drill``, and waits until it is available;
4. sets a fresh random master password on the scratch instance only (``ModifyDBInstance``, applied at once) and waits
   until it is applied. The password lives in this process only;
5. answers the copy's address as its master user over verify-full TLS; the drill then grants that user the operator
   console role on the copy and acts as it.

``discard`` deletes the scratch instance this drill made (never another drill's) (no final snapshot, its automated backups too) and waits until it is gone. Every
wait has a deadline and dies at it by name; every AWS answer that is not a success is a named error.
"""

from __future__ import annotations

import re
import secrets
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping, Optional

from ..safelog import http_error_response
from ..restore_drill import DEFAULT_TARGET_SECONDS, Backup, DrillError, Restored, target_seconds_from


class DrillBusy(DrillError):
    """Another drill still holds the scratch instance; this one restored and removed nothing."""


SCRATCH_ID = "cv-restore-drill"
RDS_HOST_PATTERN = r"rds\.[a-z0-9-]+\.amazonaws\.com"
NS = "{http://rds.amazonaws.com/doc/2014-10-31/}"
SNAPSHOT_TYPES = ("automated", "awsbackup")
CONSOLE_ROLE = "consentvault_console"
# The drill's hold on the one scratch instance: a tag written when the instance is made, naming the time until which the
# drill that made it may still be running (its stated target plus a margin). Before it, another drill
# leaves the instance alone; after it, the instance is stale and is removed.
LEASE_TAG = "cv-drill-lease-until"
# The lease is the drill's own stated target (CONSENTVAULT_RESTORE_DRILL_TARGET_SECONDS, up to seven days) plus this margin:
# a drill still inside its target is never taken for stale, however long the target is.
LEASE_MARGIN_SECONDS = 6 * 3600
ENV = {
    "source": "CONSENTVAULT_RESTORE_DRILL_SOURCE_DB",
    "subnet_group": "CONSENTVAULT_RESTORE_DRILL_SUBNET_GROUP",
    "security_group": "CONSENTVAULT_RESTORE_DRILL_SECURITY_GROUP",
    "instance_class": "CONSENTVAULT_RESTORE_DRILL_INSTANCE_CLASS",
    "parameter_group": "CONSENTVAULT_RESTORE_DRILL_PARAMETER_GROUP",
}
_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]{0,62}$")
_SG = re.compile(r"^sg-[0-9a-f]{8,17}$")
_CLASS = re.compile(r"^db\.[a-z0-9]+\.[a-z0-9]+$")


def _transport(timeout_s: float = 30.0):
    import urllib.error
    import urllib.request

    from ..urlguard import open_no_redirect

    def send(method, url, headers, body):
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
        try:
            with open_no_redirect(req, timeout=timeout_s, host_pattern=RDS_HOST_PATTERN, loopback_http=False) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
        except urllib.error.HTTPError as e:  # loud-failure-exempt: a non-2xx answer is returned to _call, which raises on it
            return http_error_response(e)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise DrillError(f"{urllib.parse.urlsplit(url).hostname} could not be reached: {type(exc).__name__}") from exc

    return send


class RdsSnapshotTarget:
    def __init__(self, *, region: str, aws_access, source_db: str, subnet_group: str, security_group: str,
                 instance_class: str, parameter_group: str, db_name: str, ca_bundle: str, transport=None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc), sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic, poll_s: float = 30.0, deadline_s: float = 3 * 3600,
                 target_seconds: int = DEFAULT_TARGET_SECONDS) -> None:
        for what, value, pattern in (("source database", source_db, _NAME), ("subnet group", subnet_group, _NAME),
                                     ("parameter group", parameter_group, _NAME), ("security group", security_group, _SG),
                                     ("instance class", instance_class, _CLASS)):
            if not isinstance(value, str) or not pattern.match(value):
                raise DrillError(f"the restore drill's {what} {value!r} is not a valid name")
        self._region, self._aws = region, aws_access
        self._host = f"rds.{region}.amazonaws.com"
        self._source, self._subnet, self._sg = source_db, subnet_group, security_group
        self._class, self._params, self._db, self._ca = instance_class, parameter_group, db_name, ca_bundle
        self._send = transport or _transport()
        self._clock, self._sleep, self._mono = clock, sleep, monotonic
        self._poll, self._deadline = poll_s, deadline_s
        self.stale_removed: list[str] = []
        self._owned = False
        self._lease_s = target_seconds + LEASE_MARGIN_SECONDS

    @classmethod
    def from_environment(cls, env: Mapping[str, str]) -> "RdsSnapshotTarget":
        from ..config import DEFAULT_RDS_CA_BUNDLE
        from .rds_iam import ContainerCredentials

        got = {}
        for key, name in ENV.items():
            if not env.get(name):
                raise DrillError(f"the cloud restore drill needs {name}; nothing was restored")
            got[key] = env[name]
        region = env.get("AWS_REGION")
        db_name = env.get("CONSENTVAULT_DB_NAME") or env.get("CV_DB_NAME")
        if not region or not db_name:
            raise DrillError("the cloud restore drill needs AWS_REGION and CONSENTVAULT_DB_NAME (or CV_DB_NAME), the "
                             "database name inside the snapshot; nothing was restored")
        return cls(region=region, aws_access=ContainerCredentials(env=env), source_db=got["source"],
                   subnet_group=got["subnet_group"], security_group=got["security_group"],
                   instance_class=got["instance_class"], parameter_group=got["parameter_group"], db_name=db_name,
                   ca_bundle=env.get("CONSENTVAULT_DB_CA_BUNDLE") or DEFAULT_RDS_CA_BUNDLE,
                   target_seconds=target_seconds_from(env))

    # ---- the RDS Query API -------------------------------------------------------------------------------------------------
    def _call(self, action: str, params: Mapping[str, str], *, missing_ok: Optional[str] = None) -> Optional[ET.Element]:
        from .evidence import _sha256_hex, sigv4_headers

        body = urllib.parse.urlencode({"Action": action, "Version": "2014-10-31", **params}).encode("utf-8")
        c = self._aws.get()
        signed = sigv4_headers(method="POST", host=self._host, path="/",
                               headers={"content-type": "application/x-www-form-urlencoded"},
                               payload_sha256=_sha256_hex(body), access_key=c.access_key, secret_key=c.secret_key,
                               region=self._region, service="rds",
                               amz_date=self._clock().astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
                               session_token=c.session_token)
        status, _, answer = self._send("POST", f"https://{self._host}/", {k: v for k, v in signed.items() if k != "host"},
                                       body)
        try:
            root = ET.fromstring(answer)
        except ET.ParseError as exc:
            raise DrillError(f"RDS {action} answered HTTP {status} with a body that is not XML") from exc
        if status != 200:
            code = root.findtext(f".//{NS}Code") or root.findtext(".//Code") or "unknown"
            if missing_ok is not None and code == missing_ok:
                return None
            msg = root.findtext(f".//{NS}Message") or root.findtext(".//Message") or ""
            raise DrillError(f"RDS {action} answered HTTP {status} {code}: {msg[:300]}")
        return root

    def _instance(self) -> Optional[ET.Element]:
        root = self._call("DescribeDBInstances", {"DBInstanceIdentifier": SCRATCH_ID}, missing_ok="DBInstanceNotFound")
        return None if root is None else root.find(f".//{NS}DBInstance")

    def _wait(self, what: str, done: Callable[[Optional[ET.Element]], bool]) -> Optional[ET.Element]:
        start = self._mono()
        while True:
            inst = self._instance()
            if done(inst):
                return inst
            if self._mono() - start > self._deadline:
                state = inst.findtext(f"{NS}DBInstanceStatus") if inst is not None else "gone"
                raise DrillError(f"the scratch instance {SCRATCH_ID} was not {what} within {int(self._deadline)} seconds "
                                 f"(status {state})")
            self._sleep(self._poll)

    @staticmethod
    def _available(inst: Optional[ET.Element]) -> bool:
        return inst is not None and inst.findtext(f"{NS}DBInstanceStatus") == "available" and \
            inst.find(f"{NS}PendingModifiedValues/{NS}MasterUserPassword") is None

    def latest(self) -> tuple[str, datetime, str]:
        """(snapshot id, creation time, master user) of the newest available snapshot of the source database."""
        found = []
        for kind in SNAPSHOT_TYPES:
            root = self._call("DescribeDBSnapshots", {"DBInstanceIdentifier": self._source, "SnapshotType": kind,
                                                      "MaxRecords": "100"})
            for s in root.iter(f"{NS}DBSnapshot"):
                if s.findtext(f"{NS}Status") != "available":
                    continue
                when = datetime.fromisoformat((s.findtext(f"{NS}SnapshotCreateTime") or "").replace("Z", "+00:00"))
                found.append((when, s.findtext(f"{NS}DBSnapshotIdentifier"), s.findtext(f"{NS}MasterUsername")))
        if not found:
            raise DrillError(f"no available snapshot of {self._source} was found; there is no backup to restore")
        when, snap, user = max(found)
        if not snap or not user:
            raise DrillError("the newest snapshot answered no identifier or master user")
        return snap, when.astimezone(timezone.utc), user

    def _lease(self, inst: ET.Element) -> Optional[datetime]:
        """The lease the drill that made the instance wrote on it (tag ``cv-drill-lease-until``), or None."""
        for tag in inst.iter(f"{NS}Tag"):
            if tag.findtext(f"{NS}Key") == LEASE_TAG:
                try:
                    return datetime.fromisoformat((tag.findtext(f"{NS}Value") or "").replace("Z", "+00:00"))
                except ValueError:  # loud-failure-exempt: an unreadable lease is no lease; the copy is treated as stale
                    return None
        return None

    def restore_latest(self) -> Restored:
        snap, taken, user = self.latest()
        now = self._clock()
        inst = self._instance()
        if inst is not None:
            lease = self._lease(inst)
            if lease is not None and lease > now:  # a drill still running holds it: never touched
                raise DrillBusy(f"the scratch instance {SCRATCH_ID} is held by a running drill until {lease.isoformat()}; "
                                "this drill restored nothing")
            self._delete()  # left by a drill that ended without removing it (its lease is past)
            self.stale_removed.append(SCRATCH_ID)
        until = now + timedelta(seconds=self._lease_s)
        self._call("RestoreDBInstanceFromDBSnapshot", {
            "DBInstanceIdentifier": SCRATCH_ID, "DBSnapshotIdentifier": snap, "DBInstanceClass": self._class,
            "DBSubnetGroupName": self._subnet, "VpcSecurityGroupIds.member.1": self._sg,
            "DBParameterGroupName": self._params, "PubliclyAccessible": "false", "MultiAZ": "false",
            "DeletionProtection": "false", "CopyTagsToSnapshot": "false",
            "Tags.member.1.Key": "cv-purpose", "Tags.member.1.Value": "restore-drill",
            "Tags.member.2.Key": LEASE_TAG, "Tags.member.2.Value": until.astimezone(timezone.utc).isoformat()})
        self._owned = True
        self._wait("available", self._available)
        password = secrets.token_urlsafe(32)
        self._call("ModifyDBInstance", {"DBInstanceIdentifier": SCRATCH_ID, "MasterUserPassword": password,
                                        "ApplyImmediately": "true"})
        inst = self._wait("ready with its new password", self._available)
        host = inst.findtext(f"{NS}Endpoint/{NS}Address") if inst is not None else None
        port = inst.findtext(f"{NS}Endpoint/{NS}Port") if inst is not None else None
        if not host or not port:
            raise DrillError(f"the scratch instance {SCRATCH_ID} answered no endpoint")
        from psycopg.conninfo import make_conninfo

        dsn = make_conninfo(host=host, port=port, dbname=self._db, user=user, password=password, sslmode="verify-full",
                            sslrootcert=self._ca, connect_timeout="30")
        return Restored(Backup(snap, taken), dsn, set_role=CONSOLE_ROLE, grant_role=True)

    def discard(self) -> None:
        """Removes the instance this drill made; never one it did not make (a running drill's)."""
        if not self._owned:
            return
        self._delete()
        self._owned = False

    def _delete(self) -> None:
        if self._instance() is None:
            return
        self._call("DeleteDBInstance", {"DBInstanceIdentifier": SCRATCH_ID, "SkipFinalSnapshot": "true",
                                        "DeleteAutomatedBackups": "true"}, missing_ok="DBInstanceNotFound")
        self._wait("deleted", lambda inst: inst is None)
