"""The cloud restore drill's scratch target and the evidence listing it reconciles with, against recorded fakes of the RDS
Query API and S3 (no AWS call is made): the newest snapshot is restored to the one scratch instance, a fresh password is
set on it alone, every wait has a deadline, the instance is deleted afterwards, and every AWS refusal is named."""

import urllib.parse
from datetime import datetime, timedelta, timezone

import pytest
from psycopg.conninfo import conninfo_to_dict

from consentvault.providers.errors import EvidenceStoreError
from consentvault.providers.evidence import S3ObjectLockEvidenceStore
from consentvault.providers.rds_iam import AwsCredentials
from consentvault.providers.rds_restore import SCRATCH_ID, DrillBusy, RdsSnapshotTarget
from consentvault.restore_drill import DrillError

NS = "http://rds.amazonaws.com/doc/2014-10-31/"
T0 = datetime(2026, 10, 31, 8, tzinfo=timezone.utc)


class Creds:
    def get(self):
        return AwsCredentials("ASIAFAKE", "secret", "token", T0 + timedelta(hours=1))


class FakeRds:
    """The RDS Query API for one source database and one scratch instance; each describe advances a pending state."""

    def __init__(self, snapshots=None, *, leftover=False, stuck=False, lease=None):
        self.calls = []
        self.snapshots = snapshots if snapshots is not None else {
            "automated": [("rds:consentvault-2026-10-30", T0 - timedelta(days=1), "available"),
                          ("rds:consentvault-2026-10-31", T0, "available"),
                          ("rds:consentvault-2026-11-01", T0 + timedelta(hours=1), "creating")],
            "awsbackup": [("awsbackup:job-1", T0 - timedelta(hours=2), "available")]}
        self.instance = ({"status": "available", "pending_pw": False,
                          "tags": {"cv-drill-lease-until": lease.isoformat()} if lease else {}} if leftover else None)
        self.stuck = stuck

    def __call__(self, method, url, headers, body):
        assert method == "POST" and url == "https://rds.us-east-1.amazonaws.com/" and "host" not in headers
        assert headers["authorization"].startswith("AWS4-HMAC-SHA256 ") and "/rds/aws4_request" in headers["authorization"]
        form = dict(urllib.parse.parse_qsl(body.decode()))
        self.calls.append(form)
        action = form["Action"]
        if action == "DescribeDBSnapshots":
            assert form["DBInstanceIdentifier"] == "consentvault"
            items = "".join(f"<DBSnapshot><DBSnapshotIdentifier>{i}</DBSnapshotIdentifier><Status>{st}</Status>"
                            f"<SnapshotCreateTime>{w.isoformat().replace('+00:00', 'Z')}</SnapshotCreateTime>"
                            f"<MasterUsername>cvmaster</MasterUsername></DBSnapshot>"
                            for i, w, st in self.snapshots[form["SnapshotType"]])
            return 200, {}, self._ok(action, f"<DBSnapshots>{items}</DBSnapshots>")
        assert form["DBInstanceIdentifier"] == SCRATCH_ID, form  # only the scratch instance is ever named
        if action == "DescribeDBInstances":
            if self.instance is None:
                return 404, {}, self._err("DBInstanceNotFound")
            i = self.instance
            body = (f"<DBInstances><DBInstance><DBInstanceStatus>{i['status']}</DBInstanceStatus>"
                    + ("<PendingModifiedValues><MasterUserPassword>****</MasterUserPassword></PendingModifiedValues>"
                       if i["pending_pw"] else "<PendingModifiedValues/>")
                    + "<Endpoint><Address>cv-restore-drill.abc.us-east-1.rds.amazonaws.com</Address><Port>5432</Port>"
                      "</Endpoint><TagList>"
                    + "".join(f"<Tag><Key>{k}</Key><Value>{v}</Value></Tag>" for k, v in i["tags"].items())
                    + "</TagList></DBInstance></DBInstances>")
            if not self.stuck:  # the next describe sees the step done
                if i["status"] == "creating":
                    i["status"] = "available"
                elif i["status"] == "deleting":
                    self.instance = None
                elif i["pending_pw"]:
                    i["pending_pw"] = False
            return 200, {}, self._ok(action, body)
        if action == "RestoreDBInstanceFromDBSnapshot":
            n = 1
            tags = {}
            while f"Tags.member.{n}.Key" in form:
                tags[form[f"Tags.member.{n}.Key"]] = form[f"Tags.member.{n}.Value"]
                n += 1
            self.instance = {"status": "creating", "pending_pw": False, "tags": tags}
            return 200, {}, self._ok(action, "<DBInstance/>")
        if action == "ModifyDBInstance":
            self.instance["pending_pw"] = True
            return 200, {}, self._ok(action, "<DBInstance/>")
        if action == "DeleteDBInstance":
            self.instance["status"] = "deleting"
            return 200, {}, self._ok(action, "<DBInstance/>")
        raise AssertionError(action)

    @staticmethod
    def _ok(action, inner):
        return f'<{action}Response xmlns="{NS}"><{action}Result>{inner}</{action}Result></{action}Response>'.encode()

    @staticmethod
    def _err(code):
        return (f'<ErrorResponse xmlns="{NS}"><Error><Code>{code}</Code><Message>no such instance</Message></Error>'
                f"</ErrorResponse>").encode()


def target(fake, **kw):
    clock = {"t": 0.0}

    def sleep(s):
        clock["t"] += s
    kw.setdefault("deadline_s", 600)
    return RdsSnapshotTarget(region="us-east-1", aws_access=Creds(), source_db="consentvault", subnet_group="cv-db",
                             security_group="sg-0123456789abcdef0", instance_class="db.t4g.small",
                             parameter_group="cv-pg17", db_name="consentvault", ca_bundle="/etc/ca.pem", transport=fake,
                             clock=lambda: T0, sleep=sleep, monotonic=lambda: clock["t"], poll_s=30, **kw)


def test_the_newest_available_snapshot_is_restored_to_the_scratch_instance_with_a_fresh_password():
    fake = FakeRds()
    restored = target(fake).restore_latest()
    assert restored.backup.ref == "rds:consentvault-2026-10-31" and restored.backup.taken_at == T0
    assert restored.set_role == "consentvault_console" and restored.grant_role is True
    dsn = conninfo_to_dict(restored.dsn)
    assert dsn["host"] == "cv-restore-drill.abc.us-east-1.rds.amazonaws.com" and dsn["user"] == "cvmaster"
    assert dsn["sslmode"] == "verify-full" and dsn["sslrootcert"] == "/etc/ca.pem" and dsn["dbname"] == "consentvault"
    [restore] = [c for c in fake.calls if c["Action"] == "RestoreDBInstanceFromDBSnapshot"]
    assert restore["DBSnapshotIdentifier"] == "rds:consentvault-2026-10-31"
    assert restore["PubliclyAccessible"] == "false" and restore["DeletionProtection"] == "false"
    assert restore["VpcSecurityGroupIds.member.1"] == "sg-0123456789abcdef0" and restore["DBSubnetGroupName"] == "cv-db"
    [modify] = [c for c in fake.calls if c["Action"] == "ModifyDBInstance"]
    assert modify["MasterUserPassword"] == dsn["password"] and len(dsn["password"]) >= 40
    assert dsn["password"] not in repr(restored)


def test_discard_deletes_the_scratch_instance_and_waits_until_it_is_gone():
    fake = FakeRds()
    t = target(fake)
    t.restore_latest()
    t.discard()
    assert fake.instance is None
    [delete] = [c for c in fake.calls if c["Action"] == "DeleteDBInstance"]
    assert delete["SkipFinalSnapshot"] == "true" and delete["DeleteAutomatedBackups"] == "true"
    t.discard()  # nothing left: nothing to do


def test_a_scratch_instance_left_by_an_earlier_drill_is_removed_first():
    fake = FakeRds(leftover=True)
    t = target(fake)
    t.restore_latest()
    actions = [c["Action"] for c in fake.calls]
    assert actions.index("DeleteDBInstance") < actions.index("RestoreDBInstanceFromDBSnapshot")
    assert t.stale_removed == [SCRATCH_ID]


def test_no_available_snapshot_is_a_named_error():
    with pytest.raises(DrillError, match="no available snapshot"):
        target(FakeRds({"automated": [("rds:x", T0, "creating")], "awsbackup": []})).restore_latest()


def test_a_wait_past_its_deadline_dies_by_name():
    with pytest.raises(DrillError, match="not available within 600 seconds"):
        target(FakeRds(stuck=True), deadline_s=600).restore_latest()


def test_an_aws_refusal_is_named():
    def denied(method, url, headers, body):
        return 403, {}, (f'<ErrorResponse xmlns="{NS}"><Error><Code>AccessDenied</Code><Message>not allowed</Message>'
                         "</Error></ErrorResponse>").encode()
    with pytest.raises(DrillError, match="DescribeDBSnapshots answered HTTP 403 AccessDenied"):
        target(denied).restore_latest()


@pytest.mark.parametrize("field,value", [("security_group", "default"), ("instance_class", "large"),
                                         ("subnet_group", "bad name"), ("source_db", "")])
def test_settings_are_checked(field, value):
    kw = dict(region="us-east-1", aws_access=Creds(), source_db="consentvault", subnet_group="cv-db",
              security_group="sg-0123456789abcdef0", instance_class="db.t4g.small", parameter_group="cv-pg17",
              db_name="consentvault", ca_bundle="/etc/ca.pem", transport=FakeRds())
    kw[field] = value
    with pytest.raises(DrillError):
        RdsSnapshotTarget(**kw)


def test_from_environment_names_the_missing_setting():
    with pytest.raises(DrillError, match="CONSENTVAULT_RESTORE_DRILL_SOURCE_DB"):
        RdsSnapshotTarget.from_environment({"AWS_REGION": "us-east-1"})


# ---- the evidence listing the reconcile reads in the cloud ----------------------------------------------------------------
S3NS = "http://s3.amazonaws.com/doc/2006-03-01/"


class ListingS3:
    def __init__(self, pages):
        self.pages, self.urls = pages, []

    def __call__(self, method, url, headers, body):
        assert method == "GET" and headers["authorization"].startswith("AWS4-HMAC-SHA256 ")
        self.urls.append(url)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        assert q["list-type"] == "2" and q["prefix"] == "org-a/"
        page = self.pages[int(q["continuation-token"]) if "continuation-token" in q else 0]
        if isinstance(page, int):
            return page, {}, b"<Error><Code>AccessDenied</Code></Error>"
        items, more = page
        xml = "".join(f"<Contents><Key>{k}</Key><LastModified>{w}</LastModified></Contents>" for k, w in items)
        nxt = f"<NextContinuationToken>{more}</NextContinuationToken>" if more else ""
        return 200, {}, (f'<ListBucketResult xmlns="{S3NS}">{xml}<IsTruncated>{"true" if more else "false"}</IsTruncated>'
                         f"{nxt}</ListBucketResult>").encode()


def s3(fake):
    return S3ObjectLockEvidenceStore(endpoint="https://s3.example.com", bucket="ev-bucket", region="us-east-1",
                                     access_key="AK", secret_key="SK", transport=fake, clock=lambda: T0)


def test_the_listing_reads_every_page_and_keeps_objects_written_after_the_restore_point():
    fake = ListingS3([([("org-a/events/1", "2026-10-30T00:00:00.000Z"), ("org-a/events/2", "2026-10-31T09:00:00.000Z")], "1"),
                      ([("org-a/events/3", "2026-10-31T10:00:00.000Z")], None)])
    assert s3(fake).inventory("org-a", T0) == ["events/2", "events/3"]
    assert len(fake.urls) == 2 and fake.urls[0].startswith("https://s3.example.com/ev-bucket?")


def test_a_listing_page_that_fails_is_an_error_never_a_short_list():
    with pytest.raises(EvidenceStoreError, match="LIST answered HTTP 403"):
        s3(ListingS3([([("org-a/events/1", "2026-10-31T09:00:00Z")], "1"), 403])).inventory("org-a", T0)


def test_a_key_outside_the_prefix_or_a_truncated_page_without_a_token_is_refused():
    with pytest.raises(EvidenceStoreError, match="outside the organisation"):
        s3(ListingS3([([("org-b/events/1", "2026-10-31T09:00:00Z")], None)])).inventory("org-a", T0)

    def no_token(method, url, headers, body):
        return 200, {}, f'<ListBucketResult xmlns="{S3NS}"><IsTruncated>true</IsTruncated></ListBucketResult>'.encode()
    with pytest.raises(EvidenceStoreError, match="no continuation token"):
        s3(no_token).inventory("org-a", T0)


def test_the_new_instance_carries_the_drills_lease():
    fake = FakeRds()
    target(fake).restore_latest()
    assert fake.instance["tags"] == {"cv-purpose": "restore-drill",
                                     "cv-drill-lease-until": (T0 + timedelta(hours=4 + 6)).isoformat()}  # default target, plus margin


def test_an_instance_under_a_running_drills_lease_is_never_touched():
    fake = FakeRds(leftover=True, lease=T0 + timedelta(hours=1))
    t = target(fake)
    with pytest.raises(DrillBusy, match="held by a running drill"):
        t.restore_latest()
    t.discard()  # this drill made nothing, so it removes nothing
    assert fake.instance is not None and [c["Action"] for c in fake.calls if c["Action"] != "DescribeDBSnapshots"] == [
        "DescribeDBInstances"]
    assert t.stale_removed == []


def test_an_instance_whose_lease_is_past_is_stale_and_removed():
    fake = FakeRds(leftover=True, lease=T0 - timedelta(minutes=1))
    t = target(fake)
    t.restore_latest()
    assert t.stale_removed == [SCRATCH_ID] and fake.instance["tags"]["cv-drill-lease-until"] == (T0 + timedelta(hours=10)).isoformat()


def test_the_lease_covers_the_drills_own_target_even_at_seven_days():
    env = {"AWS_REGION": "us-east-1", "CONSENTVAULT_DB_NAME": "consentvault",
           "CONSENTVAULT_RESTORE_DRILL_SOURCE_DB": "consentvault", "CONSENTVAULT_RESTORE_DRILL_SUBNET_GROUP": "cv-db",
           "CONSENTVAULT_RESTORE_DRILL_SECURITY_GROUP": "sg-0123456789abcdef0",
           "CONSENTVAULT_RESTORE_DRILL_INSTANCE_CLASS": "db.t4g.small", "CONSENTVAULT_RESTORE_DRILL_PARAMETER_GROUP": "cv-pg17",
           "CONSENTVAULT_RESTORE_DRILL_TARGET_SECONDS": str(7 * 86400)}
    t = RdsSnapshotTarget.from_environment(env)
    assert t._lease_s == 7 * 86400 + 6 * 3600
    fake = FakeRds()
    t._send, t._clock, t._aws = fake, (lambda: T0), Creds()
    t._sleep, t._mono = (lambda s: None), (lambda: 0.0)
    t.restore_latest()
    lease = datetime.fromisoformat(fake.instance["tags"]["cv-drill-lease-until"])
    assert lease == T0 + timedelta(days=7, hours=6)
    # a second drill six days and twenty hours in, still inside the first one's target, leaves the copy alone
    second = target(fake)
    second._clock = lambda: T0 + timedelta(days=6, hours=20)
    with pytest.raises(DrillBusy):
        second.restore_latest()
