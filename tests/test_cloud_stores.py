"""The cloud API's evidence store, archive store and lifecycle ledger are S3 buckets with Object Lock on the task role;
a local folder is for the self-host only, and the cloud refuses to start with one. "Cloud" is the IAM database sign-in
(db_auth = iam), which every cloud task uses and no self-host does."""

import inspect

import pytest

from consentvault import cmd_cloud
from consentvault.config import load_config
from consentvault.errors import ConfigError
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore, S3ObjectLockEvidenceStore

HOST = "cv-db.abc123xyz.us-east-1.rds.amazonaws.com"
CLOUD = {"CONSENTVAULT_DB_AUTH": "iam", "CONSENTVAULT_DB_HOST": HOST, "CONSENTVAULT_DB_NAME": "consentvault",
         "CONSENTVAULT_DB_USER": "consentvault_runtime", "AWS_REGION": "us-east-1",
         "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x",
         "CONSENTVAULT_EVIDENCE_BUCKET": "cv-evidence", "CONSENTVAULT_ARCHIVE_BUCKET": "cv-archive",
         "CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET": "cv-lifecycle"}


def test_the_cloud_stores_are_s3_object_lock_buckets(tmp_path):
    evidence, archive, ledger = cmd_cloud.cloud_stores(load_config(env=CLOUD), CLOUD)
    for store, bucket in ((evidence, "cv-evidence"), (archive, "cv-archive"), (ledger, "cv-lifecycle")):
        assert isinstance(store, S3ObjectLockEvidenceStore) and store._bucket == bucket
        assert store._host == "s3.us-east-1.amazonaws.com" and store.enforces_retention


@pytest.mark.parametrize("local", ["CONSENTVAULT_EVIDENCE_DIR", "CONSENTVAULT_ARCHIVE_DIR",
                                   "CONSENTVAULT_LIFECYCLE_LEDGER_DIR"])
def test_the_cloud_refuses_to_start_with_a_local_folder(tmp_path, local):
    env = {**CLOUD, local: str(tmp_path / "x")}
    with pytest.raises(ConfigError, match=f"{local}.*local"):
        cmd_cloud.cloud_stores(load_config(env=env), env)


@pytest.mark.parametrize("bucket", ["CONSENTVAULT_EVIDENCE_BUCKET", "CONSENTVAULT_ARCHIVE_BUCKET",
                                    "CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET"])
def test_the_cloud_names_a_missing_bucket(bucket):
    env = {k: v for k, v in CLOUD.items() if k != bucket}
    with pytest.raises(ConfigError, match=bucket):
        cmd_cloud.cloud_stores(load_config(env=env), env)


def test_the_self_host_keeps_its_local_folders(tmp_path):
    env = {"CONSENTVAULT_DSN": "postgresql://u@127.0.0.1/x", "CONSENTVAULT_EVIDENCE_DIR": str(tmp_path / "e"),
           "CONSENTVAULT_ARCHIVE_DIR": str(tmp_path / "a")}
    evidence, archive, ledger = cmd_cloud.cloud_stores(load_config(env=env), env)
    assert all(isinstance(s, LocalAppendOnlyEvidenceStore) for s in (evidence, archive, ledger))


def test_the_server_builds_its_stores_only_through_cloud_stores():
    src = inspect.getsource(cmd_cloud.build_cloud)
    assert "cloud_stores(" in src and "LocalAppendOnlyEvidenceStore(" not in src
