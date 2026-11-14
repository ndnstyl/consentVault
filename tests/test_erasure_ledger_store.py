"""The erasure job's lifecycle ledger lives where it survives the task: S3 with Object Lock in the cloud (the task
role's credentials, refreshed per request), a local append-only folder in the self-host. Exactly one is configured."""

from error_names import named, named_any  # noqa: F401
from datetime import datetime, timedelta, timezone

import pytest

from consentvault import cmd_erasure
from consentvault.errors import ConfigError
from consentvault.providers.evidence import LocalAppendOnlyEvidenceStore, S3ObjectLockEvidenceStore
from consentvault.providers.rds_iam import AwsCredentials

T0 = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


def test_the_cloud_ledger_is_s3_with_object_lock_on_the_task_role(tmp_path):
    store = cmd_erasure.ledger_store({"CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET": "cv-lifecycle-ledger",
                                      "AWS_REGION": "us-east-1",
                                      "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x"})
    assert isinstance(store, S3ObjectLockEvidenceStore) and store.enforces_retention
    assert store._host == "s3.us-east-1.amazonaws.com" and store._bucket == "cv-lifecycle-ledger"


def test_the_self_host_ledger_is_the_local_folder(tmp_path):
    store = cmd_erasure.ledger_store({"CONSENTVAULT_LIFECYCLE_LEDGER_DIR": str(tmp_path / "ledger")})
    assert isinstance(store, LocalAppendOnlyEvidenceStore)


@pytest.mark.parametrize("env,match", [
    ({}, "CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET"),
    ({"CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET": "b-ok", "CONSENTVAULT_LIFECYCLE_LEDGER_DIR": "/x"}, "one"),
    ({"CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET": "cv-ledger"}, "CONSENTVAULT_LIFECYCLE_LEDGER_REGION"),
])
def test_a_missing_or_double_ledger_setting_is_named(env, match):
    with pytest.raises(ConfigError, match=match):
        cmd_erasure.ledger_store(env)


def test_the_s3_store_signs_each_request_with_the_current_task_credentials():
    seen, creds = [], [AwsCredentials("ASIAONE", "s1", "tok-1", T0 + timedelta(hours=1))]

    class Source:
        def get(self):
            return creds[-1]

    def send(method, url, headers, body):
        seen.append(headers)
        return 200, {}, b""

    store = S3ObjectLockEvidenceStore(endpoint="https://s3.us-east-1.amazonaws.com", bucket="cv-ledger",
                                      region="us-east-1", credentials=Source(), transport=send, clock=lambda: T0)
    store.put("org-a", "ledger/1", b"x", retain_until=T0 + timedelta(days=400))
    creds.append(AwsCredentials("ASIATWO", "s2", "tok-2", T0 + timedelta(hours=2)))
    store.put("org-a", "ledger/2", b"y", retain_until=T0 + timedelta(days=400))
    assert [h["x-amz-security-token"] for h in seen] == ["tok-1", "tok-2"]
    assert "Credential=ASIATWO/" in seen[1]["authorization"]


def test_the_s3_store_takes_static_keys_or_a_credential_source_never_both():
    with pytest.raises(Exception, match="credential"):
        S3ObjectLockEvidenceStore(endpoint="https://s3.us-east-1.amazonaws.com", bucket="cv-ledger", region="us-east-1",
                                  access_key="AK", secret_key="SK", credentials=object())


def test_the_cloud_refuses_a_local_ledger_folder_for_the_erasure_jobs(tmp_path):
    with pytest.raises(ConfigError, match="CONSENTVAULT_LIFECYCLE_LEDGER_DIR.*local.*cloud"):
        cmd_erasure.ledger_store({"CONSENTVAULT_LIFECYCLE_LEDGER_DIR": str(tmp_path)}, cloud=True)
    with pytest.raises(ConfigError, match="CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET"):
        cmd_erasure.ledger_store({}, cloud=True)
    store = cmd_erasure.ledger_store({"CONSENTVAULT_LIFECYCLE_LEDGER_BUCKET": "cv-l", "AWS_REGION": "us-east-1",
                                      "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/x"}, cloud=True)
    assert isinstance(store, S3ObjectLockEvidenceStore)


@pytest.mark.parametrize("command", ["erasure-commit-sweep", "erasure-resume"])
def test_the_jobs_pick_the_cloud_store_from_the_iam_login_and_refuse_a_folder(command, tmp_path, monkeypatch, capsys):
    from consentvault import cli

    key = tmp_path / "token.key"
    key.write_text("ab" * 32)
    for k, v in {"CONSENTVAULT_DB_AUTH": "iam", "CONSENTVAULT_DB_HOST": "cv-db.abc123xyz.us-east-1.rds.amazonaws.com",
                 "CONSENTVAULT_DB_NAME": "consentvault", "CONSENTVAULT_DB_USER": "consentvault_sweep",
                 "AWS_REGION": "us-east-1", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x",
                 "CONSENTVAULT_TOKEN_KEY_ID": "k1", "CONSENTVAULT_TOKEN_KEY_FILE": str(key),
                 "CONSENTVAULT_KEY_PROVIDER": "none:None",
                 "CONSENTVAULT_LIFECYCLE_LEDGER_DIR": str(tmp_path / "ledger")}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    assert cli.main([command]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert named("ConfigError", err) and "CONSENTVAULT_LIFECYCLE_LEDGER_DIR" not in err and not (tmp_path / "ledger").exists()
