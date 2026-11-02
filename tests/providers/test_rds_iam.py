"""RDS IAM database authentication: the hand SigV4 presigner, the auth token, the container credentials, the connector.

No network: the metadata endpoint, the clock and the Postgres connect are injected.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import urllib.parse
from datetime import datetime, timedelta, timezone

import psycopg
import re

import pytest

from consentvault import db
from consentvault.config import load_config
from consentvault.errors import (
    ConfigError, DatabaseAuthError, DatabaseCredentialsError, DatabaseError, DatabaseSigningError, DatabaseTlsError)
from consentvault.providers import rds_iam
from consentvault.providers.rds_iam import (
    AwsCredentials, ContainerCredentials, RdsIamConnector, rds_auth_token, sigv4_presign_query, sigv4_signing_key)

T0 = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)
HOST = "cv-db.abc123xyz.us-east-1.rds.amazonaws.com"
CA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def creds(expiration=T0 + timedelta(hours=6), token="SESSIONTOKEN/with+chars=="):
    return AwsCredentials("ASIAEXAMPLEKEY", "secret/EXAMPLE+key", token, expiration)


# ------------------------------------------------------------------------------------------- SigV4 vectors


def test_signing_key_matches_the_published_aws_derivation_example():
    key = sigv4_signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215", "us-east-1", "iam")
    assert key.hex() == "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"


def test_presign_matches_the_published_aws_s3_presigned_url_example():
    q = sigv4_presign_query(
        method="GET", host="examplebucket.s3.amazonaws.com", path="/test.txt", params={},
        access_key="AKIAIOSFODNN7EXAMPLE", secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region="us-east-1", service="s3", amz_date="20130524T000000Z", expires=86400, payload_sha256="UNSIGNED-PAYLOAD")
    assert q == ("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3"
                 "%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"
                 "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404")


# ------------------------------------------------------------------------------------------- the token


def _second_signature(token: str, secret: str) -> str:
    """Recompute the token's signature a second way, from the documented canonical request text."""
    host_port, query = token.split("/?", 1)
    pairs = [p.split("=", 1) for p in query.split("&")]
    unsigned = "&".join(f"{k}={v}" for k, v in sorted(pairs) if k != "X-Amz-Signature")
    params = dict(pairs)
    amz_date = params["X-Amz-Date"]
    scope = urllib.parse.unquote(params["X-Amz-Credential"]).split("/", 1)[1]
    canonical = f"GET\n/\n{unsigned}\nhost:{host_port}\n\nhost\n{hashlib.sha256(b'').hexdigest()}"
    to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
    k = ("AWS4" + secret).encode()
    for part in scope.split("/"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    return hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()


def test_token_has_the_documented_rds_shape():
    token = rds_auth_token(host=HOST, port=5432, user="consentvault_runtime", region="us-east-1", creds=creds(), now=T0)
    assert not token.startswith("http")
    assert token.startswith(f"{HOST}:5432/?Action=connect&DBUser=consentvault_runtime&X-Amz-Algorithm=AWS4-HMAC-SHA256"
                            "&X-Amz-Credential=ASIAEXAMPLEKEY%2F20261030%2Fus-east-1%2Frds-db%2Faws4_request"
                            "&X-Amz-Date=20261030T120000Z&X-Amz-Expires=900"
                            "&X-Amz-Security-Token=SESSIONTOKEN%2Fwith%2Bchars%3D%3D&X-Amz-SignedHeaders=host"
                            "&X-Amz-Signature=")
    sig = token.rsplit("X-Amz-Signature=", 1)[1]
    assert len(sig) == 64 and int(sig, 16) >= 0
    assert sig == _second_signature(token, "secret/EXAMPLE+key")


def test_token_signature_changes_with_user_host_and_time():
    base = dict(host=HOST, port=5432, user="consentvault_runtime", region="us-east-1", creds=creds(), now=T0)
    t = rds_auth_token(**base)
    assert rds_auth_token(**{**base, "user": "consentvault_sync"}) != t
    assert rds_auth_token(**{**base, "now": T0 + timedelta(seconds=1)}) != t
    assert rds_auth_token(**{**base, "port": 5433}) != t


@pytest.mark.parametrize("bad", [
    dict(creds=AwsCredentials("", "s", None, None)),
    dict(creds=AwsCredentials("AK", "", None, None)),
    dict(region=""),
    dict(region="us east 1"),
    dict(host=""),
    dict(user=""),
    dict(port=0),
])
def test_signing_failure_is_named(bad):
    args = dict(host=HOST, port=5432, user="consentvault_runtime", region="us-east-1", creds=creds(), now=T0)
    with pytest.raises(DatabaseSigningError):
        rds_auth_token(**{**args, **bad})


# ------------------------------------------------------------------------------------------- container credentials


def _meta_body(exp=T0 + timedelta(hours=6), **over):
    body = {"AccessKeyId": "ASIAEXAMPLEKEY", "SecretAccessKey": "secret/EXAMPLE+key", "Token": "SESSIONTOKEN",
            "Expiration": exp.strftime("%Y-%m-%dT%H:%M:%SZ")}
    body.update(over)
    return json.dumps(body).encode()


class Meta:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        a = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(a, Exception):
            raise a
        return a


def test_container_credentials_read_the_relative_uri_on_the_ecs_endpoint():
    meta = Meta((200, _meta_body()))
    src = ContainerCredentials(env={"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/abc"}, fetch=meta,
                               clock=Clock())
    c = src.get()
    assert (c.access_key, c.secret_key, c.session_token) == ("ASIAEXAMPLEKEY", "secret/EXAMPLE+key", "SESSIONTOKEN")
    assert c.expiration == T0 + timedelta(hours=6)
    assert meta.calls == [("http://169.254.170.2/v2/credentials/abc", {})]


def test_container_credentials_full_uri_sends_the_authorization_token():
    meta = Meta((200, _meta_body()))
    src = ContainerCredentials(env={"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials",
                                    "AWS_CONTAINER_AUTHORIZATION_TOKEN": "tok"}, fetch=meta, clock=Clock())
    src.get()
    assert meta.calls == [("http://169.254.170.23/v1/credentials", {"Authorization": "tok"})]


def test_container_credentials_refuse_a_full_uri_off_the_metadata_hosts():
    with pytest.raises(DatabaseCredentialsError, match="metadata"):
        ContainerCredentials(env={"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://evil.example/creds"},
                             fetch=Meta((200, _meta_body())), clock=Clock()).get()


def test_container_credentials_are_cached_until_near_expiry():
    clock = Clock()
    meta = Meta((200, _meta_body(exp=T0 + timedelta(hours=1))), (200, _meta_body(exp=T0 + timedelta(hours=2))))
    src = ContainerCredentials(env={"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, fetch=meta, clock=clock)
    src.get()
    clock.t = T0 + timedelta(minutes=50)
    src.get()
    assert len(meta.calls) == 1
    clock.t = T0 + timedelta(minutes=56)  # inside the five-minute margin
    assert src.get().expiration == T0 + timedelta(hours=2)
    assert len(meta.calls) == 2


@pytest.mark.parametrize("env,answer,match", [
    ({}, (200, b"{}"), "AWS_CONTAINER_CREDENTIALS"),
    ({"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, (500, b"boom"), "HTTP 500"),
    ({"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, (200, b"not json"), "JSON"),
    ({"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, (200, _meta_body(SecretAccessKey="")), "SecretAccessKey"),
    ({"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, (200, _meta_body(Expiration="soon")), "Expiration"),
    ({"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, (200, _meta_body(exp=T0 - timedelta(minutes=1))), "expired"),
    ({"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, OSError("no route"), "unreachable"),
])
def test_missing_or_bad_credentials_fail_by_name(env, answer, match):
    src = ContainerCredentials(env=env, fetch=Meta(answer), clock=Clock())
    with pytest.raises(DatabaseCredentialsError, match=match):
        src.get()


# ------------------------------------------------------------------------------------------- the connector


class StaticCreds:
    def __init__(self, c=None):
        self.c = c or creds()
        self.calls = 0

    def get(self):
        self.calls += 1
        if isinstance(self.c, Exception):
            raise self.c
        return self.c


class FakePg:
    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail

    def __call__(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise self.fail
        return "conn"


@pytest.fixture
def ca(tmp_path):
    p = tmp_path / "rds-global-bundle.pem"
    p.write_text(CA)
    return str(p)


def _connector(ca, clock=None, pg=None, source=None, **kw):
    return RdsIamConnector(host=HOST, port=5432, user="consentvault_runtime", dbname="consentvault",
                           region="us-east-1", ca_bundle=ca, credentials=source or StaticCreds(),
                           clock=clock or Clock(), pg_connect=pg or FakePg(), **kw)


def test_connector_connects_with_the_token_and_verify_full(ca):
    pg = FakePg()
    assert _connector(ca, pg=pg).connect() == "conn"
    (kw,) = pg.calls
    assert kw["host"] == HOST and kw["port"] == 5432 and kw["user"] == "consentvault_runtime"
    assert kw["dbname"] == "consentvault" and kw["sslmode"] == "verify-full" and kw["sslrootcert"] == ca
    assert kw["password"].startswith(f"{HOST}:5432/?Action=connect&DBUser=consentvault_runtime&")
    assert kw["autocommit"] is True and kw["connect_timeout"] > 0


def test_connector_reuses_the_token_then_refreshes_before_the_fifteen_minutes(ca):
    clock, pg = Clock(), FakePg()
    c = _connector(ca, clock=clock, pg=pg)
    c.connect()
    clock.t = T0 + timedelta(minutes=9)
    c.connect()
    clock.t = T0 + timedelta(minutes=10, seconds=1)
    c.connect()
    first, second, third = (k["password"] for k in pg.calls)
    assert first == second and third != first
    assert "X-Amz-Date=20261030T121001Z" in third


def test_connector_never_hands_out_a_token_past_the_credentials_expiry(ca):
    clock, pg = Clock(), FakePg()
    src = StaticCreds(creds(expiration=T0 + timedelta(minutes=8)))
    c = _connector(ca, clock=clock, pg=pg, source=src)
    c.connect()
    clock.t = T0 + timedelta(minutes=4)  # token is young but its credentials run out inside the margin
    c.connect()
    assert src.calls == 2 and pg.calls[0]["password"] != pg.calls[1]["password"]


def test_connector_missing_credentials_fail_before_connecting(ca):
    pg = FakePg()
    with pytest.raises(DatabaseCredentialsError):
        _connector(ca, pg=pg, source=StaticCreds(DatabaseCredentialsError("no container credentials"))).connect()
    assert pg.calls == []


@pytest.mark.parametrize("content", [None, "", "not a certificate"])
def test_connector_refuses_a_missing_or_unusable_ca_bundle(tmp_path, content):
    p = tmp_path / "bundle.pem"
    if content is not None:
        p.write_text(content)
    pg = FakePg()
    with pytest.raises(DatabaseTlsError, match="CA bundle"):
        _connector(str(p), pg=pg).connect()
    assert pg.calls == []


@pytest.mark.parametrize("message,err", [
    ("SSL error: certificate verify failed", DatabaseTlsError),
    ("server certificate for \"x\" does not match host name \"y\"", DatabaseTlsError),
    ("FATAL:  PAM authentication failed for user \"consentvault_runtime\"", DatabaseAuthError),
    ("connection timeout expired", DatabaseError),
])
def test_connect_failures_are_classified_by_name(ca, message, err):
    with pytest.raises(err) as exc:
        _connector(ca, pg=FakePg(psycopg.OperationalError(message))).connect()
    assert "X-Amz-Signature" not in str(exc.value)  # the token never lands in an error


def test_connector_refuses_a_refresh_at_or_past_the_token_lifetime(ca):
    with pytest.raises(ConfigError):
        _connector(ca, refresh_after_s=900)


# ------------------------------------------------------------------------------------------- config and db wiring


def test_plain_dsn_stays_the_default(monkeypatch):
    cfg = load_config(env={"CONSENTVAULT_DSN": "postgresql://u@localhost/db"})
    assert cfg.db_auth == "password" and cfg.require_dsn() == "postgresql://u@localhost/db"


IAM_ENV = {"CONSENTVAULT_DB_AUTH": "iam", "CONSENTVAULT_DB_HOST": HOST, "CONSENTVAULT_DB_NAME": "consentvault",
           "CONSENTVAULT_DB_USER": "consentvault_runtime", "CONSENTVAULT_DB_REGION": "us-east-1",
           "CONSENTVAULT_DB_CA_BUNDLE": "/etc/consentvault/rds-global-bundle.pem"}


def test_iam_config_builds_one_rds_iam_dsn_for_the_service_and_the_operator_jobs():
    cfg = load_config(env=IAM_ENV)
    dsn = cfg.require_dsn()
    assert dsn.startswith(f"rds-iam://consentvault_runtime@{HOST}:5432/consentvault?")
    assert "region=us-east-1" in dsn and "sslrootcert=%2Fetc%2Fconsentvault%2Frds-global-bundle.pem" in dsn
    assert cfg.require_operator_dsn() == dsn


def test_iam_config_reads_the_names_the_cloud_task_sets():
    cfg = load_config(env={"CV_DB_AUTH": "iam", "CV_DB_HOST": HOST, "CV_DB_NAME": "consentvault",
                           "CV_DB_USER": "consentvault_operator_login", "AWS_REGION": "us-east-1",
                           "CONSENTVAULT_DB_CA_BUNDLE": "/ca.pem"})
    assert cfg.require_operator_dsn().startswith(f"rds-iam://consentvault_operator_login@{HOST}:5432/consentvault?")


@pytest.mark.parametrize("drop", ["CONSENTVAULT_DB_HOST", "CONSENTVAULT_DB_NAME", "CONSENTVAULT_DB_USER",
                                  "CONSENTVAULT_DB_REGION"])
def test_iam_config_missing_a_setting_is_named(drop):
    env = {k: v for k, v in IAM_ENV.items() if k != drop}
    with pytest.raises(ConfigError, match=drop):
        load_config(env=env)


def test_iam_config_refuses_a_second_answer_for_the_dsn():
    with pytest.raises(ConfigError, match="CONSENTVAULT_DSN"):
        load_config(env={**IAM_ENV, "CONSENTVAULT_DSN": "postgresql://u:p@h/db"})


def test_unknown_auth_mode_is_refused():
    with pytest.raises(ConfigError, match="db_auth"):
        load_config(env={"CONSENTVAULT_DB_AUTH": "kerberos"})


def test_iam_config_leaves_the_migration_login_on_its_password_dsn():
    cfg = load_config(env={**IAM_ENV, "CONSENTVAULT_OWNER_DSN": "postgresql://m:pw@h/db"})
    assert cfg.require_owner_dsn() == "postgresql://m:pw@h/db"


def test_db_connect_routes_an_rds_iam_dsn_through_the_connector(monkeypatch, ca):
    seen = []

    class Spy:
        def __init__(self, **kw):
            seen.append(kw)

        def connect(self):
            return "iam-conn"

    monkeypatch.setattr(rds_iam, "_CONNECTORS", {})
    monkeypatch.setattr(rds_iam, "RdsIamConnector", Spy)
    dsn = load_config(env={**IAM_ENV, "CONSENTVAULT_DB_CA_BUNDLE": ca}).require_dsn()
    assert db.connect(dsn) == "iam-conn"
    assert db.connect(dsn) == "iam-conn"
    assert len(seen) == 1  # one connector per login per process, so its token cache is shared
    kw = seen[0]
    assert (kw["host"], kw["port"], kw["user"], kw["dbname"], kw["region"], kw["ca_bundle"]) == (
        HOST, 5432, "consentvault_runtime", "consentvault", "us-east-1", ca)


@pytest.mark.parametrize("dsn", ["rds-iam://u@h:5432/db?region=us-east-1",
                                 "rds-iam://u@h:5432/db?sslrootcert=%2Fca.pem",
                                 "rds-iam://u:pw@h:5432/db?region=us-east-1&sslrootcert=%2Fca.pem",
                                 "rds-iam://h:5432/db?region=us-east-1&sslrootcert=%2Fca.pem"])
def test_db_connect_refuses_a_malformed_rds_iam_dsn(dsn):
    with pytest.raises(ConfigError):
        db.connect(dsn)


def test_db_connect_plain_dsn_does_not_touch_the_iam_connector(monkeypatch):
    monkeypatch.setattr(rds_iam, "RdsIamConnector", lambda **kw: pytest.fail("IAM connector used for a plain DSN"))
    with pytest.raises(DatabaseError):
        db.connect("postgresql://nobody@127.0.0.1:1/none?connect_timeout=1")


# ------------------------------------------------------------------------------------------- the API, sync and jobs


@pytest.fixture
def iam_spy(monkeypatch, ca):
    seen = []

    class Spy:
        def __init__(self, **kw):
            self.kw = kw

        def connect(self):
            seen.append(self.kw["user"])
            return f"iam-conn:{self.kw['user']}"

    monkeypatch.setattr(rds_iam, "_CONNECTORS", {})
    monkeypatch.setattr(rds_iam, "RdsIamConnector", Spy)
    return seen, {**IAM_ENV, "CONSENTVAULT_DB_CA_BUNDLE": ca}


def test_api_settings_carry_the_iam_dsn_and_connect_through_it(iam_spy):
    from consentvault.api import load_api_settings

    seen, env = iam_spy
    settings = load_api_settings(env={**env, "CONSENTVAULT_API_SECRET": "s", "CONSENTVAULT_API_TOKEN": "t",
                                      "CONSENTVAULT_PURPOSES": "marketing"})
    assert settings.dsn.startswith("rds-iam://consentvault_runtime@")
    assert db.connect(settings.dsn) == "iam-conn:consentvault_runtime"


def test_sync_worker_connect_factory_uses_the_configured_login(iam_spy):
    seen, env = iam_spy
    connect = db.connect_factory(load_config(env={**env, "CONSENTVAULT_DB_USER": "consentvault_sync"}))
    assert connect() == "iam-conn:consentvault_sync" and connect() == "iam-conn:consentvault_sync"


def test_connect_factory_is_plain_for_a_plain_dsn(monkeypatch):
    monkeypatch.setattr(rds_iam, "RdsIamConnector", lambda **kw: pytest.fail("IAM connector used for a plain DSN"))
    with pytest.raises(DatabaseError):
        db.connect_factory(load_config(env={"CONSENTVAULT_DSN": "postgresql://n@127.0.0.1:1/x?connect_timeout=1"}))()


def test_jobs_connect_as_the_task_login_including_the_operator_job(iam_spy):
    from consentvault import cli

    seen, env = iam_spy
    assert cli._connect(load_config(env=env)) == "iam-conn:consentvault_runtime"
    op = load_config(env={**env, "CONSENTVAULT_DB_USER": "consentvault_operator_login"})
    assert db.connect(op.require_operator_dsn()) == "iam-conn:consentvault_operator_login"


def test_real_libpq_refuses_a_server_without_tls_as_a_tls_error(pg_server, ca):
    """Through libpq itself: verify-full against a server that offers no TLS never falls back to plaintext."""
    fresh = creds(expiration=datetime.now(timezone.utc) + timedelta(hours=1))  # real clock: never a fixed date
    c = RdsIamConnector(host="127.0.0.1", port=pg_server["port"], user="postgres", dbname="postgres",
                        region="us-east-1", ca_bundle=ca, credentials=StaticCreds(fresh), clock=_utc_now_clock())
    with pytest.raises(DatabaseTlsError, match=r"failed verification: OperationalError \(code cv-[g-z]{10}\)"):
        c.connect()


def _utc_now_clock():
    return lambda: datetime.now(timezone.utc)


# ------------------------------------------------------------------------------------------- review fixes


def test_the_file_region_wins_over_the_ambient_aws_region(tmp_path):
    toml = tmp_path / "consentvault.toml"
    toml.write_text('db_region = "us-east-1"\n')
    env = {k: v for k, v in IAM_ENV.items() if k != "CONSENTVAULT_DB_REGION"} | {"AWS_REGION": "eu-west-1"}
    assert "region=us-east-1" in load_config(toml, env=env).require_dsn()


def test_the_explicit_region_setting_wins_over_the_file(tmp_path):
    toml = tmp_path / "consentvault.toml"
    toml.write_text('db_region = "eu-west-1"\n')
    assert "region=us-east-1" in load_config(toml, env=IAM_ENV).require_dsn()


def test_a_region_that_disagrees_with_the_database_host_is_refused():
    with pytest.raises(ConfigError, match="eu-west-1.*us-east-1|us-east-1.*eu-west-1"):
        load_config(env={**IAM_ENV, "CONSENTVAULT_DB_REGION": "eu-west-1"})


def test_a_host_that_names_no_region_takes_the_setting_as_is():
    cfg = load_config(env={**IAM_ENV, "CONSENTVAULT_DB_HOST": "db.internal.example", "CONSENTVAULT_DB_REGION": "eu-west-1"})
    assert "region=eu-west-1" in cfg.require_dsn()


@pytest.mark.parametrize("port", ["5432²", "٥٤٣٢", " 5432", "0", "70000"])
def test_a_port_that_is_not_ascii_digits_in_range_is_refused(port):
    with pytest.raises(ConfigError, match="db_port"):
        load_config(env={**IAM_ENV, "CONSENTVAULT_DB_PORT": port})


@pytest.mark.parametrize("days", ["3²", "٣"])
def test_backup_retention_refuses_non_ascii_digits(days):
    with pytest.raises(ConfigError, match="backup_retention_days"):
        load_config(env={"CONSENTVAULT_BACKUP_RETENTION_DAYS": days})


def test_the_ca_bundle_defaults_to_the_path_the_image_ships():
    env = {k: v for k, v in IAM_ENV.items() if k != "CONSENTVAULT_DB_CA_BUNDLE"}
    assert "sslrootcert=%2Fetc%2Fconsentvault%2Frds-global-bundle.pem" in load_config(env=env).require_dsn()


@pytest.mark.parametrize("err", [psycopg.errors.InvalidPassword, psycopg.errors.InvalidAuthorizationSpecification])
def test_an_auth_error_code_is_classified_before_any_text(ca, err):
    with pytest.raises(DatabaseAuthError):  # the text mentions SSL, the SQLSTATE says authentication
        _connector(ca, pg=FakePg(err("FATAL: SSL connection has been closed unexpectedly"))).connect()


def test_credentials_with_under_five_minutes_left_are_not_refetched_on_every_connection(ca):
    clock, pg = Clock(), FakePg()
    meta = Meta((200, _meta_body(exp=T0 + timedelta(minutes=3))))
    src = ContainerCredentials(env={"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, fetch=meta, clock=clock)
    c = _connector(ca, clock=clock, pg=pg, source=src)
    for seconds in (0, 10, 20, 50):
        clock.t = T0 + timedelta(seconds=seconds)
        c.connect()
    assert len(meta.calls) == 1 and len({k["password"] for k in pg.calls}) == 1
    clock.t = T0 + timedelta(seconds=61)  # the short retry window has passed: look again, mint once
    c.connect()
    assert len(meta.calls) == 2 and len({k["password"] for k in pg.calls}) == 2


def test_credentials_about_to_expire_are_refused_by_name(ca):
    clock = Clock()
    src = StaticCreds(creds(expiration=T0 + timedelta(seconds=5)))
    with pytest.raises(DatabaseCredentialsError, match="expire"):
        _connector(ca, clock=clock, source=src).connect()


@pytest.mark.parametrize("exc", [__import__("http.client").client.BadStatusLine("garbage"),
                                 __import__("http.client").client.IncompleteRead(b"{"),
                                 ValueError("Invalid header value")])
def test_a_malformed_metadata_reply_is_a_credentials_error(exc):
    src = ContainerCredentials(env={"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, fetch=Meta(exc), clock=Clock())
    with pytest.raises(DatabaseCredentialsError):
        src.get()


@pytest.mark.parametrize("token", ["tok\r\nX-Injected: 1", "tok\nmore", "tok\x00"])
def test_an_authorization_token_with_a_line_break_is_refused_before_any_request(token):
    meta = Meta((200, _meta_body()))
    src = ContainerCredentials(env={"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials",
                                    "AWS_CONTAINER_AUTHORIZATION_TOKEN": token}, fetch=meta, clock=Clock())
    with pytest.raises(DatabaseCredentialsError, match="AUTHORIZATION_TOKEN"):
        src.get()
    assert meta.calls == []


def test_an_authorization_token_file_with_a_line_break_inside_is_refused(tmp_path):
    f = tmp_path / "token"
    f.write_text("tok\ninjected\n")
    src = ContainerCredentials(env={"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.23/v1/credentials",
                                    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": str(f)}, fetch=Meta((200, _meta_body())),
                               clock=Clock())
    with pytest.raises(DatabaseCredentialsError, match="AUTHORIZATION_TOKEN"):
        src.get()


# ------------------------------------------------------------------------------------------- second review round


class EchoPg:
    """A database that echoes the password it was given into its refusal, as a careless driver or server could."""

    def __init__(self, cls, template):
        self.cls, self.template = cls, template

    def __call__(self, **kw):
        raise self.cls(self.template.format(pw=kw["password"]))


@pytest.mark.parametrize("cls,template,err", [
    (psycopg.OperationalError, "SSL error for password {pw}: certificate verify failed", DatabaseTlsError),
    (psycopg.OperationalError, "FATAL: PAM authentication failed (password was {pw})", DatabaseAuthError),
    (psycopg.OperationalError, "connection to server failed; conninfo password={pw}", DatabaseError),
    (psycopg.errors.InvalidPassword, "bad password {pw}", DatabaseAuthError),
])
def test_the_token_never_appears_in_the_error_or_anything_it_carries(ca, cls, template, err):
    c = _connector(ca, pg=EchoPg(cls, template))
    token = c.token()
    with pytest.raises(err) as exc:
        c.connect()
    seen = [exc.value]
    while seen[-1].__cause__ is not None or seen[-1].__context__ is not None:
        seen.append(seen[-1].__cause__ or seen[-1].__context__)
    for e in seen:
        assert token not in str(e) and token not in repr(e) and token not in repr(e.args)
    # the driver's text, echo and all, is never carried: only its class and a stable code or SQLSTATE
    assert template.split("{pw}")[0].strip() not in str(exc.value) and re.search(r"\((code cv-[g-z]{10}|sqlstate [0-9A-Z]{5})\)", str(exc.value))


def test_the_region_check_reads_the_host_in_any_case():
    with pytest.raises(ConfigError, match="us-east-1"):
        load_config(env={**IAM_ENV, "CONSENTVAULT_DB_HOST": HOST.upper(), "CONSENTVAULT_DB_REGION": "eu-west-1"})
    assert "region=us-east-1" in load_config(env={**IAM_ENV, "CONSENTVAULT_DB_HOST": HOST.upper()}).require_dsn()


def test_a_failed_refresh_keeps_still_valid_credentials_and_backs_off():
    clock = Clock()
    meta = Meta((200, _meta_body(exp=T0 + timedelta(minutes=4))), (500, b"busy"), (500, b"busy"),
                (200, _meta_body(exp=T0 + timedelta(hours=6))))
    src = ContainerCredentials(env={"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, fetch=meta, clock=clock)
    first = src.get()
    clock.t = T0 + timedelta(seconds=61)  # inside the margin, retry window passed: refresh fails
    assert src.get() == first and len(meta.calls) == 2
    clock.t = T0 + timedelta(seconds=90)  # backing off: no new request
    assert src.get() == first and len(meta.calls) == 2
    clock.t = T0 + timedelta(seconds=125)  # next attempt fails too; still the valid ones
    assert src.get() == first and len(meta.calls) == 3
    clock.t = T0 + timedelta(seconds=190)
    assert src.get().expiration == T0 + timedelta(hours=6) and len(meta.calls) == 4


def test_a_failed_refresh_with_nothing_still_valid_is_loud():
    clock = Clock()
    meta = Meta((200, _meta_body(exp=T0 + timedelta(minutes=4))), (500, b"busy"))
    src = ContainerCredentials(env={"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/c"}, fetch=meta, clock=clock)
    src.get()
    clock.t = T0 + timedelta(minutes=3, seconds=55)  # under ten seconds left: nothing usable to fall back on
    with pytest.raises(DatabaseCredentialsError, match="HTTP 500"):
        src.get()
