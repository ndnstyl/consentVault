"""RDS IAM database authentication, hand-signed: no SDK.

A login token is a SigV4 presigned ``connect`` request for service ``rds-db``, valid 15 minutes, used as the password
over TLS verified against the RDS CA bundle (sslmode=verify-full). The signing credentials are the task role's, read
from the container credentials endpoint (``AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`` / ``_FULL_URI``) and cached until
five minutes before they expire. A connector mints a token for a new connection and reuses it until ``refresh_after_s``
(10 minutes by default), so no connection is ever opened on a token near its end. Every failure is a named error:
DatabaseCredentialsError, DatabaseSigningError, DatabaseTlsError, DatabaseAuthError (all DatabaseError).

The product selects it by DSN: ``rds-iam://<user>@<host>:<port>/<dbname>?region=<region>&sslrootcert=<ca bundle>``,
which config builds when ``db_auth = "iam"``. ``consentvault.db.connect`` routes that scheme here; a plain
``postgresql://`` DSN never touches this module.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping, Optional

from ..safelog import describe, http_error_response, sqlstate, text_has
from ..urlguard import UrlRefusedError, open_no_redirect
from ..errors import (
    ConfigError, DatabaseAuthError, DatabaseCredentialsError, DatabaseError, DatabaseSigningError, DatabaseTlsError)

SCHEME = "rds-iam"
SERVICE = "rds-db"
TOKEN_LIFETIME_S = 900
DEFAULT_REFRESH_AFTER_S = 600
CREDENTIAL_MARGIN = timedelta(minutes=5)
# Credentials the endpoint hands out already inside the margin are used, not refetched on every connection: they are
# looked at again after SHORT_RETRY, and refused outright once fewer than LAST_USABLE remain.
SHORT_RETRY = timedelta(seconds=60)
LAST_USABLE = timedelta(seconds=10)
# PostgreSQL's authentication SQLSTATEs: invalid_authorization_specification, invalid_password.
AUTH_SQLSTATES = ("28000", "28P01")
DEFAULT_PORT = 5432
ECS_CREDENTIALS_HOST = "169.254.170.2"
# Hosts a FULL_URI may name over plain http: the ECS and EKS pod-identity agents and loopback (the SDKs' own set).
_METADATA_HOSTS = {"169.254.170.2", "169.254.170.23", "fd00:ec2::23", "127.0.0.1", "localhost", "::1"}
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
_PORT_RE = re.compile(r"^\d{1,5}$")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

Clock = Callable[[], datetime]
Fetch = Callable[[str, Mapping[str, str]], "tuple[int, bytes]"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _q(value: str) -> str:
    return urllib.parse.quote(value, safe="-_.~")


# ---------------------------------------------------------------------------------------------- SigV4 presign


def sigv4_signing_key(secret_key: str, day: str, region: str, service: str) -> bytes:
    k = _hmac(("AWS4" + secret_key).encode("utf-8"), day)
    for part in (region, service, "aws4_request"):
        k = _hmac(k, part)
    return k


def sigv4_presign_query(*, method: str, host: str, path: str, params: Mapping[str, str], access_key: str,
                        secret_key: str, region: str, service: str, amz_date: str, expires: int,
                        payload_sha256: str = _EMPTY_SHA256, session_token: Optional[str] = None) -> str:
    """The canonical query string of a SigV4 query-signed request, ending in ``X-Amz-Signature``.

    ``path`` is the already-encoded canonical URI; the only signed header is ``host``.
    """
    scope = f"{amz_date[:8]}/{region}/{service}/aws4_request"
    q = dict(params)
    q.update({"X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": f"{access_key}/{scope}",
              "X-Amz-Date": amz_date, "X-Amz-Expires": str(int(expires)), "X-Amz-SignedHeaders": "host"})
    if session_token:
        q["X-Amz-Security-Token"] = session_token
    canonical_query = "&".join(f"{k}={v}" for k, v in sorted((_q(k), _q(v)) for k, v in q.items()))
    canonical = "\n".join([method, path, canonical_query, f"host:{host}\n", "host", payload_sha256])
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode("utf-8")).hexdigest()])
    sig = hmac.new(sigv4_signing_key(secret_key, amz_date[:8], region, service), to_sign.encode("utf-8"),
                   hashlib.sha256).hexdigest()
    return f"{canonical_query}&X-Amz-Signature={sig}"


@dataclass(frozen=True)
class AwsCredentials:
    access_key: str
    secret_key: str
    session_token: Optional[str]
    expiration: Optional[datetime]

    def __repr__(self) -> str:  # never print the secret or the session token
        return f"AwsCredentials(access_key={self.access_key!r}, expiration={self.expiration!r})"


def rds_auth_token(*, host: str, port: int, user: str, region: str, creds: AwsCredentials, now: datetime) -> str:
    """The RDS IAM login token: ``<host>:<port>/?Action=connect&DBUser=<user>&X-Amz-...`` (no scheme), 15 minutes."""
    problems = []
    if not host or not _HOST_RE.match(host):
        problems.append(f"host {host!r} is not a hostname")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        problems.append(f"port {port!r} is not a TCP port")
    if not user:
        problems.append("no database user")
    if not region or not _REGION_RE.match(region):
        problems.append(f"region {region!r} is not an AWS region name")
    if not isinstance(creds, AwsCredentials) or not creds.access_key or not creds.secret_key:
        problems.append("the credentials have no access key or no secret key")
    if not isinstance(now, datetime) or now.tzinfo is None:
        problems.append("the signing time is not a timezone-aware datetime")
    if problems:
        raise DatabaseSigningError("cannot sign the RDS login token: " + "; ".join(problems))
    try:
        query = sigv4_presign_query(
            method="GET", host=f"{host}:{port}", path="/", params={"Action": "connect", "DBUser": user},
            access_key=creds.access_key, secret_key=creds.secret_key, region=region, service=SERVICE,
            amz_date=now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), expires=TOKEN_LIFETIME_S,
            session_token=creds.session_token)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DatabaseSigningError(f"cannot sign the RDS login token: {describe(exc)}") from exc
    return f"{host}:{port}/?{query}"


# ---------------------------------------------------------------------------------------------- task role credentials


def urllib_fetch(timeout_s: float = 2.0) -> Fetch:
    """Real fetch for the credentials endpoint: ``(url, headers) -> (status, body)``. Does not follow redirects.

    A non-2xx answer is returned as its status, and the caller refuses anything but 200 by name. The endpoint is
    link-local (or loopback), so it never goes through HTTPS_PROXY / HTTP_PROXY: proxies are switched off here only.
    """

    def fetch(url: str, headers: Mapping[str, str]):
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host not in _METADATA_HOSTS:  # the proxy is skipped only for these exact hosts; any other address is refused, whatever its scheme
            raise UrlRefusedError(f"the credentials endpoint host {host!r} is not a container metadata host")
        req = urllib.request.Request(url, headers=dict(headers))
        try:
            with open_no_redirect(req, timeout=timeout_s, proxy=False, http_hosts=tuple(_METADATA_HOSTS)) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:  # loud-failure-exempt: the status is returned and ContainerCredentials refuses any non-200 by name
            status, _headers, body = http_error_response(exc)
            return status, body

    return fetch


class ContainerCredentials:
    """The task role's credentials from the container credentials endpoint, cached until five minutes before expiry."""

    def __init__(self, *, env: Optional[Mapping[str, str]] = None, fetch: Optional[Fetch] = None,
                 clock: Clock = _utcnow):
        self._env = env
        self._fetch = fetch or urllib_fetch()
        self._clock = clock
        self._cached: Optional[AwsCredentials] = None
        self._retry_at = datetime.min.replace(tzinfo=timezone.utc)
        self._lock = threading.Lock()

    def _endpoint(self) -> tuple[str, dict[str, str]]:
        env = os.environ if self._env is None else self._env
        rel, full = env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"), env.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        if rel:
            return f"http://{ECS_CREDENTIALS_HOST}{rel if rel.startswith('/') else '/' + rel}", {}
        if full:
            u = urllib.parse.urlsplit(full)
            if u.scheme not in ("http", "https") or (u.scheme == "http" and u.hostname not in _METADATA_HOSTS):
                raise DatabaseCredentialsError(
                    f"AWS_CONTAINER_CREDENTIALS_FULL_URI names {u.hostname!r}, which is not a container metadata "
                    "host; refusing to ask it for credentials")
            headers = {}
            auth = env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
            auth_file = env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
            if not auth and auth_file:
                try:
                    auth = Path(auth_file).read_text(encoding="utf-8").strip()
                except OSError as exc:
                    raise DatabaseCredentialsError(
                        f"cannot read AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: {describe(exc)}") from exc
            if auth:
                if any(ch in auth for ch in "\r\n\x00"):
                    raise DatabaseCredentialsError(
                        "AWS_CONTAINER_AUTHORIZATION_TOKEN (or its _FILE) holds a line break or NUL; refusing to send "
                        "it as a header")
                headers["Authorization"] = auth
            return full, headers
        raise DatabaseCredentialsError(
            "no task role credentials: neither AWS_CONTAINER_CREDENTIALS_RELATIVE_URI nor "
            "AWS_CONTAINER_CREDENTIALS_FULL_URI is set (IAM database login runs only inside a task with a role)")

    def get(self) -> AwsCredentials:
        with self._lock:
            now = self._clock()
            c = self._cached
            still_valid = c is not None and c.expiration is not None and c.expiration - LAST_USABLE > now
            if still_valid and (c.expiration - CREDENTIAL_MARGIN > now or now < self._retry_at):
                return c
            try:
                fresh = self._load(now)
            except DatabaseCredentialsError:
                if not still_valid:
                    raise
                # A refresh that fails while the held credentials are still usable keeps them and backs off; the
                # error surfaces once nothing usable is left.
                self._retry_at = now + SHORT_RETRY
                return c
            self._cached = fresh
            # Already inside the margin (the endpoint rotates shortly before expiry): use these, look again soon.
            self._retry_at = now + SHORT_RETRY
            return fresh

    def _load(self, now: datetime) -> AwsCredentials:
        url, headers = self._endpoint()
        try:
            status, body = self._fetch(url, headers)
        except OSError as exc:
            raise DatabaseCredentialsError(f"the container credentials endpoint is unreachable: {describe(exc)}") from exc
        except (http.client.HTTPException, ValueError) as exc:
            raise DatabaseCredentialsError(
                f"the container credentials endpoint gave a malformed reply: {describe(exc)}") from exc
        if status != 200:
            text = bytes(body)[:200].decode("utf-8", "replace")
            raise DatabaseCredentialsError(f"the container credentials endpoint answered HTTP {status}: {text}")
        try:
            doc = json.loads(body)
        except (ValueError, UnicodeError) as exc:
            raise DatabaseCredentialsError("the container credentials endpoint did not answer JSON") from exc
        if not isinstance(doc, dict):
            raise DatabaseCredentialsError("the container credentials endpoint did not answer a JSON object")
        for field in ("AccessKeyId", "SecretAccessKey", "Token", "Expiration"):
            if not isinstance(doc.get(field), str) or not doc[field]:
                raise DatabaseCredentialsError(f"the container credentials carry no {field}")
        try:
            exp = datetime.fromisoformat(doc["Expiration"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise DatabaseCredentialsError(
                f"the container credentials' Expiration {doc['Expiration']!r} is unreadable") from exc
        if exp.tzinfo is None:
            raise DatabaseCredentialsError("the container credentials' Expiration carries no time zone")
        if exp <= now:
            raise DatabaseCredentialsError(f"the container credentials expired at {exp.isoformat()}")
        return AwsCredentials(doc["AccessKeyId"], doc["SecretAccessKey"], doc["Token"], exp)


# ---------------------------------------------------------------------------------------------- the connector


_SECRET_PARTS = re.compile(r"(X-Amz-Signature=)[0-9a-fA-F]+|(X-Amz-Security-Token=)[^&\s'\")]+")


def _scrub(text: str, token: str) -> str:
    """The text with the token, and any signature or session token from one, replaced by a marker."""
    text = text.replace(token, "<token>")
    return _SECRET_PARTS.sub(lambda m: (m.group(1) or m.group(2)) + "<redacted>", text)


def _check_ca_bundle(path: str) -> None:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise DatabaseTlsError(f"the RDS CA bundle {path} cannot be read: {describe(exc)}") from exc
    if "-----BEGIN CERTIFICATE-----" not in text:
        raise DatabaseTlsError(f"the RDS CA bundle {path} holds no certificate")


class RdsIamConnector:
    """Opens connections as one login with an IAM token, verify-full against the CA bundle."""

    def __init__(self, *, host: str, port: int, user: str, dbname: str, region: str, ca_bundle: str,
                 credentials=None, clock: Clock = _utcnow, pg_connect=None,
                 refresh_after_s: int = DEFAULT_REFRESH_AFTER_S, connect_timeout_s: int = 15):
        if not 0 < refresh_after_s < TOKEN_LIFETIME_S:
            raise ConfigError(f"refresh_after_s must be above 0 and below the token's {TOKEN_LIFETIME_S} seconds")
        self.host, self.port, self.user, self.dbname = host, port, user, dbname
        self.region, self.ca_bundle = region, ca_bundle
        self._creds = credentials if credentials is not None else ContainerCredentials()
        self._clock = clock
        self._pg = pg_connect
        self._refresh = timedelta(seconds=refresh_after_s)
        self._timeout = connect_timeout_s
        self._token: Optional[str] = None
        self._renew_at: Optional[datetime] = None
        self._lock = threading.Lock()

    def token(self) -> str:
        """The current token; a new one once ``refresh_after_s`` passed or the credentials near their expiry."""
        with self._lock:
            now = self._clock()
            if self._token is not None and self._renew_at is not None and now < self._renew_at:
                return self._token
            creds = self._creds.get()
            token = rds_auth_token(host=self.host, port=self.port, user=self.user, region=self.region,
                                   creds=creds, now=now)
            renew = now + self._refresh
            if creds.expiration is not None:
                if creds.expiration - LAST_USABLE <= now:
                    raise DatabaseCredentialsError(
                        f"the task role credentials expire at {creds.expiration.isoformat()}, too soon to sign with")
                renew = min(renew, creds.expiration - CREDENTIAL_MARGIN)
                if renew <= now:  # inside the margin: keep this token briefly instead of re-signing every connection
                    renew = min(now + SHORT_RETRY, creds.expiration - LAST_USABLE)
            self._token, self._renew_at = token, renew
            return token

    def connect(self):
        import psycopg
        from psycopg.rows import dict_row

        _check_ca_bundle(self.ca_bundle)
        token = self.token()
        pg = self._pg or psycopg.connect
        try:
            return pg(host=self.host, port=self.port, user=self.user, dbname=self.dbname, password=token,
                      sslmode="verify-full", sslrootcert=self.ca_bundle, connect_timeout=self._timeout,
                      autocommit=True, row_factory=dict_row)
        except psycopg.Error as exc:
            # Only the scrubbed text and the SQLSTATE leave this block: the driver's exception (which may echo the
            # token) is never chained, so it is not reachable from the error raised below.
            failure = (describe(exc), sqlstate(exc), text_has(exc, "ssl", "certificate"), text_has(exc, "authentication failed"))
        msg, state, tls, auth = failure
        where = f"{self.user}@{self.host}:{self.port}/{self.dbname}"
        if state in AUTH_SQLSTATES:
            raise DatabaseAuthError(f"the database {where} refused the IAM login token (SQLSTATE {state}): {msg}")
        if tls:
            raise DatabaseTlsError(f"TLS to the database {where} failed verification: {msg}")
        if auth:
            raise DatabaseAuthError(f"the database {where} refused the IAM login token: {msg}")
        raise DatabaseError(f"cannot connect to the database {where} with IAM auth: {msg}")


# ---------------------------------------------------------------------------------------------- the DSN


def build_dsn(*, user: str, host: str, port: int, dbname: str, region: str, ca_bundle: str) -> str:
    return (f"{SCHEME}://{_q(user)}@{host}:{int(port)}/{_q(dbname)}?"
            + urllib.parse.urlencode({"region": region, "sslrootcert": ca_bundle}))


def parse_dsn(dsn: str) -> dict:
    u = urllib.parse.urlsplit(dsn)
    if u.scheme != SCHEME:
        raise ConfigError(f"not an {SCHEME} DSN")
    q = dict(urllib.parse.parse_qsl(u.query))
    problems = []
    if not u.username:
        problems.append("no user")
    if u.password is not None:
        problems.append("a password (IAM login takes none; the token is the password)")
    if not u.hostname:
        problems.append("no host")
    hostport = u.netloc.rsplit("@", 1)[-1]
    raw_port = hostport.rpartition(":")[2] if ":" in hostport else ""
    if raw_port and not _PORT_RE.match(raw_port):
        problems.append("a port that is not a number")
    port = int(raw_port) if raw_port and _PORT_RE.match(raw_port) else DEFAULT_PORT
    dbname = urllib.parse.unquote(u.path.lstrip("/"))
    if not dbname:
        problems.append("no database name")
    for key in ("region", "sslrootcert"):
        if not q.get(key):
            problems.append(f"no {key}")
    if problems:
        raise ConfigError(f"the {SCHEME} DSN has " + ", ".join(problems))
    return {"host": u.hostname, "port": port, "user": urllib.parse.unquote(u.username), "dbname": dbname,
            "region": q["region"], "ca_bundle": q["sslrootcert"]}


_CONNECTORS: dict = {}
_REGISTRY_LOCK = threading.Lock()
_SHARED_CREDENTIALS: Optional[ContainerCredentials] = None


def connect_dsn(dsn: str):
    """Connect for an rds-iam DSN through one connector per login per process (one token cache, one credential cache)."""
    global _SHARED_CREDENTIALS
    kw = parse_dsn(dsn)
    key = tuple(sorted(kw.items()))
    with _REGISTRY_LOCK:
        conn = _CONNECTORS.get(key)
        if conn is None:
            if _SHARED_CREDENTIALS is None:
                _SHARED_CREDENTIALS = ContainerCredentials()
            conn = RdsIamConnector(credentials=_SHARED_CREDENTIALS, **kw)
            _CONNECTORS[key] = conn
    return conn.connect()
