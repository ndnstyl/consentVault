"""EvidenceStore: write-once evidence objects with retention.

* ``S3ObjectLockEvidenceStore`` speaks the S3 REST protocol (AWS S3, MinIO, any S3-compatible store with Object
  Lock) through a minimal SigV4 signer and an injected transport; no SDK. Objects are written in COMPLIANCE mode
  with a retain-until date, never overwritten (``If-None-Match: *``), and verified by SHA-256 on read.
* ``LocalAppendOnlyEvidenceStore`` writes to a directory and refuses overwrite. It is chain-verified, NOT
  undeletable: anyone with filesystem access can delete the files. ``enforces_retention`` is False.

Objects live under a per-org prefix (``<org_id>/<key>``); names that could escape the prefix are refused.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping, Optional

from ..safelog import describe, http_error_response
from ..urlguard import open_no_redirect
from ._names import check_object_key, check_org_id
from .errors import (
    EvidenceExistsError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    EvidenceStoreError,
    InvalidEvidenceKeyError,
    ProviderConfigError,
    ProviderTransportError,
    RetentionError,
)

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class EvidenceRecord:
    org_id: str
    key: str
    sha256: str
    size: int
    retain_until: datetime
    version_id: Optional[str] = None


@dataclass(frozen=True)
class RetentionStatus:
    mode: str  # COMPLIANCE | LOCAL_APPEND_ONLY
    retain_until: datetime
    enforced: bool  # True only when the store itself refuses deletion before retain_until


def _aware(dt: datetime, what: str) -> datetime:
    if not isinstance(dt, datetime) or dt.tzinfo is None:
        raise RetentionError(f"{what} must be a timezone-aware datetime")
    return dt.astimezone(timezone.utc)


class EvidenceStore(ABC):
    @property
    @abstractmethod
    def enforces_retention(self) -> bool:
        """True only when the store itself refuses to delete or shorten retention before the date."""

    @abstractmethod
    def put(self, org_id: str, key: str, data: bytes, *, retain_until: datetime) -> EvidenceRecord:
        """Write a new object. Raises EvidenceExistsError if the key is taken; never overwrites."""

    @abstractmethod
    def get(self, org_id: str, key: str) -> bytes:
        """Read an object and check it against the digest recorded at write time."""

    @abstractmethod
    def verify_retention(self, org_id: str, key: str, *, min_retain_until: Optional[datetime] = None) -> RetentionStatus:
        """Confirm the object is locked until at least ``min_retain_until``; raises RetentionError if not."""


# ---------------------------------------------------------------------------------------------- SigV4


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sigv4_headers(*, method: str, host: str, path: str, query: str = "", headers: Mapping[str, str],
                  payload_sha256: str, access_key: str, secret_key: str, region: str, service: str = "s3",
                  amz_date: str, session_token: Optional[str] = None) -> dict[str, str]:
    """Return ``headers`` plus x-amz-date, x-amz-content-sha256 and Authorization (AWS Signature Version 4).

    ``path`` is the already-encoded canonical URI; ``query`` an already-canonical query string.
    """
    h = {k.lower(): " ".join(str(v).split()) for k, v in headers.items()}
    h["host"] = host
    h["x-amz-date"] = amz_date
    h["x-amz-content-sha256"] = payload_sha256
    if session_token:
        h["x-amz-security-token"] = session_token
    names = sorted(h)
    canonical = "\n".join([method, path, query, "".join(f"{n}:{h[n]}\n" for n in names), ";".join(names),
                           payload_sha256])
    day = amz_date[:8]
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, _sha256_hex(canonical.encode("utf-8"))])
    k = _hmac(("AWS4" + secret_key).encode("utf-8"), day)
    for part in (region, service, "aws4_request"):
        k = _hmac(k, part)
    sig = hmac.new(k, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out = dict(h)
    out["authorization"] = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={';'.join(names)}, "
                            f"Signature={sig}")
    return out


S3Transport = Callable[[str, str, Mapping[str, str], bytes], "tuple[int, Mapping[str, str], bytes]"]


def urllib_s3_transport(timeout_s: float = 30.0) -> S3Transport:
    """Real transport: ``(method, url, headers, body) -> (status, lower-cased headers, body)``. Does not follow redirects."""
    def send(method: str, url: str, headers: Mapping[str, str], body: bytes):
        req = urllib.request.Request(url, data=body if body else None, method=method, headers=dict(headers))
        try:
            with open_no_redirect(req, timeout=timeout_s) as resp:
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
        except urllib.error.HTTPError as exc:
            return http_error_response(exc)
        except OSError as exc:
            raise ProviderTransportError(f"S3 {method} {url} unreachable: {describe(exc)}") from exc

    return send


def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class S3ObjectLockEvidenceStore(EvidenceStore):
    """Path-style S3 client for a bucket created with Object Lock enabled. Writes are COMPLIANCE mode."""

    enforces_retention = True

    def __init__(self, *, endpoint: str, bucket: str, region: str, access_key: Optional[str] = None,
                 secret_key: Optional[str] = None, transport: Optional[S3Transport] = None,
                 session_token: Optional[str] = None, clock: Clock = _utcnow, min_retention: Optional[datetime] = None,
                 credentials=None, prefix: Optional[str] = None):
        """Static keys (``access_key``/``secret_key``), or ``credentials``: an object whose ``get()`` returns the
        current keys (the task role's, ``providers.rds_iam.ContainerCredentials``), read for every request. ``prefix``
        puts every object and listing under ``<prefix>/`` (a bucket shared by writers IAM keeps apart by prefix)."""
        if prefix is not None:
            check_object_key(prefix, ProviderConfigError)
        u = urllib.parse.urlsplit(endpoint)
        if u.scheme not in ("https", "http") or not u.hostname:
            raise ProviderConfigError("the S3 endpoint must be an http(s) URL")
        if u.scheme == "http" and u.hostname not in ("127.0.0.1", "localhost"):
            raise ProviderConfigError("plain http is allowed only for a loopback S3 endpoint")
        if not re.match(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", bucket or ""):
            raise ProviderConfigError(f"{bucket!r} is not a valid bucket name")
        if credentials is not None and (access_key or secret_key or session_token):
            raise ProviderConfigError("give static keys or a credential source, never both")
        if credentials is not None and not callable(getattr(credentials, "get", None)):
            raise ProviderConfigError("the credential source must offer get()")
        if not region or (credentials is None and not (access_key and secret_key)):
            raise ProviderConfigError("a region and either an access key and secret key or a credential source are "
                                      "required")
        self._creds = credentials
        self._prefix = f"{prefix}/" if prefix else ""
        self._scheme, self._host = u.scheme, u.netloc
        self._bucket, self._region = bucket, region
        self._ak, self._sk, self._token = access_key, secret_key, session_token
        self._send = transport or urllib_s3_transport()
        self._clock = clock

    def _object_path(self, org_id: str, key: str) -> str:
        check_org_id(org_id, InvalidEvidenceKeyError)
        check_object_key(key, InvalidEvidenceKeyError)
        return "/" + urllib.parse.quote(f"{self._bucket}/{self._prefix}{org_id}/{key}", safe="/-_.~")

    def _request(self, method: str, path: str, headers: Mapping[str, str], body: bytes = b"", query: str = ""):
        ak, sk, tok = self._ak, self._sk, self._token
        if self._creds is not None:
            c = self._creds.get()
            ak, sk, tok = c.access_key, c.secret_key, c.session_token
        signed = sigv4_headers(
            method=method, host=self._host, path=path, query=query, headers=headers, payload_sha256=_sha256_hex(body),
            access_key=ak, secret_key=sk, region=self._region,
            amz_date=self._clock().astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), session_token=tok)
        send_headers = {k: v for k, v in signed.items() if k != "host"}
        url = f"{self._scheme}://{self._host}{path}" + (f"?{query}" if query else "")
        status, resp_headers, resp_body = self._send(method, url, send_headers, body)
        return status, {k.lower(): v for k, v in resp_headers.items()}, resp_body

    MAX_LIST_PAGES = 10_000  # 1,000 keys a page: ten million objects for one organisation before the listing refuses

    def inventory(self, org_id: str, since: datetime) -> list[str]:
        """The object keys of ``org_id`` written after ``since`` (ListObjectsV2 under the organisation's prefix, every
        page, by each object's LastModified): what the restore reconcile re-checks in the cloud. A page that cannot be read,
        or a listing longer than ``MAX_LIST_PAGES``, raises; a partial listing is never returned."""
        import xml.etree.ElementTree as ET

        check_org_id(org_id, InvalidEvidenceKeyError)
        after = _aware(since, "since")
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        prefix, out, token = f"{self._prefix}{org_id}/", [], None
        path = "/" + urllib.parse.quote(self._bucket, safe="-_.~")
        for _ in range(self.MAX_LIST_PAGES):
            params = {"list-type": "2", "prefix": prefix, **({"continuation-token": token} if token else {})}
            query = "&".join(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
                             for k, v in sorted(params.items()))
            status, _, body = self._request("GET", path, {}, query=query)
            if status != 200:
                raise self._fail("LIST", status, body)
            try:
                root = ET.fromstring(body)
            except ET.ParseError as exc:
                raise EvidenceStoreError(f"S3 LIST answered a page that is not XML: {describe(exc)}") from exc
            for item in root.iter(f"{ns}Contents"):
                key, when = item.findtext(f"{ns}Key") or "", item.findtext(f"{ns}LastModified") or ""
                if not key.startswith(prefix):
                    raise EvidenceStoreError("S3 LIST answered a key outside the organisation's prefix")
                try:
                    modified = datetime.fromisoformat(when.replace("Z", "+00:00"))
                except ValueError as exc:
                    raise EvidenceStoreError(f"S3 LIST answered an unreadable LastModified {when!r}") from exc
                if _aware(modified, "LastModified") > after:
                    out.append(key[len(prefix):])
            if (root.findtext(f"{ns}IsTruncated") or "false").lower() != "true":
                return sorted(out)
            token = root.findtext(f"{ns}NextContinuationToken")
            if not token:
                raise EvidenceStoreError("S3 LIST said the listing continues but gave no continuation token")
        raise EvidenceStoreError(f"the listing of {org_id} is longer than {self.MAX_LIST_PAGES} pages; it was not used")

    @staticmethod
    def _fail(op: str, status: int, body: bytes) -> EvidenceStoreError:
        text = body[:300].decode("utf-8", "replace")
        if status >= 500 or status in (0, 429):
            return ProviderTransportError(f"S3 {op} answered HTTP {status}: {text}")  # type: ignore[return-value]
        return EvidenceStoreError(f"S3 {op} answered HTTP {status}: {text}")

    def put(self, org_id: str, key: str, data: bytes, *, retain_until: datetime) -> EvidenceRecord:
        if not isinstance(data, (bytes, bytearray)):
            raise EvidenceStoreError("evidence data must be bytes")
        until = _aware(retain_until, "retain_until")
        if until <= self._clock():
            raise RetentionError("retain_until is not in the future")
        path, digest = self._object_path(org_id, key), _sha256_hex(bytes(data))
        # S3 refuses an Object Lock write without an integrity header; the SHA-256 one is also checked by S3 on arrival.
        status, hdrs, body = self._request("PUT", path, {
            "content-md5": base64.b64encode(hashlib.md5(bytes(data), usedforsecurity=False).digest()).decode("ascii"),
            "x-amz-checksum-sha256": base64.b64encode(hashlib.sha256(bytes(data)).digest()).decode("ascii"),
            "if-none-match": "*",
            "x-amz-object-lock-mode": "COMPLIANCE",
            "x-amz-object-lock-retain-until-date": _iso_z(until),
            "x-amz-meta-sha256": digest,
            "content-type": "application/octet-stream",
        }, bytes(data))
        if status in (409, 412):
            raise EvidenceExistsError(f"an object already exists at {org_id}/{key}; evidence is never overwritten")
        if status not in (200, 201):
            raise self._fail("PUT", status, body)
        return EvidenceRecord(org_id, key, digest, len(data), until, hdrs.get("x-amz-version-id"))

    def get(self, org_id: str, key: str) -> bytes:
        status, hdrs, body = self._request("GET", self._object_path(org_id, key), {})
        if status == 404:
            raise EvidenceNotFoundError(f"no object at {org_id}/{key}")
        if status != 200:
            raise self._fail("GET", status, body)
        want = hdrs.get("x-amz-meta-sha256")
        if not want:
            raise EvidenceIntegrityError(f"object {org_id}/{key} carries no recorded sha256; it was not written by this store")
        if _sha256_hex(body) != want:
            raise EvidenceIntegrityError(f"object {org_id}/{key} does not match the sha256 recorded at write time")
        return body

    def verify_retention(self, org_id: str, key: str, *, min_retain_until: Optional[datetime] = None) -> RetentionStatus:
        status, hdrs, body = self._request("HEAD", self._object_path(org_id, key), {})
        if status == 404:
            raise EvidenceNotFoundError(f"no object at {org_id}/{key}")
        if status != 200:
            raise self._fail("HEAD", status, body)
        mode, raw = hdrs.get("x-amz-object-lock-mode"), hdrs.get("x-amz-object-lock-retain-until-date")
        if mode != "COMPLIANCE":
            raise RetentionError(f"object {org_id}/{key} is not in COMPLIANCE mode (mode: {mode})")
        if not raw:
            raise RetentionError(f"object {org_id}/{key} has no retain-until date")
        try:
            until = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RetentionError(f"object {org_id}/{key} has an unreadable retain-until date {raw!r}") from exc
        until = _aware(until, "retain-until")
        floor = _aware(min_retain_until, "min_retain_until") if min_retain_until else self._clock()
        if until < floor:
            raise RetentionError(f"object {org_id}/{key} is locked only until {until.isoformat()}, "
                                 f"below the required {floor.isoformat()}")
        return RetentionStatus("COMPLIANCE", until, True)


# ---------------------------------------------------------------------------------------------- local


class LocalAppendOnlyEvidenceStore(EvidenceStore):
    """Directory store: refuses overwrite, records a digest and retention beside each object.

    NOT undeletable. Anyone who can write to the directory can remove or replace files; verification detects
    that (digest mismatch, missing file) but cannot prevent it. ``enforces_retention`` is False.
    """

    enforces_retention = False

    def __init__(self, root: str | Path, *, clock: Clock = _utcnow):
        self._root = Path(root)
        self._clock = clock
        try:
            self._root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ProviderConfigError(f"cannot prepare the evidence directory {self._root}: {describe(exc)}") from exc

    def _paths(self, org_id: str, key: str) -> tuple[Path, Path]:
        check_org_id(org_id, InvalidEvidenceKeyError)
        check_object_key(key, InvalidEvidenceKeyError)
        if key.endswith(".meta.json") or ".tmp" in key:
            raise InvalidEvidenceKeyError(f"object key {key!r} collides with the store's own bookkeeping names")
        obj = self._root / org_id / "objects" / key
        return obj, obj.with_name(obj.name + ".meta.json")

    def put(self, org_id: str, key: str, data: bytes, *, retain_until: datetime) -> EvidenceRecord:
        if not isinstance(data, (bytes, bytearray)):
            raise EvidenceStoreError("evidence data must be bytes")
        until = _aware(retain_until, "retain_until")
        if until <= self._clock():
            raise RetentionError("retain_until is not in the future")
        obj, meta = self._paths(org_id, key)
        digest = _sha256_hex(bytes(data))
        tmp = obj.with_name(obj.name + f".tmp{os.getpid()}")
        try:
            obj.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, "xb") as fh:
                fh.write(bytes(data))
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o444)
            try:
                os.link(tmp, obj)  # atomic; fails if the key is taken, so no partial or replaced object
            except FileExistsError as exc:
                raise EvidenceExistsError(
                    f"an object already exists at {org_id}/{key}; evidence is never overwritten") from exc
            finally:
                tmp.unlink(missing_ok=True)
            with open(meta, "x", encoding="utf-8") as fh:
                json.dump({"sha256": digest, "size": len(data), "retain_until": until.isoformat(),
                           "written_at": self._clock().isoformat()}, fh, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(meta, 0o444)
        except EvidenceStoreError:
            raise
        except OSError as exc:
            raise EvidenceStoreError(f"cannot write evidence object {org_id}/{key}: {describe(exc)}") from exc
        return EvidenceRecord(org_id, key, digest, len(data), until)

    def _meta(self, org_id: str, key: str) -> dict:
        obj, meta = self._paths(org_id, key)
        if not obj.exists():
            raise EvidenceNotFoundError(f"no object at {org_id}/{key}")
        try:
            return json.loads(meta.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise EvidenceIntegrityError(f"object {org_id}/{key} has no metadata record") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceIntegrityError(f"metadata for {org_id}/{key} is unreadable: {describe(exc)}") from exc

    def get(self, org_id: str, key: str) -> bytes:
        meta = self._meta(org_id, key)
        obj, _ = self._paths(org_id, key)
        try:
            data = obj.read_bytes()
        except OSError as exc:
            raise EvidenceStoreError(f"cannot read evidence object {org_id}/{key}: {describe(exc)}") from exc
        if _sha256_hex(data) != meta.get("sha256"):
            raise EvidenceIntegrityError(f"object {org_id}/{key} does not match the sha256 recorded at write time")
        return data

    def verify_retention(self, org_id: str, key: str, *, min_retain_until: Optional[datetime] = None) -> RetentionStatus:
        meta = self._meta(org_id, key)
        self.get(org_id, key)
        try:
            until = _aware(datetime.fromisoformat(meta["retain_until"]), "retain_until")
        except (KeyError, ValueError) as exc:
            raise RetentionError(f"object {org_id}/{key} has no readable retain-until date") from exc
        floor = _aware(min_retain_until, "min_retain_until") if min_retain_until else self._clock()
        if until < floor:
            raise RetentionError(f"object {org_id}/{key} is retained only until {until.isoformat()}, "
                                 f"below the required {floor.isoformat()}")
        return RetentionStatus("LOCAL_APPEND_ONLY", until, False)
