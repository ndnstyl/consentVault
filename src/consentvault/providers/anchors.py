"""AnchorSink: publish a signed chain head somewhere the database owner cannot quietly rewrite.

Four sinks share one interface: a local file (one JSON line per anchor), a webhook (JSON POST, optionally
HMAC-signed), an S3 Object Lock bucket (one write-once object per anchor), and a tenant-owned sink, which is any of
the above pointed at a destination the tenant controls so the bundle's anchors can be checked against a source
outside the operator's hands. A sink that cannot publish raises ``AnchorSinkError``; it never returns quietly.
"""

from __future__ import annotations

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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping, Optional

from ..safelog import describe
from ..urlguard import open_no_redirect
from ._names import check_org_id
from .errors import (
    AnchorSinkError,
    EvidenceExistsError,
    EvidenceStoreError,
    ProviderConfigError,
    ProviderError,
)
from .evidence import EvidenceStore, S3ObjectLockEvidenceStore

Clock = Callable[[], datetime]
HTTP_TIMEOUT_S = 20
_HASH_RE = re.compile(r"^[0-9a-f]{16,128}$")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class AnchorReceipt:
    sink: str  # label, never carries credentials
    location: str  # file path, webhook URL without query, or object key
    record_sha256: str
    tenant_owned: bool


def _canonical(org_id: str, record: Mapping) -> tuple[dict, bytes]:
    check_org_id(org_id, AnchorSinkError)
    seq, row_hash = record.get("seq"), record.get("row_hash")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise AnchorSinkError("an anchor record needs a positive integer seq")
    if not isinstance(row_hash, str) or not _HASH_RE.match(row_hash):
        raise AnchorSinkError("an anchor record needs a lowercase hex row_hash")
    full = {**record, "org_id": org_id}
    try:
        return full, json.dumps(full, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AnchorSinkError(f"anchor record is not JSON-serialisable: {describe(exc)}") from exc


def _label_url(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    host = u.hostname or ""
    if u.port:
        host += f":{u.port}"
    return f"{u.scheme}://{host}{u.path}"


class AnchorSink(ABC):
    tenant_owned: bool = False

    @property
    @abstractmethod
    def label(self) -> str:
        """Safe-to-store name of the sink; never contains a secret or query string."""

    @abstractmethod
    def publish(self, org_id: str, record: Mapping) -> AnchorReceipt:
        """Publish ``{seq, row_hash, ...}`` for the org. Raises AnchorSinkError on any failure."""


class FileAnchorSink(AnchorSink):
    def __init__(self, path: str | Path):
        if not str(path):
            raise ProviderConfigError("a file anchor sink needs a path")
        self._path = Path(path)

    @property
    def label(self) -> str:
        return str(self._path)

    def publish(self, org_id: str, record: Mapping) -> AnchorReceipt:
        _, line = _canonical(org_id, record)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "ab") as fh:
                fh.write(line + b"\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise AnchorSinkError(f"cannot append to the anchor file {self._path}: {describe(exc)}") from exc
        return AnchorReceipt(self.label, str(self._path), hashlib.sha256(line).hexdigest(), self.tenant_owned)


WebhookTransport = Callable[[str, Mapping[str, str], bytes], int]


def _urllib_post(url: str, headers: Mapping[str, str], body: bytes) -> int:
    req = urllib.request.Request(url, data=body, method="POST", headers=dict(headers))
    try:
        with open_no_redirect(req, timeout=HTTP_TIMEOUT_S) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError as exc:
        raise AnchorSinkError(f"anchor webhook {_label_url(url)} unreachable: {describe(exc)}") from exc


class WebhookAnchorSink(AnchorSink):
    """POSTs the anchor JSON. With a ``secret`` the body is signed: ``X-ConsentVault-Signature: sha256=<hmac>``."""

    def __init__(self, url: str, *, secret: Optional[str] = None, transport: Optional[WebhookTransport] = None):
        u = urllib.parse.urlsplit(url)
        if u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost"):
            pass
        elif u.scheme != "https" or not u.hostname:
            raise ProviderConfigError("an anchor webhook must be https (plain http only for loopback)")
        self._url, self._secret = url, secret.encode("utf-8") if secret else None
        self._post = transport or _urllib_post

    @property
    def label(self) -> str:
        return _label_url(self._url)

    def publish(self, org_id: str, record: Mapping) -> AnchorReceipt:
        _, body = _canonical(org_id, record)
        headers = {"Content-Type": "application/json"}
        if self._secret:
            headers["X-ConsentVault-Signature"] = "sha256=" + hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        status = self._post(self._url, headers, body)
        if not 200 <= status < 300:
            raise AnchorSinkError(f"anchor webhook {self.label} answered HTTP {status}", code=f"http_{int(status)}")
        return AnchorReceipt(self.label, self.label, hashlib.sha256(body).hexdigest(), self.tenant_owned)


class S3ObjectLockAnchorSink(AnchorSink):
    """One write-once object per anchor under ``<org_id>/anchors/``. Republishing the same head is idempotent."""

    def __init__(self, store: EvidenceStore, *, retain_days: int = 365 * 7, clock: Clock = _utcnow,
                 label: str = "object-lock"):
        if not isinstance(retain_days, int) or retain_days < 1:
            raise ProviderConfigError("retain_days must be a positive integer")
        if not store.enforces_retention:
            raise ProviderConfigError("an Object Lock anchor sink needs a store that enforces retention")
        self._store, self._days, self._clock, self._label = store, retain_days, clock, label

    @property
    def label(self) -> str:
        return self._label

    def publish(self, org_id: str, record: Mapping) -> AnchorReceipt:
        full, body = _canonical(org_id, record)
        folder = "anchors" if not full.get("chain") else f"anchors-{full['chain']}"  # the raw post chain has its own folder
        key = f"{folder}/{full['seq']:012d}-{full['row_hash'][:32]}.json"
        try:
            self._store.put(org_id, key, body, retain_until=self._clock() + timedelta(days=self._days))
        except EvidenceExistsError:
            try:
                existing = json.loads(self._store.get(org_id, key))
            except (EvidenceStoreError, ValueError) as exc:
                raise AnchorSinkError(f"anchor object {org_id}/{key} exists and cannot be read back: {describe(exc)}") from exc
            if (existing.get("seq"), existing.get("row_hash")) != (full["seq"], full["row_hash"]):
                raise AnchorSinkError(f"anchor object {org_id}/{key} exists with a different head")
        except ProviderError as exc:
            raise AnchorSinkError(f"cannot write anchor object {org_id}/{key}: {describe(exc)}") from exc
        return AnchorReceipt(self.label, f"{org_id}/{key}", hashlib.sha256(body).hexdigest(), self.tenant_owned)


class TenantAnchorSink(AnchorSink):
    """A sink the tenant owns and controls: a tenant webhook or the tenant's own Object Lock bucket.

    It wraps one of the sinks above and marks receipts ``tenant_owned``, which is what lets a verifier compare
    the bundle's anchors against a record the operator cannot edit. Built from the tenant's saved settings by
    ``from_config``; credentials in the settings never appear in labels or receipts.
    """

    tenant_owned = True

    def __init__(self, delegate: AnchorSink, *, owner: str):
        if isinstance(delegate, FileAnchorSink):
            raise ProviderConfigError("a file on the operator's disk is not a tenant-owned sink")
        if not owner:
            raise ProviderConfigError("a tenant-owned sink names its owner")
        self._d, self._owner = delegate, owner

    @property
    def label(self) -> str:
        return f"tenant:{self._owner}:{self._d.label}"

    def publish(self, org_id: str, record: Mapping) -> AnchorReceipt:
        r = self._d.publish(org_id, record)
        return AnchorReceipt(self.label, r.location, r.record_sha256, True)

    @classmethod
    def from_config(cls, cfg: Mapping, *, owner: str, transport=None, clock: Clock = _utcnow) -> "TenantAnchorSink":
        kind = cfg.get("kind")
        needed = {"webhook": ("url",), "s3": ("endpoint", "bucket", "region", "access_key", "secret_key")}.get(kind, ())
        missing = [k for k in needed if k not in cfg]  # named from the settings themselves, never from an error's text
        if missing:
            raise ProviderConfigError(f"tenant anchor settings are missing {missing[0]!r}", code=f"missing_{missing[0]}")
        try:
            if kind == "webhook":
                return cls(WebhookAnchorSink(cfg["url"], secret=cfg.get("secret"), transport=transport), owner=owner)
            if kind == "s3":
                store = S3ObjectLockEvidenceStore(
                    endpoint=cfg["endpoint"], bucket=cfg["bucket"], region=cfg["region"],
                    access_key=cfg["access_key"], secret_key=cfg["secret_key"], transport=transport, clock=clock)
                return cls(S3ObjectLockAnchorSink(
                    store, retain_days=cfg.get("retain_days", 365 * 7), clock=clock,
                    label=f"s3://{cfg['bucket']}"), owner=owner)
        except KeyError as exc:
            raise ProviderConfigError(f"tenant anchor settings are missing a required setting ({describe(exc)})") from exc
        raise ProviderConfigError(f"tenant anchor kind must be 'webhook' or 's3', not {kind!r}")
