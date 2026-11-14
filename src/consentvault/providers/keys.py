"""KeyProvider: per-org key custody.

One interface, two open implementations. The managed service plugs an AWS KMS adapter into the same interface
from the private repository, named by configuration through ``consentvault.providers.plugins``.

* ``OpenBaoKeyProvider`` talks to an OpenBao (or HashiCorp Vault) transit engine over HTTP. A transit key can be
  deleted for real, so destruction here is provable when the server is backed by an HSM or a managed seal.
* ``LocalFileKeyProvider`` keeps one passphrase-sealed key file per org. It encrypts, but it gives NO PROVABLE
  DESTRUCTION: a copy of the key file taken before destruction undoes the shredding. ``provable_destruction`` is
  ``False`` and callers must read it before they promise anyone that erasure is irreversible.

Destruction follows the cloud KMS model: scheduling starts a waiting window (never shorter than 30 days), the key
is unusable while pending, scheduling can be cancelled during the window, and ``process_destructions`` carries out
every destruction that has come due and records it. Time comes from an injected clock so the window is testable.

Rotation: an org key has versions. ``rotate_org_key`` makes a new version the active one; ``wrap`` always wraps under
the active version and ``unwrap`` reads the version from the wrap itself, so every caller of ``wrap``/``unwrap`` is
version-aware without a schema change. A version-1 wrap keeps the format it always had (no header); a later version's
wrap is ``CVKV`` + the version (4 bytes, big endian) + the provider's ciphertext. ``rewrap`` moves a wrap to the active
version with the same data key. ``destroy_version`` destroys one retired version (never the active one); the caller
proves first that nothing it holds is still wrapped under it. Destroying the organisation destroys every version.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..safelog import describe, http_error_response
from ..urlguard import open_no_redirect
from ._names import check_org_id
from .errors import (
    DestructionWindowError,
    KeyDestroyedError,
    KeyExistsError,
    KeyNotFoundError,
    KeyPendingDestructionError,
    KeyProviderError,
    ProviderConfigError,
    ProviderTransportError,
    UnwrapError,
)

MIN_DESTRUCTION_DAYS = 30
VERSION_MAGIC = b"CVKV"
_VERSION_HEADER = len(VERSION_MAGIC) + 4

Clock = Callable[[], datetime]


def wrapped_version(wrapped: bytes) -> int:
    """The org key version a wrap was made under: the header's version, or 1 for a wrap with no header."""
    if not isinstance(wrapped, (bytes, bytearray, memoryview)):
        raise UnwrapError("a wrapped key must be bytes")
    blob = bytes(wrapped)
    if len(blob) > _VERSION_HEADER and blob[:len(VERSION_MAGIC)] == VERSION_MAGIC:
        version = int.from_bytes(blob[len(VERSION_MAGIC):_VERSION_HEADER], "big")
        if version < 2:
            raise UnwrapError(f"a versioned wrap names version {version}; versioned wraps start at 2")
        return version
    return 1


def _versioned(version: int, inner: bytes) -> bytes:
    return inner if version == 1 else VERSION_MAGIC + version.to_bytes(4, "big") + inner


def _inner(wrapped: bytes) -> bytes:
    blob = bytes(wrapped)
    return blob[_VERSION_HEADER:] if wrapped_version(blob) > 1 else blob


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class DestructionStatus:
    """``state`` is ``active``, ``pending`` or ``destroyed``."""

    org_id: str
    state: str
    scheduled_at: Optional[datetime] = None
    destroy_at: Optional[datetime] = None
    destroyed_at: Optional[datetime] = None


class KeyProvider(ABC):
    """Custody of one wrap key per org. Data keys are 16 to 64 bytes of caller-generated key material."""

    @property
    @abstractmethod
    def provable_destruction(self) -> bool:
        """True only when destroying a key provably removes every copy (HSM or managed KMS)."""

    @abstractmethod
    def create_org_key(self, org_id: str) -> str:
        """Create the org's wrap key; returns an opaque key reference. Refuses to overwrite an existing key."""

    @abstractmethod
    def wrap(self, org_id: str, data_key: bytes) -> bytes:
        """Wrap a data key under the org key."""

    @abstractmethod
    def unwrap(self, org_id: str, wrapped: bytes) -> bytes:
        """Return the data key; raises UnwrapError on a wrong key or altered ciphertext."""

    @abstractmethod
    def schedule_destruction(self, org_id: str, *, window_days: int = MIN_DESTRUCTION_DAYS) -> DestructionStatus:
        """Start the waiting window. Raises DestructionWindowError for fewer than 30 days."""

    @abstractmethod
    def cancel_destruction(self, org_id: str) -> DestructionStatus:
        """Cancel a pending destruction; refused once the key is destroyed."""

    @abstractmethod
    def process_destructions(self) -> list[str]:
        """Destroy every key whose window has elapsed; returns the org ids destroyed by this call."""

    @abstractmethod
    def status(self, org_id: str) -> DestructionStatus:
        """The org key's lifecycle state."""

    @abstractmethod
    def is_destroyed(self, org_id: str) -> bool:
        """Report whether the key is destroyed, checked against the backing store, not only the ledger."""

    def active_version(self, org_id: str) -> int:
        """The version ``wrap`` wraps under."""
        raise KeyProviderError(f"{type(self).__name__} does not support org key rotation")

    def rotate_org_key(self, org_id: str) -> tuple[int, str]:
        """Create the next version and make it active; returns (version, opaque key reference)."""
        raise KeyProviderError(f"{type(self).__name__} does not support org key rotation")

    def destroy_version(self, org_id: str, version: int) -> bool:
        """Destroy one retired version. True when this call destroyed it, False when it was already destroyed."""
        raise KeyProviderError(f"{type(self).__name__} does not support org key rotation")

    def versions(self, org_id: str) -> dict[int, str]:
        """Every version of the org key and its state: ``active``, ``retired`` or ``destroyed``."""
        raise KeyProviderError(f"{type(self).__name__} does not support org key rotation")

    def version_ref(self, org_id: str, version: int) -> str:
        """The opaque key reference of one version (what ``rotate_org_key`` returned for it)."""
        raise KeyProviderError(f"{type(self).__name__} does not support org key rotation")

    def rewrap(self, org_id: str, wrapped: bytes) -> bytes:
        """The same data key wrapped under the active version (the wrap itself when it already is)."""
        if wrapped_version(wrapped) == self.active_version(org_id):
            return bytes(wrapped)
        return self.wrap(org_id, self.unwrap(org_id, wrapped))


class _VersionLedger:
    """Durable record of each org's active version and destroyed versions: one JSON file, replaced atomically."""

    def __init__(self, path: Path, clock: Clock):
        self._file = _DestructionLedger(path, clock)
        self._clock = clock

    def get(self, org_id: str) -> tuple[int, dict[int, str]]:
        row = self._file._read().get(org_id) or {}
        active = row.get("active", 1)
        destroyed = {int(k): v for k, v in (row.get("destroyed") or {}).items()}
        if not isinstance(active, int) or active < 1:
            raise KeyProviderError(f"the version ledger holds a malformed active version for org {org_id}")
        return active, destroyed

    def set_active(self, org_id: str, version: int) -> None:
        data = self._file._read()
        row = data.setdefault(org_id, {})
        row["active"] = version
        self._file._write(data)

    def mark_destroyed(self, org_id: str, version: int) -> None:
        data = self._file._read()
        row = data.setdefault(org_id, {})
        row.setdefault("destroyed", {})[str(version)] = self._clock().isoformat()
        self._file._write(data)

    def states(self, org_id: str, org_destroyed: bool) -> dict[int, str]:
        active, destroyed = self.get(org_id)
        out = {}
        for v in range(1, active + 1):
            out[v] = "destroyed" if org_destroyed or v in destroyed else ("active" if v == active else "retired")
        return out

    def check_usable(self, org_id: str, version: int) -> None:
        active, destroyed = self.get(org_id)
        if version in destroyed:
            raise KeyDestroyedError(f"version {version} of the key for org {org_id} was destroyed at {destroyed[version]}")
        if version > active:
            raise KeyNotFoundError(f"org {org_id} has no key version {version} (the active version is {active})")

    def check_destroyable(self, org_id: str, version: int) -> bool:
        """True when the version may be destroyed now, False when it already was; raises when it is active or unknown."""
        active, destroyed = self.get(org_id)
        if not isinstance(version, int) or isinstance(version, bool) or version < 1 or version > active:
            raise KeyNotFoundError(f"org {org_id} has no key version {version!r}")
        if version == active:
            raise KeyProviderError(f"version {version} is the active key version of org {org_id}; the active version "
                                   "is never destroyed (rotate first)")
        return version not in destroyed


class _DestructionLedger:
    """Durable record of scheduled and completed destructions: one JSON file, replaced atomically."""

    def __init__(self, path: Path, clock: Clock):
        self._path = Path(path)
        self._clock = clock

    def _read(self) -> dict:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise KeyProviderError(f"cannot read the destruction ledger {self._path}: {describe(exc)}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise KeyProviderError(f"destruction ledger {self._path} is not valid JSON: {describe(exc)}") from exc
        if not isinstance(data, dict):
            raise KeyProviderError(f"destruction ledger {self._path} must hold a JSON object")
        return data

    def _write(self, data: dict) -> None:
        tmp = self._path.with_name(self._path.name + ".tmp")
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except OSError as exc:
            raise KeyProviderError(f"cannot write the destruction ledger {self._path}: {describe(exc)}") from exc

    @staticmethod
    def _to_status(org_id: str, row: Optional[dict]) -> DestructionStatus:
        if not row:
            return DestructionStatus(org_id, "active")

        def ts(name: str) -> Optional[datetime]:
            return datetime.fromisoformat(row[name]) if row.get(name) else None

        state = "destroyed" if row.get("destroyed_at") else "pending"
        return DestructionStatus(org_id, state, ts("scheduled_at"), ts("destroy_at"), ts("destroyed_at"))

    def get(self, org_id: str) -> DestructionStatus:
        return self._to_status(org_id, self._read().get(org_id))

    def schedule(self, org_id: str, window_days: int) -> DestructionStatus:
        if not isinstance(window_days, int) or isinstance(window_days, bool) or window_days < MIN_DESTRUCTION_DAYS:
            raise DestructionWindowError(
                f"destruction window of {window_days!r} days is below the {MIN_DESTRUCTION_DAYS}-day floor")
        data = self._read()
        current = self._to_status(org_id, data.get(org_id))
        if current.state == "destroyed":
            raise KeyDestroyedError(f"the key for org {org_id} is already destroyed")
        if current.state == "pending":
            raise KeyProviderError(f"destruction for org {org_id} is already scheduled for {current.destroy_at.isoformat()}")
        now = self._clock()
        data[org_id] = {"scheduled_at": now.isoformat(), "destroy_at": (now + timedelta(days=window_days)).isoformat()}
        self._write(data)
        return self._to_status(org_id, data[org_id])

    def cancel(self, org_id: str) -> DestructionStatus:
        data = self._read()
        current = self._to_status(org_id, data.get(org_id))
        if current.state == "destroyed":
            raise KeyDestroyedError(f"the key for org {org_id} is already destroyed; a destruction cannot be cancelled")
        if current.state == "active":
            raise KeyProviderError(f"no destruction is scheduled for org {org_id}")
        del data[org_id]
        self._write(data)
        return self._to_status(org_id, None)

    def due(self) -> list[str]:
        now = self._clock()
        return sorted(
            org for org, row in self._read().items()
            if not row.get("destroyed_at") and datetime.fromisoformat(row["destroy_at"]) <= now)

    def mark_destroyed(self, org_id: str) -> DestructionStatus:
        data = self._read()
        if org_id not in data:
            raise KeyProviderError(f"no destruction is scheduled for org {org_id}")
        data[org_id]["destroyed_at"] = self._clock().isoformat()
        self._write(data)
        return self._to_status(org_id, data[org_id])


def _require_usable(status: DestructionStatus) -> None:
    if status.state == "destroyed":
        raise KeyDestroyedError(f"the key for org {status.org_id} was destroyed at {status.destroyed_at.isoformat()}")
    if status.state == "pending":
        raise KeyPendingDestructionError(
            f"the key for org {status.org_id} is scheduled for destruction at {status.destroy_at.isoformat()}; "
            "cancel the schedule to use it")


def _check_data_key(data_key: bytes) -> None:
    if not isinstance(data_key, (bytes, bytearray)) or not 16 <= len(data_key) <= 64:
        raise KeyProviderError("a data key must be 16 to 64 bytes")


# ---------------------------------------------------------------------------------------------- local file


class LocalFileKeyProvider(KeyProvider):
    """One passphrase-sealed key file per org under ``root``.

    NO PROVABLE DESTRUCTION. Destruction overwrites and deletes the key file, but a backup, a snapshot or a copy
    of the file taken earlier still decrypts everything it wrapped. Read ``provable_destruction`` (False) and
    ``destruction_caveat`` before telling anyone erasure is irreversible; use OpenBao with an HSM or a cloud KMS
    when that promise is needed.
    """

    provable_destruction = False
    destruction_caveat = (
        "no provable destruction: a copy of the key file made before destruction still decrypts the data it wrapped")

    _SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32, "maxmem": 64 * 1024 * 1024}

    def __init__(self, root: str | Path, passphrase: str, *, clock: Clock = _utcnow):
        if not isinstance(passphrase, str) or len(passphrase) < 12:
            raise ProviderConfigError("the key passphrase must be at least 12 characters")
        self._root = Path(root)
        self._passphrase = passphrase.encode("utf-8")
        self._clock = clock
        self._ledger = _DestructionLedger(self._root / "destruction.json", clock)
        self._versions = _VersionLedger(self._root / "versions.json", clock)
        self._cache: dict[tuple[str, int], bytes] = {}
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            os.chmod(self._root, 0o700)
        except OSError as exc:
            raise ProviderConfigError(f"cannot prepare the key directory {self._root}: {describe(exc)}") from exc

    def _path(self, org_id: str) -> Path:
        return self._root / f"{check_org_id(org_id, ProviderConfigError)}.key.json"

    def _kek(self, salt: bytes) -> bytes:
        return hashlib.scrypt(self._passphrase, salt=salt, **self._SCRYPT)

    def _vpath(self, org_id: str, version: int) -> Path:
        return self._path(org_id) if version == 1 else self._root / f"{check_org_id(org_id, ProviderConfigError)}.v{version}.key.json"

    @staticmethod
    def _aad(org_id: str, version: int) -> bytes:
        return org_id.encode("utf-8") if version == 1 else f"{org_id}/v{version}".encode("utf-8")

    def _write_key_file(self, org_id: str, version: int) -> None:
        path = self._vpath(org_id, version)
        salt, nonce, org_key = secrets.token_bytes(16), secrets.token_bytes(12), AESGCM.generate_key(256)
        sealed = AESGCM(self._kek(salt)).encrypt(nonce, org_key, self._aad(org_id, version))
        body = json.dumps({"v": 1, "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
                           "ct": base64.b64encode(sealed).decode()})
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise KeyExistsError(f"a key file already exists for org {org_id} version {version}") from exc
        except OSError as exc:
            raise KeyProviderError(f"cannot create the key file for org {org_id}: {describe(exc)}") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise KeyProviderError(f"cannot write the key file for org {org_id}: {describe(exc)}") from exc

    def create_org_key(self, org_id: str) -> str:
        self._path(org_id)
        if self._ledger.get(org_id).state == "destroyed":
            raise KeyDestroyedError(f"the key for org {org_id} was destroyed; a destroyed org key is never recreated")
        try:
            self._write_key_file(org_id, 1)
        except KeyExistsError as exc:
            raise KeyExistsError(f"a key file already exists for org {org_id}") from exc
        return f"local:{org_id}"

    def _org_key(self, org_id: str, version: int = 1) -> bytes:
        _require_usable(self._ledger.get(org_id))
        self._versions.check_usable(org_id, version)
        if (org_id, version) in self._cache:
            return self._cache[(org_id, version)]
        path = self._vpath(org_id, version)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise KeyNotFoundError(f"no key exists for org {org_id}" + ("" if version == 1 else f" version {version}")) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyProviderError(f"cannot read the key file for org {org_id}: {describe(exc)}") from exc
        try:
            salt, nonce, ct = (base64.b64decode(doc[k], validate=True) for k in ("salt", "nonce", "ct"))
            org_key = AESGCM(self._kek(salt)).decrypt(nonce, ct, self._aad(org_id, version))
        except (KeyError, binascii.Error) as exc:
            raise KeyProviderError(f"the key file for org {org_id} is malformed: {describe(exc)}") from exc
        except InvalidTag as exc:
            raise KeyProviderError(f"the key file for org {org_id} did not open: wrong passphrase or altered file") from exc
        self._cache[(org_id, version)] = org_key
        return org_key

    def active_version(self, org_id: str) -> int:
        check_org_id(org_id, ProviderConfigError)
        return self._versions.get(org_id)[0]

    def wrap(self, org_id: str, data_key: bytes) -> bytes:
        _check_data_key(data_key)
        version = self.active_version(org_id)
        key = self._org_key(org_id, version)
        while True:  # a version-1 wrap never starts with the version header, so its version is never misread
            nonce = secrets.token_bytes(12)
            if version > 1 or nonce[:len(VERSION_MAGIC)] != VERSION_MAGIC:
                break
        inner = nonce + AESGCM(key).encrypt(nonce, bytes(data_key), org_id.encode("utf-8"))
        return _versioned(version, inner)

    def unwrap(self, org_id: str, wrapped: bytes) -> bytes:
        version = wrapped_version(wrapped)
        key = self._org_key(org_id, version)
        inner = _inner(wrapped)
        if len(inner) < 12 + 16 + 16:
            raise UnwrapError("wrapped key is too short to be a wrapped data key")
        try:
            return AESGCM(key).decrypt(inner[:12], inner[12:], org_id.encode("utf-8"))
        except InvalidTag as exc:
            raise UnwrapError(f"wrapped key for org {org_id} did not unwrap: wrong org key or altered ciphertext") from exc

    def rotate_org_key(self, org_id: str) -> tuple[int, str]:
        current = self.active_version(org_id)
        self._org_key(org_id, current)  # the org key is usable (not pending, not destroyed) and present
        nxt = current + 1
        if not self._vpath(org_id, nxt).exists():  # a file left by a rotation that stopped before the ledger is adopted
            self._write_key_file(org_id, nxt)
        self._versions.set_active(org_id, nxt)
        return nxt, self.version_ref(org_id, nxt)

    def version_ref(self, org_id: str, version: int) -> str:
        self._versions.check_usable(check_org_id(org_id, ProviderConfigError), version)
        return f"local:{org_id}" if version == 1 else f"local:{org_id}:v{version}"

    def _shred(self, path: Path, org_id: str) -> None:
        try:
            size = path.stat().st_size
            with open(path, "r+b") as fh:
                fh.write(secrets.token_bytes(size))
                fh.flush()
                os.fsync(fh.fileno())
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise KeyProviderError(f"cannot destroy the key file for org {org_id}: {describe(exc)}") from exc

    def destroy_version(self, org_id: str, version: int) -> bool:
        _require_usable(self._ledger.get(check_org_id(org_id, ProviderConfigError)))
        if not self._versions.check_destroyable(org_id, version):
            return False
        self._shred(self._vpath(org_id, version), org_id)
        self._cache.pop((org_id, version), None)
        self._versions.mark_destroyed(org_id, version)
        return True

    def versions(self, org_id: str) -> dict[int, str]:
        check_org_id(org_id, ProviderConfigError)
        return self._versions.states(org_id, self._ledger.get(org_id).state == "destroyed")

    def schedule_destruction(self, org_id: str, *, window_days: int = MIN_DESTRUCTION_DAYS) -> DestructionStatus:
        if not self._path(org_id).exists():
            raise KeyNotFoundError(f"no key exists for org {org_id}")
        return self._ledger.schedule(org_id, window_days)

    def cancel_destruction(self, org_id: str) -> DestructionStatus:
        return self._ledger.cancel(check_org_id(org_id, ProviderConfigError))

    def process_destructions(self) -> list[str]:
        done = []
        for org_id in self._ledger.due():
            for version in range(1, self._versions.get(org_id)[0] + 1):  # every version dies with the organisation
                self._shred(self._vpath(org_id, version), org_id)
                self._cache.pop((org_id, version), None)
            self._ledger.mark_destroyed(org_id)
            done.append(org_id)
        return done

    def status(self, org_id: str) -> DestructionStatus:
        return self._ledger.get(check_org_id(org_id, ProviderConfigError))

    def is_destroyed(self, org_id: str) -> bool:
        st = self.status(org_id)
        if st.state == "destroyed" and any(self._vpath(org_id, v).exists()
                                           for v in range(1, self._versions.get(org_id)[0] + 1)):
            raise KeyProviderError(f"the ledger says org {org_id} is destroyed but its key file still exists")
        return st.state == "destroyed"


# ---------------------------------------------------------------------------------------------- OpenBao

Transport = Callable[[str, str, Optional[dict]], "tuple[int, dict]"]


class UrllibBaoTransport:
    """HTTP transport for a real OpenBao server: ``(method, path, body) -> (status, json)``. Never logs the token."""

    def __init__(self, address: str, token: str, *, timeout_s: float = 10.0, namespace: Optional[str] = None):
        if not address.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise ProviderConfigError("the OpenBao address must be https (plain http only for loopback)")
        if not token:
            raise ProviderConfigError("an OpenBao token is required")
        self._address, self._token, self._timeout, self._ns = address.rstrip("/"), token, timeout_s, namespace

    def __call__(self, method: str, path: str, body: Optional[dict]) -> tuple[int, dict]:
        headers = {"X-Vault-Token": self._token, "Content-Type": "application/json"}
        if self._ns:
            headers["X-Vault-Namespace"] = self._ns
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(f"{self._address}{path}", data=data, method=method, headers=headers)
        try:
            with open_no_redirect(req, timeout=self._timeout) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as exc:
            status, _headers, raw = http_error_response(exc)
        except OSError as exc:
            raise ProviderTransportError(f"OpenBao {method} {path} unreachable: {describe(exc)}") from exc
        try:
            return status, (json.loads(raw) if raw else {})
        except json.JSONDecodeError as exc:
            raise ProviderTransportError(f"OpenBao {method} {path} answered HTTP {status} with a non-JSON body") from exc


class OpenBaoKeyProvider(KeyProvider):
    """Per-org AES-256 keys in an OpenBao transit engine. The key never leaves the server.

    Destruction is real: when a window elapses the key is flagged deletable and deleted on the server. Whether that
    is *provable* depends on the server (an HSM or managed seal): this class reports ``provable_destruction`` from
    its constructor argument, default False, so a deployment must assert it deliberately.

    OpenBao has no deletion schedule, so the schedule lives in ``ledger_path`` (a JSON file the operator backs up
    with the rest of the vault's state).
    """

    def __init__(self, transport: Transport, ledger_path: str | Path, *, mount: str = "transit",
                 provable_destruction: bool = False, clock: Clock = _utcnow):
        self._t = transport
        self._mount = mount.strip("/")
        self._provable = bool(provable_destruction)
        self._ledger = _DestructionLedger(Path(ledger_path), clock)
        lp = Path(ledger_path)
        self._versions = _VersionLedger(lp.with_name(lp.name + ".versions.json"), clock)

    @property
    def provable_destruction(self) -> bool:  # type: ignore[override]
        return self._provable

    def _name(self, org_id: str, version: int = 1) -> str:
        base = f"cv-org-{check_org_id(org_id, ProviderConfigError)}"
        return base if version == 1 else f"{base}-v{version}"

    def _call(self, method: str, path: str, body: Optional[dict], org_id: str, *, ok=(200, 204)) -> dict:
        status, doc = self._t(method, f"/v1/{self._mount}/{path}", body)
        if status in ok:
            return doc
        if status == 404:
            raise KeyNotFoundError(f"OpenBao has no transit key for org {org_id}")
        if status >= 500 or status in (0, 429):
            raise ProviderTransportError(f"OpenBao {method} {path} answered HTTP {status}")
        errs = doc.get("errors") if isinstance(doc, dict) else None
        raise KeyProviderError(f"OpenBao {method} {path} answered HTTP {status}: {errs}")

    def _exists(self, org_id: str, version: int = 1) -> bool:
        status, _ = self._t("GET", f"/v1/{self._mount}/keys/{self._name(org_id, version)}", None)
        if status == 200:
            return True
        if status == 404:
            return False
        raise ProviderTransportError(f"OpenBao key lookup for org {org_id} answered HTTP {status}")

    def create_org_key(self, org_id: str) -> str:
        name = self._name(org_id)
        if self._ledger.get(org_id).state == "destroyed":
            raise KeyDestroyedError(f"the key for org {org_id} was destroyed; a destroyed org key is never recreated")
        if self._exists(org_id):
            raise KeyExistsError(f"a transit key already exists for org {org_id}")
        self._call("POST", f"keys/{name}", {"type": "aes256-gcm96", "exportable": False,
                                            "allow_plaintext_backup": False, "deletion_allowed": False}, org_id)
        return f"openbao:{self._mount}/{name}"

    def _new_transit_key(self, org_id: str, version: int) -> None:
        self._call("POST", f"keys/{self._name(org_id, version)}", {"type": "aes256-gcm96", "exportable": False,
                                                                   "allow_plaintext_backup": False,
                                                                   "deletion_allowed": False}, org_id)

    def active_version(self, org_id: str) -> int:
        check_org_id(org_id, ProviderConfigError)
        return self._versions.get(org_id)[0]

    def wrap(self, org_id: str, data_key: bytes) -> bytes:
        _check_data_key(data_key)
        _require_usable(self._ledger.get(org_id))
        version = self.active_version(org_id)
        doc = self._call("POST", f"encrypt/{self._name(org_id, version)}",
                         {"plaintext": base64.b64encode(bytes(data_key)).decode()}, org_id, ok=(200,))
        try:
            return _versioned(version, doc["data"]["ciphertext"].encode("utf-8"))
        except (KeyError, TypeError, AttributeError) as exc:
            raise KeyProviderError("OpenBao encrypt answered without a ciphertext") from exc

    def unwrap(self, org_id: str, wrapped: bytes) -> bytes:
        _require_usable(self._ledger.get(org_id))
        version = wrapped_version(wrapped)
        self._versions.check_usable(org_id, version)
        try:
            ct = _inner(wrapped).decode("utf-8")
        except (UnicodeDecodeError, TypeError) as exc:
            raise UnwrapError("wrapped key is not an OpenBao ciphertext") from exc
        status, doc = self._t("POST", f"/v1/{self._mount}/decrypt/{self._name(org_id, version)}", {"ciphertext": ct})
        if status == 400:
            raise UnwrapError(f"OpenBao refused to unwrap the key for org {org_id}: {doc.get('errors')}")
        if status == 404:
            raise KeyNotFoundError(f"OpenBao has no transit key for org {org_id}")
        if status != 200:
            raise ProviderTransportError(f"OpenBao decrypt answered HTTP {status}")
        try:
            return base64.b64decode(doc["data"]["plaintext"], validate=True)
        except (KeyError, TypeError, binascii.Error) as exc:
            raise KeyProviderError("OpenBao decrypt answered without a valid plaintext") from exc

    def rotate_org_key(self, org_id: str) -> tuple[int, str]:
        _require_usable(self._ledger.get(org_id))
        current = self.active_version(org_id)
        if not self._exists(org_id, current):
            raise KeyNotFoundError(f"OpenBao has no transit key for org {org_id} version {current}")
        nxt = current + 1
        if not self._exists(org_id, nxt):  # a key left by a rotation that stopped before the ledger is adopted
            self._new_transit_key(org_id, nxt)
        self._versions.set_active(org_id, nxt)
        return nxt, self.version_ref(org_id, nxt)

    def version_ref(self, org_id: str, version: int) -> str:
        self._versions.check_usable(check_org_id(org_id, ProviderConfigError), version)
        return f"openbao:{self._mount}/{self._name(org_id, version)}"

    def _delete_transit_key(self, org_id: str, version: int) -> None:
        name = self._name(org_id, version)
        if self._exists(org_id, version):
            self._call("POST", f"keys/{name}/config", {"deletion_allowed": True}, org_id)
            self._call("DELETE", f"keys/{name}", None, org_id)
        if self._exists(org_id, version):
            raise KeyProviderError(f"OpenBao still holds the transit key for org {org_id} version {version} after deletion")

    def destroy_version(self, org_id: str, version: int) -> bool:
        _require_usable(self._ledger.get(check_org_id(org_id, ProviderConfigError)))
        if not self._versions.check_destroyable(org_id, version):
            return False
        self._delete_transit_key(org_id, version)
        self._versions.mark_destroyed(org_id, version)
        return True

    def versions(self, org_id: str) -> dict[int, str]:
        check_org_id(org_id, ProviderConfigError)
        return self._versions.states(org_id, self._ledger.get(org_id).state == "destroyed")

    def schedule_destruction(self, org_id: str, *, window_days: int = MIN_DESTRUCTION_DAYS) -> DestructionStatus:
        if not self._exists(org_id):
            raise KeyNotFoundError(f"OpenBao has no transit key for org {org_id}")
        return self._ledger.schedule(org_id, window_days)

    def cancel_destruction(self, org_id: str) -> DestructionStatus:
        return self._ledger.cancel(check_org_id(org_id, ProviderConfigError))

    def process_destructions(self) -> list[str]:
        done = []
        for org_id in self._ledger.due():
            active, destroyed = self._versions.get(org_id)
            for version in range(1, active + 1):  # every version dies with the organisation
                if version not in destroyed:
                    try:
                        self._delete_transit_key(org_id, version)
                    except KeyProviderError as exc:
                        raise KeyProviderError(f"OpenBao still holds the transit key for org {org_id} after deletion"
                                               f" ({describe(exc)})") from exc
            self._ledger.mark_destroyed(org_id)
            done.append(org_id)
        return done

    def status(self, org_id: str) -> DestructionStatus:
        return self._ledger.get(check_org_id(org_id, ProviderConfigError))

    def is_destroyed(self, org_id: str) -> bool:
        st = self.status(org_id)
        gone = not any(self._exists(org_id, v) for v in range(1, self._versions.get(org_id)[0] + 1))
        if st.state == "destroyed" and not gone:
            raise KeyProviderError(f"the ledger says org {org_id} is destroyed but OpenBao still holds the key")
        return st.state == "destroyed" and gone
