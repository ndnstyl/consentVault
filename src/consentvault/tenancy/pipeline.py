"""The capture pipeline: allocate an id, write the evidence object, commit the ledger row, sign the receipt.

1. Inside the caller's tenant (one transaction): check the request against the organisation's sources, brands,
   wording, channels and purposes, make the contact's data key if it is new, and record the object id as ``pending``
   in ``consentvault.evidence_object``. A refusal here writes nothing.
2. Write the evidence object (the request as received, encrypted under the contact's data key, bound to the
   organisation, the object id and the column) to write-once storage through the ``EvidenceStore`` provider.
3. Inside the tenant again (one transaction): append the event to the organisation's chain and mark the object
   ``committed`` with the event id. Either both happen or neither does.
4. Sign the receipt ``{org_id, event_id, seq, row_hash, received_at}`` with the platform receipt key.

A failure between 2 and 3 leaves a ``pending`` object; ``reconcile_uncommitted`` marks every pending object past its
grace ``uncommitted`` (never counted as an event, kept until its retention ends). The object is never deleted.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Optional

import psycopg
from cryptography.hazmat.primitives.asymmetric import ed25519

from .. import dbclock
from ..ledger import canonical_dumps
from ..normalize import normalize_contact
from ..providers.errors import EvidenceStoreError
from ..providers.evidence import EvidenceStore
from . import crypto as tc
from .admin_base import ApiError
from .crypto import TenantCrypto
from .errors import KeyProviderError, TenancyError
from .keys_protocol import WrappedKey
from .oauth import b64url, b64url_decode

DEFAULT_RECONCILE_GRACE = timedelta(minutes=15)
MAX_ATTRIBUTION_BYTES = 2048
_LOCK_SQL = "SELECT pg_advisory_xact_lock(consentvault.ledger_lock_key(consentvault.current_org()))"


class EvidenceStoreUnavailable(TenancyError):
    """The write-once store did not take the evidence object; nothing was recorded in the ledger."""


# Receipts ------------------------------------------------------------------------------------------------------------

class ReceiptSigner:
    """The platform receipt key (Ed25519): anyone holding the published public key can check a receipt offline."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey, *, key_id: str):
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TenancyError("the receipt key must be an Ed25519 private key")
        if not re.match(r"^[A-Za-z0-9_-]{1,64}$", key_id or ""):
            raise TenancyError("receipt key id must be 1-64 letters, digits, '_' or '-'")
        self._key = private_key
        self.key_id = key_id
        self.public_key = private_key.public_key()

    def __repr__(self) -> str:
        return f"ReceiptSigner(key_id={self.key_id!r}, private_key=<redacted>)"

    @classmethod
    def generate(cls, *, key_id: str) -> "ReceiptSigner":
        return cls(ed25519.Ed25519PrivateKey.generate(), key_id=key_id)

    def sign(self, body: Mapping[str, Any]) -> dict:
        signed = canonical_dumps(dict(body)).encode("utf-8")
        return {**body, "signature": f"ed25519:{self.key_id}:{b64url(self._key.sign(signed))}"}


def receipt_body(receipt: Mapping[str, Any]) -> bytes:
    """The bytes a receipt's signature covers: every field but ``signature``, canonical JSON."""
    return canonical_dumps({k: v for k, v in receipt.items() if k != "signature"}).encode("utf-8")


def verify_receipt(receipt: Mapping[str, Any], public_key: ed25519.Ed25519PublicKey, key_id: str) -> bool:
    """True only when the receipt carries the five fields and a valid signature by ``key_id``."""
    if set(receipt) != {"org_id", "event_id", "seq", "row_hash", "received_at", "signature"}:
        return False
    parts = str(receipt["signature"]).split(":")
    if len(parts) != 3 or parts[0] != "ed25519" or parts[1] != key_id:
        return False
    from cryptography.exceptions import InvalidSignature

    try:
        public_key.verify(b64url_decode(parts[2]), receipt_body(receipt))
    except (InvalidSignature, ValueError):
        return False  # loud-failure-exempt: a receipt that does not verify is the answer False, by contract
    return True


# The request a tenant capture carries ----------------------------------------------------------------------------------

CAPTURE_FIELDS = (
    "contact", "event_type", "channels", "purposes", "method", "origin", "disclosure_sha256", "subject_key",
    "captured_at", "page_url", "client_ip", "user_agent", "session_ref", "bot_check", "source", "edge_received_at",
    "contact_verification", "checked", "inbound_message", "source_id", "brand_ids", "attribution",
)
EVENT_TYPES = ("grant", "revoke", "suppress")


@dataclass(frozen=True)
class CaptureRequest:
    fields: dict[str, Any]
    body: bytes  # the bytes stored and hashed: the request as received, or (with a display) the canonical rest of it
    display: dict[str, str] | None = None  # name and/or company; goes to the display table only, never into the evidence


@dataclass(frozen=True)
class CaptureResult:
    event_id: str
    receipt: dict
    object_id: str


def _list_of_str(value: Any, name: str) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ApiError("validation_failed", f"{name} must be a list of names", {name: "must be a list of names"})
    return value


def _time(value: Any, name: str) -> datetime | None:
    if value is None:
        return None
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise ApiError("validation_failed", f"{name} must be ISO 8601 with a time zone",
                       {name: "must be ISO 8601 with a time zone"}) from None
    if t.tzinfo is None:
        raise ApiError("validation_failed", f"{name} must carry a time zone", {name: "must carry a time zone"})
    return t


DISPLAY_KEYS = ("name", "company")
DISPLAY_FIELD_MAX = 200


def _split_display(payload: dict) -> tuple[dict, dict | None]:
    """Take ``display`` off the top level of a capture body before anything is checked or hashed (records.md section 9).
    Returns (the rest, the validated display or None). A display is an object holding only ``name`` and/or ``company``,
    each text of 1 to 200 characters; anything else is ``validation_failed`` with ``fields.display``."""
    if "display" not in payload:
        return payload, None
    rest = {k: v for k, v in payload.items() if k != "display"}
    shown = payload["display"]
    bad = ApiError("validation_failed", "display is an object with a name and/or a company, each 1 to 200 characters",
                   {"display": "an object with only name and/or company, each text of 1 to 200 characters"})
    if not isinstance(shown, dict) or not shown or set(shown) - set(DISPLAY_KEYS):
        raise bad
    if not all(isinstance(v, str) and 1 <= len(v) <= DISPLAY_FIELD_MAX for v in shown.values()):
        raise bad
    return rest, dict(shown)


def parse_capture(payload: Any, body: bytes, scopes: tuple[str, ...]) -> CaptureRequest:
    """Shape checks that need no database. Refuses with a contract error name.

    A top-level ``display`` is removed first. When it was present, the stored and hashed body becomes the canonical JSON
    of the rest of the object (sorted keys, compact separators, UTF-8, no ASCII escaping); when it was absent, the body is
    the bytes as received."""
    if not isinstance(payload, dict):
        raise ApiError("invalid_request", "the body must be a JSON object")
    payload, display = _split_display(payload)
    if display is not None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if "disclosure_text" in payload:
        raise ApiError("validation_failed", "wording is never accepted on the wire; register it and send its sha256",
                       {"disclosure_text": "not accepted"})
    unknown = sorted(set(payload) - set(CAPTURE_FIELDS))
    if unknown:
        raise ApiError("validation_failed", f"unknown fields: {unknown}", {u: "unknown field" for u in unknown})
    for need in ("contact", "event_type", "channels", "purposes"):
        if need not in payload:
            raise ApiError("validation_failed", f"'{need}' is required", {need: "required"})
    f = dict(payload)
    if f["event_type"] not in EVENT_TYPES:
        raise ApiError("validation_failed", "event_type must be grant, revoke or suppress",
                       {"event_type": "must be grant, revoke or suppress"})
    f["channels"] = _list_of_str(f["channels"], "channels")
    f["purposes"] = _list_of_str(f["purposes"], "purposes")
    f.setdefault("method", "checkbox")
    f.setdefault("origin", "consumer")
    f.setdefault("contact_verification", "none")
    if f["contact_verification"] not in ("none", "otp", "inbound_keyword"):
        raise ApiError("validation_failed", "contact_verification must be none, otp or inbound_keyword",
                       {"contact_verification": "must be none, otp or inbound_keyword"})
    if f["contact_verification"] != "none" and "capture_verified" not in scopes:
        raise ApiError("role_not_allowed", "claiming a verified contact point needs the capture_verified scope",
                       {"role": "capture"})
    if f["contact_verification"] != "none" and f["event_type"] != "grant":
        raise ApiError("validation_failed", "only a grant claims a verified contact point",
                       {"contact_verification": "only on a grant"})
    if "brand_ids" in f:
        brands = f["brand_ids"]
        if not isinstance(brands, list):
            raise ApiError("validation_failed", "brand_ids must be a list", {"brand_ids": "must be a list"})
        try:
            f["brand_ids"] = sorted({str(uuid.UUID(str(b))) for b in brands})
        except ValueError:
            raise ApiError("brand_not_allowed", "a brand id is not one of this organization's brands") from None
    if f.get("source_id") is not None:
        try:
            f["source_id"] = str(uuid.UUID(str(f["source_id"])))
        except ValueError:
            raise ApiError("source_not_allowed", "the source does not belong to the credential") from None
    if f.get("attribution") is not None:
        if not isinstance(f["attribution"], dict):
            raise ApiError("validation_failed", "attribution must be an object", {"attribution": "must be an object"})
        if len(canonical_dumps(f["attribution"]).encode("utf-8")) > MAX_ATTRIBUTION_BYTES:
            raise ApiError("validation_failed", "attribution is larger than 2 KB", {"attribution": "at most 2 KB"})
    for name in ("captured_at", "edge_received_at"):
        f[name] = _time(f.get(name), name)
    if f["event_type"] == "grant":
        if not f.get("disclosure_sha256"):
            raise ApiError("UnknownDisclosureError", "a grant must carry the sha256 of wording this organization registered")
        if not f.get("brand_ids"):
            raise ApiError("validation_failed", "a grant names the brands on its wording", {"brand_ids": "required on a grant"})
    return CaptureRequest(f, body, display)


# Org checks (inside the tenant) --------------------------------------------------------------------------------------

def org_status(conn: psycopg.Connection) -> str:
    row = conn.execute("SELECT status FROM consentvault.organization WHERE org_id = consentvault.current_org()").fetchone()
    if row is None:
        raise ApiError("org_not_active", "the organization's status refuses this action")
    return row["status"]


def require_serving(conn: psycopg.Connection) -> str:
    """Capture, gate and proof answer in every status but closed (contracts/billing.md)."""
    status = org_status(conn)
    if status == "closed":
        raise ApiError("org_not_active", "the organization's status refuses this action")
    return status


def org_region(conn: psycopg.Connection, deployment_region: str | None) -> str | None:
    """The phone region national-format numbers are read with: the organization's own, else the deployment's setting."""
    row = conn.execute("SELECT default_region FROM consentvault.organization WHERE org_id = consentvault.current_org()").fetchone()
    return row["default_region"] if row is not None and row["default_region"] else deployment_region


def org_channels(conn: psycopg.Connection) -> set[str]:
    return {r["channel"] for r in conn.execute(
        "SELECT channel FROM consentvault.channel WHERE org_id = consentvault.current_org()")}


def org_purposes(conn: psycopg.Connection) -> set[str]:
    return {r["purpose"] for r in conn.execute(
        "SELECT purpose FROM consentvault.purpose WHERE org_id = consentvault.current_org()")}


def check_channel_purpose(conn: psycopg.Connection, channels: list[str], purposes: list[str], *,
                          allow_star: bool) -> None:
    have_ch = org_channels(conn)
    bad = [c for c in channels if c not in have_ch]
    if bad:
        raise ApiError("invalid_channel", f"channel(s) {bad} are not channels this organization has")
    have_pu = org_purposes(conn)
    bad = [p for p in purposes if p not in have_pu and not (allow_star and p == "*")]
    if bad:
        raise ApiError("UnknownPurposeError", f"purpose(s) {bad} are not in this organization's configured list")


def _check_source_and_brands(conn: psycopg.Connection, f: dict, credential_id: uuid.UUID) -> None:
    cred = conn.execute("SELECT source_id FROM consentvault.credential WHERE org_id = consentvault.current_org()"
                        " AND credential_id = %s", (credential_id,)).fetchone()
    held = str(cred["source_id"]) if cred and cred["source_id"] else None
    wanted = f.get("source_id") or held
    if held is None or wanted != held:
        raise ApiError("source_not_allowed", "the source does not belong to the credential")
    f["source_id"] = held
    src = conn.execute("SELECT to_jsonb(s) AS s FROM consentvault.capture_source s"
                       " WHERE org_id = consentvault.current_org() AND source_id = %s", (held,)).fetchone()
    if src is None or src["s"].get("status", "active") != "active":
        raise ApiError("source_not_allowed", "the source does not belong to the credential or is retired")
    brands = f.get("brand_ids") or []
    if brands:
        known = {str(r["brand_id"]) for r in conn.execute(
            "SELECT brand_id FROM consentvault.brand WHERE org_id = consentvault.current_org()"
            " AND brand_id = ANY(%s::uuid[])", (brands,))}
        source_brands = {str(b) for b in (src["s"].get("brand_ids") or [])}
        if any(b not in known or b not in source_brands for b in brands):
            raise ApiError("brand_not_allowed", "a brand does not belong to this organization and source")


def _check_disclosure(conn: psycopg.Connection, f: dict) -> None:
    if f["event_type"] != "grant":
        if f.get("disclosure_sha256"):
            raise ApiError("validation_failed", "only a grant carries wording", {"disclosure_sha256": "only on a grant"})
        return
    row = conn.execute("SELECT to_jsonb(d) AS d FROM consentvault.disclosure d"
                       " WHERE org_id = consentvault.current_org() AND sha256 = %s",
                       (str(f["disclosure_sha256"]),)).fetchone()
    if row is None:
        raise ApiError("UnknownDisclosureError", "this organization has not registered that wording")
    named = {str(b) for b in (row["d"].get("brand_ids") or [])}
    if named and any(b not in named for b in f.get("brand_ids") or []):
        raise ApiError("brand_not_allowed", "a brand is not named on that wording")


def retention_until(conn: psycopg.Connection, default_years: int, now: datetime) -> datetime:
    """The retain-until date of a new evidence object: the organisation's retention in force, else the platform's."""
    row = conn.execute(
        "SELECT evidence_years FROM consentvault.retention_policy WHERE org_id = consentvault.current_org()"
        " AND applies_from <= now() ORDER BY version DESC LIMIT 1").fetchone()
    years = row["evidence_years"] if row else default_years
    return now + timedelta(days=366 * int(years))


# Contact keys ---------------------------------------------------------------------------------------------------------

def contact_key(conn: psycopg.Connection, crypto: TenantCrypto, org: uuid.UUID, kind: str, norm: str,
                *, create: bool) -> tuple[str, bytes | None]:
    """(fingerprint, data key) of a contact in the current tenant; makes the key when ``create`` and it is new.

    Same layout as the ledger writer (``record_tenant_event``): a random 32-byte data key wrapped by the org key, and
    the contact's salt encrypted under it, bound to the fingerprint. Takes the organisation's ledger lock.
    """
    fp = crypto.contact_fingerprint(org, kind, norm)
    conn.execute(_LOCK_SQL)
    held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (fp,)).fetchone()
    if held is not None:
        return fp, crypto.open_contact_key(org, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
    if not create:
        return fp, None
    ck = crypto.new_contact_key(org)
    conn.execute(
        "INSERT INTO consentvault.contact_key (org_id, contact_fp, wrapped_key, key_version, salt_ct)"
        " VALUES (%s, %s, %s, %s, %s)",
        (org, fp, ck.wrapped.ciphertext, ck.wrapped.key_version,
         tc.encrypt_field(ck.data_key, org, fp, "contact_salt", os.urandom(32).hex())))
    return fp, ck.data_key


def normalize(contact: Any, region: str | None) -> tuple[str, str]:
    from ..errors import NormalizationError

    if not isinstance(contact, str) or not contact.strip():
        raise ApiError("invalid_contact", "the contact point is not a valid phone number or email address")
    try:
        return normalize_contact(contact, None, region)
    except NormalizationError:
        raise ApiError("invalid_contact", "the contact point is not a valid phone number or email address") from None


# The pipeline -----------------------------------------------------------------------------------------------------------

class CapturePipeline:
    def __init__(self, *, store: EvidenceStore, crypto: TenantCrypto, receipts: ReceiptSigner,
                 default_retain_years: int, region: str | None = None,
                 clock: Optional[Callable[[], datetime]] = None):
        if not isinstance(store, EvidenceStore):
            raise TenancyError("store must be an EvidenceStore")
        if not isinstance(default_retain_years, int) or default_retain_years < 1:
            raise TenancyError("default_retain_years must be a whole number of years, at least 1")
        self.store = store
        self.crypto = crypto
        self.receipts = receipts
        self.default_retain_years = default_retain_years
        self.region = region
        self.clock = clock

    def capture(self, conn: psycopg.Connection, enter: Callable, req: CaptureRequest, *,
                credential_id: uuid.UUID) -> CaptureResult:
        """``enter(conn)`` is a context manager that opens a transaction inside the caller's tenant and yields its
        org id (``tenancy.tokens.org_transaction`` bound to the caller's token)."""
        from ..capture import tenant_capture

        f = dict(req.fields)
        object_id = uuid.uuid4()
        key = f"events/{object_id}"
        try:
            with enter(conn) as org:
                require_serving(conn)
                region = org_region(conn, self.region)
                kind, norm = normalize(f["contact"], region)
                check_channel_purpose(conn, f["channels"], f["purposes"], allow_star=f["event_type"] != "grant")
                _check_source_and_brands(conn, f, credential_id)
                _check_disclosure(conn, f)
                fp, data_key = contact_key(conn, self.crypto, org, kind, norm, create=True)
                retain = retention_until(conn, self.default_retain_years,
                                        self.clock() if self.clock else dbclock.now(conn))
                conn.execute("INSERT INTO consentvault.evidence_object (org_id, object_id, object_key, contact_fp,"
                             " retain_until) VALUES (%s, %s, %s, %s, %s)", (org, object_id, key, fp, retain))
        except KeyProviderError as exc:
            raise ApiError("key_unavailable", "the organization key could not be used; nothing was written") from exc

        evidence = {"object_id": str(object_id), "org_id": str(org), "credential_id": str(credential_id),
                    "fields": {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in f.items()},
                    "body_b64": b64url(req.body)}
        blob = tc.encrypt_field(data_key, org, str(object_id), "evidence_object",
                                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        try:
            stored = self.store.put(str(org), key, blob, retain_until=retain)
        except EvidenceStoreError as exc:
            raise EvidenceStoreUnavailable(
                f"the evidence store did not take object {object_id}: {type(exc).__name__}") from exc

        try:
            with enter(conn):
                ev = tenant_capture(conn, self.crypto, payload=req.body, region=region,
                                    allowed_purposes=None, display=req.display, **f)
                conn.execute("UPDATE consentvault.evidence_object SET status = 'committed', event_id = %s,"
                             " sha256 = %s, settled_at = clock_timestamp()"
                             " WHERE org_id = consentvault.current_org() AND object_id = %s",
                             (ev.event_id, stored.sha256, object_id))
                r = conn.execute("SELECT * FROM consentvault.receipt_of(%s)", (ev.event_id,)).fetchone()
        except KeyProviderError as exc:
            raise ApiError("key_unavailable", "the organization key could not be used; nothing was written") from exc
        if r is None:
            raise TenancyError(f"event {ev.event_id} was committed but its receipt could not be read")
        receipt = self.receipts.sign({
            "org_id": str(org), "event_id": str(ev.event_id), "seq": r["seq"], "row_hash": r["row_hash"],
            "received_at": r["received_at"].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        })
        return CaptureResult(str(ev.event_id), receipt, str(object_id))


def reconcile_uncommitted(conn: psycopg.Connection, enter: Callable, *,
                          grace: timedelta = DEFAULT_RECONCILE_GRACE) -> int:
    """Mark every pending evidence object of the entered organisation older than ``grace`` as uncommitted.

    The ledger row and the ``committed`` mark are written in one transaction, so an object still pending after its
    grace has no event. Returns the number marked. Runs under any token of the organisation (the worker's included).
    """
    if not isinstance(grace, timedelta) or grace < timedelta(0):
        raise TenancyError("grace must be a non-negative timedelta")
    with enter(conn):
        rows = conn.execute(
            "UPDATE consentvault.evidence_object SET status = 'uncommitted', settled_at = clock_timestamp()"
            " WHERE org_id = consentvault.current_org() AND status = 'pending' AND created_at < clock_timestamp() - %s"
            " RETURNING object_id", (grace,)).fetchall()
    return len(rows)
