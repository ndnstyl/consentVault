"""Per-organisation key rotation (spec FR-011; contracts/admin.md, "Key rotation"; migration 0020).

``start_rotation`` (POST /v1/orgs/{org_id}/key-rotations, operator) makes a new version of the organisation key the
active one in the key provider and in ``consentvault.org_key``, retires the old version and opens a rotation record.
From then on every new contact key is wrapped under the new version.

``run_rotation`` (the operator job, one organisation) re-wraps the existing contact keys in batches, then every other
value the organisation key wraps (the fingerprint secret, credential secrets, connected system credentials, the sealed
reasons of holds), then destroys the old version. The data keys never change, so no ciphertext, event, chain link, seal
or anchor is touched, and every key opens throughout. Each re-wrap is a compare-and-swap in the database, so a pass that
stops part way resumes where it stopped and a replayed pass changes nothing.

The old version is destroyed only when the database counts nothing still wrapped under it (``key_version_census``; the
database refuses the destruction otherwise) and never while a legal hold of the organisation is active. A version that
still seals a write-once lifecycle ledger entry inside that entry's retention (a hold's reason in the archive) is not
destroyed by the rotation: the rotation completes, the version is kept as ``retained_for_ledger`` until the last such
entry's retention ends (``org_key.destroy_after``), and the job destroys it then (``sweep_retained``). Every retired
version is also kept until the oldest database backup taken while it still wrapped keys ages out (the backup retention
setting, ``config.backup_retention_days``, default 35 days): ``retained_for_backup`` until then, so a restore of any
backup still opens. A hold, a final export still sealed under the old version, or a failed step leaves the rotation
``blocked`` with the reason named on the record, writes an audit row and raises an operator alarm; a failed step also
raises ``KeyRotationError``. Every key operation is in the organisation's audit chain and the platform chain.

A rotation blocked by a legal hold names the hold only on the rotation record, the platform chain and the operator alarm
(ref ``legal_hold``). The tenant's chain reads a neutral "blocked; operator alerted"; a legal-process hold the customer has
not been told of (``hold_disclosure`` = undisclosed) leaves no tenant row at all.

Offboarding cancels an open rotation before it proceeds (``cancel_open_rotation``): the record reads ``cancelled`` with
the time and reason, a job pass in flight stops at its next batch, and the job never picks it up again.
"""

from __future__ import annotations

import base64
import struct
from datetime import timedelta
from typing import Any, Callable, Optional

import psycopg

from ..safelog import describe
from ..providers.errors import KeyProviderError as CustodyKeyError
from ..providers.keys import wrapped_version
from .admin_base import ApiError, iso, need_text, to_uuid
from .erasure import LifecycleError, audit_org, audit_platform, operator_org
from .errors import KeyProviderError
from .holds import SEALED_PREFIX
from .keys_adapter import DISPLAY_LOADER_SCOPE as DISPLAY_KEY_SCOPE
from .keys_protocol import WrappedKey
from .tokens import TokenKey

ALARM_BLOCKED = "key_rotation.blocked"
ALARM_FAILED = "key_rotation.failed"
TENANT_BLOCKED_NOTE = "blocked; operator alerted"
HOLD_PREFIX = "legal_hold_active:"
CANCELLED = "cancelled"
OFFBOARDING_CANCEL_REASON = "organization offboarding"
DEFAULT_BATCH = 500
JOB_OPERATOR = "key-rotation-job"
MAX_PASSES = 3  # contact keys written under the old version while a pass ran are picked up by the next pass
CENSUS_KINDS = ("contact_key", "fingerprint_secret", "display_key", "credential", "connected_system", "sending_account", "export_key", "final_export", "hold_reason", "connector_secret")


class KeyRotationError(LifecycleError):
    """A rotation step failed. The rotation is recorded as blocked with the cause and an operator alarm is raised. ``org_ids``
    names the organisations it concerns, as a field, so a report never has to look for them in the message."""

    def __init__(self, *args, org_ids=(), **kw) -> None:
        super().__init__(*args, **kw)
        self.org_ids = tuple(str(o) for o in org_ids)


# ---- reading the state ---------------------------------------------------------------------------------------------------
def _census(conn, version: int) -> dict[str, int]:
    """Inside the entered organisation: what is still wrapped under ``version``, by kind (every kind, named)."""
    got = {r["kind"]: int(r["n"]) for r in conn.execute("SELECT kind, n FROM consentvault.key_version_census(%s)",
                                                         (version,))}
    if set(got) != set(CENSUS_KINDS):
        raise KeyRotationError(f"the key version census answered {sorted(got)}, expected {sorted(CENSUS_KINDS)}")
    return got


def _state(conn, rot: dict) -> dict:
    """Inside the entered organisation: the rotation as the contract shows it."""
    census = _census(conn, rot["from_version"])
    old = conn.execute("SELECT status, destroy_after FROM consentvault.org_key WHERE org_id ="
                       " (SELECT consentvault.current_org()) AND version = %s", (rot["from_version"],)).fetchone()
    return {"rotation_id": str(rot["rotation_id"]), "org_id": str(rot["org_id"]), "from_version": rot["from_version"],
            "to_version": rot["to_version"], "status": rot["status"], "blocked_reason": rot["blocked_reason"],
            "rewrapped": rot["rewrapped"], "batches": rot["batches"], "remaining": census["contact_key"],
            "remaining_other": sum(n for k, n in census.items() if k != "contact_key"),
            "old_version": old["status"] if old is not None else None,
            "old_version_destroy_after": iso(old["destroy_after"]) if old is not None else None,
            "old_version_destroyed": old is not None and old["status"] == "destroyed",
            "started_at": iso(rot["started_at"]), "last_batch_at": iso(rot["last_batch_at"]),
            "completed_at": iso(rot["completed_at"]), "cancelled_at": iso(rot.get("cancelled_at")),
            "cancel_reason": rot.get("cancel_reason")}


def _open(conn, *, lock: bool = False) -> Optional[dict]:
    return conn.execute("SELECT * FROM consentvault.key_rotation WHERE org_id = (SELECT consentvault.current_org())"
                        " AND status NOT IN ('complete', 'cancelled')" + (" FOR UPDATE" if lock else "")).fetchone()


def _still_open(conn, rot: dict) -> bool:
    """Inside the entered organisation: the rotation is still open (locks its row until the transaction ends)."""
    row = conn.execute("SELECT status FROM consentvault.key_rotation WHERE org_id = (SELECT consentvault.current_org())"
                       " AND rotation_id = %s FOR UPDATE", (rot["rotation_id"],)).fetchone()
    if row is None:
        raise KeyRotationError(f"the key rotation {rot['rotation_id']} is no longer on record")
    return row["status"] not in ("complete", CANCELLED)


def _backup_days(value: Optional[int]) -> int:
    """The backup retention in days: the value given, else the configured setting (default 35)."""
    if value is None:
        from ..config import load_config

        value = load_config().backup_retention_days
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise KeyRotationError(f"the backup retention must be a whole number of days, 0 or more; got {value!r}")
    return value


def cancel_open_rotation(conn, *, actor_id: str, request_id: str, reason: str = OFFBOARDING_CANCEL_REASON
                         ) -> Optional[str]:
    """Inside the entered organisation: cancel its open rotation, if any, visibly (status ``cancelled`` with the time and
    reason, an audit row on its chain and the platform chain). Returns the rotation id, or None when none was open. Keys
    already moved stay on the new version; nothing is destroyed here."""
    conn.execute("SELECT consentvault.lifecycle_lock()")
    rot = _open(conn, lock=True)
    if rot is None:
        return None
    conn.execute("UPDATE consentvault.key_rotation SET status = 'cancelled', blocked_reason = NULL,"
                 " cancelled_at = clock_timestamp(), cancel_reason = %s"
                 " WHERE org_id = (SELECT consentvault.current_org()) AND rotation_id = %s",
                 (reason[:500], rot["rotation_id"]))
    note = f"version {rot['from_version']} to {rot['to_version']} cancelled: {reason}"
    audit_org(conn, actor_kind="operator", actor_id=actor_id, action="org_key.rotation_cancelled",
              target_kind="org_key", target_id=rot["rotation_id"], reason=note, request_id=request_id)
    audit_platform(conn, operator_id=actor_id, action="org_key.rotation_cancelled", target_kind="org_key",
                   target_id=rot["rotation_id"], reason=note, request_id=request_id)
    return str(rot["rotation_id"])


def get_rotation(connect: Callable[[], psycopg.Connection], token_key: TokenKey, org_id, rotation_id) -> dict:
    """GET /v1/orgs/{org_id}/key-rotations/{rotation_id} (operator)."""
    rid = to_uuid(rotation_id, "key rotation")
    with connect() as conn, operator_org(conn, token_key, org_id):
        rot = conn.execute("SELECT * FROM consentvault.key_rotation WHERE org_id = (SELECT consentvault.current_org())"
                           " AND rotation_id = %s", (rid,)).fetchone()
        if rot is None:
            raise ApiError("not_found", "no such key rotation in this organization")
        return _state(conn, rot)


def get_rotation_state(connect: Callable[[], psycopg.Connection], token_key: TokenKey, org_id) -> Optional[dict]:
    """The organisation's latest rotation, or None when it was never rotated."""
    with connect() as conn, operator_org(conn, token_key, org_id):
        rot = conn.execute("SELECT * FROM consentvault.key_rotation WHERE org_id = (SELECT consentvault.current_org())"
                           " ORDER BY started_at DESC LIMIT 1").fetchone()
        return None if rot is None else _state(conn, rot)


# ---- starting ------------------------------------------------------------------------------------------------------------
def start_rotation(conn: psycopg.Connection, *, token_key: TokenKey, custody, operator_id: str, request_id: str, org_id,
                   reason: str) -> dict:
    """Make a new version of the organisation key the active one and open the rotation. Refused by name while a rotation
    is open, while the organisation is offboarding or closed, or while its key is scheduled for destruction."""
    why = need_text({"reason": reason}, "reason", max_len=500)
    with operator_org(conn, token_key, org_id) as org:
        conn.execute("SELECT consentvault.lifecycle_lock()")
        o = conn.execute("SELECT status FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())"
                         " FOR UPDATE").fetchone()
        if o is None:
            raise ApiError("not_found", "no such organization")
        if o["status"] in ("offboarding", "closed"):
            raise ApiError("validation_failed", f"an organization in {o['status']} is not rotated",
                           {"status": o["status"]})
        if _open(conn) is not None:
            raise ApiError("rotation_in_progress", "a key rotation of this organization is still open")
        keys = conn.execute("SELECT version, status FROM consentvault.org_key WHERE org_id ="
                            " (SELECT consentvault.current_org()) ORDER BY version").fetchall()
        if not keys or keys[-1]["status"] != "active":
            raise ApiError("validation_failed", "the organization key is not active (scheduled for destruction or "
                           "destroyed); it is not rotated", {"key": keys[-1]["status"] if keys else "missing"})
        current = keys[-1]["version"]
        try:
            held = custody.active_version(str(org))
            if held == current:
                new, ref = custody.rotate_org_key(str(org))
            elif held == current + 1:  # a start that stopped after the provider rotated: adopt its version
                new, ref = held, custody.version_ref(str(org), held)
            else:
                raise KeyRotationError(f"the key provider's active version {held} does not follow the recorded version "
                                       f"{current} of organization {org}; nothing was changed", org_ids=(org,))
        except CustodyKeyError as exc:
            raise ApiError("key_unavailable", f"the organization key could not be rotated ({type(exc).__name__}); "
                           "nothing was recorded") from exc
        if new != current + 1:
            raise KeyRotationError(f"the key provider rotated organization {org} to version {new}, expected {current + 1}", org_ids=(org,))
        conn.execute("INSERT INTO consentvault.org_key (org_id, version, kms_key_ref) VALUES"
                     " ((SELECT consentvault.current_org()), %s, %s)", (new, ref))
        conn.execute("UPDATE consentvault.org_key SET status = 'retired' WHERE org_id = (SELECT consentvault.current_org())"
                     " AND version = %s", (current,))
        rot = conn.execute("INSERT INTO consentvault.key_rotation (org_id, from_version, to_version, reason, started_by)"
                           " VALUES ((SELECT consentvault.current_org()), %s, %s, %s, %s) RETURNING *",
                           (current, new, why, operator_id)).fetchone()
        note = f"version {current} to {new}: {why}"
        audit_org(conn, actor_kind="operator", actor_id=operator_id, action="org_key.rotation_started",
                  target_kind="org_key", target_id=rot["rotation_id"], reason=note, request_id=request_id)
        audit_platform(conn, operator_id=operator_id, action="org_key.rotation_started", target_kind="org_key",
                       target_id=rot["rotation_id"], reason=note, request_id=request_id)
        return _state(conn, rot)


# ---- re-wrapping ---------------------------------------------------------------------------------------------------------
def _rewrap_sealed(crypto, org, sealed: Optional[str], to_version: int) -> Optional[str]:
    """A hold reason sealed under a fresh data key (holds.seal_reason), with only the wrap of that key moved."""
    if sealed is None or not sealed.startswith(SEALED_PREFIX):
        return sealed
    packed = base64.urlsafe_b64decode(sealed[len(SEALED_PREFIX):])
    n, version = struct.unpack(">HI", packed[:6])
    if version >= to_version:
        return sealed
    moved = crypto.rewrap_contact_key(org, WrappedKey(packed[6:6 + n], version))
    out = struct.pack(">HI", len(moved.ciphertext), moved.key_version) + moved.ciphertext + packed[6 + n:]
    return SEALED_PREFIX + base64.urlsafe_b64encode(out).decode("ascii")


def _contact_batch(conn, *, token_key, crypto, org, rot: dict, batch_size: int, operator_id: str,
                   request_id: str) -> Optional[int]:
    """One batch of contact keys moved to the new version, in one transaction. Returns how many rows it looked at, or
    None when the rotation was cancelled (offboarding) since the pass began."""
    with operator_org(conn, token_key, org):
        if not _still_open(conn, rot):
            return None
        rows = conn.execute("SELECT contact_fp, wrapped_key FROM consentvault.contact_key WHERE org_id ="
                            " (SELECT consentvault.current_org()) AND key_version = %s ORDER BY contact_fp LIMIT %s",
                            (rot["from_version"], batch_size)).fetchall()
        if not rows:
            return 0
        moved = 0
        for r in rows:
            new = crypto.rewrap_contact_key(org, WrappedKey(bytes(r["wrapped_key"]), rot["from_version"]))
            if new.key_version != rot["to_version"]:
                raise KeyRotationError(f"the key provider wrapped under version {new.key_version}, not the rotation's "
                                       f"version {rot['to_version']}")
            moved += bool(conn.execute("SELECT consentvault.rewrap_contact_key(%s, %s, %s, %s) AS ok",
                                       (r["contact_fp"], rot["from_version"], new.ciphertext,
                                        rot["to_version"])).fetchone()["ok"])
        conn.execute("UPDATE consentvault.key_rotation SET rewrapped = rewrapped + %s, batches = batches + 1,"
                     " last_batch_at = clock_timestamp(), status = 'rewrapping', blocked_reason = NULL"
                     " WHERE org_id = (SELECT consentvault.current_org()) AND rotation_id = %s",
                     (moved, rot["rotation_id"]))
        audit_org(conn, actor_kind="system", actor_id=operator_id, action="org_key.rewrapped", target_kind="org_key",
                  target_id=rot["rotation_id"], request_id=request_id,
                  reason=f"{moved} contact keys re-wrapped from version {rot['from_version']} to {rot['to_version']}")
        return len(rows)


def _rewrap_secrets(conn, *, token_key, custody, crypto, org, rot: dict, operator_id: str, request_id: str) -> int:
    """Every other value the organisation key wraps, moved to the new version in one transaction."""
    old = rot["from_version"]
    moved = 0
    with operator_org(conn, token_key, org, scopes=("admin", DISPLAY_KEY_SCOPE)):  # the display key row opens only to its own scope
        def secret(kind: str, ref, blob) -> None:
            nonlocal moved
            if blob is None or wrapped_version(bytes(blob)) != old:
                return
            new = custody.rewrap(str(org), bytes(blob))
            moved += bool(conn.execute("SELECT consentvault.rewrap_org_secret(%s, %s, %s, %s) AS ok",
                                       (kind, ref, bytes(blob), new)).fetchone()["ok"])

        for r in conn.execute("SELECT wrapped FROM consentvault.org_fingerprint_secret WHERE org_id ="
                              " (SELECT consentvault.current_org())").fetchall():
            secret("fingerprint_secret", None, r["wrapped"])
        for r in conn.execute("SELECT wrapped FROM consentvault.org_display_key WHERE org_id ="
                              " (SELECT consentvault.current_org())").fetchall():
            secret("display_key", None, r["wrapped"])
        for r in conn.execute("SELECT export_id, wrapped FROM consentvault.record_export_key WHERE org_id ="
                              " (SELECT consentvault.current_org()) AND wrapped IS NOT NULL").fetchall():
            secret("export_key", r["export_id"], r["wrapped"])
        for r in conn.execute("SELECT credential_id, secret_ct FROM consentvault.credential WHERE org_id ="
                              " (SELECT consentvault.current_org()) AND secret_ct IS NOT NULL").fetchall():
            secret("credential", r["credential_id"], r["secret_ct"])
        for r in conn.execute("SELECT system_id, credentials_ct FROM consentvault.connected_system WHERE org_id ="
                              " (SELECT consentvault.current_org()) AND credentials_ct IS NOT NULL").fetchall():
            secret("connected_system", r["system_id"], r["credentials_ct"])
        for r in conn.execute("SELECT account_id, credentials_ct, auth_token_ct FROM consentvault.sending_account WHERE org_id ="
                              " (SELECT consentvault.current_org())").fetchall():
            secret("sending_credentials", r["account_id"], r["credentials_ct"])
            secret("sending_auth_token", r["account_id"], r["auth_token_ct"])
        # the Twenty connector's envelope keys (API key, webhook secret) and the organisation's connector hash key
        for r in conn.execute("SELECT secret_id, wrapped FROM consentvault.connector_secret WHERE org_id ="
                              " (SELECT consentvault.current_org())").fetchall():
            secret("connector_secret", r["secret_id"], r["wrapped"])
        for r in conn.execute("SELECT hold_id, reason, release_reason FROM consentvault.legal_hold WHERE org_id ="
                              " (SELECT consentvault.current_org())").fetchall():
            reason = _rewrap_sealed(crypto, org, r["reason"], rot["to_version"])
            release = _rewrap_sealed(crypto, org, r["release_reason"], rot["to_version"])
            if (reason, release) != (r["reason"], r["release_reason"]):
                moved += bool(conn.execute("SELECT consentvault.rewrap_hold_reason(%s, %s, %s, %s, %s) AS ok",
                                           (r["hold_id"], r["reason"], reason, r["release_reason"],
                                            release)).fetchone()["ok"])
        if moved:
            audit_org(conn, actor_kind="system", actor_id=operator_id, action="org_key.rewrapped", target_kind="org_key",
                      target_id=rot["rotation_id"], request_id=request_id,
                      reason=f"{moved} organization secrets re-wrapped from version {old} to {rot['to_version']}")
    return moved


def _block(conn, *, token_key, org, rot: dict, why: str, alarm: str, error_class: str, operator_id: str,
           request_id: str) -> None:
    """Record the rotation as blocked, audit it and raise the operator alarm (each in the entered organisation).

    The rotation record, the platform chain and the alarm name a blocking hold; the tenant's chain never does: a neutral
    note for a hold the tenant may know of, and no row at all for a legal-process hold the customer has not been told
    of. A rotation offboarding cancelled meanwhile is left as it is."""
    from ..alarms import AlarmWriteError, raise_operator_alarm
    from .erasure import VIEW_HIDDEN, hold_view

    hold = why[len(HOLD_PREFIX):] if why.startswith(HOLD_PREFIX) else None
    with operator_org(conn, token_key, org):
        if not _still_open(conn, rot):
            return
        conn.execute("UPDATE consentvault.key_rotation SET status = 'blocked', blocked_reason = %s"
                     " WHERE org_id = (SELECT consentvault.current_org()) AND rotation_id = %s",
                     (why[:500], rot["rotation_id"]))
        if hold is None:
            audit_org(conn, actor_kind="system", actor_id=operator_id, action="org_key.rotation_blocked",
                      target_kind="org_key", target_id=rot["rotation_id"], reason=why, request_id=request_id)
        elif hold_view(conn, hold) != VIEW_HIDDEN:
            audit_org(conn, actor_kind="system", actor_id=operator_id, action="org_key.rotation_blocked",
                      target_kind="org_key", target_id=rot["rotation_id"], reason=TENANT_BLOCKED_NOTE,
                      request_id=request_id)
        audit_platform(conn, operator_id=operator_id, action="org_key.rotation_blocked", target_kind="org_key",
                       target_id=rot["rotation_id"], reason=why, request_id=request_id)
        try:
            raise_operator_alarm(conn, name=alarm, error_class=error_class,
                                 ref_kind="key_rotation" if hold is None else "legal_hold",
                                 ref_id=rot["rotation_id"] if hold is None else hold, request_id=request_id)
        except AlarmWriteError as exc:
            raise KeyRotationError(f"the rotation of {org} is blocked ({why}) and its alarm could not be written: "
                                   f"{describe(exc)}", org_ids=(org,)) from exc


def _destroy_version(conn, *, custody, org, version: int, rotation_id, operator_id: str, request_id: str,
                     note: str) -> None:
    """Inside the entered organisation: mark the version destroyed (the database checks nothing is wrapped under it),
    destroy it in the key provider, audit it."""
    conn.execute("UPDATE consentvault.org_key SET status = 'destroyed' WHERE org_id = (SELECT consentvault.current_org())"
                 " AND version = %s AND status IN ('retired', 'retained_for_ledger', 'retained_for_backup')", (version,))
    try:
        custody.destroy_version(str(org), version)
    except CustodyKeyError as exc:
        raise KeyRotationError(f"the key provider did not destroy version {version} of {org}: "
                               f"{describe(exc)}", org_ids=(org,)) from exc
    audit_org(conn, actor_kind="system", actor_id=operator_id, action="org_key.version_destroyed",
              target_kind="org_key", target_id=rotation_id, reason=note, request_id=request_id)
    audit_platform(conn, operator_id=operator_id, action="org_key.version_destroyed", target_kind="org_key",
                   target_id=rotation_id, reason=note, request_id=request_id)


def _destroy_old(conn, *, token_key, custody, ledger, org, rot: dict, operator_id: str, request_id: str,
                 backup_days: int) -> Optional[str]:
    """Destroy the old version when nothing is wrapped under it and no hold stands, or keep it (``retained_for_ledger``
    or ``retained_for_backup``) until the later of the ledger's retention and the oldest backup's. Returns the reason it
    is blocked, ``cancelled`` when offboarding cancelled the rotation, or None once complete. The database refuses the
    destruction while anything is still wrapped under the version."""
    with operator_org(conn, token_key, org):
        conn.execute("SELECT consentvault.lifecycle_lock()")
        if not _still_open(conn, rot):
            return CANCELLED
        hold = conn.execute("SELECT hold_id FROM consentvault.legal_hold WHERE org_id = (SELECT consentvault.current_org())"
                            " AND released_at IS NULL ORDER BY set_at, hold_id LIMIT 1").fetchone()
        if hold is not None:
            return f"{HOLD_PREFIX}{hold['hold_id']}"
        census = _census(conn, rot["from_version"])
        if census["final_export"]:
            return "final_export_under_old_version"
        if any(census.values()):
            return "still_wrapped:" + ", ".join(f"{k}={n}" for k, n in census.items() if n)
        now = ledger.now()
        until = ledger.sealed_retention(org).get(rot["from_version"])
        backups = now + timedelta(days=backup_days) if backup_days else None
        if (until is not None and until > now) or backups is not None:
            for_ledger = until is not None and until > now and (backups is None or until >= backups)
            keep = until if for_ledger else backups
            status = "retained_for_ledger" if for_ledger else "retained_for_backup"
            conn.execute("UPDATE consentvault.org_key SET status = %s, destroy_after = %s"
                         " WHERE org_id = (SELECT consentvault.current_org()) AND version = %s AND status = 'retired'",
                         (status, keep, rot["from_version"]))
            if for_ledger:
                action = "org_key.version_retained"
                note = (f"version {rot['from_version']} kept until {keep.isoformat()}: it seals lifecycle ledger entries "
                        "still inside their retention; every key moved to version " + str(rot["to_version"]))
            else:
                action = "org_key.version_retained_for_backups"
                note = (f"version {rot['from_version']} kept until {keep.isoformat()}: database backups up to "
                        f"{backup_days} days old may still hold keys wrapped under it; every key moved to version "
                        + str(rot["to_version"]))
            audit_org(conn, actor_kind="system", actor_id=operator_id, action=action,
                      target_kind="org_key", target_id=rot["rotation_id"], reason=note, request_id=request_id)
            audit_platform(conn, operator_id=operator_id, action=action, target_kind="org_key",
                           target_id=rot["rotation_id"], reason=note, request_id=request_id)
        else:
            _destroy_version(conn, custody=custody, org=org, version=rot["from_version"],
                             rotation_id=rot["rotation_id"], operator_id=operator_id, request_id=request_id,
                             note=f"version {rot['from_version']} destroyed after every key moved to version "
                                  f"{rot['to_version']}")
        conn.execute("UPDATE consentvault.key_rotation SET status = 'complete', blocked_reason = NULL,"
                     " completed_at = clock_timestamp() WHERE org_id = (SELECT consentvault.current_org())"
                     " AND rotation_id = %s", (rot["rotation_id"],))
    return None


def sweep_retained(conn: psycopg.Connection, *, token_key: TokenKey, custody, ledger, operator_id: str,
                   request_id: str, org_id) -> list[int]:
    """Destroy every version of the organisation kept for the ledger or for backups whose time is past (the ledger's last
    sealed entry out of retention, the oldest backup aged out), unless a legal hold is active (then it stays kept).
    Returns the versions destroyed."""
    done: list[int] = []
    with operator_org(conn, token_key, org_id) as org:
        conn.execute("SELECT consentvault.lifecycle_lock()")
        rows = conn.execute("SELECT version, destroy_after FROM consentvault.org_key WHERE org_id ="
                            " (SELECT consentvault.current_org()) AND status IN ('retained_for_ledger', 'retained_for_backup')"
                            " ORDER BY version"
                            ).fetchall()
        now = ledger.now()
        due = [r for r in rows if r["destroy_after"] <= now]
        if not due or conn.execute("SELECT 1 FROM consentvault.legal_hold WHERE org_id = (SELECT consentvault.current_org())"
                                   " AND released_at IS NULL LIMIT 1").fetchone() is not None:
            return done
        retention = ledger.sealed_retention(org)
        for r in due:
            until = retention.get(r["version"])
            if until is not None and until > now:  # the ledger says later than the row did: keep it until then
                conn.execute("UPDATE consentvault.org_key SET status = 'retained_for_ledger', destroy_after = %s"
                             " WHERE org_id = (SELECT consentvault.current_org()) AND version = %s", (until, r["version"]))
                continue
            rot = conn.execute("SELECT rotation_id FROM consentvault.key_rotation WHERE org_id ="
                               " (SELECT consentvault.current_org()) AND from_version = %s", (r["version"],)).fetchone()
            _destroy_version(conn, custody=custody, org=org, version=r["version"],
                             rotation_id=rot["rotation_id"] if rot else None, operator_id=operator_id,
                             request_id=request_id, note=f"version {r['version']} destroyed: the last lifecycle ledger "
                                                         "entry it sealed is out of retention and the oldest backup "
                                                         "that could hold a key wrapped under it has aged out")
            done.append(r["version"])
    return done


def _drain(conn, *, token_key, crypto, org, rot: dict, batch_size: int, max_batches: Optional[int], operator_id: str,
           request_id: str) -> Optional[bool]:
    """Move contact keys batch by batch. True when none is left under the old version, False when the budget ran out,
    None when the rotation was cancelled. Bounded: every batch moves at least one key (a key that moves is never
    selected again), or the loop ends."""
    done = 0
    while max_batches is None or done < max_batches:
        n = _contact_batch(conn, token_key=token_key, crypto=crypto, org=org, rot=rot, batch_size=batch_size,
                           operator_id=operator_id, request_id=request_id)
        if n is None:
            return None
        if n == 0:
            return True
        done += 1
    return False


def run_rotation(conn: psycopg.Connection, *, token_key: TokenKey, custody, crypto, ledger, operator_id: str,
                 request_id: str, org_id, batch_size: int = DEFAULT_BATCH, max_batches: Optional[int] = None,
                 backup_retention_days: Optional[int] = None) -> Optional[dict]:
    """The job step for one organisation: re-wrap up to ``max_batches`` batches (all when None), then the organisation's
    other secrets, then destroy the old version or keep it for the ledger or for backups (``backup_retention_days``,
    the configured setting when None). Returns the rotation's state, or None when none is open."""
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= 10_000:
        raise ApiError("validation_failed", "a batch is 1 to 10000 keys", {"batch_size": "1 to 10000"})
    if ledger is None:
        raise KeyRotationError("the lifecycle ledger is needed to know which key versions it still seals; none is "
                               "configured, so nothing was rotated")
    backup_days = _backup_days(backup_retention_days)
    org = to_uuid(org_id, "organization")
    with operator_org(conn, token_key, org):
        rot = _open(conn)
    if rot is None:
        return None
    try:
        for attempt in range(1, MAX_PASSES + 1):
            drained = _drain(conn, token_key=token_key, crypto=crypto, org=org, rot=rot, batch_size=batch_size,
                             max_batches=max_batches, operator_id=operator_id, request_id=request_id)
            if not drained:
                break  # the batch budget of this run is spent (the next run resumes), or offboarding cancelled it
            _rewrap_secrets(conn, token_key=token_key, custody=custody, crypto=crypto, org=org, rot=rot,
                            operator_id=operator_id, request_id=request_id)
            why = _destroy_old(conn, token_key=token_key, custody=custody, ledger=ledger, org=org, rot=rot,
                               operator_id=operator_id, request_id=request_id, backup_days=backup_days)
            if why is None or why == CANCELLED:
                break
            if why.startswith("still_wrapped:") and attempt < MAX_PASSES:
                continue  # keys written under the old version while this pass ran: one more pass
            _block(conn, token_key=token_key, org=org, rot=rot, why=why, alarm=ALARM_BLOCKED,
                   error_class="LegalHoldActive" if why.startswith(HOLD_PREFIX) else "RotationBlocked",
                   operator_id=operator_id, request_id=request_id)
            break
    except (KeyProviderError, CustodyKeyError, KeyRotationError, LifecycleError, psycopg.Error) as exc:
        why = f"rewrap_failed: {type(exc).__name__}"
        _block(conn, token_key=token_key, org=org, rot=rot, why=why, alarm=ALARM_FAILED, error_class="KeyRotationError",
               operator_id=operator_id, request_id=request_id)
        raise KeyRotationError(f"the key rotation of organization {org} is blocked ({why}): {describe(exc)}", org_ids=(org,)) from exc
    with operator_org(conn, token_key, org):
        now = conn.execute("SELECT * FROM consentvault.key_rotation WHERE org_id = (SELECT consentvault.current_org())"
                           " AND rotation_id = %s", (rot["rotation_id"],)).fetchone()
        return _state(conn, now)


def _sweep(conn, *, token_key, custody, ledger, operator_id: str, request_id: str, org) -> None:
    """``sweep_retained`` for the job: a failure raises the operator alarm and ``KeyRotationError``."""
    from ..alarms import AlarmWriteError, raise_operator_alarm

    try:
        sweep_retained(conn, token_key=token_key, custody=custody, ledger=ledger, operator_id=operator_id,
                       request_id=request_id, org_id=org)
    except (KeyProviderError, CustodyKeyError, LifecycleError, psycopg.Error) as exc:
        try:
            with operator_org(conn, token_key, org):
                raise_operator_alarm(conn, name=ALARM_FAILED, error_class="KeyRotationError", ref_kind="org_key",
                                     request_id=request_id)
        except AlarmWriteError as aexc:
            raise KeyRotationError(f"a retained key version of {org} could not be destroyed ({describe(exc)}) and its alarm "
                                   f"could not be written: {describe(aexc)}", org_ids=(org,)) from exc
        raise KeyRotationError(f"a retained key version of {org} could not be destroyed: {describe(exc)}",
                               org_ids=(org,)) from exc


def run_rotation_job(connect: Callable[[], psycopg.Connection], *, token_key: TokenKey, custody, crypto, ledger,
                     request_id: str, batch_size: int = DEFAULT_BATCH, operator_id: str = JOB_OPERATOR,
                     backup_retention_days: Optional[int] = None) -> list[dict]:
    """The operator job: every organisation with an open rotation, one after another (organisations are listed by id
    through ``restore_org_ids``; each one's rotation is read inside it). A failure in one organisation is recorded on its
    rotation and alarmed, the others still run, and the job then raises ``KeyRotationError`` naming every organisation
    that failed."""
    backup_days = _backup_days(backup_retention_days)
    with connect() as conn:
        orgs = [r["org_id"] for r in conn.execute("SELECT consentvault.restore_org_ids() AS org_id").fetchall()]
    out: list[dict[str, Any]] = []
    failed: list[str] = []
    failed_orgs: list[str] = []
    for org in orgs:
        with connect() as conn:
            try:
                state = run_rotation(conn, token_key=token_key, custody=custody, crypto=crypto, ledger=ledger,
                                     operator_id=operator_id, request_id=request_id, org_id=org, batch_size=batch_size,
                                     backup_retention_days=backup_days)
                _sweep(conn, token_key=token_key, custody=custody, ledger=ledger, operator_id=operator_id,
                       request_id=request_id, org=org)
            except KeyRotationError as exc:  # loud-failure-exempt: recorded blocked and alarmed by run_rotation; re-raised below once every org ran
                failed.append(f"{org}: {describe(exc)}")
                failed_orgs.append(str(org))
                out.append({"org_id": str(org), "status": "blocked", "error": describe(exc)})
                continue
        if state is not None:
            out.append(state)
    if failed:
        raise KeyRotationError(f"{len(failed)} of {len(orgs)} key rotations failed: " + "; ".join(failed), org_ids=failed_orgs)
    return out
