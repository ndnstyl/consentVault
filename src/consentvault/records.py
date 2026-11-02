"""The contact record list's writers (records.md sections 8 and 9, core change R1).

``record_tenant_event`` calls ``write_event_records`` inside the event's own transaction, so the event and its record rows
commit together or not at all: a failure here rolls the event back, as an outbox failure does. The SQL does the work in
owner-rights functions (migration 0044); this module only prepares what the database cannot: the masked contact and the
name and company, sealed under the organisation's display key with ``encrypt_field``, so each ciphertext is bound to the
organisation, the ``record_id`` and the column (``mask_ct``, ``name_ct``, ``company_ct``).

Nothing here logs a contact point, a name or a company.
"""

from __future__ import annotations

import uuid
from typing import Any, Mapping, Optional

import psycopg

from .errors import ConsentVaultError
from .normalize import subject_key
from .tenancy.errors import KeyProviderError

MASK_COLUMN = "mask_ct"
NAME_COLUMN = "name_ct"
COMPANY_COLUMN = "company_ct"
DISPLAY_FIELD_MAX = 200


class RecordsError(ConsentVaultError):
    """The records tables could not be written. The event that caused the write is not recorded."""


def mask_contact(kind: str, norm: str) -> str:
    """The masked form of a normalised contact point, safe to show on a list: ``(555) ***-0142`` for a North American
    number, only the last four digits of any other number, and ``d***@example.com`` for an email address."""
    if kind == "email":
        local, _, domain = norm.partition("@")
        if not local or not domain:
            raise RecordsError("an email address to mask has no local part or domain")
        return f"{local[0]}***@{domain}"
    if kind == "phone":
        digits = norm[1:] if norm.startswith("+") else norm
        if not digits.isdigit() or len(digits) < 8:
            raise RecordsError("a phone number to mask is not a normalised number")
        if norm.startswith("+1") and len(norm) == 12:
            return f"({digits[1:4]}) ***-{digits[-4:]}"
        return "+" + "*" * (len(digits) - 4) + digits[-4:]
    raise RecordsError(f"cannot mask a contact point of kind {kind!r}")


def clean_display(display: Optional[Mapping[str, Any]]) -> Optional[dict]:
    """The name and company to keep, or None. Strings of 1 to 200 characters under only those two keys."""
    if display is None:
        return None
    if not isinstance(display, Mapping) or not display or set(display) - {"name", "company"}:
        raise RecordsError("display is an object with a name and/or a company, and no other key")
    for key, value in display.items():
        if not isinstance(value, str) or not 1 <= len(value) <= DISPLAY_FIELD_MAX:
            raise RecordsError(f"display.{key} must be text of 1 to {DISPLAY_FIELD_MAX} characters")
    return dict(display)


def default_subject_fp(crypto, org, contact_norm: str) -> str:
    """The subject fingerprint an event about this contact carries when it was captured with no person key of its own. The
    records layer needs it to tell a keyed event (which links records) from an unkeyed one (which never moves a link)."""
    return crypto.subject_fingerprint(org, subject_key(contact_norm))


def write_event_records(conn: psycopg.Connection, crypto, *, org: uuid.UUID, event_id: str, contact_fp: str,
                        contact_kind: str, contact_norm: str, display: Optional[Mapping[str, Any]] = None) -> str:
    """Inside the event's transaction: the active record of the fingerprint (made when there is none), its derived index with
    the mask sealed on the record's first event, and the display row when the capture carried a name or a company.
    Returns the ``record_id``. Any failure raises (``RecordsError`` for a database refusal, ``KeyProviderError`` when the
    display key cannot be used) and the caller's transaction rolls the event back."""
    from .tenancy import crypto as tc

    shown = clean_display(display)
    try:
        rid = conn.execute("SELECT consentvault.record_upsert(%s, %s, %s) AS record_id",
                           (event_id, contact_fp, contact_kind)).fetchone()["record_id"]
        key = None
        try:
            key = crypto.display_key(org)
        except KeyProviderError:
            # A stop, or any event that carries no name or company, is recorded even when the display key cannot be used:
            # the record's mask stays empty (the list names it in ``partial``) and the next event fills it. An event that
            # carries a name or company needs the key and is refused.
            if shown:
                raise
        mask_ct = (tc.encrypt_field(key, org, str(rid), MASK_COLUMN, mask_contact(contact_kind, contact_norm))
                   if key is not None else None)
        conn.execute("SELECT consentvault.record_index_refresh(%s, %s, %s, %s)",
                     (event_id, contact_fp, mask_ct, default_subject_fp(crypto, org, contact_norm)))
        if shown:
            conn.execute("SELECT consentvault.record_display_write(%s, %s, %s)",
                         (rid, tc.encrypt_field(key, org, str(rid), NAME_COLUMN, shown["name"]) if "name" in shown else None,
                          tc.encrypt_field(key, org, str(rid), COMPANY_COLUMN, shown["company"]) if "company" in shown else None))
    except psycopg.Error as exc:
        raise RecordsError(f"the records tables refused the event: {type(exc).__name__}") from exc
    return str(rid)
