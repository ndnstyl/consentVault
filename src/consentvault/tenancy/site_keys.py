"""Site keys: the public identifier a browser widget sends, found again by its hash.

A site key (``cv_site_...``) names one capture source of one organisation. The vault stores it on the credential
twice: as ``site_key_id`` (shown to the organisation's admins so they can paste it into the widget) and as
``site_key_hash`` (SHA-256), which is the only thing the pre-authentication lookup compares. The lookup is
``consentvault.resolve_site_key``: one key in, one row or none out, never a list.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime
from dataclasses import dataclass

import psycopg

from .errors import TenancyError

SITE_KEY = re.compile(r"^cv_site_[A-Za-z0-9_-]{16,64}$")


class SiteKeyLookupError(TenancyError):
    """The site-key lookup could not be read (the database did not answer)."""


@dataclass(frozen=True)
class SiteKeyOwner:
    org_id: uuid.UUID
    credential_id: uuid.UUID
    source_id: uuid.UUID
    brand_ids: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    state: str  # active | revoked | source_retired


def hash_site_key(site_key: str) -> str:
    return hashlib.sha256(site_key.encode("utf-8")).hexdigest()


def resolve_site_key(conn: psycopg.Connection, site_key: str) -> SiteKeyOwner | None:
    """The organisation, source and credential a site key belongs to, or None when no credential holds that key."""
    if not isinstance(site_key, str) or not SITE_KEY.match(site_key):
        return None
    try:
        row = conn.execute("SELECT * FROM consentvault.resolve_site_key(%s)", (site_key,)).fetchone()
    except psycopg.Error as exc:
        raise SiteKeyLookupError(f"the site key lookup failed: {type(exc).__name__}") from exc
    if row is None:
        return None
    return SiteKeyOwner(row["org_id"], row["credential_id"], row["source_id"],
                        tuple(str(b) for b in (row["brand_ids"] or ())), tuple(row["allowed_origins"] or ()),
                        row["state"])


def resolve_site_key_times(conn: psycopg.Connection, site_key: str) -> tuple[datetime | None, datetime | None] | None:
    """When the key was revoked and when its capture source was retired (None for a time that has not happened), or None when no
    credential holds the key. A projection judges a key by these against the post's arrival, never by its state now."""
    if not isinstance(site_key, str) or not SITE_KEY.match(site_key):
        return None
    try:
        row = conn.execute("SELECT * FROM consentvault.resolve_site_key_times(%s)", (site_key,)).fetchone()
    except psycopg.Error as exc:
        raise SiteKeyLookupError(f"the site key lookup failed: {type(exc).__name__}") from exc
    return None if row is None else (row["revoked_at"], row["source_retired_at"])
