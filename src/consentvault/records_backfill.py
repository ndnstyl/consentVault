"""Backfill for organizations that existed before the contact record list (migration 0044).

For each organization it (1) makes the display key when the organization has none, wrapped by the organization key exactly as
``admin.create_org`` does, and (2) makes the record and the derived index for every contact point that has events but no
record, sealing the mask under the display key. A contact whose key was erased (no contact key) is marked erased. Names and
companies were never kept before, so none are invented.

It is safe to run again: it only touches contact points with no record, and an organization that already has a display key
keeps it. A contact an active legal hold covers is not marked erased and is counted in ``held``; an organization it could not
finish is listed in ``failed`` and the run exits 1; nothing is skipped quietly.

``python -m consentvault.records_backfill`` runs it with the server's configuration.
"""

from __future__ import annotations

import os
from typing import Any

import psycopg

from .safelog import describe
from .errors import ConsentVaultError
from .providers.keys import wrapped_version
from .records import MASK_COLUMN, default_subject_fp, mask_contact
from .tenancy import crypto as tc
from .tenancy.errors import FieldCryptoError, KeyProviderError
from .tenancy.keys_protocol import WrappedKey
from .tenancy.tokens import mint_org_token, org_transaction

SCOPES = ["admin", "worker:display_key"]


class NoOrganizationKey(ConsentVaultError):
    """The organization has no key of its own (the single-company home organization): there is nothing to seal under."""


class BackfillError(ConsentVaultError):
    """The backfill could not finish a contact point; the organization is listed as failed."""


def backfill(owner_connect, token_key, custody, crypto) -> dict[str, Any]:
    """Run the backfill for every organization that is not closed. Answers the counts, and the organizations it stopped on."""
    totals: dict[str, Any] = {"organizations": 0, "display_keys": 0, "records": 0, "erased": 0, "held": 0, "unmasked": 0,
                              "relinked": 0, "held_contacts": [], "without_org_key": [], "failed": []}
    with owner_connect() as conn:
        orgs = [r["evidence_org_ids"] for r in conn.execute("SELECT consentvault.evidence_org_ids()")]
    for org in orgs:
        try:
            with owner_connect() as conn:
                one = _backfill_org(conn, token_key, custody, crypto, org)
        except NoOrganizationKey:  # loud-failure-exempt: listed in the result's without_org_key list
            totals["without_org_key"].append(str(org))
            continue
        except (psycopg.Error, KeyProviderError, ConsentVaultError) as exc:  # loud-failure-exempt: listed in the result's failed list and the run exits 1
            totals["failed"].append({"org_id": str(org), "cause": type(exc).__name__})
            continue
        totals["organizations"] += 1
        for k in ("display_keys", "records", "erased", "held", "unmasked", "relinked"):
            totals[k] += one[k]
        totals["held_contacts"] += [{"org_id": str(org), "contact": fp[:8]} for fp in one["held_fps"]]
    return totals


def _backfill_org(conn, token_key, custody, crypto, org) -> dict[str, int]:
    out = {"display_keys": 0, "records": 0, "erased": 0, "held": 0, "unmasked": 0, "relinked": 0, "held_fps": []}
    token = mint_org_token(token_key, org, SCOPES, credential_id=None, ttl_seconds=300)
    with org_transaction(conn, token):
        if conn.execute("SELECT 1 FROM consentvault.org_key WHERE org_id = (SELECT consentvault.current_org())").fetchone() is None:
            raise NoOrganizationKey(f"organization {org} has no organization key")
        if conn.execute("SELECT 1 FROM consentvault.org_display_key WHERE org_id = (SELECT consentvault.current_org())").fetchone() is None:
            wrapped = custody.wrap(str(org), os.urandom(32))
            conn.execute("INSERT INTO consentvault.org_display_key (org_id, wrapped, key_version) VALUES (%s, %s, %s)",
                         (org, wrapped, wrapped_version(wrapped)))
            out["display_keys"] += 1
    with org_transaction(conn, token):
        first = conn.execute(
            "SELECT DISTINCT ON (e.contact_fp) e.event_id, e.contact_fp, e.contact_kind, e.contact_ct FROM consentvault.post_history_all_events e"
            " WHERE e.org_id = (SELECT consentvault.current_org()) AND NOT EXISTS (SELECT 1 FROM consentvault.record r"
            " WHERE r.org_id = e.org_id AND r.contact_fp = e.contact_fp) ORDER BY e.contact_fp, e.seq").fetchall()
    for ev in first:
        with org_transaction(conn, token):
            _one(conn, crypto, org, ev, out)
    with org_transaction(conn, token):
        legacy = conn.execute("SELECT contact_fp, event_id FROM consentvault.record_index_without_default()").fetchall()
    for row in legacy:
        with org_transaction(conn, token):
            _relink(conn, crypto, org, row, out)
    return out


def _relink(conn, crypto, org, row: dict, out: dict) -> None:
    """An index written before migration 0058 has no default subject fingerprint, so its link may follow an unkeyed event.
    Re-derive it with the default, which re-reads the link from the newest keyed event."""
    fp = row["contact_fp"]
    ev = conn.execute("SELECT event_id, contact_ct FROM consentvault.post_history_all_events WHERE org_id = (SELECT consentvault.current_org())"
                      " AND event_id = %s", (row["event_id"],)).fetchone()
    held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (fp,)).fetchone()
    if held is None:
        # an erased contact whose record a legal hold keeps active: its key is gone, so it has no default subject to give and
        # links to nothing. Counted held and named in the run output on every run, never a failure of the organization.
        if fp not in out["held_fps"]:
            out["held"] += 1
            out["held_fps"].append(fp)
        return
    try:
        dk = crypto.open_contact_key(org, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
        norm = tc.decrypt_text(dk, org, str(ev["event_id"]), "contact_norm", bytes(ev["contact_ct"]))
    except (KeyProviderError, FieldCryptoError) as exc:
        raise BackfillError(f"the contact {fp[:8]} could not be opened: {type(exc).__name__}") from exc
    conn.execute("SELECT consentvault.record_index_refresh(%s, %s, %s, %s)", (ev["event_id"], fp, None, default_subject_fp(crypto, org, norm)))
    out["relinked"] += 1


def _one(conn, crypto, org, ev: dict, out: dict) -> None:
    fp = ev["contact_fp"]
    rid = conn.execute("SELECT consentvault.record_upsert(%s, %s, %s) AS r", (ev["event_id"], fp, ev["contact_kind"])).fetchone()["r"]
    held = conn.execute("SELECT * FROM consentvault.contact_key_of(%s)", (fp,)).fetchone()
    mask_ct = dflt = None
    if held is not None:
        try:
            dk = crypto.open_contact_key(org, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
            norm = tc.decrypt_text(dk, org, str(ev["event_id"]), "contact_norm", bytes(ev["contact_ct"]))
            mask_ct = tc.encrypt_field(crypto.display_key(org), org, str(rid), MASK_COLUMN, mask_contact(ev["contact_kind"], norm))
            dflt = default_subject_fp(crypto, org, norm)
        except (KeyProviderError, FieldCryptoError) as exc:
            raise BackfillError(f"the contact {fp[:8]} could not be opened: {type(exc).__name__}") from exc
    conn.execute("SELECT consentvault.record_index_refresh(%s, %s, %s, %s)", (ev["event_id"], fp, mask_ct, dflt))
    out["records"] += 1
    if held is None:
        out["unmasked"] += 1
        try:
            with conn.transaction():
                conn.execute("SELECT consentvault.erase_contact(%s)", (fp,))
            out["erased"] += 1
        except psycopg.errors.IntegrityConstraintViolation:  # loud-failure-exempt: counted in held and named; the record stays active
            out["held"] += 1
            out["held_fps"].append(fp)


def main(argv=None, env=None) -> int:
    from . import safelog as _safelog
    _safelog.setup_process()  # the scrub filter on every handler, warnings, and the exception hooks
    import sys

    from . import cmd_cloud
    from .config import load_config
    from .errors import ConfigError
    from .tenancy.admin_routes import AdminApp

    env = os.environ if env is None else env
    try:
        settings = cmd_cloud.build_cloud(load_config(env=env), env)
        app = next(r._app for r in settings.routes if isinstance(getattr(r, "_app", None), AdminApp))
        result = backfill(app._owner_connect, app._key, app._custody, app.crypto)
    except (ConfigError, ConsentVaultError) as exc:
        print(f"consentvault.records_backfill: {describe(exc)}", file=sys.stderr)
        return 2
    print(result)
    return 0 if not result["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
