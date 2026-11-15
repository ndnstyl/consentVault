"""Record links: one sealed record, shared by a link a stranger can open (competitive-builds, Build 1).

Four things live here.

* The sender's side (``mint``, ``list_shares``, ``revoke``, ``reset_match``, ``preview_material``): run inside an entered tenant
  with an admin token. A link, a withdrawal and a match reset are each one fact in their own append-only table; nothing writes a
  consent event and nothing alters a sealed row.
* ``build_view``: turns what the database returned (``record_link_material``) into the one view the page, the JSON and the
  one-record file are all made from. It opens only the ciphertext the database sent, which the link's flags decided, and it
  recomputes each integrity check from the stored values: the input, the output, and whether the output equals the stored value.
  No model and no randomness anywhere in it; the same material gives the same view.
* ``PublicVerify``: the stranger's side. It talks to the database as a login that can run one function and read no table.
* ``certificate_link``: a certificate value becomes a link only when it exactly matches an issuer's address pattern.

The checks are integrity arithmetic over the stored record and say nothing about what the record means (rulings 1 and 10). A
check that cannot be recomputed because the link withholds one of its inputs says so by name; it is never shown as passing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import psycopg

from .errors import ConsentVaultError, NormalizationError
from .ledger import HASH_VERSIONS, _canon_value, canonical_dumps, link_hash
from .normalize import normalize_contact
from .safelog import describe
from .tenancy import audit

CODE_VERSION = "record-link-1"
RULE_SET = "record_link_checks_v1"
FORMAT_VERSION = 1

FLAG_DEFAULTS = {"show_org_name": True, "show_contact": False, "allow_contact_match": True, "show_page_url": False,
                 "show_bot_check": False}
CONTACT_ACK = "Anyone who holds this link will see the phone number or email address."
NOT_CHECKED = ("This page shows one record and the time it was sealed. It does not show what happened to this contact afterward.")
CHAIN_NOT_CHECKED = ("This check does not check where this record sits in the whole chain, and it does not show whether a later "
                     "record exists. The full export bundle checks the chain.")
NOT_AN_OPINION = "This page recomputes checks on the stored record. It is not an opinion about the record."
CERT_LABEL = "sent by the form, not checked with the issuer"

LINK_ID = re.compile(r"^cvp_[a-z2-7]{26}$")
_CERT_PATTERN = re.compile(r"^https://cert\.trustedform\.com/[0-9a-f]{40}$")
SEALED_COLUMNS = tuple(dict.fromkeys(tuple(HASH_VERSIONS[2]) + ("prev_hash", "row_hash")))
_TIME_COLUMNS = ("captured_at", "received_at", "edge_received_at")
_POST_TIME_COLUMNS = ("received_at", "edge_received_at")
CERT_FIELDS = (("trustedform_cert", "TrustedForm certificate"), ("jornaya_token", "Jornaya token"))


class ShareError(ConsentVaultError):
    """A record link could not be made, read or changed."""


class AckRequired(ShareError):
    """Showing the contact point needs the typed acknowledgement."""


class UnknownRecord(ShareError):
    """The record is not in this organisation (or is not a record a link can point to)."""


class UnknownShare(ShareError):
    """The link is not in this organisation."""


# ---- ids -----------------------------------------------------------------------------------------------------------------------

def new_link_id() -> str:
    """128 random bits from the platform source, as ``cvp_`` plus 26 lowercase base32 characters."""
    return "cvp_" + base64.b32encode(secrets.token_bytes(16)).decode("ascii").lower().rstrip("=")


def link_digest(link_id: str) -> str:
    return hashlib.sha256(link_id.encode("utf-8")).hexdigest()


def certificate_link(value: str) -> str | None:
    """The address to link, only for the exact TrustedForm certificate pattern; anything else stays plain text."""
    return value if isinstance(value, str) and _CERT_PATTERN.match(value) else None


# ---- the sender's side ----------------------------------------------------------------------------------------------------------

def _scope(flags: dict | None, contact_ack: str | None, *, require_ack: bool = True) -> dict:
    flags = dict(flags or {})
    unknown = sorted(set(flags) - set(FLAG_DEFAULTS))
    if unknown:
        raise ShareError(f"unknown record link setting(s): {unknown}; the settings are {sorted(FLAG_DEFAULTS)}")
    for k, v in flags.items():
        if not isinstance(v, bool):
            raise ShareError(f"the record link setting {k} must be true or false")
    scope = {**FLAG_DEFAULTS, **flags}
    if require_ack and scope["show_contact"] and contact_ack != CONTACT_ACK:
        raise AckRequired("showing the contact point needs the typed acknowledgement that anyone holding the link will see it")
    return scope


def _actor(actor: str) -> tuple[str, str | None]:
    kind, _, ident = actor.partition(":")
    return kind, (ident or None)


def _rid(what: str, ident: str) -> str:
    return f"{what}:{ident}"[:100]


def _event_row(conn, event_id) -> dict:
    try:
        eid = uuid.UUID(str(event_id))
    except ValueError as exc:
        raise UnknownRecord("that record id is not an id") from exc
    row = conn.execute("SELECT event_id, hash_version FROM consentvault.event WHERE org_id = (SELECT consentvault.current_org())"
                       " AND event_id = %s", (eid,)).fetchone()
    if row is None:
        raise UnknownRecord("no such record in this organization")
    if row["hash_version"] != 2:
        raise UnknownRecord("a record link points to a multi-tenant record; this one is not")
    return row


def _trigger_post(conn, event_id) -> uuid.UUID | None:
    row = conn.execute("SELECT post_id FROM consentvault.event_source_post WHERE org_id = (SELECT consentvault.current_org())"
                       " AND event_id = %s AND role = 'trigger' ORDER BY recorded_at, post_id LIMIT 1", (event_id,)).fetchone()
    return row["post_id"] if row else None


def mint(conn: psycopg.Connection, *, event_id, actor: str, flags: dict | None = None, contact_ack: str | None = None,
         note: str = "") -> dict:
    """Make one link for one record. Returns the link id once: only its digest is stored. The audit row is written first and
    never holds the link id."""
    scope = _scope(flags, contact_ack)
    ev = _event_row(conn, event_id)
    post_id = _trigger_post(conn, ev["event_id"])
    link_id = new_link_id()
    share_id = uuid.uuid4()
    kind, ident = _actor(actor)
    audit.append(conn, actor_kind=kind, actor_id=ident, action="share.created", target_kind="record_link", target_id=str(share_id),
                 request_id=_rid("share-create", str(share_id)),
                 detail={"event_id": str(ev["event_id"]), **scope, "has_note": bool(note)})
    conn.execute(
        "INSERT INTO consentvault.proof_share (share_id, link_digest, event_id, raw_post_id, show_org_name, show_contact,"
        " allow_contact_match, show_page_url, show_bot_check, created_by, note, code_version)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (share_id, link_digest(link_id), ev["event_id"], post_id, scope["show_org_name"], scope["show_contact"],
         scope["allow_contact_match"], scope["show_page_url"], scope["show_bot_check"], actor, note or "", CODE_VERSION))
    return {"share_id": str(share_id), "link_id": link_id, "flags": scope, "event_id": str(ev["event_id"])}


def _share(conn, share_id) -> dict:
    try:
        sid = uuid.UUID(str(share_id))
    except ValueError as exc:
        raise UnknownShare("no such record link in this organization") from exc
    row = conn.execute("SELECT * FROM consentvault.proof_share WHERE org_id = (SELECT consentvault.current_org()) AND share_id = %s",
                       (sid,)).fetchone()
    if row is None:
        raise UnknownShare("no such record link in this organization")
    return row


def list_shares(conn: psycopg.Connection, *, limit: int = 100) -> list[dict]:
    """The organisation's links, newest first, with how often each was opened. The link itself is never listed."""
    rows = conn.execute(
        "SELECT s.share_id, s.event_id, s.note, s.created_at, s.created_by, s.show_org_name, s.show_contact, s.allow_contact_match,"
        " s.show_page_url, s.show_bot_check, r.revoked_at, r.reason AS revoked_reason,"
        " (SELECT count(*) FROM consentvault.proof_share_view v WHERE v.org_id = s.org_id AND v.share_id = s.share_id"
        "   AND v.kind IN ('page', 'file')) + (SELECT count(*) FROM consentvault.proof_share_daily_count d"
        "   WHERE d.org_id = s.org_id AND d.share_id = s.share_id) AS view_count,"
        " (SELECT count(*) FROM consentvault.proof_share_view v WHERE v.org_id = s.org_id AND v.share_id = s.share_id"
        "   AND v.kind IN ('match_yes', 'match_no') AND v.viewed_at > greatest(clock_timestamp() - interval '24 hours',"
        "   coalesce((SELECT max(z.reset_at) FROM consentvault.proof_share_reset z WHERE z.org_id = s.org_id"
        "   AND z.share_id = s.share_id), '-infinity'::timestamptz))) AS recent_matches"
        " FROM consentvault.proof_share s LEFT JOIN consentvault.proof_share_revocation r"
        " ON r.org_id = s.org_id AND r.share_id = s.share_id WHERE s.org_id = (SELECT consentvault.current_org())"
        " ORDER BY s.created_at DESC, s.share_id LIMIT %s", (max(1, min(int(limit), 500)),)).fetchall()
    out = []
    for r in rows:
        out.append({
            "share_id": str(r["share_id"]), "event_id": str(r["event_id"]), "note": r["note"] or None,
            "created_at": _canon_value(r["created_at"]), "created_by": r["created_by"],
            "show_org_name": r["show_org_name"], "show_contact": r["show_contact"],
            "allow_contact_match": r["allow_contact_match"], "show_page_url": r["show_page_url"],
            "show_bot_check": r["show_bot_check"], "view_count": int(r["view_count"]),
            "match_locked": bool(r["allow_contact_match"]) and r["revoked_at"] is None and int(r["recent_matches"]) >= MATCH_CAP,
            "withdrawn_at": _canon_value(r["revoked_at"]) if r["revoked_at"] else None})
    return out


MATCH_CAP = 10


def revoke(conn: psycopg.Connection, share_id, *, actor: str, reason: str = "sender") -> dict:
    """Withdraw a link: one new row. Withdrawing twice is one fact; the second call answers ``revoked: False``."""
    if reason not in ("sender", "org_closed"):
        raise ShareError("a sender withdraws for the reason 'sender'; erasure is withdrawn by the erasure itself")
    row = _share(conn, share_id)
    kind, ident = _actor(actor)
    done = conn.execute("SELECT 1 FROM consentvault.proof_share_revocation WHERE org_id = (SELECT consentvault.current_org())"
                        " AND share_id = %s", (row["share_id"],)).fetchone()
    if done is not None:
        return {"share_id": str(row["share_id"]), "revoked": False}
    audit.append(conn, actor_kind=kind, actor_id=ident, action="share.withdrawn", target_kind="record_link",
                 target_id=str(row["share_id"]), reason=reason, request_id=_rid("share-withdraw", str(row["share_id"])))
    n = conn.execute("INSERT INTO consentvault.proof_share_revocation (share_id, revoked_by, reason) VALUES (%s, %s, %s)"
                     " ON CONFLICT (org_id, share_id) DO NOTHING", (row["share_id"], actor, reason)).rowcount
    return {"share_id": str(row["share_id"]), "revoked": n == 1}


def reset_match(conn: psycopg.Connection, share_id, *, actor: str) -> dict:
    row = _share(conn, share_id)
    kind, ident = _actor(actor)
    audit.append(conn, actor_kind=kind, actor_id=ident, action="share.match_reset", target_kind="record_link",
                 target_id=str(row["share_id"]), request_id=_rid("share-reset", f"{row['share_id']}:{uuid.uuid4().hex[:8]}"))
    conn.execute("INSERT INTO consentvault.proof_share_reset (share_id, reset_by) VALUES (%s, %s)", (row["share_id"], actor))
    return {"share_id": str(row["share_id"]), "reset": True}


def preview_material(conn: psycopg.Connection, *, event_id, flags: dict | None = None, contact_ack: str | None = None) -> dict:
    """What the public page would be made from, for these settings, without writing anything: the same database function the
    public path runs, so the preview and the page are one query and one answer."""
    scope = _scope(flags, contact_ack, require_ack=False)  # a preview writes nothing, so it needs no acknowledgement
    ev = _event_row(conn, event_id)
    post_id = _trigger_post(conn, ev["event_id"])
    mat = conn.execute("SELECT consentvault.record_link_material(%s, %s, %s, %s, %s) AS m",
                       (ev["event_id"], post_id, scope["show_contact"], scope["show_page_url"], scope["show_org_name"])).fetchone()["m"]
    if mat is None:
        raise UnknownRecord("no such record in this organization")
    return {**mat, "flags": scope}


# ---- the view -------------------------------------------------------------------------------------------------------------------

def _t(value) -> str | None:
    """A database timestamp (ISO text) in the one canonical text form."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return _canon_value(value)
    return _canon_value(datetime.fromisoformat(str(value).replace("Z", "+00:00")))


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hexb(value) -> bytes | None:
    return None if value is None else bytes.fromhex(value)


def _json_text(raw: str) -> str:
    """The text a JSON string value spells (for display and for hashing the wording), or the raw text for anything else."""
    if raw[:1] == '"':
        try:
            v = json.loads(raw)
            if isinstance(v, str):
                return v
        except ValueError:  # loud-failure-exempt: a value that is not a JSON string is shown as sent
            return raw
    return raw


def _clean(text: str | None) -> str | None:
    """Visitor-controlled text for display: control characters and bidirectional overrides become visible markers, so no page
    byte is invisible or reorders the text around it. Storage and the one-record file keep the exact text."""
    if text is None:
        return None
    return "".join(f"<U+{ord(c):04X}>" if (ord(c) < 32 and c not in "\n\t") or ord(c) == 127 or 0x202A <= ord(c) <= 0x202E
                   or 0x2066 <= ord(c) <= 0x2069 else c for c in text)


@dataclass
class _Opened:
    org: uuid.UUID
    crypto: Any
    post_key: bytes | None = None
    contact_key: bytes | None = None


def _open_post_key(material: dict, crypto, org: uuid.UUID) -> bytes | None:
    from .tenancy.keys_protocol import WrappedKey

    key = (material.get("post") or {}).get("key")
    if not key:
        return None
    return crypto.open_contact_key(org, WrappedKey(bytes.fromhex(key["wrapped_hex"]), key["key_version"]))


def _readings(material: dict, crypto, org: uuid.UUID) -> dict[str, dict]:
    from .extract import COL_VALUES
    from .tenancy import crypto as tc

    post = material.get("post")
    out: dict[str, dict] = {}
    if not post:
        return out
    encrypted = post["encryption"] != "none"
    data_key = _open_post_key(material, crypto, org) if encrypted else None
    for r in post["readings"]:
        values: list = []
        state = r["state"]
        if r["values_ct_hex"] is not None:
            blob = bytes.fromhex(r["values_ct_hex"])
            if not encrypted:
                raw = blob
            elif data_key is None:
                raw, state = None, "erased"
            else:
                raw = tc.decrypt_field(data_key, org, f"{post['post_id']}:{r['map_version']}:{r['field']}", COL_VALUES, blob)
            values = [] if raw is None else json.loads(raw)
        out[r["field"]] = {"state": state, "values": values, "map_version": r["map_version"],
                           "extractor_version": r["extractor_version"]}
    return out


def _body(material: dict, crypto, org: uuid.UUID) -> bytes | None:
    from .rawpost import COL_BODY
    from .tenancy import crypto as tc

    post = material.get("post")
    if not post or post.get("body_ct_hex") is None:
        return None
    blob = bytes.fromhex(post["body_ct_hex"])
    if post["encryption"] == "none":
        return blob
    data_key = _open_post_key(material, crypto, org)
    if data_key is None:
        return None
    return tc.decrypt_field(data_key, org, post["post_id"], COL_BODY, blob)


def _contact_fields(material: dict, crypto, org: uuid.UUID, event_id: str) -> tuple[str | None, str | None]:
    from .tenancy import crypto as tc
    from .tenancy.keys_protocol import WrappedKey

    ck = material.get("contact_key")
    if not ck:
        return None, None
    data_key = crypto.open_contact_key(org, WrappedKey(bytes.fromhex(ck["wrapped_hex"]), ck["key_version"]))
    contact = (tc.decrypt_text(data_key, org, event_id, "contact_norm", bytes.fromhex(material["contact_ct_hex"]))
               if material.get("contact_ct_hex") else None)
    url = (tc.decrypt_text(data_key, org, event_id, "page_url", bytes.fromhex(material["page_url_ct_hex"]))
           if material.get("page_url_ct_hex") else None)
    return contact, url


_AUTO = object()


def _check(name: str, what: str, input_text: str, output: str, stored: str | None, *, stored_note: str = "",
           equal=_AUTO, algorithm: str = "sha256") -> dict:
    """One recomputation. ``equal`` is True or False when it was recomputed against a stored value and None when it was not (the
    input is withheld, or nothing separate is stored); left out, it is the comparison of the output with the stored value."""
    if equal is _AUTO:
        equal = (output == stored) if stored is not None else None
    return {"name": name, "what": what, "algorithm": algorithm, "input": input_text, "output": output, "stored": stored,
            "stored_note": stored_note, "equal": equal}


def _event_canon(raw: dict) -> dict:
    ev = dict(raw)
    for c in _TIME_COLUMNS:
        ev[c] = _t(ev.get(c))
    return {k: _canon_value(v) if not isinstance(v, str) else v for k, v in ev.items()}


def _post_canon(post: dict) -> dict:
    """The columns the raw post's own hash covers, in the form its writer hashed them."""
    return {
        "org_id": post["org_id"], "post_id": post["post_id"], "seq": post["seq"], "intake": post["intake"],
        "received_at": _t(post["received_at"]), "method": post["method"], "path": post["path"],
        "path_ct_sha256": post["path_ct_sha256"], "body_object_sha256": post["body_object_sha256"],
        "facts_sha256": post["facts_sha256"], "query_ct_sha256": post["query_ct_sha256"],
        "headers_ct_sha256": post["headers_ct_sha256"], "body_ct_sha256": post["body_ct_sha256"],
        "body_object_id": post["body_object_id"], "body_bytes": post["body_bytes"], "body_sha256": post["body_sha256"],
        "unusual_size": post["unusual_size"], "edge_received_at": _t(post.get("edge_received_at")),
        "headers_presented_by": post["headers_presented_by"], "kind": post["kind"], "encryption": post["encryption"],
        "prev_hash": post["prev_hash"], "hash_version": post["hash_version"]}


def build_view(material: dict, crypto) -> dict:
    """The one view a record link is rendered from. ``material`` is ``record_link_material``'s answer plus ``flags``.

    Opens only what the material carries (the database sent ciphertext only for what the flags allow). Raises when the
    organisation's key cannot be used: a page is never half built."""
    org = uuid.UUID(str(material["org_id"]))
    flags = {**FLAG_DEFAULTS, **material["flags"]}
    event = _event_canon(material["event"])
    event_id = str(event["event_id"])
    withheld: list[str] = []
    if event.get("bot_check") is not None and not flags["show_bot_check"]:
        event["bot_check"] = None
        withheld.append("bot_check")
    readings = _readings(material, crypto, org)
    contact, page_url = _contact_fields(material, crypto, org, event_id)
    body = _body(material, crypto, org)
    post = material.get("post")
    disclosure = material.get("disclosure")

    def reading(name):
        r = readings.get(name)
        return None if r is None else {"state": r["state"], "values": [_clean(v) if isinstance(v, str) else v for v in r["values"]]}

    sent_wording = readings.get("wording")
    sent_text = None
    if sent_wording and sent_wording["values"] and isinstance(sent_wording["values"][0], str):
        sent_text = _json_text(sent_wording["values"][0])
    certificates = []
    for field_name, label in CERT_FIELDS:
        r = readings.get(field_name)
        shown = [{"text": _clean(_json_text(v)), "link": certificate_link(_json_text(v)), "as_sent": _clean(v)}
                 for v in (r["values"] if r else []) if isinstance(v, str)]
        certificates.append({"reading": field_name, "label": label, "state": r["state"] if r else "not_read", "values": shown,
                             "note": CERT_LABEL})

    checks: list[dict] = []
    # --- the chain link of the sealed row
    dependent_note = ("not recomputed here: this link withholds the bot-check column, which is one input of this hash"
                      if withheld else "")
    cols = HASH_VERSIONS[2]
    content_input = canonical_dumps({c: event[c] for c in cols}) if not withheld else "(withheld input)"
    content = _sha(content_input) if not withheld else ""
    if withheld:
        checks.append(_check("content hash", "the SHA-256 of the sealed columns of the row", content_input, content, None,
                             stored_note=dependent_note, equal=None))
    else:
        checks.append(_check("content hash", "the SHA-256 of the sealed columns of the row", content_input, content, None,
                             stored_note="no separate value is stored; it feeds the row hash check below", equal=None))
    link = {"contact_commit": event["contact_commit"], "content_sha256": content, "subject_commit": event["subject_commit"]}
    row_input = event["prev_hash"] + canonical_dumps(link) if not withheld else "(withheld input)"
    row_out = link_hash(event["prev_hash"], event["contact_commit"], event["subject_commit"], content) if not withheld else ""
    checks.append(_check("row hash", "the chain hash of the row from the previous hash, the two commitments and the content hash",
                         row_input, row_out, event["row_hash"], stored_note=dependent_note if withheld else "",
                         equal=None if withheld else row_out == event["row_hash"]))
    seals = []
    for s in material["seals"]:
        gen = _t(s["gen_time"])
        want = [c for c in s["columns"]]
        usable = all(c in event for c in want) and not withheld
        seal_input = canonical_dumps({c: event[c] for c in want}) if usable else "(withheld input)"
        out = _sha(seal_input) if usable else ""
        seals.append({"seal_id": str(s["seal_id"]), "hash_version": s["hash_version"], "columns": want, "digest": s["digest_hex"],
                      "tsa_url": s["tsa_url"], "gen_time": gen, "token_hex": s["token_hex"]})
        checks.append(_check("seal digest", f"the SHA-256 the timestamp seal was issued over ({s['tsa_url']})", seal_input, out,
                             s["digest_hex"], stored_note=dependent_note if withheld else "",
                             equal=None if not usable else out == s["digest_hex"]))
        received = event["received_at"]
        checks.append(_check("seal signing time", "the authority's signing time against the arrival time of the row",
                             f"arrival {received}; signed {gen}", "signed at or after arrival" if gen and gen >= received else
                             "signed before arrival", f"arrival {received}", equal=bool(gen and gen >= received),
                             algorithm="comparison"))
    # --- the wording
    if disclosure is not None:
        out = _sha(disclosure["body"])
        checks.append(_check("wording hash", "the SHA-256 of the registered wording text against the wording hash the row carries",
                             disclosure["body"], out, event["disclosure_sha256"]))
    # --- the raw post
    post_view = None
    if post:
        canon = _post_canon(post)
        pi = canonical_dumps(canon)
        po = _sha(pi)
        checks.append(_check("raw post row hash", "the SHA-256 of the columns of the stored post, as the post's own hash includes them",
                             pi, po, post["row_hash"]))
        for s in post["seals"]:
            cols_p = list(s["columns"])
            ok = all(c in canon for c in cols_p)
            pin = canonical_dumps({c: canon[c] for c in cols_p}) if ok else "(columns the post does not have)"
            pout = _sha(pin) if ok else ""
            checks.append(_check("raw post seal digest", f"the SHA-256 the post's timestamp seal was issued over ({s['tsa_url']})", pin,
                                 pout, s["digest_hex"], equal=ok and pout == s["digest_hex"]))
        if body is not None:
            checks.append(_check("post body hash", "the SHA-256 of the stored post body against the hash the post row carries",
                                 body.decode("utf-8", "replace"), hashlib.sha256(body).hexdigest(), post["body_sha256"]))
        post_view = {"post_id": post["post_id"], "seq": post["seq"], "received_at": _t(post["received_at"]),
                     "row_hash": post["row_hash"], "prev_hash": post["prev_hash"], "body_sha256": post["body_sha256"],
                     "body_bytes": post["body_bytes"], "canonical": canon,
                     "seals": [{"seal_id": str(s["seal_id"]), "hash_version": s["hash_version"], "columns": list(s["columns"]),
                                "digest": s["digest_hex"], "tsa_url": s["tsa_url"], "gen_time": _t(s["gen_time"]),
                                "token_hex": s["token_hex"]} for s in post["seals"]],
                     "body_withheld": body is None}
        if body is not None:
            post_view["body_text"] = body.decode("utf-8", "replace")
    sent_wording_facts = None
    if sent_text is not None:
        sent_hash_reading = readings.get("wording_hash")
        sent_hash = None
        if sent_hash_reading and sent_hash_reading["values"] and isinstance(sent_hash_reading["values"][0], str):
            sent_hash = _json_text(sent_hash_reading["values"][0])
        sent_wording_facts = {"text": _clean(sent_text), "sha256": _sha(sent_text), "sent_hash": _clean(sent_hash),
                              "equals_event_wording_hash": _sha(sent_text) == event["disclosure_sha256"],
                              "equals_sent_hash": (_sha(sent_text) == sent_hash) if sent_hash is not None else None}

    consent = reading("consent")
    decided = reading("decision_time")
    return {
        "format_version": FORMAT_VERSION, "code_version": CODE_VERSION, "rule_set": RULE_SET,
        "org_name": _clean(material.get("org_name")), "flags": flags, "withheld": withheld,
        "event": event, "contact": _clean(contact), "page_url": _clean(page_url),
        "consent_box": consent, "decision_time_sent": decided, "arrival_time": event["received_at"],
        "wording_registered": None if disclosure is None else {"text": _clean(disclosure["body"]), "sha256": disclosure["sha256"],
                                                               "computed_sha256": _sha(disclosure["body"]),
                                                               "label": _clean(disclosure["label"]), "locale": disclosure["locale"]},
        "wording_sent": sent_wording_facts,
        "certificates": certificates, "seals": seals,
        "anchors": [{"head_id": str(a["head_id"]), "seq": a["seq"], "row_hash": a["row_hash"],
                     "anchored_at": _t(a["anchored_at"])} for a in material["anchors"]],
        "post": post_view, "checks": checks,
        "statements": {"one_record": NOT_CHECKED, "chain": CHAIN_NOT_CHECKED, "not_an_opinion": NOT_AN_OPINION},
        "_raw": {"disclosure_body": None if disclosure is None else disclosure["body"], "body": body,
                 "contact": contact, "page_url": page_url, "sent_wording": sent_text,
                 "certificate_values": {n: (readings.get(n) or {"values": []})["values"] for n, _ in CERT_FIELDS},
                 "consent_values": (readings.get("consent") or {"values": []})["values"],
                 "decision_values": (readings.get("decision_time") or {"values": []})["values"]},
    }


# ---- the stranger's side -------------------------------------------------------------------------------------------------------

@dataclass
class Outcome:
    status: str  # ok | not_found | withdrawn | locked
    view: dict | None = None
    match: str | None = None


class PublicVerify:
    """Reads a link through the public login. ``connect`` opens a connection as ``consentvault_public_verify``; ``crypto`` is the
    platform's ``TenantCrypto`` (the only thing that can open a ciphertext the database sent)."""

    def __init__(self, connect: Callable[[], psycopg.Connection], crypto, *, region: str | None = None) -> None:
        self._connect, self._crypto, self._region = connect, crypto, region

    def _call(self, link_id: str, kind: str, candidate_fp: str | None = None) -> dict:
        conn = self._connect()
        try:
            return conn.execute("SELECT consentvault.public_proof_view(%s, %s, %s) AS r",
                                (link_digest(link_id), kind, candidate_fp)).fetchone()["r"]
        finally:
            conn.close()

    def read(self, link_id: str, kind: str = "page") -> Outcome:
        got = self._call(link_id, kind)
        if got["status"] != "ok":
            return Outcome(got["status"])
        return Outcome("ok", build_view(got["material"], self._crypto))

    def match(self, link_id: str, typed: str) -> Outcome:
        """Whether what the visitor typed gives the same fingerprint as the record's contact point. The fingerprint is worked out
        here (it needs the organisation's secret) and compared inside the database function, which counts the attempt, applies the
        lock and records yes or no without the contact. Typed text that is not a phone number or email address is answered 'no'
        and counts as an attempt like any other."""
        ctx = self._call(link_id, "match_context")
        if ctx["status"] != "ok":
            return Outcome(ctx["status"])
        fp = "0" * 64
        try:
            kind, norm = normalize_contact(typed, None, ctx.get("region") or self._region)
        except NormalizationError:  # loud-failure-exempt: text that is no contact point is the answer 'no', counted like any other try
            kind = norm = None
        if kind is not None:
            fp = self._crypto.contact_fingerprint(ctx["org_id"], kind, norm)
        got = self._call(link_id, "match", fp)
        return Outcome(got["status"], match=got.get("match"))
