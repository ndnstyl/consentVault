"""The raw post writer: the first and only write of the capture step.

Every request that reaches an intake is stored here, whole, before anything reads it (contracts/capture-api.md,
data-model.md section 1). The writer keeps the request exactly as received: method, path, query string, every header
name and value in the order presented, and every byte of the body, with the SHA-256 and byte count of the whole body.
Nothing about the request is checked, trimmed, sorted, re-serialised or judged. The only failure the writer has is
``StoreUnavailable``: the vault could not write, and nothing partial was written.

1. Encrypt the body under the post's own data key and, when it is above the inline limit, write it whole to the write-once
   evidence store and check the store's copy against its digest, before any lock is taken.
2. Inside the entered organisation (one short transaction): take the organisation's raw-post lock, read the chain head and
   append one ``raw_post`` row, the wrapped post key and the arrival facts together.
3. Sign the receipt ``{org_id, post_id, seq, row_hash, received_at, body_sha256}`` with the platform receipt key.

Extraction, matching and alarms run after the commit and can neither change the answer nor remove the row.

Without a key provider (a single-company vault that configured none) the bytes are stored as sent and the row says so
(``encryption = 'none'``); with one, the body, headers and query string are encrypted under a per-post data key wrapped
by the organisation key, and that key is the only thing an erasure deletes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping

import psycopg

from .errors import ConsentVaultError
from .ledger import GENESIS, canonical_dumps
from .safelog import describe
from .tenancy.errors import KeyProviderError

INLINE_LIMIT_BYTES = 64 * 1024
UNUSUAL_SIZE_BYTES = 1024 * 1024
HASH_VERSION = 3
ENC_WRAPPED = "wrapped_post_key"
ENC_NONE = "none"
RECEIPT_FIELDS = {"org_id", "post_id", "seq", "row_hash", "received_at", "body_sha256", "signature"}
INTAKES = ("edge_site_key", "edge_single", "gateway", "api", "api_single", "signal", "twenty", "sms_reply", "stop_page",
           "restore", "site_form")

COL_BODY, COL_HEADERS, COL_QUERY, COL_FACT = "raw_post.body", "raw_post.headers", "raw_post.query", "raw_post_fact.value"
_LOCK_SQL = "SELECT pg_advisory_xact_lock(consentvault.raw_post_lock_key(consentvault.current_org()))"


class StoreUnavailable(ConsentVaultError):
    """The vault could not write the post (key provider, evidence store or database down). Nothing partial was written."""


@dataclass(frozen=True)
class Fact:
    """One thing the transport knew about a post. ``value`` is any JSON value, stored as canonical JSON text."""
    source: str
    name: str
    value: Any


@dataclass(frozen=True)
class RawRequest:
    intake: str
    method: str
    path: str
    query: bytes | str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    headers_presented_by: str = "vault-http"
    kind: str = "post"
    edge_received_at: datetime | None = None
    facts: tuple[Fact, ...] = ()


@dataclass(frozen=True)
class StoredPost:
    org_id: str
    post_id: str
    seq: int
    row_hash: str
    prev_hash: str
    received_at: datetime
    body_sha256: str
    body_bytes: int
    unusual_size: bool
    encryption: str
    receipt: dict
    data_key: bytes | None = field(default=None, repr=False)

    def answer(self) -> dict:
        """The 201 answer of contracts/capture-api.md section 3. Never a judgment of the post."""
        stamp = _stamp(self.received_at)
        return {"stored": True, "post_id": self.post_id, "received_at": stamp, "body_sha256": self.body_sha256,
                "body_bytes": self.body_bytes, "unusual_size": self.unusual_size, "receipt": self.receipt}


def _stamp(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _db_text(value: str) -> str:
    """A string the database can hold: the only changes are the characters PostgreSQL text cannot store (NUL and lone
    surrogates), written as percent escapes. The exact request is in the encrypted headers and body."""
    out = []
    for ch in value:
        if ch == "\x00" or 0xD800 <= ord(ch) <= 0xDFFF:
            out.append("".join("%%%02X" % b for b in ch.encode("utf-8", "surrogatepass")))
        else:
            out.append(ch)
    return "".join(out)


def _as_bytes(value: bytes | str) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8", "surrogatepass")


def headers_json(headers: Iterable[tuple[str, str]]) -> bytes:
    """Every header name and value as presented, in order, repeats kept (a list of pairs, never a mapping)."""
    return json.dumps([[n, v] for n, v in headers], ensure_ascii=True, separators=(",", ":")).encode("ascii")


def canonical_row(row: Mapping[str, Any], ct: Mapping[str, bytes | None]) -> dict:
    """The columns hash version 3 covers: every column but the two hashes, ciphertext columns by their SHA-256."""
    def dig(b: bytes | None) -> str | None:
        return hashlib.sha256(b).hexdigest() if b is not None else None
    return {
        "org_id": str(row["org_id"]), "post_id": str(row["post_id"]), "seq": row["seq"], "intake": row["intake"],
        "received_at": _stamp(row["received_at"]), "method": row["method"], "path": row["path"],
        "query_ct_sha256": dig(ct["query_ct"]), "headers_ct_sha256": dig(ct["headers_ct"]),
        "body_ct_sha256": dig(ct["body_ct"]),
        "body_object_id": str(row["body_object_id"]) if row["body_object_id"] is not None else None,
        "body_bytes": row["body_bytes"], "body_sha256": row["body_sha256"], "unusual_size": row["unusual_size"],
        "edge_received_at": _stamp(row["edge_received_at"]) if row["edge_received_at"] is not None else None,
        "headers_presented_by": row["headers_presented_by"], "kind": row["kind"], "encryption": row["encryption"],
        "prev_hash": row["prev_hash"], "hash_version": HASH_VERSION,
    }


def raw_post_row_hash(row: Mapping[str, Any], ct: Mapping[str, bytes | None]) -> str:
    return hashlib.sha256(canonical_dumps(canonical_row(row, ct)).encode("utf-8")).hexdigest()


# Receipts ---------------------------------------------------------------------------------------------------------------

def receipt_body(receipt: Mapping[str, Any]) -> bytes:
    return canonical_dumps({k: v for k, v in receipt.items() if k != "signature"}).encode("utf-8")


def verify_post_receipt(receipt: Mapping[str, Any], public_key, key_id: str) -> bool:
    """True only when the receipt carries exactly the six fields and a valid signature by ``key_id`` (offline check)."""
    from cryptography.exceptions import InvalidSignature

    from .tenancy.oauth import b64url_decode

    if set(receipt) != RECEIPT_FIELDS:
        return False
    parts = str(receipt["signature"]).split(":")
    if len(parts) != 3 or parts[0] != "ed25519" or parts[1] != key_id:
        return False
    try:
        public_key.verify(b64url_decode(parts[2]), receipt_body(receipt))
    except (InvalidSignature, ValueError):
        return False  # loud-failure-exempt: a receipt that does not verify is the answer False, by contract
    return True


# The writer -------------------------------------------------------------------------------------------------------------

class RawPostWriter:
    """Writes raw posts. ``crypto`` (a ``TenantCrypto``) wraps each post's data key; ``store`` (an ``EvidenceStore``)
    holds bodies above ``inline_limit``; ``receipts`` (a ``ReceiptSigner``) signs the answer. Any of the three may be
    None for a single-company vault that configured none: no key provider stores the bytes as sent (labelled), no store
    keeps every body inline, no signer leaves the receipt's signature empty."""

    def __init__(self, *, crypto=None, store=None, receipts=None, inline_limit: int = INLINE_LIMIT_BYTES,
                 unusual_size: int = UNUSUAL_SIZE_BYTES, retain_years: int = 7) -> None:
        if not isinstance(inline_limit, int) or inline_limit < 0:
            raise ConsentVaultError("inline_limit must be a non-negative whole number of bytes")
        if not isinstance(unusual_size, int) or unusual_size < 1:
            raise ConsentVaultError("unusual_size must be a positive whole number of bytes")
        self.crypto, self.store, self.receipts = crypto, store, receipts
        self.inline_limit, self.unusual_size, self.retain_years = inline_limit, unusual_size, retain_years

    # ---- encryption ---------------------------------------------------------------------------------------------------
    def _seal(self, key: bytes | None, org: uuid.UUID, post_id: uuid.UUID, column: str, value: bytes) -> bytes:
        if key is None:
            return value
        from .tenancy import crypto as tc
        return tc.encrypt_field(key, org, str(post_id), column, value)

    def open_key(self, conn: psycopg.Connection, org: uuid.UUID, post_id: uuid.UUID | str) -> bytes | None:
        """The data key of one stored post, or None when it was stored unencrypted. Raises when the key row is gone."""
        row = conn.execute("SELECT post_key_wrapped, key_version FROM consentvault.raw_post_key"
                           " WHERE org_id = %s AND post_id = %s", (org, uuid.UUID(str(post_id)))).fetchone()
        if row is None:
            return None
        from .tenancy.keys_protocol import WrappedKey
        if self.crypto is None:
            raise StoreUnavailable("the post is encrypted and no key provider is configured to open it")
        return self.crypto.open_contact_key(org, WrappedKey(bytes(row["post_key_wrapped"]), row["key_version"]))

    def read_body(self, conn: psycopg.Connection, org: uuid.UUID, post_id: uuid.UUID | str) -> bytes:
        """The whole body of a stored post, decrypted; an object in the store is read back and checked against its digest."""
        row = conn.execute("SELECT body_ct, body_object_id, body_sha256, encryption FROM consentvault.raw_post"
                           " WHERE org_id = %s AND post_id = %s", (org, uuid.UUID(str(post_id)))).fetchone()
        if row is None:
            raise ConsentVaultError("no such raw post in this organisation")
        blob = bytes(row["body_ct"]) if row["body_ct"] is not None else self._object(org, row["body_object_id"])
        if row["encryption"] == ENC_NONE:
            return blob
        from .tenancy import crypto as tc
        key = self.open_key(conn, org, post_id)
        if key is None:
            raise ConsentVaultError("the key of this post was erased; its bytes cannot be read")
        return tc.decrypt_field(key, org, str(post_id), COL_BODY, blob)

    def _object(self, org: uuid.UUID, object_id) -> bytes:
        if self.store is None:
            raise StoreUnavailable("the post's body is in the evidence store and none is configured")
        return self.store.get(str(org), f"raw-posts/{object_id}")

    # ---- the write ----------------------------------------------------------------------------------------------------
    def write(self, conn: psycopg.Connection, enter: Callable, req: RawRequest) -> StoredPost:
        """Store ``req``. ``enter(conn)`` opens a transaction inside the caller's tenant (``org_transaction`` bound to a
        token; ``None`` stands for the single-company vault, where the transaction is the connection's own).

        Two short transactions with the heavy work between them: the first reads the organisation, the home organisation and
        the database's clock; the body is then encrypted and, when it is above the inline limit, written whole to the
        evidence store (no transaction, no lock held while bytes travel); the second takes the organisation's raw-post lock,
        reads the head and appends the row, the key and the facts together."""
        if not isinstance(req.body, (bytes, bytearray)):
            raise ConsentVaultError("a raw post body is bytes")
        body = bytes(req.body)
        post_id = uuid.uuid4()
        size = len(body)
        body_sha = hashlib.sha256(body).hexdigest()
        object_id = uuid.uuid4() if (size > self.inline_limit and self.store is not None) else None
        try:
            ctx = enter(conn) if enter is not None else conn.transaction()
            with ctx:
                who = conn.execute("SELECT consentvault.current_org() AS org, consentvault.home_org() AS home,"
                                   " clock_timestamp() AS now").fetchone()
            org, home = who["org"], who["home"]
            if org is None:
                raise StoreUnavailable("no organisation is entered for the write (the home organisation was not reachable)")
            key, wrapped = None, None
            if self.crypto is not None:
                try:
                    wrapped_key = self.crypto.new_contact_key(org)
                    key, wrapped = wrapped_key.data_key, wrapped_key.wrapped
                except KeyProviderError:
                    if org != home:
                        raise
                    # the platform intake (the home organisation of a cloud vault) may have no key of its own: the
                    # post is stored as sent and the row says so, never dropped for want of a key
            enc = ENC_WRAPPED if key is not None else ENC_NONE
            blob = self._seal(key, org, post_id, COL_BODY, body)
            body_ct = blob
            if object_id is not None:
                retain = who["now"] + timedelta(days=366 * self.retain_years)
                record = self.store.put(str(org), f"raw-posts/{object_id}", blob, retain_until=retain)
                if record.sha256 != hashlib.sha256(blob).hexdigest():
                    raise StoreUnavailable("the evidence store's copy of the body does not match what was sent to it")
                body_ct = None
            query_ct = self._seal(key, org, post_id, COL_QUERY, _as_bytes(req.query))
            headers_ct = self._seal(key, org, post_id, COL_HEADERS, headers_json(req.headers))
            ctx = enter(conn) if enter is not None else conn.transaction()
            with ctx:
                conn.execute(_LOCK_SQL)
                received = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
                head = conn.execute("SELECT * FROM consentvault.raw_post_head()").fetchone()
                row = {
                    "org_id": org, "post_id": post_id, "seq": head["seq"] + 1 if head else 1,
                    "intake": _db_text(req.intake), "received_at": received, "method": _db_text(req.method),
                    "path": _db_text(req.path), "body_object_id": object_id, "body_bytes": size, "body_sha256": body_sha,
                    "unusual_size": size > self.unusual_size, "edge_received_at": req.edge_received_at,
                    "headers_presented_by": _db_text(req.headers_presented_by), "kind": _db_text(req.kind),
                    "encryption": enc, "prev_hash": head["row_hash"] if head else GENESIS,
                }
                ct = {"query_ct": query_ct, "headers_ct": headers_ct, "body_ct": body_ct}
                row_hash = raw_post_row_hash(row, ct)
                conn.execute(
                    "INSERT INTO consentvault.raw_post (org_id, post_id, seq, intake, received_at, method, path, query_ct,"
                    " headers_ct, body_ct, body_object_id, body_bytes, body_sha256, unusual_size, edge_received_at,"
                    " headers_presented_by, kind, encryption, prev_hash, row_hash, hash_version)"
                    " VALUES (%(org_id)s, %(post_id)s, %(seq)s, %(intake)s, %(received_at)s, %(method)s, %(path)s,"
                    " %(query_ct)s, %(headers_ct)s, %(body_ct)s, %(body_object_id)s, %(body_bytes)s, %(body_sha256)s,"
                    " %(unusual_size)s, %(edge_received_at)s, %(headers_presented_by)s, %(kind)s, %(encryption)s,"
                    " %(prev_hash)s, %(row_hash)s, 3)",
                    {**row, **ct, "row_hash": row_hash})
                if wrapped is not None:
                    conn.execute("INSERT INTO consentvault.raw_post_key (org_id, post_id, post_key_wrapped, key_version)"
                                 " VALUES (%s, %s, %s, %s)", (org, post_id, wrapped.ciphertext, wrapped.key_version))
                for fact in req.facts:
                    self._insert_fact(conn, org, post_id, key, fact)
        except StoreUnavailable:
            raise
        except ConsentVaultError as exc:  # provider, key and store failures all mean the same: nothing was stored
            raise StoreUnavailable(f"the post could not be stored: {type(exc).__name__}") from exc
        except psycopg.Error as exc:
            raise StoreUnavailable(f"the post could not be stored: {describe(exc)}") from exc
        receipt = self._receipt(org, post_id, row["seq"], row_hash, received, body_sha)
        return StoredPost(str(org), str(post_id), row["seq"], row_hash, row["prev_hash"], received, body_sha, size,
                          row["unusual_size"], enc, receipt, key)

    def _insert_fact(self, conn: psycopg.Connection, org: uuid.UUID, post_id: uuid.UUID, key: bytes | None, fact: Fact) -> None:
        raw = canonical_dumps(fact.value).encode("utf-8")
        conn.execute("INSERT INTO consentvault.raw_post_fact (org_id, post_id, fact_id, source, name, value_ct)"
                     " VALUES (%s, %s, %s, %s, %s, %s)",
                     (org, post_id, uuid.uuid4(), _db_text(fact.source), _db_text(fact.name),
                      self._seal(key, org, post_id, COL_FACT, raw)))

    def add_facts(self, conn: psycopg.Connection, enter: Callable, stored: StoredPost, facts: Iterable[Fact]) -> None:
        """Facts learned after the post committed (appended; never changes the post)."""
        ctx = enter(conn) if enter is not None else conn.transaction()
        with ctx:
            org = uuid.UUID(stored.org_id)
            for fact in facts:
                self._insert_fact(conn, org, uuid.UUID(stored.post_id), stored.data_key, fact)

    def link_event(self, conn: psycopg.Connection, enter: Callable, stored: StoredPost, event_id: str | uuid.UUID,
                   role: str = "trigger") -> None:
        """Record which post an event came from (``event_source_post``): an event written because of this post cites it."""
        ctx = enter(conn) if enter is not None else conn.transaction()
        with ctx:
            conn.execute("INSERT INTO consentvault.event_source_post (org_id, event_id, post_id, role) VALUES (%s, %s, %s, %s)",
                         (uuid.UUID(stored.org_id), uuid.UUID(str(event_id)), uuid.UUID(stored.post_id), role))

    def _receipt(self, org, post_id, seq, row_hash, received, body_sha) -> dict:
        body = {"org_id": str(org), "post_id": str(post_id), "seq": seq, "row_hash": row_hash,
                "received_at": _stamp(received), "body_sha256": body_sha}
        if self.receipts is None:
            return {**body, "signature": None}
        return self.receipts.sign(body)



# Chain verification ----------------------------------------------------------------------------------------------------

def verify_raw_chain(conn: psycopg.Connection) -> list[dict]:
    """Every break in the entered organisation's raw-post chain: a link that does not extend the one before it, a row
    hash that does not recompute from the stored columns. Returns [] when the chain is whole. Reads the stored rows only."""
    breaks: list[dict] = []
    prev, expect = GENESIS, 1
    for r in conn.execute("SELECT * FROM consentvault.raw_post WHERE org_id = (SELECT consentvault.current_org())"
                          " ORDER BY seq"):
        if r["seq"] != expect:
            breaks.append({"seq": r["seq"], "post_id": str(r["post_id"]), "reason": f"seq {r['seq']} where {expect} was expected"})
        if r["prev_hash"] != prev:
            breaks.append({"seq": r["seq"], "post_id": str(r["post_id"]), "reason": "prev_hash is not the previous row's hash"})
        ct = {"query_ct": bytes(r["query_ct"]), "headers_ct": bytes(r["headers_ct"]),
              "body_ct": bytes(r["body_ct"]) if r["body_ct"] is not None else None}
        if raw_post_row_hash(r, ct) != r["row_hash"]:
            breaks.append({"seq": r["seq"], "post_id": str(r["post_id"]), "reason": "row_hash does not recompute from the stored columns"})
        prev, expect = r["row_hash"], r["seq"] + 1
    return breaks


def read_raw_sink(path: str) -> list[dict]:
    """The raw post anchors a file sink holds (the lines labelled ``"chain": "raw_post"``)."""
    out: list[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("chain") == "raw_post":
                    out.append({"seq": int(rec["seq"]), "row_hash": str(rec["row_hash"]), "org_id": rec.get("org_id")})
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ConsentVaultError(f"cannot read the raw post anchors of {path}: {describe(exc)}") from exc
    return out


def verify_raw_anchors(conn: psycopg.Connection, *, sink_file: str | None = None) -> list[dict]:
    """Every anchor of the entered organisation's raw post chain (the database rows, and the sink file's lines when given)
    against the posts now held: a post missing at an anchored sequence, or holding a different hash, is a break."""
    rows = {r["seq"]: r["row_hash"] for r in conn.execute(
        "SELECT seq, row_hash FROM consentvault.raw_post WHERE org_id = (SELECT consentvault.current_org())")}
    org = str(conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"])
    anchors = [(a["seq"], a["row_hash"], "raw_post_chain_head") for a in conn.execute(
        "SELECT seq, row_hash FROM consentvault.raw_post_chain_head ORDER BY anchored_at, seq")]
    if sink_file:
        anchors += [(a["seq"], a["row_hash"], "sink") for a in read_raw_sink(sink_file) if a["org_id"] in (None, org)]
    breaks = []
    for seq, row_hash, label in anchors:
        if seq not in rows:
            breaks.append({"seq": seq, "reason": f"anchored_post_missing:{label}"})
        elif rows[seq] != row_hash:
            breaks.append({"seq": seq, "reason": f"anchored_post_changed:{label}"})
    return breaks
