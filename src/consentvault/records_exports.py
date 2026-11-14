"""The records list export worker and its one-use download links (records.md section 7).

``run_export_builds(now=None)`` is one pass over the exports still building: it builds each file, writes the
``records.export_built`` audit row and commits it, and only then stores the encrypted file. A file never reaches the
store before the audit row that accounts for it. When the audit row cannot be written the export fails with
``audit_unavailable`` and nothing is stored; when the store refuses after the audit row is committed the export fails with
``store_unavailable`` and its own ``records.export_store_failed`` audit row says so.

A download link is good for 15 minutes from the moment it is minted, by the clock the admin app was given, and for one
download. The signed token carries the ids; the ``record_export_link`` row says whether it was used. Production runs
``run_export_builds`` on a schedule as the records jobs login (``consentvault_records_jobs``, migration 0050); a test calls it. A process that builds exports itself (the job; a test) calls ``configure`` with its
worker, so a pass without an argument uses it.
"""

from __future__ import annotations

import base64
from .safelog import describe
from . import safelog
import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import psycopg

from . import testing
from .errors import ConsentVaultError
from .tenancy import audit, crypto as tc
from .tenancy.admin_base import ROLE_ADMIN, Actor, ApiError, Ctx
from .tenancy.errors import KeyProviderError
from .tenancy.keys_protocol import WrappedKey
from .tenancy.tokens import mint_org_token, org_transaction

LINK_TTL = timedelta(minutes=15)
FILE_KEPT = timedelta(hours=24)
BUILD_STEP = "records.export.build"
WORKER = "records-export-worker"
JOB = "records_exports"
GROUP = "consentvault_records_jobs"
_current: list = []
_log = safelog.get(__name__)


class ExportBuildError(ConsentVaultError):
    """An export build could not be carried through; the export is marked failed with a named cause."""


class ExportRunError(ConsentVaultError):
    """A pass could not finish one or more organizations; ``done`` exports were finished and ``failures`` is [(org_id, error)]."""

    def __init__(self, done: int, failures: list) -> None:
        self.done, self.failures = done, failures
        super().__init__(f"{len(failures)} organization(s) could not be built, {done} export(s) finished: "
                         + "; ".join(f"organization {o}: {c}" for o, c in failures))


class ExportKeyDestroyed(ConsentVaultError):
    """The export's data key has been destroyed; the stored file can no longer be opened."""


class ExportFinishLost(ExportBuildError):
    """The export was no longer building when its file was ready to be marked done (it was failed or finished by something
    else meanwhile). It is not reported done."""


class JobLoginRefused(ConsentVaultError):
    """The vault is multi-tenant and the login is not in the records jobs group: without a per-organization token it would
    see no rows and report a clean run having built nothing."""


class Worker:
    """What one pass needs: a connection factory for the records jobs login, the tenant crypto (display key, contact keys), the
    evidence store, and a clock (epoch seconds)."""

    def __init__(self, connect, crypto, store, clock) -> None:
        self.connect, self.crypto, self.store, self.clock = connect, crypto, store, clock


class JobDisplayKeyLoader:
    """Reads the wrapped display key under the token the database hands this login for the export job (the group's read scope
    admits it), so the worker needs no token-signing key of its own. Same shape as the server's loader, for ``CustodyKeyAdapter``."""

    def __init__(self, connect) -> None:
        self._connect = connect

    def __call__(self, org_id) -> bytes:
        org = uuid.UUID(str(org_id))
        try:
            conn = self._connect()
            try:
                token = conn.execute("SELECT consentvault.dispatch_org_token(%s, %s) AS t", (JOB, org)).fetchone()["t"]
                with org_transaction(conn, token):
                    row = conn.execute("SELECT wrapped FROM consentvault.org_display_key"
                                       " WHERE org_id = (SELECT consentvault.current_org())").fetchone()
            finally:
                conn.close()
        except psycopg.Error as exc:
            raise KeyProviderError(f"the display key of organisation {org} could not be read: {type(exc).__name__}") from exc
        if row is None:
            raise KeyProviderError(f"no wrapped display key is stored for organisation {org}")
        return bytes(row["wrapped"])


def _no_fingerprint_secret(org_id) -> bytes:
    raise KeyProviderError("the export worker holds no fingerprint secret and builds no fingerprints")


def worker_from_login(connect, custody, store, clock) -> Worker:
    """A worker whose crypto opens only what an export needs: the display key and contact keys, through the login ``connect``."""
    from .tenancy.crypto import TenantCrypto
    from .tenancy.keys_adapter import CustodyKeyAdapter

    return Worker(connect, TenantCrypto(CustodyKeyAdapter(custody, _no_fingerprint_secret, JobDisplayKeyLoader(connect))),
                  store, clock)


def configure(worker: Optional[Worker]) -> None:
    """The worker a pass without an argument runs (a process that builds exports itself: the job, or a test)."""
    _current[:] = [worker] if worker is not None else []


def configured() -> bool:
    return bool(_current)


def is_jobs_login(conn) -> bool:
    row = conn.execute("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = %s"
                       " AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')) AS member", (GROUP,)).fetchone()
    return bool(row["member"])


def require_jobs_login(conn) -> None:
    """Refuse (``JobLoginRefused``) unless this is a member of the records jobs group, the multi-tenant job login. The mode is
    read the way every login can: ``current_org()`` with no token names the home organisation in single mode, nothing in multi."""
    if is_jobs_login(conn):
        return
    who = conn.execute("SELECT current_user AS u").fetchone()["u"]
    raise JobLoginRefused(f"login {who} is not a member of {GROUP}: without a per-organization token it would see no rows and "
                          "report a clean run having built nothing. Run this job as the records jobs login", code='jobs_login_not_in_group')


def run_export_builds(now: Optional[float] = None, worker: Optional[Worker] = None) -> int:
    """One pass over the exports still building, one organization at a time under its own token; answers how many it finished
    (ready or failed). Every organization is attempted; one that breaks is named in ``ExportRunError`` after the rest ran. While
    the test step ``records.export.build`` is held it leaves them building and answers 0."""
    worker = worker or (_current[0] if _current else None)
    if worker is None:
        raise ExportBuildError("no export worker is configured to build records exports")
    if BUILD_STEP in testing.hold_steps:
        return 0
    stamp = worker.clock() if now is None else now
    conn = worker.connect()
    try:
        orgs = [r["o"] for r in conn.execute("SELECT o FROM consentvault.dispatch_org_ids(%s) o", (JOB,))]
    finally:
        conn.close()
    done, failures = 0, []
    for org in orgs:
        try:
            done += _build_org(worker, org, stamp)
        except (psycopg.Error, ConsentVaultError, KeyProviderError) as exc:  # loud-failure-exempt: collected and raised as ExportRunError after the rest ran
            failures.append((str(org), type(exc).__name__))
    if failures:
        raise ExportRunError(done, failures)
    return done


def delete_object(store, org, key: str) -> str:
    """Try to delete a stored file where the store allows it: 'deleted', 'retained' (the store keeps objects until their retention
    ends, so the destroyed key is the protection) or 'delete_failed' (logged at critical; the key is destroyed regardless)."""
    from .providers.errors import ProviderError

    delete = getattr(store, "delete", None)
    if delete is None:
        return "retained"
    try:
        delete(str(org), key)
    except ProviderError:  # loud-failure-exempt: logged at critical and recorded as delete_failed; the key is already destroyed
        _log.critical("a records export file could not be deleted from the store", store_key=key, exc_info=True)
        return "delete_failed"
    return "deleted"


def _destroy_expired(worker: Worker, org, now: float) -> None:
    """The 24 hours are up: mark the export expired and destroy its key; then try to delete each destroyed export's file once."""
    when = _stamp(now)

    def sweep(conn, token):
        conn.execute("UPDATE consentvault.record_export SET status = 'expired' WHERE org_id = (SELECT consentvault.current_org())"
                     " AND status = 'ready' AND expires_at <= %s", (when,))
        conn.execute("UPDATE consentvault.record_export_key k SET wrapped = NULL, destroyed_at = %s"
                     " FROM consentvault.record_export e WHERE k.org_id = e.org_id AND k.export_id = e.export_id"
                     " AND e.org_id = (SELECT consentvault.current_org()) AND e.status = 'expired' AND k.destroyed_at IS NULL",
                     (when,))
        return [r["export_id"] for r in conn.execute(
            "SELECT export_id FROM consentvault.record_export_key WHERE org_id = (SELECT consentvault.current_org())"
            " AND destroyed_at IS NOT NULL AND object_state IS NULL")]
    for export_id in _in_org(worker, org, sweep):
        state = delete_object(worker.store, org, f"records-exports/{export_id}")
        _in_org(worker, org, lambda conn, token, e=export_id, st=state: conn.execute(
            "UPDATE consentvault.record_export_key SET object_state = %s WHERE org_id = (SELECT consentvault.current_org())"
            " AND export_id = %s", (st, e)))


def _build_org(worker: Worker, org, now: float) -> int:
    """Build this organization's pending exports. One pass at a time per organization: a session advisory lock on a connection
    this pass holds for the whole build; a pass that finds it taken does nothing (the other is building)."""
    lock = worker.connect()
    try:
        key = f"records_exports:{org}"
        if not lock.execute("SELECT pg_try_advisory_lock(hashtext(%s)) AS got", (key,)).fetchone()["got"]:
            return 0
        try:
            _destroy_expired(worker, org, now)
            pending = _in_org(worker, org, lambda conn, token: [r["export_id"] for r in conn.execute(
                "SELECT export_id FROM consentvault.record_export WHERE org_id = (SELECT consentvault.current_org())"
                " AND status = 'building' ORDER BY created_at, export_id")])
            return sum(1 for export_id in pending if _build_one(worker, org, export_id, now))
        finally:
            lock.execute("SELECT pg_advisory_unlock(hashtext(%s))", (key,))
    finally:
        lock.close()


# ---- links --------------------------------------------------------------------------------------------------------------------------
class Links:
    """Signed one-use download links."""

    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    def token(self, org, export_id, link_id, expires_at: datetime) -> str:
        payload = f"{org}.{export_id}.{link_id}.{int(expires_at.timestamp() * 1000)}".encode()
        mac = hmac.new(b"records-export-link.v1:" + self._secret, payload, hashlib.sha256).hexdigest()
        return base64.urlsafe_b64encode(payload).decode().rstrip("=") + "." + mac

    def parse(self, token: Any) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
        try:
            body, mac = str(token).rsplit(".", 1)
            payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            org, export_id, link_id, _ = payload.decode().split(".")
            ids = (uuid.UUID(org), uuid.UUID(export_id), uuid.UUID(link_id))
        except (ValueError, AttributeError, UnicodeDecodeError):
            raise ApiError("export_link_invalid", "the download link is not valid") from None
        want = hmac.new(b"records-export-link.v1:" + self._secret, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, mac):
            raise ApiError("export_link_invalid", "the download link is not valid")
        return ids

    @staticmethod
    def url(export_id, token: str) -> str:
        return f"/v1/records/exports/{export_id}/download?link={token}"

    def mint(self, conn, org, export_id, minted_by: str, now: datetime) -> tuple[str, datetime]:
        link_id, exp = uuid.uuid4(), now + LINK_TTL
        conn.execute("INSERT INTO consentvault.record_export_link (org_id, link_id, export_id, minted_by, minted_at, expires_at)"
                     " VALUES (%s, %s, %s, %s, %s, %s)", (org, link_id, export_id, minted_by, now, exp))
        return self.url(export_id, self.token(org, export_id, link_id, exp)), exp

    def standing_url(self, ctx: Ctx, job: dict) -> Optional[str]:
        """The link a viewer of a ready export is given: the newest one that is unused and not expired; else, when the file has
        not been downloaded yet, a new one minted now (its 15 minutes start now); else None (use ``:link``)."""
        now = datetime.fromtimestamp(ctx.now(), tz=timezone.utc)
        row = ctx.conn.execute(
            "SELECT link_id, expires_at FROM consentvault.record_export_link WHERE org_id = (SELECT consentvault.current_org())"
            " AND export_id = %s AND used_at IS NULL AND expires_at > %s ORDER BY minted_at DESC LIMIT 1",
            (job["export_id"], now)).fetchone()
        if row is not None:
            return self.url(job["export_id"], self.token(job["org_id"], job["export_id"], row["link_id"], row["expires_at"]))
        if job["downloaded_at"] is not None:
            return None
        return self.mint(ctx.conn, job["org_id"], job["export_id"], ctx.actor.id, now)[0]


# ---- the build ----------------------------------------------------------------------------------------------------------------------
def _stamp(now: float) -> datetime:
    return datetime.fromtimestamp(now, tz=timezone.utc)


def _ctx(worker: Worker, conn, token: str, now: float, export_id) -> Ctx:
    return Ctx(conn, Actor("system", WORKER, ROLE_ADMIN), f"export-{export_id}", b"", None, lambda: now,
               crypto=worker.crypto, token=token, connect=worker.connect)


def _in_org(worker: Worker, org, fn):
    """Run ``fn(conn, token)`` in its own transaction inside the organization, under the token the database hands this login
    for the export job (committed when it returns)."""
    conn = worker.connect()
    try:
        token = conn.execute("SELECT consentvault.dispatch_org_token(%s, %s) AS t", (JOB, org)).fetchone()["t"]
        with org_transaction(conn, token):
            return fn(conn, token)
    finally:
        conn.close()


_MARK_FAILED = ("UPDATE consentvault.record_export SET status = 'failed', failed_cause = %s, completed_at = %s"
                " WHERE org_id = (SELECT consentvault.current_org()) AND export_id = %s AND status = 'building'")


def _fail(worker: Worker, org, export_id, cause: str, now: float, audit_action: Optional[str] = None) -> None:
    """Mark the export failed with a named cause (visible on the job row) and, when asked, write its own audit row."""
    def mark(conn, token):
        if audit_action:
            audit.append(conn, actor_kind="system", actor_id=WORKER, action=audit_action, target_kind="export",
                         target_id=str(export_id), reason=cause, request_id=f"export-{export_id}")
        conn.execute(_MARK_FAILED, (cause, _stamp(now), export_id))
    try:
        _in_org(worker, org, mark)
    except (audit.AuditError, psycopg.Error):  # loud-failure-exempt: the job is still marked failed on the next line; only its audit row is lost
        _in_org(worker, org, lambda conn, token: conn.execute(_MARK_FAILED, (cause, _stamp(now), export_id)))


def _build_one(worker: Worker, org, export_id, now: float) -> bool:
    from .providers.errors import EvidenceExistsError, ProviderError
    from .tenancy import records_admin as rec

    when = _stamp(now)

    def read(conn, token):
        job = conn.execute("SELECT * FROM consentvault.record_export WHERE org_id = (SELECT consentvault.current_org())"
                           " AND export_id = %s AND status = 'building'", (export_id,)).fetchone()
        if job is None:
            return None
        # the same lock an erasure takes: either the erasure came first and this build reads the record as erased, or this build is
        # recorded (key and membership) before the erasure looks for the exports that hold the record
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"records_export_shred:{org}",))
        ctx = _ctx(worker, conn, token, now, export_id)
        where, params, echo = rec.build_filters(ctx, job["filters"] or {}, rec.FILTER_KEYS)
        rows = conn.execute(rec._select(ROLE_ADMIN, "r.first_recorded_at") + " WHERE " + " AND ".join(where)
                            + " ORDER BY r.first_recorded_at, r.record_id", params).fetchall()
        name = conn.execute("SELECT name FROM consentvault.organization WHERE org_id = (SELECT consentvault.current_org())"
                            ).fetchone()["name"]
        data, sha, ids = rec._build_file(ctx, rows, job["contact_form"], job["include_person"], echo, export_id,
                                         job["requested_by"], name, when)
        key = worker.crypto.new_contact_key(org)  # this export's own data key, wrapped by the organization key
        blob = tc.encrypt_field(key.data_key, org, str(export_id), "records_export", data)
        conn.execute("INSERT INTO consentvault.record_export_key (org_id, export_id, wrapped, key_version)"
                     " VALUES ((SELECT consentvault.current_org()), %s, %s, %s)",
                     (export_id, key.wrapped.ciphertext, key.wrapped.key_version))
        with conn.cursor() as cur:
            cur.executemany("INSERT INTO consentvault.record_export_record (org_id, export_id, record_id)"
                            " VALUES ((SELECT consentvault.current_org()), %s, %s)", [(export_id, i) for i in ids])
        return job, sha, ids, blob

    try:
        built = _in_org(worker, org, read)
    except (KeyProviderError, ApiError, psycopg.Error, ConsentVaultError) as exc:  # loud-failure-exempt: the export is marked failed with this cause
        _fail(worker, org, export_id, "build_failed:" + type(exc).__name__, now)
        return True
    if built is None:
        return False
    job, sha, ids, blob = built
    listed = ({"record_ids": [str(i) for i in ids]}
              if job["contact_form"] == "full" or (job["contact_form"] == "masked" and job["include_person"])
              else {"count": len(ids)})

    def note(conn, token):  # committed on exit: the audit row stands before the file is stored
        audit.append(conn, actor_kind="system", actor_id=WORKER, action="records.export_built", target_kind="export",
                     target_id=str(export_id), request_id=f"export-{export_id}", detail=listed)
    try:
        _in_org(worker, org, note)
    except (audit.AuditError, psycopg.Error):  # loud-failure-exempt: the export is marked failed with audit_unavailable and nothing is stored
        _fail(worker, org, export_id, "audit_unavailable", now)
        return True
    try:
        worker.store.put(str(org), f"records-exports/{export_id}", blob, retain_until=when + FILE_KEPT)
    except EvidenceExistsError:  # loud-failure-exempt: failed with its own audit row, records.export_store_failed
        _fail(worker, org, export_id, "file_already_stored", now, "records.export_store_failed")
        return True
    except ProviderError:  # loud-failure-exempt: failed with its own audit row, records.export_store_failed
        _fail(worker, org, export_id, "store_unavailable", now, "records.export_store_failed")
        return True

    def finish(conn, token):
        done = conn.execute("UPDATE consentvault.record_export SET status = 'ready', row_count = %s, progress_done = %s, sha256 = %s,"
                     " completed_at = %s, expires_at = %s WHERE org_id = (SELECT consentvault.current_org())"
                     " AND export_id = %s AND status = 'building'", (len(ids), len(ids), sha, when, when + FILE_KEPT, export_id))
        if done.rowcount != 1:
            raise ExportFinishLost(f"export {export_id} was no longer building when its file was stored; it is not marked done")
    _in_org(worker, org, finish)
    return True


# ---- the download -------------------------------------------------------------------------------------------------------------------
def download(app, token: Any, now: float, path_export_id: Any = None) -> tuple[bytes, dict]:
    """Serve one file for a link, once. The link is marked used, the download audited and the file opened in one transaction:
    a file that cannot be opened leaves the link unused."""
    from .tenancy import records_admin as rec

    if not token:
        raise ApiError("unauthenticated", "a download link is required")
    org, export_id, link_id = app._links.parse(token)
    if path_export_id is not None and str(path_export_id) != str(export_id):
        raise ApiError("not_found", "no such export")  # the link is for another export; it is not used
    when = _stamp(now)
    t = mint_org_token(app._key, org, ["proof_read"], credential_id=None, ttl_seconds=120)
    conn = app._connect()
    try:
        with org_transaction(conn, t):
            link = conn.execute("SELECT * FROM consentvault.record_export_link WHERE org_id = (SELECT consentvault.current_org())"
                                " AND link_id = %s AND export_id = %s FOR UPDATE", (link_id, export_id)).fetchone()
            if link is None:
                raise ApiError("export_link_invalid", "the download link is not valid")
            if link["revoked_at"] is not None:
                raise ApiError("export_expired", "the file is no longer kept; request a new export")
            if link["used_at"] is not None:
                raise ApiError("export_link_used", "This download link was already used. Ask for a new link; the file is kept 24 hours.")
            if link["expires_at"] <= when:
                raise ApiError("export_link_expired", "This download link expired after 15 minutes. Ask for a new link; the file is kept 24 hours.")
            job = conn.execute("SELECT * FROM consentvault.record_export WHERE org_id = (SELECT consentvault.current_org())"
                               " AND export_id = %s", (export_id,)).fetchone()
            if job is None or rec.effective_status(job, when) != "ready":
                raise ApiError("export_expired", "the file is no longer kept; request a new export")
            ctx = Ctx(conn, Actor("member", link["minted_by"], ROLE_ADMIN), f"export-dl-{link_id}", app._cursor_key, app._custody,
                      lambda: now, crypto=app.crypto, token=t, connect=app._connect)
            rec.audited(ctx, "records.export_downloaded", "export", str(export_id), None, None)
            try:
                held = conn.execute("SELECT wrapped, key_version FROM consentvault.record_export_key WHERE org_id ="
                                    " (SELECT consentvault.current_org()) AND export_id = %s", (export_id,)).fetchone()
                if held is None or held["wrapped"] is None:
                    raise ExportKeyDestroyed(f"the key of export {export_id} is destroyed")
                dk = app.crypto.open_contact_key(org, WrappedKey(bytes(held["wrapped"]), held["key_version"]))
                blob = app.evidence_store.get(str(org), f"records-exports/{export_id}")
                data = tc.decrypt_field(dk, org, str(export_id), "records_export", blob)
            except ExportKeyDestroyed as exc:
                raise ApiError("export_expired", "the file is no longer kept; request a new export") from exc
            except Exception as exc:  # loud-failure-exempt: re-raised below as a named refusal
                raise ApiError("service_unavailable", "the file could not be read; the link is still unused") from exc
            conn.execute("UPDATE consentvault.record_export_link SET used_at = %s WHERE org_id = (SELECT consentvault.current_org())"
                         " AND link_id = %s", (when, link_id))
            conn.execute("UPDATE consentvault.record_export SET downloaded_at = coalesce(downloaded_at, %s)"
                         " WHERE org_id = (SELECT consentvault.current_org()) AND export_id = %s", (when, export_id))
    finally:
        conn.close()
    return data, {"Content-Type": "application/zip", "Cache-Control": "no-store",
                  "Content-Disposition": f'attachment; filename="records-{str(export_id)[:8]}.zip"'}


def main(argv=None, env=None) -> int:
    """``python -m consentvault.records_exports``: one pass of the export worker as the records jobs login (``CONSENTVAULT_DSN``).
    Prints how many exports it finished. Exit 3 when the login is not in the records jobs group in multi-tenant mode; exit 2
    naming the first thing missing or each organization it could not finish."""
    from . import safelog as _safelog
    _safelog.setup_process()  # the scrub filter on every handler, warnings, and the exception hooks
    import os
    import sys

    from . import cmd_cloud, db, dbclock
    from .cli import EXIT_BROKEN, EXIT_ERROR, EXIT_OK
    from .config import load_config
    from .errors import ConfigError
    from .providers.plugins import load_key_provider

    env = os.environ if env is None else env
    try:
        cfg = load_config(env=env)
        with db.connect(cfg.require_dsn()) as conn:
            if conn.execute("SELECT consentvault.current_org() AS o").fetchone()["o"] is not None:
                print("consentvault.records_exports: single-company mode has no organizations to build exports for; nothing was run")
                return EXIT_OK
            require_jobs_login(conn)
        store = cmd_cloud.evidence_store_only(cfg, env)  # the evidence bucket only: no archive or ledger bucket is read
        connect = lambda: db.connect(cfg.require_dsn())  # noqa: E731
        worker = worker_from_login(connect, load_key_provider(cfg.key_provider, env=env), store,
                                   dbclock.epoch_clock(connect))   # the export link expiry is judged on the database's clock
        print(f"records exports finished: {run_export_builds(worker=worker)}")
    except JobLoginRefused as exc:
        print(f"consentvault.records_exports: {describe(exc)}", file=sys.stderr)
        return EXIT_BROKEN
    except (ConfigError, ConsentVaultError) as exc:
        print(f"consentvault.records_exports: {describe(exc)}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
