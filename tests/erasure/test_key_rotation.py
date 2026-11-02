"""Per-tenant key rotation: a new org key version wraps new contact keys, the job re-wraps every existing key in
resumable batches, the old version is destroyed only once nothing is wrapped under it and never while a hold stands,
reads and chain verification hold throughout, and one organisation's rotation never touches another's keys."""

import json
import uuid
from datetime import datetime, timedelta

import psycopg
import pytest

from consentvault import db
from consentvault.ledger import record_tenant_event, verify_chain
from consentvault.providers.errors import KeyProviderError as CustodyKeyError
from consentvault.route_wiring import OperatorDecision
from consentvault.tenancy import admin, holds, key_rotation as kr
from consentvault.tenancy import crypto as tc
from consentvault.tenancy.admin_base import ApiError
from consentvault.tenancy.crypto import TenantCrypto
from consentvault.tenancy.erasure import LEDGER_RETAIN_DAYS, LifecycleLedger
from consentvault.tenancy.keys_adapter import CustodyKeyAdapter
from consentvault.tenancy.keys_protocol import WrappedKey
from consentvault.tenancy.lifecycle_routes import LifecycleApp, LifecycleRoutes
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from .support import OPERATOR

PHONES = [f"+1415555{n:04d}" for n in range(7)]


class Rot:
    def __init__(self, env):
        self.env, self.t = env, env.t
        self.crypto = TenantCrypto(CustodyKeyAdapter.from_database(env.custody, self.t.operator, self.t.key),
                                   cache_seconds=0)
        self.c = self._org("charlie")
        self.d = self._org("delta")

    def _org(self, name):
        with self.env.operator() as c:
            out = admin.create_org(c, token_key=self.t.key, custody=self.env.custody, operator_id=OPERATOR,
                                   request_id="req-create", name=name, admin_email=f"admin@{name}.example.com")
        org = uuid.UUID(out["org_id"])
        for phone in PHONES:
            self.write(org, phone)
        return org

    def write(self, org, phone):
        with self.t.app() as app, org_transaction(app, mint_org_token(self.t.key, org, ["capture", "gate_read"],
                                                                      credential_id=None)):
            return record_tenant_event(app, self.crypto, contact=phone, event_type="revoke", channels=["sms"],
                                       purposes=["marketing"], method="keyword", origin="consumer")

    def start(self, org, reason="annual rotation"):
        with self.env.operator() as c:
            return kr.start_rotation(c, token_key=self.t.key, custody=self.env.custody, operator_id=OPERATOR,
                                     request_id="req-rot", org_id=org, reason=reason)

    def run(self, org, **kw):
        kw.setdefault("batch_size", 3)
        kw.setdefault("ledger", self.env.ledger)
        with self.env.operator() as c:
            return kr.run_rotation(c, token_key=self.t.key, custody=self.env.custody, crypto=self.crypto,
                                   operator_id=OPERATOR, request_id="req-job", org_id=org, **kw)

    def sql(self, q, *args):
        with self.t.superuser() as su:
            return su.execute(q, args).fetchall()

    def versions(self, org):
        return sorted(r["key_version"] for r in self.sql(
            "SELECT key_version FROM consentvault.contact_key WHERE org_id = %s", org))

    def read_all(self, org):
        """Every contact's plaintext, read the way the vault reads it: open the contact key, decrypt the event."""
        out = []
        with self.t.app() as app, org_transaction(app, mint_org_token(self.t.key, org, ["gate_read"],
                                                                      credential_id=None)):
            for e in app.execute("SELECT e.event_id, e.contact_ct, k.wrapped_key, k.key_version FROM consentvault.event e"
                                 " JOIN consentvault.contact_key k ON k.org_id = e.org_id AND k.contact_fp = e.contact_fp"
                                 " ORDER BY e.seq").fetchall():
                dk = self.crypto.open_contact_key(org, WrappedKey(bytes(e["wrapped_key"]), e["key_version"]))
                out.append(tc.decrypt_text(dk, org, str(e["event_id"]), "contact_norm", e["contact_ct"]))
        return out

    def chain(self, org):
        with self.t.app() as app, org_transaction(app, mint_org_token(self.t.key, org, ["gate_read"],
                                                                      credential_id=None)):
            return verify_chain(app, crypto=self.crypto)

    def hashes(self, org):
        return [(r["seq"], r["row_hash"], r["key_version"]) for r in self.sql(
            "SELECT seq, row_hash, key_version FROM consentvault.event WHERE org_id = %s ORDER BY seq", org)]

    def actions(self, org):
        return [r["action"] for r in self.sql(
            "SELECT action FROM consentvault.audit_event WHERE org_id = %s ORDER BY seq", org)]


@pytest.fixture
def rot(env):
    return Rot(env)


def test_rotation_rewraps_every_key_in_batches_while_reads_and_the_chain_hold(rot):
    org = rot.c
    before, plain = rot.hashes(org), rot.read_all(org)
    assert plain == PHONES and rot.versions(org) == [1] * 7
    started = rot.start(org)
    assert (started["from_version"], started["to_version"], started["status"]) == (1, 2, "rewrapping")
    assert rot.env.custody.active_version(str(org)) == 2
    fresh = rot.write(org, "+14155559999")  # a contact first seen during the rotation wraps under the new version
    assert rot.versions(org).count(2) == 1
    plain.append("+14155559999")

    one = rot.run(org, max_batches=1)
    assert one["status"] == "rewrapping" and one["rewrapped"] == 3 and one["remaining"] == 4
    assert sorted(rot.versions(org)) == [1] * 4 + [2] * 4
    assert rot.read_all(org) == plain and rot.chain(org) == []  # mid-rotation: every key opens, the chain verifies

    done = rot.run(org, backup_retention_days=0)  # a deployment keeping no backups (the backup hold: wave 3 final)
    assert done["status"] == "complete" and done["rewrapped"] == 7 and done["remaining"] == 0
    assert done["old_version_destroyed"] is True
    assert rot.versions(org) == [2] * 8
    assert rot.env.custody.versions(str(org)) == {1: "destroyed", 2: "active"}
    assert {(r["version"], r["status"]) for r in rot.sql(
        "SELECT version, status FROM consentvault.org_key WHERE org_id = %s", org)} == {(1, "destroyed"), (2, "active")}
    assert rot.read_all(org) == plain and rot.chain(org) == []
    assert rot.hashes(org)[:len(before)] == before  # history is never re-chained or re-signed
    assert rot.hashes(org)[-1][0] == fresh.seq
    rot.crypto.forget()  # the fingerprint secret was re-wrapped too: stop matching still finds the same person
    assert rot.crypto.contact_fingerprint(org, "phone", PHONES[0]) == rot.sql(
        "SELECT contact_fp FROM consentvault.event WHERE org_id = %s ORDER BY seq LIMIT 1", org)[0]["contact_fp"]
    acts = rot.actions(org)
    assert "org_key.rotation_started" in acts and "org_key.version_destroyed" in acts
    assert acts.count("org_key.rewrapped") >= 3


def test_the_job_is_resumable_and_idempotent(rot):
    org = rot.c
    rot.start(org)
    rot.run(org, max_batches=1)
    rot.run(org, max_batches=1)  # a second pass resumes where the first stopped; nothing is counted twice
    done = rot.run(org)
    assert done["status"] == "complete" and done["rewrapped"] == 7
    assert rot.run(org) is None  # nothing open: the job is a no-op
    assert rot.versions(org) == [2] * 7 and rot.read_all(org) == PHONES
    with rot.env.operator() as c, org_transaction(c, mint_org_token(rot.t.key, org, ["admin"], credential_id=None)):
        # a re-wrap replayed against a key already moved is a no-op, never a second change
        fp = c.execute("SELECT contact_fp, wrapped_key FROM consentvault.contact_key LIMIT 1").fetchone()
        assert c.execute("SELECT consentvault.rewrap_contact_key(%s, 1, %s, 2) AS ok",
                         (fp["contact_fp"], b"x" * 60)).fetchone()["ok"] is False


def test_a_second_rotation_while_one_is_open_is_refused_by_name(rot):
    rot.start(rot.c)
    with pytest.raises(ApiError) as e:
        rot.start(rot.c)
    assert e.value.name == "rotation_in_progress"


def test_a_hold_blocks_destroying_the_old_version_and_the_block_is_visible(rot):
    org = rot.c
    with rot.env.operator() as c:
        hold = holds.place_hold_operator(c, token_key=rot.t.key, ledger=rot.env.ledger, custody=rot.env.custody,
                                         operator_id=OPERATOR, request_id="req-hold", org_id=org, scope="org",
                                         reason="litigation", contacts=(), crypto=rot.crypto, region=None)
    rot.start(org)
    out = rot.run(org)
    assert out["status"] == "blocked" and out["blocked_reason"] == f"legal_hold_active:{hold['hold_id']}"
    assert out["remaining"] == 0 and out["old_version_destroyed"] is False
    assert rot.env.custody.versions(str(org)) == {1: "retired", 2: "active"}
    assert rot.sql("SELECT status FROM consentvault.org_key WHERE org_id = %s AND version = 1", org)[0]["status"] == "retired"
    assert rot.sql("SELECT name FROM consentvault.operator_alarm WHERE org_id = %s", org)[0]["name"] == kr.ALARM_BLOCKED
    assert "org_key.rotation_blocked" in rot.actions(org)
    assert rot.read_all(org) == PHONES
    with rot.env.operator() as c:
        holds.release_hold_operator(c, token_key=rot.t.key, ledger=rot.env.ledger, custody=rot.env.custody,
                                    operator_id=OPERATOR, request_id="req-rel", org_id=org, hold_id=hold["hold_id"],
                                    reason="matter closed", crypto=rot.crypto)
    done = rot.run(org)
    assert done["status"] == "complete" and done["old_version"] == "retained_for_ledger"
    with rot.env.operator() as c:  # the hold's sealed reason was re-wrapped and still opens under the new version
        with org_transaction(c, mint_org_token(rot.t.key, org, ["admin"], credential_id=None)):
            row = c.execute("SELECT reason FROM consentvault.legal_hold WHERE hold_id = %s", (hold["hold_id"],)).fetchone()
        assert holds.open_reason(rot.crypto, org, hold["hold_id"], "legal_hold.reason", row["reason"]) == "litigation"


def test_a_failing_key_service_blocks_the_rotation_by_name_and_raises_an_alarm(rot, monkeypatch):
    org = rot.c
    rot.start(org)
    real = rot.env.custody.wrap

    def broken(org_id, data_key):
        raise CustodyKeyError("key service unreachable")

    monkeypatch.setattr(rot.env.custody, "wrap", broken)
    with pytest.raises(kr.KeyRotationError, match=rf"{org}.*rewrap_failed.*KeyProviderError") as blocked:  # the org id stays
        rot.run(org)
    assert "key service unreachable" not in str(blocked.value)  # the key service's own text never travels
    assert blocked.value.org_ids == (str(org),)  # the organisation travels as a field, so a report never searches the text
    state = kr.get_rotation_state(rot.env.operator, rot.t.key, org)
    assert state["status"] == "blocked" and state["blocked_reason"].startswith("rewrap_failed:")
    assert rot.sql("SELECT name, error_class FROM consentvault.operator_alarm WHERE org_id = %s", org)[0] == {
        "name": kr.ALARM_FAILED, "error_class": "KeyRotationError"}
    assert rot.read_all(org) == PHONES  # nothing half-written: every key still opens
    monkeypatch.setattr(rot.env.custody, "wrap", real)
    assert rot.run(org)["status"] == "complete" and rot.read_all(org) == PHONES


def test_one_organisations_rotation_never_touches_another(rot):
    c, d = rot.c, rot.d
    rot.start(c)
    rot.run(c)
    assert rot.versions(d) == [1] * 7 and rot.env.custody.versions(str(d)) == {1: "active"}
    assert rot.read_all(d) == PHONES and rot.chain(d) == []
    assert rot.run(d) is None  # D has no rotation of its own
    c_key = rot.sql("SELECT contact_fp, wrapped_key FROM consentvault.contact_key WHERE org_id = %s LIMIT 1", c)[0]
    with pytest.raises(CustodyKeyError):  # C's re-wrapped key never opens under D's org key
        rot.env.custody.unwrap(str(d), bytes(c_key["wrapped_key"]))
    rot.start(d)
    with rot.env.operator() as conn, org_transaction(conn, mint_org_token(rot.t.key, d, ["admin"], credential_id=None)):
        assert conn.execute("SELECT count(*) AS n FROM consentvault.key_rotation").fetchone()["n"] == 1  # D's own only
        # entered as D, a re-wrap naming C's contact touches nothing: the swap is bound to the entered organisation
        assert conn.execute("SELECT consentvault.rewrap_contact_key(%s, 1, %s, 2) AS ok",
                            (c_key["contact_fp"], bytes(c_key["wrapped_key"]))).fetchone()["ok"] is False
    assert rot.sql("SELECT wrapped_key FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s", c,
                   c_key["contact_fp"])[0]["wrapped_key"] == c_key["wrapped_key"]
    with pytest.raises(ApiError) as e:
        kr.get_rotation(rot.env.operator, rot.t.key, d, rot.sql(
            "SELECT rotation_id FROM consentvault.key_rotation WHERE org_id = %s", c)[0]["rotation_id"])
    assert e.value.name == "not_found"


def test_a_contact_key_changes_only_through_the_rewrap_function(rot):
    org = rot.c
    with rot.t.migrator() as m, org_transaction(m, mint_org_token(rot.t.key, org, ["admin"], credential_id=None)):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="re-wrap"):
            m.execute("UPDATE consentvault.contact_key SET key_version = key_version")
    with rot.t.superuser() as su:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            su.execute("UPDATE consentvault.org_fingerprint_secret SET wrapped = wrapped || '\\x00'::bytea")
    rot.start(org)
    with rot.env.operator() as c, org_transaction(c, mint_org_token(rot.t.key, org, ["admin"], credential_id=None)):
        fp = c.execute("SELECT contact_fp FROM consentvault.contact_key LIMIT 1").fetchone()["contact_fp"]
        with pytest.raises(psycopg.errors.RaiseException, match="active"):  # only to the active version
            c.execute("SELECT consentvault.rewrap_contact_key(%s, 1, %s, 1)", (fp, b"x" * 60))
    with rot.t.app() as app, org_transaction(app, mint_org_token(rot.t.key, org, ["capture"], credential_id=None)):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT consentvault.rewrap_contact_key(%s, 1, %s, 2)", (fp, b"x" * 60))


def test_the_database_refuses_to_destroy_a_version_that_still_wraps_a_key(rot):
    org = rot.c
    rot.start(org)
    rot.run(org, max_batches=1)
    with rot.env.operator() as c, org_transaction(c, mint_org_token(rot.t.key, org, ["admin"], credential_id=None)):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="key_version_in_use"):
            c.execute("UPDATE consentvault.org_key SET status = 'destroyed' WHERE version = 1")
    rot.run(org, backup_retention_days=0)
    with rot.t.migrator() as c, org_transaction(c, mint_org_token(rot.t.key, org, ["admin"], credential_id=None)):
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="destroyed"):
            c.execute("INSERT INTO consentvault.contact_key (org_id, contact_fp, wrapped_key, key_version, salt_ct)"
                      " VALUES ((SELECT consentvault.current_org()), %s, %s, 1, %s)", ("ab" * 32, b"w" * 60, b"s"))


class _Auth:
    def operator_decision(self, headers):
        return OperatorDecision(OPERATOR, "verified", "issuer|op")


def test_the_operator_route_starts_a_rotation_and_reports_its_state(rot):
    t, env = rot.t, rot.env
    app = LifecycleApp(connect=lambda: db.connect(t.app_dsn), owner_connect=lambda: db.connect(t.operator_dsn),
                       token_key=t.key, crypto=rot.crypto, custody=env.custody, ledger=env.ledger, store=env.archive,
                       signer=env.signer, notifier=env.notifier)
    routes = LifecycleRoutes(app, _Auth())
    h = {"X-Request-Id": "req-route", "Authorization": "Bearer op-token"}
    path = f"/v1/orgs/{rot.c}/key-rotations"
    assert routes.handles("POST", path)
    r = routes.handle("POST", path, body=json.dumps({"reason": "annual rotation"}).encode(), headers=h)
    assert r.status == 202 and r.payload["status"] == "rewrapping" and r.payload["to_version"] == 2
    again = routes.handle("POST", path, body=json.dumps({"reason": "again"}).encode(), headers=h)
    assert (again.status, again.payload["error"]) == (409, "rotation_in_progress")
    rot.run(rot.c)
    got = routes.handle("GET", f"{path}/{r.payload['rotation_id']}", headers=h)
    assert got.status == 200 and got.payload["status"] == "complete" and got.payload["old_version_destroyed"] is False
    assert got.payload["old_version"] == "retained_for_backup" and got.payload["old_version_destroy_after"] is not None
    other = routes.handle("GET", f"/v1/orgs/{rot.d}/key-rotations/{r.payload['rotation_id']}", headers=h)
    assert other.status == 404


def test_the_operator_job_runs_every_open_rotation(rot):
    rot.start(rot.c)
    rot.start(rot.d)
    out = kr.run_rotation_job(rot.env.operator, token_key=rot.t.key, custody=rot.env.custody, crypto=rot.crypto,
                              ledger=rot.env.ledger, request_id="req-job", batch_size=2)
    assert {o["org_id"]: o["status"] for o in out} == {str(rot.c): "complete", str(rot.d): "complete"}
    assert rot.versions(rot.c) == [2] * 7 and rot.versions(rot.d) == [2] * 7


def _ledger_reason(rot, org, hold_id):
    [entry] = [e for e in rot.env.ledger.entries(org) if e["kind"] == "hold_set" and e["hold_id"] == str(hold_id)]
    return entry


def test_a_version_sealing_a_ledger_entry_is_retained_until_that_entry_s_retention_ends(rot):
    org = rot.c
    with rot.env.operator() as c:
        hold = holds.place_hold_operator(c, token_key=rot.t.key, ledger=rot.env.ledger, custody=rot.env.custody,
                                         operator_id=OPERATOR, request_id="req-hold", org_id=org, scope="org",
                                         reason="litigation", contacts=(), crypto=rot.crypto, region=None)
        holds.release_hold_operator(c, token_key=rot.t.key, ledger=rot.env.ledger, custody=rot.env.custody,
                                    operator_id=OPERATOR, request_id="req-rel", org_id=org, hold_id=hold["hold_id"],
                                    reason="matter closed", crypto=rot.crypto)
    entry = _ledger_reason(rot, org, hold["hold_id"])
    last = max(datetime.fromisoformat(e["at"]) for e in rot.env.ledger.entries(org)
               if e.get("hold_id") == str(hold["hold_id"]))  # set and release: both sealed under version 1
    rot.start(org)
    done = rot.run(org)
    assert done["status"] == "complete" and done["remaining"] == 0 and done["remaining_other"] == 0
    assert done["old_version"] == "retained_for_ledger" and done["old_version_destroyed"] is False
    until = last + timedelta(days=LEDGER_RETAIN_DAYS)
    assert datetime.fromisoformat(done["old_version_destroy_after"]) == until
    assert rot.env.custody.versions(str(org)) == {1: "retired", 2: "active"}
    assert rot.sql("SELECT status, destroy_after FROM consentvault.org_key WHERE org_id = %s AND version = 1", org)[0] == {
        "status": "retained_for_ledger", "destroy_after": until}
    assert "org_key.version_retained" in rot.actions(org)
    # the write-once ledger copy of the reason, sealed under the old version, still opens
    assert holds.open_reason(rot.crypto, org, hold["hold_id"], "legal_hold.reason", entry["reason"]) == "litigation"
    rot.start(org, reason="the next rotation does not wait on the retention")  # 2 -> 3 while 1 is still retained
    assert rot.env.custody.active_version(str(org)) == 3

    def job(now):
        return kr.run_rotation_job(rot.env.operator, token_key=rot.t.key, custody=rot.env.custody, crypto=rot.crypto,
                                   ledger=LifecycleLedger(rot.env.archive, clock=lambda: now), request_id="req-job",
                                   backup_retention_days=0)  # the ledger's retention alone (backups: wave 3 final)

    job(until - timedelta(seconds=1))  # still inside the entry's retention: version 1 stays
    assert rot.env.custody.versions(str(org))[1] == "retired"
    assert rot.sql("SELECT status FROM consentvault.org_key WHERE org_id = %s AND version = 1", org)[0]["status"] \
        == "retained_for_ledger"
    job(until + timedelta(seconds=1))  # retention over: version 1 is destroyed, the ledger copy no longer opens
    assert rot.env.custody.versions(str(org)) == {1: "destroyed", 2: "destroyed", 3: "active"}
    assert {r["version"]: r["status"] for r in rot.sql(
        "SELECT version, status FROM consentvault.org_key WHERE org_id = %s", org)} == {
        1: "destroyed", 2: "destroyed", 3: "active"}
    with pytest.raises(Exception):
        holds.open_reason(rot.crypto, org, hold["hold_id"], "legal_hold.reason", entry["reason"])
    assert rot.actions(org).count("org_key.version_destroyed") == 2
    assert rot.read_all(org) == PHONES and rot.chain(org) == []


def test_a_hold_that_cancels_an_offboarding_returns_only_the_versions_offboarding_scheduled(env):
    from .test_offboard import _run

    t = env.t
    org = t.a.org_id
    with t.migrator() as m, org_transaction(m, t.admin_token(org)):  # a rotation retired 1 and holds 2 for the ledger
        m.execute("INSERT INTO consentvault.org_key (org_id, version, kms_key_ref) VALUES (%s, 2, 'k2'), (%s, 3, 'k3')",
                  (org, org))
        m.execute("UPDATE consentvault.org_key SET status = 'retired' WHERE org_id = %s AND version = 1", (org,))
        m.execute("UPDATE consentvault.org_key SET status = 'retained_for_ledger', destroy_after = '2036-01-01Z'"
                  " WHERE org_id = %s AND version = 2", (org,))
    before = {r["version"]: (r["status"], r["destroy_after"]) for r in _keys(env, org)}
    out = _run(env, t.a)
    assert out["steps"]["key_destruction"]["status"] == "scheduled"
    assert {r["status"] for r in _keys(env, org)} == {"scheduled_destroy"}  # offboarding schedules every version
    with env.operator() as c:
        hold = holds.place_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto,
                                         operator_id=OPERATOR, request_id="req-h", org_id=org, scope="org",
                                         reason="subpoena preservation")
    assert hold["destruction_cancelled"] is True
    assert {r["version"]: (r["status"], r["destroy_after"]) for r in _keys(env, org)} == before
    assert before[1][0] == "retired" and before[2][0] == "retained_for_ledger" and before[3][0] == "active"


def _keys(env, org):
    with env.t.superuser() as su:
        return su.execute("SELECT version, status, destroy_after FROM consentvault.org_key WHERE org_id = %s"
                          " ORDER BY version", (org,)).fetchall()


def test_rotation_rewraps_the_sending_account_secrets_and_leaves_none_on_the_old_key(rot):
    """confirmations.md section 13 (stored secrets): the provider secret and the auth token are wrapped by the organization key,
    so the census counts them and the rotation moves them; the old version is destroyed only when none is left on it."""
    from consentvault.providers.keys import wrapped_version

    org, custody = rot.c, rot.env.custody
    first, second = b"s" * 20, b"t" * 32
    with rot.t.superuser() as su:
        su.execute(
            "INSERT INTO consentvault.sending_account (org_id, account_id, channel, provider, inbound_key, inbound_url,"
            " provider_replies, credentials_ct, credential_ids_ct, auth_token_ct) VALUES (%s, gen_random_uuid(), 'sms', 'twilio',"
            " %s, 'u', '{\"stop\": false, \"help\": false, \"start\": false}'::jsonb, %s, %s, %s)",
            (org, "k" * 40, custody.wrap(str(org), first), b"ids", custody.wrap(str(org), second)))
    started = rot.start(org)
    assert started["remaining_other"] >= 2  # the census counts both blobs
    done = rot.run(org, backup_retention_days=0)
    assert done["status"] == "complete" and done["old_version_destroyed"] is True
    (row,) = rot.sql("SELECT credentials_ct, auth_token_ct FROM consentvault.sending_account WHERE org_id = %s", org)
    assert wrapped_version(bytes(row["credentials_ct"])) == 2 and wrapped_version(bytes(row["auth_token_ct"])) == 2
    assert custody.unwrap(str(org), bytes(row["credentials_ct"])) == first
    assert custody.unwrap(str(org), bytes(row["auth_token_ct"])) == second
