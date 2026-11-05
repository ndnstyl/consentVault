"""Erasure of one person and legal holds: the key goes, the fingerprint and the stop stay, a hold refuses or queues,
the ledger is written before anything is deleted, and queued work resumes on release."""

import psycopg
import pytest

from consentvault import db, dbclock
from consentvault.evidence import contact_has_records
from consentvault.providers.errors import EvidenceStoreError
from consentvault.tenancy import erasure, holds
from consentvault.tenancy.admin_base import ApiError
from consentvault.tenancy.erasure import LedgerUnavailableError, LifecycleLedger
from consentvault.tenancy.tokens import org_transaction

from isolation.cloud_harness import Cloud
from isolation.harness import PHONE

from .support import OPERATOR


def _request(env, org, contact=PHONE):
    with env.admin(org) as ctx:
        return erasure.request_erasure(ctx, {"contact": contact, "reason": "the person asked"}, crypto=env.t.crypto)


def _confirm(env, org, eid, **kw):
    with env.operator() as c:
        return erasure.confirm_erasure(c, token_key=env.t.key, crypto=env.t.crypto, ledger=env.ledger, operator_id=OPERATOR,
                                       request_id="req-op", org_id=org.org_id, erasure_id=eid, **kw)


def _hold(env, org, scope="contacts", contacts=(PHONE,)):
    with env.admin(org) as ctx:
        body = {"scope": scope, "reason": "litigation preservation"}
        if scope == "contacts":
            body["contacts"] = list(contacts)
        return holds.place_hold_member(ctx, body, ledger=env.ledger, crypto=env.t.crypto)


def test_erasure_deletes_the_key_and_the_fingerprint_still_matches_its_stop(env, tmp_path):
    t = env.t
    cloud = Cloud(t, str(tmp_path / "evidence"))
    try:
        before = cloud.gate(cloud.a, PHONE)
        assert before[0] == 200 and len(before[1]["stops"]) == 1 and before[1]["lifts"] == [], before
        req = _request(env, t.a)
        assert req["status"] == "pending_operator_confirmation"
        assert env.key_present(t.a)  # nothing is deleted before an operator confirms
        out = _confirm(env, t.a, req["erasure_id"])
        assert out["status"] == "completed" and out["key_deleted"] is True
        assert not env.key_present(t.a) and env.key_present(t.b)  # only this organisation's contact
        after = cloud.gate(cloud.a, PHONE)
        assert after[0] == 200 and len(after[1]["stops"]) == 2 and after[1]["stops"][-1]["source"] == "erasure", after
        assert "policy_action" not in after[1]
        with t.app() as app, org_transaction(app, t.token(t.a, ("proof_read",))):
            assert contact_has_records(app, t.crypto, env.fp(t.a)) is False  # the person's data reads as gone
    finally:
        cloud.close()
    entries = env.ledger.entries(t.a.org_id)
    assert [(e["kind"], e["contact_fp"]) for e in entries] == [("erasure_stop", env.fp(t.a)),
                                                               ("erasure_intent", env.fp(t.a)),
                                                               ("erasure_commit", env.fp(t.a)),
                                                               ("erasure_stop_commit", env.fp(t.a))]
    assert entries[2]["intent_seq"] == entries[1]["seq"] and entries[3]["stop_seq"] == entries[0]["seq"]
    assert PHONE not in str(entries) and PHONE[1:] not in str(entries)
    stop_entry = next(e for e in entries if e["kind"] == "erasure_stop")
    assert set(stop_entry) == {"kind", "contact_fp", "erasure_id", "channels", "stopped_at", "seq", "org_id", "at", "v",
                               "prev_sha256"}, sorted(stop_entry)
    with env.admin(t.a) as ctx:
        got = erasure.get_erasure(ctx, req["erasure_id"])
    assert got["status"] == "completed" and got["contact_fp_hint"] == env.fp(t.a)[:8]


def test_nothing_is_deleted_when_the_archive_store_refuses_the_ledger_entry(env):
    class Refusing:
        def get(self, org, key):
            from consentvault.providers.errors import EvidenceNotFoundError
            raise EvidenceNotFoundError("empty")

        def put(self, *a, **kw):
            raise EvidenceStoreError("the archive is down")

    req = _request(env, env.t.a)
    with env.operator() as c, pytest.raises(LedgerUnavailableError):
        erasure.confirm_erasure(c, token_key=env.t.key, crypto=env.t.crypto, ledger=LifecycleLedger(Refusing(), clock=dbclock.datetime_clock(lambda: db.connect(env.t.app_dsn))), operator_id=OPERATOR,
                                request_id="req-op", org_id=env.t.a.org_id, erasure_id=req["erasure_id"])
    assert env.key_present(env.t.a)
    with env.admin(env.t.a) as ctx:
        assert erasure.get_erasure(ctx, req["erasure_id"])["status"] == "pending_operator_confirmation"


def test_erasure_expires_the_contacts_cached_packages_and_deletes_them_where_the_cache_can(env):
    t = env.t
    with env.operator() as o, org_transaction(o, t.admin_token(t.a.org_id)):
        o.execute("INSERT INTO consentvault.export_job (org_id, contact_fp, status, requested_by, completed_at,"
                  " package_object_key, package_sha256, expires_at) VALUES (%s, %s, 'ready', gen_random_uuid(), now(),"
                  " 'exports/x.pkg', repeat('a', 64), now() + interval '7 days')", (t.a.org_id, env.fp(t.a)))

    class Cache:
        deleted = []

        def delete(self, org, key):
            self.deleted.append((org, key))

    req = _request(env, t.a)
    out = _confirm(env, t.a, req["erasure_id"], export_cache=Cache())
    assert out["export_cache"] == {"expired_jobs": 1, "deleted": 1, "unreadable_only": 0}
    assert Cache.deleted == [(str(t.a.org_id), "exports/x.pkg")]
    with t.superuser() as su:
        assert su.execute("SELECT expires_at <= now() AS gone FROM consentvault.export_job WHERE org_id = %s",
                          (t.a.org_id,)).fetchone()["gone"]


def test_a_hold_refuses_a_new_request_and_the_database_refuses_any_key_delete(env):
    t = env.t
    hold = _hold(env, t.a)
    with pytest.raises(ApiError) as e:
        _request(env, t.a)
    assert e.value.name == "legal_hold_active" and e.value.fields == {"hold_id": hold["hold_id"]}
    with env.operator() as o, org_transaction(o, t.admin_token(t.a.org_id)):
        with pytest.raises(Exception, match="legal_hold_active"):
            o.execute("SELECT consentvault.erase_contact(%s)", (env.fp(t.a),))
    with env.operator() as o, org_transaction(o, t.admin_token(t.a.org_id)):  # the console holds no delete at all
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            o.execute("DELETE FROM consentvault.contact_key WHERE contact_fp = %s", (env.fp(t.a),))
    with env.t.migrator() as o, org_transaction(o, t.admin_token(t.a.org_id)):  # the owner's rights: the hold trigger
        with pytest.raises(Exception, match="legal_hold_active"):
            o.execute("DELETE FROM consentvault.contact_key WHERE contact_fp = %s", (env.fp(t.a),))
    assert env.key_present(t.a)


def test_a_confirmed_erasure_under_a_hold_is_queued_and_runs_when_the_hold_is_released(env):
    t = env.t
    req = _request(env, t.a)
    hold = _hold(env, t.a, scope="org")
    with pytest.raises(ApiError) as e:
        _confirm(env, t.a, req["erasure_id"])
    assert e.value.name == "legal_hold_active"
    with env.admin(t.a) as ctx:
        queued = erasure.get_erasure(ctx, req["erasure_id"])
    assert queued["status"] == "held" and queued["held_by"] == hold["hold_id"]
    assert env.key_present(t.a)
    with env.admin(t.a) as ctx:
        holds.release_hold_member(ctx, hold["hold_id"], {"reason": "matter closed"}, ledger=env.ledger, crypto=env.t.crypto)
    with env.operator() as c:
        resumed = holds.resume(c, token_key=t.key, crypto=t.crypto, ledger=env.ledger, custody=env.custody, org_id=t.a.org_id,
                               request_id="req-resume")
    assert resumed["erasures_completed"] == 1
    assert not env.key_present(t.a)
    kinds = [e["kind"] for e in env.ledger.entries(t.a.org_id)]
    assert kinds[:3] == ["hold_set", "hold_released", "erasure_intent"]
    with env.operator() as c:  # the commit entry, if the release path did not write it, comes from the erasure job's sweep
        erasure.resume_waiting(c, token_key=t.key, crypto=t.crypto, ledger=env.ledger, request_id="req-sweep", org_id=t.a.org_id)
    kinds = [e["kind"] for e in env.ledger.entries(t.a.org_id)]
    assert kinds == ["hold_set", "hold_released", "erasure_intent", "erasure_commit"]


def test_an_unconfirmed_request_returns_to_the_operator_queue_on_release(env):
    t = env.t
    req = _request(env, t.a)
    hold = _hold(env, t.a, scope="org")
    with env.operator() as o, org_transaction(o, t.admin_token(t.a.org_id)):
        o.execute("UPDATE consentvault.erasure_request SET held_by = %s, held_since = now() WHERE erasure_id = %s",
                  (hold["hold_id"], req["erasure_id"]))
    with env.operator() as c:
        holds.release_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto, operator_id=OPERATOR,
                                    request_id="req-r", org_id=t.a.org_id, hold_id=hold["hold_id"], reason="done")
    with env.admin(t.a) as ctx:
        got = erasure.get_erasure(ctx, req["erasure_id"])
    assert got["status"] == "pending_operator_confirmation" and got["held_by"] is None
    assert env.key_present(t.a)  # never erased without an operator's confirmation


def test_a_hold_an_operator_set_is_released_only_by_an_operator(env):
    t = env.t
    with env.operator() as c:
        hold = holds.place_hold_operator(c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto,
                                         operator_id=OPERATOR, request_id="req-h", org_id=t.a.org_id, scope="org",
                                         reason="subpoena preservation")
    with env.admin(t.a) as ctx, pytest.raises(ApiError) as e:
        holds.release_hold_member(ctx, hold["hold_id"], {"reason": "we want it gone"}, ledger=env.ledger, crypto=t.crypto)
    assert e.value.name == "role_not_allowed"
    with t.superuser() as su:
        assert su.execute("SELECT released_at FROM consentvault.legal_hold WHERE hold_id = %s",
                          (hold["hold_id"],)).fetchone()["released_at"] is None


def test_the_operator_declines_a_request_visibly(env):
    req = _request(env, env.t.a)
    with env.operator() as c:
        out = erasure.decline_erasure(c, token_key=env.t.key, operator_id=OPERATOR, request_id="req-d",
                                      org_id=env.t.a.org_id, erasure_id=req["erasure_id"], reason="identity unproven")
    assert out["status"] == "declined" and env.key_present(env.t.a)
    with pytest.raises(ApiError) as e:
        _confirm(env, env.t.a, req["erasure_id"])
    assert e.value.name == "validation_failed"


def test_hold_and_erasure_records_cannot_be_deleted_or_rewritten(env):
    t = env.t
    hold = _hold(env, t.a)
    with t.superuser() as su:
        for sql in ("DELETE FROM consentvault.legal_hold", "UPDATE consentvault.legal_hold SET reason = 'x'",
                    "TRUNCATE consentvault.legal_hold CASCADE"):
            with pytest.raises(Exception):
                with su.transaction():
                    su.execute(sql)
    assert hold["scope"] == "contacts"
