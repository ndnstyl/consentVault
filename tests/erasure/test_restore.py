"""Restore reconciliation against a real restored copy: the database is copied at a restore point, work continues on
the original (a stop, a new contact's stop, an erasure, a hold), and the copy is then reconciled. The gate answers 503
until reconciliation completes; the missing stop is re-ingested; the erasure and the hold are replayed."""

import dataclasses
import threading
from datetime import datetime, timezone

import psycopg
import pytest

from consentvault import api
from consentvault.tenancy import erasure, holds, restore
from consentvault.tenancy.restore import RestoreIncompleteError, local_inventory

from isolation.cloud_harness import Cloud
from isolation.harness import PHONE

from .support import OPERATOR
from .test_attacks_wave3_lifecycle import drop_synthetic_seals

X, Y = "+15555550177", "+15555550178"


def _stop(cloud, contact):
    body = {"contact": contact, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
            "method": "keyword"}
    return cloud.call("/v1/events", body, token=cloud.token(cloud.a, "capture"))


def _copy(t, port):
    src = t.operator_dsn.rsplit("/", 1)[1]
    dst = src + "_restored"
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{port}/postgres", autocommit=True) as su:
        su.execute(f'CREATE DATABASE "{dst}" TEMPLATE "{src}" OWNER cv_test_owner')
    swap = lambda dsn: dsn.rsplit("/", 1)[0] + "/" + dst  # noqa: E731
    return dataclasses.replace(t, operator_dsn=swap(t.operator_dsn), super_dsn=swap(t.super_dsn), app_dsn=swap(t.app_dsn),
                               migrator_dsn=swap(t.migrator_dsn))


def test_the_gate_answers_503_until_reconciliation_and_the_lost_work_comes_back(env, tmp_path, pg_server):
    t = env.t
    evidence = tmp_path / "evidence"
    cloud = Cloud(t, str(evidence))
    server2 = None
    try:
        assert cloud.grant(cloud.a, X)[0] in (200, 201)
        r = _copy(t, pg_server["port"])  # the restore point
        restore_point = datetime.now(timezone.utc)

        assert _stop(cloud, X)[0] in (200, 201)  # work that the restored copy will not hold
        assert _stop(cloud, Y)[0] in (200, 201)
        with env.admin(t.a) as ctx:
            eid = erasure.request_erasure(ctx, {"contact": PHONE, "reason": "asked"}, crypto=t.crypto)["erasure_id"]
        with env.operator() as c:
            erasure.confirm_erasure(c, token_key=t.key, crypto=t.crypto, ledger=env.ledger, operator_id=OPERATOR, request_id="req-e",
                                    org_id=t.a.org_id, erasure_id=eid)
        with env.admin(t.a) as ctx:
            hold = holds.place_hold_member(ctx, {"scope": "contacts", "contacts": [X], "reason": "preserve"},
                                           ledger=env.ledger, crypto=t.crypto)
        assert cloud.gate(cloud.a, X)[1]["evidence_status"] == "stop_on_record"

        server2 = api.make_cloud_server(dataclasses.replace(cloud.settings, dsn=r.app_dsn), "127.0.0.1", 0)
        threading.Thread(target=server2.serve_forever, daemon=True).start()
        cloud.base = f"http://127.0.0.1:{server2.server_address[1]}"  # from here every call reaches the restored copy
        assert cloud.gate(cloud.a, X)[1]["evidence_status"] == "consent_record_found"  # the stop is missing

        with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
            restore.begin_restore(o, operator_id=OPERATOR, request_id="req-rs", restore_point=restore_point)
        status, body = cloud.gate(cloud.a, X)
        assert status == 503 and body["policy_action"] == "hold", body  # contract: hold when the approved policy holds on unavailability
        assert body["policy_version"] == cloud.a.policy_version
        assert body["error"] == "restore_in_progress" and body["evidence_status"] == "unavailable:restore_in_progress"

        drop_synthetic_seals(r)  # the harness's fake seals would rightly fail the restore's seal re-check
        kw = dict(token_key=t.key, crypto=t.crypto, store=cloud.store, ledger=env.ledger,
                  inventory=local_inventory(evidence), operator_id=OPERATOR, request_id="req-rc", region="US")
        with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
            with pytest.raises(RestoreIncompleteError) as e:
                restore.reconcile(o, **kw)
        a = e.value.report["orgs"][str(t.a.org_id)]
        assert len(a["stops_reingested"]) == 1 and len(a["unreadable"]) == 1  # Y's key was born after the copy
        assert a["erasures_replayed"] == 1 and a["keys_deleted"] == 1 and a["holds_restored"] == 1
        assert cloud.gate(cloud.a, X)[0] == 503  # still closed: an operator has not accepted the unreadable object

        with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
            report = restore.reconcile(o, accept_unreadable="Y re-captured from the client's own stop list", **kw)
        assert report["orgs"][str(t.a.org_id)]["stops_reingested"] == []  # idempotent: nothing twice
        status, body = cloud.gate(cloud.a, X)
        assert status == 200 and body["evidence_status"] == "stop_on_record", body
        with psycopg.connect(r.super_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as su:
            assert su.execute("SELECT 1 FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                              (t.a.org_id, env.fp(t.a))).fetchone() is None  # the erasure survived the restore
            assert su.execute("SELECT released_at FROM consentvault.legal_hold WHERE hold_id = %s",
                              (hold["hold_id"],)).fetchone() == {"released_at": None}
            gap = su.execute("SELECT count(*) AS n FROM consentvault.audit_event WHERE org_id = %s"
                             " AND action = 'restore.stop_reingested'", (t.a.org_id,)).fetchone()["n"]
            assert gap == 1
    finally:
        if server2 is not None:
            server2.shutdown()
            server2.server_close()
        cloud.close()


def test_reconcile_refuses_without_a_pending_restore_and_a_second_begin_is_refused(env):
    from consentvault.tenancy.erasure import LifecycleError

    drop_synthetic_seals(env.t)  # the harness's fake seals would rightly fail the restore's seal re-check
    with env.operator() as o:
        with pytest.raises(LifecycleError):
            restore.reconcile(o, token_key=env.t.key, crypto=env.t.crypto, store=env.archive, ledger=env.ledger,
                              inventory=lambda org, since: [], operator_id=OPERATOR, request_id="r")
        restore.begin_restore(o, operator_id=OPERATOR, request_id="r", restore_point=datetime.now(timezone.utc))
        with pytest.raises(LifecycleError):
            restore.begin_restore(o, operator_id=OPERATOR, request_id="r", restore_point=datetime.now(timezone.utc))
        report = restore.reconcile(o, token_key=env.t.key, crypto=env.t.crypto, store=env.archive, ledger=env.ledger,
                                   inventory=lambda org, since: [], operator_id=OPERATOR, request_id="r")
        assert set(report["orgs"]) >= {str(env.t.a.org_id), str(env.t.b.org_id)}
        assert restore.pending(o) is None


def test_a_restore_replays_the_erasure_with_its_stop_so_the_gate_still_denies(env, tmp_path, pg_server):
    t = env.t
    evidence = tmp_path / "evidence"
    cloud = Cloud(t, str(evidence))
    server2 = None
    try:
        assert cloud.grant(cloud.a, X)[0] in (200, 201)
        r = _copy(t, pg_server["port"])  # the restore point: X consents, no erasure yet
        restore_point = datetime.now(timezone.utc)
        with env.admin(t.a) as ctx:
            eid = erasure.request_erasure(ctx, {"contact": X, "reason": "asked"}, crypto=t.crypto)["erasure_id"]
        with env.operator() as c:
            erasure.confirm_erasure(c, token_key=t.key, crypto=t.crypto, ledger=env.ledger, operator_id=OPERATOR,
                                    request_id="req-e", org_id=t.a.org_id, erasure_id=eid)

        server2 = api.make_cloud_server(dataclasses.replace(cloud.settings, dsn=r.app_dsn), "127.0.0.1", 0)
        threading.Thread(target=server2.serve_forever, daemon=True).start()
        cloud.base = f"http://127.0.0.1:{server2.server_address[1]}"
        assert cloud.gate(cloud.a, X)[1]["evidence_status"] == "consent_record_found"  # the copy predates the erasure

        with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
            restore.begin_restore(o, operator_id=OPERATOR, request_id="req-rs", restore_point=restore_point)
        drop_synthetic_seals(r)
        kw = dict(token_key=t.key, crypto=t.crypto, store=cloud.store, ledger=env.ledger,
                  inventory=local_inventory(evidence), operator_id=OPERATOR, request_id="req-rc", region="US")
        with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
            report = restore.reconcile(o, **kw)
        assert report["orgs"][str(t.a.org_id)]["erasures_replayed"] == 1
        status, body = cloud.gate(cloud.a, X)
        assert status == 200 and body["evidence_status"] == "stop_on_record", body
        with psycopg.connect(r.super_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as su:
            assert su.execute("SELECT 1 FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                              (t.a.org_id, env.fp(t.a, X))).fetchone() is None
            assert su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND source = 'erasure'"
                              " AND contact_fp = %s", (t.a.org_id, env.fp(t.a, X))).fetchone()["n"] == 1
    finally:
        if server2 is not None:
            server2.shutdown()
            server2.server_close()
        cloud.close()


def test_a_stop_written_before_the_erasure_completed_is_in_the_ledger_and_a_restore_replays_it(env, tmp_path, pg_server,
                                                                                               monkeypatch):
    t = env.t
    evidence = tmp_path / "evidence"
    cloud = Cloud(t, str(evidence))
    server2 = None
    try:
        assert cloud.grant(cloud.a, X)[0] in (200, 201)
        r = _copy(t, pg_server["port"])  # the restore point: consent, no stop
        restore_point = datetime.now(timezone.utc)
        with env.admin(t.a) as ctx:
            eid = erasure.request_erasure(ctx, {"contact": X, "reason": "asked"}, crypto=t.crypto)["erasure_id"]
        with monkeypatch.context() as m:
            m.setattr(erasure, "pending_pushes", lambda conn, fp: 1)  # confirmed, stop written, not completed
            with env.operator() as c:
                assert erasure.confirm_erasure(c, token_key=t.key, crypto=t.crypto, ledger=env.ledger,
                                               operator_id=OPERATOR, request_id="req-e", org_id=t.a.org_id,
                                               erasure_id=eid)["status"] == "held"
        entries = env.ledger.entries(t.a.org_id)
        assert [e["kind"] for e in entries] == ["erasure_stop", "erasure_stop_commit"] and entries[0]["erasure_id"] == eid
        assert entries[1]["stop_seq"] == entries[0]["seq"]
        assert sorted(entries[0]["channels"]) == ["artificial_voice", "email", "sms", "voice"]
        assert X not in str(entries)

        server2 = api.make_cloud_server(dataclasses.replace(cloud.settings, dsn=r.app_dsn), "127.0.0.1", 0)
        threading.Thread(target=server2.serve_forever, daemon=True).start()
        cloud.base = f"http://127.0.0.1:{server2.server_address[1]}"
        assert cloud.gate(cloud.a, X)[1]["evidence_status"] == "consent_record_found"  # the copy lacks the stop

        with psycopg.connect(r.super_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as su:
            su.execute("DELETE FROM consentvault.channel WHERE org_id = %s AND channel = 'voice'", (t.a.org_id,))
        with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
            restore.begin_restore(o, operator_id=OPERATOR, request_id="req-rs", restore_point=restore_point)
        drop_synthetic_seals(r)
        kw = dict(token_key=t.key, crypto=t.crypto, store=cloud.store, ledger=env.ledger,
                  inventory=local_inventory(evidence), operator_id=OPERATOR, request_id="req-rc", region="US")
        with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
            report = restore.reconcile(o, **kw)
        assert report["orgs"][str(t.a.org_id)]["stops_replayed"] == 1
        for ch in ("sms", "artificial_voice", "email"):
            status, body = cloud.gate(cloud.a, X, channel=ch)
            assert status == 200 and body["evidence_status"] == "stop_on_record", (ch, body)
        with psycopg.connect(r.super_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as su:
            row = su.execute("SELECT channels FROM consentvault.event WHERE org_id = %s AND source = 'erasure'",
                             (t.a.org_id,)).fetchone()
        assert sorted(row["channels"]) == ["artificial_voice", "email", "sms", "voice"]  # the ledger's, not the copy's now
    finally:
        if server2 is not None:
            server2.shutdown()
            server2.server_close()
        cloud.close()


def _restore_copy(env, cloud, r, restore_point, evidence, *, allow=()):
    """Point the cloud at the restored copy and run the whole reconcile; returns the org's report."""
    t = env.t
    server2 = api.make_cloud_server(dataclasses.replace(cloud.settings, dsn=r.app_dsn), "127.0.0.1", 0)
    threading.Thread(target=server2.serve_forever, daemon=True).start()
    cloud.base = f"http://127.0.0.1:{server2.server_address[1]}"
    with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
        restore.begin_restore(o, operator_id=OPERATOR, request_id="req-rs", restore_point=restore_point)
    drop_synthetic_seals(r)
    kw = dict(token_key=t.key, crypto=t.crypto, store=cloud.store, ledger=env.ledger,
              inventory=local_inventory(evidence), operator_id=OPERATOR, request_id="req-rc", region="US")
    with psycopg.connect(r.operator_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as o:
        try:
            report = restore.reconcile(o, **kw)
        except restore.RestoreIncompleteError as exc:
            org = exc.report["orgs"][str(t.a.org_id)]
            extra = [f for f in org["failed_checks"] if f["cause"] not in allow]
            assert not extra, f"restore incomplete: {extra}"
            return server2, org
    return server2, report["orgs"][str(t.a.org_id)]


def _unconfirmed_checks(r, t, eid):
    with psycopg.connect(r.super_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as su:
        alarms = su.execute("SELECT count(*) AS n FROM consentvault.operator_alarm WHERE org_id = %s AND name = %s",
                            (t.a.org_id, restore.ALARM_STOPS_UNCONFIRMED)).fetchone()["n"]
        audit = su.execute("SELECT count(*) AS n FROM consentvault.audit_event WHERE org_id = %s AND"
                           " action = 'restore.stop_unconfirmed' AND target_id = %s", (t.a.org_id, eid)).fetchone()["n"]
        marks = [x["recorded_by"] for x in su.execute(
            "SELECT recorded_by FROM consentvault.event WHERE org_id = %s AND source = 'erasure'", (t.a.org_id,))]
    assert alarms == 1 and audit == 1 and len(marks) == 1 and marks[0].startswith(f"erasure-unconfirmed:{eid}:"), (alarms, audit, marks)


def test_a_stop_whose_confirm_rolled_back_is_replayed_unconfirmed_and_alarmed(env, tmp_path, pg_server):
    from consentvault.tenancy.erasure import commit_after, operator_org, record_erasure_stop

    t = env.t
    evidence = tmp_path / "evidence"
    cloud = Cloud(t, str(evidence))
    server2 = None
    try:
        assert cloud.grant(cloud.a, X)[0] in (200, 201)
        r = _copy(t, pg_server["port"])
        restore_point = datetime.now(timezone.utc)
        eid = "33333333-3333-4333-8333-333333333333"

        class Rollback(Exception):
            pass

        with env.operator() as c:
            with pytest.raises(Rollback):
                with operator_org(c, t.key, t.a.org_id):  # the confirm's transaction: stop entered, then it fails
                    record_erasure_stop(c, t.crypto, fp=env.fp(t.a, X), erasure_id=eid, ledger=env.ledger)
                    raise Rollback()
            commit_after(c, token_key=t.key, ledger=env.ledger, org_id=t.a.org_id, request_id="req-c")
        assert [e["kind"] for e in env.ledger.entries(t.a.org_id)] == ["erasure_stop"]  # entered, never committed
        assert cloud.gate(cloud.a, X)[1]["evidence_status"] == "consent_record_found"  # the rollback left no stop

        server2, org = _restore_copy(env, cloud, r, restore_point, evidence)
        assert [u["erasure_id"] for u in org["stops_unconfirmed"]] == [eid] and org["stops_replayed"] == 1
        assert cloud.gate(cloud.a, X)[1]["evidence_status"] == "stop_on_record"  # over-stop, never under-stop
        _unconfirmed_checks(r, t, eid)
    finally:
        if server2 is not None:
            server2.shutdown()
            server2.server_close()
        cloud.close()


def test_the_ledger_down_at_commit_then_a_restore_still_stops_the_person_and_alarms(env, tmp_path, pg_server):
    from consentvault.tenancy.erasure import LedgerUnavailableError

    class DownForCommits(erasure.LifecycleLedger):
        def append(self, org, entry, *, hint=0):
            if entry["kind"] == "erasure_stop_commit":
                raise LedgerUnavailableError("the archive is down")
            return super().append(org, entry, hint=hint)

    t = env.t
    evidence = tmp_path / "evidence"
    cloud = Cloud(t, str(evidence))
    server2 = None
    try:
        assert cloud.grant(cloud.a, X)[0] in (200, 201)
        r = _copy(t, pg_server["port"])
        restore_point = datetime.now(timezone.utc)
        with env.admin(t.a) as ctx:
            eid = erasure.request_erasure(ctx, {"contact": X, "reason": "asked"}, crypto=t.crypto)["erasure_id"]
        down = DownForCommits(env.archive, clock=env.ledger._clock)
        with pytest.MonkeyPatch.context() as m:
            m.setattr(erasure, "pending_pushes", lambda conn, fp: 1)
            with env.operator() as c:
                out = erasure.confirm_erasure(c, token_key=t.key, crypto=t.crypto, ledger=down, operator_id=OPERATOR,
                                              request_id="req-e", org_id=t.a.org_id, erasure_id=eid)
        assert out["status"] == "held" and out["ledger_commit"]["status"] == "pending"
        assert [e["kind"] for e in env.ledger.entries(t.a.org_id)] == ["erasure_stop"]  # no commit: the ledger was down

        server2, org = _restore_copy(env, cloud, r, restore_point, evidence)
        assert [u["erasure_id"] for u in org["stops_unconfirmed"]] == [eid]
        assert cloud.gate(cloud.a, X)[1]["evidence_status"] == "stop_on_record"
        _unconfirmed_checks(r, t, eid)
    finally:
        if server2 is not None:
            server2.shutdown()
            server2.server_close()
        cloud.close()


def test_a_backup_taken_after_the_erasure_and_the_return_is_left_alone_by_the_restore(env, tmp_path, pg_server):
    """The person is erased, comes back and consents again with a verified grant; the backup is taken then. Restoring it
    must not delete the new key, re-stop the verified re-grant or count the erasure twice."""
    from erasure.test_erasure_stop import _verified_regrant_and_release

    t = env.t
    evidence = tmp_path / "evidence"
    cloud = Cloud(t, str(evidence))
    server2 = None
    try:
        assert cloud.grant(cloud.a, X)[0] in (200, 201)
        with env.admin(t.a) as ctx:
            eid = erasure.request_erasure(ctx, {"contact": X, "reason": "asked"}, crypto=t.crypto)["erasure_id"]
        with env.operator() as c:
            erasure.confirm_erasure(c, token_key=t.key, crypto=t.crypto, ledger=env.ledger, operator_id=OPERATOR,
                                    request_id="req-e", org_id=t.a.org_id, erasure_id=eid)
        assert not env.key_present(t.a, X)
        conn, tx = _verified_regrant_and_release(env, cloud, X, commit=True)  # the person returns, verified
        tx.__exit__(None, None, None)
        conn.close()
        assert env.key_present(t.a, X) and cloud.gate(cloud.a, X)[1]["evidence_status"] == "consent_record_found"
        r = _copy(t, pg_server["port"])  # the backup, taken after all of it
        restore_point = datetime.now(timezone.utc)

        # the rows sealed under the destroyed key read as erased: the chain re-check passes
        server2, org = _restore_copy(env, cloud, r, restore_point, evidence)
        assert org["failed_checks"] == []
        assert org["keys_deleted"] == 0 and org["erasures_replayed"] == 0 and org["erasures_present"] == 1
        assert org["stops_present"] == 1 and org["stops_replayed"] == 0
        with psycopg.connect(r.super_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as su:
            allowed = su.execute("SELECT allowed FROM consentvault.current_permission WHERE org_id = %s AND"
                                 " contact_fp = %s AND channel = 'sms' AND purpose = 'marketing'",
                                 (t.a.org_id, env.fp(t.a, X))).fetchone()["allowed"]
            assert allowed is True  # the verified re-grant still stands
            assert su.execute("SELECT 1 FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                              (t.a.org_id, env.fp(t.a, X))).fetchone() is not None
            assert su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND source = 'erasure'",
                              (t.a.org_id,)).fetchone()["n"] == 1
    finally:
        if server2 is not None:
            server2.shutdown()
            server2.server_close()
        cloud.close()


def test_a_rolled_back_stop_then_a_successful_erasure_does_not_break_the_restore(env, tmp_path, pg_server):
    from consentvault.tenancy.erasure import operator_org, record_erasure_stop

    t = env.t
    evidence = tmp_path / "evidence"
    cloud = Cloud(t, str(evidence))
    server2 = None
    try:
        assert cloud.grant(cloud.a, X)[0] in (200, 201)
        r = _copy(t, pg_server["port"])  # before everything: the copy holds the key and no stop
        restore_point = datetime.now(timezone.utc)
        with env.admin(t.a) as ctx:
            eid = erasure.request_erasure(ctx, {"contact": X, "reason": "asked"}, crypto=t.crypto)["erasure_id"]

        class Rollback(Exception):
            pass

        with env.operator() as c:  # the first confirm fails after entering its stop
            with pytest.raises(Rollback):
                with operator_org(c, t.key, t.a.org_id):
                    record_erasure_stop(c, t.crypto, fp=env.fp(t.a, X), erasure_id=eid, ledger=env.ledger)
                    raise Rollback()
        with env.operator() as c:  # the retry succeeds
            erasure.confirm_erasure(c, token_key=t.key, crypto=t.crypto, ledger=env.ledger, operator_id=OPERATOR,
                                    request_id="req-e", org_id=t.a.org_id, erasure_id=eid)
        kinds = [e["kind"] for e in env.ledger.entries(t.a.org_id)]
        assert kinds == ["erasure_stop", "erasure_stop", "erasure_intent", "erasure_commit", "erasure_stop_commit"]

        server2, org = _restore_copy(env, cloud, r, restore_point, evidence)  # raises if any check failed
        assert org["failed_checks"] == [] and [u["seq"] for u in org["stops_superseded"]] == [1]
        assert org["stops_replayed"] == 1 and org["erasures_replayed"] == 1 and org["stops_unconfirmed"] == []
        assert cloud.gate(cloud.a, X)[1]["evidence_status"] == "stop_on_record"
    finally:
        if server2 is not None:
            server2.shutdown()
            server2.server_close()
        cloud.close()


def test_the_ledger_failing_between_the_erasure_commit_and_the_stop_commit_still_leaves_the_person_stopped(
        env, tmp_path, pg_server):
    """An erasure's commit never settles its stop: with the stop's own commit missing, the stop is replayed (the safe
    direction) before the key is deleted, and the gate reads stopped."""
    from consentvault.tenancy.erasure import LedgerUnavailableError

    class DownForStopCommits(erasure.LifecycleLedger):
        def append(self, org, entry, *, hint=0):
            if entry["kind"] == "erasure_stop_commit":
                raise LedgerUnavailableError("the archive went down")
            return super().append(org, entry, hint=hint)

    t = env.t
    evidence = tmp_path / "evidence"
    cloud = Cloud(t, str(evidence))
    server2 = None
    try:
        assert cloud.grant(cloud.a, X)[0] in (200, 201)
        r = _copy(t, pg_server["port"])
        restore_point = datetime.now(timezone.utc)
        with env.admin(t.a) as ctx:
            eid = erasure.request_erasure(ctx, {"contact": X, "reason": "asked"}, crypto=t.crypto)["erasure_id"]
        with env.operator() as c:
            erasure.confirm_erasure(c, token_key=t.key, crypto=t.crypto, ledger=DownForStopCommits(env.archive, clock=env.ledger._clock),
                                    operator_id=OPERATOR, request_id="req-e", org_id=t.a.org_id, erasure_id=eid)
        kinds = [e["kind"] for e in env.ledger.entries(t.a.org_id)]
        assert kinds == ["erasure_stop", "erasure_intent", "erasure_commit"]  # no stop commit
        assert cloud.gate(cloud.a, X)[1]["evidence_status"] == "stop_on_record"

        server2, org = _restore_copy(env, cloud, r, restore_point, evidence)
        assert org["failed_checks"] == [] and org["stops_replayed"] == 1 and org["erasures_replayed"] == 1
        assert [u["seq"] for u in org["stops_unconfirmed"]] == [1] and org["stops_superseded"] == []
        assert cloud.gate(cloud.a, X)[1]["evidence_status"] == "stop_on_record"
        with psycopg.connect(r.super_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as su:
            assert su.execute("SELECT 1 FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                              (t.a.org_id, env.fp(t.a, X))).fetchone() is None  # erased, and stopped first
    finally:
        if server2 is not None:
            server2.shutdown()
            server2.server_close()
        cloud.close()
