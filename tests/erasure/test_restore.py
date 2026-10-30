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
            erasure.confirm_erasure(c, token_key=t.key, ledger=env.ledger, operator_id=OPERATOR, request_id="req-e",
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
        assert status == 503 and body["policy_action"] is None, body
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
