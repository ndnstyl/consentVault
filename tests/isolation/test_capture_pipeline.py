"""The evidence pipeline, the tenant release rule, tenant anchors and the 0008 down migration."""

import json
import os
from datetime import timedelta
from pathlib import Path

import psycopg
import pytest

from consentvault import door as capture_mod
from consentvault.anchor import anchor
from consentvault.providers.errors import EvidenceStoreError
from consentvault.tenancy import crypto as tc
from consentvault.tenancy.keys_protocol import WrappedKey
from consentvault.tenancy.pipeline import reconcile_uncommitted
from consentvault.tenancy.tokens import org_transaction

from .cloud_harness import Cloud
from .harness import make_login_role

X = "+15555550177"
MIGRATIONS = Path(__file__).resolve().parents[2] / "migrations"


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def _objects(cloud, org_id):
    with cloud.t.superuser() as su:
        return su.execute("SELECT * FROM consentvault.evidence_object WHERE org_id = %s ORDER BY created_at",
                          (org_id,)).fetchall()


def test_a_capture_writes_its_encrypted_evidence_object_before_the_ledger_row(cloud):
    s, r = cloud.grant(cloud.a, X)
    assert s == 201
    obj, = _objects(cloud, cloud.a.org.org_id)
    assert obj["status"] == "committed" and str(obj["event_id"]) == r["event_id"]
    blob = cloud.store.get(str(cloud.a.org.org_id), obj["object_key"])
    assert X.encode() not in blob  # encrypted
    with cloud.t.superuser() as su:
        k = su.execute("SELECT wrapped_key, key_version FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                       (cloud.a.org.org_id, obj["contact_fp"])).fetchone()
    dk = cloud.t.crypto.open_contact_key(cloud.a.org.org_id, WrappedKey(bytes(k["wrapped_key"]), k["key_version"]))
    ev = json.loads(tc.decrypt_field(dk, cloud.a.org.org_id, str(obj["object_id"]), "evidence_object", blob))
    assert ev["fields"]["contact"] == X and ev["org_id"] == str(cloud.a.org.org_id)


def test_a_store_failure_stores_the_post_and_derives_no_event_and_leaves_the_object_pending(cloud, monkeypatch):
    def refuse(*a, **k):
        raise EvidenceStoreError("store down")
    monkeypatch.setattr(cloud.store, "put", refuse)
    s, r = cloud.grant(cloud.a, X)
    assert s == 201 and r["stored"] is True and "event_id" not in r
    from .cloud_harness import facts_of, raw_posts
    assert facts_of(cloud.t, raw_posts(cloud.t, cloud.a.org.org_id)[-1])["event_not_derived"] == "EvidenceStoreUnavailable"
    with cloud.t.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND contact_fp IN"
                          " (SELECT contact_fp FROM consentvault.evidence_object)",
                          (cloud.a.org.org_id,)).fetchone()["n"] == 0
    assert [o["status"] for o in _objects(cloud, cloud.a.org.org_id)] == ["pending"]


def test_a_failed_commit_leaves_the_object_pending_until_reconciled_by_the_worker(cloud, monkeypatch):
    assert cloud.grant(cloud.a, X)[0] == 201

    def broken(*a, **k):
        raise psycopg.errors.QueryCanceled("simulated commit failure")
    monkeypatch.setattr(capture_mod, "write_tenant_event", broken)
    s, r = cloud.grant(cloud.a, X)
    assert s == 201 and r["stored"] is True  # the post is stored before the event is tried; the event failing cannot remove it
    from .cloud_harness import facts_of, raw_posts
    last = facts_of(cloud.t, raw_posts(cloud.t, cloud.a.org.org_id)[-1])
    assert "event_not_derived" not in last and "event_derived" not in last  # no outcome is left, so the projection runs again for it
    objs = _objects(cloud, cloud.a.org.org_id)
    assert [o["status"] for o in objs] == ["committed", "pending"]
    assert cloud.store.get(str(cloud.a.org.org_id), objs[1]["object_key"])  # the object itself is kept

    worker_dsn = make_login_role(int(cloud.t.app_dsn.rsplit(":", 1)[1].split("/")[0]),
                                 cloud.t.app_dsn.rsplit("/", 1)[1], "consentvault_worker")
    with psycopg.connect(worker_dsn, autocommit=True, row_factory=psycopg.rows.dict_row) as w:
        tokens = {r["org_id"]: r["token"] for r in w.execute("SELECT * FROM consentvault.dispatch_orgs('reconcile')")}
        enter_b = lambda c: org_transaction(c, tokens[cloud.b.org.org_id])  # noqa: E731
        enter_a = lambda c: org_transaction(c, tokens[cloud.a.org.org_id])  # noqa: E731
        assert reconcile_uncommitted(w, enter_b, grace=timedelta(0)) == 0  # B cannot touch A's objects
        assert reconcile_uncommitted(w, enter_a, grace=timedelta(hours=1)) == 0  # still inside its grace
        assert reconcile_uncommitted(w, enter_a, grace=timedelta(0)) == 1
    assert [o["status"] for o in _objects(cloud, cloud.a.org.org_id)] == ["committed", "uncommitted"]
    with cloud.t.app() as app, pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        with org_transaction(app, cloud.t.token(cloud.t.a)):
            app.execute("UPDATE consentvault.evidence_object SET status = 'committed' WHERE status = 'uncommitted'")


def test_a_form_grant_after_the_persons_own_stop_is_a_later_line_and_lifts_nothing(cloud):
    stop = {"contact": X, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword"}
    assert cloud.call("/v1/events", stop, token=cloud.token(cloud.a, "capture"))[0] == 201
    assert cloud.grant(cloud.a, X)[0] == 201
    s, g = cloud.gate(cloud.a, X)
    assert [x["event_type"] for x in g["history"]] == ["revoke", "grant"]
    assert g["stops"][0]["lifted_by_post_ids"] == [] and g["lifts"] == []
    s, p = cloud.proof(cloud.a, X)
    assert p["reviews"]["items"] == []
    assert [i["event_type"] for i in p["timeline"]["items"]] == ["revoke", "grant"]


def test_a_tenant_anchor_names_its_organisation_and_its_uuid(cloud, tmp_path):
    assert cloud.grant(cloud.a, X)[0] == 201
    sink = str(tmp_path / "anchors.jsonl")
    with cloud.t.app() as app, org_transaction(app, cloud.t.token(cloud.t.a, ("gate_read",))):
        rec = anchor(app, sink)
    assert rec["org_id"] == str(cloud.a.org.org_id) and len(rec["anchor_id"]) == 36
    s, p = cloud.proof(cloud.a, X)
    assert rec["anchor_id"] in [a["anchor_id"] for a in p["chain"]["anchors"]]
    s, p = cloud.proof(cloud.b, X)
    assert p == {"found": False, "evaluated_at": p["evaluated_at"], "notice": p["notice"], "permissions": []}


def test_the_0008_down_migration_refuses_while_evidence_exists_and_round_trips_when_empty(dsn, super_dsn, conn):
    down = (MIGRATIONS / "down" / "0008_capture.sql").read_text()
    up = (MIGRATIONS / "0008_capture.sql").read_text()
    with psycopg.connect(super_dsn, autocommit=True) as su:
        su.execute(down)
        assert su.execute("SELECT to_regclass('consentvault.gate_decision')").fetchone()[0] is None
    conn.execute(up)
    with psycopg.connect(super_dsn, autocommit=True) as su:
        home = su.execute("SELECT consentvault.home_org()").fetchone()[0]
        su.execute("INSERT INTO consentvault.gate_decision (org_id, contact_fp, channel, purpose, evidence_status)"
                   " VALUES (%s, %s, 'sms', 'marketing', 'no_record')", (home, "c" * 64))
        with pytest.raises(psycopg.errors.RaiseException, match="refused"):
            su.execute(down)
        su.execute("ROLLBACK")
        assert su.execute("SELECT count(*) FROM consentvault.gate_decision").fetchone()[0] == 1


def test_gate_decisions_are_append_only_and_land_in_monthly_partitions(cloud):
    assert cloud.gate(cloud.a, X)[0] == 200
    with cloud.t.superuser() as su:
        part = su.execute("SELECT tableoid::regclass::text AS p FROM consentvault.gate_decision").fetchone()["p"]
        assert part.startswith("consentvault.gate_decision_2")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
            su.execute("DELETE FROM consentvault.gate_decision")
    with cloud.t.app() as app, org_transaction(app, cloud.t.token(cloud.t.a, ("capture",))):
        assert app.execute("SELECT count(*) AS n FROM consentvault.gate_decision").fetchone()["n"] == 0  # write-only
    with cloud.t.app() as app:  # a partition is never reached directly
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(f"SELECT * FROM {part}")


def test_a_version_2_seal_made_by_the_seal_job_matches_the_exported_verifiers_digest(cloud, monkeypatch):
    from datetime import datetime, timezone

    from consentvault import evidence, seal
    from consentvault.ledger import _canon_value

    assert cloud.grant(cloud.a, X)[0] == 201
    monkeypatch.setattr(seal, "stamp", lambda d, url, **k: (b"token-for-" + d.encode(), datetime.now(timezone.utc)))
    with cloud.t.app() as app, org_transaction(app, cloud.t.token(cloud.t.a, ("gate_read",))):
        sealed = seal.seal_pending(app, "https://tsa.example.test")
    with cloud.t.superuser() as su:
        s = su.execute("SELECT * FROM consentvault.seal WHERE org_id = %s AND event_id = %s",
                       (cloud.a.org.org_id, sealed[-1])).fetchone()
        row = su.execute("SELECT * FROM consentvault.event WHERE org_id = %s AND event_id = %s",
                         (cloud.a.org.org_id, sealed[-1])).fetchone()
    assert s["hash_version"] == 2 and list(s["columns"]) == list(seal.SEAL_HASH_VERSIONS[2])
    ns: dict = {"__file__": "verify.py"}
    src = evidence.render_verifier("0" * 64)
    exec(compile(src.split("def main():")[0], "verify.py", "exec"), ns)
    exported = {c: _canon_value(row[c]) for c in evidence._EVENT_COLUMNS_V2}
    theirs, why = ns["seal_digest"](exported, 2, list(s["columns"]))
    assert theirs == bytes(s["digest"]).hex(), why
