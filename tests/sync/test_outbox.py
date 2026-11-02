"""The transactional outbox: queued with the event or not at all; one push per change; only the latest state is sent."""

import json
import uuid

import psycopg
import pytest

from consentvault.sync.errors import OutboxError, OutboxTransactionError
from consentvault.sync.outbox import (PAYLOAD_COLUMN, StateChange, build_body, decrypt_payload,
                                      enqueue_event_pushes)
from consentvault.tenancy.keys_protocol import WrappedKey
from consentvault.tenancy.tokens import org_transaction

from .support import PHONES

A_PHONE, B_PHONE = PHONES[0], PHONES[1]


def _open_payload(env, org, row) -> dict:
    with env.t.superuser() as su:
        ck = su.execute("SELECT wrapped_key, key_version FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                        (org.org_id, row["contact_fp"])).fetchone()
    key = env.t.crypto.open_contact_key(org.org_id, WrappedKey(bytes(ck["wrapped_key"]), ck["key_version"]))
    return json.loads(decrypt_payload(key, org.org_id, row["outbox_id"], bytes(row["payload_ct"])))


def test_a_grant_queues_one_push_per_connected_system(env):
    a = env.t.a
    env.add_system(a, "crm", contact_form="plaintext")
    env.add_system(a, "dialer", contact_form="fingerprint")
    ev, res = env.grant(a, A_PHONE)
    assert [(c.channel, c.purpose, c.version, c.state) for c in res.changes] == [("sms", "marketing", 1, "permitted")]
    assert len(res.queued) == 2
    rows = env.outbox(a)
    assert {r["status"] for r in rows} == {"pending"} and {r["version"] for r in rows} == {1}
    fp = env.fp(a, A_PHONE)
    bodies = {r["system_id"]: _open_payload(env, a, r) for r in rows}
    by_form = {env.q("SELECT contact_form FROM consentvault.connected_system WHERE system_id = %s",
                     (sid,))[0]["contact_form"]: b for sid, b in bodies.items()}
    assert by_form["plaintext"]["contact"] == A_PHONE
    assert by_form["fingerprint"]["contact"] == fp and A_PHONE not in json.dumps(by_form["fingerprint"])
    for b in bodies.values():
        assert b["org_id"] == str(a.org_id) and b["state"] == "permitted" and b["version"] == 1
        assert b["basis_event_id"] == ev.event_id and b["channel"] == "sms" and b["purpose"] == "marketing"
        assert b["reason"] == "grant" and b["at"].endswith("Z")


def test_the_payload_is_a_ciphertext_under_the_contacts_key(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, A_PHONE)
    row = env.outbox(a)[0]
    assert A_PHONE.encode() not in bytes(row["payload_ct"]) and b"permitted" not in bytes(row["payload_ct"])
    from consentvault.tenancy.errors import FieldDecryptError
    from consentvault.tenancy import crypto as tc
    with env.t.superuser() as su:
        ck = su.execute("SELECT wrapped_key, key_version FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                        (a.org_id, row["contact_fp"])).fetchone()
    key = env.t.crypto.open_contact_key(a.org_id, WrappedKey(bytes(ck["wrapped_key"]), ck["key_version"]))
    with pytest.raises(FieldDecryptError):  # bound to this row: a copy under another row or column fails
        tc.decrypt_field(key, a.org_id, str(uuid.uuid4()), PAYLOAD_COLUMN, bytes(row["payload_ct"]))
    with pytest.raises(FieldDecryptError):
        tc.decrypt_field(key, env.t.b.org_id, str(row["outbox_id"]), PAYLOAD_COLUMN, bytes(row["payload_ct"]))


def test_the_hook_refuses_to_run_outside_a_transaction(env):
    a = env.t.a
    ev, _ = env.grant(a, A_PHONE, hook=False)
    key = None
    with env.t.app() as app:
        with pytest.raises(OutboxTransactionError, match="inside the transaction"):
            enqueue_event_pushes(app, event_id=ev.event_id, contact_fp=env.fp(a, A_PHONE), contact=A_PHONE,
                                 data_key=b"k" * 32)
    assert key is None and env.outbox(a) == []


def test_the_event_and_its_pushes_commit_together_or_not_at_all(env):
    a = env.t.a
    env.add_system(a, "crm")

    class Boom(Exception):
        pass

    with pytest.raises(Boom):
        with env.t.app() as app, org_transaction(app, env.t.token(a, scopes=("capture",))):
            from consentvault.ledger import record_tenant_event
            from consentvault.sync.signals import ensure_contact_key
            # the ledger writer runs the hook inside its own transaction (integration pass), so the pushes are on ev
            ev = record_tenant_event(app, env.t.crypto, contact=A_PHONE, event_type="grant", channels=["sms"],
                                     purposes=["marketing"], method="checkbox", origin="consumer",
                                     disclosure_sha256=a.disclosure)
            assert len(ev.pushes.queued) == 1
            raise Boom()  # anything after the hook (a later write of the capture) fails
    assert env.outbox(a) == []
    assert env.q("SELECT 1 FROM consentvault.event WHERE org_id = %s AND contact_fp = %s",
                 (a.org_id, env.fp(a, A_PHONE))) == []
    # scoped to this contact: the harness's own events now advance state through the writer's hook (integration pass)
    assert env.q("SELECT 1 FROM consentvault.state_version WHERE org_id = %s AND contact_fp = %s",
                 (a.org_id, env.fp(a, A_PHONE))) == []


def test_a_failed_enqueue_rolls_the_event_back_with_a_named_error(env):
    a = env.t.a
    env.add_system(a, "crm")
    with pytest.raises(OutboxError, match="could not be queued"):
        with env.t.app() as app, org_transaction(app, env.t.token(a, scopes=("capture",))):
            from consentvault.ledger import record_tenant_event
            ev = record_tenant_event(app, env.t.crypto, contact=A_PHONE, event_type="grant", channels=["sms"],
                                     purposes=["marketing"], method="checkbox", origin="consumer",
                                     disclosure_sha256=a.disclosure)
            enqueue_event_pushes(app, event_id=ev.event_id, contact_fp="f" * 64, contact=A_PHONE, data_key=b"k" * 32)
    assert env.q("SELECT 1 FROM consentvault.event WHERE org_id = %s AND contact_fp = %s",
                 (a.org_id, env.fp(a, A_PHONE))) == []


def test_a_change_that_does_not_move_the_state_queues_nothing(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, A_PHONE)
    _, again = env.grant(a, A_PHONE)  # permitted already
    assert again.changes == () and again.queued == ()
    _, stop = env.stop(a, A_PHONE)
    assert [c.version for c in stop.changes] == [2]
    _, stop2 = env.stop(a, A_PHONE)  # denied already
    assert stop2.changes == () and stop2.queued == ()
    assert [(r["version"], r["status"]) for r in env.outbox(a)] == [(1, "superseded"), (2, "pending")]


def test_the_next_version_supersedes_a_push_nobody_started(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, A_PHONE)
    env.stop(a, A_PHONE)
    rows = env.outbox(a)
    assert [(r["version"], r["status"]) for r in rows] == [(1, "superseded"), (2, "pending")]
    assert rows[0]["finished_at"] is not None and rows[0]["next_attempt_at"] is None
    env.worker_sent = env.run_worker()
    sent = env.transport.sent
    assert len(sent) == 1 and json.loads(sent[0].body)["state"] == "denied"  # the stale "permitted" never leaves


def test_a_push_in_flight_is_not_superseded_and_the_newer_one_waits(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, A_PHONE)
    with env.worker_conn() as w:
        token = env.dispatch(w, a)
        with org_transaction(w, token):
            claimed = w.execute("SELECT * FROM consentvault.sync_claim(10, 60)").fetchall()
    assert len(claimed) == 1
    env.stop(a, A_PHONE)
    assert [(r["version"], r["status"]) for r in env.outbox(a)] == [(1, "sent"), (2, "pending")]


def test_the_all_purposes_stop_moves_every_purpose_the_person_has(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, A_PHONE)
    wording = env.register_wording(a, "alpha: service texts about your order.", purposes=["servicing"])
    env.grant(a, A_PHONE, purposes=["servicing"], disclosure_sha256=wording)
    _, res = env.stop(a, A_PHONE, purposes=["*"])
    moved = {(c.purpose, c.version, c.state) for c in res.changes}
    assert moved == {("marketing", 2, "denied"), ("servicing", 2, "denied"), ("*", 1, "denied")}


def test_a_stop_by_one_person_never_queues_anything_for_another(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, A_PHONE)
    env.grant(a, B_PHONE)
    env.stop(a, A_PHONE)
    assert {r["contact_fp"] for r in env.outbox(a)} == {env.fp(a, A_PHONE), env.fp(a, B_PHONE)}
    assert [r["version"] for r in env.outbox(a, contact_fp=env.fp(a, B_PHONE))] == [1]


def test_an_unverified_consumer_grant_after_a_stop_does_not_lift_it_and_queues_nothing(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, A_PHONE)
    env.stop(a, A_PHONE)
    _, res = env.grant(a, A_PHONE)  # a web checkbox alone proves nothing about who holds the number
    assert res.changes == () and res.queued == ()


def test_a_hard_stop_is_not_lifted_by_a_later_grant(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, A_PHONE)
    env.record(a, A_PHONE, "suppress", method="staff", origin="staff")
    _, res = env.grant(a, A_PHONE)
    assert res.changes == ()


def test_the_enqueue_function_refuses_a_state_this_transaction_did_not_advance(env):
    a = env.t.a
    env.add_system(a, "crm")
    env.grant(a, A_PHONE)
    sid = env.outbox(a)[0]["system_id"]
    fp = env.fp(a, A_PHONE)
    with env.t.app() as app:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="was not advanced by this transaction"):
            with org_transaction(app, env.t.token(a, scopes=("capture",))):
                app.execute("SELECT consentvault.sync_enqueue(%s, %s, %s, 'sms', 'marketing', 1, %s)",
                            (uuid.uuid4(), sid, fp, b"forged"))
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):  # an invented future version
            with org_transaction(app, env.t.token(a, scopes=("capture",))):
                app.execute("SELECT consentvault.sync_enqueue(%s, %s, %s, 'sms', 'marketing', 9, %s)",
                            (uuid.uuid4(), sid, fp, b"forged"))
    assert len(env.outbox(a)) == 1


def test_queuing_the_same_push_twice_in_one_transaction_is_one_row(env):
    a = env.t.a
    env.add_system(a, "crm")
    with env.t.app() as app, org_transaction(app, env.t.token(a, scopes=("capture",))):
        from consentvault.ledger import record_tenant_event
        ev = record_tenant_event(app, env.t.crypto, contact=A_PHONE, event_type="grant", channels=["sms"],
                                 purposes=["marketing"], method="checkbox", origin="consumer",
                                 disclosure_sha256=a.disclosure)
        fp = env.fp(a, A_PHONE)
        # the writer's own hook advanced the state and queued the first push (integration pass); a second queue of
        # the same version in the same transaction is a no-op
        assert [c.version for c in ev.pushes.changes] == [1] and len(ev.pushes.queued) == 1
        first = ev.pushes.queued[0].outbox_id
        sid = app.execute("SELECT system_id FROM consentvault.sync_targets()").fetchone()["system_id"]
        second = app.execute("SELECT consentvault.sync_enqueue(%s, %s, %s, 'sms', 'marketing', 1, %s) AS id",
                             (uuid.uuid4(), sid, fp, b"y")).fetchone()["id"]
    assert first is not None and second is None
    assert len(env.outbox(a)) == 1


def test_the_advance_function_refuses_an_event_for_another_contact(env):
    a = env.t.a
    ev, _ = env.grant(a, A_PHONE, hook=False)
    with env.t.app() as app, org_transaction(app, env.t.token(a, scopes=("capture",))):
        with pytest.raises(psycopg.errors.InvalidParameterValue, match="not for that contact"):
            app.execute("SELECT * FROM consentvault.sync_advance_state(%s, %s)", (ev.event_id, env.fp(a, B_PHONE)))


def test_build_body_is_canonical_and_names_only_what_the_contract_lists(env):
    from datetime import datetime, timezone
    change = StateChange("sms", "marketing", 3, "denied", str(uuid.uuid4()), "revoke",
                         datetime(2026, 10, 29, 12, 0, 0, 123000, tzinfo=timezone.utc))
    body = build_body(org_id=env.t.a.org_id, contact="+15555552001", contact_fp="a" * 64, contact_form="plaintext",
                      change=change)
    parsed = json.loads(body)
    assert sorted(parsed) == ["at", "basis_event_id", "channel", "contact", "org_id", "purpose", "reason", "state", "version"]
    assert parsed["at"] == "2026-10-29T12:00:00.123Z"
    assert body == json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(OutboxError):
        build_body(org_id=env.t.a.org_id, contact="x", contact_fp="a" * 64, contact_form="carrier-pigeon", change=change)
