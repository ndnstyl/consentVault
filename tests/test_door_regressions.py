import json, time
import psycopg
import pytest
from consentvault import api, door, rawpost, ledger
from consentvault.errors import LedgerError
from test_api import SECRET, TOKEN, VERIFIED_SECRET, PURPOSES, _call, _serve

def _settings(app_dsn):
    return api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, verified_secret=VERIFIED_SECRET,
                           default_region="US")

def _stop(contact="+12125550111"):
    body = json.dumps({"contact": contact, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
                       "method": "keyword", "origin": "consumer"}).encode()
    ts = str(int(time.time()))
    return body, {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}

def _revokes(conn):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type='revoke'").fetchone()["n"]

def _facts(conn):
    return [dict(r) for r in conn.execute("SELECT p.seq, o.outcome AS name FROM consentvault.raw_post p JOIN consentvault.projection_outcome o USING (org_id, post_id) ORDER BY p.seq")]

def test_a_store_failure_then_the_senders_retry_loses_the_stop(app_dsn, conn, monkeypatch):
    gen = _serve(_settings(app_dsn)); base = next(gen)
    body, headers = _stop()
    real = rawpost.RawPostWriter.write
    calls = {"n": 0}
    def flaky(self, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise rawpost.StoreUnavailable("disk hiccup")
        return real(self, *a, **k)
    monkeypatch.setattr(rawpost.RawPostWriter, "write", flaky)
    s1, a1, _ = _call(base + "/v1/events", "POST", body, headers); base.settle()
    s2, a2, _ = _call(base + "/v1/events", "POST", body, headers); base.settle()   # the sender retries the same request
    gen.close()
    door.rebuild(conn); door.rebuild(conn)
    print("REPRO-A", s1, s2, "revokes", _revokes(conn), _facts(conn))
    assert _revokes(conn) == 1

def test_a_transient_ledger_fault_is_never_projected_again(app_dsn, conn, monkeypatch):
    gen = _serve(_settings(app_dsn)); base = next(gen)
    body, headers = _stop("+12125550112")
    real = door.record_event
    calls = {"n": 0}
    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            try:
                raise psycopg.errors.SerializationFailure("could not serialize")
            except psycopg.Error as exc:
                raise LedgerError("event refused by the database") from exc
        return real(*a, **k)
    monkeypatch.setattr(door, "record_event", flaky)
    s1, _, _ = _call(base + "/v1/events", "POST", body, headers); base.settle()
    gen.close()
    door.rebuild(conn); door.rebuild(conn)
    print("REPRO-B", s1, "revokes", _revokes(conn), _facts(conn))
    assert _revokes(conn) == 1


def _signed(payload, age=0):
    body = json.dumps(payload).encode()
    ts = str(int(time.time()) - age)
    return body, {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}


def test_a_late_redelivered_stop_still_counts_but_a_late_grant_does_not(app_dsn, conn, disclosure):
    gen = _serve(_settings(app_dsn)); base = next(gen)
    stop = {"contact": "+12125550113", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
            "method": "keyword", "origin": "consumer"}
    grant = {"contact": "+12125550114", "event_type": "grant", "channels": ["sms"], "purposes": ["marketing"],
             "method": "checkbox", "origin": "consumer", "checked": True, "disclosure_sha256": disclosure}
    s1, _, _ = _call(base + "/v1/events", "POST", *_signed(stop, age=86400)); base.settle()
    s2, _, _ = _call(base + "/v1/events", "POST", *_signed(grant, age=86400)); base.settle()
    gen.close()
    door.rebuild(conn)
    assert (s1, s2) == (201, 201)
    assert _revokes(conn) == 1
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type='grant'").fetchone()["n"] == 0


def test_a_stop_signed_while_the_clock_read_failed_still_counts(app_dsn, conn, monkeypatch):
    from consentvault import dbclock
    gen = _serve(_settings(app_dsn)); base = next(gen)
    def down(_conn):
        raise psycopg.OperationalError("the clock read failed")
    monkeypatch.setattr(dbclock, "epoch", down)
    body, headers = _stop("+12125550115")
    s1, _, _ = _call(base + "/v1/events", "POST", body, headers); base.settle()
    gen.close()
    door.rebuild(conn)
    assert s1 == 201 and _revokes(conn) == 1


def test_every_projection_names_the_code_version_that_produced_it(app_dsn, conn):
    gen = _serve(_settings(app_dsn)); base = next(gen)
    body, headers = _stop("+12125550116")
    _call(base + "/v1/events", "POST", body, headers); base.settle()
    gen.close()
    door.rebuild(conn)
    versions = [r["n"] for r in conn.execute("SELECT count(*) AS n FROM consentvault.projection_outcome WHERE fold_code_version = %s", (door.CODE_VERSION,))]
    assert versions == [1]

