"""An event is placed by the earliest post that carries its request key (one-door.md, addendum point 4). Which copy of one signed
request the projection reaches first no longer matters: a replay from empty places the event at the first copy's arrival too.
Reproduces the third review round's duplicate-copy finding: copy A faults, the later copy B projects, and the event used to sit at
B's arrival."""

import json
import time

import psycopg

from consentvault import api, door
from consentvault.rawpost import request_key_digest
from test_api import SECRET, TOKEN, VERIFIED_SECRET, PURPOSES, _call, _serve


def _settings(app_dsn):
    return api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, verified_secret=VERIFIED_SECRET, default_region="US")


def _signed(payload):
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    return body, {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}


def stop(c):
    return {"contact": c, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", "origin": "consumer"}


def _posts(conn):
    return [r["post_id"] for r in conn.execute("SELECT post_id::text AS post_id FROM consentvault.raw_post WHERE kind='post' ORDER BY seq").fetchall()]


def _n(conn, c):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type='revoke' AND contact_norm=%s", (c,)).fetchone()["n"]


def test_the_event_sits_at_the_earliest_copys_arrival_whichever_copy_projected_first(app_dsn, conn, monkeypatch):
    bad = set()
    real = door.read_view

    def flaky(writer, c, org, post_id, *a, **k):
        if post_id in bad:
            raise psycopg.errors.SerializationFailure("x")
        return real(writer, c, org, post_id, *a, **k)

    gen = _serve(_settings(app_dsn))
    base = next(gen)
    body_a, headers_a = _signed(stop("+12125550181"))
    monkeypatch.setattr(door, "read_view", flaky)
    real_pp = door.project_post
    monkeypatch.setattr(door, "project_post", lambda *a, **k: door.Outcome("x", reason="skipped", retry=True))   # crash after the store
    _call(base + "/v1/events", "POST", body_a, headers_a)
    base.settle()
    monkeypatch.setattr(door, "project_post", real_pp)
    a_id = _posts(conn)[-1]
    bad.add(a_id)   # copy A: its read keeps faulting
    time.sleep(1.2)
    _call(base + "/v1/events", "POST", body_a, headers_a)   # copy B: the same signed request resent
    base.settle()
    _call(base + "/v1/events", "POST", *_signed(stop("+12125550182")))
    base.settle()
    gen.close()
    a_post, b_post = _posts(conn)[0], _posts(conn)[1]
    assert a_post == a_id and b_post != a_id

    keys = conn.execute("SELECT post_id::text AS p, request_key FROM consentvault.raw_post_request ORDER BY post_id").fetchall()
    assert len({r["request_key"] for r in keys if r["p"] in (a_post, b_post)}) == 1   # both copies carry one key, as a column of their own

    monkeypatch.setattr(door, "HALT_CAP_SECONDS", 0)
    door.rebuild(conn)   # A faults, B (the copy) projects and the stop for Y goes ahead
    assert (_n(conn, "+12125550181"), _n(conn, "+12125550182")) == (1, 1)
    event = conn.execute("SELECT e.org_id, e.event_id, e.received_at, s.post_id::text AS cited FROM consentvault.event e"
                         " JOIN consentvault.event_source_post s ON s.event_id = e.event_id AND s.role = 'trigger'"
                         " WHERE e.contact_norm = '+12125550181'").fetchone()
    arrived = {r["p"]: r for r in conn.execute("SELECT post_id::text AS p, received_at, seq FROM consentvault.raw_post").fetchall()}
    assert event["cited"] == b_post   # the copy whose bytes were read made the event
    assert conn.execute("SELECT consentvault.arrival_at(%s, %s, %s) AS t, consentvault.arrival_post_seq(%s, %s) AS s",
                        (event["org_id"], event["event_id"], event["received_at"], event["org_id"], event["event_id"])
                        ).fetchone() == {"t": arrived[a_post]["received_at"], "s": arrived[a_post]["seq"]}   # but it sits where copy A arrived

    bad.clear()
    door.rebuild(conn)   # the fault is gone: copy A is the request seen before; nothing changes
    assert _n(conn, "+12125550181") == 1
    facts = conn.execute("SELECT o.post_id::text AS p, o.outcome AS name FROM consentvault.projection_outcome o").fetchall()
    assert (a_post, "event_not_derived") in {(r["p"], r["name"]) for r in facts}


def test_the_request_key_of_a_post_stored_before_the_column_is_backfilled_from_its_stored_facts(conn):
    from consentvault.rawpost import Fact, RawPostWriter, RawRequest

    writer = RawPostWriter()
    stored = writer.write(conn, None, RawRequest(intake="api", method="POST", path="/v1/events", query="", headers=(),
                                                  body=b"{}", facts=(Fact("vault", "request_key", "sig:abc"),)))
    assert conn.execute("SELECT request_key FROM consentvault.raw_post_request WHERE post_id = %s", (stored.post_id,)
                        ).fetchall() == [{"request_key": request_key_digest("sig:abc")}]   # the writer records it with the post
    old = writer.write(conn, None, RawRequest(intake="api", method="POST", path="/v1/events", query="", headers=(), body=b"{}"))
    conn.execute("INSERT INTO consentvault.raw_post_fact (org_id, post_id, fact_id, source, name, value_ct)"
                 " VALUES (%s, %s, gen_random_uuid(), 'vault', 'request_key', %s)", (old.org_id, old.post_id, b'"sig:old"'))
    assert conn.execute("SELECT count(*) AS n FROM consentvault.raw_post_request WHERE post_id = %s", (old.post_id,)).fetchone()["n"] == 0
    assert door.backfill_request_keys(writer, conn, None) == 1
    assert conn.execute("SELECT request_key FROM consentvault.raw_post_request WHERE post_id = %s", (old.post_id,)
                        ).fetchall() == [{"request_key": request_key_digest("sig:old")}]
    assert door.backfill_request_keys(writer, conn, None) == 0   # nothing left to record, and running it again changes nothing
