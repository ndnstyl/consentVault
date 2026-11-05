import json, time, secrets
from consentvault import api, door
from test_api import SECRET, TOKEN, VERIFIED_SECRET, PURPOSES, _call, _serve

def _settings(app_dsn):
    return api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, verified_secret=VERIFIED_SECRET,
                           default_region="US")

def _signed(payload):
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    return body, {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}

def _revokes(conn, contact):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type='revoke' AND contact_norm=%s", (contact,)).fetchone()["n"]

STOP = {"contact": "+12125550171", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword", "origin": "consumer"}

def _store_both(app_dsn, poison):
    gen = _serve(_settings(app_dsn)); base = next(gen)
    s1, _, _ = _call(base + "/v1/events", "POST", *_signed(poison)); base.settle()
    s2, _, _ = _call(base + "/v1/events", "POST", *_signed(STOP)); base.settle()
    gen.close()
    assert (s1, s2) == (201, 201)

def test_type_poison_is_the_readers_own_refusal_so_it_is_final_and_holds_nobody(app_dsn, conn, disclosure):
    poison = {"contact": "+12125550170", "event_type": "grant", "channels": 5, "purposes": ["marketing"], "method": "checkbox",
              "origin": "consumer", "checked": True, "disclosure_sha256": disclosure}
    _store_both(app_dsn, poison)
    door.rebuild(conn)
    assert _revokes(conn, "+12125550171") == 1
    door.rebuild(conn)
    assert _revokes(conn, "+12125550171") == 1

def test_index_size_poison_holds_the_stop_behind_it_for_the_bound_from_its_first_attempt_and_then_the_stop_goes_ahead(app_dsn, conn, monkeypatch):
    poison = dict(STOP, contact="+12125550172", subject_key=secrets.token_hex(6000))
    _store_both(app_dsn, poison)
    outs = door.rebuild(conn)   # the poison post fails at the database: no error is final, so it is unfinished and holds the stop
    assert _revokes(conn, "+12125550171") == 0
    assert [(o.retry, o.halts) for o in outs] == [(True, True), (True, False)]
    monkeypatch.setattr(door, "HALT_CAP_SECONDS", 0)   # the bound since its first attempt has run out
    outs = door.rebuild(conn)
    assert _revokes(conn, "+12125550171") == 1
    assert [o.retry for o in outs] == [True, False]
    door.rebuild(conn)
    assert _revokes(conn, "+12125550171") == 1
