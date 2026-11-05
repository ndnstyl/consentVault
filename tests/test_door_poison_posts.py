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

def _run(app_dsn, conn, poison, monkeypatch):
    monkeypatch.setattr(door, "HALT_CAP_SECONDS", 0)
    gen = _serve(_settings(app_dsn)); base = next(gen)
    s1, _, _ = _call(base + "/v1/events", "POST", *_signed(poison)); base.settle()
    s2, _, _ = _call(base + "/v1/events", "POST", *_signed(STOP)); base.settle()
    gen.close()
    errs = []
    for _ in range(2):
        try:
            outs = door.rebuild(conn)
            errs.append([(o.reason, o.retry, o.halts) for o in outs])
        except Exception as exc:
            errs.append("RAISED " + type(exc).__name__ + ": " + str(exc)[:120])
    n = _revokes(conn, "+12125550171")
    print("R2", s1, s2, "later stop revokes:", n, errs)
    return n

def test_type_poison_stalls_later_stop(app_dsn, conn, disclosure, monkeypatch):
    poison = {"contact": "+12125550170", "event_type": "grant", "channels": 5, "purposes": ["marketing"], "method": "checkbox",
              "origin": "consumer", "checked": True, "disclosure_sha256": disclosure}
    assert _run(app_dsn, conn, poison, monkeypatch) == 1

def test_index_size_poison_halts_later_stop(app_dsn, conn, monkeypatch):
    poison = dict(STOP, contact="+12125550172", subject_key=secrets.token_hex(6000))
    assert _run(app_dsn, conn, poison, monkeypatch) == 1
