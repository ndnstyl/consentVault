"""The single-company live HTTP path gives the projection the post's stored arrival (one-door review round 5, gate 3)."""

import json
import time

from consentvault import api, door
from test_api import SECRET, TOKEN, VERIFIED_SECRET, PURPOSES, _call, _serve


def test_the_live_view_has_the_stored_arrival(app_dsn, monkeypatch):
    seen = []
    real = door.project_post

    def spy(writer, conn, enter, backend, view, **k):
        seen.append(view.arrived_epoch)
        return real(writer, conn, enter, backend, view, **k)

    monkeypatch.setattr(door, "project_post", spy)
    s = api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, verified_secret=VERIFIED_SECRET, default_region="US")
    gen = _serve(s)
    base = next(gen)
    body = json.dumps({"contact": "+12125550166", "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
                       "method": "keyword", "origin": "consumer"}).encode()
    ts = str(int(time.time()))
    _call(base + "/v1/events", "POST", body, {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts,
                                              api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)})
    base.settle()
    gen.close()
    assert seen and all(e is not None for e in seen)
