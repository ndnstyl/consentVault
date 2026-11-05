"""Settings travel with the post (the one door, class E): the region and purposes a post is projected with are stored beside it
when it is taken in, so whichever process projects it later (the server, the rebuild job, a command line run) gives one answer."""

import json
import time

import pytest

from consentvault import api, door
from test_api import PURPOSES, SECRET, TOKEN, VERIFIED_SECRET, _call, _serve


def _settings(app_dsn):
    return api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, verified_secret=VERIFIED_SECRET,
                           default_region="US")


def _signed(payload):
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    return body, {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}


def test_a_post_is_projected_with_the_settings_stored_beside_it_whoever_runs_the_projection(app_dsn, conn, disclosure):
    gen = _serve(_settings(app_dsn)); base = next(gen)
    grant = {"contact": "+12125550117", "event_type": "grant", "channels": ["sms"], "purposes": ["marketing"],
             "method": "checkbox", "origin": "consumer", "checked": True, "disclosure_sha256": disclosure}
    with pytest.MonkeyPatch.context() as m:
        def crash(*a, **k):
            raise RuntimeError("crash between the answer and the projection")
        m.setattr(door, "project_post", crash)
        s1, _, _ = _call(base + "/v1/events", "POST", *_signed(grant)); base.settle()
    gen.close()
    # a runner with a narrower purpose list and another region (a command line run) projects the post the server stored
    door.rebuild(conn, backend=door.SingleBackend("GB", ("billing",)))
    assert s1 == 201
    assert conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type='grant'").fetchone()["n"] == 1
