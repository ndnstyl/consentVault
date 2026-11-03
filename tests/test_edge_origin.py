"""An edge-forwarded browser capture is always a consumer capture: a public browser can never label a record as staff,
import or regulatory, and what it says about its own origin or method is stored as sent and used for nothing."""

import json

import pytest

from isolation.harness import build_tenancy
from isolation.test_hardening_wave2 import _edge_body, _edge_post, _envelope, _events_of, _facts, _posts_of, _site_key, hw  # noqa: F401


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


def _last_event(hw, org):
    with hw.t.superuser() as su:
        return su.execute("SELECT origin, method FROM consentvault.event WHERE org_id = %s ORDER BY seq DESC LIMIT 1",
                          (org.org_id,)).fetchone()


@pytest.mark.parametrize("origin", ["staff", "import", "regulatory"])
def test_a_forbidden_origin_through_the_edge_is_stored_as_sent_and_the_event_is_a_consumer_one(hw, origin):
    a = hw.cloud.a
    key = _site_key(hw, a)
    status, body = _edge_post(hw, _envelope(key, _edge_body(a, key, origin=origin)))
    assert status == 201 and body["stored"] is True
    from isolation.cloud_harness import post_body
    assert json.loads(post_body(hw.t, _posts_of(hw, a.org)[-1]))["origin"] == origin
    assert _last_event(hw, a.org)["origin"] == "consumer"


@pytest.mark.parametrize("method", ["staff", "import"])
def test_a_staff_or_import_method_through_the_edge_is_stored_as_sent_and_the_event_is_a_checkbox_one(hw, method):
    a = hw.cloud.a
    key = _site_key(hw, a)
    status, body = _edge_post(hw, _envelope(key, _edge_body(a, key, method=method)))
    assert status == 201 and body["stored"] is True
    assert _last_event(hw, a.org)["method"] == "checkbox"


def test_a_consumer_or_unlabelled_edge_capture_is_recorded_as_consumer(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    status, answer = _edge_post(hw, _envelope(key, _edge_body(a, key)))
    assert status == 201, answer
    assert _last_event(hw, a.org)["origin"] == "consumer"
