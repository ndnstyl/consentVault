"""An edge-forwarded browser capture is always a consumer capture: a public browser can never label a record as staff,
import or regulatory."""

import pytest

from isolation.harness import build_tenancy
from isolation.test_hardening_wave2 import _edge_body, _edge_post, _events_of, _site_key, hw  # noqa: F401


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


@pytest.mark.parametrize("origin", ["staff", "import", "regulatory"])
def test_a_forbidden_origin_through_the_edge_is_refused_by_name(hw, origin):
    a = hw.cloud.a
    key = _site_key(hw, a)
    before = len(_events_of(hw, a.org))
    status, body = _edge_post(hw, _edge_body(a, key, origin=origin))
    assert (status, body["error"]) == (403, "role_not_allowed")
    assert len(_events_of(hw, a.org)) == before


@pytest.mark.parametrize("method", ["staff", "import"])
def test_a_staff_or_import_method_through_the_edge_is_refused(hw, method):
    a = hw.cloud.a
    key = _site_key(hw, a)
    status, body = _edge_post(hw, _edge_body(a, key, method=method))
    assert (status, body["error"]) == (403, "role_not_allowed")


def test_a_consumer_or_unlabelled_edge_capture_is_recorded_as_consumer(hw):
    a = hw.cloud.a
    key = _site_key(hw, a)
    body = _edge_body(a, key)
    del body["origin"]
    status, answer = _edge_post(hw, body)
    assert status == 201, answer
    with hw.t.superuser() as su:
        row = su.execute("SELECT origin FROM consentvault.event WHERE event_id = %s", (answer["event_id"],)).fetchone()
    assert row["origin"] == "consumer"
