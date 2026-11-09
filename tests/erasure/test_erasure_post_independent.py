"""Review finding 6 (pure projection, round one): the erasure stop stored as a post must not be able to abort the stop event."""

from isolation.cloud_harness import Cloud
from isolation.harness import PHONE

from .test_erasure import _confirm, _request


def test_a_failure_storing_the_erasure_stop_post_leaves_the_stop_event_written(env, tmp_path, monkeypatch):
    from consentvault import door

    c = Cloud(env.t, str(tmp_path / "evidence"))
    try:
        assert c.grant(c.a, PHONE)[0] == 201

        def boom(*a, **k):
            raise RuntimeError("the post store is down")

        monkeypatch.setattr(door, "store_erasure_stop_post", boom)
        req = _request(env, env.t.a, PHONE)
        assert _confirm(env, env.t.a, req["erasure_id"])["status"] == "completed"
        status, answer = c.gate(c.a, PHONE)
        assert status == 200 and any(s["event_type"] == "suppress" for s in answer["stops"]), "the stop event stands"
    finally:
        c.close()
