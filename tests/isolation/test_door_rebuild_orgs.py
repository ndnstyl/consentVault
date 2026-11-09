"""The multi-tenant rebuild, end to end over two organisations: one organisation's failure never ends the run for the others, the
failure is reported by name, and every projected post has its outcome recorded beside it (the catch-up's scope can append)."""

import pytest

from consentvault import api, door
from consentvault.errors import ConsentVaultError

from .cloud_harness import Cloud, facts_of, raw_posts
from .test_one_door_mixed_doors import _grant

CONTACT = "+12125550186"


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def _store_without_projecting(cloud, co, n):
    token = cloud.token(co, "capture")
    with pytest.MonkeyPatch.context() as m:
        def crash(*a, **k):
            raise RuntimeError("crash between the answer and the event")
        m.setattr(door, "project_post", crash)
        status, _ = cloud.call("/v1/events", _grant(co, CONTACT, n), token=token, headers={"X-ConsentVault-Request-Id": "r%d" % n})
        assert status == 201


def _events(cloud, org_id):
    with cloud.t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.event e WHERE e.org_id = %s AND EXISTS ("
                          " SELECT 1 FROM consentvault.event_source_post s WHERE s.event_id = e.event_id)", (org_id,)).fetchone()["n"]


def test_a_failing_organisation_does_not_stop_the_ones_after_it(cloud, monkeypatch):
    a, b = cloud.a, cloud.b
    _store_without_projecting(cloud, a, 1)
    _store_without_projecting(cloud, b, 2)
    real = door.project_pending
    calls = {"n": 0}

    def first_fails(*args, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("the first organisation's pass broke")
        return real(*args, **kw)
    monkeypatch.setattr(door, "project_pending", first_fails)
    failures: list = []
    outcomes: list = []
    api.rebuild_cloud(cloud.settings, [a.org.org_id, b.org.org_id], outcomes=outcomes, failures=failures)
    assert [str(f[0]) for f in failures] == [str(a.org.org_id)]
    assert _events(cloud, b.org.org_id) == 1 and _events(cloud, a.org.org_id) == 0
    with pytest.raises(ConsentVaultError):   # with no list to collect into, the run still ends loudly, after every organisation
        monkeypatch.setattr(door, "project_pending", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("broke")))
        api.rebuild_cloud(cloud.settings, [a.org.org_id, b.org.org_id])


def test_every_projected_post_has_its_outcome_recorded_beside_it(cloud):
    a = cloud.a
    _store_without_projecting(cloud, a, 3)
    api.rebuild_cloud(cloud.settings, [a.org.org_id])
    post = raw_posts(cloud.t, a.org.org_id)[-1]
    assert "event_derived" in facts_of(cloud.t, post)


def test_the_catch_up_before_a_new_post_records_the_outcome_of_the_earlier_post(cloud):
    a = cloud.a
    _store_without_projecting(cloud, a, 4)
    status, _ = cloud.call("/v1/events", _grant(a, "+12125550187", 5), token=cloud.token(a, "capture"),
                           headers={"X-ConsentVault-Request-Id": "r5"})
    assert status == 201
    first = raw_posts(cloud.t, a.org.org_id)[-2]
    assert "event_derived" in facts_of(cloud.t, first)


def _command_env(cloud, monkeypatch):
    from consentvault import cmd_cloud

    monkeypatch.setenv("CONSENTVAULT_DSN", cloud.t.app_dsn)
    monkeypatch.setenv("CONSENTVAULT_PROJECTION_DSN", cloud.t.projection_dsn)
    monkeypatch.setenv("CONSENTVAULT_OPERATOR_DSN", cloud.t.operator_dsn)
    monkeypatch.setattr(cmd_cloud, "build_cloud", lambda cfg, env: cloud.settings)


def test_the_command_runs_the_multi_tenant_path_end_to_end(cloud, monkeypatch, capsys):
    import json

    from consentvault import cli

    a, b = cloud.a, cloud.b
    _store_without_projecting(cloud, a, 6)
    _store_without_projecting(cloud, b, 7)
    _command_env(cloud, monkeypatch)
    assert cli.main(["projection-rebuild"]) == 0
    summary = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert summary["mode"] == "multi-tenant" and summary["events"] == 2 and summary["unfinished"] == 0
    assert _events(cloud, a.org.org_id) == 1 and _events(cloud, b.org.org_id) == 1


def _fails_for(org_id, real):
    def wrapper(writer, conn, enter, *args, **kw):
        with enter(conn) as entered:
            current = entered
        if str(current) == str(org_id):
            raise RuntimeError("this organisation's pass broke")
        return real(writer, conn, enter, *args, **kw)
    return wrapper


def test_the_command_goes_through_every_organisation_and_then_exits_non_zero_naming_the_one_that_failed(cloud, monkeypatch, capsys):
    from consentvault import cli

    a, b = cloud.a, cloud.b
    _store_without_projecting(cloud, a, 8)
    _store_without_projecting(cloud, b, 9)
    _command_env(cloud, monkeypatch)
    monkeypatch.setattr(door, "project_pending", _fails_for(a.org.org_id, door.project_pending))
    assert cli.main(["projection-rebuild"]) != 0
    err = capsys.readouterr().err
    assert str(a.org.org_id) in err and str(b.org.org_id) not in err
    assert _events(cloud, a.org.org_id) == 0 and _events(cloud, b.org.org_id) == 1
