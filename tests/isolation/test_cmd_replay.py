"""``consentvault replay-sweep``: the scheduled job that removes expired nonces from the replay guard."""

import json
from datetime import datetime, timedelta, timezone

from consentvault import cli
from consentvault.tenancy.replay import claim_nonce

from isolation.harness import make_login_role


def test_the_sweep_is_a_registered_command_and_removes_only_expired_nonces(tenancy, pg_server, monkeypatch, capsys):
    cli.build_parser()
    assert "replay-sweep" in cli.REGISTRY
    soon = datetime.now(timezone.utc) + timedelta(minutes=5)
    with tenancy.app() as app:
        claim_nonce(app, tenancy.a.org_id, "live-nonce-0002", soon)
    with tenancy.superuser() as owner:
        owner.execute("INSERT INTO consentvault.replay_guard (org_id, nonce, expires_at)"
                      " VALUES (%s, 'stale-nonce-0002', now() - interval '2 hours')", (tenancy.a.org_id,))
    worker_dsn = make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker")
    monkeypatch.setenv("CONSENTVAULT_DSN", worker_dsn)
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    assert cli.main(["replay-sweep"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out) == {"swept": 1}
    with tenancy.superuser() as owner:
        assert [r["nonce"] for r in owner.execute("SELECT nonce FROM consentvault.replay_guard"
                                                  " WHERE nonce LIKE '%-nonce-0002'")] == ["live-nonce-0002"]


def test_the_sweep_on_the_wrong_login_exits_2_never_0(tenancy, monkeypatch, capsys):
    cli.build_parser()
    monkeypatch.setenv("CONSENTVAULT_DSN", tenancy.app_dsn)  # the runtime login holds no right to sweep
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    assert cli.main(["replay-sweep"]) == 2
    assert capsys.readouterr().out.strip() == ""


def test_the_replay_sweep_job_runs_the_command(monkeypatch):
    from consentvault import jobs

    seen = []
    monkeypatch.setattr(cli, "main", lambda argv: seen.append(list(argv)) or 0)
    assert jobs.main(["replay-sweep"]) == 0 and seen == [["replay-sweep"]]
