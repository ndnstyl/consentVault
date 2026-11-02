"""The erasure job: ``consentvault erasure-resume`` runs every confirmed erasure that waited for its stop pushes, then
writes the ledger commits. It is a scheduled job like seal and anchor; a missing setting is a named failure, never a
quiet run."""

from error_names import named, named_any  # noqa: F401
import json
import sys
import types

from consentvault import cli
from consentvault.tenancy import erasure

from isolation.harness import PHONE

from providers.test_plugins import GoodProvider

from .support import OPERATOR


def _waiting(env, monkeypatch):
    with env.admin(env.t.a) as ctx:
        eid = erasure.request_erasure(ctx, {"contact": PHONE, "reason": "asked"}, crypto=env.t.crypto)["erasure_id"]
    monkeypatch.setattr(erasure, "pending_pushes", lambda conn, fp: 1)
    with env.operator() as c:
        out = erasure.confirm_erasure(c, token_key=env.t.key, crypto=env.t.crypto, ledger=env.ledger, operator_id=OPERATOR,
                                      request_id="req-e", org_id=env.t.a.org_id, erasure_id=eid)
    monkeypatch.undo()
    assert out["status"] == "held"
    return eid


def _env(monkeypatch, env, tmp_path, **drop):
    mod = types.ModuleType("cv_erasure_plugin")
    mod.GoodProvider = GoodProvider
    monkeypatch.setitem(sys.modules, "cv_erasure_plugin", mod)
    key = tmp_path / "token.key"
    key.write_text(env.t.key.secret.hex(), encoding="utf-8")
    values = {"CONSENTVAULT_OPERATOR_DSN": env.t.operator_dsn, "CONSENTVAULT_TOKEN_KEY_ID": env.t.key.key_id,
              "CONSENTVAULT_KEY_PROVIDER": "cv_erasure_plugin:GoodProvider",
              "CONSENTVAULT_TOKEN_KEY_FILE": str(key), "CONSENTVAULT_LIFECYCLE_LEDGER_DIR": str(tmp_path / "archive")}
    for name, value in values.items():
        if name in drop:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)


def test_the_erasure_job_is_a_registered_command(env):
    parser = cli.build_parser()
    assert "erasure-resume" in cli.REGISTRY
    assert parser.parse_args(["erasure-resume"]).command == "erasure-resume"


def test_the_erasure_job_completes_a_waiting_erasure_and_writes_its_commit(env, monkeypatch, tmp_path, capsys):
    eid = _waiting(env, monkeypatch)
    _env(monkeypatch, env, tmp_path)
    assert cli.main(["erasure-resume"]) == cli.EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["completed"] == [eid]
    assert not env.key_present(env.t.a)
    kinds = [e["kind"] for e in env.ledger.entries(env.t.a.org_id)]
    assert kinds == ["erasure_intent", "erasure_commit"]


def test_the_erasure_job_without_its_token_key_fails_by_name(env, monkeypatch, tmp_path, capsys):
    _env(monkeypatch, env, tmp_path, CONSENTVAULT_TOKEN_KEY_FILE=True)
    assert cli.main(["erasure-resume"]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert named("ConfigError", err) and "CONSENTVAULT_TOKEN_KEY_FILE" not in err


def test_the_erasure_job_runs_on_the_operator_login_never_the_migration_login(env, monkeypatch, tmp_path, capsys):
    """Without the operator DSN the job refuses by name; a migration DSN alone is not a fallback."""
    _env(monkeypatch, env, tmp_path, CONSENTVAULT_OPERATOR_DSN=True)
    monkeypatch.setenv("CONSENTVAULT_OWNER_DSN", env.t.migrator_dsn)
    assert cli.main(["erasure-resume"]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert named("ConfigError", err) and "CONSENTVAULT_OPERATOR_DSN" not in err
