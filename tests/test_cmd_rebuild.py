"""``consentvault projection-rebuild`` is the command and the scheduled job that runs the one door's rebuild: it projects every
stored post that has no event, and an error leaves the post unfinished with exit 2, named in the summary, with the attempt recorded on it (never stored as refused)."""

import json
import time

import psycopg
import pytest

from consentvault import api, cli, door
from consentvault.errors import LedgerError
from test_api import PURPOSES, SECRET, TOKEN, VERIFIED_SECRET, _call, _serve


def _store_a_stop_whose_projection_crashed(app_dsn, contact):
    settings = api.ApiSettings(dsn=app_dsn, secret=SECRET, token=TOKEN, purposes=PURPOSES, verified_secret=VERIFIED_SECRET,
                               default_region="US")
    gen = _serve(settings)
    base = next(gen)
    body = json.dumps({"contact": contact, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"],
                       "method": "keyword", "origin": "consumer"}).encode()
    ts = str(int(time.time()))
    headers = {"Content-Type": "application/json", api.TIMESTAMP_HEADER: ts, api.SIGNATURE_HEADER: api.sign(SECRET, ts, body)}
    with pytest.MonkeyPatch.context() as m:
        def crash(*a, **k):
            raise RuntimeError("crash between the answer and the projection")
        m.setattr(door, "project_post", crash)
        status, _, _ = _call(base + "/v1/events", "POST", body, headers)
        base.settle()
    gen.close()
    assert status == 201


def _revokes(conn):
    return conn.execute("SELECT count(*) AS n FROM consentvault.event WHERE event_type='revoke'").fetchone()["n"]


def test_the_command_projects_a_stored_post_that_has_no_event_and_a_second_run_changes_nothing(dsn, app_dsn, conn, monkeypatch, capsys):
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_DEFAULT_REGION", "US")
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    _store_a_stop_whose_projection_crashed(app_dsn, "+12125550121")
    assert _revokes(conn) == 0
    assert cli.main(["projection-rebuild"]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["events"] == 1 and _revokes(conn) == 1
    assert cli.main(["projection-rebuild"]) == 0 and _revokes(conn) == 1


def test_an_error_leaves_the_post_unfinished_with_exit_2_named_and_the_next_run_finishes_it(dsn, app_dsn, conn, monkeypatch, capsys):
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_DEFAULT_REGION", "US")
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    _store_a_stop_whose_projection_crashed(app_dsn, "+12125550122")
    real = door.record_event
    def flaky(*a, **k):
        try:
            raise psycopg.errors.SerializationFailure("could not serialize")
        except psycopg.Error as exc:
            raise LedgerError("event refused by the database") from exc
    monkeypatch.setattr(door, "record_event", flaky)
    assert cli.main(["projection-rebuild"]) == 2
    assert _revokes(conn) == 0
    summary = json.loads(capsys.readouterr().out.splitlines()[-1])
    post = conn.execute("SELECT post_id::text AS p FROM consentvault.raw_post").fetchone()["p"]
    assert summary["unfinished"] == 1 and summary["unfinished_posts"] == [{"post": post, "error": "LedgerError:SerializationFailure"}]
    assert conn.execute("SELECT count(*) AS n FROM consentvault.raw_post_fact WHERE name = 'event_not_derived'").fetchone()["n"] == 0
    attempt, = conn.execute("SELECT code_version, error_class, attempted_at FROM consentvault.projection_attempt").fetchall()
    assert (attempt["code_version"], attempt["error_class"]) == (door.CODE_VERSION, "LedgerError:SerializationFailure")
    assert attempt["attempted_at"] is not None
    monkeypatch.setattr(door, "record_event", real)
    assert cli.main(["projection-rebuild"]) == 0 and _revokes(conn) == 1


def test_two_runs_at_once_do_not_both_project(dsn, app_dsn, conn, monkeypatch, capsys):
    monkeypatch.setenv("CONSENTVAULT_DSN", dsn)
    monkeypatch.setenv("CONSENTVAULT_DEFAULT_REGION", "US")
    monkeypatch.setenv("CONSENTVAULT_PURPOSES", "marketing")
    _store_a_stop_whose_projection_crashed(app_dsn, "+12125550123")
    holder = psycopg.connect(dsn, autocommit=True)
    try:
        assert holder.execute("SELECT pg_try_advisory_lock(hashtext('consentvault.projection-rebuild'))").fetchone()[0]
        assert cli.main(["projection-rebuild"]) != 0
        assert "another projection-rebuild is running" in capsys.readouterr().err
        assert _revokes(conn) == 0
    finally:
        holder.close()
    assert cli.main(["projection-rebuild"]) == 0 and _revokes(conn) == 1
