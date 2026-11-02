"""The gag-safety migration's down file: refuses while an emergency access under a gag is recorded, otherwise reverses
the grants, the policy and the functions cleanly."""

import os
from datetime import datetime, timezone

import psycopg
import pytest

from consentvault import db
from consentvault.tenancy import legal_process

from .support import OPERATOR

DOWN = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "down", "0018_gag_safety.sql")


def _down(super_dsn):
    with psycopg.connect(super_dsn, autocommit=True) as su:
        su.execute(open(DOWN, encoding="utf-8").read())


def test_the_down_file_refuses_while_an_emergency_access_under_a_gag_is_recorded(env):
    t = env.t
    with env.operator() as c:
        p = legal_process.log_legal_process(
            c, token_key=t.key, ledger=env.ledger, custody=env.custody, crypto=t.crypto, operator_id=OPERATOR,
            request_id="req-lp", org_id=t.a.org_id, type="court_order", received_at=datetime.now(timezone.utc),
            received_via="email", requester="a court", scope_summary="records", hold_scope=None)
        legal_process.record_customer_notice(c, token_key=t.key, notifier=env.notifier, operator_id=OPERATOR,
                                             request_id="req-n", org_id=t.a.org_id, process_id=p["process_id"],
                                             prohibited_basis="sealed order")
        legal_process.open_operator_access(c, token_key=t.key, notifier=env.notifier, operator_id=OPERATOR,
                                           request_id="req-a", org_id=t.a.org_id, reason="x", emergency=True,
                                           legal_process_id=p["process_id"])
    with pytest.raises(psycopg.errors.RaiseException, match="emergency access under a gag"):
        _down(t.super_dsn)
    with db.connect(t.super_dsn) as su:
        assert su.execute("SELECT to_regprocedure('consentvault.hold_disclosure(uuid)') IS NOT NULL AS x").fetchone()["x"]


def test_the_down_file_reverses_an_empty_install(dsn, super_dsn):
    _down(super_dsn)
    with db.connect(super_dsn) as c:
        assert c.execute("SELECT to_regprocedure('consentvault.hold_disclosure(uuid)') AS x").fetchone()["x"] is None
        assert c.execute("SELECT count(*) n FROM pg_policies WHERE policyname = 'legal_hold_tenant_disclosed'"
                         ).fetchone()["n"] == 0
        assert c.execute("SELECT has_table_privilege('consentvault_app', 'consentvault.legal_hold', 'SELECT') AS x"
                         ).fetchone()["x"]
