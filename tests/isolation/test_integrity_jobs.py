"""Seal, verify-seals, verify-chain and anchor in multi-tenant mode run once per organisation, each under its own token
minted by the database just before that organisation is worked (``dispatch_org_ids``, ``dispatch_org_token``), as the dedicated integrity login (``consentvault_integrity``: the token
handout, the tenant entry, and the runtime role's read and seal/anchor writes on the evidence tables, nothing else).

A run that leaves any organisation unchecked is a failure that names the organisation id and nothing personal. An
organisation with an empty ledger is skipped by name by the anchor job, never counted as a failure. Without these loops a
multi-tenant job sees no rows under row security and exits clean having done nothing."""

from error_names import named, named_any  # noqa: F401
from datetime import datetime, timezone
import json

import psycopg
import pytest

from consentvault import cli, db, integrity
from consentvault.ledger import record_tenant_event
from consentvault.tenancy.tokens import org_transaction

from . import harness
from .harness import create_org, make_login_role

PHONE = "+15555550142"


def _events_only(t, org):
    """Two real ledger events per organisation, and nothing synthetic (no hand-made seal or anchor)."""
    from consentvault import disclosure as disc

    with t.app() as app, org_transaction(app, t.token(org)):
        org.disclosure = disc.register(app, f"{org.name}: texts about your account. Reply STOP to end.",
                                       f"{org.name}-form", "en", ["sms"], ["marketing"])
        g = record_tenant_event(app, t.crypto, contact=PHONE, event_type="grant", channels=["sms"],
                                purposes=["marketing"], method="checkbox", origin="consumer",
                                disclosure_sha256=org.disclosure, source_id=org.source_id, brand_ids=[org.brand_id])
        s = record_tenant_event(app, t.crypto, contact=PHONE, event_type="revoke", channels=["sms"],
                                purposes=["marketing"], method="keyword", origin="consumer")
        org.event_ids = [g.event_id, s.event_id]


@pytest.fixture
def two_orgs(dsn, pg_server, monkeypatch):
    monkeypatch.setattr(harness, "_populate", _events_only)
    t = harness.build_tenancy(dsn, pg_server["port"])
    dbname = dsn.rsplit("/", 1)[1]
    t.integrity_dsn = make_login_role(pg_server["port"], dbname, "consentvault_integrity")
    return t


@pytest.fixture
def tsa():
    import tempfile
    from pathlib import Path

    from consentvault import seal
    from test_seal import _TestTsa

    root = Path(tempfile.mkdtemp(prefix="consentvault-tsa-"))
    server = _TestTsa(root)
    mp = pytest.MonkeyPatch()
    mp.setenv(seal.ENV_CAFILE, str(server.cafile))
    yield server
    mp.undo()
    server.close()


def _seals(t, org):
    with t.superuser() as su:
        return su.execute("SELECT count(*) AS n FROM consentvault.seal WHERE org_id = %s", (org.org_id,)).fetchone()["n"]


def _tamper(t, org):
    """Change one stored field of the organisation's first event, out of band (a DBA bypassing the triggers)."""
    with psycopg.connect(t.super_dsn, autocommit=True) as su:
        su.execute("SET session_replication_role = replica")
        su.execute("UPDATE consentvault.event SET method = 'keyword' WHERE org_id = %s AND seq = 1", (org.org_id,))


def test_the_integrity_login_holds_exactly_its_grants(two_orgs):
    with db.connect(two_orgs.integrity_dsn) as c:
        assert c.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0  # no token, no rows
        assert {r["org_id"] for r in c.execute("SELECT o AS org_id FROM consentvault.dispatch_org_ids('seal') o")} >= {
            two_orgs.a.org_id, two_orgs.b.org_id}
        for forbidden in ("SELECT * FROM consentvault.contact_log", "SELECT * FROM consentvault.contact_key",
                          "SELECT * FROM consentvault.outbox", "SELECT * FROM consentvault.review",
                          "SELECT consentvault.sign_org_token(gen_random_uuid(), ARRAY['admin'], NULL, 60)",
                          "SELECT * FROM consentvault.alarm_relay_pending(1)"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                c.execute(forbidden)
            c.rollback() if not c.autocommit else None


def test_seal_and_verify_seals_cover_every_organisation(two_orgs, tsa):
    with db.connect(two_orgs.integrity_dsn) as c:
        sealed = integrity.seal_every_org(c, tsa.url, 100)
    assert {o: len(ids) for o, ids in sealed.items()} == {str(two_orgs.a.org_id): 2, str(two_orgs.b.org_id): 2,
                                                          **{k: 0 for k in sealed if k not in (str(two_orgs.a.org_id), str(two_orgs.b.org_id))}}
    assert _seals(two_orgs, two_orgs.a) == 2 and _seals(two_orgs, two_orgs.b) == 2
    with db.connect(two_orgs.integrity_dsn) as c:
        checked = integrity.verify_seals_every_org(c)
    assert checked[str(two_orgs.a.org_id)] == 2 and checked[str(two_orgs.b.org_id)] == 2


def test_verify_chain_covers_every_organisation_and_a_tampered_row_in_org_two_fails_the_run(two_orgs):
    with db.connect(two_orgs.integrity_dsn) as c:
        ok = integrity.verify_chain_every_org(c)
    assert ok[str(two_orgs.a.org_id)] == 2 and ok[str(two_orgs.b.org_id)] == 2
    _tamper(two_orgs, two_orgs.b)
    with db.connect(two_orgs.integrity_dsn) as c, pytest.raises(integrity.IntegrityRunError) as e:
        integrity.verify_chain_every_org(c)
    msg = str(e.value)
    assert str(two_orgs.b.org_id) in msg and str(two_orgs.a.org_id) not in msg
    assert PHONE not in msg and "row_hash_mismatch" in msg
    assert [f[0] for f in e.value.failures] == [str(two_orgs.b.org_id)]


def test_a_tampered_row_fails_verify_seals_by_organisation(two_orgs, tsa):
    with db.connect(two_orgs.integrity_dsn) as c:
        integrity.seal_every_org(c, tsa.url, 100)
    _tamper(two_orgs, two_orgs.b)
    with db.connect(two_orgs.integrity_dsn) as c, pytest.raises(integrity.IntegrityRunError) as e:
        integrity.verify_seals_every_org(c)
    assert [f[0] for f in e.value.failures] == [str(two_orgs.b.org_id)] and PHONE not in str(e.value)


def test_anchor_covers_every_organisation_and_skips_an_empty_one_by_name(two_orgs, tmp_path):
    with db.connect(two_orgs.operator_dsn) as op:
        empty = create_org(op, two_orgs.key, two_orgs.provider, "charlie")
    sink = str(tmp_path / "anchors.jsonl")
    with db.connect(two_orgs.integrity_dsn) as c:
        out = integrity.anchor_every_org(c, sink)
    assert out["anchored"][str(two_orgs.a.org_id)]["seq"] == 2 and out["anchored"][str(two_orgs.b.org_id)]["seq"] == 2
    assert str(empty.org_id) in out["skipped_empty"]
    lines = [json.loads(x) for x in open(sink, encoding="utf-8").read().splitlines()]
    assert {x.get("org_id") for x in lines} >= {str(two_orgs.a.org_id), str(two_orgs.b.org_id)}
    with db.connect(two_orgs.integrity_dsn) as c:  # the sink holds every org's anchors; each org checks only its own
        assert integrity.verify_chain_every_org(c, sink_file=sink)[str(two_orgs.a.org_id)] == 2


def test_one_failing_organisation_fails_the_run_after_the_others_ran(two_orgs, tmp_path):
    _tamper(two_orgs, two_orgs.a)
    sink = str(tmp_path / "anchors.jsonl")
    with db.connect(two_orgs.integrity_dsn) as c, pytest.raises(integrity.IntegrityRunError) as e:
        integrity.anchor_every_org(c, sink)
    assert [f[0] for f in e.value.failures] == [str(two_orgs.a.org_id)]
    assert e.value.results["anchored"][str(two_orgs.b.org_id)]["seq"] == 2


def test_the_cli_runs_the_per_organisation_loop_as_the_integrity_login_and_fails_loudly(two_orgs, monkeypatch, capsys):
    monkeypatch.setenv("CONSENTVAULT_DSN", two_orgs.integrity_dsn)
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    assert cli.main(["verify-chain"]) == cli.EXIT_OK
    got = capsys.readouterr()
    out = json.loads(got.out)
    assert out["ok"] is True and str(two_orgs.b.org_id) in out["orgs"]
    assert _emf(got.err.splitlines()) == {"VerifyChainFailures": 0}
    _tamper(two_orgs, two_orgs.b)
    assert cli.main(["verify-chain"]) == cli.EXIT_BROKEN
    got = capsys.readouterr()
    assert str(two_orgs.b.org_id) in got.out and named_any(got.err) and PHONE not in got.err + got.out  # the org is named in the report
    assert _emf(got.err.splitlines()) == {"VerifyChainFailures": 1}


def _emf(lines):
    """The embedded-metric lines a job printed: {metric name: value}."""
    found = {}
    for x in lines:
        if not x.startswith("{"):
            continue  # a human-readable message on the same stream
        doc = json.loads(x)
        if "_aws" in doc:
            [m] = doc["_aws"]["CloudWatchMetrics"][0]["Metrics"]
            assert set(doc) == {"_aws", m["Name"]}
            found[m["Name"]] = doc[m["Name"]]
    return found


def test_the_seal_and_verify_seals_jobs_emit_their_metrics(two_orgs, tsa, monkeypatch, capsys):
    monkeypatch.setenv("CONSENTVAULT_DSN", two_orgs.integrity_dsn)
    monkeypatch.setenv("CONSENTVAULT_TSA_URL", tsa.url)
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    with psycopg.connect(two_orgs.super_dsn, autocommit=True) as su:  # org one's oldest event waited two hours
        su.execute("SET session_replication_role = replica")
        su.execute("UPDATE consentvault.event SET received_at = now() - interval '2 hours', captured_at = now() - interval '2 hours' WHERE org_id = %s AND seq = 1",
                   (two_orgs.a.org_id,))
    assert cli.main(["seal", "--limit", "1"]) == cli.EXIT_OK
    age = _emf(capsys.readouterr().err.splitlines())["UnsealedOldestAgeSeconds"]
    assert 0 <= age < 7200  # org one's first event is sealed now; what still waits is younger
    assert cli.main(["seal"]) == cli.EXIT_OK
    assert _emf(capsys.readouterr().err.splitlines()) == {"UnsealedOldestAgeSeconds": 0}
    assert cli.main(["verify-seals"]) in (cli.EXIT_OK, cli.EXIT_BROKEN)
    got = _emf(capsys.readouterr().err.splitlines())
    assert set(got) == {"VerifySealsFailures"} and isinstance(got["VerifySealsFailures"], int)


# ---- multi-tenant mode refuses any other login (the reviewer's probe) -------------------------------------------------
@pytest.mark.parametrize("command", ["verify-chain", "verify-seals", "seal", "anchor"])
def test_in_multi_mode_a_login_outside_the_integrity_group_is_refused_never_a_clean_empty_run(
        two_orgs, monkeypatch, capsys, tmp_path, command):
    """The probe: org two tampered, the job run as the runtime login (not in the integrity group). Before the fix it saw
    no rows, exited 0 with ok: true and zero failures, and the runner sent a heartbeat. Now it exits 3 by name."""
    from consentvault import alarm_relay, jobs

    _tamper(two_orgs, two_orgs.b)
    monkeypatch.setenv("CONSENTVAULT_DSN", two_orgs.app_dsn)
    monkeypatch.setenv("CONSENTVAULT_TSA_URL", "http://127.0.0.1:9/")
    monkeypatch.setenv("CONSENTVAULT_ANCHOR_SINK", str(tmp_path / "anchors.jsonl"))
    monkeypatch.delenv("CONSENTVAULT_CONFIG", raising=False)
    monkeypatch.setattr(jobs, "_cloud", lambda env: True)  # the runner would send a heartbeat after a clean run
    monkeypatch.setattr(jobs, "_task_role_access", lambda env: pytest.fail("a heartbeat was attempted"))
    sent = []
    monkeypatch.setattr(alarm_relay, "_urllib_transport", lambda **kw: lambda *a: sent.append(a))
    rc = jobs.main([command])
    got = capsys.readouterr()
    assert rc == 3, got
    assert named("MultiTenantRefused", got.err) and "consentvault_integrity" not in got.err
    assert '"ok": true' not in got.out and sent == []
    assert _emf(got.err.splitlines()) == {}


# ---- the controls a revert would undo ---------------------------------------------------------------------------------
def test_a_failure_in_the_first_organisation_never_stops_the_later_ones(two_orgs):
    with db.connect(two_orgs.integrity_dsn) as c:
        order = [r["o"] for r in c.execute("SELECT o FROM consentvault.dispatch_org_ids('verify_chain') o")
                 if r["o"] in (two_orgs.a.org_id, two_orgs.b.org_id)]
    first, last = order[0], order[-1]
    org = two_orgs.a if first == two_orgs.a.org_id else two_orgs.b if first == two_orgs.b.org_id else None
    assert org is not None and first != last
    _tamper(two_orgs, org)
    with db.connect(two_orgs.integrity_dsn) as c, pytest.raises(integrity.IntegrityRunError) as e:
        integrity.verify_chain_every_org(c)
    assert [f[0] for f in e.value.failures] == [str(first)]
    assert str(last) in e.value.results, "the run stopped at the first failed organisation"


def test_a_worker_scoped_token_reads_no_evidence_for_a_login_outside_the_integrity_group(two_orgs):
    """The integrity scopes open the evidence read only with integrity-group membership (0048). The runtime login, with
    a token carrying the same scope, reads nothing."""
    from consentvault.tenancy.tokens import mint_org_token

    for scope in ("worker:verify_chain", "worker:seal", "worker:anchor", "worker:verify_seals"):
        tok = mint_org_token(two_orgs.key, two_orgs.a.org_id, [scope], credential_id=None)
        with two_orgs.app() as app, org_transaction(app, tok):
            assert app.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0, scope
    with db.connect(two_orgs.integrity_dsn) as c:  # and the integrity login, with its own token, does read
        tok = c.execute("SELECT consentvault.dispatch_org_token('verify_chain', %s) AS t",
                        (two_orgs.a.org_id,)).fetchone()["t"]
        with org_transaction(c, tok):
            assert c.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 2


INTEGRITY_TABLE_PRIVILEGES = {("chain_head", "INSERT"), ("chain_head", "SELECT"), ("event", "SELECT"),
                              ("seal", "INSERT"), ("seal", "SELECT"), ("unsealed_events", "SELECT")}
INTEGRITY_FUNCTIONS = {"consentvault.current_org()", "consentvault.current_token_scopes()",
                       "consentvault.dispatch_org_ids(text)", "consentvault.dispatch_org_token(text,uuid)",
                       "consentvault.enter_org(text)", "consentvault.home_org()", "consentvault.ledger_head()",
                       "consentvault.mark_seal_verified(uuid)", "consentvault.may_read_evidence()"}


def test_the_integrity_group_holds_exactly_its_privileges(two_orgs):
    with two_orgs.superuser() as su:
        tables = {(r["t"], r["p"]) for r in su.execute(
            "SELECT c.relname AS t, a.privilege_type AS p FROM pg_class c,"
            " aclexplode(c.relacl) a WHERE a.grantee = 'consentvault_integrity'::regrole")}
        columns = su.execute(
            "SELECT c.relname, t.attname FROM pg_attribute t JOIN pg_class c ON c.oid = t.attrelid,"
            " aclexplode(t.attacl) a WHERE a.grantee = 'consentvault_integrity'::regrole").fetchall()
        funcs = {r["f"].replace(", ", ",") for r in su.execute(
            "SELECT p.oid::regprocedure::text AS f FROM pg_proc p, aclexplode(p.proacl) a"
            " WHERE a.grantee = 'consentvault_integrity'::regrole")}
        schema = {r["p"] for r in su.execute(
            "SELECT a.privilege_type AS p FROM pg_namespace n, aclexplode(n.nspacl) a"
            " WHERE a.grantee = 'consentvault_integrity'::regrole")}
        member_of = {r["g"] for r in su.execute(
            "SELECT g.rolname AS g FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid"
            " WHERE m.member = 'consentvault_integrity'::regrole")}
    assert tables == INTEGRITY_TABLE_PRIVILEGES
    assert columns == [] and funcs == INTEGRITY_FUNCTIONS and schema == {"USAGE"} and member_of == set()


def test_an_organisation_closed_after_listing_fails_the_run_by_id(two_orgs, monkeypatch):
    """Closed between listing and minting its token: the token handout refuses it, and that is a failure of the run,
    never a quiet skip."""
    real = integrity._org_ids

    def list_then_close(conn, job):
        ids = real(conn, job)
        with psycopg.connect(two_orgs.super_dsn, autocommit=True) as su:
            su.execute("SET session_replication_role = replica")
            su.execute("UPDATE consentvault.organization SET status = 'closed' WHERE org_id = %s", (two_orgs.b.org_id,))
        return ids
    monkeypatch.setattr(integrity, "_org_ids", list_then_close)
    with db.connect(two_orgs.integrity_dsn) as c, pytest.raises(integrity.IntegrityRunError) as e:
        integrity.verify_chain_every_org(c)
    assert [f[0] for f in e.value.failures] == [str(two_orgs.b.org_id)]
    assert str(two_orgs.a.org_id) in e.value.results
