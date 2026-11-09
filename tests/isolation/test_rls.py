"""Row-level security, the narrow cross-organisation lookups, worker dispatch, composite keys and the replay guard."""

from error_names import db_codes
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from consentvault import db
from consentvault.errors import LedgerError
from consentvault.ledger import record_event
from consentvault.tenancy.errors import ReplayError, TenancyError
from consentvault.tenancy.replay import claim_nonce, sweep
from consentvault.tenancy.tokens import org_transaction

from .harness import FILLED_TABLES, PHONE, PLATFORM_TABLES, make_login_role, tenant_tables, tenant_views


def test_every_tenant_table_forces_row_level_security_bound_to_the_verified_tenant(tenancy):
    with tenancy.superuser() as owner:
        tables, views = tenant_tables(owner), tenant_views(owner)
        assert set(FILLED_TABLES) | {"contact_salt"} <= set(tables)  # the catalog read cannot silently shrink
        rows = {r["relname"]: r for r in owner.execute(
            "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c"
            " JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'consentvault' AND c.relname = ANY(%s)",
            (list(tables),))}
        assert set(rows) == set(tables)
        assert all(r["relrowsecurity"] and r["relforcerowsecurity"] for r in rows.values()), \
            [t for t, r in rows.items() if not (r["relrowsecurity"] and r["relforcerowsecurity"])]
        # every partition of a partitioned tenant table forces row-level security too (direct reads see nothing)
        parts = owner.execute(
            "SELECT c.relname, c.relrowsecurity AND c.relforcerowsecurity AS forced FROM pg_inherits i"
            " JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent"
            " JOIN pg_namespace n ON n.oid = p.relnamespace WHERE n.nspname = 'consentvault' AND p.relname = ANY(%s)",
            (list(tables),)).fetchall()
        assert all(r["forced"] for r in parts), parts
        policies = owner.execute("SELECT tablename, policyname, permissive, cmd, qual, with_check FROM pg_policies"
                                 " WHERE schemaname = 'consentvault'").fetchall()
        tenant = [p for p in policies if p["policyname"].endswith("_tenant")]
        # the reroute table (migration 0083) has no org_id: its tenant policy compares from_org, the original's organisation
        assert {p["tablename"] for p in tenant} - {"raw_post_reroute"} == set(tables)
        for p in tenant:
            assert p["permissive"] == "PERMISSIVE" and p["cmd"] == "ALL", p
            assert "current_org()" in p["qual"] and "current_org()" in p["with_check"], p
        scoped = {p["tablename"] for p in policies if p["policyname"].endswith("_read_scope")
                  and p["permissive"] == "RESTRICTIVE" and p["cmd"] == "SELECT" and "may_read_evidence" in p["qual"]}
        # the foundation's evidence tables plus the lanes' export jobs and gate decisions
        assert scoped == {"event", "contact_key", "contact_salt", "contact_log", "review", "export_job", "gate_decision",
                          "confirmation_send", "confirmation_connect_test", "confirmation_reply",
                          # the raw post store (migration 0067): the post, its key, facts, readings, links, seals and anchors
                          "raw_post", "raw_post_key", "raw_post_chain_head", "raw_post_fact", "raw_post_field",
                          "raw_post_match", "raw_post_seal", "event_source_post",
                          # a stop and the post that lifted it (migration 0069)
                          "stop_lift",
                          # the attempts the projection made on a post that did not project (migration 0077)
                          "projection_attempt",
                          # the request key beside the post that carries it (migration 0078)
                          "raw_post_request",
                          # the arrival a post stored again in its owner's organisation had the first time (migration 0079)
                          "raw_post_original_arrival",
                          # the history of a person, one row per stored post (migration 0084)
                          "post_history"}
        audit = {p["tablename"] for p in policies if p["policyname"].endswith("_read_scope")
                 and p["permissive"] == "RESTRICTIVE" and p["cmd"] == "SELECT" and "may_read_audit" in p["qual"]}
        assert audit == {"audit_event"}
        # a legal-process hold the customer has not been told of is no row the runtime role reads (gag safety)
        disclosed = {p["tablename"] for p in policies if p["policyname"].endswith("_disclosed")
                     and p["permissive"] == "RESTRICTIVE" and p["cmd"] == "SELECT"
                     and "legal_process_disclosed" in p["qual"]}
        assert disclosed == {"legal_hold"}
        # the contact record list: names open to an admin or a viewer only, the wrapped display key to its loader's scope only
        names = {p["tablename"]: p["qual"] for p in policies if p["policyname"].endswith("_read_scope")
                 and p["permissive"] == "RESTRICTIVE" and p["cmd"] == "SELECT"
                 and ("may_read_names" in p["qual"] or "may_read_display_key" in p["qual"] or "may_read_records" in p["qual"]
                      or "may_read_record_exports" in p["qual"])}
        assert set(names) == {"record", "record_index", "record_display", "org_display_key", "record_export", "record_export_link",
                                "record_export_key", "record_export_record"}
        assert "may_read_records" in names["record"] and "may_read_records" in names["record_index"]
        assert "may_read_names" in names["record_display"] and "may_read_display_key" in names["org_display_key"]
        counted = {(p["tablename"], p["policyname"]) for p in tenant} | {(p["tablename"], p["policyname"]) for p in policies if p["policyname"].endswith(("_read_scope", "_disclosed")) and p["tablename"] in scoped | audit | disclosed | set(names)}
        left = sorted((p["tablename"], p["policyname"]) for p in policies if (p["tablename"], p["policyname"]) not in counted)
        assert left == [("single_fingerprint_secret", "single_fingerprint_secret_owner")], left
        opts = {r["relname"]: r["reloptions"] for r in owner.execute(
            "SELECT relname, reloptions FROM pg_class WHERE relname = ANY(%s)", (list(views),))}
        assert set(opts) == set(views)
        assert all("security_invoker=true" in (o or []) for o in opts.values()), opts
        # the platform tables with an org_id are owner-only: no runtime role holds any grant on them
        grants = owner.execute(
            "SELECT table_name, grantee FROM information_schema.table_privileges WHERE table_schema = 'consentvault'"
            " AND table_name = ANY(%s) AND grantee IN ('consentvault_app', 'consentvault_worker', 'consentvault_operator',"
            " 'PUBLIC')", (list(PLATFORM_TABLES),)).fetchall()
        assert grants == [], grants


def test_no_runtime_role_bypasses_and_the_operator_reads_no_personal_column(tenancy):
    with tenancy.superuser() as owner:
        bypass = {r["rolname"]: r["rolbypassrls"] for r in owner.execute(
            "SELECT rolname, rolbypassrls FROM pg_roles WHERE rolname IN"
            " ('consentvault_app', 'consentvault_worker', 'consentvault_operator')")}
        assert bypass == {"consentvault_app": False, "consentvault_worker": False, "consentvault_operator": True}
        owner.execute("SET ROLE consentvault_operator")
        try:
            for sql in ("SELECT contact_fp FROM consentvault.event", "SELECT * FROM consentvault.contact_key",
                        "SELECT secret_ct FROM consentvault.credential", "SELECT name FROM consentvault.organization",
                        "SELECT body FROM consentvault.disclosure", "SELECT * FROM consentvault.contact_log",
                        "SELECT secret FROM consentvault.tenant_token_key"):
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    with owner.transaction():
                        owner.execute(sql)
            assert owner.execute("SELECT count(*) AS n FROM consentvault.organization").fetchone()["n"] == 3
        finally:
            owner.execute("RESET ROLE")


def test_resolve_credential_answers_one_credential_across_organisations(tenancy):
    with tenancy.app() as app:  # no tenant entered yet: this is the pre-tenant lookup
        for org in (tenancy.a, tenancy.b):
            rows = app.execute("SELECT * FROM consentvault.resolve_credential(%s)", (org.credential_id,)).fetchall()
            assert len(rows) == 1 and rows[0]["org_id"] == org.org_id and rows[0]["status"] == "active"
            assert rows[0]["scopes"] == ["capture"] and rows[0]["allowed_origins"] == [f"https://{org.name}.example.com"]
            assert set(rows[0]) == {"org_id", "scopes", "public_key", "alg", "kind", "allowed_origins", "status"}
        assert app.execute("SELECT * FROM consentvault.resolve_credential(%s)", (uuid.uuid4(),)).fetchall() == []
    with tenancy.superuser() as owner:
        owner.execute("UPDATE consentvault.credential SET revoked_at = now() WHERE credential_id = %s",
                      (tenancy.a.credential_id,))
        owner.execute("UPDATE consentvault.organization SET status = 'suspended' WHERE org_id = %s", (tenancy.b.org_id,))
    with tenancy.app() as app:
        assert app.execute("SELECT status FROM consentvault.resolve_credential(%s)",
                           (tenancy.a.credential_id,)).fetchone()["status"] == "revoked"
        assert app.execute("SELECT status FROM consentvault.resolve_credential(%s)",
                           (tenancy.b.credential_id,)).fetchone()["status"] == "org_suspended"


def test_resolve_member_answers_only_that_identity(tenancy):
    with tenancy.superuser() as owner:
        owner.execute("INSERT INTO consentvault.member (org_id, idp_issuer, idp_subject, role)"
                      " VALUES (%s, 'https://idp.example.com', 'user_alpha', 'compliance_viewer')", (tenancy.b.org_id,))
    with tenancy.app() as app:
        rows = app.execute("SELECT * FROM consentvault.resolve_member('https://idp.example.com', 'user_alpha')").fetchall()
        assert {(r["org_id"], r["role"]) for r in rows} == {(tenancy.a.org_id, "admin"),
                                                            (tenancy.b.org_id, "compliance_viewer")}
        assert app.execute("SELECT * FROM consentvault.resolve_member('https://other.example.com', 'user_alpha')"
                           ).fetchall() == []


def test_dispatch_orgs_mints_one_worker_token_per_active_org_for_the_worker_role_only(tenancy, pg_server):
    with tenancy.superuser() as owner:
        owner.execute("UPDATE consentvault.organization SET status = 'offboarding' WHERE org_id = %s",
                      (tenancy.b.org_id,))
    worker_dsn = make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1],
                                 "consentvault_worker, consentvault_app")
    with db.connect(worker_dsn) as worker:
        tokens = {r["org_id"]: r["token"] for r in worker.execute("SELECT * FROM consentvault.dispatch_orgs('sync')")}
        # ruled 2026-10-29: background jobs cover every org but closed, so offboarding B is dispatched too (one token
        # per org; the per-org fence below is unchanged)
        assert set(tokens) == {tenancy.a.org_id, tenancy.b.org_id, tenancy.home}
        with org_transaction(worker, tokens[tenancy.a.org_id]) as org:
            assert org == tenancy.a.org_id
            assert worker.execute("SELECT consentvault.current_token_scopes() AS s").fetchone()["s"] == ["worker:sync"]
            assert {r["org_id"] for r in worker.execute("SELECT org_id FROM consentvault.capture_source")} == {tenancy.a.org_id}
            # a worker token reads no evidence row directly; its jobs read what they need through owner functions
            assert worker.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 0
        with pytest.raises(psycopg.errors.InvalidParameterValue):
            worker.execute("SELECT * FROM consentvault.dispatch_orgs('Sync; DROP')")


def test_a_row_cannot_point_at_another_organisations_row(tenancy):
    with tenancy.app() as app:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute("INSERT INTO consentvault.review (kind, contact_kind, contact_fp, contact_ct, event_id)"
                            " VALUES ('stop_message', 'phone', %s, 'x', %s)", ("a" * 64, tenancy.b.event_ids[0]))
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute("INSERT INTO consentvault.seal (event_id, hash_version, columns, digest, tsa_url, token)"
                            " VALUES (%s, 2, ARRAY['seq'], decode(repeat('00', 32), 'hex'), 'x', 'x')",
                            (tenancy.b.event_ids[0],))


@pytest.mark.parametrize("kind,extra,scope", [
    ("edge_site_key", {}, ["capture", "capture_verified"]),
    ("jwt_public_key", {"alg": "ES256", "public_key": "k"}, ["operator"]),
    ("jwt_public_key", {"alg": "ES256", "public_key": "k"}, ["capture", "gate_read"]),
    ("jwt_public_key", {"alg": "HS256", "public_key": "k"}, ["gate_read"]),
    ("jwt_public_key", {"public_key": "k"}, ["gate_read"]),
])
def test_credentials_keep_their_scope_rules(tenancy, kind, extra, scope):
    cols = {"org_id": tenancy.a.org_id, "source_id": tenancy.a.source_id, "kind": kind, "scope": scope, **extra}
    with tenancy.superuser() as owner, pytest.raises(psycopg.errors.CheckViolation):
        owner.execute(f"INSERT INTO consentvault.credential ({', '.join(cols)}) VALUES ({', '.join(['%s'] * len(cols))})",
                      list(cols.values()))


def test_a_clear_contact_point_is_refused_outside_the_home_organisation(tenancy):
    with tenancy.app() as app:
        with pytest.raises(LedgerError, match=db_codes("mint_contact_salt", "home organisation") + "|" +
                           db_codes("check_clear_contact_home_only", "clear contact point")):
            with org_transaction(app, tenancy.token(tenancy.a)):
                record_event(app, contact=PHONE, event_type="revoke", channels=["sms"], purposes=["marketing"],
                             method="keyword", origin="consumer")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="home organisation"):
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute("INSERT INTO consentvault.contact_log (contact_kind, contact_norm, channel, contacted_at)"
                            " VALUES ('phone', %s, 'sms', now())", (PHONE,))


def test_the_replay_guard_refuses_a_second_presentation_per_organisation(tenancy):
    soon = datetime.now(timezone.utc) + timedelta(minutes=5)
    with tenancy.app() as app:
        claim_nonce(app, tenancy.a.org_id, "jti-0001-abcdef", soon)
        with pytest.raises(ReplayError):
            claim_nonce(app, tenancy.a.org_id, "jti-0001-abcdef", soon)
        claim_nonce(app, tenancy.b.org_id, "jti-0001-abcdef", soon)
        with pytest.raises(TenancyError, match=db_codes("claim_replay_nonce", "within one day")):
            claim_nonce(app, tenancy.a.org_id, "jti-0002-abcdef", datetime.now(timezone.utc) + timedelta(days=2))
        with pytest.raises(TenancyError, match=db_codes("claim_replay_nonce", "expiry must be in the future")):
            claim_nonce(app, tenancy.a.org_id, "jti-0003-abcdef", datetime.now(timezone.utc) - timedelta(seconds=1))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT * FROM consentvault.replay_guard")
        with pytest.raises(TenancyError):
            sweep(app)


def test_the_sweeper_removes_only_expired_nonces_and_a_late_sweep_never_lets_a_replay_through(tenancy, pg_server):
    soon = datetime.now(timezone.utc) + timedelta(minutes=5)
    with tenancy.app() as app:
        claim_nonce(app, tenancy.a.org_id, "live-nonce-0001", soon)
    with tenancy.superuser() as owner:
        owner.execute("INSERT INTO consentvault.replay_guard (org_id, nonce, expires_at)"
                      " VALUES (%s, 'stale-nonce-0001', now() - interval '2 hours')", (tenancy.a.org_id,))
    worker_dsn = make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker")
    with tenancy.app() as app:
        with pytest.raises(ReplayError):  # expired but not yet swept: still a replay
            claim_nonce(app, tenancy.a.org_id, "stale-nonce-0001", soon)
    with db.connect(worker_dsn) as worker:
        assert sweep(worker) == 1
    with tenancy.superuser() as owner:
        assert [r["nonce"] for r in owner.execute("SELECT nonce FROM consentvault.replay_guard")] == ["live-nonce-0001"]


def test_only_a_capture_verified_token_may_claim_a_verified_contact_point(tenancy):
    from consentvault.ledger import record_tenant_event

    def grant(scopes):
        with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a, scopes=scopes)):
            return record_tenant_event(app, tenancy.crypto, contact="+15555550111", event_type="grant",
                                       channels=["sms"], purposes=["marketing"], method="checkbox", origin="consumer",
                                       disclosure_sha256=tenancy.a.disclosure, contact_verification="otp")

    for scopes in (["capture"], ["worker:sync"], ["admin"]):
        with pytest.raises(LedgerError, match=db_codes("check_verified_claim", "capture_verified")):
            grant(scopes)
    assert grant(["capture", "capture_verified"]).seq == 3


def test_the_mode_never_returns_to_single_and_the_home_organisation_never_moves(tenancy):
    with tenancy.superuser() as owner:
        for sql in ("UPDATE consentvault.tenancy_setting SET mode = 'single'",
                    "DELETE FROM consentvault.tenancy_setting",
                    f"UPDATE consentvault.tenancy_setting SET home_org_id = '{tenancy.a.org_id}'"):
            with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="single to multi"):
                owner.execute(sql)
        assert owner.execute("SELECT mode FROM consentvault.tenancy_setting").fetchone()["mode"] == "multi"


def test_no_version_two_release_can_be_written_whatever_it_decides(tenancy):
    from consentvault.ledger import record_tenant_event

    verified = tenancy.token(tenancy.a, scopes=["capture", "capture_verified"])
    common = dict(channels=["sms"], purposes=["marketing"], origin="consumer")
    with tenancy.app() as app, org_transaction(app, verified):
        g = record_tenant_event(app, tenancy.crypto, contact="+15555550122", event_type="grant", method="checkbox",
                                disclosure_sha256=tenancy.a.disclosure, contact_verification="otp", **common)
    for contact in ("+15555550122", "+15555550133"):  # the grant's own contact point, and another person's
        with tenancy.app() as app:
            with pytest.raises(LedgerError, match=db_codes("check_release_ref", "no release event can be written")):
                with org_transaction(app, verified):
                    record_tenant_event(app, tenancy.crypto, contact=contact, event_type="release", method="checkbox",
                                        release_of_event_id=g.event_id, release_outcome="released", **common)


@pytest.mark.parametrize("table,column", [("seal", "seal_uuid"), ("chain_head", "head_uuid"),
                                          ("contact_log", "contact_log_uuid"), ("review", "review_uuid")])
def test_tenant_visible_rows_carry_random_ids(tenancy, table, column):
    with tenancy.superuser() as owner:
        info = owner.execute(
            "SELECT data_type, is_nullable, column_default FROM information_schema.columns"
            " WHERE table_schema = 'consentvault' AND table_name = %s AND column_name = %s", (table, column)).fetchone()
        assert info["data_type"] == "uuid" and info["is_nullable"] == "NO" and "gen_random_uuid" in info["column_default"]
        assert owner.execute("SELECT count(*) AS n FROM pg_indexes WHERE schemaname = 'consentvault' AND tablename = %s"
                             " AND indexdef LIKE %s", (table, f"%UNIQUE%({column})%")).fetchone()["n"] == 1
        ids = [r["id"] for r in owner.execute(f"SELECT {column} AS id FROM consentvault.{table}")]
    assert len(ids) >= 2 and len(set(ids)) == len(ids)
    assert all(isinstance(i, uuid.UUID) and i.version == 4 for i in ids)
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):  # a tenant sees only its own ids
        mine = {r["id"] for r in app.execute(f"SELECT {column} AS id FROM consentvault.{table}")}
    assert mine and mine < set(ids)


def test_a_nonce_stays_for_an_hour_after_it_expires_so_clock_skew_cannot_reopen_a_replay(tenancy, pg_server):
    with tenancy.superuser() as owner:
        owner.execute("INSERT INTO consentvault.replay_guard (org_id, nonce, expires_at) VALUES"
                      " (%s, 'just-expired-0001', now() - interval '1 minute'),"
                      " (%s, 'expired-59min-0001', now() - interval '59 minutes'),"
                      " (%s, 'expired-61min-0001', now() - interval '61 minutes')",
                      (tenancy.a.org_id, tenancy.a.org_id, tenancy.a.org_id))
    worker_dsn = make_login_role(pg_server["port"], tenancy.operator_dsn.rsplit("/", 1)[1], "consentvault_worker")
    with db.connect(worker_dsn) as worker:
        assert sweep(worker) == 1
    with tenancy.superuser() as owner:
        left = {r["nonce"] for r in owner.execute("SELECT nonce FROM consentvault.replay_guard")}
    assert {"just-expired-0001", "expired-59min-0001"} <= left and "expired-61min-0001" not in left
