"""Regression tests ported from the adversarial security review of the tenancy foundation.

Each test is the reviewer's attack with the assertion turned around: the attack ran against the first build and
succeeded; here it must fail. Names keep the reviewer's labels (attack A1..A5, down-migration D1..D2) so the review
record and the suite stay joined; the later tests pin the remaining items of the same review.
"""

from error_names import db_codes
import os
import subprocess
import uuid

import psycopg
import pytest

from conftest import _pg_bin
from consentvault import db, disclosure as disc
from consentvault.errors import LedgerError, MigrationError
from consentvault.ledger import record_event, record_tenant_event
from consentvault.tenancy.errors import TenantTokenError
from consentvault.tenancy.tokens import TokenKey, mint_org_token, org_transaction

from .harness import PHONE

DOWN = os.path.join(os.path.dirname(__file__), "..", "..", "migrations", "down")


# A1: wording collided across organisations (global sha256 key) ----------------------------------------------------
def test_A1_two_organisations_register_the_same_wording_independently(tenancy):
    body = "alpha: texts about your account. Reply STOP to end."
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.b)):
        assert disc.register(app, body, "b-form", "en", ["sms"], ["marketing"]) == tenancy.a.disclosure
    with tenancy.superuser() as su:
        orgs = {r["org_id"] for r in su.execute("SELECT org_id FROM consentvault.disclosure WHERE sha256 = %s",
                                                (tenancy.a.disclosure,))}
    assert orgs == {tenancy.a.org_id, tenancy.b.org_id}


# A2: mark_seal_verified crossed tenants when the owner was a superuser ---------------------------------------------
def test_A2_a_tenant_cannot_stamp_another_tenants_seal(tenancy):
    with tenancy.operator() as o:
        assert o.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()["rolsuper"] is False
    with tenancy.superuser() as su:
        b_seal = su.execute("SELECT seal_id, seal_uuid, verified_at FROM consentvault.seal WHERE org_id = %s",
                            (tenancy.b.org_id,)).fetchone()
    assert b_seal["verified_at"] is None
    with tenancy.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):  # the bigint form is withdrawn in multi mode
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute("SELECT consentvault.mark_seal_verified(%s::bigint)", (b_seal["seal_id"],))
        with pytest.raises(psycopg.errors.NoDataFound):
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute("SELECT consentvault.mark_seal_verified(%s::uuid)", (b_seal["seal_uuid"],))
    with tenancy.superuser() as su:
        assert su.execute("SELECT verified_at FROM consentvault.seal WHERE seal_uuid = %s",
                          (b_seal["seal_uuid"],)).fetchone()["verified_at"] is None
    # and the bigint form, where it still exists (single mode), is narrowed to the current organisation
    with tenancy.operator() as o:
        body = o.execute("SELECT prosrc FROM pg_proc WHERE proname = 'mark_seal_verified'"
                         " AND pg_get_function_arguments(oid) = 'p_seal_id bigint'").fetchone()["prosrc"]
    assert "current_org()" in body


# A3: an unknown hash version stored clear personal columns outside the home organisation ----------------------------
def test_A3_an_unknown_hash_version_is_refused(tenancy):
    with tenancy.app() as app:
        with pytest.raises(psycopg.errors.CheckViolation, match="event_shape_by_hash_version"):
            with org_transaction(app, tenancy.token(tenancy.a)):
                h = app.execute("SELECT * FROM consentvault.event WHERE org_id = consentvault.current_org()"
                                " ORDER BY seq DESC LIMIT 1").fetchone()
                now = app.execute("SELECT clock_timestamp() AS t").fetchone()["t"]
                app.execute(
                    "INSERT INTO consentvault.event (seq, event_id, contact_kind, contact_commit, event_type, channels,"
                    " purposes, method, origin, captured_at, received_at, client_ip, page_url, user_agent, contact_fp,"
                    " hash_version, prev_hash, row_hash) VALUES (%s, %s, 'phone', %s, 'revoke', ARRAY['sms'],"
                    " ARRAY['marketing'], 'keyword', 'consumer', %s, %s, '198.51.100.23',"
                    " 'https://x/?phone=+15555550142', 'UA', %s, 3, %s, %s)",
                    (h["seq"] + 1, uuid.uuid4(), "a" * 64, now, now, h["contact_fp"], h["row_hash"],
                     os.urandom(32).hex()))
    with tenancy.superuser() as su:
        assert su.execute("SELECT count(*) AS n FROM consentvault.event WHERE hash_version NOT IN (1, 2)"
                          ).fetchone()["n"] == 0


# A4: on a non-autocommit connection the token outlived the block (a savepoint, not a transaction) -------------------
def test_A4_the_tenant_block_refuses_a_connection_already_in_a_transaction(tenancy):
    c = psycopg.connect(tenancy.app_dsn, autocommit=False, row_factory=psycopg.rows.dict_row)
    try:
        with pytest.raises(TenantTokenError, match="autocommit"):
            with org_transaction(c, tenancy.token(tenancy.a)):
                pass
        c.rollback()
    finally:
        c.close()
    with tenancy.app() as app:
        app.execute("BEGIN")
        with pytest.raises(TenantTokenError, match="idle"):
            with org_transaction(app, tenancy.token(tenancy.a)):
                pass
        app.execute("ROLLBACK")


def test_A4_the_setting_is_cleared_when_the_block_ends_even_on_error(tenancy):
    with tenancy.app() as app:
        with pytest.raises(RuntimeError):
            with org_transaction(app, tenancy.token(tenancy.a)):
                raise RuntimeError("request failed")
        assert app.execute("SELECT consentvault.current_org() AS o").fetchone()["o"] is None
        with org_transaction(app, tenancy.token(tenancy.a)):
            pass
        assert app.execute("SELECT coalesce(current_setting('consentvault.org_token', true), '') AS t"
                           ).fetchone()["t"] == ""


# A5: in single mode a token-less caller reached home while other organisations existed -----------------------------
def test_A5_single_mode_refuses_a_second_organisation(dsn, app_dsn):
    with db.connect(dsn) as o:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="needs multi mode"):
            o.execute("INSERT INTO consentvault.organization (name) VALUES ('tenant-b')")
        assert o.execute("SELECT mode FROM consentvault.tenancy_setting").fetchone()["mode"] == "single"
    with db.connect(app_dsn) as app:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            app.execute("SELECT consentvault.require_multi_tenant()")


def test_A5_a_multi_tenant_service_can_check_the_mode_at_startup(tenancy):
    with tenancy.app() as app:
        app.execute("SELECT consentvault.require_multi_tenant()")


# D1, D2: the down migration, run by a role row security filters, counted zero and dropped a tenant's keys -----------
def _victim(pg_server, with_contact_log):
    port = pg_server["port"]
    name, owner = "o_" + uuid.uuid4().hex[:10], "own_" + uuid.uuid4().hex[:10]
    sup = f"postgresql://postgres@127.0.0.1:{port}/"
    with psycopg.connect(sup + "postgres", autocommit=True) as s:
        s.execute(f'CREATE DATABASE "{name}"')
        s.execute(f'CREATE ROLE "{owner}" LOGIN IN ROLE consentvault_operator')  # group roles exist (dsn fixtures)
        s.execute(f'ALTER DATABASE "{name}" OWNER TO "{owner}"')
    with psycopg.connect(sup + name, autocommit=True) as s:
        s.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    odsn = f"postgresql://{owner}@127.0.0.1:{port}/{name}"
    k = TokenKey("k1", os.urandom(32))
    org = uuid.uuid4()
    with db.connect(odsn) as o:
        db.migrate(o)
        o.execute("SELECT consentvault.install_token_key(%s, %s)", (k.key_id, k.secret))
        o.execute("SELECT consentvault.enable_multi_tenant()")
        with org_transaction(o, mint_org_token(k, org, ["admin"], credential_id=None)):
            o.execute("INSERT INTO consentvault.organization (org_id, name) VALUES (%s, 'victim')", (org,))
            o.execute("INSERT INTO consentvault.org_key (org_id, version, kms_key_ref) VALUES (%s, 1, 'kms/v')", (org,))
            o.execute("INSERT INTO consentvault.contact_key (org_id, contact_fp, wrapped_key, key_version, salt_ct)"
                      " VALUES (%s, %s, '\\x00', 1, '\\x00')", (org, "b" * 64))
            if with_contact_log:
                o.execute("INSERT INTO consentvault.contact_log (contact_kind, contact_fp, contact_ct, channel,"
                          " contacted_at) VALUES ('phone', %s, '\\x00', 'sms', now())", ("b" * 64,))
    return odsn, sup + name


def _schema_intact(sdsn):
    with psycopg.connect(sdsn, autocommit=True) as s:
        assert s.execute("SELECT to_regclass('consentvault.contact_key')").fetchone()[0] is not None
        assert s.execute("SELECT count(*) FROM consentvault.contact_key").fetchone()[0] == 1
        assert s.execute("SELECT relrowsecurity FROM pg_class WHERE oid = 'consentvault.event'::regclass"
                         ).fetchone()[0] is True
        cols = {r[0] for r in s.execute("SELECT column_name FROM information_schema.columns"
                                        " WHERE table_schema = 'consentvault' AND table_name = 'contact_log'")}
        assert {"org_id", "contact_fp", "contact_ct"} <= cols


def test_D1_a_filtered_role_running_the_down_in_one_transaction_is_refused(pg_server):
    odsn, sdsn = _victim(pg_server, False)
    p = subprocess.run([str(_pg_bin() / "psql"), odsn, "-X", "-q", "-1", "-v", "ON_ERROR_STOP=1",
                        "-f", os.path.join(DOWN, "0002_tenancy.sql")], capture_output=True, text=True, timeout=60)
    assert p.returncode != 0
    _schema_intact(sdsn)


def test_D2_a_filtered_role_running_the_down_with_psql_defaults_changes_nothing(pg_server):
    odsn, sdsn = _victim(pg_server, True)
    p = subprocess.run([str(_pg_bin() / "psql"), odsn, "-X", "-q", "-f", os.path.join(DOWN, "0002_tenancy.sql")],
                       capture_output=True, text=True, timeout=60)
    assert "row-level security" in p.stderr or "multi mode" in p.stderr
    _schema_intact(sdsn)


def test_D_even_a_superuser_down_is_refused_in_multi_mode(pg_server):
    _odsn, sdsn = _victim(pg_server, False)
    with db.connect(sdsn) as su:
        with pytest.raises(psycopg.Error, match="multi mode"):
            su.execute(open(os.path.join(DOWN, "0002_tenancy.sql")).read())
        su.execute("ROLLBACK")
    _schema_intact(sdsn)


# the remaining items of the same review ----------------------------------------------------------------------------
def test_the_migration_refuses_a_superuser_owner(pg_server):
    name = "s_" + uuid.uuid4().hex[:10]
    with psycopg.connect(f"postgresql://postgres@127.0.0.1:{pg_server['port']}/postgres", autocommit=True) as s:
        s.execute(f'CREATE DATABASE "{name}"')
    with db.connect(f"postgresql://postgres@127.0.0.1:{pg_server['port']}/{name}") as su:
        with pytest.raises(MigrationError, match=db_codes("inline_code_block", "refusing to migrate as %, a superuser or BYPASSRLS")):
            db.migrate(su)


def test_event_ids_and_row_hashes_are_unique_per_organisation_only(tenancy):
    with tenancy.superuser() as su:
        uniques = {r["indexdef"].split(" USING btree ")[1] for r in su.execute(
            "SELECT indexdef FROM pg_indexes WHERE schemaname = 'consentvault'"
            " AND tablename IN ('event', 'disclosure') AND indexdef LIKE 'CREATE UNIQUE%'")}
    assert "(event_id)" not in uniques and "(row_hash)" not in uniques and "(sha256)" not in uniques
    assert {"(org_id, event_id)", "(org_id, row_hash)", "(org_id, sha256)", "(org_id, seq)"} <= uniques


def test_multi_mode_withdraws_the_counting_ids_from_the_runtime_role(tenancy):
    with tenancy.app() as app:
        for table, col, seq in (("seal", "seal_id", "seal_seal_id_seq"), ("chain_head", "head_id", "chain_head_head_id_seq"),
                                ("contact_log", "contact_log_id", "contact_log_contact_log_id_seq"),
                                ("review", "review_id", "review_review_id_seq")):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with org_transaction(app, tenancy.token(tenancy.a)):
                    app.execute(f"SELECT {col} FROM consentvault.{table}")
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(f"SELECT nextval('consentvault.{seq}')")
    with tenancy.superuser() as su:  # new rows got random internal ids, not the next number of a shared count
        ids = [r["seal_id"] for r in su.execute("SELECT seal_id FROM consentvault.seal ORDER BY created_at")]
    assert len(ids) == 2 and abs(ids[1] - ids[0]) > 1_000_000


def test_multi_mode_refuses_a_new_version_one_row_even_for_the_home_organisation(tenancy):
    with tenancy.app() as app:
        with pytest.raises(LedgerError, match=db_codes("check_clear_contact_home_only", "clear contact point")):
            with org_transaction(app, tenancy.token_for_home()):
                record_event(app, contact=PHONE, event_type="revoke", channels=["sms"], purposes=["marketing"],
                             method="keyword", origin="consumer")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="multi mode"):
            with org_transaction(app, tenancy.token_for_home()):
                app.execute("INSERT INTO consentvault.contact_log (contact_kind, contact_norm, channel, contacted_at)"
                            " VALUES ('phone', %s, 'sms', now())", (PHONE,))


@pytest.mark.parametrize("scopes", [["capture"], ["capture", "capture_verified"], ["worker:sync"]])
def test_write_and_worker_tokens_read_no_evidence_rows(tenancy, scopes):
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a, scopes=scopes)):
        for t in ("event", "contact_key", "contact_salt", "contact_log", "review", "current_permission",
                  "unsealed_events"):
            assert app.execute(f"SELECT count(*) AS n FROM consentvault.{t}").fetchone()["n"] == 0, t
        assert app.execute("SELECT count(*) AS n FROM consentvault.disclosure").fetchone()["n"] == 1  # wording is not evidence


def test_a_capture_token_still_writes_a_chained_event(tenancy):
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a, scopes=["capture"])):
        e = record_tenant_event(app, tenancy.crypto, contact=PHONE, event_type="revoke", channels=["sms"],
                                purposes=["marketing"], method="keyword", origin="consumer")
    assert e.seq == 3
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a, scopes=["gate_read"])):
        assert app.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 3


def test_unbind_filters_on_the_tokens_own_organisation(tenancy, pg_server):
    """Owner-rights function added at the integration pass (0011): another tenant's admin cannot unbind a system."""
    from sync.support import SyncEnv
    env = SyncEnv(tenancy, pg_server["port"])
    sys_a = env.add_system(tenancy.a, "crm", signal=True)
    with tenancy.app() as app:
        with pytest.raises(psycopg.errors.NoDataFound):
            with org_transaction(app, tenancy.admin_token(tenancy.b.org_id)):
                app.execute("SELECT consentvault.sync_system_unbind_credential(%s)", (sys_a.system_id,))
        with pytest.raises(psycopg.Error):  # a capture token is not an admin or developer token
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute("SELECT consentvault.sync_system_unbind_credential(%s)", (sys_a.system_id,))
    with tenancy.superuser() as su:
        assert su.execute("SELECT signal_credential_id FROM consentvault.connected_system WHERE system_id = %s",
                          (sys_a.system_id,)).fetchone()["signal_credential_id"] == tenancy.a.credential_id
