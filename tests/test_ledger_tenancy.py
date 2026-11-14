"""Per-organisation chains, hash version 2, and version-1 rows that still verify."""

import hashlib
import threading
import uuid
from pathlib import Path

import psycopg
import pytest

from consentvault import db
from consentvault.errors import LedgerError
from consentvault.ledger import (GENESIS, HASH_VERSIONS, compute_row_hash, contact_commitment, record_event,
                                 record_tenant_event, verify_chain)
from consentvault.tenancy import crypto as tc
from consentvault.tenancy.errors import FieldDecryptError, TenantRequiredError
from consentvault.tenancy.keys_protocol import WrappedKey
from consentvault.tenancy.tokens import org_transaction

from isolation.harness import PHONE, build_tenancy

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"


@pytest.fixture
def tenancy(dsn, pg_server):
    return build_tenancy(dsn, pg_server["port"])


def _revoke(t, org, contact=PHONE):
    with t.app() as app, org_transaction(app, t.token(org)):
        return record_tenant_event(app, t.crypto, contact=contact, event_type="revoke", channels=["sms"],
                                   purposes=["marketing"], method="keyword", origin="consumer")


def _tamper(t, sql, params=()):
    with t.superuser() as owner:
        owner.execute("ALTER TABLE consentvault.event DISABLE TRIGGER USER")
        try:
            owner.execute(sql, params)
        finally:
            owner.execute("ALTER TABLE consentvault.event ENABLE TRIGGER USER")


def test_each_organisation_has_its_own_chain_from_genesis(tenancy):
    with tenancy.superuser() as owner:
        rows = owner.execute("SELECT org_id, seq, prev_hash FROM consentvault.event ORDER BY org_id, seq").fetchall()
    for org in (tenancy.a, tenancy.b):
        mine = [r for r in rows if r["org_id"] == org.org_id]
        assert [r["seq"] for r in mine] == [1, 2] and mine[0]["prev_hash"] == GENESIS
    assert _revoke(tenancy, tenancy.b).seq == 3
    assert _revoke(tenancy, tenancy.a).seq == 3
    with tenancy.superuser() as owner:
        assert verify_chain(owner, crypto=tenancy.crypto) == []
    for org in (tenancy.a, tenancy.b):
        with tenancy.app() as app, org_transaction(app, tenancy.token(org)):
            assert verify_chain(app, crypto=tenancy.crypto) == []
            assert app.execute("SELECT count(*) AS n FROM consentvault.chain_breaks").fetchone()["n"] == 0


def test_one_organisations_writer_never_waits_on_anothers_lock(tenancy):
    holder = tenancy.app()
    try:
        holder.execute("BEGIN")
        holder.execute("SELECT consentvault.enter_org(%s)", (tenancy.token(tenancy.a),))
        holder.execute("SELECT pg_advisory_xact_lock(consentvault.ledger_lock_key(consentvault.current_org()))")
        with tenancy.app() as app:
            app.execute("SET lock_timeout = '500ms'")
            with org_transaction(app, tenancy.token(tenancy.b)):  # B is not blocked by A's lock
                record_tenant_event(app, tenancy.crypto, contact=PHONE, event_type="revoke", channels=["sms"],
                                    purposes=["marketing"], method="keyword", origin="consumer")
            with pytest.raises(LedgerError, match=r"LockNotAvailable \(sqlstate 55P03\)"):
                with org_transaction(app, tenancy.token(tenancy.a)):  # A is
                    record_tenant_event(app, tenancy.crypto, contact=PHONE, event_type="revoke", channels=["sms"],
                                        purposes=["marketing"], method="keyword", origin="consumer")
        holder.execute("ROLLBACK")
    finally:
        holder.close()


def test_concurrent_writers_in_one_organisation_serialise(tenancy):
    errors: list[Exception] = []

    def write():
        try:
            for _ in range(5):
                _revoke(tenancy, tenancy.a)
        except Exception as exc:  # loud-failure-exempt: collected here, asserted empty by the main thread below
            errors.append(exc)

    threads = [threading.Thread(target=write) for _ in range(3)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=60)
    assert errors == [] and not any(th.is_alive() for th in threads)
    with tenancy.superuser() as owner:
        seqs = [r["seq"] for r in owner.execute("SELECT seq FROM consentvault.event WHERE org_id = %s ORDER BY seq",
                                                (tenancy.a.org_id,))]
        assert seqs == list(range(1, 18)) and verify_chain(owner, crypto=tenancy.crypto) == []


def test_the_home_organisation_keeps_the_single_company_lock_key(tenancy):
    with tenancy.superuser() as owner:
        row = owner.execute("SELECT consentvault.ledger_lock_key(consentvault.home_org()) AS home,"
                            " hashtext('consentvault.ledger') AS legacy,"
                            " consentvault.ledger_lock_key(%s) AS a", (tenancy.a.org_id,)).fetchone()
        assert row["home"] == row["legacy"] != row["a"]
        with pytest.raises(psycopg.errors.InvalidAuthorizationSpecification):
            owner.execute("SELECT consentvault.ledger_lock_key(NULL)")


def test_a_version_two_row_holds_no_clear_personal_data(tenancy):
    with tenancy.superuser() as owner:
        row = owner.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (tenancy.a.event_ids[0],)).fetchone()
        b_fp = owner.execute("SELECT contact_fp FROM consentvault.event WHERE event_id = %s",
                             (tenancy.b.event_ids[0],)).fetchone()["contact_fp"]
    assert row["hash_version"] == 2
    for col in ("contact_norm", "contact_salt", "subject_key", "page_url", "client_ip", "user_agent", "session_ref"):
        assert row[col] is None, col
    blob = b"".join(bytes(row[c]) for c in ("contact_ct", "subject_key_ct", "page_url_ct", "client_ip_ct",
                                            "user_agent_ct", "session_ref_ct", "attribution_ct"))
    for secret in (PHONE.encode(), b"203.0.113.7", b"alpha.example.com", b"Mozilla", b"alpha-fall"):
        assert secret not in blob
    assert row["payload_sha256"] != hashlib.sha256(b'{"form":"signup"}').hexdigest()
    assert row["contact_fp"] != b_fp  # the same person in two organisations is not linkable by fingerprint


@pytest.mark.parametrize("column,value", [("contact_fp", "f" * 64), ("subject_fp", "e" * 64), ("key_version", 9),
                                          ("brand_ids", []), ("source_id", None), ("evidence_sha256", "d" * 64)])
def test_re_pointing_a_version_two_row_breaks_the_chain_without_any_key(tenancy, column, value):
    _tamper(tenancy, f"UPDATE consentvault.event SET {column} = %s WHERE event_id = %s",
            (value, tenancy.a.event_ids[0]))
    with tenancy.superuser() as owner:
        breaks = verify_chain(owner)
    assert [(b.event_id, b.reason) for b in breaks] == [(tenancy.a.event_ids[0], "row_hash_mismatch")]


def test_a_ciphertext_swapped_between_rows_is_caught_with_the_key(tenancy):
    with tenancy.superuser() as owner:
        other = owner.execute("SELECT contact_ct FROM consentvault.event WHERE event_id = %s",
                              (tenancy.a.event_ids[1],)).fetchone()["contact_ct"]
    _tamper(tenancy, "UPDATE consentvault.event SET contact_ct = %s WHERE event_id = %s",
            (other, tenancy.a.event_ids[0]))
    with tenancy.superuser() as owner:
        assert verify_chain(owner) == []  # links and stored digests are intact
        breaks = verify_chain(owner, crypto=tenancy.crypto)
    assert [(b.event_id, b.reason) for b in breaks] == [(tenancy.a.event_ids[0], "ciphertext_invalid")]


def test_a_contact_key_deleted_by_hand_keeps_every_link_verifiable_and_reads_as_a_break_not_an_erasure(tenancy):
    fp = tenancy.crypto.contact_fingerprint(tenancy.a.org_id, "phone", PHONE)
    with tenancy.superuser() as owner:
        held = owner.execute("SELECT * FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                             (tenancy.a.org_id, fp)).fetchone()
        owner.execute("DELETE FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s",
                      (tenancy.a.org_id, fp))
        assert verify_chain(owner) == []  # links and stored digests are intact
        seqs = [r["seq"] for r in owner.execute("SELECT seq FROM consentvault.event WHERE org_id = %s AND contact_fp = %s"
                                                " ORDER BY seq", (tenancy.a.org_id, fp)).fetchall()]
        # no completed erasure covers these rows, so a missing key is a break, never an erasure
        assert [(b.seq, b.reason) for b in verify_chain(owner, crypto=tenancy.crypto)] == [
            (s, "contact_key_missing") for s in seqs]
        row = owner.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (tenancy.a.event_ids[0],)).fetchone()
        assert row["contact_fp"] == fp  # a returning number still matches its old stop
    with pytest.raises(FieldDecryptError):
        tc.decrypt_field(b"\x00" * 32, tenancy.a.org_id, str(row["event_id"]), "contact_norm", row["contact_ct"])
    # with the (now deleted) wrapped key the field opened; without it nothing in the database can
    dk = tenancy.crypto.open_contact_key(tenancy.a.org_id, WrappedKey(bytes(held["wrapped_key"]), held["key_version"]))
    assert tc.decrypt_text(dk, tenancy.a.org_id, str(row["event_id"]), "contact_norm", row["contact_ct"]) == PHONE


def test_the_runtime_role_cannot_delete_or_rewrite_a_contact_key(tenancy):
    with tenancy.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute("DELETE FROM consentvault.contact_key")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute("UPDATE consentvault.contact_key SET key_version = 1")


def test_the_permission_view_reads_per_organisation_by_fingerprint(tenancy):
    fp_a = tenancy.crypto.contact_fingerprint(tenancy.a.org_id, "phone", PHONE)
    fp_b = tenancy.crypto.contact_fingerprint(tenancy.b.org_id, "phone", PHONE)
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)):
        # a later unverified grant does not lift the person's own earlier stop
        g = record_tenant_event(app, tenancy.crypto, contact=PHONE, event_type="grant", channels=["sms"],
                                purposes=["marketing"], method="checkbox", origin="consumer",
                                disclosure_sha256=tenancy.a.disclosure, brand_ids=[tenancy.a.brand_id])
        rows_a = app.execute("SELECT * FROM consentvault.current_permission").fetchall()
        fresh = record_tenant_event(app, tenancy.crypto, contact="+15555550199", event_type="grant", channels=["sms"],
                                    purposes=["marketing"], method="checkbox", origin="consumer",
                                    disclosure_sha256=tenancy.a.disclosure)
        granted = app.execute("SELECT allowed, reason, deciding_event_id FROM consentvault.current_permission"
                              " WHERE contact_fp = %s",
                              (tenancy.crypto.contact_fingerprint(tenancy.a.org_id, "phone", "+15555550199"),)
                              ).fetchone()
    assert [(r["org_id"], r["contact_fp"], r["contact_norm"], r["allowed"], r["reason"], str(r["deciding_event_id"]))
            for r in rows_a] == [(tenancy.a.org_id, fp_a, None, False, "stopped:revoke", g.event_id)]
    assert (granted["allowed"], granted["reason"], str(granted["deciding_event_id"])) == (True, "granted", fresh.event_id)
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.b)):
        rows_b = app.execute("SELECT contact_fp, deciding_event_id FROM consentvault.current_permission").fetchall()
    assert [(r["contact_fp"], str(r["deciding_event_id"])) for r in rows_b] == [(fp_b, tenancy.b.event_ids[1])]


def test_a_hand_written_row_must_extend_its_own_organisations_head(tenancy):
    with tenancy.superuser() as owner:
        src = owner.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (tenancy.a.event_ids[0],)).fetchone()
    row = dict(src)
    row.update(event_id=uuid.uuid4(), seq=1, prev_hash=GENESIS)
    row.pop("received_at")
    cols = [c for c in row if c not in ("row_hash", "org_id")]
    with tenancy.app() as app, pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="extend"):
        with org_transaction(app, tenancy.token(tenancy.a)):
            app.execute(f"INSERT INTO consentvault.event ({', '.join(cols)}, received_at, row_hash)"
                        f" VALUES ({', '.join(['%s'] * len(cols))}, clock_timestamp(), %s)",
                        [row[c] for c in cols] + ["a" * 64])


def test_writing_a_version_two_event_needs_a_tenant(tenancy):
    with tenancy.app() as app:
        with pytest.raises(TenantRequiredError):
            record_tenant_event(app, tenancy.crypto, contact=PHONE, event_type="revoke", channels=["sms"],
                                purposes=["marketing"], method="keyword", origin="consumer")


def test_a_version_one_row_written_in_single_mode_still_verifies(conn, disclosure):
    e = record_event(conn, contact=PHONE, event_type="grant", channels=["sms"], purposes=["marketing"],
                     method="checkbox", origin="consumer", disclosure_sha256=disclosure, session_ref="s1")
    row = conn.execute("SELECT * FROM consentvault.event WHERE event_id = %s", (e.event_id,)).fetchone()
    home = conn.execute("SELECT consentvault.home_org() AS h").fetchone()["h"]
    assert row["hash_version"] == 1 and row["org_id"] == home
    assert compute_row_hash(GENESIS, row, 1) == row["row_hash"]
    assert row["contact_commit"] == contact_commitment(row["contact_salt"], PHONE)
    assert "org_id" not in HASH_VERSIONS[1]
    assert {"org_id", "contact_fp", "subject_fp", "source_id", "brand_ids", "key_version",
            "evidence_sha256"} <= set(HASH_VERSIONS[2])
    assert verify_chain(conn) == []


def test_down_then_up_round_trips_the_tenancy_migrations(raw_dsn, super_dsn):
    with db.connect(raw_dsn) as c, db.connect(super_dsn) as su:
        db.migrate(c)
        after_init = [p.name for p in db.list_migrations(MIGRATIONS) if p.name != "0001_init.sql"]
        assert after_init[:2] == ["0002_tenancy.sql", "0003_replay_guard.sql"]
        for name in reversed(after_init):  # every down, newest first, down to the tenancy migration
            su.execute((MIGRATIONS / "down" / name).read_text())
        assert c.execute("SELECT to_regclass('consentvault.organization') AS t").fetchone()["t"] is None
        c.execute("DELETE FROM consentvault.schema_migration WHERE name <> '0001_init.sql'")
        assert db.migrate(c) == after_init


def test_the_down_migration_refuses_while_a_second_organisation_exists(tenancy):
    with tenancy.superuser() as owner:
        owner.execute((MIGRATIONS / "down" / "0003_replay_guard.sql").read_text())
        with pytest.raises(psycopg.Error, match="down 0002 refused: the vault is in multi mode"):
            owner.execute((MIGRATIONS / "down" / "0002_tenancy.sql").read_text())
        owner.execute("ROLLBACK")
        assert owner.execute("SELECT to_regclass('consentvault.contact_key') AS t").fetchone()["t"] is not None
        assert verify_chain(owner, crypto=tenancy.crypto) == []
