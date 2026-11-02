"""The tenant setting cannot be forged: a forged, expired, foreign-key or missing token selects no rows.

Covers the security review's first finding: anyone can call set_config, so the setting holds the signed token
itself and every policy re-verifies it.
"""

import hashlib
import hmac
import json
import os
import time
import uuid

import psycopg
import pytest

from consentvault import disclosure as disc
from consentvault.tenancy.errors import TenantTokenError
from consentvault.tenancy.tokens import TokenKey, mint_org_token, org_transaction

from .harness import FILLED_TABLES, expired_token, tenant_tables, tenant_views


def _relations(conn) -> tuple[str, ...]:
    """Every tenant table and view from the catalog that this role may read at all (the rest refuse outright)."""
    return tuple(t for t in tenant_tables(conn) + tenant_views(conn) if conn.execute(
        "SELECT has_any_column_privilege(%s, 'SELECT') AS ok", (f"consentvault.{t}",)).fetchone()["ok"])


def _counts(conn) -> dict[str, int]:
    return {t: conn.execute(f"SELECT count(*) AS n FROM consentvault.{t}").fetchone()["n"] for t in _relations(conn)}


def _with_setting(conn, token):
    """Write the setting by hand, the way a bug or an injected statement would, then count every table."""
    with conn.transaction():
        conn.execute("SELECT set_config('consentvault.org_token', %s, true)", (token,))
        return _counts(conn)


def _sign(secret: bytes, kid: str, payload: dict) -> str:
    body = json.dumps(payload, separators=(",", ":")).encode().hex()
    return f"v1.{kid}.{body}.{hmac.new(secret, f'v1.{kid}.{body}'.encode(), hashlib.sha256).hexdigest()}"


def _assert_empty(counts):
    assert counts == {k: 0 for k in counts}, {k: v for k, v in counts.items() if v}


def test_a_valid_token_sees_its_own_rows_and_only_those(tenancy):
    with tenancy.app() as app, org_transaction(app, tenancy.token(tenancy.a)) as org:
        assert org == tenancy.a.org_id
        counts = _counts(app)
        assert all(counts[t] > 0 for t in FILLED_TABLES + ("current_permission", "unsealed_events")), counts
        for t in _relations(app):
            other = app.execute(f"SELECT count(*) AS n FROM consentvault.{t} WHERE org_id <> %s",
                                (tenancy.a.org_id,)).fetchone()["n"]
            assert other == 0, t


def test_no_token_in_multi_mode_sees_nothing(tenancy):
    with tenancy.app() as app:
        _assert_empty(_counts(app))


@pytest.mark.parametrize("garbage", ["", "x", "v1", "v1.test-k1.zz.00", "v1.test-k1.7b7d." + "0" * 64,
                                     "v2.test-k1.7b7d." + "0" * 64, "' OR 1=1 --", "a" * 5000])
def test_a_hand_written_setting_sees_nothing(tenancy, garbage):
    with tenancy.app() as app:
        _assert_empty(_with_setting(app, garbage))


def test_a_valid_token_with_its_org_swapped_sees_nothing(tenancy):
    good = tenancy.token(tenancy.a)
    _v, kid, body, sig = good.split(".")
    payload = json.loads(bytes.fromhex(body))
    payload["org"] = str(tenancy.b.org_id)
    forged = f"v1.{kid}.{json.dumps(payload, separators=(',', ':')).encode().hex()}.{sig}"
    with tenancy.app() as app:
        _assert_empty(_with_setting(app, forged))
        with pytest.raises(TenantTokenError):
            with org_transaction(app, forged):
                pass


def test_a_token_signed_with_another_secret_sees_nothing(tenancy):
    wrong = mint_org_token(TokenKey(tenancy.key.key_id, os.urandom(32)), tenancy.b.org_id, ["gate_read"],
                           credential_id=None)
    with tenancy.app() as app:
        _assert_empty(_with_setting(app, wrong))
        with pytest.raises(TenantTokenError):
            with org_transaction(app, wrong):
                pass


def test_an_expired_token_sees_nothing_and_cannot_be_entered(tenancy):
    stale = expired_token(tenancy, tenancy.a)
    with tenancy.app() as app:
        _assert_empty(_with_setting(app, stale))
        with pytest.raises(TenantTokenError):
            with org_transaction(app, stale):
                pass


def test_a_token_claiming_a_life_over_fifteen_minutes_sees_nothing(tenancy):
    now = int(time.time())
    long_lived = _sign(tenancy.key.secret, tenancy.key.key_id,
                       {"org": str(tenancy.a.org_id), "scp": ["gate_read"], "cid": None, "iat": now, "exp": now + 3600})
    with tenancy.app() as app:
        _assert_empty(_with_setting(app, long_lived))
    with pytest.raises(TenantTokenError):
        mint_org_token(tenancy.key, tenancy.a.org_id, ["gate_read"], credential_id=None, ttl_seconds=901)


def test_a_retired_or_unknown_key_sees_nothing(tenancy):
    token = tenancy.token(tenancy.a)
    unknown = mint_org_token(TokenKey("nobody", tenancy.key.secret), tenancy.a.org_id, ["gate_read"],
                             credential_id=None)
    with tenancy.app() as app:
        _assert_empty(_with_setting(app, unknown))
        assert _with_setting(app, token)["event"] > 0
    with tenancy.superuser() as owner:
        owner.execute("SELECT consentvault.retire_token_key(%s)", (tenancy.key.key_id,))
    with tenancy.app() as app:
        _assert_empty(_with_setting(app, token))


def test_the_setting_ends_with_the_transaction(tenancy):
    with tenancy.app() as app:
        with org_transaction(app, tenancy.token(tenancy.a)):
            assert app.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] == 2
        _assert_empty(_counts(app))


def test_no_token_cannot_write_and_a_tenant_cannot_write_into_another(tenancy):
    stray = ("INSERT INTO consentvault.disclosure (sha256, body, label, locale, channels, purposes)"
             " VALUES (%s, 'x', 'stray', 'en', ARRAY['sms'], ARRAY['marketing'])")
    planted = ("INSERT INTO consentvault.disclosure (org_id, sha256, body, label, locale, channels, purposes)"
               " VALUES (%s, %s, 'x', 'planted', 'en', ARRAY['sms'], ARRAY['marketing'])")
    with tenancy.app() as app:
        with pytest.raises((psycopg.errors.NotNullViolation, psycopg.errors.InsufficientPrivilege)):
            app.execute(stray, ("d" * 64,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute(planted, (tenancy.b.org_id, "e" * 64))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute("INSERT INTO consentvault.contact_key (org_id, contact_fp, wrapped_key, key_version, salt_ct)"
                            " VALUES (%s, %s, 'w', 1, 's')", (tenancy.b.org_id, "f" * 64))
    with tenancy.superuser() as owner:
        assert owner.execute("SELECT count(*) AS n FROM consentvault.disclosure WHERE label IN ('stray', 'planted')"
                             ).fetchone()["n"] == 0
        assert owner.execute("SELECT count(*) AS n FROM consentvault.contact_key WHERE contact_fp = %s",
                             ("f" * 64,)).fetchone()["n"] == 0


def test_the_signing_key_and_mode_are_out_of_the_runtime_roles_reach(tenancy):
    denied = [
        "SELECT * FROM consentvault.tenant_token_key",
        "SELECT * FROM consentvault.tenancy_setting",
        "UPDATE consentvault.tenancy_setting SET mode = 'single'",
        "SELECT consentvault.enable_multi_tenant()",
        "SELECT consentvault.install_token_key('evil', decode(repeat('00', 32), 'hex'))",
        "SELECT consentvault.retire_token_key('test-k1')",
        "SELECT * FROM consentvault.verify_org_token('x')",
        f"SELECT consentvault.sign_org_token('{uuid.uuid4()}', ARRAY['admin'], NULL, 300)",
        "SELECT * FROM consentvault.dispatch_orgs('sync')",
        "SELECT consentvault.hmac_sha256('k'::bytea, 'm'::bytea)",
        "SELECT * FROM consentvault.active_org_ids()",
        "SET ROLE consentvault_operator",
        "SET ROLE consentvault_worker",
    ]
    with tenancy.app() as app:
        for sql in denied:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(sql)


def test_the_database_hmac_matches_the_python_signer(tenancy):
    key = os.urandom(70)  # longer than one block: hashed first, as HMAC requires
    with tenancy.superuser() as owner:
        for k in (key, key[:32]):
            got = owner.execute("SELECT consentvault.hmac_sha256(%s, %s) AS h", (k, b"message")).fetchone()["h"]
            assert bytes(got) == hmac.new(k, b"message", hashlib.sha256).digest()


def test_single_mode_needs_no_token_holds_only_the_home_organisation_and_refuses_a_forged_token(dsn, pg_server):
    from consentvault import db

    from .harness import make_login_role

    with db.connect(dsn) as owner:
        key = TokenKey("single-k", os.urandom(32))
        owner.execute("SELECT consentvault.install_token_key(%s, %s)", (key.key_id, key.secret))
        home = owner.execute("SELECT consentvault.home_org() AS h").fetchone()["h"]
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="needs multi mode"):
            owner.execute("INSERT INTO consentvault.organization (name) VALUES ('second')")
    app_dsn = make_login_role(pg_server["port"], dsn.rsplit("/", 1)[1], "consentvault_app")
    with db.connect(app_dsn) as app:
        sha = disc.register(app, "Home wording. Reply STOP to end.", "home", "en", ["sms"], ["marketing"])
        assert app.execute("SELECT org_id FROM consentvault.disclosure WHERE sha256 = %s", (sha,)).fetchone()["org_id"] == home
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="single mode"):
            app.execute("SELECT consentvault.require_multi_tenant()")
        with org_transaction(app, mint_org_token(key, home, ["admin"], credential_id=None)):
            assert app.execute("SELECT count(*) AS n FROM consentvault.disclosure").fetchone()["n"] == 1
        _assert_empty({"forged": _with_setting(app, "v1.single-k.00." + "0" * 64)["disclosure"]})


def test_a_token_valid_when_its_transaction_opened_holds_the_tenant_to_the_end_of_that_transaction(tenancy):
    """Expiry is judged at the start of the transaction that entered the token, so one transaction never loses its tenant
    part way through (a write after the instant of expiry once failed deep in the sync outbox with "no tenant entered"),
    and the next transaction with the same token is refused."""
    with tenancy.app() as app:
        # minted at a fixed instant once the connection is open, so its expiry is known exactly and nothing slow (opening the
        # connection under load) eats into its life before the transaction opens
        issued, ttl = int(time.time()), 3  # ttl: arbitrary test config
        token = tenancy.token(tenancy.a, ttl_seconds=ttl, now=issued)
        expires_at = issued + ttl
        with org_transaction(app, token) as org:
            while time.time() <= expires_at:  # bounded: at most ttl seconds; past the token's exact expiry, by measurement
                time.sleep(min(0.05, max(0.0, expires_at - time.time()) + 0.01))
            assert app.execute("SELECT consentvault.current_org() AS o").fetchone()["o"] == org
            assert app.execute("SELECT count(*) AS n FROM consentvault.event").fetchone()["n"] > 0
        _assert_empty(_with_setting(app, token))
        with pytest.raises(TenantTokenError):
            with org_transaction(app, token):
                pass
