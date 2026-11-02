import os

import pytest

from consentvault.providers.keys import LocalFileKeyProvider
from consentvault.tenancy.admin_routes import AdminApp
from consentvault.tenancy.session import SessionMinter
from consentvault.tenancy.tokens import TokenKey

from conftest import operator_dsn_for
from isolation.harness import make_login_role
from .support import FakeIdentity, RecordingMailer, Vault


@pytest.fixture
def vault(dsn, pg_server, tmp_path) -> Vault:
    from consentvault import db
    dbname = dsn.rsplit("/", 1)[1]
    key = TokenKey("adm-k1", os.urandom(32))
    with db.connect(dsn) as migrator:  # setup steps run as the migrator (a member of the NOLOGIN schema owner)
        migrator.execute("SELECT consentvault.install_token_key(%s, %s)", (key.key_id, key.secret))
        migrator.execute("SELECT consentvault.enable_multi_tenant()")
    operator_dsn = operator_dsn_for(dsn)
    app_dsn = make_login_role(pg_server["port"], dbname, "consentvault_app")
    records_jobs_dsn = make_login_role(pg_server["port"], dbname, "consentvault_records_jobs")
    custody = LocalFileKeyProvider(tmp_path / "keys", "a-long-test-passphrase")
    idp, mailer = FakeIdentity(), RecordingMailer()
    sessions = SessionMinter(idp, key)
    app = AdminApp(connect=lambda: db.connect(app_dsn), owner_connect=lambda: db.connect(operator_dsn), token_key=key,
                   sessions=sessions, custody=custody, mailer=mailer)
    return Vault(operator_dsn, app_dsn, f"postgresql://postgres@127.0.0.1:{pg_server['port']}/{dbname}", key, custody, idp, mailer,
                 sessions, app, migrator_dsn=dsn, records_jobs_dsn=records_jobs_dsn)
