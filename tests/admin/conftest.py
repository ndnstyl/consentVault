import os

import pytest

from consentvault.providers.keys import LocalFileKeyProvider
from consentvault.tenancy.admin_routes import AdminApp
from consentvault.tenancy.session import SessionMinter
from consentvault.tenancy.tokens import TokenKey

from isolation.harness import make_login_role
from .support import FakeIdentity, RecordingMailer, Vault


@pytest.fixture
def vault(dsn, pg_server, tmp_path) -> Vault:
    from consentvault import db
    dbname = dsn.rsplit("/", 1)[1]
    key = TokenKey("adm-k1", os.urandom(32))
    with db.connect(dsn) as owner:
        owner.execute("SELECT consentvault.install_token_key(%s, %s)", (key.key_id, key.secret))
        owner.execute("SELECT consentvault.enable_multi_tenant()")
    app_dsn = make_login_role(pg_server["port"], dbname, "consentvault_app")
    custody = LocalFileKeyProvider(tmp_path / "keys", "a-long-test-passphrase")
    idp, mailer = FakeIdentity(), RecordingMailer()
    sessions = SessionMinter(idp, key)
    app = AdminApp(connect=lambda: db.connect(app_dsn), owner_connect=lambda: db.connect(dsn), token_key=key,
                   sessions=sessions, custody=custody, mailer=mailer)
    return Vault(dsn, app_dsn, f"postgresql://postgres@127.0.0.1:{pg_server['port']}/{dbname}", key, custody, idp, mailer,
                 sessions, app)
