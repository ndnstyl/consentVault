"""The vault service of the stack: migrated by the migrator, pinned by a superuser, migrator login removed, running as
the runtime login that cannot rewrite history."""

import socket

import psycopg
import pytest


@pytest.fixture(scope="module")
def dsns(settings):
    port = settings["DB_PORT"]
    base = f"127.0.0.1:{port}/consentvault"
    return {
        "admin": f"postgresql://consentvault_admin:{settings['POSTGRES_ADMIN_PASSWORD']}@{base}",
        "runtime": f"postgresql://consentvault_runtime:{settings['CONSENTVAULT_APP_PASSWORD']}@{base}",
        "migrator": f"postgresql://consentvault_migrator:{settings['CONSENTVAULT_MIGRATOR_PASSWORD']}@{base}",
        "operator": f"postgresql://consentvault_operator_login:{settings['CONSENTVAULT_OPERATOR_PASSWORD']}@{base}",
    }


def test_server_is_postgresql_17(dsns):
    with psycopg.connect(dsns["admin"]) as c:
        assert c.execute("SHOW server_version").fetchone()[0].startswith("17.")


def test_migrations_applied_by_the_owner(dsns):
    with psycopg.connect(dsns["admin"]) as c:
        tables = [r[0] for r in c.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'consentvault'").fetchall()]
        assert "event" in tables and len(tables) >= 10, tables
        assert c.execute("SELECT count(*) FROM consentvault_guard.pin_violations()").fetchone()[0] == 0
        assert c.execute("SELECT count(*) FROM consentvault_guard.pin").fetchone()[0] > 0


def test_owner_and_migrator_cannot_log_in_and_the_schema_is_owned_by_the_owner(dsns):
    with psycopg.connect(dsns["admin"]) as c:
        rows = dict(c.execute(
            "SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname IN ('consentvault_owner', 'consentvault_migrator')").fetchall())
        assert rows == {"consentvault_owner": False, "consentvault_migrator": False}
        assert c.execute("SELECT count(*) FROM pg_tables WHERE schemaname = 'consentvault' AND tableowner <> 'consentvault_owner'"
                         ).fetchone()[0] == 0
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(dsns["migrator"], connect_timeout=5)


def test_runtime_role_cannot_update_delete_or_alter_the_ledger(dsns):
    with psycopg.connect(dsns["runtime"], autocommit=True) as c:
        for sql in ("UPDATE consentvault.event SET purposes = purposes", "DELETE FROM consentvault.event",
                    "TRUNCATE consentvault.event", "ALTER TABLE consentvault.event ADD COLUMN x int",
                    "ALTER TABLE consentvault.event DISABLE TRIGGER ALL"):
            with pytest.raises(psycopg.errors.Error):
                c.execute(sql)
        assert c.execute("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()[0] is False


def test_operator_console_login_owns_nothing_and_cannot_alter_the_schema(dsns):
    with psycopg.connect(dsns["operator"], autocommit=True) as c:
        with pytest.raises(psycopg.errors.Error):
            c.execute("ALTER TABLE consentvault.event ADD COLUMN y int")
        assert c.execute("SELECT count(*) FROM pg_tables WHERE tableowner = current_user").fetchone()[0] == 0


def test_the_vault_container_answers(settings):
    with socket.create_connection(("127.0.0.1", int(settings["VAULT_PORT"])), timeout=5):
        pass
