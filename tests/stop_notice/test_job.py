"""The scheduled job path: a stop recorded in the database leaves as a sent email through ``jobs.main``, the same entry the
cloud schedule runs, under the worker login the job's task role uses. Nothing here touches the network."""

import pytest

from consentvault import jobs

from .support import JobNotifier, Mailroom, count, record_stop

PHONE = "+15555550177"


@pytest.fixture
def room(vault, pg_server, monkeypatch):
    mail = Mailroom(vault, pg_server)
    JobNotifier.shared = mail
    monkeypatch.setenv("CONSENTVAULT_NOTIFIER", "stop_notice.support:JobNotifier")
    monkeypatch.setenv("CONSENTVAULT_PORTAL_URL", "https://app.example.test")
    monkeypatch.setenv("CONSENTVAULT_DSN", mail.dsn)
    return mail


def test_a_recorded_stop_is_emailed_to_the_admins_by_the_scheduled_job(vault, room, capsys):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    vault.add_member(boss, "two@acme.example", "admin")
    record_stop(vault, org["org_id"], PHONE)
    assert room.sender.sent == []
    assert jobs.main(["stop-notices-send"]) == 0
    assert sorted(m.to for m in room.sender.sent) == ["boss@acme.example", "two@acme.example"]
    assert "(555) ***-0177" in room.sender.sent[0].text and "5555550177" not in room.sender.sent[0].text
    assert count(vault, "SELECT count(*) AS n FROM consentvault.stop_notice_mail WHERE org_id = %s AND status = 'sent'", org["org_id"]) == 2
    assert jobs.main(["stop-notices-send"]) == 0 and len(room.sender.sent) == 2  # a second pass sends nothing more


def test_the_job_is_registered_with_a_heartbeat_and_a_failed_send_fails_the_run(vault, room):
    assert jobs.JOBS["stop-notices-send"] == "stop-notices-send" and "stop-notices-send" in jobs.HEARTBEAT_JOBS
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    record_stop(vault, org["org_id"], PHONE)
    room.sender.fail = True
    assert jobs.main(["stop-notices-send"]) == 2  # no heartbeat beats on a failed run, so the missed-heartbeat alarm fires
    assert room.alarms.raised
    room.sender.fail = False
    assert jobs.main(["stop-notices-send"]) == 0 and len(room.sender.sent) == 1


def test_the_job_refuses_a_login_that_is_not_the_workers(vault, room, monkeypatch):
    monkeypatch.setenv("CONSENTVAULT_DSN", vault.app_dsn)
    assert jobs.main(["stop-notices-send"]) == 3
