"""Stop notices: queued with the stop, one email per admin, bursts merged, masked, loud on failure, acknowledged per admin."""

from datetime import datetime, timedelta, timezone
import re

import pytest

from consentvault.notify.stop_notice import DueMail, StopNoticeSendError, group_by_window

from .support import Mailroom, count, record_stop

PHONE = "+15555550177"
PHONE_2 = "+15555550178"
PHONE_3 = "+15555550179"


@pytest.fixture
def mail(vault, pg_server):
    return Mailroom(vault, pg_server)


@pytest.fixture
def acme(vault):
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    second = vault.add_member(boss, "two@acme.example", "admin")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    return org["org_id"], boss, second, dev


def _mail_rows(vault, org_id):
    with vault.superuser() as su:
        return su.execute("SELECT * FROM consentvault.stop_notice_mail WHERE org_id = %s", (org_id,)).fetchall()


def test_a_stop_queues_one_email_per_admin_in_the_same_transaction(vault, acme):
    org_id, boss, second, dev = acme
    record_stop(vault, org_id, PHONE)
    rows = _mail_rows(vault, org_id)
    assert len(rows) == 2 and {str(r["member_id"]) for r in rows} == {boss.member_id, second.member_id}
    # the stop and its notice stand or fall together
    class Abort(Exception):
        pass
    def abort():
        raise Abort()
    with pytest.raises(Abort):
        record_stop(vault, org_id, PHONE_2, then=abort)
    assert count(vault, "SELECT count(*) AS n FROM consentvault.stop_notice WHERE org_id = %s", org_id) == 1
    assert len(_mail_rows(vault, org_id)) == 2


def test_only_a_stop_that_moves_state_makes_a_notice(vault, acme):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE)
    record_stop(vault, org_id, PHONE)  # the stop already stands: nothing moved
    assert count(vault, "SELECT count(*) AS n FROM consentvault.stop_notice WHERE org_id = %s", org_id) == 1
    record_stop(vault, org_id, PHONE_2, event_type="suppress", purposes=("*",))
    assert count(vault, "SELECT count(*) AS n FROM consentvault.stop_notice WHERE org_id = %s", org_id) == 2


def test_several_stops_in_a_minute_become_one_email_per_admin(vault, acme, mail):
    org_id, boss, second, dev = acme
    for p in (PHONE, PHONE_2, PHONE_3):
        record_stop(vault, org_id, p)
    report = mail.run()
    assert report.emails_sent == 2 and report.stops_listed == 6
    assert len(mail.to("boss@acme.example")) == 1 and len(mail.to("two@acme.example")) == 1
    assert mail.to("dev@acme.example") == []
    body = mail.to("boss@acme.example")[0].text
    assert body.count("Contact:") == 3
    assert mail.run().emails_sent == 0  # sent rows are never sent again


def test_the_window_splits_bursts_more_than_a_minute_apart():
    t0 = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
    def row(i, secs, who="a@x.example"):
        return DueMail(mail_id=f"{i:08d}-0000-0000-0000-000000000000", notice_id=i, address=who,
                       queued_at=t0 + timedelta(seconds=secs), org_name="Acme", masked_contact="(555) ***-0177",
                       channels=["sms"], purposes=["marketing"], stopped_at=t0, record_id=None)
    groups = group_by_window([row(1, 0), row(2, 59), row(3, 61), row(4, 5, who="b@x.example")])
    assert sorted(len(g) for g in groups) == [1, 1, 2]


def test_no_full_contact_point_reaches_a_body_or_the_log(vault, acme, mail):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE)
    mail.run()
    msg = mail.to("boss@acme.example")[0]
    for text in (msg.text, msg.html, msg.subject):
        assert "5555550177" not in re.sub(r"\D", "", text) and "@example.test" not in text
    assert "(555) ***-0177" in msg.text
    assert all(r.recipient_domain == "acme.example" and "boss" not in str(r) for r in mail.log.records)
    assert "ConsentVault has recorded this stop. Acting on it in your own systems is up to you." in msg.text


def test_each_connected_system_shows_its_delivery_status(vault, acme, mail):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE)
    mail.run()
    assert "none connected" in mail.to("boss@acme.example")[0].text
    with vault.superuser() as su:
        for name in ("crm", "dialer", "texting"):
            su.execute("INSERT INTO consentvault.connected_system (org_id, name, kind, endpoint, signature, contact_form, credentials_ct)"
                       " VALUES (%s, %s, 'crm', %s, 'hmac', 'plaintext', %s)", (org_id, name, f"https://{name}.acme.example.test/h", b"x"))
    record_stop(vault, org_id, PHONE_2)
    with vault.superuser() as su:
        su.execute("UPDATE consentvault.outbox SET status = 'acknowledged', next_attempt_at = NULL, finished_at = now()"
                   " WHERE org_id = %s AND system_id = (SELECT system_id FROM consentvault.connected_system WHERE name = 'crm')", (org_id,))
        su.execute("UPDATE consentvault.outbox SET status = 'dead', next_attempt_at = NULL, finished_at = now()"
                   " WHERE org_id = %s AND system_id = (SELECT system_id FROM consentvault.connected_system WHERE name = 'dialer')", (org_id,))
    mail.run()
    text = mail.sender.sent[-1].text
    assert "crm (delivered)" in text and "dialer (refused)" in text and "texting (waiting)" in text


def test_a_failed_send_is_a_loud_alarm_and_a_log_row_and_is_retried(vault, acme, mail):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE)
    mail.sender.fail = True
    with pytest.raises(StopNoticeSendError):
        mail.run()
    assert [r.outcome for r in mail.log.records] == ["failed", "failed"]
    assert {n for n, _ in mail.alarms.raised} == {"notify.send_failed"}
    assert {r["status"] for r in _mail_rows(vault, org_id)} == {"failed"}
    mail.sender.fail = False
    assert mail.run().emails_sent == 2
    assert {r["status"] for r in _mail_rows(vault, org_id)} == {"sent"}


def test_the_popup_list_stays_until_that_admin_acknowledges_and_only_for_that_admin(vault, acme):
    org_id, boss, second, dev = acme
    record_stop(vault, org_id, PHONE)
    record_stop(vault, org_id, PHONE_2)
    first = boss.ok("GET", "/v1/stop-notices")
    assert len(first["notices"]) == 2 and boss.ok("GET", "/v1/stop-notices") == first  # reading never clears it
    n = first["notices"][0]
    assert n["contact"] == "(555) ***-0177" and PHONE not in str(first) and n["delivery"][0]["status"] == "none_connected"
    assert "up to you" in first["note"]
    ids = [x["notice_id"] for x in first["notices"]]
    assert boss.ok("POST", "/v1/stop-notices:acknowledge", body={"notice_ids": ids}) == {"acknowledged": 2, "remaining": 0}
    assert boss.ok("GET", "/v1/stop-notices")["notices"] == []
    assert len(second.ok("GET", "/v1/stop-notices")["notices"]) == 2
    with vault.superuser() as su:
        rows = su.execute("SELECT actor_id, action, detail FROM consentvault.audit_event WHERE org_id = %s AND action = 'stop_notice.acknowledged'",
                          (org_id,)).fetchall()
    assert len(rows) == 1 and rows[0]["actor_id"] == boss.member_id and sorted(rows[0]["detail"]["notice_ids"]) == sorted(ids)
    assert boss.ok("POST", "/v1/stop-notices:acknowledge", body={"notice_ids": ids})["acknowledged"] == 0  # no second audit row
    assert count(vault, "SELECT count(*) AS n FROM consentvault.audit_event WHERE org_id = %s AND action = 'stop_notice.acknowledged'", org_id) == 1


def test_only_admins_see_or_acknowledge_notices(vault, acme):
    org_id, boss, second, dev = acme
    record_stop(vault, org_id, PHONE)
    dev.err("GET", "/v1/stop-notices", name="role_not_allowed", status=403)
    dev.err("POST", "/v1/stop-notices:acknowledge", body={"notice_ids": []}, name="role_not_allowed", status=403)
    boss.err("POST", "/v1/stop-notices:acknowledge", body={"notice_ids": "all"}, name="validation_failed")


def test_an_added_recipient_gets_the_next_notice_and_admins_always_do(vault, acme, mail):
    org_id, boss, *_ = acme
    added = boss.ok("POST", "/v1/stop-notices/recipients", body={"email": "Legal@Acme.example"})
    assert added["email_hint"] == "l***@acme.example"
    listed = boss.ok("GET", "/v1/stop-notices/recipients")
    assert listed["admins_always_receive"] is True and listed["admin_count"] == 2 and len(listed["recipients"]) == 1
    boss.err("POST", "/v1/stop-notices/recipients", body={"email": "legal@acme.example"}, name="validation_failed")
    record_stop(vault, org_id, PHONE)
    mail.run()
    assert {m.to for m in mail.sender.sent} == {"boss@acme.example", "two@acme.example", "legal@acme.example"}
    boss.ok("DELETE", f"/v1/stop-notices/recipients/{added['recipient_id']}")
    record_stop(vault, org_id, PHONE_2)
    mail.sender.sent.clear()
    mail.run()
    assert {m.to for m in mail.sender.sent} == {"boss@acme.example", "two@acme.example"}
