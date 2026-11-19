"""Stop notices: queued with the stop, one email per admin, bursts merged, masked, loud on failure, acknowledged per admin, and a
notice failure never refuses a stop."""

import re
import pytest

from consentvault.notify.errors import NotifyError
from consentvault.notify.stop_notice import StopNoticeSender, StopNoticeSendError
from consentvault.tenancy.tokens import mint_org_token, org_transaction

from consentvault.tenancy import stop_notices

from .support import SHARED, Mailroom, NoDisplayKey, count, record_stop, _PROVIDER

PHONE = "+15555550177"
PHONE_2 = "+15555550178"
PHONE_3 = "+15555550179"


@pytest.fixture
def mail(vault, pg_server):
    return Mailroom(vault, pg_server)


@pytest.fixture
def acme(vault):
    vault.app._crypto = SHARED  # the portal opens masks with the key service the writer sealed them under
    org, boss = vault.org_with_admin("Acme", "boss@acme.example")
    second = vault.add_member(boss, "two@acme.example", "admin")
    dev = vault.add_member(boss, "dev@acme.example", "developer")
    return org["org_id"], boss, second, dev


def _mail_rows(vault, org_id):
    with vault.superuser() as su:
        return su.execute("SELECT * FROM consentvault.stop_notice_mail WHERE org_id = %s", (org_id,)).fetchall()


def _alarms(vault, org_id):
    with vault.superuser() as su:
        return [r["name"] for r in su.execute("SELECT name FROM consentvault.operator_alarm WHERE org_id = %s", (org_id,)).fetchall()]


# ---- recording ---------------------------------------------------------------------------------------------------------

def test_a_stop_queues_one_email_per_admin_in_the_same_transaction(vault, acme):
    org_id, boss, second, dev = acme
    record_stop(vault, org_id, PHONE)
    rows = _mail_rows(vault, org_id)
    assert len(rows) == 2 and {str(r["member_id"]) for r in rows} == {boss.member_id, second.member_id}

    class Abort(Exception):
        pass

    def abort():
        raise Abort()

    with pytest.raises(Abort):
        record_stop(vault, org_id, PHONE_2, then=abort)  # the stop and its notice stand or fall together
    assert count(vault, "SELECT count(*) AS n FROM consentvault.stop_notice WHERE org_id = %s", org_id) == 1


def test_only_a_stop_that_moves_state_makes_a_notice(vault, acme):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE)
    record_stop(vault, org_id, PHONE)  # the stop already stands: nothing moved
    record_stop(vault, org_id, PHONE_2, event_type="suppress", purposes=("*",))
    assert count(vault, "SELECT count(*) AS n FROM consentvault.stop_notice WHERE org_id = %s", org_id) == 2


def test_a_notice_that_cannot_be_written_never_refuses_the_stop_and_raises_an_alarm(vault, acme):
    org_id, *_ = acme
    with vault.superuser() as su:
        su.execute("REVOKE EXECUTE ON FUNCTION consentvault.stop_notice_record(uuid, uuid, text, bytea, text, text[], text[], jsonb,"
                   " timestamptz) FROM consentvault_app")
    record_stop(vault, org_id, PHONE)  # must not raise
    assert count(vault, "SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", org_id) == 1
    assert count(vault, "SELECT count(*) AS n FROM consentvault.stop_notice WHERE org_id = %s", org_id) == 0
    assert "stop_notice.not_recorded" in _alarms(vault, org_id)


def test_a_very_long_email_still_records_its_stop_and_its_notice(vault, acme, mail):
    org_id, *_ = acme
    long_email = "b@" + "a" * 60 + "." + "c" * 60 + ".com"  # the old 120-character cap on the mask refused this one
    record_stop(vault, org_id, long_email, channels=("email",))
    assert count(vault, "SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", org_id) == 1
    assert count(vault, "SELECT count(*) AS n FROM consentvault.stop_notice WHERE org_id = %s", org_id) == 1
    mail.run()
    assert "b***@" in mail.to("boss@acme.example")[0].text and "Email" in mail.to("boss@acme.example")[0].text


def test_a_stop_that_queues_no_email_raises_an_alarm_and_still_stands(vault, acme):
    org_id, *_ = acme
    with vault.superuser() as su:
        su.execute("UPDATE consentvault.member SET email_norm = NULL WHERE org_id = %s", (org_id,))
    record_stop(vault, org_id, PHONE)
    assert count(vault, "SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", org_id) == 1
    assert "stop_notice.no_recipients" in _alarms(vault, org_id)


# ---- sending -----------------------------------------------------------------------------------------------------------

def test_stops_queued_in_separate_runs_within_a_minute_become_one_email_per_admin(vault, acme, pg_server):
    org_id, *_ = acme
    mail = Mailroom(vault, pg_server, window_seconds=60)
    record_stop(vault, org_id, PHONE)
    assert mail.run().emails_sent == 0  # the first notice waits for the window
    record_stop(vault, org_id, PHONE_2)
    assert mail.run().emails_sent == 0
    with vault.superuser() as su:
        su.execute("UPDATE consentvault.stop_notice_mail SET queued_at = queued_at - interval '61 seconds' WHERE org_id = %s", (org_id,))
    record_stop(vault, org_id, PHONE_3)  # younger than the window, but its recipient's oldest is due: it merges
    report = mail.run()
    assert report.emails_sent == 2 and report.stops_listed == 6
    assert len(mail.to("boss@acme.example")) == 1 and mail.to("dev@acme.example") == []
    assert mail.to("boss@acme.example")[0].text.count("Contact:") == 3
    assert mail.run().emails_sent == 0  # sent rows are never sent again


def test_a_claimed_row_that_never_answered_is_never_sent_again_and_an_alarm_names_it(vault, acme, mail):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE)
    with vault.superuser() as su:  # a run claimed the rows and died after sending: the lease ran out with no answer
        su.execute("UPDATE consentvault.stop_notice_mail SET status = 'sending', attempts = 1,"
                   " claimed_until = clock_timestamp() - interval '1 minute' WHERE org_id = %s", (org_id,))
    with pytest.raises(StopNoticeSendError):
        mail.run()
    assert mail.sender.sent == []
    assert {r["status"] for r in _mail_rows(vault, org_id)} == {"unknown"}
    assert all(r["mask_text"] is None for r in _mail_rows(vault, org_id))  # a row that may have been sent holds no text any more
    assert [n for n, _ in mail.alarms.raised].count("notify.stop_notice_unknown") == 1
    mail.run()  # the next pass finds the unknown rows already reported: no second alarm, no resend
    assert [n for n, _ in mail.alarms.raised].count("notify.stop_notice_unknown") == 1 and mail.sender.sent == []


def test_no_full_contact_point_reaches_a_body_or_the_log_and_a_phone_shows_its_last_four_only(vault, acme, mail):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE)
    mail.run()
    msg = mail.to("boss@acme.example")[0]
    for text in (msg.text, msg.html, msg.subject):
        assert "5555550177" not in re.sub(r"\D", "", text) and "@example.test" not in text and "555" not in text
    assert "***-0177" in msg.text and "Text message" in msg.text
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


def test_the_attempt_that_runs_out_writes_a_log_row_and_an_alarm(vault, acme, mail):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE)
    with vault.superuser() as su:
        su.execute("UPDATE consentvault.stop_notice_mail SET attempts = 4 WHERE org_id = %s", (org_id,))
    mail.sender.fail = True
    with pytest.raises(StopNoticeSendError):
        mail.run()
    assert "notify.stop_notice_gave_up" in {n for n, _ in mail.alarms.raised}
    assert any(r.detail == "attempts_exhausted" for r in mail.log.records)
    assert mail.run(raise_on_error=False).emails_sent == 0  # attempts are spent: nothing more is sent


def test_one_bad_stop_never_blocks_the_others_in_a_merged_email(vault, acme, mail):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE)
    record_stop(vault, org_id, PHONE_2)
    with vault.superuser() as su:  # one stop that the template refuses (a channel that is not a plain word)
        su.execute("UPDATE consentvault.stop_notice SET channels = ARRAY['SMS!'] WHERE notice_id = ("
                   "SELECT notice_id FROM consentvault.stop_notice WHERE org_id = %s ORDER BY stopped_at LIMIT 1)", (org_id,))
    with pytest.raises(StopNoticeSendError):
        mail.run()
    assert len(mail.to("boss@acme.example")) == 1 and mail.to("boss@acme.example")[0].text.count("Contact:") == 1
    assert "notify.stop_notice_refused" in {n for n, _ in mail.alarms.raised}
    assert any(r.outcome == "failed" and "refused" in (r.detail or "") for r in mail.log.records)
    assert sorted(r["status"] for r in _mail_rows(vault, org_id)) == ["failed", "failed", "sent", "sent"]


def test_one_organisations_error_never_stops_the_others(vault, pg_server, monkeypatch):
    vault.app._crypto = SHARED
    org_a, boss_a = vault.org_with_admin("Acme", "boss@acme.example")
    org_b, boss_b = vault.org_with_admin("Birch", "boss@birch.example")
    record_stop(vault, org_a["org_id"], PHONE)
    record_stop(vault, org_b["org_id"], PHONE_2)
    mail = Mailroom(vault, pg_server)
    real = StopNoticeSender._run_org

    def run_org(self, conn, org_id, token, report, org_transaction):
        if str(org_id) == str(org_a["org_id"]):
            raise NotifyError("this organisation's pass failed")
        return real(self, conn, org_id, token, report, org_transaction)

    monkeypatch.setattr(StopNoticeSender, "_run_org", run_org)
    with pytest.raises(StopNoticeSendError):
        mail.run()
    assert [m.to for m in mail.sender.sent] == ["boss@birch.example"]


# ---- the pop-up --------------------------------------------------------------------------------------------------------

def test_the_popup_list_stays_until_that_admin_acknowledges_and_only_for_that_admin(vault, acme):
    org_id, boss, second, dev = acme
    record_stop(vault, org_id, PHONE)
    record_stop(vault, org_id, PHONE_2)
    first = boss.ok("GET", "/v1/stop-notices")
    assert len(first["notices"]) == 2 and first["remaining"] == 2 and boss.ok("GET", "/v1/stop-notices") == first
    n = first["notices"][0]
    assert n["contact"] == "***-0177" and "555" not in str(first) and n["delivery"][0]["status"] == "none_connected"
    assert "up to you" in first["note"]
    ids = [x["notice_id"] for x in first["notices"]]
    assert boss.ok("POST", "/v1/stop-notices:acknowledge", body={"notice_ids": ids}) == {"acknowledged": 2, "remaining": 0}
    assert boss.ok("GET", "/v1/stop-notices")["notices"] == []
    assert len(second.ok("GET", "/v1/stop-notices")["notices"]) == 2
    with vault.superuser() as su:
        rows = su.execute("SELECT actor_id, detail FROM consentvault.audit_event WHERE org_id = %s AND action = 'stop_notice.acknowledged'",
                          (org_id,)).fetchall()
    assert len(rows) == 1 and rows[0]["actor_id"] == boss.member_id and sorted(rows[0]["detail"]["notice_ids"]) == sorted(ids)
    assert boss.ok("POST", "/v1/stop-notices:acknowledge", body={"notice_ids": ids})["acknowledged"] == 0  # no second audit row
    assert count(vault, "SELECT count(*) AS n FROM consentvault.audit_event WHERE org_id = %s AND action = 'stop_notice.acknowledged'", org_id) == 1


def test_a_long_list_is_answered_a_page_at_a_time_so_an_admin_is_never_locked_out(vault, acme, monkeypatch):
    monkeypatch.setattr(stop_notices, "PAGE_LIMIT", 2)
    org_id, boss, *_ = acme
    for i in range(5):
        record_stop(vault, org_id, f"+1555555{1000 + i:04d}")
    page = boss.ok("GET", "/v1/stop-notices")
    assert len(page["notices"]) == 2 and page["remaining"] == 5
    ack = lambda p: boss.ok("POST", "/v1/stop-notices:acknowledge", body={"notice_ids": [x["notice_id"] for x in p["notices"]]})
    assert ack(page) == {"acknowledged": 2, "remaining": 3}
    page = boss.ok("GET", "/v1/stop-notices")
    assert len(page["notices"]) == 2 and ack(page)["remaining"] == 1
    page = boss.ok("GET", "/v1/stop-notices")
    assert len(page["notices"]) == 1 and ack(page)["remaining"] == 0


def test_a_new_admin_sees_only_stops_recorded_after_they_joined(vault, acme):
    org_id, boss, *_ = acme
    record_stop(vault, org_id, PHONE)
    newcomer = vault.add_member(boss, "new@acme.example", "admin")
    assert newcomer.ok("GET", "/v1/stop-notices")["notices"] == []
    record_stop(vault, org_id, PHONE_2)
    assert len(newcomer.ok("GET", "/v1/stop-notices")["notices"]) == 1
    assert len(boss.ok("GET", "/v1/stop-notices")["notices"]) == 2


def test_only_admins_see_or_acknowledge_notices(vault, acme):
    org_id, boss, second, dev = acme
    record_stop(vault, org_id, PHONE)
    dev.err("GET", "/v1/stop-notices", name="role_not_allowed", status=403)
    dev.err("POST", "/v1/stop-notices:acknowledge", body={"notice_ids": []}, name="role_not_allowed", status=403)
    boss.err("POST", "/v1/stop-notices:acknowledge", body={"notice_ids": "all"}, name="validation_failed")


def test_an_erasure_leaves_nothing_readable_in_the_stop_notice_rows(vault, acme):
    org_id, boss, *_ = acme
    record_stop(vault, org_id, PHONE)
    assert boss.ok("GET", "/v1/stop-notices")["notices"][0]["contact"] == "***-0177"
    with vault.superuser() as su:
        fp = su.execute("SELECT contact_fp FROM consentvault.stop_notice WHERE org_id = %s", (org_id,)).fetchone()["contact_fp"]
    token = mint_org_token(vault.key, org_id, ["admin"], credential_id=None)
    with vault.operator() as c, org_transaction(c, token):  # the operator console runs an erasure
        c.execute("SELECT consentvault.erase_contact(%s)", (fp,))
    with vault.superuser() as su:
        row = su.execute("SELECT masked_ct, n::text AS everything FROM consentvault.stop_notice n WHERE org_id = %s", (org_id,)).fetchone()
        queue = su.execute("SELECT q::text AS everything FROM consentvault.stop_notice_mail q WHERE org_id = %s", (org_id,)).fetchall()
    assert row["masked_ct"] is None and "0177" not in row["everything"]
    assert queue and all("0177" not in q["everything"] for q in queue)  # the send queue's text is blanked too
    assert boss.ok("GET", "/v1/stop-notices")["notices"][0]["contact"] == "contact not shown"


# ---- recipients --------------------------------------------------------------------------------------------------------

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


# ---- review fixes: stranding, orphans, alarms --------------------------------------------------------------------------

def test_an_admin_address_the_refuser_rejects_never_strands_the_rest_of_the_batch(vault, acme, mail):
    org_id, boss, second, dev = acme
    record_stop(vault, org_id, PHONE)
    with vault.superuser() as su:  # the second admin's address is one the notifier refuses (no dot in the domain)
        su.execute("UPDATE consentvault.member SET email_norm = 'admin@localhost' WHERE member_id = %s", (second.member_id,))
        su.execute("UPDATE consentvault.stop_notice_mail SET queued_at = queued_at - interval '1 hour' WHERE member_id = %s", (second.member_id,))
    with pytest.raises(StopNoticeSendError):
        mail.run()
    assert [m.to for m in mail.sender.sent] == ["boss@acme.example"]  # the good address was still emailed
    by_status = {str(r["member_id"]): r["status"] for r in _mail_rows(vault, org_id)}
    assert by_status == {boss.member_id: "sent", second.member_id: "failed"}  # the refused row is failed, not stranded in flight
    assert "notify.stop_notice_refused" in {n for n, _ in mail.alarms.raised}
    assert any(r.outcome == "failed" and "refused" in (r.detail or "") for r in mail.log.records)


def test_a_queued_row_whose_admin_is_gone_is_closed_with_a_reason_and_an_alarm(vault, acme, mail):
    org_id, boss, second, dev = acme
    record_stop(vault, org_id, PHONE)
    with vault.superuser() as su:
        su.execute("UPDATE consentvault.member SET email_norm = NULL WHERE member_id = %s", (second.member_id,))
    with pytest.raises(StopNoticeSendError):
        mail.run()
    rows = {str(r["member_id"]): r for r in _mail_rows(vault, org_id)}
    assert rows[second.member_id]["status"] == "failed" and rows[second.member_id]["failure_reason"] == "no_address"
    assert rows[second.member_id]["mask_text"] is None and rows[boss.member_id]["status"] == "sent"
    assert "notify.stop_notice_orphaned" in {n for n, _ in mail.alarms.raised}


def test_a_lease_that_runs_out_under_a_send_is_an_alarm(vault, acme, mail):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE)

    def expire(message):  # while the email is being sent, the claim is lost
        with vault.superuser() as su:
            su.execute("UPDATE consentvault.stop_notice_mail SET status = 'unknown', claimed_until = NULL WHERE org_id = %s", (org_id,))
    mail.sender.on_send = expire
    with pytest.raises(StopNoticeSendError):
        mail.run()
    assert "notify.stop_notice_lease_lost" in {n for n, _ in mail.alarms.raised}


def test_a_mask_that_cannot_be_sealed_raises_an_alarm_and_the_stop_stands(vault, acme):
    org_id, *_ = acme
    record_stop(vault, org_id, PHONE, crypto=NoDisplayKey(_PROVIDER))
    assert count(vault, "SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s", org_id) == 1
    assert "stop_notice.mask_not_sealed" in _alarms(vault, org_id)
