"""The integration pass across the wave-one lanes: live statuses, the outbox hook in capture, the operator alarm row, the
email send log, and what the operator role may read."""

import json
import uuid

import psycopg
import pytest

from consentvault.alarms import raise_operator_alarm
from consentvault.cmd_anchor import TENANT_ANCHOR_JOB
from consentvault.errors import LedgerError
from consentvault.notify import PostgresSendLog, SendLogError, SendRecord, scrub_detail
from consentvault.tenancy.tokens import org_transaction

from sync.support import SyncEnv

from .cloud_harness import Cloud
from .harness import make_login_role

X = "+15555550177"


@pytest.fixture
def cloud(tenancy, tmp_path):
    c = Cloud(tenancy, str(tmp_path / "evidence"))
    yield c
    c.close()


def _port_db(t):
    return int(t.app_dsn.rsplit(":", 1)[1].split("/")[0]), t.app_dsn.rsplit("/", 1)[1]


def _set_status(t, org, status):
    with t.superuser() as su:
        su.execute("UPDATE consentvault.organization SET status = %s WHERE org_id = %s", (status, org.org_id))


# ---- live statuses ------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("status", ["trial", "past_due", "suspended"])
def test_trial_past_due_and_suspended_orgs_keep_capture_and_gate(cloud, status):
    _set_status(cloud.t, cloud.t.a, status)
    s, r = cloud.grant(cloud.a, X)  # a fresh access token is issued in this status
    assert s == 201, r
    s, g = cloud.gate(cloud.a, X)
    assert s == 200 and g["status"] == "records_found", g


def test_a_closed_org_gets_no_access_token(cloud):
    _set_status(cloud.t, cloud.t.a, "closed")
    s, body = cloud.call("/v1/oauth/token", form=cloud.token_form(cloud.a.clients["capture"]))
    assert s == 403 and body["error"] == "org_not_active", body


def test_background_jobs_cover_every_org_but_closed_and_billing_only_the_live_ones(tenancy):
    """Ruled 2026-10-29: evidence and suppression never pause for non-payment; only closed leaves (offboarding leaves
    once its final export is taken, in the offboarding lane). The billing usage job meters live statuses only."""
    port, dbname = _port_db(tenancy)
    worker = make_login_role(port, dbname, "consentvault_worker")
    for status in ("trial", "past_due", "active", "suspended", "offboarding", "closed"):
        _set_status(tenancy, tenancy.a, status)
        with psycopg.connect(worker, autocommit=True, row_factory=psycopg.rows.dict_row) as w:
            def ids(job):
                return {r["org_id"] for r in w.execute("SELECT org_id FROM consentvault.dispatch_orgs(%s)", (job,))}
            for job in ("sync", TENANT_ANCHOR_JOB, "reconcile"):
                assert (tenancy.a.org_id in ids(job)) is (status != "closed"), (status, job)
                assert tenancy.b.org_id in ids(job)
            assert (tenancy.a.org_id in ids("usage")) is (status in ("trial", "past_due", "active")), status


def test_an_event_captured_while_suspended_is_pushed_and_anchored_without_reinstatement(tenancy, pg_server, tmp_path):
    from consentvault import db
    from consentvault.cmd_anchor import anchor_tenants
    from consentvault.evidence import LocalEcdsaSigner
    from consentvault.providers.anchors import FileAnchorSink

    env = SyncEnv(tenancy, pg_server["port"])
    crm = env.add_system(tenancy.a, "crm")
    _set_status(tenancy, tenancy.a, "suspended")
    ev, res = env.stop(tenancy.a, X)  # capture keeps working while suspended
    assert len(res.queued) == 1
    env.run_worker()
    sent = env.transport.to(crm.endpoint)
    assert len(sent) == 1 and json.loads(sent[0].body)["state"] == "denied"
    sink = FileAnchorSink(tmp_path / "alpha.jsonl")
    with db.connect(env.worker_dsn) as w, tenancy.app() as app:
        results = anchor_tenants(w, app, LocalEcdsaSigner.generate("k", 1),
                                 lambda org: sink if org == tenancy.a.org_id else FileAnchorSink(tmp_path / "x.jsonl"))
    mine = [r for r in results if r["org_id"] == str(tenancy.a.org_id)]
    assert mine and mine[0]["status"] == "published" and mine[0]["seq"] >= ev.seq
    with tenancy.superuser() as su:
        assert su.execute("SELECT status FROM consentvault.organization WHERE org_id = %s",
                          (tenancy.a.org_id,)).fetchone()["status"] == "suspended"


# ---- the outbox hook in capture ----------------------------------------------------------------------------------------
def _outbox(t, org, contact_fp):
    with t.superuser() as su:
        return su.execute("SELECT version, status FROM consentvault.outbox WHERE org_id = %s AND contact_fp = %s"
                          " ORDER BY version, created_at", (org.org_id, contact_fp)).fetchall()


def test_capture_queues_its_pushes_in_the_same_transaction_and_a_later_grant_lifts_nothing(cloud, pg_server):
    env = SyncEnv(cloud.t, pg_server["port"])
    env.add_system(cloud.t.a, "crm")
    fp = env.fp(cloud.t.a, X)
    stop = {"contact": X, "event_type": "revoke", "channels": ["sms"], "purposes": ["marketing"], "method": "keyword"}
    assert cloud.call("/v1/events", stop, token=cloud.token(cloud.a, "capture"))[0] == 201
    assert _outbox(cloud.t, cloud.t.a, fp) == [{"version": 1, "status": "pending"}]  # the capture queued the stop
    # an otp-verified grant after the person's own stop is recorded as a later line; only a consent post matched to the contact
    # point lifts a stop (tests/test_stop_lift.py), so no release is written and the pushed state stays on the stop
    s, r = cloud.grant(cloud.a, X, contact_verification="otp", token=cloud.token(cloud.a, "capture_verified"))
    assert s == 201, r
    with cloud.t.superuser() as su:
        moved = su.execute("SELECT state, version, basis_event_id FROM consentvault.state_version WHERE org_id = %s"
                           " AND contact_fp = %s", (cloud.t.a.org_id, fp)).fetchone()
        releases = su.execute("SELECT count(*) AS n FROM consentvault.event WHERE org_id = %s AND event_type = 'release'",
                              (cloud.t.a.org_id,)).fetchone()["n"]
    assert moved["state"] == "denied" and releases == 0
    assert _outbox(cloud.t, cloud.t.b, env.fp(cloud.t.b, X)) == []  # nothing crosses to the other organisation


# ---- an operator alarm row ----------------------------------------------------------------------------------------------
def test_an_operator_alarm_row_is_seen_by_the_operator_only_and_acknowledged_once(cloud):
    ref = str(uuid.uuid4())
    with cloud.t.app() as app, org_transaction(app, cloud.t.token(cloud.t.a)):
        raise_operator_alarm(app, name="capture.link_failed", error_class="LedgerError", ref_kind="raw_post", ref_id=ref,
                             request_id="req-1")
    with cloud.t.superuser() as su:
        su.execute("SET ROLE consentvault_operator")
        rows = su.execute("SELECT org_id, name, ref_kind, ref_id, error_class, request_id, acknowledged_at"
                          " FROM consentvault.operator_alarm").fetchall()
        su.execute("RESET ROLE")
    assert len(rows) == 1
    row = rows[0]
    assert (row["org_id"], row["name"], row["ref_kind"], str(row["ref_id"]), row["error_class"]) == (
        cloud.t.a.org_id, "capture.link_failed", "raw_post", ref, "LedgerError")
    assert row["request_id"] and row["acknowledged_at"] is None
    # the other organisation's tenant never sees it; nobody deletes it; it is acknowledged once
    with cloud.t.app() as app, org_transaction(app, cloud.t.admin_token(cloud.t.b.org_id)):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT * FROM consentvault.operator_alarm")
    with cloud.t.superuser() as su:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            su.execute("DELETE FROM consentvault.operator_alarm")
        su.execute("SET ROLE consentvault_operator")
        su.execute("UPDATE consentvault.operator_alarm SET acknowledged_at = now(), acknowledged_by = 'op-1'")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation):
            su.execute("UPDATE consentvault.operator_alarm SET acknowledged_by = 'op-2'")
        su.execute("RESET ROLE")


def test_a_runtime_role_raises_an_alarm_only_for_its_own_organisation(tenancy):
    with tenancy.app() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):  # row-level security: org_id must be current_org()
            with org_transaction(app, tenancy.token(tenancy.a)):
                app.execute("INSERT INTO consentvault.operator_alarm (org_id, name, error_class) VALUES (%s, 'x', 'E')",
                            (tenancy.b.org_id,))


# ---- the email send log -------------------------------------------------------------------------------------------------
def test_the_postgres_send_log_appends_domain_only_rows_the_operator_reads(tenancy):
    log = PostgresSendLog(tenancy.app)
    log.append(SendRecord("invite", "Example.COM", "sent", "ses", "msg-1"))
    log.append(SendRecord("security_alert", "example.org", "failed", "smtp", None,
                          "550 mailbox jane.doe@example.org unknown"))
    with tenancy.superuser() as su:
        su.execute("SET ROLE consentvault_operator")
        rows = su.execute("SELECT type, recipient_domain, outcome, provider, provider_message_id, detail"
                          " FROM consentvault.notify_send_log ORDER BY send_id").fetchall()
        su.execute("RESET ROLE")
    assert rows == [
        {"type": "invite", "recipient_domain": "example.com", "outcome": "sent", "provider": "ses",
         "provider_message_id": "msg-1", "detail": None},
        {"type": "security_alert", "recipient_domain": "example.org", "outcome": "failed", "provider": "smtp",
         "provider_message_id": None, "detail": "550 mailbox [address] unknown"}]
    with tenancy.app() as app, pytest.raises(psycopg.errors.InsufficientPrivilege):
        app.execute("SELECT * FROM consentvault.notify_send_log")  # the runtime role appends and never reads
    with tenancy.superuser() as su, pytest.raises(psycopg.errors.IntegrityConstraintViolation):
        su.execute("UPDATE consentvault.notify_send_log SET outcome = 'sent'")
    with pytest.raises(SendLogError, match="could not be written"):
        log.append(SendRecord("invite", "not a domain", "sent", "ses", "msg-2"))
    assert scrub_detail("bounce for a@b.c and <x@y.z>") == "bounce for [address] and <[address]>"


# ---- the operator role ---------------------------------------------------------------------------------------------------
# Every column the operator may read, by table. Read from the catalog, so a grant added later fails here until a person
# adds it to this list on purpose. organization: no name (the session lane reads each name inside its own tenant).
OPERATOR_COLUMNS = {
    "audit_event": "*", "notify_send_log": "*", "operator_alarm": "*",
    # the cloud key provider's destruction record (0028): org references, key ids and dates, no personal data; the
    # operator role owns its two access functions, and no login reads the table directly
    "kms_key_ledger": "*",
    "billing_account": {"org_id", "stripe_customer_id"},
    # brand_ids and status: the site-key lookup answers a retired source by name (0015)
    "capture_source": {"org_id", "source_id", "allowed_origins", "brand_ids", "status"},
    # site_key_hash: the hash the site-key lookup compares (0015); never the key itself
    "credential": {"org_id", "credential_id", "source_id", "kind", "alg", "public_key", "scope", "revoked_at",
                   "site_key_hash"},
    # the checklist writer checks the version is approved; check_id is what the insert returns (0015)
    "doc_checklist": {"org_id", "version", "status"},
    # the Twenty receiver resolves its id before any tenant is entered (0060): the hash of the receiver id, its system, and
    # whether that system is a live Twenty one; never a secret, never a contact
    "connector_receiver": {"org_id", "receiver_hash", "system_id", "retired_at"},
    "connected_system": {"org_id", "system_id", "status", "connector"},
    # the Twenty workflow credential's check resolves its secret's hash before any tenant is entered (0061); never a secret
    "workflow_credential": {"org_id", "credential_id", "system_id", "secret_hash", "expires_at", "overlap_until",
                            "revoked_at", "tokens", "refilled_at"},
    "doc_check_result": {"org_id", "check_id"},
    # the confirmation lookups (0049) read across organizations: which account an inbound key belongs to, which organization
    # owns a verified link host, which organizations have a message waiting; ids and status only, never a secret or a message
    "sending_account": {"org_id", "account_id", "inbound_key"},
    "confirmation_link_host": {"org_id", "host", "status"},
    "confirmation_send_intent": {"org_id", "status", "send_id", "contact_fp", "channel"},   # + the seed of effect intents from the queue (0091)
    "event": {"org_id", "event_id", "received_at", "seq", "source_id", "row_hash"},   # + the receipt of an event (0103)
    # the pure-projection lane: the seed reads the old push queue, the receipt and the stop reader read the history, and the reroute check
    # reads the stored posts it compares (0091, 0093, 0103, 0108); ids, hashes, times and flags, never a contact or a payload
    "outbox": {"org_id", "outbox_id", "system_id", "contact_fp", "channel", "status"},
    "post_history": {"org_id", "event_id", "post_id", "history_seq", "row_hash", "received_at", "contact_fp", "event_type_sent", "standing",
                     "earliest_copy", "channels_sent", "origin_sent", "method_sent", "source_id_sent", "label"},
    "post_history_seal": {"org_id", "history_seq"},
    "post_history_event_index": {"org_id", "event_id", "seq", "received_at", "source_id"},
    "event_source_post": {"org_id", "post_id", "role"},
    "post_history_receipts": {"org_id", "event_id", "chain_seq", "row_hash", "received_at", "frozen"},
    "history_stop_lift": {"org_id", "stop_event_id"},
    "effect_watermark": {"org_id"},
    "raw_post_original_arrival": {"org_id", "post_id", "arrived_at"},
    "raw_post": {"org_id", "post_id", "received_at", "body_sha256"},
    # an offboarding org leaves the evidence jobs once its final export is taken (0014)
    "offboarding_request": {"org_id", "state", "final_export_at"},
    # pending invitees' addresses: accepted 2026-10-29 (staff addresses, not consumers; the invitation lookup needs them)
    "invite": {"org_id", "invite_id", "email_norm", "role", "token_digest", "invited_by", "invited_by_operator",
               "expires_at", "accepted_at", "withdrawn_at"},
    "member": {"org_id", "member_id", "idp_issuer", "idp_subject", "role"},
    "org_sso": {"org_id", "version", "workos_org_id"},  # one sign-in-service organization binds to one organization (0042)
    "org_status_history": {"org_id", "seq"},
    "organization": {"org_id", "status", "created_at"},
    "seal": {"org_id", "event_id"},
}


def test_the_operator_reads_only_the_listed_columns_and_never_an_organisation_name(tenancy):
    with tenancy.superuser() as su:
        cols = su.execute(
            "SELECT c.relname AS t, a.attname AS col FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped"
            " WHERE n.nspname = 'consentvault' AND c.relkind IN ('r', 'p', 'v') AND NOT c.relispartition"
            " AND has_column_privilege('consentvault_operator', c.oid, a.attnum, 'SELECT')").fetchall()
        whole = {r["t"] for r in su.execute(
            "SELECT c.relname AS t FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = 'consentvault' AND c.relkind IN ('r', 'p', 'v')"
            " AND has_table_privilege('consentvault_operator', c.oid, 'SELECT')")}
    readable: dict[str, set] = {}
    for r in cols:
        readable.setdefault(r["t"], set()).add(r["col"])
    assert {t for t, v in OPERATOR_COLUMNS.items() if v == "*"} == whole
    assert set(readable) == set(OPERATOR_COLUMNS), set(readable) ^ set(OPERATOR_COLUMNS)
    for t, allowed in OPERATOR_COLUMNS.items():
        if allowed != "*":
            assert readable[t] == allowed, (t, readable[t] ^ allowed)
    assert "name" not in readable["organization"]
