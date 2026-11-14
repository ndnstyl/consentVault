"""The periodic passes (confirmations.md section 13): ``recheck_link_hosts(now)`` hourly, ``run_alarm_checks(now)`` every five
minutes and ``purge(now)`` daily. Each runs for every organization, one transaction per organization, on the injected clock.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from .core import ProviderError, log
from .inbound import FAILURE_WINDOW, FAILURES_TO_ALARM

LINK_FAILURES_TO_FAIL = 2
UNREAD_AFTER = timedelta(hours=24)
KEEP_UNMATCHED = timedelta(days=30)
KEEP_TOKEN_AFTER_DISCONNECT = timedelta(days=30)
STUCK_SENDING = timedelta(minutes=15)
REFUSAL_STOP_ALARM_FOR = timedelta(hours=24)
OPTOUT_DEAD_ALARM_FOR = timedelta(days=7)


class JobsMixin:
    def recheck_link_hosts(self, now: Optional[float] = None) -> int:
        """Look each organization's wording link host up again. A host that fails twice in a row is ``failing`` (an alarm shows and
        sends are skipped); one that answers again is ``verified``. A resolver that does not answer changes nothing."""
        checked = 0
        for org in self._org_list("confirmation_org_ids"):
            with self.tx(org) as conn:
                when = self._when(conn, now)
                row = self._link_host_row(conn)
                if row is None or row["status"] == "pending_dns":
                    continue
                try:
                    ok = self._dns_matches(row)
                except (TimeoutError, OSError):
                    log.warning("the DNS resolver did not answer; the link host check was skipped")
                    continue
                checked += 1
                if ok:
                    conn.execute("UPDATE consentvault.confirmation_link_host SET status = 'verified', fail_count = 0,"
                                 " last_checked_at = %s WHERE org_id = %s", (when, org))
                    if row["status"] == "failing":
                        self._alarm_clear(conn, "link_host_failing", when)
                    continue
                fails = row["fail_count"] + 1
                status = "failing" if fails >= LINK_FAILURES_TO_FAIL else row["status"]
                conn.execute("UPDATE consentvault.confirmation_link_host SET status = %s, fail_count = %s, last_checked_at = %s"
                             " WHERE org_id = %s", (status, fails, when, org))
                if status == "failing":
                    self._alarm_raise(conn, "link_host_failing", {"host": row["host"]}, when)
        return checked

    def run_alarm_checks(self, now: Optional[float] = None) -> None:
        """Open or clear the alarms that are decided by the passing of time rather than by one request."""
        for org in self._org_list("confirmation_org_ids"):
            with self.tx(org) as conn:
                self._alarm_checks(conn, org, self._when(conn, now))

    def _alarm_checks(self, conn, org, when: datetime) -> None:
        def settle(kind: str, active: bool, detail: Optional[dict] = None) -> None:
            if active:
                self._alarm_raise(conn, kind, detail or {}, when)
            else:
                self._alarm_clear(conn, kind, when)

        unread = conn.execute("SELECT count(*) AS n, min(received_at) AS oldest FROM consentvault.confirmation_reply"
                              " WHERE org_id = %s AND state = 'to_read' AND received_at <= %s", (org, when - UNREAD_AFTER)).fetchone()
        settle("replies_unread_24h", unread["n"] > 0, {"count": unread["n"]})
        _, stale = self._delivery_state(conn, org, when)
        settle("delivery_reports_stale", stale)
        fails = conn.execute("SELECT count(*) AS n FROM consentvault.confirmation_inbound_failure WHERE org_id = %s AND at > %s",
                             (org, when - FAILURE_WINDOW)).fetchone()["n"]
        if fails < FAILURES_TO_ALARM:
            self._alarm_clear(conn, "inbound_signature_failures", when)
        s = self._settings_row(conn)
        cap = s["send_cap_per_hour"] if s else 500
        capped = conn.execute("SELECT 1 FROM consentvault.confirmation_send_intent WHERE org_id = %s AND kind = 'confirmation'"
                              " AND status IN ('sending', 'sent', 'delivered') AND at > %s GROUP BY channel HAVING count(*) >= %s",
                              (org, when - timedelta(hours=1), cap)).fetchone()
        if capped is None:
            self._alarm_clear(conn, "send_cap_reached", when)
        if conn.execute("SELECT 1 FROM consentvault.confirmation_send_intent WHERE org_id = %s AND provider_refusal_stop AND at > %s"
                        " LIMIT 1", (org, when - REFUSAL_STOP_ALARM_FOR)).fetchone() is None:
            self._alarm_clear(conn, "provider_refusal_stop", when)
        if conn.execute("SELECT 1 FROM consentvault.confirmation_send_intent WHERE org_id = %s AND kind = 'optout_reply' AND status = 'dead'"
                        " AND at > %s LIMIT 1", (org, when - OPTOUT_DEAD_ALARM_FOR)).fetchone() is None:
            self._alarm_clear(conn, "optout_reply_dead", when)
        if conn.execute("SELECT 1 FROM consentvault.sending_account WHERE org_id = %s AND status = 'failing' LIMIT 1", (org,)).fetchone() is None:
            self._alarm_clear(conn, "sending_account_failing", when)
        host = self._link_host_row(conn)
        if host is None or host["status"] != "failing":
            self._alarm_clear(conn, "link_host_failing", when)
        stuck = conn.execute("SELECT * FROM consentvault.confirmation_send_intent WHERE org_id = %s AND status = 'sending'"
                             " AND at <= clock_timestamp() - make_interval(secs => %s) FOR UPDATE SKIP LOCKED",
                             (org, STUCK_SENDING.total_seconds())).fetchall()
        for it in stuck:  # a crash between the provider's answer and its record: never sent again, never silent
            self._dead(conn, org, it, when, "send_outcome_unknown")
        if stuck:
            self._alarm_raise(conn, "send_outcome_unknown", {"count": len(stuck)}, when)

    def purge(self, now: Optional[float] = None) -> None:
        """Daily: unmatched inbound texts and the test reply go 30 days after they arrived; a Twilio auth token goes 30 days after
        the account was disconnected; old signature-failure counts go. The seen-message rows stay, so a replay months later is
        still refused."""
        for org in self._org_list("confirmation_org_ids"):
            with self.tx(org) as conn:
                when = self._when(conn, now)
                conn.execute("DELETE FROM consentvault.confirmation_connect_test WHERE org_id = %s AND received_at < %s",
                             (org, when - KEEP_UNMATCHED))
                conn.execute("DELETE FROM consentvault.confirmation_reply WHERE org_id = %s AND key_kind = 'org' AND received_at < %s",
                             (org, when - KEEP_UNMATCHED))
                conn.execute("UPDATE consentvault.confirmation_send_intent SET dest_ct = NULL, body_ct = NULL WHERE org_id = %s"
                             " AND kind <> 'confirmation' AND created_at < %s AND status <> 'intent' AND status <> 'sending'",
                             (org, when - KEEP_UNMATCHED))
                conn.execute("UPDATE consentvault.sending_account SET auth_token_ct = NULL WHERE org_id = %s AND status = 'disconnected'"
                             " AND disconnected_at < %s", (org, when - KEEP_TOKEN_AFTER_DISCONNECT))
                conn.execute("DELETE FROM consentvault.confirmation_inbound_failure WHERE org_id = %s AND at < %s",
                             (org, when - timedelta(days=2)))
