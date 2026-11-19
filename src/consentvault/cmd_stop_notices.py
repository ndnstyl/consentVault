"""``consentvault stop-notices-send``: email the stop notices that are queued (every minute, so a stop reads as immediate).

One pass of ``notify.stop_notice.StopNoticeSender`` as the worker login: each admin's queued notices leave as one email per
burst, a failed send is a send-log row and an alarm and stays queued for the next pass. Exit 0 when nothing failed, 2 when a send
failed (so no heartbeat is beaten and the missed-heartbeat alarm fires), 3 when the login is not the worker's.
"""

from __future__ import annotations

import json
import os

from .cli import EXIT_BROKEN, EXIT_ERROR, EXIT_OK, register
from .errors import ConfigError

ENV_NOTIFIER = "CONSENTVAULT_NOTIFIER"
ENV_PORTAL_URL = "CONSENTVAULT_PORTAL_URL"


def _args(p) -> None:
    return None


def _run(args, cfg) -> int:
    from . import db
    from .notify.stop_notice import StopNoticeSendError, StopNoticeSender
    from .providers.plugins import resolve_object

    portal = (os.environ.get(ENV_PORTAL_URL) or "").strip()
    if not portal.startswith("https://"):
        raise ConfigError(f"{ENV_PORTAL_URL} must be the portal's https address; a stop notice links to the records page")
    name = (os.environ.get(ENV_NOTIFIER) or "").strip()
    if not name:
        raise ConfigError(f"{ENV_NOTIFIER} is not set; stop notices cannot be emailed")
    notifier = resolve_object(name).from_environment(os.environ)
    with db.connect(cfg.require_dsn()) as conn:
        row = conn.execute("SELECT current_user AS u, pg_catalog.pg_has_role(current_user, 'consentvault_worker', 'MEMBER') AS ok").fetchone()
        if not row["ok"]:
            print(json.dumps({"stop_notices_send": "refused", "error": f"login {row['u']} is not a member of consentvault_worker"}), flush=True)
            return EXIT_BROKEN
        try:
            report = StopNoticeSender(notifier, portal_url=portal).run_once(conn)
        except StopNoticeSendError as exc:  # loud-failure-exempt: named on stdout, exit 2, no heartbeat; the send log row and alarm were written by the notifier and the queue rows stay due
            print(json.dumps({"stop_notices_send": "failed", "error": type(exc).__name__}), flush=True)
            return EXIT_ERROR
    print(json.dumps({"stop_notices_send": "done", "emails_sent": report.emails_sent, "stops_listed": report.stops_listed}), flush=True)
    return EXIT_OK


register("stop-notices-send", "email the stop notices that are queued for each organisation's admins", _run, _args)
