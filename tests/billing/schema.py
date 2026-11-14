"""The vault schema the billing tests run on: the migrations billing depends on (0001-0004) plus its own (0007).

Other lanes' migrations (sync, admin, erasure) are not applied here, so a half-finished neighbour cannot turn a
billing test red. The repository-wide suite still applies every migration in order.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from consentvault import db

# 0004_sync joined at the integration pass: the tenant ledger writer queues the sync outbox in its own transaction, so
# every vault that records an event carries the sync schema.
SUBSET = ("0001_init.sql", "0002_tenancy.sql", "0003_replay_guard.sql", "0004_sync.sql", "0007_billing.sql", "0010_operator_alarm.sql",
          "0012_suspension_reason.sql", "0027_usage_plan_of_record.sql", "0029_billing_sent_marks.sql", "0031_billing_verdicts_and_locks.sql",
          "0032_usage_run_and_audit.sql", "0036_gate_check_tally.sql", "0040_price_change_mark.sql", "0041_price_set_mark.sql",
          "0065_billing_clock.sql")


def apply_billing_schema(raw_dsn: str) -> None:
    src = db.default_migrations_dir()
    with tempfile.TemporaryDirectory(prefix="cv-billing-mig-") as tmp:
        for name in SUBSET:
            shutil.copy(src / name, Path(tmp) / name)
        with db.connect(raw_dsn) as conn:
            db.migrate(conn, tmp)
