"""``python -m consentvault.jobs <job>``: the scheduled jobs the cloud runs, one name each (tofu compute schedules.tf).

A job that maps to a product command runs it (the same code as ``consentvault <command>``). A job the product does not
have yet is refused by name with exit 2, so a schedule that fires it shows a failed task, never a quiet success.

In the cloud (``db_auth = iam``) every job in ``HEARTBEAT_JOBS`` sends one CloudWatch heartbeat after a clean run (exit 0):
metric ``Heartbeat``, dimension ``Job`` = the job name, in the job's own namespace ``ConsentVault/Heartbeat/<job>`` (the
only one its task role may write), with the task role's access. Nothing else is sent. A failed run sends none, so the
missed-heartbeat alarm fires; a heartbeat that cannot be sent fails the run with exit 2 naming the job. The alarm relay
sends its own heartbeat (``cmd_alarms``) and is not beaten twice. The self-host sends none.
"""

from __future__ import annotations

import os
import sys
from typing import Mapping, Sequence

from .safelog import describe
from . import cli
from .errors import ConsentVaultError

# job name -> the CLI command that runs it, or None when the product has no such job yet
JOBS: dict[str, str | None] = {
    "seal": "seal",
    "anchor": "anchor",
    "verify-chain": "verify-chain",
    "verify-seals": "verify-seals",
    "erasure-resume": "erasure-resume",
    "replay-sweep": "replay-sweep",
    "erasure-commit-sweep": "erasure-commit-sweep",
    "alarm-relay": "alarm-relay",
    "usage-daily": "usage-daily",
    "usage-retry": "usage-retry",
    "usage-acknowledge": "usage-acknowledge",
    "records-exports": "records-exports",
    "records-backfill": "records-backfill",
    "isolation-self-test": "isolation-self-test",
    "key-lifecycle": "key-lifecycle",
    "restore-drill": "restore-drill",
    "twenty-reconcile": "twenty-reconcile",
    "twenty-workflow-reminders": "twenty-workflow-reminders",
}
EXIT_REFUSED = 2
EXIT_HEARTBEAT = cli.EXIT_ERROR

# Jobs the cloud schedules whose heartbeat this runner sends (the alarm relay sends its own; records-backfill is a one-shot
# run on demand and is not scheduled, so it has none).
HEARTBEAT_JOBS = ("seal", "anchor", "verify-chain", "verify-seals", "erasure-resume", "usage-daily", "usage-retry",
                  "replay-sweep", "erasure-commit-sweep", "records-exports", "key-lifecycle", "isolation-self-test",
                  "restore-drill", "twenty-reconcile", "twenty-workflow-reminders")


def _task_role_access(env: Mapping[str, str]):
    from .providers.rds_iam import ContainerCredentials

    return ContainerCredentials(env=env)


def _cloud(env: Mapping[str, str]) -> bool:
    return (env.get("CONSENTVAULT_DB_AUTH") or env.get("CV_DB_AUTH") or "").strip().lower() == "iam"


def _beat(job: str, env: Mapping[str, str]) -> int:
    from .alarm_relay import CloudWatchHeartbeat

    region = env.get("AWS_REGION")
    if not region:
        print(f"consentvault.jobs: {job} finished but its heartbeat needs AWS_REGION; failing the run so the gap is seen",
              file=sys.stderr)
        return EXIT_HEARTBEAT
    try:
        CloudWatchHeartbeat(region, _task_role_access(env), job=job).beat()
    except ConsentVaultError as exc:
        print(f"consentvault.jobs: {job} finished but its heartbeat could not be sent: {describe(exc)}", file=sys.stderr)
        return EXIT_HEARTBEAT
    return cli.EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    from . import safelog as _safelog
    _safelog.setup_process()  # the scrub filter on every handler, warnings, and the exception hooks
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in JOBS:
        print(f"consentvault.jobs: name one job of: {', '.join(sorted(JOBS))}", file=sys.stderr)
        return EXIT_REFUSED
    command = JOBS[args[0]]
    if command is None:
        print(f"consentvault.jobs: the job {args[0]!r} is not built in this product yet; nothing was run",
              file=sys.stderr)
        return EXIT_REFUSED
    rc = cli.main([command, *args[1:]])
    if rc == cli.EXIT_OK and args[0] in HEARTBEAT_JOBS and _cloud(os.environ):
        return _beat(args[0], os.environ)
    return rc


if __name__ == "__main__":
    sys.exit(main())
