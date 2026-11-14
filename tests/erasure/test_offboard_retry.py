"""Offboarding's key-destruction step survives a provider that crashed or throttled mid-way.

A cloud provider writes its schedule before asking KMS, so after a crash it can read "pending" with no date yet; a retry
must finish the schedule and save the real date, never an empty one. A throttle or a missing setting is the provider
failing like any other: it reaches the caller as the named error, and when the database refuses to record a schedule
the "cancel it by hand" instruction survives whatever the cancel itself raised.
"""

import psycopg
import pytest

from consentvault.providers.errors import ProviderConfigError, ProviderTransportError
from consentvault.providers.keys import DestructionStatus
from consentvault.tenancy import offboard
from consentvault.tenancy.admin_base import ApiError
from consentvault.tenancy.offboard import DestructionError

from .support import OPERATOR


class Custody:
    """The suite's real provider, with one behaviour changed at a time."""

    def __init__(self, inner, *, crashed_schedule=False, schedule_error=None, cancel_error=None):
        self._inner, self.crashed, self.schedule_error, self.cancel_error = inner, crashed_schedule, schedule_error, cancel_error
        self.scheduled = 0

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def status(self, org_id):
        st = self._inner.status(org_id)
        if self.crashed and st.state == "active":  # recorded before KMS was asked; the date never came back
            return DestructionStatus(org_id, "pending", self._inner._clock(), None)
        return st

    def schedule_destruction(self, org_id, **kw):
        if self.schedule_error:
            raise self.schedule_error
        self.scheduled += 1
        self.crashed = False
        return self._inner.schedule_destruction(org_id, **kw)

    def cancel_destruction(self, org_id):
        if self.cancel_error:
            raise self.cancel_error
        return self._inner.cancel_destruction(org_id)


class RefusesTheRecord:
    """A connection whose UPDATE of the org key rows is refused, as a lost connection or a guard would."""

    def __init__(self, conn):
        self._c = conn

    def __getattr__(self, name):
        return getattr(self._c, name)

    def execute(self, sql, *a, **kw):
        if isinstance(sql, str) and sql.startswith("UPDATE consentvault.org_key SET"):
            raise psycopg.errors.InsufficientPrivilege("injected: the database refused the schedule record")
        return self._c.execute(sql, *a, **kw)

    def transaction(self, *a, **kw):
        return self._c.transaction(*a, **kw)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return self._c.__exit__(*a)


def _run(env, custody, conn_wrap=lambda c: c):
    env.open_access(env.t.a)
    with env.operator() as c:
        return offboard.run_offboard(conn_wrap(c), token_key=env.t.key, custody=custody, crypto=env.t.crypto,
                                     signer=env.signer, store=env.archive, notifier=env.notifier, operator_id=OPERATOR,
                                     request_id="req-off", org_id=env.t.a.org_id, reason="contract ended",
                                     window_days=30, clock=env.clock, deliver=lambda o, r, pkg, sha: None)


def _db(env, sql, *args):
    with env.t.superuser() as su:
        return su.execute(sql, args).fetchall()


def test_a_schedule_recorded_before_a_crash_is_finished_and_its_real_date_is_saved(env):
    custody = Custody(env.custody, crashed_schedule=True)
    out = _run(env, custody)
    assert custody.scheduled == 1
    assert out["steps"]["key_destruction"]["destroy_after"] is not None
    rows = _db(env, "SELECT destroy_after FROM consentvault.org_key WHERE org_id = %s", env.t.a.org_id)
    assert rows and all(r["destroy_after"] is not None for r in rows)


@pytest.mark.parametrize("error", [ProviderTransportError("KMS throttled the request"),
                                   ProviderConfigError("CONSENTVAULT_KMS_LIFECYCLE_ROLE_ARN is not set")])
def test_a_throttle_or_a_missing_setting_while_scheduling_is_the_named_key_error(env, error):
    with pytest.raises(ApiError) as exc:
        _run(env, Custody(env.custody, schedule_error=error))
    assert exc.value.name == "key_unavailable"


@pytest.mark.parametrize("error", [ProviderTransportError("KMS throttled the cancel"),
                                   ProviderConfigError("CONSENTVAULT_KMS_LIFECYCLE_ROLE_ARN is not set")])
def test_the_cancel_by_hand_instruction_survives_any_cancel_failure(env, error):
    with pytest.raises(DestructionError, match="cancel it by hand before"):
        _run(env, Custody(env.custody, cancel_error=error), conn_wrap=RefusesTheRecord)
