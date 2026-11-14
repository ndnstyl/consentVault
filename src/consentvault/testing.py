"""Deterministic test switches (confirmations.md section 13). Production never sets ``CONSENTVAULT_TEST_SEAMS``.

``fail_reads`` is a set of read names: a named read behaves exactly as if its database read had failed (its field is null
and named in ``partial``). ``hold_steps`` is a set of step names a job leaves unfinished while the name is present.
``overrides`` holds numeric overrides by name. Changing any of them is refused (``RuntimeError``) unless the process started
with ``CONSENTVAULT_TEST_SEAMS=1``; no clock or timeout is involved.
"""

from __future__ import annotations

import os

ENV = "CONSENTVAULT_TEST_SEAMS"


def _armed() -> bool:
    return os.environ.get(ENV) == "1"


def _refuse(what: str) -> None:
    if not _armed():
        raise RuntimeError(f"{what} is a test switch and {ENV}=1 is not set; refused")


class _GuardedSet(set):
    def add(self, item):
        _refuse("consentvault.testing")
        super().add(item)

    def update(self, *others):
        _refuse("consentvault.testing")
        super().update(*others)

    def difference_update(self, *others):
        _refuse("consentvault.testing")
        super().difference_update(*others)


class _GuardedDict(dict):
    def __setitem__(self, key, value):
        _refuse("consentvault.testing.overrides")
        super().__setitem__(key, value)

    def pop(self, *args):
        _refuse("consentvault.testing.overrides")
        return super().pop(*args)


fail_reads: set = _GuardedSet()
hold_steps: set = _GuardedSet()
overrides: dict = _GuardedDict()


def override(name: str, default):
    """The numeric override for ``name``, or ``default``. Reading never needs the switch."""
    return overrides.get(name, default)
