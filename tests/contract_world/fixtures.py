"""Fixtures shared by the records, confirmations and setup suites (imported into each suite's conftest)."""

import os

import pytest

os.environ.setdefault("CONSENTVAULT_TEST_SEAMS", "1")  # the failed-reads switch refuses to arm without it (confirmations.md section 13)

from admin.conftest import vault  # noqa: F401  (the multi-mode vault with a fake identity provider and the admin app)

from .world import World


class Lazy:
    """Builds on first use, so a feature that is not built yet fails inside the test body (a failure), not in fixture
    setup (an error). `needs` are built first, outside the build, so a callback they run (arming) can use this object
    without re-entering its build; a re-entrant build is refused loudly."""

    def __init__(self, make, needs=()):
        object.__setattr__(self, "_make", make)
        object.__setattr__(self, "_obj", None)
        object.__setattr__(self, "_after_build", [])
        object.__setattr__(self, "_needs", tuple(needs))
        object.__setattr__(self, "_building", False)

    def _get(self):
        g = object.__getattribute__
        for dep in g(self, "_needs"):
            dep._get()
        if g(self, "_obj") is None:  # a callback run by a dependency may have built this already
            if g(self, "_building"):
                raise RuntimeError("re-entrant build of a lazy fixture: a double build would split the test's state")
            object.__setattr__(self, "_building", True)
            try:
                object.__setattr__(self, "_obj", g(self, "_make")())
            finally:
                object.__setattr__(self, "_building", False)
            for fn in g(self, "_after_build"):
                fn()
        return g(self, "_obj")

    def _after(self, fn):
        """Run fn right after the object is first built (used to arm a world before the test's first action on it)."""
        object.__getattribute__(self, "_after_build").append(fn)

    def __getattr__(self, name):
        return getattr(self._get(), name)

    def __setattr__(self, name, value):
        setattr(self._get(), name, value)


@pytest.fixture
def world(vault, tmp_path):
    """Built on first use, so a feature that is not built yet (the evidence-store mount) fails inside the test, not in setup."""
    return Lazy(lambda: World(vault, tmp_path))


def pytest_collection_modifyitems(config, items):
    """The whole set carries the contract_pending marker and stays out of every run that does not ask for it by name,
    whatever other -m expression a script passes (CI passes -m "not network", which would otherwise re-include it)."""
    expr = config.getoption("-m") or ""
    if "contract_pending" in expr:
        return
    dropped = [i for i in items if i.get_closest_marker("contract_pending")]
    if dropped:
        config.hook.pytest_deselected(items=dropped)
        items[:] = [i for i in items if not i.get_closest_marker("contract_pending")]
