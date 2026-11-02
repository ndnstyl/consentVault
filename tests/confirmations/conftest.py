import pytest

from contract_world.fixtures import *  # noqa: F401,F403
from contract_world.fixtures import pytest_collection_modifyitems  # noqa: F401
from contract_world.confirm import arm, build_stack


@pytest.fixture
def stack(world):
    """The confirmation stack, built the moment the world is first touched (as ``armed`` is), so a test that calls the admin routes
    before it reads anything from the stack finds the confirmation routes mounted."""
    lazy = Lazy(lambda: build_stack(world), needs=[world])
    world._after(lazy._get)
    return lazy


@pytest.fixture
def armed(world, stack):
    """The world is armed (rules on, accounts connected) the moment the test first touches it, before its first grant, so a
    rule is on when a grant arrives (a rule never sends for older grants)."""
    def make():
        st = stack._get()  # the fixture's own stack is built and cached first, so armed.stack is stack
        res = arm(st, world._get().a)
        assert res.stack is st
        return res
    lazy = Lazy(make, needs=[world])
    world._after(lazy._get)
    return lazy


@pytest.fixture
def db_follows_service_clock(stack, monkeypatch):
    """The sender's database-clock seam answers with the service's injected clock, so a test that drives time (an hour passing,
    a clock that ticks between the hours check and the send) keeps testing the same decision against the clock the sender reads."""
    from consentvault.confirm import sender as S
    monkeypatch.setattr(S, "db_now", lambda conn: stack.service._dt())
