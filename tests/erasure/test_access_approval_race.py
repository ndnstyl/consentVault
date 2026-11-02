"""An admin's operator access approval is never refused by the clock: the approval row's two times are taken from one
instant, so the 24-hour window check holds on every call, not only when two clock reads land in the same microsecond."""

from consentvault.tenancy import legal_process

from .support import OPERATOR

REPEATS = 400


def test_an_approval_is_accepted_every_time_it_is_given(env):
    t = env.t
    with env.admin(t.a) as ctx:
        for i in range(REPEATS):
            ap = legal_process.approve_operator_access(ctx, {"operator_id": OPERATOR, "reason": f"ticket {i}"})
            assert ap["approval_id"]
    with t.superuser() as su:
        row = su.execute("SELECT count(*) AS n, bool_and(expires_at = approved_at + interval '24 hours') AS exact"
                         " FROM consentvault.operator_access_approval WHERE org_id = %s", (t.a.org_id,)).fetchone()
    assert row["n"] == REPEATS and row["exact"] is True


def test_an_approval_then_an_access_opens_every_time(env):
    t = env.t
    for i in range(60):
        a = env.open_access(t.a, reason=f"support {i}")
        with env.operator() as c:
            legal_process.close_operator_access(c, token_key=t.key, operator_id=OPERATOR, request_id="r",
                                                org_id=t.a.org_id, access_id=a["access_id"])
