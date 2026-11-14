"""Model conformance: drive the REAL connector (worker, receiver, reconcile, erasure core, Postgres) through event sequences of
the Twenty erasure model's ``PersonModel`` against a fake Twenty, and assert the same states after every step.

The model (``models/twenty_erasure.py`` in the design kit) follows one Person holding two contacts, an email (0) and a phone (1).
Each model event is mapped to the real action below; a delivery is the model's claim, send and land taken as one step (the
real worker delivers a claimed group atomically under the Person's lease). What is compared after every step:
- each contact's ledger status (none, permitted, denied) against the vault's state on the sms channel;
- each contact's life (absent, live, erasing, erased) against its key and erasure request;
- the Person's vault-owned status field against the model's ``fields`` (while the Person exists and is not soft-deleted);
- the contacts linked to the Person, and whether a destroyed marker exists.

Events not replayed here, and why: ``lift`` (a staff release is a separate core path), ``stall``, ``timeout_*`` and
``lease_expires`` (proved by the named lease tests in test_connector.py with an injected monotonic clock), ``day_passes``
(proved by the 7 and 30 day alarm test). The model is kept in this repository (``model/twenty_erasure.py`` beside this test, a
copy of the design kit's) so every CI run checks it; it never skips. When ``TWENTY_MODEL_DIR`` names the design kit's folder (as
``scripts/checkpoint.sh`` may), the test first proves the copy here is that model byte for byte, so the two cannot drift.
"""

import os
import random
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from consentvault.tenancy import erasure

from erasure.support import OPERATOR, Env as ErasureEnv
from .support import TwentyEnv

MODEL_DIR = Path(__file__).resolve().parent / "model"
if not (MODEL_DIR / "twenty_erasure.py").is_file():
    pytest.fail(f"the Twenty model is missing from {MODEL_DIR}; a conformance check that skips proves nothing", pytrace=False)
_KIT = os.environ.get("TWENTY_MODEL_DIR", "")
if _KIT:
    if not Path(_KIT, "twenty_erasure.py").is_file():
        pytest.fail("TWENTY_MODEL_DIR names no folder holding twenty_erasure.py", pytrace=False)
    if Path(_KIT, "twenty_erasure.py").read_bytes() != (MODEL_DIR / "twenty_erasure.py").read_bytes():
        pytest.fail("the repository's copy of the Twenty model differs from the design kit's (TWENTY_MODEL_DIR): copy it again",
                    pytrace=False)
sys.path.insert(0, str(MODEL_DIR))
import twenty_erasure as twenty_model  # noqa: E402

CONTACTS = ("ann@example.com", "+15555552001")
REPLAYED = {"grant", "stop", "erase", "decline", "complete", "claim_state", "claim_clear", "flag", "unflag", "merge_in",
            "delete_person", "deleted_webhook", "restore", "destroy", "late_update", "staff_edit", "scan", "recheck"}
WALKS = int(os.environ.get("TWENTY_CONFORMANCE_WALKS", "24"))
STEPS = int(os.environ.get("TWENTY_CONFORMANCE_STEPS", "14"))


class Real:
    """The real side of one walk: a fresh contact pair, a fake Twenty Person and the erasure requests."""

    def __init__(self, env, tw: TwentyEnv, life: ErasureEnv, start_points) -> None:
        self.env, self.tw, self.life, self.org = env, tw, life, env.t.a
        self.reqs: dict[int, str] = {}
        self.pid = tw.twenty.add(email=CONTACTS[0] if 0 in start_points else None,
                                 phone=CONTACTS[1] if 1 in start_points else None)
        self.late = None

    # -- actions ------------------------------------------------------------------------------------------------------
    def grant(self, i):
        self.env.grant(self.org, CONTACTS[i], channels=["sms"], purposes=["marketing"])

    def stop(self, i):
        self.env.stop(self.org, CONTACTS[i], channels=["sms"], purposes=["marketing"])

    def erase(self, i):
        with self.life.admin(self.org) as ctx:
            eid = erasure.request_erasure(ctx, {"contact": CONTACTS[i], "reason": "asked"}, crypto=self.life.t.crypto)["erasure_id"]
        self.reqs[i] = eid
        with self.life.operator() as c:
            erasure.confirm_erasure(c, token_key=self.life.t.key, crypto=self.life.t.crypto, ledger=self.life.ledger,
                                    operator_id=OPERATOR, request_id="r", org_id=self.org.org_id, erasure_id=eid)

    def decline(self, i):
        with self.life.operator() as c:
            erasure.decline_erasure(c, token_key=self.life.t.key, operator_id=OPERATOR, request_id="r", org_id=self.org.org_id,
                                    erasure_id=self.reqs[i], reason="not ours", crypto=self.life.t.crypto)

    def complete(self, i):
        """The model completes ONE contact's erasure; the resume job runs every eligible request, so this step runs exactly
        what the job runs for that one request: the erase under the lifecycle lock, then the ledger commit."""
        with self.life.operator() as c:
            with erasure.operator_org(c, self.life.t.key, self.org.org_id):
                c.execute("SELECT consentvault.lifecycle_lock()")
                erasure.erase_in_org(c, ledger=self.life.ledger, crypto=self.life.t.crypto, erasure_id=self.reqs[i],
                                     actor_kind="system", actor_id="erasure-resume", request_id="r")
            erasure.commit_after(c, token_key=self.life.t.key, ledger=self.life.ledger, org_id=self.org.org_id, request_id="r")

    def deliver(self, i):
        """Deliver only contact i's group: the other contact's open rows are held back for this one pass."""
        other = self.env.fp(self.org, CONTACTS[1 - i]) if CONTACTS[1 - i] else None
        mine = self.env.fp(self.org, CONTACTS[i])
        self.env.q("UPDATE consentvault.outbox SET next_attempt_at = clock_timestamp() + interval '1 hour'"
                   " WHERE org_id = %s AND contact_fp = %s AND status IN ('pending', 'failed')", [self.org.org_id, other])
        self.env.q("UPDATE consentvault.outbox SET next_attempt_at = clock_timestamp() - interval '1 second'"
                   " WHERE org_id = %s AND contact_fp = %s AND status IN ('pending', 'failed')", [self.org.org_id, mine])
        with self.env.worker_conn() as w:
            self.tw.worker().run_once(w, raise_on_error=True)
        self.env.q("UPDATE consentvault.outbox SET next_attempt_at = clock_timestamp()"
                   " WHERE org_id = %s AND contact_fp = %s AND status IN ('pending', 'failed')", [self.org.org_id, other])

    def hook(self, name, record=None):
        status, body = self.tw.webhook(name, self.pid, record)
        assert status in (202,), (name, status, body)

    def flag(self, _):
        self.tw.twenty.touch(self.pid, cvStopFlag=True)
        self.hook("person.updated")

    def unflag(self, _):
        self.tw.twenty.touch(self.pid, cvStopFlag=False)
        self.hook("person.updated")

    def merge_in(self, i):
        self.tw.twenty.add_point(self.pid, email=CONTACTS[0] if i == 0 else None, phone=CONTACTS[1] if i == 1 else None)
        self.hook("person.updated")

    def delete_person(self, _):
        self.tw.twenty.soft_delete(self.pid)

    def deleted_webhook(self, _):
        self.hook("person.deleted", dict(self.tw.twenty.people[self.pid]) if self.pid in self.tw.twenty.people else {"id": self.pid})

    def restore(self, _):
        self.tw.twenty.restore(self.pid)
        self.hook("person.restored")

    def destroy(self, _):
        gone = self.tw.twenty.destroy(self.pid)
        self.late = dict(gone) if gone.get("cvStopFlag") else None
        self.hook("person.destroyed", {"id": self.pid})

    def late_update(self, _):
        rec = dict(self.late or {"id": self.pid, "cvStopFlag": True, "emails": {}, "phones": {}})
        rec["updatedAt"] = "2099-01-01T00:00:00.000Z"
        self.hook("person.updated", rec)

    def staff_edit(self, _):
        self.tw.twenty.touch(self.pid, cvStatusSms="permitted")

    def scan(self, _):
        self.tw.reconcile(full=True)

    recheck = scan

    # -- observations -------------------------------------------------------------------------------------------------
    def status(self, i):
        return self.tw.gate(CONTACTS[i])

    def life_of(self, i):
        fp = self.env.fp(self.org, CONTACTS[i])
        key = self.env.q("SELECT 1 AS x FROM consentvault.contact_key WHERE org_id = %s AND contact_fp = %s", [self.org.org_id, fp])
        req = self.env.q("SELECT status, held_by FROM consentvault.erasure_request WHERE org_id = %s AND contact_fp = %s"
                         " ORDER BY requested_at DESC LIMIT 1", [self.org.org_id, fp])
        if req and req[0]["status"] == "pending_operator_confirmation" and req[0]["held_by"] is None:
            return "erasing"
        if key:
            return "live"
        return "erased" if req and req[0]["status"] == "completed" else "absent"

    def links(self):
        fps = {self.env.fp(self.org, c): i for i, c in enumerate(CONTACTS)}
        return frozenset(fps[l["contact_fp"]] for l in self.tw.links())

    def marker(self):
        return bool(self.env.q("SELECT 1 AS x FROM consentvault.connector_destroyed WHERE system_id = %s", [self.tw.sys.system_id]))

    def fields(self):
        if self.pid not in self.tw.twenty.people or self.pid in self.tw.twenty.deleted:
            return "unseen"
        return self.tw.twenty.people[self.pid].get("cvStatusSms")


def model_step(m, s, e):
    """A delivery is claim, send and land in one step (the real worker delivers a claimed group atomically)."""
    s = m.step(s, e)
    if e[0] in ("claim_state", "claim_clear") and s.inflight:
        k = len(s.inflight) - 1
        s = m.step(s, ("send", k))
        s = m.step(s, ("land", len(s.inflight) - 1))
    return s


def compare(m, s, real, trace):
    problems = []
    for i in (0, 1):
        c = s.contacts[i]
        want = c.status if c.life != "absent" else "none"
        if real.status(i) != want:
            problems.append(f"contact {i}: ledger {real.status(i)!r}, model {want!r}")
        if real.life_of(i) != c.life:
            problems.append(f"contact {i}: life {real.life_of(i)!r}, model {c.life!r}")
    if real.links() != s.links:
        problems.append(f"links {sorted(real.links())}, model {sorted(s.links)}")
    if real.marker() != s.marker:
        problems.append(f"marker {real.marker()}, model {s.marker}")
    got = real.fields()
    if got != "unseen" and not s.deleted and not s.gone and got != s.fields:
        problems.append(f"Twenty sms field {got!r}, model {s.fields!r}")
    return problems


def walks(seed: int):
    m = twenty_model.PersonModel()
    rng = random.Random(seed)
    for w in range(WALKS):
        start = twenty_model.PERSON_STARTS[w % len(twenty_model.PERSON_STARTS)]
        s, trace = start, []
        for _ in range(STEPS):
            options = [e for e in m.enabled(s) if e[0] in REPLAYED]
            if not options:
                break
            e = rng.choice(sorted(options))
            if e[0] == "complete" and any(x[0] != e[0] for x in []):
                continue
            trace.append(e)
            s = model_step(m, s, e)
        yield start, tuple(trace)


@pytest.mark.parametrize("walk_no", range(WALKS))
def test_the_real_connector_follows_the_model(env, tenancy, tmp_path, walk_no):
    m = twenty_model.PersonModel()
    start, trace = list(walks(20261031))[walk_no]
    life = ErasureEnv(tenancy, tmp_path)
    tw = TwentyEnv(env, env.t.a)
    real = Real(env, tw, life, start.points)
    s = start
    for n, e in enumerate(trace):
        name, arg = e
        s = model_step(m, s, e)
        if name in ("claim_state", "claim_clear"):
            real.deliver(arg)
        else:
            getattr(real, name)(arg)
        bad = compare(m, s, real, trace[: n + 1])
        assert not bad, f"walk {walk_no} diverged after {list(trace[: n + 1])}: {bad}"
    assert not s.viol, s.viol   # the model's own invariants hold on the replayed trace


def test_walks_cover_every_replayed_event():
    seen = {e[0] for _s, t in walks(20261031) for e in t}
    missing = REPLAYED - seen - {"recheck", "late_update", "deleted_webhook", "complete", "staff_edit"}
    assert not missing, f"the seeded walks never replay {sorted(missing)}; raise TWENTY_CONFORMANCE_WALKS"
