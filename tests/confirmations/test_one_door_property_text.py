"""The one-door property test on the text reply: random STOP texts, START texts, the provider's retry of a message (a
duplicate) and a crash between the check of the provider's signature and the stop. Every text is stored whole; a START creates
nothing; a stop always counts; a duplicate counts once; a crash is repaired by the rebuild (``rebuild_replies``), twice over."""

import random
import uuid

import pytest

from consentvault import door

from contract_world.confirm import text_in

KINDS = ("stop", "start", "dup", "crash_stop")
SENDERS = ("+13055550142", "+13055550143")


def _sequence(seed):
    rng = random.Random(seed)
    ops = []
    for _ in range(8):
        kind = rng.choice(KINDS)
        if kind == "dup" and not ops:
            kind = "stop"
        ops.append((kind, rng.randrange(2), rng.randrange(len(ops)) if kind == "dup" else None))
    return ops


def _kinds(ops):
    out = []
    for kind, _, ref in ops:
        out.append(out[ref] if kind == "dup" else ("stop" if kind == "crash_stop" else kind))
    return out


@pytest.mark.parametrize("seed", list(range(10)))
def test_the_text_reply_gives_the_reference_history_for_a_random_sequence(seed, world, stack, armed, monkeypatch):
    o = world.a
    def stops():
        return len(world.sql(o, "SELECT 1 FROM consentvault.event WHERE org_id = %s AND event_type = 'revoke'", (o.org_id,)))

    def posts():
        return len(world.sql(o, "SELECT 1 FROM consentvault.raw_post WHERE org_id = %s AND intake = 'sms_reply'", (o.org_id,)))

    ops = _sequence(seed)
    posts0, stops0 = posts(), stops()
    base = _kinds(ops)
    sids = []
    sent = 0
    for n, ((kind, person, ref), b) in enumerate(zip(ops, base)):
        sid = sids[ref] if kind == "dup" else "SM" + uuid.uuid4().hex[:30]
        sids.append(sid)
        text = "STOP" if b == "stop" else "START"
        sender = SENDERS[person] if kind != "dup" else SENDERS[ops[ref][1]]
        if kind == "crash_stop":
            def crash(*a, **k):
                raise RuntimeError("crash between the check of the signature and the stop")
            with pytest.MonkeyPatch.context() as m:
                m.setattr(door.TenantLedgerBackend, "apply", crash)
                with pytest.raises(RuntimeError):
                    text_in(armed, text, sender=sender, sid=sid)
        else:
            assert text_in(armed, text, sender=sender, sid=sid).status == 200
        sent += 1
    want = sum(1 for (kind, _, _), b in zip(ops, base) if kind != "dup" and b == "stop")
    # a duplicate (the provider's retry of a message already counted) writes no second event: the reference counts messages once
    first_seen = set()
    want = 0
    for sid, b in zip(sids, base):
        if b == "stop" and sid not in first_seen:
            want += 1
        first_seen.add(sid)

    assert posts() - posts0 == sent  # every text is stored whole
    stack.service.rebuild_replies(o.org_id)
    assert stops() - stops0 == want
    stack.service.rebuild_replies(o.org_id)  # safe to run twice
    assert stops() - stops0 == want
    assert world.sql(o, "SELECT 1 FROM consentvault.event e WHERE e.org_id = %s AND e.event_type = 'revoke' AND NOT EXISTS ("
                        "SELECT 1 FROM consentvault.event_source_post s WHERE s.event_id = e.event_id)", (o.org_id,)) == []
