"""Executable model of the Twenty erasure-and-clear state machine (see twenty_erasure.md, the table it implements).

One contact, one Twenty system, up to two Person records that duplicate the contact, up to two erasure requests.
A second model at the end (PersonModel) follows one Person holding two contacts, an email and a phone.
Every defect the reviews found is a named fix that can be switched off; with every fix on, no invariant breaks
(tests: test_twenty_erasure.py). Violations are recorded in ``State.viol`` instead of raising, so a buggy policy
can be run and its counterexample read.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional, Tuple, FrozenSet, List

ALL_FIXES = frozenset({
    "F_waiver_terminal",        # a waiver is terminal for its own request; the next erase never revives its clear
    "F_clear_per_request",      # each erasure request gets its own clear
    "F_hold_sets_held",         # placing a hold marks pending requests held and supersedes their open clear
    "F_rewrite_after_change",   # a decline, a hold, a release re-writes current state to Twenty
    "F_block_by_contact",       # an erased contact is blocked by fingerprint, so any duplicate Person is blocked
    "F_resume_all_confirmed",   # resume picks every confirmed, unheld request, whatever reason it was stored with
    "F_wait_precedence",        # dead clear outranks everything else in the wait reason
    "F_suppress_on_clear",      # status pushes are suppressed by an open clear, not by confirmed_at
    "F_group_clear_only",       # a claim group holding a clear delivers only the clear
    "F_decline_dead",           # a decline supersedes a dead clear too
    "F_stop_at_completion",     # completion writes a fresh erasure stop (a grant or lift after the first stop must not leave the gate open)
    "F_refresh_suppressed",     # a refresh push obeys the same suppression rule as a state push
    "F_one_pending_refuse_erased",  # one pending request per contact; a request on an erased contact is refused
    "F_member_hold_refuses",    # a client's own hold refuses the request outright; an operator's hold creates it held
    "F_claim_exclusive",        # one delivery per (system, contact) in flight: a clear and a status write never overlap
    "F_waive_needs_disconnect",  # proceed-without-clear is refused by the route unless the system is disconnected and its key destroyed
    "F_status_write_waits",     # a queued or in-flight Twenty status write is a delivery wait, like pending_pushes
    "F_stop_at_confirm",        # the erasure stop is written at the first unheld confirm and stays after a decline
    "F_stale_held_cleared",     # erase_in_org clears a held_by left behind by the two-step hold release
    "F_flag_seen_kept",         # flag_seen survives link deletion (a keyed-hash store apart from the contact's links)
})

OPEN = ("pending", "sent", "dead", "ack")  # clear states that mean "an erasure is mid-flight for this system"


@dataclass(frozen=True)
class Req:
    rid: int
    status: str = "pending"          # pending (= pending_operator_confirmation) | declined | completed
    confirmed: bool = False          # the operator's intent, stamped at the first confirm call
    held: bool = False               # held_by set
    waived: bool = False             # operator chose proceed-without-clear
    clear: Optional[str] = None      # None | pending | sent | ack | dead | sup_held | sup_declined | sup_waived
    stop_due: bool = False           # ghost: the first unheld confirm happened, so a stop must stand (unless lifted)
    lifted: bool = False             # ghost: a staff or regulatory decision lifted a stop after the request was made
    air: bool = False                # the clear's call to Twenty has been claimed and has not landed yet
    wait: Optional[str] = None       # stored wait reason


@dataclass(frozen=True)
class Person:
    fields: Optional[str] = None     # None = cleared or never written; otherwise the status string written
    flag: bool = False               # cvStopFlag, staff only
    once: bool = False               # ghost: this flag value was already processed and has not changed since
    seen: Optional[bool] = None      # connector_flag_seen row; None = no row, never processed (first sight)


@dataclass(frozen=True)
class State:
    contact: str = "live"            # live | erased (key destroyed)
    status: str = "none"             # ledger: none | permitted | denied (a stop survives erasure as a fingerprint)
    hold: str = ""                   # "" | member (the client's own hold) | operator
    known: bool = False              # the vault holds a record of this contact (the core refuses a request otherwise)
    disc: bool = False               # the Twenty system is disconnected and its key destroyed
    rel_pending: bool = False        # hold row released, held_by marks not yet cleared (two core steps)
    generic: bool = False            # a push to a generic webhook system is undelivered
    persons: Tuple[Person, ...] = ()
    queued: bool = False             # a status or refresh push to Twenty is queued
    inflight: Optional[str] = None   # a claimed status write that has not landed yet (the value it will write)
    reqs: Tuple[Req, ...] = ()
    shared_clear: Optional[str] = None   # only used when F_clear_per_request is off (the old one-clear-forever bug)
    tomb: FrozenSet[int] = frozenset()   # only used when F_block_by_contact is off (the old per-Person tombstone)
    viol: FrozenSet[str] = frozenset()


def _req(s: State, rid: int) -> Req:
    return next(r for r in s.reqs if r.rid == rid)


def _set(s: State, rid: int, **kw) -> State:
    return replace(s, reqs=tuple(replace(r, **kw) if r.rid == rid else r for r in s.reqs))


def _viol(s: State, *names: str) -> State:
    return replace(s, viol=s.viol | frozenset(names))


class Model:
    def __init__(self, fixes=ALL_FIXES, coarse=False, no_system=False, generic_system=False):
        self.f = frozenset(fixes)
        self.generic_system = generic_system  # a generic webhook system is connected: every ledger event queues a push that must be delivered
        self.no_system = no_system      # no Twenty system connected: no clear is needed (the core-only view used by the conformance harness)
        self.coarse = coarse            # also offer claim-and-land as one step, so shallow searches reach deeper scenarios

    def fx(self, name: str) -> bool:
        return name in self.f

    # ---- rules shared by several events ------------------------------------------------------------------------

    def suppress(self, s: State) -> bool:
        """Is a status write to Twenty withheld because an erasure is mid-flight?"""
        if self.fx("F_suppress_on_clear"):
            return any(r.status == "pending" and not r.held and r.clear in OPEN for r in s.reqs)
        return any(r.status == "pending" and r.confirmed for r in s.reqs)   # the old rule keyed on confirmed_at

    def enqueue(self, s: State) -> State:
        if self.no_system or s.disc or s.contact == "erased" or self.suppress(s):
            return s                                         # no Twenty system: nothing to queue
        return replace(s, queued=True)

    def ledger_push(self, s: State) -> State:
        """A ledger event (grant, stop, lift, re-capture, erasure stop) queues pushes to every connected system."""
        s = self.enqueue(s)
        return replace(s, generic=True) if self.generic_system else s

    def refresh(self, s: State) -> State:
        """A refresh push (decline, hold, release, person created). It obeys the same rule as a state push."""
        if not self.fx("F_rewrite_after_change"):
            return s
        if self.fx("F_refresh_suppressed"):
            return self.enqueue(s)
        return s if (s.contact == "erased" or s.disc) else replace(s, queued=True)   # the old bug: refresh ignored suppression

    def write_all(self, s: State, value: Optional[str]) -> State:
        if value is not None:
            if s.contact == "erased":
                s = _viol(s, "write_erased")
            if any(r.status == "pending" and not r.held and r.clear in ("ack",) for r in s.reqs):
                s = _viol(s, "write_after_clear")       # the clear already ran, so this write repopulates
        return replace(s, persons=tuple(replace(p, fields=value) for p in s.persons))

    def exclusive_busy(self, s: State) -> bool:
        """Is some delivery for this (system, contact) in flight?"""
        return s.inflight is not None or any(r.air for r in s.reqs)

    def delivery_wait(self, s: State) -> bool:
        """A push of the person's state is undelivered (matches pending_pushes: queued, failed or in flight)."""
        if s.generic:
            return True
        return self.fx("F_status_write_waits") and (s.queued or s.inflight is not None)

    def wait_reason(self, s: State, r: Req) -> Optional[str]:
        if self.fx("F_wait_precedence"):
            if r.clear == "dead" and not r.waived:
                return "system_clear_dead"
            if r.clear in ("pending", "sent"):
                return "waiting_for_system_clear"
            if self.delivery_wait(s):
                return "pending_suppression_delivery"
            return None
        if self.delivery_wait(s):                                  # the old order let a delivery wait hide a dead clear
            return "pending_suppression_delivery"
        if r.clear in ("pending", "sent"):
            return "waiting_for_system_clear"
        if r.clear == "dead" and not r.waived:
            return "system_clear_dead"
        return None

    def blocked(self, s: State, idx: int) -> bool:
        """May this Person's data never be imported because its contact was erased?"""
        if self.fx("F_block_by_contact"):
            return s.contact == "erased"
        return idx in s.tomb

    # ---- events --------------------------------------------------------------------------------------------------

    def enabled(self, s: State) -> List[Tuple[str, int]]:
        ev: List[Tuple[str, int]] = []
        pend = [r for r in s.reqs if r.status == "pending"]
        if len(s.reqs) < 2:
            if self.fx("F_one_pending_refuse_erased"):
                ok = s.contact == "live" and not pend
            else:
                ok = True                                    # the old behaviour: a second request, or one on an erased contact
            if ok and self.no_system and not s.known:
                ok = False                                   # core: "this organization holds no record of this contact"
            if ok and s.hold == "member" and self.fx("F_member_hold_refuses"):
                ok = False                                   # the client's own hold refuses the request outright
            if ok:
                ev.append(("erase_request", 0))
        for r in pend:
            ev.append(("confirm", r.rid))
            ev.append(("decline", r.rid))
            if r.clear == "pending" and not r.held and (not self.fx("F_claim_exclusive") or not self.exclusive_busy(s)):
                ev.append(("clear_claim", r.rid))
            if r.clear in ("pending", "sent"):
                ev.append(("clear_dead", r.rid))
            if r.clear == "dead" and not r.waived and not r.held and (s.disc or not self.fx("F_waive_needs_disconnect")):
                ev.append(("operator_proceed", r.rid))
            if self._resumable(r):
                ev.append(("resume", r.rid))
        for r in s.reqs:
            if r.air:
                ev.append(("clear_land", r.rid))
        if not s.disc and not self.no_system:
            ev.append(("system_disconnect", 0))
        if not s.disc and any(r.clear == "dead" and not r.waived and r.status == "pending" and not r.held and not r.air for r in s.reqs):
            ev.append(("redrive", 0))
        if s.rel_pending:
            ev.append(("hold_resume", 0))
        if s.contact == "live" and s.status == "denied":
            ev.append(("vault_lift", 0))
        if s.contact == "erased":
            ev.append(("recapture", 0))
        if s.hold:
            ev.append(("hold_released", 0))
        else:
            ev.append(("hold_placed_operator", 0))
            ev.append(("hold_placed_member", 0))
        ev.append(("generic_delivered", 0) if s.generic else ("generic_push", 0))
        ev.append(("vault_stop", 0))
        ev.append(("vault_grant", 0))                       # an unverified grant during a stop changes nothing
        if len(s.persons) < 2:
            ev.append(("create_person", len(s.persons)))
        for i, p in enumerate(s.persons):
            ev.append(("flag_clear", i) if p.flag else ("flag_set", i))
            if p.seen is not p.flag:
                ev.append(("webhook", i))
        if s.persons:
            ev.append(("reconcile_pass", 0))
            ev.append(("nightly_scan", 0))
        if s.queued and not s.disc and s.inflight is None and (not self.fx("F_claim_exclusive") or not any(r.air for r in s.reqs)):
            ev.append(("claim_state", 0))
        if s.inflight is not None:
            ev.append(("land_state", 0))
        if self.coarse:
            for r in pend:
                if ("clear_claim", r.rid) in ev:
                    ev.append(("clear_delivered", r.rid))
            if ("claim_state", 0) in ev:
                ev.append(("deliver_state", 0))
        return ev

    def _resumable(self, r: Req) -> bool:
        if r.status != "pending" or r.held or not r.confirmed:
            return False
        if r.wait == "uncommitted_ledger_intent":
            return False        # restore held it for the operator to re-confirm: the resume job never runs it
        if self.fx("F_resume_all_confirmed"):
            return True
        return r.wait in ("waiting_for_system_clear", "pending_suppression_delivery")   # the old selection

    def step(self, s: State, e: Tuple[str, int]) -> State:
        name, arg = e
        before = s
        s = getattr(self, "ev_" + name)(s, arg)
        for r in before.reqs:   # a waiver is terminal for its request
            if r.waived and _req(s, r.rid).clear != "sup_waived":
                s = _viol(s, "waiver_revived")
        for r in s.reqs:
            if r.status in ("declined", "completed") and r.clear == "dead":
                s = _viol(s, "dead_clear_lingers")
            if r.status == "pending" and s.hold and not r.held:
                s = _viol(s, "hold_not_marked")
        if sum(1 for r in s.reqs if r.status == "pending") > 1:
            s = _viol(s, "two_pending")
        if s.contact == "erased" and s.status != "denied":
            s = _viol(s, "gate_permits_erased")          # the gate must deny an erased contact on every channel
        for r in s.reqs:
            if r.stop_due and not r.lifted and s.status != "denied":
                s = _viol(s, "erasure_stop_lost")        # the stop from the first unheld confirm stays, even after a decline
            if r.status in ("declined", "completed") and r.held:
                s = _viol(s, "stale_held_on_closed")
        return s

    def ev_erase_request(self, s, _):
        if s.contact == "erased":
            s = _viol(s, "request_on_erased")
        if s.hold == "member":
            s = _viol(s, "request_under_member_hold")
        return replace(s, reqs=s.reqs + (Req(rid=len(s.reqs), held=bool(s.hold)),))   # an operator's hold marks it at creation

    def ev_confirm(self, s, rid):
        """erase_in_org: the single place a request advances."""
        r = _req(s, rid)
        s = _set(s, rid, confirmed=True)
        if s.hold:
            s = _set(s, rid, held=True)
            if self.fx("F_stop_at_confirm") and s.status != "denied":
                s = self.ledger_push(replace(s, status="denied"))   # core: the stop is written under a hold too; only key destruction waits
            s = _set(s, rid, stop_due=True)
            if self.fx("F_hold_sets_held") and _req(s, rid).clear in OPEN:
                s = _set(s, rid, clear="sup_held")
            return self.refresh(s)
        if self.fx("F_stale_held_cleared"):
            s = _set(s, rid, held=False)                    # a held_by left by the two-step release is cleared here
        else:
            r2 = _req(s, rid)
            if r2.held:
                return s                                    # the old code kept waiting on a stale mark forever
        if self.fx("F_stop_at_confirm") and (not _req(s, rid).stop_due or self.fx("F_stop_at_completion")):
            # core writes the erasure stop on every unheld erase_in_org call (record_erasure_stop), before the clear is
            # queued and before pending_pushes; it is a no-op while nothing has lifted the stop since the last one
            if s.status != "denied":
                s = self.ledger_push(replace(s, status="denied"))
        s = _set(s, rid, stop_due=True)
        r = _req(s, rid)
        c = r.clear
        if c is None:
            if not self.fx("F_clear_per_request") and s.shared_clear == "ack":
                c = "ack"                                   # the old bug: one clear per contact, forever
            elif self.no_system:
                c = "ack"                                   # nothing to clear in a system that is not connected
            else:
                c = "pending"
                if self.fx("F_group_clear_only"):
                    s = replace(s, queued=False)            # queued status pushes are superseded as the clear is queued
        elif c == "sup_held":
            c = "ack" if self.no_system else "pending"      # a hold released: the same request revives its own clear (none to deliver if no system)
            if self.fx("F_group_clear_only"):
                s = replace(s, queued=False)                # and supersedes the refresh queued while it was held
        elif c == "sup_waived" and not self.fx("F_waiver_terminal"):
            c = "pending"                                   # the old bug: the next erase revived the waived clear
        s = _set(s, rid, clear=c)
        r = _req(s, rid)
        reason = self.wait_reason(s, r)
        if c == "dead" and not r.waived and reason != "system_clear_dead":
            s = _viol(s, "dead_clear_hidden")
        if reason is not None:
            s = _set(s, rid, wait=reason)
            return s
        if c not in ("ack", "sup_waived"):
            s = _viol(s, "completed_uncleared")
        elif c == "ack" and any(p.fields is not None for p in s.persons):
            s = _viol(s, "completed_uncleared")
        if s.contact == "erased":
            s = _viol(s, "double_erase")
        s = _set(s, rid, status="completed", wait=None, held=False)
        if not self.fx("F_flag_seen_kept"):
            s = replace(s, persons=tuple(replace(p, seen=None) for p in s.persons))   # flag_seen lived on the deleted link
        # erasure writes a stop by fingerprint for every channel before the key is destroyed (core fix): the gate denies
        new_status = "denied" if self.fx("F_stop_at_completion") else s.status
        return replace(s, contact="erased", queued=False, status=new_status)

    def ev_decline(self, s, rid):
        r = _req(s, rid)
        c = r.clear
        if c in ("pending", "sent", "sup_held") or (c == "dead" and self.fx("F_decline_dead")):
            c = "sup_declined"
        s = _set(s, rid, status="declined", held=False, wait=None, clear=c)
        return self.refresh(s)

    def _place(self, s, kind):
        s = replace(s, hold=kind)
        if self.fx("F_hold_sets_held"):
            for r in s.reqs:
                if r.status == "pending":
                    # an acknowledged clear is superseded too: the refresh below writes data back, so the clear must run again
                    c = "sup_held" if r.clear in OPEN else r.clear
                    s = _set(s, r.rid, held=True, clear=c)
        return self.refresh(s)

    def ev_hold_placed_operator(self, s, _):
        return self._place(s, "operator")

    def ev_hold_placed_member(self, s, _):
        return self._place(s, "member")

    def ev_hold_released(self, s, _):
        """Step one (holds.release_in_org): the hold row is released, a refresh is queued; held_by marks stay."""
        operator = s.hold == "operator"
        s = replace(s, hold="", rel_pending=any(r.held for r in s.reqs if r.status == "pending"))
        s = self.refresh(s)
        # core: release_hold_operator resumes at once; release_hold_member leaves it to the caller (a separate hold_resume)
        return self.ev_hold_resume(s, 0) if operator else s

    def ev_hold_resume(self, s, _):
        """Step two (holds.resume): clear held_by on released requests, then run confirmed ones through erase_in_org."""
        s = replace(s, rel_pending=False)
        for r in s.reqs:
            if r.status == "pending" and r.held and not s.hold:
                s = _set(s, r.rid, held=False)
        for r in s.reqs:
            if r.status == "pending" and r.confirmed and not _req(s, r.rid).held:
                s = self.ev_confirm(s, r.rid)
        return self.refresh(s)

    def ev_vault_lift(self, s, _):
        """A staff or regulatory decision lifts the stop of a live contact."""
        s = replace(s, status="permitted", reqs=tuple(replace(r, lifted=True) for r in s.reqs))
        return self.ledger_push(s)

    def ev_recapture(self, s, _):
        """Captured again after erasure: a new key; the stop from erasure still stands."""
        return self.ledger_push(replace(s, contact="live", known=True))

    def ev_system_disconnect(self, s, _):
        """The Twenty system is disconnected and its key destroyed: queued writes are superseded, an open clear can never be sent."""
        s = replace(s, disc=True, queued=False)
        for r in s.reqs:
            if r.status == "pending" and r.clear == "pending":
                s = _set(s, r.rid, clear="dead")          # not sendable: it waits for the operator's waiver
        return s

    def ev_operator_proceed(self, s, rid):
        if not s.disc:
            s = _viol(s, "waive_without_disconnect")
        return _set(s, rid, waived=True, clear="sup_waived", wait=None)

    def ev_clear_claim(self, s, rid):
        """The worker claims the clear (the call is not made yet)."""
        if s.hold:
            s = _viol(s, "clear_under_hold")
        s = _set(s, rid, clear="sent", air=True)
        if self.fx("F_group_clear_only"):
            s = replace(s, queued=False)
        return s

    def ev_clear_land(self, s, rid):
        """The call to Twenty lands: every Person is blanked. If the clear was superseded meanwhile the call still lands."""
        r = _req(s, rid)
        if s.contact == "live":
            s = replace(s, persons=tuple(replace(p, fields=None) for p in s.persons))
            if not self.fx("F_block_by_contact") and s.persons:
                s = replace(s, tomb=s.tomb | frozenset({0}))   # the old bug: one tombstone, for the first Person only
        s = replace(s, shared_clear="ack")
        return _set(s, rid, air=False, clear="ack" if r.clear == "sent" else r.clear)

    def ev_clear_delivered(self, s, rid):                       # claim and land in one step (kept for named scenarios)
        return self.ev_clear_land(self.ev_clear_claim(s, rid), rid)

    def ev_clear_dead(self, s, rid):
        return _set(s, rid, clear="dead")

    def ev_redrive(self, s, _):
        for r in s.reqs:
            if r.status == "pending" and r.clear == "dead" and not r.waived and not r.held and not r.air:
                s = _set(s, r.rid, clear="pending")
        return s

    def ev_resume(self, s, rid):
        return self.ev_confirm(s, rid)

    def ev_generic_push(self, s, _):
        return replace(s, generic=True)

    def ev_generic_delivered(self, s, _):
        return replace(s, generic=False)

    def ev_vault_stop(self, s, _):          # a new stop from the vault (a person texts STOP): a new key if erased
        s = replace(s, contact="live", status="denied", known=True)
        return self.ledger_push(s)

    def ev_vault_grant(self, s, _):
        if s.status == "denied":
            if s.contact == "erased":                        # a re-capture: new key, the stop stands
                return self.ledger_push(replace(s, contact="live", known=True))
            return s                                         # a stop stands: no event that moves state, no push
        s = replace(s, contact="live", status="permitted", known=True)
        return self.ledger_push(s)

    def ev_create_person(self, s, _):
        s = replace(s, persons=s.persons + (Person(),))       # person.created queues a refresh push
        if s.contact != "live" or s.disc:
            return s
        return self.enqueue(s) if self.fx("F_refresh_suppressed") else replace(s, queued=True)

    def ev_flag_set(self, s, i):
        return self._person(s, i, flag=True)

    def ev_flag_clear(self, s, i):
        return self._person(s, i, flag=False, once=False)

    def _person(self, s, i, **kw):
        return replace(s, persons=tuple(replace(p, **kw) if j == i else p for j, p in enumerate(s.persons)))

    def ev_webhook(self, s, i):
        p = s.persons[i]
        if p.flag and p.seen is not True:                    # false to true, or first sight with the flag true
            if self.blocked(s, i):
                pass                                         # an erased contact is never imported
            elif s.contact == "erased":
                s = _viol(s, "reimport")                     # only reachable when the block is off
            else:
                if p.once:
                    s = _viol(s, "restop_without_new_flag")
                if s.status != "denied":
                    s = self.enqueue(replace(s, status="denied"))
        return self._person(s, i, seen=p.flag, once=p.flag)

    def ev_reconcile_pass(self, s, _):
        for i in range(len(s.persons)):
            if s.persons[i].seen is not s.persons[i].flag:
                s = self.ev_webhook(s, i)
        return s

    def ev_claim_state(self, s, _):
        """A worker claims the queued status push. A group that holds a clear delivers only the clear."""
        s = replace(s, queued=False)
        if s.contact == "erased":
            return s                                         # the key is gone: superseded, never written
        if self.fx("F_group_clear_only") and any(r.status == "pending" and r.clear == "pending" for r in s.reqs):
            return s
        return replace(s, inflight=s.status)                 # the value is read now and written later

    def ev_land_state(self, s, _):
        v = s.inflight
        s = replace(s, inflight=None)
        return self.write_all(s, v)

    def ev_deliver_state(self, s, _):                        # claim and land in one step (kept for named scenarios)
        return self.ev_land_state(self.ev_claim_state(s, 0), 0)

    def ev_nightly_scan(self, s, _):
        """The nightly full scan: blank every Person that matches an erased contact; correct drift on live contacts."""
        if s.contact == "erased":
            return replace(s, persons=tuple(replace(p, fields=None) for p in s.persons))
        if self.suppress(s) or self.exclusive_busy(s):
            return s
        return replace(s, persons=tuple(replace(p, fields=s.status) for p in s.persons))


# ---- environment that helps (used to test liveness) ---------------------------------------------------------------

def settle(m: Model, s: State, release_holds: bool = True, scan: bool = False, limit: int = 80) -> Tuple[State, bool]:
    """Run every event that makes progress, in a fixed fair order, until nothing changes. True when it stabilised.
    ``scan`` adds the nightly scan to the helpful events."""
    for _ in range(limit):
        start = s
        if s.inflight is not None:
            s = m.step(s, ("land_state", 0))
        for r in s.reqs:
            if r.air:
                s = m.step(s, ("clear_land", r.rid))
        if release_holds and s.hold:
            s = m.step(s, ("hold_released", 0))
        if s.rel_pending:
            s = m.step(s, ("hold_resume", 0))
        if s.generic:
            s = m.step(s, ("generic_delivered", 0))
        for r in [r for r in s.reqs if r.status == "pending"]:
            cur = _req(s, r.rid)
            if not cur.confirmed:
                s = m.step(s, ("confirm", r.rid))          # the operator confirms
                cur = _req(s, r.rid)
            if cur.clear == "dead" and not cur.held and not cur.air:
                s = m.step(s, ("operator_proceed", r.rid) if s.disc else ("redrive", 0))
            cur = _req(s, r.rid)
            if cur.clear == "pending" and not cur.held and ("clear_claim", r.rid) in m.enabled(s):
                s = m.step(s, ("clear_claim", r.rid))
                s = m.step(s, ("clear_land", r.rid))
            if m._resumable(_req(s, r.rid)):
                s = m.step(s, ("resume", r.rid))
        if s.persons:
            s = m.step(s, ("reconcile_pass", 0))
        if s.queued and ("claim_state", 0) in m.enabled(s):
            s = m.step(s, ("claim_state", 0))
            if s.inflight is not None:
                s = m.step(s, ("land_state", 0))
        if scan and s.persons:
            s = m.step(s, ("nightly_scan", 0))
        if s == start:
            return s, True
    return s, False


def liveness_problems(m: Model, s: State, release_holds: bool, scan: bool = False) -> List[str]:
    out: List[str] = []
    t, ok = settle(m, s, release_holds, scan)
    if not ok:
        out.append("settle_did_not_stabilise")
    pending = [r for r in t.reqs if r.status == "pending"]
    if release_holds and pending:
        out.append("waits_forever")
    if t.queued:
        out.append("queue_not_drained")
    for p in t.persons:
        if p.seen is not p.flag:
            out.append("flag_not_processed")
    if t.disc:
        pass                                              # no system any more: Twenty is no longer kept current
    elif t.contact == "live":
        for p in t.persons:
            if p.fields != t.status:
                out.append("twenty_not_current")      # includes a stop that never reached Twenty
    elif not any(r.waived for r in t.reqs):
        if any(p.fields is not None for p in t.persons):
            out.append("erased_fields_populated")
    return sorted(set(out))


# ---- one Person holding several contacts (rounds fourteen and fifteen) --------------------------------------------
#
# The model above follows one contact through erasure. A Twenty Person often holds an email and a phone, which are two
# contacts in the vault with their own ledger state and their own erasure. This second model follows one Person holding up to
# two contacts (0 = the email, 1 = the phone) and asks what the Person's status fields read. The per-contact lifecycle (holds,
# waivers, resume, disconnect) is the model above, unchanged; here an erasure is request, clear, complete or decline. Combining
# is applied channel by channel in the connector; one channel is enough to show every order.

PERSON_FIXES = frozenset({
    "P_combine_contacts",       # a write is the most restrictive state over every contributing contact on the Person
    "P_erase_recomputes",       # a clear for one contact writes the state of the rest, and blanks only when no contact is left
    "P_link_per_contact",       # connector_link is keyed (org, system, person_id_hash, contact_fp)
    "P_person_lease",           # one write in flight per Twenty Person, whichever contact's group claimed it
    "P_skip_per_point",         # a staff flag skips only the erased contact points, and records the stop on every other one
    "P_scan_recomputes",        # the nightly scan writes the state of the remaining contacts, never a blank over a stop
    "P_lease_outlives_write",   # the lease outlives the write timeout: a write is landed or abandoned before the lease ends, then a refresh
    "P_refresh_on_points",      # a merge, a restore or any change of the Person's contact points queues a refresh
    "P_complete_waits",         # completion waits while a write of the contact is queued or in flight (defence in depth: see the tests)
    # round sixteen
    "P_clear_waits_deleted",    # a clear to a soft-deleted Person stays open until the Person is restored (then cleared) or hard-deleted
    "P_stop_new_points",        # a contact point added to a flagged Person gets the stop
    "P_send_deadline",          # no send later than 15 seconds after the lease extension, by a monotonic clock
    "P_alarm_hidden_stop",      # a correction that uncovers a hidden stop alarms every time
    "P_lease_never_deleted",    # no webhook deletes the lease row (a soft-delete webhook can arrive after the restore)
    # round seventeen
    "P_destroy_drops_links",    # a hard delete deletes the Person's links, so a later 404 is not read as a restorable soft delete
    "P_destroyed_marker",       # every hard delete leaves one marker keyed on the record hash alone; later events for that Person are ignored
    "P_deleted_wait_alarms",    # a clear waiting on a never-restored soft-deleted Person alarms the customer at 7 days, daily, the operator at 30
})

RANK = {"permitted": 0, "none": 1, "denied": 2}   # combining: any denial wins, then a grant, then no record


def combine(values) -> Optional[str]:
    """The Person's combined status: denied if any contact is denied, else permitted if any is permitted; None (blank)
    when no contact contributes."""
    vs = [v for v in values if v is not None]
    if not vs:
        return None
    if "denied" in vs:
        return "denied"
    return "permitted" if "permitted" in vs else "none"


@dataclass(frozen=True)
class Contact:
    life: str = "absent"            # absent (no record, no key) | live | erasing (an unheld confirmed erasure is mid-flight) | erased
    status: str = "none"            # ledger: none | permitted | denied (an erasure stop is written at confirm and stays)
    queued: bool = False            # a status or refresh push for this contact is queued
    clear: Optional[str] = None     # None | pending | acked: this contact's clear for its current erasure
    waited: int = 0                 # the clear's wait on a soft-deleted Person: 0 under 7 days, 1 day 7, 2 day 8, 3 day 30
    alarm: str = ""                 # "" | customer (pinned on the overview) | customer+operator
    raised: int = 0                 # how many times the customer alarm was raised (once on day 7, then daily)


# An in-flight write: (contact, "state" | "clear", value, contacts the value was computed from, lease held, phase).
# Phase: ready (lease extended, not sent) | stalled (the worker stalled past 15 seconds since the extension) | sent | late
# (sent after a stall, so the lease can end while the call is still out).
Write = Tuple[int, str, Optional[str], FrozenSet[int], bool, str]


@dataclass(frozen=True)
class PState:
    contacts: Tuple[Contact, ...] = (Contact(), Contact())
    points: FrozenSet[int] = frozenset({0, 1})          # the contact points the Twenty Person holds (a merge adds one)
    deleted: bool = False                               # the Person is soft-deleted in Twenty (a write answers 404)
    del_hook: bool = False                              # its person.deleted webhook is not processed yet (it may come after a restore)
    gone: bool = False                                  # the Person is hard-deleted (destroyed): nothing holds its fields any more
    flag: bool = False                                  # cvStopFlag on the Person (staff own it; the vault never writes it)
    late_flag: bool = False                             # a person.updated for the destroyed Person, flag true, can still arrive
    marker: bool = False                                # a destroyed marker exists for this Person's record hash
    links: FrozenSet[int] = frozenset()                 # contacts linked to the Person in connector_link
    fields: Optional[str] = None                        # the Person's status fields: None = blank or never written
    src: FrozenSet[int] = frozenset()                   # the contacts whose state the fields were computed from
    recheck: bool = False                               # a reconcile of this Person is due (it changed since the watermark)
    inflight: Tuple[Write, ...] = ()
    viol: FrozenSet[str] = frozenset()


def _c(s: PState, i: int, **kw) -> PState:
    return replace(s, contacts=tuple(replace(c, **kw) if j == i else c for j, c in enumerate(s.contacts)))


def _drop(s: PState, k: int) -> PState:
    return replace(s, inflight=s.inflight[:k] + s.inflight[k + 1:])


def _put(s: PState, k: int, w: Write) -> PState:
    return replace(s, inflight=s.inflight[:k] + (w,) + s.inflight[k + 1:])


class PersonModel:
    def __init__(self, fixes=PERSON_FIXES):
        self.f = frozenset(fixes)

    def fx(self, name: str) -> bool:
        return name in self.f

    @staticmethod
    def contributors(s: PState, without: Optional[int] = None) -> List[int]:
        """Contacts whose state the Person shows: a contact point on the Person, a live key and no unheld erasure
        mid-flight. The connector reads the Person's contact points at write time, so a contact counts whether or not its
        own push has been delivered."""
        return [i for i, c in enumerate(s.contacts) if c.life == "live" and i in s.points and i != without]

    def truth(self, s: PState, without: Optional[int] = None) -> Optional[str]:
        return combine(s.contacts[i].status for i in self.contributors(s, without))

    def value(self, s: PState, i: int, kind: str) -> Tuple[Optional[str], FrozenSet[int]]:
        if kind == "clear":
            if self.fx("P_erase_recomputes"):
                return self.truth(s, without=i), frozenset(self.contributors(s, without=i))
            return None, frozenset()
        if self.fx("P_combine_contacts"):
            return self.truth(s), frozenset(self.contributors(s))
        return s.contacts[i].status, frozenset({i})                     # the old rule: the delivering contact's state, last write wins

    def looks_deleted(self, s: PState, i: int) -> bool:
        """A 404 the connector must read as a restorable soft delete: the Person is soft-deleted, or it is destroyed but a link
        to it survived (nothing then tells a destroyed record from a deleted one)."""
        return s.deleted or (s.gone and i in s.links)

    def lease_free(self, s: PState) -> bool:
        return not self.fx("P_person_lease") or not any(w[4] for w in s.inflight)

    def enabled(self, s: PState) -> List[Tuple[str, int]]:
        ev: List[Tuple[str, int]] = []
        busy = {w[0] for w in s.inflight}                             # any write of the contact still out there (completion waits)
        held = {w[0] for w in s.inflight if w[4]}                     # the group claim lock is a lease too and expires with it
        free = self.lease_free(s)
        for i, c in enumerate(s.contacts):
            ev.append(("grant", i))
            ev.append(("stop", i))
            if c.life == "live" and c.status == "denied":
                ev.append(("lift", i))
            if c.life == "live":
                ev.append(("erase", i))
            if c.life == "erasing":
                ev.append(("decline", i))
                if c.clear == "acked" and (not self.fx("P_complete_waits") or (not c.queued and i not in busy)):
                    ev.append(("complete", i))
            if i not in held and free and len(s.inflight) < 2:      # two calls out at once is enough to show any overlap
                if c.queued and c.life == "live":
                    ev.append(("claim_state", i))
                if c.clear == "pending" and not (self.looks_deleted(s, i) and self.fx("P_clear_waits_deleted")):
                    ev.append(("claim_clear", i))
            if c.clear == "pending" and self.looks_deleted(s, i) and c.waited < 3:
                ev.append(("day_passes", i))             # time passes while the clear waits on a deleted record
            if i not in s.points and not s.gone:
                ev.append(("merge_in", i))               # a merge (or an edit) adds this contact point to the Person
        for k, (_, _, _, _, hold, phase) in enumerate(s.inflight):
            if phase == "ready":
                ev.append(("stall", k))
                ev.append(("send", k))
            elif phase == "stalled":
                ev.append(("send", k))
            else:
                ev.append(("land", k))
                if hold:
                    if self.fx("P_lease_outlives_write"):
                        ev.append(("timeout_landed", k))
                        ev.append(("timeout_lost", k))
                    if phase == "late" or not self.fx("P_lease_outlives_write"):
                        ev.append(("lease_expires", k))
        if not s.gone:
            ev.append(("unflag", 0) if s.flag else ("flag", 0))    # staff set cvStopFlag (false to true) or clear it
            ev.append(("restore", 0) if s.deleted else ("delete_person", 0))
            ev.append(("destroy", 0))
            if s.fields is not None:
                ev.append(("staff_edit", 0))                       # staff type into a status field the vault owns
        if s.del_hook:
            ev.append(("deleted_webhook", 0))
        if s.gone and s.late_flag:
            ev.append(("late_update", 0))                  # Twenty sends no ordering guarantee: an update can follow the destroy
        if free and not s.deleted and not s.gone:
            ev.append(("scan", 0))
            if s.recheck:
                ev.append(("recheck", 0))
        return ev

    def step(self, s: PState, e: Tuple[str, int]) -> PState:
        name, arg = e
        return getattr(self, "ev_" + name)(s, arg)

    def _ledger(self, s: PState, i: int, status: str) -> PState:
        c = s.contacts[i]
        life = "live" if c.life in ("absent", "erased") else c.life     # a new fact through the vault: a new key if erased
        s = _c(s, i, life=life, status=status)
        return _c(s, i, queued=True) if life == "live" else s           # an erasing contact's status push is suppressed (R1)

    def _refresh(self, s: PState) -> PState:
        """A refresh for the Person: one per contributing contact (the lease makes them one write at a time), and a recheck
        of the Person by the reconcile, which also covers a Person whose only contact points are erased or being erased."""
        for i in self.contributors(s):
            s = _c(s, i, queued=True)
        return s if s.gone else replace(s, recheck=True)             # a destroyed Person has nothing left to recheck

    def ev_grant(self, s, i):
        c = s.contacts[i]
        if c.status == "denied":                                        # a stop stands; re-capture after erasure keeps it
            return self._ledger(s, i, "denied") if c.life == "erased" else s
        return self._ledger(s, i, "permitted")

    def ev_stop(self, s, i):
        return self._ledger(s, i, "denied")

    def ev_lift(self, s, i):
        return self._ledger(s, i, "permitted")

    def ev_erase(self, s, i):
        """Request and first unheld confirm: the erasure stop is written, the contact's queued status push is dropped (R5)
        and its clear is queued."""
        return _c(s, i, life="erasing", status="denied", queued=False, clear="pending")

    def ev_decline(self, s, i):
        """A decline: the stop stays, the clear is superseded (one in flight still lands), a refresh is queued."""
        return _c(s, i, life="live", clear=None, queued=True)

    def ev_complete(self, s, i):
        if s.contacts[i].queued or any(w[0] == i for w in s.inflight):
            s = _viol(s, "erased_with_write_in_flight")              # the key is destroyed with a write of it undelivered
        if s.deleted and i in s.src:
            s = _viol(s, "erased_data_restorable")                   # a soft-deleted, restorable Person still holds its state
        return replace(_c(s, i, life="erased", clear=None, queued=False), links=s.links - {i})

    def _link(self, s: PState, i: int) -> Optional[PState]:
        """Remember the match. None: the insert conflicts with another contact's row on the same Person (old key)."""
        if i in s.links:
            return s
        if not self.fx("P_link_per_contact") and s.links:
            return None
        return replace(s, links=s.links | {i})

    def _claim(self, s: PState, i: int, kind: str) -> PState:
        if i not in s.points or s.gone or s.deleted:          # (a destroyed Person with a kept link is only claimed under the old clear rule)
            # no Person holds this contact point, or it answers 404: acknowledged not_in_system, nothing written. A clear only
            # reaches here for a soft-deleted Person when the old rule is in force (the fixed rule keeps it open).
            return _c(s, i, queued=False) if kind == "state" else _c(s, i, clear="acked")
        t = self._link(s, i)
        if t is None:
            return s                                                    # the delivery fails and is retried: nothing changes
        s = t
        v, src = self.value(s, i, kind)
        remaining = self.truth(s, without=i) if kind == "clear" else self.truth(s)
        if remaining == "denied" and v != "denied":
            s = _viol(s, "clear_drops_a_stop" if kind == "clear" else "write_hides_a_stop")
        if kind == "state":
            s = _c(s, i, queued=False)
        return replace(s, inflight=s.inflight + ((i, kind, v, src, True, "ready"),))

    def ev_claim_state(self, s, i):
        return self._claim(s, i, "state")

    def ev_claim_clear(self, s, i):
        return self._claim(s, i, "clear")

    def ev_stall(self, s, k):
        """The worker stalls between the lease extension and the send, past 15 seconds on its monotonic clock."""
        i, kind, v, src, hold, _ = s.inflight[k]
        return _put(s, k, (i, kind, v, src, hold, "stalled"))

    def ev_send(self, s, k):
        i, kind, v, src, hold, phase = s.inflight[k]
        if phase == "stalled" and self.fx("P_send_deadline"):
            # refused: more than 15 seconds since the extension, so the call could outlive the lease. Nothing is sent; the
            # rows are released (not an attempt) and claimed again.
            s = _drop(s, k)
            return _c(s, i, queued=True) if kind == "state" and s.contacts[i].life == "live" else s
        return _put(s, k, (i, kind, v, src, hold, "late" if phase == "stalled" else "sent"))

    def _write(self, s: PState, v: Optional[str], src: FrozenSet[int]) -> PState:
        if s.deleted or s.gone:
            return s                                                    # a deleted Person answers 404
        return replace(s, fields=v, src=src)

    def ev_land(self, s, k):
        i, kind, v, src, hold, _ = s.inflight[k]
        absent = s.deleted or s.gone                                    # the call answers 404 and writes nothing
        if not hold and not absent:
            s = _viol(s, "write_after_lease_lost")                     # a late landing: another write may have gone since
        s = _drop(self._write(s, v, src), k)
        if kind == "clear" and s.contacts[i].clear == "pending":
            if self.looks_deleted(s, i) and self.fx("P_clear_waits_deleted"):
                return s                                                # a 404 from a soft-deleted Person: the clear stays open
            s = _c(s, i, clear="acked")
        return s

    def _timeout(self, s, k, landed):
        """The write's deadline passed while the lease still holds: it either landed or it never will. The lease is released,
        the outcome is unknown, so a refresh is queued (a clear stays pending and is sent again)."""
        i, kind, v, src, _, _ = s.inflight[k]
        if landed:
            s = self._write(s, v, src)
        return self._refresh(_drop(s, k))

    def ev_timeout_landed(self, s, k):
        return self._timeout(s, k, True)

    def ev_timeout_lost(self, s, k):
        return self._timeout(s, k, False)

    def ev_lease_expires(self, s, k):
        """The lease ran out while the call could still land (the old lease rule, or a send after a stall); nothing refreshes."""
        i, kind, v, src, _, phase = s.inflight[k]
        return _put(s, k, (i, kind, v, src, False, phase))

    def _drop_leases(self, s: PState) -> PState:
        """The old rule: a delete webhook deleted the lease row, so every write out on the Person loses its lease."""
        if self.fx("P_lease_never_deleted"):
            return s
        return replace(s, inflight=tuple((i, k, v, src, False, ph) for i, k, v, src, _, ph in s.inflight))

    def _record_flag(self, s: PState, pts) -> PState:
        for i in pts:
            if s.contacts[i].life != "erased":
                s = self._ledger(s, i, "denied")
        return s

    def ev_flag(self, s, _):
        """Staff set the flag (a false to true transition). The stop is recorded against every contact point on the Person
        except one whose erasure completed and that has no key since (3.7)."""
        pts = sorted(s.points)
        s = replace(s, flag=True)
        if self.fx("P_skip_per_point") or not any(s.contacts[i].life == "erased" for i in pts):
            s = self._record_flag(s, pts)
        # (the old rule skipped the whole Person when any point was erased)
        if any(s.contacts[i].life != "erased" and s.contacts[i].status != "denied" for i in pts):
            s = _viol(s, "staff_stop_not_recorded")                     # a live point on the flagged Person holds no stop
        return s

    def ev_unflag(self, s, _):
        """True to false: not a lift; the ledger is unchanged (3.4)."""
        return replace(s, flag=False)

    def ev_staff_edit(self, s, _):
        """Staff type into a status field the vault owns (drift, 1.5)."""
        return replace(s, fields="permitted", src=frozenset(), recheck=True)   # it moves updatedAt: the reconcile reads it (3.5)

    def ev_scan(self, s, _):
        """The nightly full scan, under the Person's lease like any write."""
        want = self.truth(s)
        if self.fx("P_scan_recomputes"):
            v, src = want, frozenset(self.contributors(s))
        else:
            erased = any(s.contacts[i].life == "erased" for i in s.points)
            v, src = (None, frozenset()) if erased else (want, frozenset(self.contributors(s)))
        if want == "denied" and v != "denied":
            s = _viol(s, "scan_drops_a_stop")
        nothing_pending = not s.inflight and not any(s.contacts[i].queued for i in self.contributors(s))
        if want == "denied" and s.fields != "denied" and nothing_pending and not self.fx("P_alarm_hidden_stop"):
            s = _viol(s, "hidden_stop_not_alarmed")                     # the old rule: a count, alarmed only past 25 a day
        return self._write(s, v, src)

    def ev_recheck(self, s, _):
        """The reconcile reads a Person changed since its watermark and applies the scan rule to it."""
        return replace(self.ev_scan(s, 0), recheck=False)

    def ev_merge_in(self, s, i):
        """Twenty merges another Person holding contact point i into this one: emails and phones are unioned, every other
        field keeps the winner's value (read from the 2.46.0 server), so the status fields and the flag are the winner's.
        If the winner is flagged, the new point is now on a Do-not-contact Person and gets the stop."""
        s = replace(s, points=s.points | {i})
        if s.flag and self.fx("P_stop_new_points"):
            s = self._record_flag(s, [i])
        if s.flag and s.contacts[i].life != "erased" and s.contacts[i].status != "denied":
            s = _viol(s, "new_point_missing_stop")
        return self._refresh(s) if self.fx("P_refresh_on_points") else s

    def ev_delete_person(self, s, _):
        return replace(s, deleted=True, del_hook=True)

    def ev_deleted_webhook(self, s, _):
        """person.deleted is processed, possibly after the Person was already restored: nothing is deleted (3.3)."""
        return replace(self._drop_leases(s), del_hook=False)

    def ev_destroy(self, s, _):
        """person.destroyed (a hard delete, or a merge removing this Person): the record and its fields are gone; links and
        flag history are deleted, one destroyed marker is kept per deleted Person, keyed on its record hash; the lease row is not deleted."""
        links = frozenset() if self.fx("P_destroy_drops_links") else s.links
        # the marker: one per record hash, always; the old rule derived markers from link rows, so a Person never linked got none
        marker = True if self.fx("P_destroyed_marker") else bool(s.links)
        s = replace(self._drop_leases(s), gone=True, deleted=False, del_hook=False, fields=None, src=frozenset(),
                    links=links, late_flag=s.flag, flag=False, recheck=False, marker=marker)
        return self._close_alarms(s)

    def ev_late_update(self, s, _):
        """A person.updated for the destroyed Person, flag true, processed after person.destroyed. Its flag history is gone, so
        without the marker it reads as first sight with the flag true and stops every point again."""
        s = replace(s, late_flag=False)
        if s.marker:
            return s                                                    # the marker: every later event for this Person is ignored
        for i in sorted(s.points):
            c = s.contacts[i]
            if c.life != "erased" and c.status != "denied":
                s = _viol(s, "restop_without_new_flag")                 # a lifted contact stopped again by a flag already processed
        return self._record_flag(s, sorted(s.points))

    def ev_day_passes(self, s, i):
        """Time passes while contact i's clear waits on a soft-deleted Person that nobody restores. The connector never
        hard-deletes the customer's record: it alarms the customer at 7 days (pinned on the overview, daily after) and the
        operator at 30, and the erasure stays open."""
        c = s.contacts[i]
        s = _c(s, i, waited=c.waited + 1)
        if not self.fx("P_deleted_wait_alarms"):
            return s                                                    # the old rule: a silent wait, forever
        alarm = "customer+operator" if c.waited + 1 == 3 else "customer"
        return _c(s, i, alarm=alarm, raised=c.raised + 1)               # opened on day 7, raised daily, the operator added on day 30

    @staticmethod
    def _close_alarms(s: PState) -> PState:
        """A restore sends the clear, a permanent delete acknowledges it: either closes the wait and its alarms."""
        return replace(s, contacts=tuple(replace(c, waited=0, alarm="", raised=0) for c in s.contacts))

    def ev_restore(self, s, _):
        """person.restored: the Person is back with the fields it had when deleted, and writes meanwhile answered 404."""
        s = self._close_alarms(replace(s, deleted=False))
        return self._refresh(s) if self.fx("P_refresh_on_points") else s


PERSON_STARTS = (PState(), PState(points=frozenset({0})))   # a Person holding both, and one holding the email until a merge


def person_settle(m: PersonModel, s: PState, limit: int = 60) -> Tuple[PState, bool]:
    """Deliver everything and complete every erasure, in a fixed fair order, until nothing changes."""
    def drain(s):
        while s.inflight:
            ph = s.inflight[0][5]
            s = m.step(s, ("send", 0) if ph in ("ready", "stalled") else ("land", 0))
        return s
    for _ in range(limit):
        start = s
        s = drain(s)
        for i in range(len(s.contacts)):                   # nobody restores the Person: time passes, the alarms must fire
            while ("day_passes", i) in m.enabled(s):
                s = m.step(s, ("day_passes", i))
        if s.del_hook:
            s = m.step(s, ("deleted_webhook", 0))
        for name in ("claim_clear", "claim_state", "recheck", "complete"):
            for i in range(len(s.contacts)):
                if (name, i) in m.enabled(s):
                    s = drain(m.step(s, (name, i)))
                if name == "recheck":
                    break
        if s == start:
            return s, True
    return s, False


# The customer's alarm links the waiting record on their own Twenty host. Confirmed on Twenty v2.46.0 (2026-10-31, read only from the
# built frontend in the local container): route RecordShowPage = "/object/:objectNameSingular/:objectRecordId". The alarm carries the
# erasure id, the system, the record id and this link; never a name, email or phone.
RECORD_URL = "{base_url}/object/person/{record_id}"
RECORD_URL_CONFIRMED_ON = "2.46.0"


def alarm_link(base_url: str, record_id: str) -> str:
    return RECORD_URL.format(base_url=base_url.rstrip("/"), record_id=record_id)


ALARM_AT = {0: ("", 0), 1: ("customer", 1), 2: ("customer", 2), 3: ("customer+operator", 3)}   # wait level: (alarm, raises)


def alarm_problems(s: PState) -> List[str]:
    """The alarm state a wait level requires: nothing before day 7, the customer's pinned alarm from day 7 raised once a day,
    the operator alarm added on day 30. A wait that is not on a soft-deleted record holds no alarm."""
    out = []
    for c in s.contacts:
        if (c.alarm, c.raised) != ALARM_AT[c.waited]:
            out.append("erasure_wait_not_alarmed")
    return out


def person_problems(m: PersonModel, s: PState) -> List[str]:
    out = sorted(s.viol) + alarm_problems(s)
    t, ok = person_settle(m, s)
    out += sorted(t.viol - s.viol) + alarm_problems(t)
    if s.deleted and not t.deleted:
        out.append("settle_restored_the_record")                         # nobody restores it: the environment must not either
    if not ok:
        out.append("settle_did_not_stabilise")
    for i, c in enumerate(t.contacts):
        waits = c.clear == "pending" and m.looks_deleted(t, i)
        if waits and not t.gone and c.waited == 3:
            continue                    # open on a never-restored soft-deleted Person, alarmed to the customer and the operator
        if c.queued or c.clear:
            out.append("queue_not_drained" if not waits else "erasure_blocked_silently")
    if t.recheck and not t.deleted:
        out.append("queue_not_drained")
    if not t.gone and not t.deleted:
        want = m.truth(t)
        if t.fields != want:
            out.append("erased_fields_populated" if want is None else "twenty_not_current")
    return sorted(set(out))
