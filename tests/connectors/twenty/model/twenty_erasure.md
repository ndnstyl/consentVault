# Twenty erasure and clear: the state machine

The rules in `twenty.md` sections 3.7 and 5 are this table. The executable model is `twenty_erasure.py`; the tests are
`test_twenty_erasure.py` (run from this folder: `python3 -m unittest test_twenty_erasure -v`). When the table and the model
disagree the model wins, and this file is corrected from it. Words used here: **request** is one erasure request (status
`pending_operator_confirmation`, `declined` or `completed`); **held** is `erasure_request.held_by` being set (there is no
`held` status); **clear** is the one outbox row of kind `clear` that blanks the vault's fields on every matching Person in
Twenty; **status write** is a `state` or `refresh` push.

## What is stored

| Thing | Values | Notes |
|---|---|---|
| request.status | pending, declined, completed | `completed` only through `erase_contact` |
| request.confirmed | bool | the operator's intent, stamped at the first confirm call. It drives nothing else |
| request.held | bool | `held_by` is set: a legal hold covers the contact |
| request.waived | bool | the operator chose proceed-without-clear; terminal for this request |
| request.clear | none, pending (queued), sent (claimed, call in flight), ack, dead, sup_held, sup_declined, sup_waived | one clear per request, keyed `(org, system, erasure_id)` |
| request.wait | stored wait reason | recomputed on every confirm call; never used to decide whether to resume |
| contact | live, erased | erased = key destroyed. A new stop from the vault makes it live again with a new key |
| ledger status | none, permitted, denied | after erasure it is `denied` on every channel (erasure writes a stop by fingerprint before the key goes) |
| hold | none, member, operator | a client's own hold (`set_by_kind = member`) or an operator's |
| in flight | one status write claimed, one clear call claimed | at most one delivery in flight per (system, contact) |
| Person.fields | cleared or the status written | per Person; duplicates are separate Persons |
| Person.flag, Person.seen | staff flag; the last flag this connector processed (no row = never) | `seen` lives in `connector_flag_seen` keyed `(org, system, person_id_hash)`, not on the link |

Clear states: `pending` (queued or in flight), `ack` (written and read back), `dead` (window ended), and three superseded
reasons, `sup_held`, `sup_declined`, `sup_waived`. `sup_held` is the only superseded state that may be revived, and only by
its own request.

## Rules applied by every event

- **R1 suppression.** A status write is withheld while some request is `pending`, not held, and its clear is `pending`, `dead` or
  `ack`. It is never keyed on `confirmed`, and a request with no clear yet (not confirmed, or covered by a hold) withholds nothing.
- **R2 erased.** While the contact is erased no status write is delivered (superseded) and no flag from any Person is imported.
  The block is by contact fingerprint, so every Person, including one created after the erasure, is blocked.
- **R3 wait reason precedence** (one reason shown): `system_clear_dead`, then `waiting_for_system_clear`, then
  `pending_suppression_delivery`, then `uncommitted_ledger_intent`.
- **R4 resume.** The resume job calls the same function as a confirm for every request that is `pending`, confirmed and not held,
  whatever its stored reason (including none and `system_clear_dead`). The function recomputes everything.
- **R5 status pushes are dropped when a clear is queued or revived**, because the clear blanks the person's fields (the vault keeps the stop; the Twenty flag is left).
- **R6 refresh obeys R1.** A refresh push (person created, decline, hold, release) is queued only if a state push would be.
- **R7 exclusive delivery.** Delivery is two steps, claim and land. A clear is not claimed while a status write is in flight, and a status
  write is not claimed while a clear is in flight, so a write claimed before the clear cannot land after it.
- **R8 nightly scan** (backstop): blanks every Person matching an erased contact and corrects drift on live contacts.

## Events

| Event | Precondition | Effect |
|---|---|---|
| erase request | contact live, no pending request, no client hold | new request. A client's own hold refuses it outright (`0018_gag_safety.sql` line 74); an operator's hold creates it held. A second pending request, or a request on an erased contact, is refused |
| confirm (also resume) | request pending | set confirmed. If a hold covers the contact: held; an open, dead or acknowledged clear becomes `sup_held`; queue a refresh; stop. Else not held. Clear: none gives a new clear `pending`; `sup_held` is revived to `pending`; `sup_waived`, `ack`, `pending`, `dead` stay. Queued status pushes dropped (R5). Compute the wait reason (R3). No reason: complete (below). Else store it |
| complete | no reason | requires clear `ack` and every Person cleared, or `sup_waived`; contact becomes erased; ledger status becomes `denied` on every channel |
| decline | request pending | status declined, not held; clear `pending`, `sent`, `dead` or `sup_held` becomes `sup_declined` (an `ack` stays: it was delivered); queue a refresh |
| hold placed (member or operator) | no hold | every pending request is marked held; an open, dead or acknowledged clear becomes `sup_held` (the refresh below writes data back, so the clear must run again); queue a refresh |
| hold released | hold in force | requests unheld; queue a refresh; the resume job (R4) re-runs each request |
| operator proceed without clear | request pending, clear dead, not waived, not held, **and the Twenty system disconnected with its key destroyed (the route refuses otherwise)** | waived; clear `sup_waived`; the request completes at the next confirm; the proof records Twenty was not cleared |
| clear claim | clear pending, request not held, nothing else in flight (R7) | clear `sent`, call in flight |
| clear land | clear call in flight | Persons blanked; clear `ack` if still `sent`. A clear superseded meanwhile still lands (the call cannot be recalled) |
| clear dead | clear pending or sent | clear `dead` |
| redrive | a dead clear, request pending, not held, not waived, system not disconnected | clear `pending` |
| vault stop or grant | any | the contact is live (a new key if it was erased), ledger updated, status write queued (R1 may withhold it) |
| create Person | up to two | a status write is queued if the contact is live |
| webhook or reconcile on a Person | flag differs from `seen` | false to true or first sight with flag true: if the contact is erased, skip (R2); else record a stop and queue a status write. `seen` follows the flag |
| claim status write | queued, nothing in flight (R7) | erased: dropped. Group holds a pending clear: dropped. Else the current status is read and held in flight |
| land status write | in flight | every Person is written the value read at claim |
| nightly scan | persons exist | R8 |
| generic push, generic delivered | | a generic webhook delivery is outstanding or not (a wait reason) |

## Invariants the tests assert (exhaustive over every order of events to a depth the run prints, claim and land separate and with one-step deliveries, plus 20,000 seeded walks of 60 to 100 events; the counts are printed by the run)

1. An erased contact's Twenty fields are never repopulated, and no flag from any Person is imported while the contact is erased. The gate denies an erased contact on every channel, including a contact who consented, was erased, then was flagged in Twenty.
2. No status write happens while an erasure is mid-flight for that system (open, dead or acknowledged clear, request pending, not held).
3. Every stop not covered by an erasure reaches Twenty: after the helping events run, every Person shows the ledger's current status.
4. A waiver is terminal: a waived request's clear stays `sup_waived`.
5. Each request has its own clear; a request completes only with its own acknowledged clear (or a waiver).
6. A hold blocks the clear, never a stop: a hold marks pending requests held at placement and at creation, and stops still reach Twenty with the hold in force.
7. A decline, a hold or a hold release re-writes current state to Twenty.
8. One pending request per contact; a request on an erased contact and a request under a client's own hold are refused.
9. Nothing waits forever: with the operator confirming, the clear delivered or redriven and holds released, no request stays pending.
10. A dead clear of a declined or completed request does not linger; a dead clear is always shown as `system_clear_dead`.

## Round six additions

- **R9** A queued or in-flight status write is a delivery wait (like `pending_pushes`), so the key is never destroyed with a write undelivered.
- **R10** The erasure stop is written at the first confirm, including a confirm made under a legal hold (only key destruction waits), before the clear is queued, and stays after a decline (ruled). It is written again at any later unheld call after a grant or lift (R13).
- **R11** Hold release is two events, `hold_released` (row released, refresh queued) then `hold_resume` (held marks cleared, confirmed requests re-run); a confirm between them clears the stale mark.
- **R13** Every unheld erase call writes a fresh erasure stop when a grant or lift came after the last one (`F_stop_at_completion`; core: `record_erasure_stop`); planted trace: grant, request, confirm, lift, clear claim, clear land, resume.
- **R12** `flag_seen` survives link deletion (keyed-hash store), modelled by the `restop_without_new_flag` invariant.
- Events added: `vault_lift`, `recapture`, `hold_resume`.

## Findings the model found beyond the reviews (now rules)

- Without the exclusive delivery rule a status write claimed before the clear lands after it; the nightly scan repairs it (both are tested).

- An acknowledged clear must also be superseded when a hold is placed, because the refresh that follows writes data back.
- A refresh queued while a clear was `sup_held` must be dropped when the clear is revived (R5), or it writes after the clear.
- A request created while a hold is in force must be created held.

## Conformance against the real core

`test_conformance_core.py` (same folder) replays walks of the core-owned events that cover every state and every transition of the model (the run prints the counts) (grant, erase request, confirm, decline, hold placed by the
client or the operator, hold release, hold resume, lift by a verified grant, re-capture) against the real core in Postgres and checks, after each step, every erasure request's status and the gate: all eight channel and purpose cells on a step that takes a
transition not replayed before and on the last step of each walk, and a rotating pair of cells (through all four channels) on the rest. The model runs with `no_system=True` (and `generic_system=True` for the wait trace). It found
three model drifts that are now fixed: an operator hold release resumes at once (only the client's release is two steps), a request needs a
record of the contact, and no Twenty push is queued when no Twenty system is connected. Run it from the core repository (command in the file).

- **R14** The resume job skips a request restore holds for operator re-confirmation (`uncommitted_ledger_intent`); a replayed committed erasure closes its open clear as erased.
- **R15** Proceed-without-clear is refused by the route unless the system is disconnected and its key destroyed (`F_waive_needs_disconnect`); disconnecting supersedes queued status writes and makes an unsent clear dead, waiting for that waiver.

## One Person, several contacts (round fourteen)

A Twenty Person often holds an email and a phone, which are two contacts in the vault, each with its own ledger state and its
own erasure. The single-contact table above wrote each contact's state as it was delivered, so the last write won: an email
grant overwrote the phone's stop, and erasing the email blanked a stop the phone still held. `PersonModel` in
`twenty_erasure.py` follows one Person holding two contacts through grants, stops, lifts, erasure (request with the first
unheld confirm, clear, complete, decline) and deliveries claimed and landed as separate steps. Its whole reachable state graph
is finite and the tests walk all of it (the run prints the count). The per-contact lifecycle (holds, waivers, resume,
disconnect, the delivery waits) is the table above, unchanged.

Words: a **contributing contact** of a Person is a contact point on that Person (primary or additional email or phone, read
from Twenty at write time) whose fingerprint the vault holds with a live key and no unheld erasure mid-flight (its clear
pending, sent, dead or acknowledged). An erased contact, and one being erased, contributes nothing.

- **R16 combined state.** Every write to a Person (a `state` or `refresh` push of any of its contacts) is computed at write time
  from every contributing contact, channel by channel: `denied` if any contributing contact is denied on that channel (any
  purpose), else `permitted` if any is permitted, else `none`. A stop or a denial on any contact always wins. `cvStateSeq` is the
  largest `as_of_seq` among them. (`P_combine_contacts`; without it the email's push overwrites the phone's stop.)
- **R17 erasure recomputes.** A clear for one contact writes the combined state of the Person's other contributing contacts; it
  blanks the fields only when none is left. It never clears a stop another contact holds. (`P_erase_recomputes`; without it the
  clear blanks the phone's stop.)
- **R18 one link per Person and contact.** `connector_link` is keyed `(org, system, person_id_hash, contact_fp)`, so the email and
  the phone each link the same Person, and erasing one deletes only its own rows. (`P_link_per_contact`; with the key on the
  Person alone the phone's link conflicts with the email's and its stop never reaches Twenty.)
- **R19 one write in flight per Person.** Two contacts are two claim groups, so the group lock does not cover a shared Person.
  Before the GET the connector takes a lease on the Person (`sync_lease_person`, keyed `(org, system, person_id_hash)`), computes
  the value after it holds the lease and releases it after the read-back; a Person already leased releases the claim (not an
  attempt) to finish on the next claim. (`P_person_lease`; without it a value computed before the phone's stop lands after it.)

| Event | Effect |
|---|---|
| grant, stop, lift on contact i | ledger updated (a grant during a stop changes nothing; after erasure, a new key and the stop stands); a push for i is queued unless i is being erased (R1) |
| erase i | the erasure stop is written, i's queued push is dropped (R5), i's clear is queued; i stops contributing |
| decline i | i contributes again (its stop stays); a refresh is queued |
| claim a push or clear of i | refused while another write to the Person is in flight (R19); link (Person, i) (R18); the value is computed now (R16, R17) |
| land | the Person's fields are the value; a clear becomes acknowledged |
| complete i | needs i's clear acknowledged and nothing of i queued or in flight; i is erased and its links deleted |

Invariants: a computed write is `denied` whenever any contributing contact is denied (`write_hides_a_stop`, `clear_drops_a_stop`);
with every delivery made, every queue drains and the Person's fields equal the combined state of its contributing contacts, and
are blank once every contact is erased. Named scenarios: email granted plus phone stopped, in both orders, reads `denied`; erasing
the email while the phone is stopped writes `denied`, never a blank, and leaves only the phone's link; erasing both blanks only at
the last clear and both stops stay as fingerprints.

## Round fifteen additions

The Person model now also covers a Person that holds only the email until a merge brings the phone in, a soft delete and restore,
the staff flag, the nightly scan and a reconcile recheck of one Person, and a lease that expires while its write is still out. At
most two writes are out at once, which is enough to show any overlap. The whole reachable graph is walked from both starting
Persons (the run prints the count).

- **R20 skip per point.** A staff flag records the stop against every contact point on the Person except one whose erasure
  completed with no key since. One erased email never skips the Person, so the phone's stop is recorded. (`P_skip_per_point`;
  invariant `staff_stop_not_recorded`.)
- **R21 the scan recomputes.** The nightly scan (and a reconcile recheck) writes the combined state of the remaining contributing
  contacts, under the Person's lease, and blanks only when none is left. (`P_scan_recomputes`; invariant `scan_drops_a_stop`.)
- **R22 the lease outlives the write.** The lease runs 30 seconds from each extension and a call's deadline is 15, so a write is
  answered or past its deadline before the lease ends. No write is sent without the lease. A write past its deadline has an unknown
  outcome (events `timeout_landed`, `timeout_lost`): a refresh and a recheck follow, and a clear stays open. The group claim lock
  is a lease too. (`P_lease_outlives_write`; the old rule is event `lease_expires`, after which the write can land late; invariant
  `write_after_lease_lost`.)
- **R23 refresh on any change of the Person.** A merge (the winner keeps its own status fields and flag and gains the losers'
  emails and phones, read in the Twenty 2.46.0 server), a restore and any change of contact points queue a refresh for each
  contributing contact and a recheck, which also covers a Person whose only points are erased. A soft delete deletes nothing, a
  hard delete deletes links and flag history, and no event deletes a lease. (`P_refresh_on_points`.)
- **R24 completion waits for every write of the contact** (`P_complete_waits`). Its queued half cannot be reached: an erasure
  drops the contact's queued push and R1 suppresses new ones (asserted over the whole graph). Its in-flight half cannot be reached
  while R22 holds, because a clear cannot be claimed while a write of that contact holds its lease. It fires once a lease
  expires under a write: a named test shows the guard blocking completion, and the search finds
  `erased_with_write_in_flight` when both the guard and R22 are off. So it is defence in depth, kept and tested.

## Round sixteen additions

The Person model now also has the Person's own flag, a staff edit of a vault-owned field, a hard delete (`destroy`), a
soft-delete webhook processed separately and possibly after the restore, and a send step after the lease extension that a worker
stall can delay. The fixed model's whole reachable graph is walked (the run prints the count) and each rule below fails its
own test when switched off.

- **R25 a clear waits for a soft-deleted Person** (`P_clear_waits_deleted`). A clear is not claimed while the Person is
  soft-deleted, and a 404 from one is not an acknowledgement; it is sent after a restore, and acknowledged `not_in_system` after a
  hard delete. Invariant `erased_data_restorable`: an erasure never completes while a soft-deleted Person holds a value computed
  from the erased contact. The fixed model found the second half itself (a clear in flight when the Person was deleted).
- **R26 a point added to a flagged Person gets the stop** (`P_stop_new_points`), so a merge racing a staff stop leaves every
  point stopped in either order. Invariant `new_point_missing_stop`.
- **R27 send deadline** (`P_send_deadline`). No send more than 15 seconds after the lease extension, by a monotonic clock; a
  stalled send is refused and the push claimed again. Without it the stalled send's lease can end while it is out
  (`write_after_lease_lost`).
- **R28 an uncovered stop alarms every time** (`P_alarm_hidden_stop`). A staff edit moves `updatedAt`, so the reconcile rechecks
  the Person; a correction that finds a stop hidden with nothing of that Person queued or in flight alarms each time. Invariant
  `hidden_stop_not_alarmed`.
- **R29 no event deletes a lease** (`P_lease_never_deleted`). The failing order is a soft delete, a restore, then the late
  `person.deleted` webhook freeing the lease of a write still out. On a hard delete alone a freed lease is harmless (the record is
  gone, so nothing can land); the test fails on any revert of the rule because both handlers share it.

## Round seventeen additions

- **R30 hard delete drops links, keeps a destroyed marker** (`P_destroy_drops_links`, `P_destroyed_marker`). A link kept past the
  hard delete makes the clear read the 404 as a restorable soft delete and wait for ever (`erasure_blocked_silently`). With the flag
  history deleted, a late `person.updated` (event `late_update`) would stop again a contact lifted since
  (`restop_without_new_flag`); the marker, one per deleted Person keyed on its record hash only, makes every later event for that Person
  ignored.
- **R31 a record nobody restores** (`P_deleted_wait_alarms`). The settle step no longer restores a soft-deleted Person: time passes
  instead (event `day_passes`, three levels: under 7 days, from 7, from 30). The erasure stays open and the connector never deletes
  the record; from 7 days the customer's pinned admin alarm (daily), from 30 the operator alarm. An open clear on a never-restored
  Person is accepted by the liveness check only at the 30-day level with both alarms raised; anything else is
  `erasure_blocked_silently`, and an unalarmed wait is `erasure_wait_not_alarmed`.

## Final check additions

- **R30, amended.** The destroyed marker is one per deleted Person, keyed on its record hash alone, written at every hard delete. Late
  events are ignored because the marker exists (`PState.marker`), not as a blanket rule; with the old rule (markers from link rows) a
  flagged, lifted Person destroyed before it was ever linked is re-stopped by a late update.
- **R31, amended.** The alarm is state the model holds and checks: `alarm` and `raised` per contact must match the wait day
  (`ALARM_AT`: nothing before day 7, the customer's pinned alarm on day 7 raised again each day, the operator alarm added on day 30;
  all closed by a restore or a permanent delete), checked in every reachable state and in every settled one. The liveness check also
  fails if settling a soft-deleted Person restores it (`settle_restored_the_record`), and a test puts the forced restore back and sees
  it caught.
- **Alarm link.** `{base_url}/object/person/{record_id}`, confirmed on Twenty v2.46.0 on 2026-10-31 from the built frontend's
  `RecordShowPage` route `/object/:objectNameSingular/:objectRecordId` (read only); `RECORD_URL` and `alarm_link` in the model.
