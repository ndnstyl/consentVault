# Changelog

All notable changes are listed here. Format follows Keep a Changelog; versions follow semantic versioning.

## Unreleased

- One door: every entry point (the single-company server, the multi-tenant server, the text reply, the command line, the
  library, the stop page, a connected system's signal) stores the request whole and hands it to one projection. The events are
  a rebuildable projection of the posts with one writer; each event cites the one post it came from, and the database refuses
  a second event for the same post or the same signed request (migration 0073), so running the projection again after a crash is
  always safe. A duplicate is a fold rule, not a claim: the seen-request record and the transaction choreography around it are
  gone, as are the two copies of the step that parsed and judged a post while its request was open. The property test in
  `tests/test_one_door_property.py` drives random grants, stops, START texts, form consents, resends, duplicates and crashes
  through every adapter and compares the result with a reference fold; `tests/test_one_writer.py` fails if any code outside the
  door appends an event. The anchor sink now lists the raw post chain's head beside the event head (marked `chain: raw_post`) and
  the bundle verifier skips it when it checks the event path.
- Raw post store: every request that reaches a capture path (any method, headers, body, size or origin, signed or not) is
  written whole to an append-only, per-organisation hash chain before anything reads it, and answered with a signed
  receipt carrying the fingerprint of the whole body. Large bodies are kept whole in the write-once evidence store. The
  existing event chain and its seals are unchanged.
- Nothing about a capture is refused any more: signatures, credentials, site keys, origins, hosts, bot checks, rates,
  sizes and shapes are recorded as facts beside the post. The only refusal is `503 store_unavailable`, given when the vault
  could not write, and it says nothing was stored.
- Consent is read from the stored bytes as the exact value sent (`true`, `false`, `"on"`, absent), with the decision time
  and the wording as sent, kept beside the arrival time, through a per-form field map. A missing box, missing wording,
  unmapped form, unreadable body or unusual size raises an operator alarm.
- The capture edge forwards the browser's own bytes and headers in one signed envelope and queues them when the vault is
  down; the widget sends the decision time with its offset and the exact text on screen.
- The contact check returns the recorded facts and history for a contact point (every line as written, every stop with its
  source and the posts that triggered it, every lift with the post that lifted it) and no verdict: no `allowed`, `proceed`
  or `hold`, and no deny by default. `may-contact` prints the same facts and exits non-zero only when the record could not
  be read.
- A stop is lifted only by a later consent post from the same person on the same contact point, whose consent value as sent
  equals the value its form's box sends when ticked. The lift is a link from the stop to the post (migration 0069); no
  admin, operator, customer, connector or review queue can lift a stop, a text such as START lifts nothing, and no release
  event can be written any more.
- The refusal codes and the portal's help copy for answers that no longer fire were removed.

## 0.1.0 – initial release

- Chained, append-only consent ledger with a database-enforced runtime role, anchoring of the chain head to an
  external sink, and RFC 3161 timestamp seals.
- Registered disclosure wording, grants limited to the channels and purposes their wording names, stops that
  outrank grants, and a release rule that lets a person's own later grant lift their own earlier stop.
- A stop is lifted only by a grant whose contact point the integrator verified (one-time code or inbound START
  keyword); a web-form grant is refused with a pending review row. Evidence bundles carry the chain path from the
  first event, and `verify.py` requires anchors from the sink. Salts are minted by a database function.
- Contact gate, proof lookup and a self-verifying evidence bundle.
- Optional signed HTTP API, capture edge worker and embeddable checkbox widget, adapter protocols, and
  packaging.
