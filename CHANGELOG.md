# Changelog

All notable changes are listed here. Format follows Keep a Changelog; versions follow semantic versioning.

## Unreleased

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
