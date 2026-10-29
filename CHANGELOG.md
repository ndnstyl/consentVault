# Changelog

All notable changes are listed here. Format follows Keep a Changelog; versions follow semantic versioning.

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
