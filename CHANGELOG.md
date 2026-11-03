# Changelog

All notable changes are listed here. Format follows Keep a Changelog; versions follow semantic versioning.

## 0.1.0 – initial release

- Chained, append-only consent ledger with a database-enforced runtime role, anchoring of the chain head to an
  external sink, and RFC 3161 timestamp seals.
- Registered disclosure wording, grants limited to the channels and purposes their wording names, stops that
  and a record that keeps a person's own later consent beside their earlier stop.
- A stop and a later consent are both kept, in the order they arrived, with any proof the integrator gives that the person controls the contact point; neither is ranked, released or refused. Evidence bundles carry the chain path from the
  first event, and `verify.py` requires anchors from the sink. Salts are minted by a database function.
- Contact gate, proof lookup and a self-verifying evidence bundle.
- Optional signed HTTP API, capture edge worker and embeddable checkbox widget, adapter protocols, and
  packaging.
