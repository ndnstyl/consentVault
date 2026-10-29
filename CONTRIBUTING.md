# Contributing

Thanks for helping. ConsentVault.AI is small on purpose: one job, few dependencies, typed errors.

## Setup

```
uv sync            # or: python -m venv .venv && .venv/bin/pip install -e .[dev]
pytest             # needs PostgreSQL 15+ binaries on PATH (or set PG_BIN); tests start their own server
cd edge && npm test    # Node 24+, no installs needed
```

Tests that need the network are marked `network`; skip them with `pytest -m "not network"`.

## Ground rules

1. **Append-only is the product.** No change may add an update or delete path to the event ledger.
2. **Schema changes are additive.** See `docs/evidence-model.md` for what a seal covers.
3. **Errors are raised as typed exceptions with a non-zero exit.**
4. **No vendor in the core.** Integrations go behind the adapter protocols.
5. **White label.** No brand, company, person, domain, phone number or machine path in code, docs or tests.
   Use `example.com` and the `555-01xx` range.
6. **Tests with every change.** A bug fix starts with a failing test.
7. **No secrets in commits.** CI runs gitleaks.

## Pull requests

Keep one concern per PR. Describe what changed and how you checked it. Add a line to `CHANGELOG.md` under
`Unreleased`.
