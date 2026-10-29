## What changed and why

## How you checked it

- [ ] Tests added or updated (a bug fix starts with a failing test)
- [ ] `pytest -m "not network"` passes; `npm test` in `edge/` passes if the edge changed
- [ ] No update or delete path added to the event ledger
- [ ] Schema changes are additive, with a matching `down/` file
- [ ] No brand, company, person, domain, phone number or machine path in code, docs or tests
- [ ] No secrets in the diff
- [ ] A line added to `CHANGELOG.md` under `Unreleased`
