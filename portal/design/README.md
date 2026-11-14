# ConsentVault Cloud portal: design package

Seat: ui-ux-engineer, 2026-10-29. Next seat: web-designer (hi-fi), then ui-ux review, then the portal build.

| File | What it is |
|---|---|
| ux-audit.md | What exists today, what the site gives the portal, defects not to copy |
| ia.md | Navigation model and route map, one job per route |
| roles.md | Role matrix: admin, compliance viewer, developer (proposed) |
| flows.md | Ten flows with a failure branch at every step (Mermaid) |
| copy-rules.md | Evidence-not-conclusion rules, banned words, label dictionary, error formula |
| accessibility.md | WCAG 2.2 AA spec, computed contrast, new ink tokens |
| contract-gaps.md | Endpoints and error names the screens need that no contract defines |
| handoff.md | Per-screen contract with the front end and numbered acceptance criteria |
| wireframes/README.md | Markdown wireframes |
| wireframes/NN-*.html | 25 self-contained HTML wireframes, every state behind a state switcher |
| (2026-10-30) | Added Records (23), Setup walkthrough (24), Confirmation messages (25): ia.md, flows.md F11 to F15, roles.md, copy-rules.md section 8, contract-gaps.md section F, handoff.md "Additions 2026-10-30"; contracts proposed in `specs/268-consentvault-cloud/contracts/records.md` and `confirmations.md` |

Open any HTML file directly in a browser. With scripts off, every state shows stacked.
