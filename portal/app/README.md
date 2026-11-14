# ConsentVault Cloud dashboard

Next.js 14 static export (pages router, TypeScript). Visual source: `../design/hifi/tokens.css` (copied unchanged to `src/styles/tokens.css`) and `../design/hifi/_build/portal.css`. Copy of record: `../design/copy-rules.md` and the wireframe text. Contracts: the cloud contracts.

```
npm install
npm run typecheck
npm test                 # node:test: role gating, API client, copy check, formats
npm run build           # writes out/ (static HTML, _headers with the CSP, _redirects for dynamic routes)
npm run e2e              # Playwright over every screen and state at 375 and 1440, then the acceptance flows
```

Real-API end to end (no mock, no WorkOS): `scripts/e2e/stack.py` starts a throwaway Postgres, the API, a stub sign-in issuer the
tests control, and the portal edge Worker (`wrangler dev`) serving `out/`, with two synthetic organizations and a person in
both. `e2e/real/run.mjs` drives Chromium through sign-in (stub issuer, edge, session cookie), the organization chooser, one
contact's records and timeline, building and downloading an evidence package, running the package's own verify tool, and
checks the second organization sees none of the first one's data. Everything it starts is stopped before it exits.

```
npm run build                                   # writes out/
PG_BIN=/path/to/postgres/bin npm run e2e:real   # or leave PG_BIN unset with pg_config on PATH
# the stack alone (prints one {"ready": ...} line, runs until its input closes or SIGTERM):
PG_BIN=... ../../.venv/bin/python ../../scripts/e2e/stack.py --wrangler /path/to/wrangler
```

`WRANGLER` and `PLAYWRIGHT_PATH` override the wrangler executable and the playwright package used.

Manual smoke of the sign-in leg against WorkOS staging (not run in CI; a person completes the hosted sign-in in a visible
browser): `node e2e/real/workos-smoke.mjs --dry-run` checks the setup and prints what to register, `node e2e/real/workos-smoke.mjs`
runs it. The account owner registers `http://localhost:8787/auth/callback` as a redirect URI and `http://localhost:8787/sign-in`
as the sign-out redirect in the WorkOS staging dashboard. The script reads the staging key inside itself, never prints it,
and reports whether the token WorkOS issues would pass the vault's checks (signature, audience, `amr` second factor).

Dev: `node mock/server.ts --port 4010 --no-static` in one terminal, then
`NEXT_PUBLIC_API_BASE=http://127.0.0.1:4010 npx next dev -p 3000` in another.
Stop both when you are done.

- `src/lib/api/client.ts` is the typed client (hand-written from the contracts). It holds no token: the edge holds the session cookie.
- `mock/` is the mock API and static host. `POST /__mock/scenario` sets the role, organization status and which reads fail or come back empty or null.
- Dynamic routes (`/sources/<id>`, `/wording/<sha>`, `/policies/<n>`, `/checklists/<n>`, `/exports/<id>`, `/systems/<id>`, `/confirmations/<source>/<channel>`) are served the list page's HTML by the host rewrite in `public/_redirects`; `src/lib/router.tsx` resolves them on the client.
- Sign-in is WorkOS's hosted page. The portal links to `/auth/login` and `/auth/logout` on the edge and finishes at `/auth/callback`.
- A feature flag named for a contract gap lives in `src/lib/flags.ts`; the one open gap today is the site-key header for the first-event command.
