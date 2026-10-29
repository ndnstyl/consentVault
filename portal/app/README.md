# ConsentVault Cloud dashboard

Next.js 14 static export (pages router, TypeScript). Visual source: `../design/hifi/tokens.css` (copied unchanged to `src/styles/tokens.css`) and `../design/hifi/_build/portal.css`. Copy of record: `../design/copy-rules.md` and the wireframe text. Contracts: `/Users/oxfloors/brain/specs/268-consentvault-cloud/contracts/`.

```
npm install
npm run typecheck
npm test                 # node:test: role gating, API client, copy check, formats
npx next build           # writes out/ (static HTML, _headers with the CSP, _redirects for dynamic routes)
npm run e2e              # Playwright over every screen and state at 375 and 1440, then the acceptance flows
```

Dev: `node mock/server.ts --port 4010 --no-static` in one terminal, then
`NEXT_PUBLIC_API_BASE=http://127.0.0.1:4010 npx next dev -p 3000` in another.
Stop both when you are done.

- `src/lib/api/client.ts` is the typed client (hand-written from the contracts). It holds no token: the edge holds the session cookie.
- `mock/` is the mock API and static host. `POST /__mock/scenario` sets the role, organization status and which reads fail or come back empty or null.
- Dynamic routes (`/sources/<id>`, `/wording/<sha>`, `/policies/<n>`, `/checklists/<n>`, `/exports/<id>`, `/systems/<id>`) are served the list page's HTML by the host rewrite in `public/_redirects`; `src/lib/router.tsx` resolves them on the client.
- Sign-in is WorkOS's hosted page. The portal links to `/auth/login` and `/auth/logout` on the edge and finishes at `/auth/callback`.
- A feature flag named for a contract gap lives in `src/lib/flags.ts`; the one open gap today is the site-key header for the first-event command.
