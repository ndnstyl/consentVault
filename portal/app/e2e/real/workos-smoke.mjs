// MANUAL smoke test of the sign-in leg against the REAL WorkOS staging environment. Not run in CI, not part of
// `npm run e2e:real`. A person completes the hosted sign-in; the script judges what the edge and the vault's token rules
// would do with the result. It touches only the sign-in leg: the vault is a tiny local stand-in that records what the edge
// forwards, so no organization data is involved and no production service is called.
//
//   node e2e/real/workos-smoke.mjs --dry-run     checks the setup and prints what to register; starts and calls nothing
//   node e2e/real/workos-smoke.mjs               DEFAULT (--own-browser): opens the login address in your own default
//                                                browser with `open`, so passkeys (Touch ID, iCloud Keychain) work. Every
//                                                check is judged server side: a logging proxy in front of the edge records the
//                                                Set-Cookie attributes (values redacted), the vault stand-in captures the
//                                                forwarded identity token and the edge's signed sign-in-method assertion.
//   node e2e/real/workos-smoke.mjs --playwright  drives Playwright's bundled Chromium instead (no passkeys: it cannot reach
//                                                the OS authenticator; use a password or magic-link staging setup)
//
// Needs (account owner, once, in the WorkOS staging dashboard):
//   Redirect URI      http://localhost:8787/auth/callback
//   Sign-out redirect http://localhost:8787/sign-in
// Credentials: the file named by WORKOS_ENV_FILE, kept in the private operations repository (WORKOS_API_KEY, WORKOS_CLIENT_ID). They are read
// inside this script and never printed. Each wait has a 5 minute deadline. Every process it starts is stopped before it exits.
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { SESSION, judgeAssertion, judgeClearedCookie, judgeSessionCookie, judgeToken, parseEnv, describePortHolder, stopGroup, killGroupSync } from './workos-smoke-lib.mjs';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..', '..', '..', '..');
const ENV_FILE = process.env.WORKOS_ENV_FILE;
const wrangler = process.env.WRANGLER ?? 'wrangler';
const dry = process.argv.includes('--dry-run');
const usePlaywright = process.argv.includes('--playwright');
const PORT = Number(process.env.SMOKE_PORT ?? 8787);
const PUBLIC = `http://localhost:${PORT}`;
const API = 'https://api.workos.com/user_management';
const DEADLINE_MS = 300_000;

const results = [];
const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`); };
const checkRows = (rows) => rows.forEach((r) => check(r.name, r.ok, r.detail));

function readEnv() {
  if (!ENV_FILE) { console.error('FAIL  WORKOS_ENV_FILE is not set: point it at the WorkOS credentials file'); process.exit(3); }
  if (!fs.existsSync(ENV_FILE)) { console.error(`FAIL  credentials file missing: ${ENV_FILE}`); process.exit(3); }
  const mode = fs.statSync(ENV_FILE).mode & 0o777;
  const env = parseEnv(fs.readFileSync(ENV_FILE, 'utf8'));
  for (const k of ['WORKOS_API_KEY', 'WORKOS_CLIENT_ID']) if (!env[k]) { console.error(`FAIL  ${k} is not set in the credentials file`); process.exit(3); }
  return { env, mode };
}

const { env, mode } = readEnv();
check('credentials file is private (mode 600)', mode === 0o600, `mode ${mode.toString(8)}`);
check('both WorkOS names are set', true);
console.log(`\nRegister in the WorkOS staging dashboard (account owner, once):\n  Redirect URI:       ${PUBLIC}/auth/callback\n  Sign-out redirect:  ${PUBLIC}/sign-in\n`);
if (dry) { check('dry run: nothing was started and no service was called', true); process.exit(results.every(Boolean) ? 0 : 1); }

for (const port of [PORT, PORT + 1]) {
  const holder = describePortHolder(port);
  if (holder) { console.error(`FAIL  port ${port} is already in use by ${holder.command} (pid ${holder.pid}); stop it (kill ${holder.pid}) or set SMOKE_PORT`); process.exit(4); }
}
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-smoke-'));
const edgeKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); // the edge's signing key for this run; the vault stand-in holds the public half
const seen = { token: null, assertion: null, setCookies: [], logout: null, signInAfterLogout: false, callbackSeen: false, loginRedirect: null };
const waiters = [];
const changed = () => waiters.splice(0).forEach((w) => w());
const until = (pred, what) => new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error(`${what} did not happen within ${DEADLINE_MS / 1000}s`)), DEADLINE_MS);
  const tick = () => { if (pred()) { clearTimeout(t); resolve(); } else waiters.push(tick); };
  tick();
});

let edge; let vault; let proxy; let browser;
const stop = async () => {
  await browser?.close();
  await stopGroup(edge);
  await new Promise((r) => (proxy ? (proxy.closeAllConnections?.(), proxy.close(r)) : r()));
  await new Promise((r) => (vault ? (vault.closeAllConnections?.(), vault.close(r)) : r()));
  fs.rmSync(work, { recursive: true, force: true });
};
let stopping = null;
const stopOnce = () => (stopping ??= stop());
for (const [sig, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) process.on(sig, () => stopOnce().then(() => process.exit(code)));
process.on('exit', () => killGroupSync(edge)); // last resort on any exit path: the whole wrangler and workerd group

// A logging proxy in front of the edge: the browser talks to PORT, the edge listens one port higher. It records what the edge
// sends (Set-Cookie with the value redacted, the sign-out answer) and passes everything else through untouched.
function startProxy(edgePort) {
  proxy = http.createServer((req, res) => {
    // no compression upstream: the proxy reads bodies (the sign-out answer) as text
    const up = http.request({ host: '127.0.0.1', port: edgePort, path: req.url, method: req.method, headers: { ...req.headers, 'accept-encoding': 'identity' } }, (r) => {
      const url = new URL(req.url, PUBLIC);
      const sc = r.headers['set-cookie'] ?? [];
      seen.setCookies.push(...sc);
      if (url.pathname === '/auth/login' && r.statusCode === 302) seen.loginRedirect = r.headers.location;
      if (url.pathname === '/auth/callback' && url.searchParams.has('code')) seen.callbackSeen = r.statusCode === 302 && sc.some((c) => c.startsWith(`${SESSION}=`) && !c.includes('Max-Age=0'));
      if (url.pathname === '/auth/logout' && req.method === 'POST') {
        let body = ''; r.on('data', (d) => { body += d; });
        r.on('end', () => { try { seen.logout = { status: r.statusCode, redirect: JSON.parse(body).redirect ?? null, cookies: sc }; } catch { seen.logout = { status: r.statusCode, redirect: r.headers.location ?? null, cookies: sc }; } changed(); });
      }
      if (url.pathname === '/sign-in' && seen.logout) seen.signInAfterLogout = true;
      res.writeHead(r.statusCode ?? 502, r.headers);
      r.pipe(res);
      changed();
    });
    up.on('error', (e) => { res.writeHead(502); res.end(`edge unreachable: ${e.message}`); });
    req.pipe(up);
  });
  return new Promise((r) => proxy.listen(PORT, '127.0.0.1', r));
}

try {
  vault = http.createServer((req, res) => {
    if (req.url?.startsWith('/v1/session')) {
      seen.token = (req.headers.authorization ?? '').replace(/^Bearer /, '') || seen.token;
      seen.assertion = req.headers['x-consentvault-edge-assertion'] ?? seen.assertion;
      changed();
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ expires_at: new Date(Date.now() + 3600e3).toISOString(), user: { display_name: null, email: null }, items: [], next_cursor: null }));
  });
  await new Promise((r) => vault.listen(0, '127.0.0.1', r));
  const edgePort = PORT + 1;
  fs.writeFileSync(path.join(work, 'wrangler.toml'), `name = "cv-portal-smoke"
main = "${repo}/edge/src/portal.ts"
compatibility_date = "2026-01-01"
[assets]
directory = "${repo}/portal/app/out"
binding = "ASSETS"
run_worker_first = ["/auth/*", "/v1/*"]
[[kv_namespaces]]
binding = "SESSIONS"
id = "smoke-sessions"
[vars]
ORIGIN_URL = "http://127.0.0.1:${vault.address().port}"
ACCESS_CLIENT_ID = "local-access-id"
AUTH_BASE_URL = "${API}"
AUTH_CLIENT_ID = "${env.WORKOS_CLIENT_ID}"
PUBLIC_URL = "${PUBLIC}"
`);
  fs.writeFileSync(path.join(work, '.dev.vars'), `ACCESS_CLIENT_SECRET=local-access-value\nAUTH_CLIENT_SECRET=${env.WORKOS_API_KEY}\nASSERTION_KEY_JWK=${JSON.stringify({ ...edgeKey.privateKey.export({ format: 'jwk' }), kid: 'smoke-edge' })}\n`, { mode: 0o600 });
  edge = spawn(wrangler, ['dev', '--config', path.join(work, 'wrangler.toml'), '--local', '--ip', '127.0.0.1', '--port', String(edgePort), '--persist-to', path.join(work, 'state'), '--log-level', 'warn'], { cwd: work, detached: true /* own process group, so the whole tree is stopped in stop() */, stdio: ['ignore', fs.openSync(path.join(work, 'edge.log'), 'w'), 'inherit'], env: { ...process.env, CI: '1', WRANGLER_SEND_METRICS: 'false' } });
  await startProxy(edgePort);
  const deadline = Date.now() + 120_000;
  for (;;) {
    if (Date.now() > deadline) throw new Error(`the edge did not answer on ${PUBLIC} within 120s`);
    if (edge.exitCode !== null) throw new Error(`the edge exited early (${edge.exitCode}); is port ${PORT} free? ${fs.readFileSync(path.join(work, 'edge.log'), 'utf8').slice(-600)}`);
    if (await fetch(`${PUBLIC}/sign-in`).then((r) => r.ok, () => false)) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  seen.logout = null; seen.signInAfterLogout = false; seen.setCookies.length = 0;

  const loginUrl = `${PUBLIC}/auth/login?method=passkey&return=%2F`;
  let page; let ctx;
  if (usePlaywright) {
    const { chromium } = require(process.env.PLAYWRIGHT_PATH ?? 'playwright');
    browser = await chromium.launch({ headless: false });
    ctx = await browser.newContext();
    page = await ctx.newPage();
    await page.goto(loginUrl);
    console.log("NOTE  Playwright's Chromium cannot use passkeys (no Touch ID or iCloud Keychain); use a password or magic-link staging setup with this mode.");
  } else {
    spawn('open', [loginUrl], { stdio: 'ignore' }).on('error', (e) => { throw new Error(`could not open your browser with the macOS open command: ${e.message}`); });
  }
  await until(() => seen.loginRedirect, 'the edge starting the sign-in');
  check('the edge sent the browser to the WorkOS hosted sign-in', /workos|authkit/i.test(new URL(seen.loginRedirect).host), new URL(seen.loginRedirect).host);
  const lq = new URL(seen.loginRedirect).searchParams;
  check('the sign-in request carries PKCE (S256) and a state, and no secret', lq.get('code_challenge_method') === 'S256' && !!lq.get('state') && !lq.has('client_secret') && !lq.has('code_verifier'));
  console.log(`>>> Complete the sign-in in your browser (passkey). Waiting up to ${DEADLINE_MS / 60000} minutes.`);

  await until(() => seen.callbackSeen && seen.token && seen.assertion, 'the sign-in finishing at the edge');
  checkRows(judgeSessionCookie(seen.setCookies));
  check('the edge forwarded an identity token to the vault stand-in', !!seen.token);
  let jwks = null;
  try { jwks = await (await fetch(`https://api.workos.com/sso/jwks/${env.WORKOS_CLIENT_ID}`)).json(); } catch (e) { console.log(`      key set fetch failed: ${e.message}`); }
  const tj = judgeToken(seen.token, env.WORKOS_CLIENT_ID, jwks);
  console.log(`      token header: alg=${tj.header.alg} kid=${tj.header.kid ? 'present' : 'MISSING'}; claim names: ${tj.claimNames.join(', ')}; iss=${tj.iss}`);
  checkRows(tj.rows);
  check('the edge sent a signed assertion with the identity token', !!seen.assertion);
  const aj = judgeAssertion(seen.assertion, seen.token, edgeKey.publicKey);
  console.log(`      WorkOS reported authentication_method=${JSON.stringify(aj.method)}; the edge turned it into amr=${JSON.stringify(aj.amr)}`);
  checkRows(aj.rows);

  if (usePlaywright) {
    await page.getByRole('button', { name: 'Sign out' }).first().click();
  } else {
    console.log('>>> In your browser tab, click Sign out (the stand-in vault has no organizations, so the page offers it). Waiting up to 5 minutes.');
  }
  await until(() => seen.logout && seen.signInAfterLogout, 'sign-out finishing');
  check('sign-out was a POST that the edge accepted (200 with the provider address, or a redirect)', seen.logout.status === 200 || seen.logout.status === 302, String(seen.logout.status));
  check('sign-out sent the browser to the WorkOS sign-out address and back to /sign-in', /workos/i.test(String(seen.logout.redirect)) && seen.signInAfterLogout, seen.logout.redirect ? new URL(seen.logout.redirect, PUBLIC).host : 'no address');
  checkRows(judgeClearedCookie(seen.logout.cookies));
} catch (e) {
  check('smoke run completed', false, e.message.split('\n')[0]);
} finally {
  await stop();
}
console.log(`\n${results.filter(Boolean).length} of ${results.length} checks passed`);
process.exit(results.every(Boolean) ? 0 : 1);
