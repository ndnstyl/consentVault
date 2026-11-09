// Dashboard end-to-end against the REAL API (not the mock): scripts/e2e/stack.py starts a throwaway Postgres, the API, a
// stub sign-in issuer the tests control, and the portal edge Worker serving the dashboard build. Chromium signs in through
// the edge (/auth/login -> stub issuer -> /auth/callback), picks an organization, looks up a contact, builds and downloads
// an evidence package, verifies it with the package's own verify tool, and checks a second organization sees none of the
// first one's data. CI never needs WorkOS: the issuer is the stub.
//
//   (in portal/app)  npx next build && node e2e/real/run.mjs
//   env: PG_BIN (Postgres bin dir), WRANGLER (wrangler executable, default: wrangler on PATH), PLAYWRIGHT_PATH (a playwright package dir)
//
// Every process it starts is stopped before it exits; a stack that will not stop fails the run.
import { createRequire } from 'node:module';
import { spawn, spawnSync } from 'node:child_process';
import { test, after, before } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..', '..', '..', '..');
const { chromium } = require(process.env.PLAYWRIGHT_PATH ?? 'playwright');
const python = process.env.PYTHON ?? path.join(repo, '.venv/bin/python');
const wrangler = process.env.WRANGLER ?? 'wrangler';

let stack; let S; let browser; let work;
const SESSION = '__Host-cv_session';

before(async () => {
  work = fs.mkdtempSync(path.join(os.tmpdir(), 'cv-e2e-run-'));
  stack = spawn(python, [path.join(repo, 'scripts/e2e/stack.py'), '--wrangler', wrangler], { cwd: repo, stdio: ['pipe', 'pipe', 'pipe'] });
  let err = '';
  stack.stderr.on('data', (d) => { err += d; });
  S = await new Promise((resolve, reject) => {
    let buf = '';
    const timer = setTimeout(() => reject(new Error(`the stack did not report ready within 240s\n${err.slice(-2000)}`)), 240_000);
    stack.stdout.on('data', (d) => {
      buf += d;
      const line = buf.split('\n').find((l) => l.startsWith('{"ready"'));
      if (line) { clearTimeout(timer); resolve(JSON.parse(line).ready); }
    });
    stack.on('exit', (code) => { clearTimeout(timer); reject(new Error(`the stack exited early (${code})\n${err.slice(-2000)}`)); });
  });
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close();
  if (stack && stack.exitCode === null) {
    const exited = new Promise((r) => stack.once('exit', (code) => r(code)));
    stack.stdin.end();
    const code = await Promise.race([exited, new Promise((r) => setTimeout(() => r('timeout'), 40_000))]);
    if (code === 'timeout') { stack.kill('SIGTERM'); assert.fail('the stack did not stop within 40s of its input closing'); }
    assert.equal(code, 0, 'the stack must stop cleanly');
  }
  if (work) fs.rmSync(work, { recursive: true, force: true });
});

const persona = (p) => fetch(`${S.stub}/__stub/persona`, { method: 'POST', body: JSON.stringify(p) }).then((r) => r.json());
const stubLog = () => fetch(`${S.stub}/__stub/log`).then((r) => r.json());
const asPerson = (name, extra = {}) => persona({ sub: S.people[name].sub, email: S.people[name].email, name: S.people[name].name, ...extra });

async function newPage(opts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true, ...opts });
  const page = await ctx.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push(`pageerror ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error' && !/status of (401|404|409)/.test(m.text())) problems.push(`console ${m.text()}`); });
  page.__bad = [];
  page.on('response', (r) => { if (r.status() >= 400) page.__bad.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`); });
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));
  });
  return { ctx, page, problems };
}

// A wait that fails says what the page showed and which calls failed, so a red run explains itself.
async function seen(page, what, fn) {
  try { return await fn(); } catch (e) {
    const body = await page.locator('body').innerText().catch(() => '(no page)');
    throw new Error(`${what}: ${e.message.split('\n')[0]}\n  url: ${page.url()}\n  failed calls: ${page.__bad.join(', ') || 'none'}\n  page said: ${body.replace(/\s+/g, ' ').slice(0, 600)}`);
  }
}

async function signIn(page, next = '/') {
  await page.goto(`${S.edge}/sign-in?return=${encodeURIComponent(next)}`);
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
}

async function lookup(page, contact) {
  await page.goto(`${S.edge}/evidence`);
  await page.getByLabel('Phone number or email').fill(contact);
  await page.getByRole('button', { name: 'Look up records' }).click();
}

function verifyPackage(zipPath, anchor) {
  const dir = path.join(work, path.basename(zipPath, '.zip'));
  fs.mkdirSync(dir, { recursive: true });
  const un = spawnSync('unzip', ['-q', '-o', zipPath, '-d', dir], { encoding: 'utf8' });
  assert.equal(un.status, 0, `unzip failed: ${un.stderr}`);
  const run = spawnSync(S.python, [path.join(dir, 'verify.py'), '--cafile', S.cafile, '--evidence-key', S.evidence_key, '--anchor', anchor], { cwd: dir, encoding: 'utf8' });
  return { dir, run };
}
const allText = (dir) => fs.readdirSync(dir, { recursive: true, withFileTypes: true }).filter((e) => e.isFile()).map((e) => fs.readFileSync(path.join(e.parentPath ?? e.path, e.name), 'latin1')).join('\n');

let alphaExportId = null;

test('a signed-out browser is refused by the real API, and the sign-in page needs no password', async () => {
  const { ctx, page, problems } = await newPage();
  const res = await ctx.request.get(`${S.edge}/v1/org`);
  assert.equal(res.status(), 401);
  assert.equal((await res.json()).error, 'bearer_missing');
  await page.goto(`${S.edge}/sign-in`);
  assert.equal(await page.locator('input[type=password]').count(), 0);
  assert.deepEqual(problems, []);
  await ctx.close();
});

test('sign in (stub issuer), pick an organization, look up one contact, read the timeline, build, download and verify a package', async () => {
  const { ctx, page, problems } = await newPage();
  await asPerson('carol');
  await signIn(page, '/evidence');
  await page.waitForURL('**/choose-org', { timeout: 20_000 });
  await page.getByText('alpha', { exact: false }).first().waitFor();
  assert.ok(await page.getByText('bravo', { exact: false }).count() > 0, 'a person in two organizations sees both');
  await page.getByRole('radio', { name: /alpha/ }).check().catch(async () => { await page.getByText(/alpha/).first().click(); });
  await page.getByRole('button', { name: /continue|open|choose|select/i }).first().click();
  await page.waitForURL((u) => !u.pathname.startsWith('/choose-org'), { timeout: 20_000 });

  // the session cookie: opaque, HttpOnly, Secure, Lax, __Host-, and nothing token-shaped anywhere the page can read
  const cookie = (await ctx.cookies()).find((c) => c.name === SESSION);
  assert.ok(cookie, 'the session cookie was set');
  assert.equal(cookie.httpOnly, true);
  assert.equal(cookie.secure, true);
  assert.equal(cookie.sameSite, 'Lax');
  assert.equal(cookie.path, '/');
  assert.ok(!cookie.value.includes('.') && !cookie.value.startsWith('eyJ') && !cookie.value.startsWith('v1.'), 'an opaque id, not a token');
  assert.ok(!(await page.evaluate(() => document.cookie)).includes('cv_session'), 'script cannot read the cookie');
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
  assert.ok(!/eyJ|"v1\.|v1\.[a-z0-9_-]+\.[0-9a-f]{20}/.test(stored), 'no token in browser storage');

  await lookup(page, S.contact);
  await seen(page, 'lookup in alpha', () => page.getByRole('heading', { name: /Records for .* in alpha/ }).waitFor({ timeout: 20_000 }));
  const timeline = page.locator('ol.tl li');
  assert.ok(await timeline.count() >= 2, 'the timeline lists the grant and the stop');
  const text = await page.locator('main').innerText();
  assert.match(text, /alpha Brand/);
  assert.match(text, /alpha-?fall|Source/i);
  assert.ok(!/bravo/i.test(text), 'no trace of the other organization');

  await page.getByRole('button', { name: 'Build evidence package' }).click();
  await page.waitForURL(/\/exports\/[0-9a-f-]{36}/, { timeout: 20_000 });
  alphaExportId = page.url().match(/exports\/([0-9a-f-]{36})/)[1];
  await page.getByText('Package ready').waitFor({ timeout: 30_000 });
  const [download] = await Promise.all([page.waitForEvent('download', { timeout: 20_000 }), page.getByRole('link', { name: 'Download package' }).click()]);
  const zip = path.join(work, 'alpha-package.zip');
  await download.saveAs(zip);
  const { dir, run } = verifyPackage(zip, S.orgs.alpha.anchor);
  assert.equal(run.status, 0, `the package verify tool failed:\n${run.stdout}\n${run.stderr}`);
  console.log(`# alpha package: verify tool ran ${run.stdout.split('\n').filter((l) => l.trim()).length} checks, exit 0`);
  assert.ok(!/bravo/i.test(allText(dir)), 'the package holds nothing from the other organization');
  assert.deepEqual(await page.evaluate(() => window.__csp), [], 'the page security policy was never violated');
  assert.deepEqual(problems, []);
  await ctx.close();
});

test('a download link is single use', async () => {
  const { ctx, page } = await newPage();
  await asPerson('alice');
  await signIn(page, `/exports/${alphaExportId}`);
  await page.waitForURL(`**/exports/${alphaExportId}`, { timeout: 20_000 });
  await seen(page, 'export page', () => page.getByText(/used or expired|Package ready/).first().waitFor({ timeout: 20_000 }));
  assert.ok(await page.getByText('This download link was used or expired').count() > 0, 'the first download spent the link');
  await ctx.close();
});

test('a second organization sees none of the first one\'s data, in the dashboard or through the API', async () => {
  const { ctx, page, problems } = await newPage();
  await asPerson('bob');
  await signIn(page, '/evidence');
  await page.waitForURL('**/evidence', { timeout: 20_000 });
  await lookup(page, S.contact); // the same phone number is a contact of both organizations
  await seen(page, 'lookup in bravo', () => page.getByRole('heading', { name: /Records for .* in bravo/ }).waitFor({ timeout: 20_000 }));
  const text = await page.locator('main').innerText();
  assert.ok(/bravo Brand/.test(text) && !/alpha/i.test(text), 'only this organization\'s records');

  const peek = await ctx.request.get(`${S.edge}/v1/exports/${alphaExportId}`);
  assert.ok([403, 404].includes(peek.status()), `another organization's package is not readable (got ${peek.status()})`);
  assert.ok(!/alpha/i.test(await peek.text()));
  for (const p of ['/v1/brands', '/v1/sources', '/v1/members', '/v1/audit']) {
    const r = await ctx.request.get(`${S.edge}${p}`);
    assert.ok(!/alpha|alice/i.test(await r.text()), `${p} leaks nothing from the first organization`);
  }

  await page.getByRole('button', { name: 'Build evidence package' }).click();
  await page.waitForURL(/\/exports\/[0-9a-f-]{36}/, { timeout: 20_000 });
  await page.getByText('Package ready').waitFor({ timeout: 30_000 });
  const [download] = await Promise.all([page.waitForEvent('download', { timeout: 20_000 }), page.getByRole('link', { name: 'Download package' }).click()]);
  const zip = path.join(work, 'bravo-package.zip');
  await download.saveAs(zip);
  const { dir, run } = verifyPackage(zip, S.orgs.bravo.anchor);
  assert.equal(run.status, 0, `the package verify tool failed:\n${run.stdout}\n${run.stderr}`);
  console.log(`# bravo package: verify tool ran ${run.stdout.split('\n').filter((l) => l.trim()).length} checks, exit 0`);
  assert.ok(!/alpha/i.test(allText(dir)), 'the second organization\'s package holds nothing from the first');
  assert.deepEqual(problems, []);
  await ctx.close();
});

test('sign-out clears the cookie, ends the stored session and the issuer\'s session, and the API refuses the browser again', async () => {
  const { ctx, page } = await newPage();
  await asPerson('alice');
  await signIn(page, '/');
  await page.waitForURL(`${S.edge}/`, { timeout: 20_000 });
  assert.equal((await ctx.request.get(`${S.edge}/v1/org`)).status(), 200);
  assert.equal((await ctx.request.get(`${S.edge}/auth/logout`)).status(), 405, 'a followed link cannot sign anyone out');
  assert.ok((await ctx.cookies()).find((c) => c.name === SESSION), 'and it did not');
  await page.locator('button.who').click({ timeout: 20_000 });
  await page.getByRole('button', { name: 'Sign out' }).first().click();
  await page.waitForURL('**/sign-in');
  assert.equal((await ctx.cookies()).find((c) => c.name === SESSION), undefined);
  const after = await ctx.request.get(`${S.edge}/v1/org`);
  assert.equal(after.status(), 401);
  assert.ok((await stubLog()).some((e) => e.route === 'logout'), 'the issuer was told to end its session');
  await ctx.close();
});

test('a sign-in with no second factor is explained by the dashboard; an account with no organization says so; a refusal returns to sign-in', async () => {
  let c = await newPage();
  await asPerson('alice', { amr: ['pwd'] });
  await signIn(c.page, '/');
  await c.page.getByRole('heading', { name: 'Your sign-in needs a second factor' }).waitFor({ timeout: 20_000 });
  await c.ctx.close();

  c = await newPage();
  await asPerson('alice', { method: 'MagicAuth' }); // a magic link is not a second factor, whatever else the token says
  await signIn(c.page, '/');
  await c.page.getByRole('heading', { name: 'Your sign-in needs a second factor' }).waitFor({ timeout: 20_000 });
  await c.ctx.close();

  c = await newPage();
  await asPerson('dave');
  await signIn(c.page, '/');
  await c.page.getByRole('heading', { name: 'Your account is not a member of any organization' }).waitFor({ timeout: 20_000 });
  await c.ctx.close();

  c = await newPage();
  await fetch(`${S.stub}/__stub/persona`, { method: 'POST', body: 'null' }); // nobody signs in: the issuer answers with a refusal
  await signIn(c.page, '/');
  await c.page.waitForURL('**/sign-in', { timeout: 20_000 });
  await c.ctx.close();
});

test('the edge refuses a forged callback and a state-changing call from another origin', async () => {
  const { ctx } = await newPage();
  const forged = await ctx.request.get(`${S.edge}/auth/callback?code=x&state=forged`, { maxRedirects: 0 });
  assert.equal(forged.status(), 400);
  assert.equal((await ctx.cookies()).find((c) => c.name === SESSION), undefined);
  const { ctx: c2, page } = await newPage();
  await asPerson('alice');
  await signIn(page, '/');
  await page.waitForURL(`${S.edge}/`, { timeout: 20_000 });
  const cross = await c2.request.post(`${S.edge}/v1/brands`, { data: { display_name: 'x' }, headers: { origin: 'https://evil.example' } });
  assert.equal(cross.status(), 403);
  assert.equal((await cross.json()).error, 'origin_refused');
  await ctx.close();
  await c2.close();
});

test('an address in the return parameter can never send the browser to another site', async () => {
  const { ctx, page } = await newPage();
  await asPerson('alice');
  await page.goto(`${S.edge}/sign-in?return=${encodeURIComponent('/\t/evil.example')}`);
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await page.waitForURL((u) => u.origin === S.edge, { timeout: 20_000 });
  await page.waitForTimeout(1500);
  assert.equal(new URL(page.url()).origin, S.edge, 'still on the portal');
  assert.ok(!/evil\.example/.test(page.url()));
  // and the page's own callback address, opened by hand with the tab trick
  await page.goto(`${S.edge}/auth/callback?return=/%09/evil.example`);
  await page.waitForTimeout(2000);
  assert.equal(new URL(page.url()).origin, S.edge, 'the callback page stays on the portal');
  await ctx.close();
});

test('a tab that still shows one organization cannot write into the one another tab chose', async () => {
  const { ctx, page } = await newPage();
  await asPerson('carol');
  await signIn(page, '/');
  await page.waitForURL('**/choose-org', { timeout: 20_000 });
  const alpha = S.orgs.alpha.org_id; const bravo = S.orgs.bravo.org_id;
  const origin = { origin: S.edge };
  const pick = (org) => ctx.request.post(`${S.edge}/v1/session/org`, { data: { org_id: org }, headers: origin });
  assert.equal((await pick(alpha)).status(), 200);
  const write = (org) => ctx.request.post(`${S.edge}/v1/brands`, { data: { display_name: 'Race Test' }, headers: { ...origin, 'x-cv-org': org } });
  assert.equal((await ctx.request.get(`${S.edge}/v1/org`, { headers: { 'x-cv-org': alpha } })).status(), 200);
  assert.equal((await pick(bravo)).status(), 200, 'the other tab chooses organization two');
  const stale = await write(alpha);
  assert.equal(stale.status(), 409);
  assert.equal((await stale.json()).error, 'org_mismatch');
  assert.equal((await ctx.request.post(`${S.edge}/v1/brands`, { data: { display_name: 'x' }, headers: origin })).status(), 409, 'a call that names no organization is refused too');
  await ctx.close();
});

test('an invitation cannot be accepted by someone whose verified address is a different one', async () => {
  const { ctx, page } = await newPage();
  await asPerson('dave');
  await signIn(page, '/');
  await page.getByRole('heading', { name: /not a member of any organization/ }).waitFor({ timeout: 20_000 });
  const accept = await ctx.request.post(`${S.edge}/v1/invites/${S.invite.token}:accept`, { headers: { origin: S.edge }, data: {} });
  assert.equal(accept.status(), 403);
  assert.equal((await accept.json()).error, 'invite_wrong_account');
  await ctx.close();
});

test('an invitation is accepted on the address the provider verified, which the token itself does not carry', async () => {
  const { ctx, page } = await newPage();
  const view = await ctx.request.get(`${S.edge}/v1/invites/${S.invite.token}`);
  assert.equal(view.status(), 200, 'the invitation can be read before signing in');
  await asPerson('erin');
  await signIn(page, '/');
  await page.getByRole('heading', { name: /not a member of any organization/ }).waitFor({ timeout: 20_000 });
  const noMember = await ctx.request.get(`${S.edge}/v1/session`);
  assert.deepEqual((await noMember.json()).items, []);
  assert.equal((await noMember.json()).user.email, 'erin@alpha.test', 'the address shown comes from the provider answer, not "null"');
  const accept = await ctx.request.post(`${S.edge}/v1/invites/${S.invite.token}:accept`, { headers: { origin: S.edge }, data: {} });
  assert.equal(accept.status(), 200, await accept.text());
  const body = await accept.json();
  assert.equal(body.org_id, S.invite.org_id);
  assert.equal(body.role, 'compliance_viewer');
  const after = await (await ctx.request.get(`${S.edge}/v1/session`)).json();
  assert.equal(after.items.length, 1);
  await ctx.close();
});

test('the overview shows each organization\'s own open alarms by role: what happened, since when and the next action; usage alarms never', async () => {
  let c = await newPage();
  await asPerson('alice');
  await signIn(c.page, '/');
  await c.page.waitForURL(`${S.edge}/`, { timeout: 20_000 });
  const region = c.page.getByRole('region', { name: 'Open alarms' });
  await region.waitFor({ timeout: 20_000 });
  const text = await region.innerText();
  assert.match(text, /2 stops were put back after a restore without the confirmation behind them/);
  assert.match(text, /Review them on the evidence lookup page/);
  assert.match(text, /two live subscriptions/);
  assert.match(text, /Cancel the extra one in the billing portal/);
  assert.match(text, /5,200 records were revealed/);
  assert.match(text, /A sending account was refused five times/);
  assert.equal((text.match(/Since /g) ?? []).length, 4, 'four open; the cleared one and the usage one are not shown');
  assert.ok(!/usage|link address/i.test(text));
  assert.equal(await c.page.getByRole('button', { name: /acknowledge|dismiss/i }).count(), 0, 'nothing to acknowledge');
  await c.ctx.close();
  c = await newPage();
  await asPerson('bob');
  await signIn(c.page, '/');
  await c.page.waitForURL(`${S.edge}/`, { timeout: 20_000 });
  const bobText = await c.page.getByRole('region', { name: 'Open alarms' }).innerText();
  assert.match(bobText, /1 stop was put back/);
  assert.match(bobText, /two live subscriptions/);
  assert.ok(!/5,200|sending account/.test(bobText), 'the other organization\'s alarms never cross');
  await c.ctx.close();
  // a compliance viewer (carol in bravo) sees the restore alarm and not the subscription one, straight from the API
  c = await newPage();
  await asPerson('carol');
  await signIn(c.page, '/');
  await c.page.waitForURL('**/choose-org', { timeout: 20_000 });
  const pick = await c.ctx.request.post(`${S.edge}/v1/session/org`, { headers: { origin: S.edge }, data: { org_id: S.orgs.bravo.org_id } });
  assert.equal(pick.status(), 200);
  const health = await (await c.ctx.request.get(`${S.edge}/v1/health`, { headers: { 'x-cv-org': S.orgs.bravo.org_id } })).json();
  assert.deepEqual(health.alarms.map((a) => a.name), ['restore.stops_unconfirmed']);
  assert.equal(health.alarms[0].count, 1);
  await c.ctx.close();
});

test('company single sign-on: the operator bound it, an admin proves it by signing in through it, may then require it, and nobody else gets in', async () => {
  const CONN = S.sso.connection; const WOS = S.sso.workos_org;
  const OTHER = 'conn_01HZZZZZZZZZZZZZZZZZZZZZZZ'; const WOS_OTHER = 'org_01HZZZZZZZZZZZZZZZZZZZZZZZ';
  const alpha = S.orgs.alpha.org_id;
  const headers = { origin: S.edge };
  const org = (extra = {}) => ({ headers: { ...headers, 'x-cv-org': alpha, ...extra } });
  // 1. the admin (passkey) sees it bound but unproved; there is no field to type a connection into, and it cannot be required yet
  let c = await newPage();
  await asPerson('alice');
  await signIn(c.page, '/');
  await c.page.waitForURL(`${S.edge}/`, { timeout: 20_000 });
  assert.deepEqual((await (await c.ctx.request.get(`${S.edge}/v1/org`, org())).json()).sso, { connected: true, connection_id: null, required: false, verified: false });
  assert.equal((await c.ctx.request.put(`${S.edge}/v1/org/sso`, { ...org(), data: { connection_id: CONN, require_sso: false } })).status(), 422, 'an admin cannot type a connection');
  assert.equal((await c.ctx.request.put(`${S.edge}/v1/org/sso`, { ...org(), data: { require_sso: true } })).status(), 422, 'unproved cannot be required');
  await c.ctx.close();
  // 2. a sign-in through another company's connection, or the right connection of another company's account, does not enter
  for (const persona of [{ method: 'SSO', connection: OTHER, workosOrg: WOS }, { method: 'SSO', connection: CONN, workosOrg: WOS_OTHER }]) {
    c = await newPage();
    await asPerson('alice', persona);
    await signIn(c.page, '/');
    await c.page.getByRole('heading', { name: /not a member of any organization/ }).waitFor({ timeout: 20_000 });
    const refused = await c.ctx.request.post(`${S.edge}/v1/session/org`, { headers, data: { org_id: alpha } });
    assert.equal(refused.status(), 403);
    assert.equal((await refused.json()).error, 'sso_not_connected');
    await c.ctx.close();
  }
  // 3. SSO with no connection reported, and a personal Google account, are not second factors at all
  for (const persona of [{ method: 'SSO' }, { method: 'SSO', connection: CONN }, { method: 'GoogleOAuth' }]) {
    c = await newPage();
    await asPerson('alice', persona);
    await signIn(c.page, '/');
    await c.page.getByRole('heading', { name: 'Your sign-in needs a second factor' }).waitFor({ timeout: 20_000 });
    await c.ctx.close();
  }
  // 4. the admin signs in through the bound connection: that proves it, and now the requirement can be turned on
  c = await newPage();
  await asPerson('alice', { method: 'SSO', connection: CONN, workosOrg: WOS });
  await signIn(c.page, '/');
  await c.page.waitForURL(`${S.edge}/`, { timeout: 20_000 });
  assert.deepEqual((await (await c.ctx.request.get(`${S.edge}/v1/org`, org())).json()).sso, { connected: true, connection_id: CONN, required: false, verified: true });
  assert.equal((await c.ctx.request.put(`${S.edge}/v1/org/sso`, { ...org(), data: { require_sso: true } })).status(), 200);
  await c.ctx.close();
  // 5. required: the passkey is refused at sign-in
  c = await newPage();
  await asPerson('alice');
  await signIn(c.page, '/');
  const pk = await c.ctx.request.post(`${S.edge}/v1/session/org`, { headers, data: { org_id: alpha } });
  assert.equal(pk.status(), 403);
  assert.equal((await pk.json()).error, 'sso_required');
  await c.ctx.close();
});
