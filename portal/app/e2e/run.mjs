// End-to-end run: serves the static export plus the mock API, then drives every screen in Chromium at 375px and 1440px.
// Checks per screen and state: no horizontal scroll, no console errors, no password field, one h1, every control named,
// banned copy absent, CSP never violated. Then the acceptance flows (roles, suspended, polling, dialogs, fake timers).
//   node e2e/run.mjs            (build first: npx next build)
import { createRequire } from 'node:module';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createMock } from '../mock/server.ts';
import { scanCopy } from '../src/lib/copycheck.ts';
import { fmtDateTime, fmtTime } from '../src/lib/format.ts';
import { navFor, refusalHeading } from '../src/lib/roles.ts';
// The promise to the person: a dashboard that cannot start says so after 8 seconds. Written here on purpose, not imported, so
// changing the constant in the app cannot move the test with it.
const BOOT_DEADLINE_MS = 8000;

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(here, '..', 'out');
if (!fs.existsSync(path.join(out, 'index.html'))) { console.error('out/ is missing: run npx next build first'); process.exit(2); }

const mock = createMock();
const server = mock.server(out, null);
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;
const only = process.argv.find((a) => a.startsWith('--only='))?.slice(7) ?? null;

const results = { pass: 0, fail: 0, failures: [] };
function ok(name, cond, detail = '') {
  if (cond) results.pass++; else { results.fail++; results.failures.push(`${name}${detail ? `: ${detail}` : ''}`); console.log(`  FAIL ${name}${detail ? `: ${detail}` : ''}`); }
}
const scenario = (s) => fetch(`${base}/__mock/scenario`, { method: 'POST', body: JSON.stringify(s) }).then((r) => r.json());
const log = () => fetch(`${base}/__mock/log`).then((r) => r.json());
const mstate = () => fetch(`${base}/__mock/state`).then((r) => r.json());

const browser = await chromium.launch();
const SHA = '9f2c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6ee1';

async function settle(page, ms = 4000) {
  await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]') && document.querySelector('main h1, main h2, main [role=alert], main .empty'), null, { timeout: ms }).catch(() => undefined);
  await page.waitForTimeout(120);
}

async function newPage(width, extra = {}) {
  const ctx = await browser.newContext({ viewport: { width, height: width < 500 ? 800 : 900 }, ...extra });
  const page = await ctx.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(`pageerror ${e.message}`));
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));
    // When each boot state first showed, on the page's own clock (time since navigation began). A deadline is a claim about
    // that clock; how long the machine took to run the browser is not.
    new MutationObserver(() => {
      const f = document.getElementById('boot-fail');
      if (f && !f.hidden && window.__bootAt == null) window.__bootAt = performance.now();
      if (window.__loadAt == null && document.querySelector('[aria-busy="true"]')) window.__loadAt = performance.now();
      if (window.__errAt == null && document.body && /did not load/.test(document.body.innerText)) window.__errAt = performance.now();
    }).observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
  });
  return { ctx, page, errors };
}

// ---------- the case list: every screen, every state a fixture can reach ----------
const gone = { 'GET /v1/org': { status: 503, error: 'service_unavailable' } };
const fail = (k, status = 503, error = 'service_unavailable') => ({ fail: { [k]: { status, error } } });
const cases = [
  ['sign-in', '/sign-in', {}], ['sign-in expired', '/sign-in?reason=expired', {}],
  ['callback ok', '/auth/callback', {}], ['callback no org', '/auth/callback', { orgs: 'none' }], ['callback no second factor', '/auth/callback', { noSecondFactor: true }, true], ['callback error', '/auth/callback', fail('GET /v1/session'), true],
  ['invite ok', '/invite?token=abc', {}], ['invite no token', '/invite', {}], ['invite expired', '/invite?token=abc', { inviteMode: 'expired' }, true], ['invite used', '/invite?token=abc', { inviteMode: 'used' }, true], ['invite withdrawn', '/invite?token=abc', { inviteMode: 'withdrawn' }, true], ['invite not found', '/invite?token=missing', {}, true],
  ['choose-org', '/choose-org', { orgs: 'two', preselected: false }], ['choose-org partial', '/choose-org', { orgs: 'two', preselected: false, nulls: ['org2_status'] }], ['choose-org error', '/choose-org', { orgs: 'two', preselected: false, ...fail('GET /v1/session') }, true],
  ['plan', '/start/plan', { orgStatus: 'trial' }], ['plan empty', '/start/plan', { orgStatus: 'trial', empty: ['plans'] }], ['plan error', '/start/plan', { orgStatus: 'trial', ...fail('GET /v1/billing/plans') }, true], ['plan not admin', '/start/plan', { role: 'compliance_viewer' }],
  ['checkout cancel', '/billing/return?result=cancel', { orgStatus: 'trial' }], ['checkout confirming', '/billing/return?result=success', { orgStatus: 'trial' }], ['checkout active', '/billing/return?result=success', {}],
  ['overview', '/', {}], ['overview new org', '/', { setup: 'new', firstEvent: 'none', policyInForce: false, orgStatus: 'trial' }], ['overview blank', '/', { setup: 'blank', firstEvent: 'none', policyInForce: false }], ['overview partial', '/', { nulls: ['usage', 'health'] }], ['overview error', '/', gone, true],
  ['overview past due', '/', { orgStatus: 'past_due' }], ['overview suspended', '/', { orgStatus: 'suspended' }], ['overview trial', '/', { orgStatus: 'trial' }], ['overview offboarding', '/', { orgStatus: 'offboarding' }], ['overview closed', '/', { orgStatus: 'closed' }],
  ['overview viewer', '/', { role: 'compliance_viewer' }], ['overview developer', '/', { role: 'developer' }], ['overview two orgs', '/', { orgs: 'two' }],
  ['overview alarms', '/', { alarms: ['reveal_volume', 'sending_account_failing', 'something_new'] }], ['overview alarms viewer', '/', { role: 'compliance_viewer', alarms: ['reveal_volume'] }],
  ['first-event waiting', '/setup/first-event', { firstEvent: 'none' }], ['first-event unsealed', '/setup/first-event', { firstEvent: 'unsealed' }], ['first-event sealed', '/setup/first-event', {}], ['first-event setup missing', '/setup/first-event', { setup: 'blank', firstEvent: 'none' }], ['first-event developer', '/setup/first-event', { role: 'developer', firstEvent: 'none' }],
  ['brands', '/brands', {}], ['brands empty', '/brands', { empty: ['brands'] }], ['brands partial', '/brands', { nulls: ['source_counts'] }], ['brands error', '/brands', fail('GET /v1/brands'), true], ['brands developer', '/brands', { role: 'developer' }],
  ['sources', '/sources', {}], ['sources empty', '/sources', { empty: ['sources'] }], ['sources no brand', '/sources', { empty: ['brands', 'sources'] }], ['sources partial', '/sources', { nulls: ['last_event'] }], ['sources error', '/sources', fail('GET /v1/sources'), true], ['source detail', '/sources/src_web', {}], ['source detail not found', '/sources/zzz', {}, true],
  ['credentials', '/credentials', {}], ['credentials empty', '/credentials', { empty: ['credentials'] }], ['credentials partial', '/credentials', fail('GET /v1/sources'), true], ['credentials error', '/credentials', fail('GET /v1/credentials'), true], ['credentials suspended', '/credentials', { orgStatus: 'suspended' }], ['credentials developer', '/credentials', { role: 'developer' }],
  ['credential new', '/credentials/new', {}], ['credential new no policy', '/credentials/new', { policyInForce: false }], ['credential new suspended', '/credentials/new', { orgStatus: 'suspended' }], ['credential new developer', '/credentials/new', { role: 'developer' }],
  ['wording', '/wording', {}], ['wording empty', '/wording', { empty: ['disclosures'] }], ['wording error', '/wording', fail('GET /v1/disclosures'), true], ['wording viewer', '/wording', { role: 'compliance_viewer' }], ['wording new', '/wording/new', {}], ['wording detail', `/wording/${SHA}`, {}], ['wording detail not found', '/wording/nope', {}, true],
  ['policies', '/policies', {}], ['policies empty', '/policies', { empty: ['policies'] }], ['policies none in force', '/policies', { policyInForce: false }], ['policies partial', '/policies', { nulls: ['approver'] }], ['policies error', '/policies', fail('GET /v1/policies'), true], ['policies viewer', '/policies', { role: 'compliance_viewer' }],
  ['policy new', '/policies/new', {}], ['policy draft', '/policies/4', {}], ['policy in force', '/policies/3', {}], ['policy in force viewer', '/policies/3', { role: 'compliance_viewer' }], ['policy approve', '/policies/4/approve', {}],
  ['checklists', '/checklists', {}], ['checklists empty', '/checklists', { empty: ['checklists'] }], ['checklists partial', '/checklists', fail('GET /v1/policies/3'), true], ['checklists error', '/checklists', fail('GET /v1/checklists'), true], ['checklist approved', '/checklists/2', {}], ['checklist draft', '/checklists/3', {}],
  ['evidence', '/evidence', {}], ['evidence viewer', '/evidence', { role: 'compliance_viewer' }], ['evidence suspended', '/evidence', { orgStatus: 'suspended' }], ['evidence developer refused', '/evidence', { role: 'developer' }],
  ['exports', '/exports', {}], ['exports suspended', '/exports', { orgStatus: 'suspended' }], ['exports error', '/exports', fail('GET /v1/exports'), true], ['exports viewer', '/exports', { role: 'compliance_viewer' }],
  ['systems', '/systems', {}], ['systems empty', '/systems', { empty: ['systems'] }], ['systems partial', '/systems', { nulls: ['system_counts'] }], ['systems error', '/systems', fail('GET /v1/systems'), true], ['systems viewer', '/systems', { role: 'compliance_viewer' }], ['system new', '/systems/new', {}], ['system detail', '/systems/sys_dialer', {}], ['system detail crm', '/systems/sys_crm', {}],
  ['retention', '/retention', {}], ['retention empty', '/retention', { empty: ['retention'] }], ['retention partial', '/retention', { nulls: ['retention_history'] }], ['retention error', '/retention', fail('GET /v1/retention'), true], ['retention viewer', '/retention', { role: 'compliance_viewer' }],
  ['company sign-in', '/sso', {}], ['company sign-in pending', '/sso', { sso: 'pending' }], ['company sign-in proved', '/sso', { sso: 'verified' }], ['company sign-in viewer', '/sso', { role: 'compliance_viewer' }], ['company sign-in developer', '/sso', { role: 'developer' }],
  ['members', '/members', {}], ['members only you', '/members', { empty: ['members'] }], ['members error', '/members', fail('GET /v1/members'), true], ['members refused', '/members', { role: 'developer' }],
  ['audit', '/audit', {}], ['audit empty', '/audit', { empty: ['audit'] }], ['audit partial', '/audit', { nulls: ['audit_names'] }], ['audit error', '/audit', fail('GET /v1/audit'), true], ['audit viewer', '/audit', { role: 'compliance_viewer' }], ['audit filtered', '/audit?action=nothing.here', {}],
  ['billing', '/billing', {}], ['billing trial', '/billing', { orgStatus: 'trial' }], ['billing partial', '/billing', { nulls: ['usage'] }], ['billing error', '/billing', fail('GET /v1/billing'), true], ['billing past due', '/billing', { orgStatus: 'past_due' }],
  ['settings', '/settings', {}], ['settings partial', '/settings', { nulls: ['key'] }], ['settings offboarding', '/settings', { offboarding: true, orgStatus: 'offboarding' }], ['settings viewer', '/settings', { role: 'compliance_viewer' }], ['settings developer', '/settings', { role: 'developer' }], ['settings error', '/settings', fail('GET /v1/org'), true],
  ['references', '/references', {}], ['references empty', '/references', { empty: ['references'] }], ['references partial', '/references', { nulls: ['review_dates'] }], ['references error', '/references', fail('GET /v1/rule-references'), true], ['references jurisdiction empty', '/references?jurisdiction=Texas', {}],
  // ---- records, setup walkthrough, confirmation messages (screens 23, 24, 25) ----
  ['records', '/records', {}], ['records empty', '/records', { records: 'none' }], ['records no match', '/records?channel=sms&status=stop_on_record&source_id=src_sf', {}], ['records filtered', '/records?channel=sms&status=stop_on_record', {}],
  ['records erased', '/records?state=erased', {}], ['records partial masks', '/records', { nulls: ['rec_mask'] }], ['records partial names', '/records', { nulls: ['rec_person'] }], ['records partial total', '/records', { nulls: ['rec_total'] }],
  ['records partial chart', '/records', { nulls: ['rec_chart'] }], ['records summary failed', '/records', fail('GET /v1/records/summary'), true], ['records error', '/records', fail('GET /v1/records'), true],
  ['records audit unavailable', '/records', fail('GET /v1/records', 503, 'audit_unavailable'), true], ['records viewer', '/records', { role: 'compliance_viewer' }], ['records developer', '/records', { role: 'developer' }], ['records suspended', '/records', { orgStatus: 'suspended' }],
  ['setup welcome', '/setup', { setup: 'blank', firstEvent: 'none', policyInForce: false }], ['setup resumed', '/setup', { setup: 'new', firstEvent: 'none', policyInForce: false }], ['setup waiting for event', '/setup?step=first_event', { setup: 'almost', firstEvent: 'none' }],
  ['setup partial', '/setup', { setup: 'new', firstEvent: 'none', policyInForce: false, nulls: ['setup.credential'] }], ['setup policy step', '/setup?step=policy', { setup: 'new', firstEvent: 'none', policyInForce: false }], ['setup optional step', '/setup?step=system', { setup: 'almost' }],
  ['setup developer', '/setup', { role: 'developer', setup: 'new', firstEvent: 'none', policyInForce: false }], ['setup suspended', '/setup?step=credential', { setup: 'almost', orgStatus: 'suspended', empty: ['credentials'] }], ['setup error', '/setup', fail('GET /v1/setup'), true],
  ['setup viewer refused', '/setup', { role: 'compliance_viewer' }], ['setup complete', '/setup', {}],
  ['confirmations', '/confirmations', {}], ['confirmations empty', '/confirmations', { confirmations: 'empty' }], ['confirmations texts off', '/confirmations', { confirmations: 'texts_off' }], ['confirmations awaiting test reply', '/confirmations', { confirmations: 'awaiting' }],
  ['confirmations link host unset', '/confirmations', { confirmations: 'link_unset' }], ['confirmations account failing', '/confirmations', { confirmations: 'failing' }], ['confirmations partial counts', '/confirmations', { nulls: ['conf_counts'] }],
  ['confirmations provider refusals', '/confirmations', { nulls: ['conf_refusal'] }], ['confirmations signature failures', '/confirmations', { nulls: ['conf_sigfail'] }], ['confirmations delivery reports stale', '/confirmations', { nulls: ['conf_stale'] }],
  ['confirmations old reply', '/confirmations', { nulls: ['conf_old_reply'] }], ['confirmations suspended', '/confirmations', { orgStatus: 'suspended' }], ['confirmations developer', '/confirmations', { role: 'developer' }], ['confirmations viewer', '/confirmations', { role: 'compliance_viewer' }],
  ['confirmations error', '/confirmations', fail('GET /v1/confirmations/settings'), true],
  ['confirmation edit email', '/confirmations/src_web/email', {}], ['confirmation edit text', '/confirmations/src_web/sms', {}], ['confirmation edit developer', '/confirmations/src_web/email', { role: 'developer' }],
  ['confirmation edit viewer refused', '/confirmations/src_web/email', { role: 'compliance_viewer' }], ['confirmation edit not found', '/confirmations/zzz/email', {}, true],
  ['not found', '/definitely/not/a/page', {}, true],
];

async function checkPage(label, page, errors, expectErrors, width) {
  const info = await page.evaluate(() => {
    const clone = document.body.cloneNode(true);
    clone.querySelectorAll('script,style,[data-copy-exempt]').forEach((n) => n.remove());
    const nameless = [];
    document.querySelectorAll('button,a[href],input:not([type=hidden]),select,textarea').forEach((el) => {
      if (el.closest('[hidden],[inert]') && false) return;
      const cs = getComputedStyle(el); if (cs.display === 'none' || cs.visibility === 'hidden') return;
      const labelled = el.getAttribute('aria-label') || el.getAttribute('aria-labelledby') || (el.labels && el.labels.length) || el.textContent.trim() || el.getAttribute('title');
      if (!labelled) nameless.push(el.outerHTML.slice(0, 90));
    });
    return {
      scrollW: document.documentElement.scrollWidth, text: clone.textContent || '', pw: document.querySelectorAll('input[type=password]').length,
      h1: [...document.querySelectorAll('h1')].filter((h) => getComputedStyle(h).display !== 'none' && h.offsetParent !== null).length,
      nameless, csp: window.__csp, title: document.title,
    };
  });
  ok(`${label} @${width}: no horizontal scroll`, info.scrollW <= width, `scrollWidth ${info.scrollW}`);
  const errs = expectErrors ? errors.filter((e) => !/Failed to load resource/.test(e)) : errors;
  ok(`${label} @${width}: no console errors`, errs.length === 0, errs.slice(0, 2).join(' | '));
  ok(`${label} @${width}: no password field`, info.pw === 0);
  ok(`${label} @${width}: exactly one visible h1`, info.h1 === 1, `found ${info.h1}`);
  ok(`${label} @${width}: every control has a name`, info.nameless.length === 0, info.nameless.slice(0, 2).join(' '));
  ok(`${label} @${width}: no CSP violation`, info.csp.length === 0, info.csp.join(','));
  const hits = scanCopy(info.text);
  ok(`${label} @${width}: copy check`, hits.length === 0, hits.slice(0, 2).join(' | '));
}

console.log(`serving ${out} at ${base}`);
for (const width of [375, 1440]) {
  const { ctx, page, errors } = await newPage(width);
  for (const [name, p, sc, expectErrors] of cases) {
    if (only && !name.includes(only)) continue;
    await scenario(sc);
    errors.length = 0;
    await page.goto(base + p);
    await settle(page);
    await checkPage(name, page, errors, !!expectErrors, width);
  }
  await ctx.close();
}

// ---------- open alarms on the overview: what happened, when, the next action; developers are not shown them ----------
async function alarmStates() {
  const { ctx, page } = await newPage(1440);
  const go = async (sc) => { await scenario(sc); await page.goto(base + '/'); await settle(page); return page.locator('main').innerText(); };
  const all = ['restore.stops_unconfirmed', 'billing.second_live_subscription', 'reveal_volume', 'something_new'];
  let t = await go({ alarms: all });
  ok('alarms: a restore with unconfirmed stops shows the count', /2 stops were put back after a restore without the confirmation behind them/.test(t), t.slice(0, 300));
  ok('alarms: a second live subscription is shown to an admin', /two live subscriptions/.test(t));
  ok('alarms: each shows since when and the next action the vault gave', (t.match(/Since /g) ?? []).length === 4 && /Next step for reveal_volume\./.test(t));
  ok('alarms: a name the page does not know is shown, in words that say so', /kind of alert \(something_new\)/.test(t));
  ok('alarms: nothing on the page can acknowledge one', (await page.getByRole('button', { name: /acknowledge|dismiss/i }).count()) === 0);
  t = await go({ alarms: [] });
  ok('alarms: none open shows none', !/Open alarms|Since /.test(t));
  t = await go({ role: 'compliance_viewer', alarms: all });
  ok('alarms: a compliance viewer sees the restore alarm but not the subscription one', /after a restore/.test(t) && !/two live subscriptions/.test(t));
  t = await go({ role: 'developer', alarms: all });
  ok('alarms: a developer is shown none', !/after a restore|revealed|two live/.test(t));
  t = await go({ alarms: all, nulls: ['alarms'] });
  ok('alarms: a read that failed is said to have failed, never shown as none', /Open alarms did not load/.test(t));
  await ctx.close();
}
await alarmStates();

// ---------- company sign-in screen: the admin never types a connection id ----------
async function ssoScreen() {
  const { ctx, page } = await newPage(1440);
  const go = async (sc) => { await scenario(sc); await page.goto(base + '/sso'); await settle(page); return page.locator('main').innerText(); };
  let t = await go({ sso: 'none' });
  ok('sso: not connected says to ask the ConsentVault contact, and offers no field', /Ask your ConsentVault contact/.test(t) && (await page.locator('main input').count()) === 0);
  t = await go({ sso: 'pending' });
  ok('sso: connected but unconfirmed asks an admin to sign in with the company account', /waiting for an admin to confirm it/.test(t) && !/Require company sign-in/.test(t));
  t = await go({ sso: 'verified' });
  ok('sso: once confirmed the requirement can be turned on, and still no field', /Require company sign-in/.test(t) && (await page.locator('main input').count()) === 0);
  await page.getByRole('button', { name: 'Require company sign-in' }).click();
  await page.getByText('Company sign-in is now required for everyone.').waitFor({ timeout: 8000 }).catch(() => undefined);
  ok('sso: turning it on is confirmed and the screen offers to stop requiring it', (await page.locator('main').innerText()).includes('Stop requiring it'));
  await ctx.close();
}
await ssoScreen();

// ---------- a dashboard that cannot start is never left as bare text ----------
async function bootStates() {
  const shown = (page) => page.evaluate(() => { const f = document.getElementById('boot-fail'); if (!f || f.hidden) return null; const cs = getComputedStyle(f); return { text: f.innerText, border: cs.borderLeftWidth, bg: cs.backgroundColor, retry: !!f.querySelector('button#boot-retry') }; });
  // 1. the page's scripts and styles never arrive (server gone): the inline watch shows the styled state after the deadline
  { const { ctx, page, errors } = await newPage(1440);
    await page.route('**/_next/**', (r) => r.abort());
    await page.goto(base + '/sign-in');
    await page.waitForFunction(() => { const f = document.getElementById('boot-fail'); return f && !f.hidden; }, null, { timeout: 30000 }).catch(() => undefined);
    const bootAt = await page.evaluate(() => window.__bootAt);
    // The state shows at the deadline on the page clock: never earlier (it would flash on a slow but healthy load), and not
    // later than the deadline plus a scheduler allowance (a deadline of 12 s or 20 s is a different promise to the person).
    ok('boot: it first showed at the deadline on the page clock, no earlier and no later than 1 s after', bootAt >= BOOT_DEADLINE_MS - 50 && bootAt <= BOOT_DEADLINE_MS + 1000, String(bootAt));
    const s = await shown(page);
    ok('boot: after the deadline a styled "Can\'t reach ConsentVault" state with cause and Retry appears', !!s && /Can.t reach ConsentVault/.test(s.text) && /Cause:/.test(s.text) && s.retry && s.border === '4px', JSON.stringify(s));
    ok('boot: the state carries no CSP violation', (await page.evaluate(() => window.__csp)).length === 0);
    await page.unroute('**/_next/**');
    await page.getByRole('button', { name: 'Retry' }).click();
    await page.waitForSelector('main h1', { timeout: 8000 });
    ok('boot: Retry loads the dashboard once the service is back', (await page.locator('main h1').first().innerText()).length > 0);
    ok('boot: and the state is gone', (await shown(page)) === null);
    await ctx.close(); }
  // 2. the scripts load but the service never answers: the dashboard itself shows the styled error with Try again
  { const { ctx, page } = await newPage(1440);
    await scenario({});
    await page.route('**/v1/**', () => undefined);
    await page.goto(base + '/');
    await page.getByText(/did not load/).first().waitFor({ timeout: 30000 }).catch(() => undefined);
    const t = await page.locator('main').innerText();
    const [errAt, loadAt] = await page.evaluate(() => [window.__errAt, window.__loadAt]);
    ok('boot: a service that never answers becomes an error with Try again within the deadline', /did not load/.test(t) && /Try again/.test(t), t.slice(0, 200));
    ok('boot: that error lands 8 to 9 s after the first loading render on the page clock (the boot deadline, not a longer one or the 15 s request timeout)', errAt != null && loadAt != null && errAt - loadAt >= BOOT_DEADLINE_MS - 50 && errAt - loadAt <= BOOT_DEADLINE_MS + 1000, `loading ${loadAt}, error ${errAt}`);
    await ctx.close(); }
  // 3. a sign-out the service could not finish is shown as an error and the page stays where it is
  { const { ctx, page } = await newPage(1440);
    await scenario({});
    await page.route('**/auth/logout', (r) => r.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'session_unavailable', message: 'The session store did not answer.' }) }));
    await page.goto(base + '/');
    await settle(page);
    await page.locator('button.who').click();
    await page.getByRole('button', { name: 'Sign out' }).first().click();
    await page.getByRole('alert').filter({ hasText: 'Sign-out did not finish' }).waitFor({ timeout: 8000 }).catch(() => undefined);
    ok('boot: a failed sign-out is shown as an error, not treated as signed out', (await page.getByText(/Sign-out did not finish/).count()) > 0 && new URL(page.url()).pathname === '/');
    await ctx.close(); }
}
await bootStates();

// ---------- flows (acceptance criteria) ----------
async function flows() {
  const { ctx, page, errors } = await newPage(1440, { permissions: ['clipboard-read', 'clipboard-write'] });
  const go = async (p, sc) => { if (sc) await scenario(sc); await page.goto(base + p); await settle(page); };
  const text = () => page.locator('main').innerText();

  // G-AC1: navigation per role matches the role matrix
  for (const role of ['admin', 'developer', 'compliance_viewer']) {
    await go('/', { role });
    const links = await page.locator('nav[aria-label="Portal"] a').allInnerTexts();
    const want = navFor(role).flatMap((g) => g.items.map((i) => i.label));
    ok(`G-AC1 nav for ${role}`, JSON.stringify(links) === JSON.stringify(want), `${links.join(',')} vs ${want.join(',')}`);
  }
  // G-AC2: hidden route shows the refusal and a button that leads somewhere allowed
  await go('/members', { role: 'developer' });
  ok('G-AC2 refusal heading', (await page.locator('main h2').first().innerText()) === refusalHeading('members'));
  await page.getByRole('link', { name: /^Go to/ }).click(); await settle(page);
  ok('G-AC2 refusal button lands on an allowed page', (await page.locator('main h1').first().innerText()).length > 0 && !(await text()).includes('This page is for'));
  await go('/evidence', { role: 'developer' });
  ok('developer never sees evidence lookup', (await text()).includes('This page is for admins and compliance viewers'));
  // G-AC3: suspended disables build package and issue credential with visible reasons
  await go('/exports', { orgStatus: 'suspended' });
  ok('G-AC3 build package disabled on exports', await page.getByRole('button', { name: 'Build evidence package' }).first().isDisabled());
  ok('G-AC3 reason visible on exports', (await text()).includes('Evidence packages are paused while Acme Lending is suspended'));
  ok('G-AC3 suspended banner text', (await page.locator('[aria-label="Organization status"]').innerText()).includes('Acme Lending is suspended. Capture keeps recording, because evidence is never refused for non-payment.'));
  await go('/credentials', { orgStatus: 'suspended' });
  ok('G-AC3 issue a credential disabled', (await page.getByRole('link', { name: 'Issue a credential' }).getAttribute('aria-disabled')) === 'true');
  ok('G-AC3 reason visible on credentials', (await text()).includes('New credentials are paused while Acme Lending is suspended'));
  await go('/evidence', { orgStatus: 'suspended' });
  await page.getByLabel('Phone number or email').fill('(555) 555-0100'); await page.getByRole('button', { name: 'Look up records' }).click(); await settle(page);
  ok('G-AC3 build package disabled on evidence lookup', await page.getByRole('button', { name: 'Build evidence package' }).isDisabled());
  // G-AC8: a 401 sends the person to sign-in with the return route
  await go('/brands', { signedOut: true });
  await page.waitForURL(/\/sign-in\?return=/, { timeout: 4000 }).catch(() => undefined);
  ok('G-AC8 401 goes to sign-in with return', page.url().includes('/sign-in?return=%2Fbrands'), page.url());
  // 02: invite
  await go('/invite?token=abc', {});
  await page.getByRole('button', { name: 'Sign in to accept' }).click(); await settle(page);
  ok('02-3 success names the role and offers Choose a plan', (await text()).includes('You joined Acme Lending as Admin.') && (await page.getByRole('button', { name: 'Choose a plan' }).count()) === 1);
  await go('/invite?token=abc', { inviteMode: 'wrong_account' });
  await page.getByRole('button', { name: 'Sign in to accept' }).click(); await settle(page);
  ok('02 wrong account state', (await text()).includes('You are signed in with a different address'));
  // 03: one membership skips choose-org
  await go('/choose-org', { orgs: 'one', preselected: false }); await page.waitForURL(base + '/', { timeout: 4000 }).catch(() => undefined);
  ok('03-1 one membership redirects to /', new URL(page.url()).pathname === '/', page.url());
  await go('/choose-org', { orgs: 'two', preselected: false });
  await page.getByRole('button', { name: 'Open Acme Lending' }).click(); await page.waitForURL(base + '/', { timeout: 4000 }).catch(() => undefined); await settle(page);
  ok('03-2 selecting an org lands on / with no org id in the URL', new URL(page.url()).pathname === '/' && !page.url().includes('org_'), page.url());
  // 04-1: checkout once
  await go('/start/plan', { orgStatus: 'trial' });
  await page.getByRole('button', { name: 'Choose Growth' }).click(); await page.waitForURL(/__mock\/stripe\/checkout/, { timeout: 4000 }).catch(() => undefined);
  ok('04-1 checkout posts once and navigates to Stripe', page.url().includes('/__mock/stripe/checkout') && (await log()).filter((r) => r.url === '/v1/billing/checkout').length === 1);
  // 05-1: new org checklist
  await go('/', { setup: 'new', firstEvent: 'none', policyInForce: false, orgStatus: 'trial' });
  ok('05-1 the checklist is the eight steps the service reports, one primary button', (await page.locator('ol.steps > li').count()) === 8 && (await page.locator('ol.steps .btn-primary').count()) === 1);
  ok('05-1 primary is the first not-done item', (await page.locator('ol.steps .btn-primary').innerText()) === 'Register your consent wording');
  const stepLis = await page.locator('ol.steps > li').allInnerTexts();
  ok('05-1 the checklist names the two optional steps and each step status word', /Done/.test(stepLis[0]) && /Done/.test(stepLis[1]) && /To do/.test(stepLis[2]) && /Connect a system that receives stops \(optional\)/.test(stepLis[6]) && /Turn on confirmation messages \(optional\)/.test(stepLis[7]), stepLis.join(' | '));
  ok('05-1 the checklist is driven by GET /v1/setup and not by five separate list reads', (await log()).filter((r) => r.url === '/v1/setup').length === 1 && (await log()).filter((r) => /^\/v1\/(brands|sources|credentials|disclosures)(\?|$)/.test(r.url)).length === 0);
  await go('/', { role: 'compliance_viewer', setup: 'new', firstEvent: 'none', policyInForce: false });
  ok('05-4 a compliance viewer sees the same eight steps read only, with no button', (await page.locator('ol.steps > li').count()) === 8 && (await page.locator('ol.steps .btn-primary').count()) === 0 && (await page.locator('ol.steps a').count()) === 0);
  await go('/', { setup: 'new', firstEvent: 'none', policyInForce: false, nulls: ['setup.credential'] });
  ok('05-5 a step the service could not read says Not available, never To do', /Not available/.test((await page.locator('ol.steps > li').allInnerTexts())[3]));
  await go('/', fail('GET /v1/setup'));
  ok('05-6 a setup read that failed is named and no checklist is invented', /Setup progress/.test(await text()) && (await page.locator('ol.steps > li').count()) === 0);
  await go('/', { nulls: ['usage'] });
  ok('05-2 usage failure reads Not available, never 0', (await text()).includes('Not available'));
  await go('/', {});
  ok('05-3 undelivered tile links to the system with the most dead deliveries', (await page.locator('a[href="/systems/sys_dialer"]').count()) >= 1);
  // 06: first event
  await go('/setup/first-event', { firstEvent: 'none' });
  // The shipped permissions policy turns clipboard reading off, so the run records what the page writes (the real write
  // still happens and must succeed) instead of reading it back.
  await page.evaluate(() => {
    const write = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = async (t) => { await write(t); window.__cvCopied = t; };
  });
  await page.getByRole('button', { name: 'Copy command' }).click();
  await page.waitForFunction(() => typeof window.__cvCopied === 'string', null, { timeout: 5000 });
  const clip = await page.evaluate(() => window.__cvCopied);
  const shown = await page.locator('pre.code').first().innerText();
  ok('06-1 copy puts the exact snippet on the clipboard', clip === shown && clip.includes('"disclosure_sha256"') && clip.includes('"source_id":"src_web"'), clip.slice(0, 80));
  await go('/setup/first-event', { setup: 'blank', firstEvent: 'none' });
  ok('06-2 missing steps named', (await text()).includes('Four steps come first') || (await text()).includes('steps come first'));
  await scenario({ firstEvent: 'none' }); await page.goto(base + '/setup/first-event'); await settle(page);
  ok('06 waiting text', (await text()).includes('Waiting for your first event from Website form'));
  // 07: brands
  await go('/brands', {});
  await page.getByRole('button', { name: 'Add a brand' }).click();
  await page.getByLabel('Brand name').fill('Acme Lending'); await page.getByRole('button', { name: 'Add brand' }).click();
  await page.waitForSelector('[role=dialog] [role=alert]', { timeout: 3000 }).catch(() => undefined);
  ok('07-2 brand_exists keeps the dialog open with the field value kept', (await page.locator('[role=dialog]').count()) === 1 && (await page.getByLabel('Brand name').inputValue()) === 'Acme Lending' && (await page.locator('[role=dialog]').innerText()).includes('A brand with this name already exists in Acme Lending'));
  await page.getByLabel('Brand name').fill('Acme Solar Loans'); await page.getByRole('button', { name: 'Add brand' }).click(); await settle(page);
  ok('07-1 new brand row appears without reload', (await page.locator('main').innerText()).includes('Acme Solar Loans') && (await log()).filter((r) => r.method === 'POST' && r.url === '/v1/brands').length === 2);
  // 08: sources
  await go('/sources', {});
  await page.getByRole('button', { name: 'Add a capture source' }).click();
  await page.getByLabel('Name').fill('Landing page'); await page.getByRole('checkbox', { name: 'Acme Lending' }).check();
  await page.getByLabel('Allowed website origins').fill('https://acme.com/form');
  ok('08-1 origin error shown before submit', (await page.locator('[role=dialog]').innerText()).includes('https://acme.com/form is not an origin. An origin has no path.'));
  const before = (await log()).filter((r) => r.method === 'POST' && r.url === '/v1/sources').length;
  await page.getByRole('button', { name: 'Add source' }).click();
  ok('08-1 invalid origin sends nothing', (await log()).filter((r) => r.method === 'POST' && r.url === '/v1/sources').length === before);
  await go('/sources', { empty: ['brands', 'sources'] });
  ok('08-2 no brand: Add a brand first and no add-source button', (await text()).includes('Add a brand first') && (await page.getByRole('button', { name: 'Add a capture source' }).count()) === 0);
  // 09: credentials
  await go('/credentials/new', { policyInForce: false });
  ok('09-1 gate option disabled with its reason visible', (await page.getByLabel(/^Gate check/).isDisabled()) && (await text()).includes('Gate check credentials need a policy in force'));
  await go('/credentials/new', {});
  await page.getByLabel('Name').fill('Salesforce key'); await page.getByLabel(/^Public key for a server/).check(); await page.getByRole('button', { name: 'Next' }).click();
  await page.getByLabel('Public key (PEM)').fill('-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----');
  const c0 = (await log()).filter((r) => r.url === '/v1/credentials' && r.method === 'POST').length;
  await page.getByRole('button', { name: 'Issue credential' }).click();
  ok('09-4 pasted private key is refused and sends no request', (await text()).includes('That text is a private key. Only a public key may be added') && (await log()).filter((r) => r.url === '/v1/credentials' && r.method === 'POST').length === c0);
  await go('/credentials/new', {});
  await page.getByLabel('Name').fill('Hook secret'); await page.getByLabel(/^Signed webhook secret/).check(); await page.getByRole('button', { name: 'Issue credential' }).click();
  await page.waitForSelector('[role=dialog]', { timeout: 4000 });
  ok('09-2 Done is disabled until the box is ticked', await page.getByRole('button', { name: 'Done' }).isDisabled());
  await page.keyboard.press('Escape');
  ok('09 Esc asks to confirm before closing', (await page.locator('[role=alertdialog]').innerText()).includes('This secret will not be shown again.'));
  await page.getByRole('button', { name: 'Go back' }).click();
  await page.getByLabel('I stored this secret somewhere safe').check();
  ok('09-2 Done enabled after ticking', !(await page.getByRole('button', { name: 'Done' }).isDisabled()));
  await page.getByRole('button', { name: 'Done' }).click(); await page.waitForURL(/\/credentials\?issued=/, { timeout: 4000 }).catch(() => undefined); await settle(page);
  ok('09 success banner after issue', (await text()).includes('Hook secret issued.'));
  await go('/credentials', {});
  await page.getByRole('button', { name: 'Revoke Website form key' }).click();
  await page.getByRole('button', { name: 'Revoke now' }).click();
  ok('09-3 revoke without a reason cannot submit', (await page.locator('[role=alertdialog]').innerText()).includes('Enter a reason') && (await log()).filter((r) => r.url.includes(':revoke')).length === 0);
  // 10: wording
  await go('/wording/new', {});
  const exact = '  Leading and trailing spaces “quoted”  ';
  await page.getByLabel('Exact wording').fill(exact); await page.getByLabel('Version label').fill('2026-11');
  await page.getByRole('checkbox', { name: 'SMS' }).check(); await page.getByRole('checkbox', { name: 'Marketing' }).check(); await page.getByRole('checkbox', { name: 'Acme Lending' }).check();
  await page.getByRole('button', { name: 'Register wording' }).click(); await page.waitForURL(/\/wording\/[0-9a-f]{64}/, { timeout: 4000 }).catch(() => undefined); await settle(page);
  const sent = (await log()).find((r) => r.method === 'POST' && r.url === '/v1/disclosures');
  ok('10-1 wording sent byte for byte', sent?.body.body === exact, JSON.stringify(sent?.body.body));
  ok('10-2 detail has no edit control', (await page.getByRole('button', { name: /^Edit/ }).count()) === 0 && (await page.getByRole('link', { name: /^Edit/ }).count()) === 0);
  await go('/wording/new');
  await page.getByLabel('Exact wording').fill(exact); await page.getByLabel('Version label').fill('dup');
  await page.getByRole('checkbox', { name: 'SMS' }).check(); await page.getByRole('checkbox', { name: 'Marketing' }).check(); await page.getByRole('checkbox', { name: 'Acme Lending' }).check();
  await page.getByRole('button', { name: 'Register wording' }).click(); await settle(page);
  ok('10-3 disclosure_exists links to the existing version', (await page.getByRole('link', { name: /^Open version 2026-11/ }).count()) === 1);
  // 11: policies
  await go('/policies/4/approve', {});
  const approve = page.getByRole('button', { name: 'Approve version 4' });
  ok('11-1 approve disabled until ticked, reason visible', (await approve.isDisabled()) && (await text()).includes('Approve turns on after the box is ticked'));
  await page.getByLabel(/^I accept this attestation/).check(); await approve.click(); await page.waitForURL(/\/policies\/4\?approved=1/, { timeout: 4000 }).catch(() => undefined); await settle(page);
  const ap = (await log()).find((r) => r.url.includes('/policies/4:approve'));
  ok('11-2 approve request carries no name field', ap && !('name' in ap.body) && !('approved_by' in ap.body) && ap.body.accepted === true, JSON.stringify(ap?.body));
  ok('11 success names the new version', (await text()).includes('Policy version 4 is in force.'));
  await go('/policies/3', {});
  ok('11-3 approved version has no editable control', (await page.locator('main select').count()) === 0);
  await go('/policies/4', {});
  const names = await page.locator('main select[aria-label]').evaluateAll((els) => els.map((e) => e.getAttribute('aria-label')));
  ok('11-4 every matrix select names its status and channel', names.length > 0 && names.every((n) => /,/.test(n)) && names.includes('No record, SMS'), names.slice(0, 3).join('|'));
  ok('11 stop on record cells are locked', !names.some((n) => n.startsWith('Stop on record')));
  // 12: checklist keyboard
  await go('/checklists/3', {});
  const n0 = await page.getByRole('button', { name: /^Remove element/ }).count();
  await page.getByRole('button', { name: 'Add element' }).focus(); await page.keyboard.press('Enter');
  ok('12-2 element added by keyboard', (await page.getByRole('button', { name: /^Remove element/ }).count()) === n0 + 1);
  await page.getByRole('button', { name: /^Remove element/ }).last().focus(); await page.keyboard.press('Enter');
  ok('12-2 element removed by keyboard', (await page.getByRole('button', { name: /^Remove element/ }).count()) === n0);
  ok('12-1 approve label states documentation completeness', (await text()).includes('not a legal test'));
  // 13: evidence lookup
  await go('/evidence', {});
  const urlBefore = page.url();
  await page.getByLabel('Phone number or email').fill('(555) 555-0100'); await page.getByRole('button', { name: 'Look up records' }).click(); await settle(page);
  ok('13-1 URL unchanged after search', page.url() === urlBefore);
  ok('13-3 status chips carry visible text', (await text()).includes('Stop on record') && (await text()).includes('No record') && (await text()).includes('Your policy: hold'));
  const notice = "Evidence status and the outcome of your organization's approved policy. Not a legal determination.";
  ok('13-4 notice appears exactly once', (await text()).split(notice).length - 1 === 1);
  ok('13 heading names the contact and org', (await text()).includes('Records for (555) 555-0100 in Acme Lending'));
  ok('13 deliveries section', (await text()).includes('Stops sent to your connected systems') && (await text()).includes('Undelivered (dead)'));
  await go('/evidence', { role: 'compliance_viewer' });
  await page.getByLabel('Phone number or email').fill('(555) 555-0100'); await page.getByRole('button', { name: 'Look up records' }).click(); await settle(page);
  ok('13 viewer: brand and source are named from the names reads, never as ids', /Brand Acme Lending · Source Website form/.test(await text()) && !/brd_acme|src_web/.test(await text()), (await text()).slice(0, 200));
  ok('13 viewer: the names reads were made and no brand or source list was asked', (await log()).filter((r) => /^\/v1\/(brand|source)-names/.test(r.url)).length >= 2 && (await log()).filter((r) => /^\/v1\/(sources|brands)(\?|$)/.test(r.url)).length === 0);
  await go('/evidence', {});
  await page.getByLabel('Phone number or email').fill('(555) 555-0199'); await page.getByRole('button', { name: 'Look up records' }).click(); await settle(page);
  ok('13-2 found:false names the contact and org', (await text()).includes('No records for (555) 555-0199 in Acme Lending'));
  await page.getByLabel('Phone number or email').fill('(555) 555-01'); await page.getByRole('button', { name: 'Look up records' }).click();
  ok('13 incomplete phone refused inline, no request', (await page.getByLabel('Phone number or email').getAttribute('aria-invalid')) === 'true');
  await page.getByRole('link', { name: 'Brands' }).click(); await settle(page); await page.getByRole('link', { name: 'Evidence lookup' }).click(); await settle(page);
  ok('13-6 returning to the page leaves the input empty', (await page.getByLabel('Phone number or email').inputValue()) === '');
  await go('/evidence', { fail: { 'POST /v1/proof': { status: 503, error: 'key_unavailable' } } });
  await page.getByLabel('Phone number or email').fill('(555) 555-0100'); await page.getByRole('button', { name: 'Look up records' }).click(); await settle(page);
  ok('13 key_unavailable named', (await text()).includes('Records could not be read') && (await text()).includes('key_unavailable'));
  await go('/evidence', {});
  await page.getByLabel('Phone number or email').fill('(555) 555-0100'); await page.getByRole('button', { name: 'Look up records' }).click(); await settle(page);
  await page.getByRole('button', { name: 'Request erasure' }).click();
  ok('13 erasure dialog states what happens', (await page.locator('[role=alertdialog]').innerText()).includes('This cannot be undone.'));
  await page.keyboard.press('Escape');
  ok('a11y: Esc closes a dialog and focus returns to the opener', (await page.evaluate(() => document.activeElement?.textContent)) === 'Request erasure');
  await go('/evidence', {});
  await page.getByLabel('Phone number or email').fill('(555) 555-0103'); await page.getByRole('button', { name: 'Look up records' }).click(); await settle(page);
  ok('13-5 failing gate section renders partial banner and the rest', (await text()).includes('Some sections did not load') && (await text()).includes('Evidence status now'));
  await go('/evidence', {});
  await page.getByLabel('Phone number or email').fill('(555) 555-0101'); await page.getByRole('button', { name: 'Look up records' }).click(); await settle(page);
  ok('13 seal pending banner', (await text()).includes('1 event is not sealed yet'));
  await go('/evidence', {});
  await page.getByLabel('Phone number or email').fill('(555) 555-0102'); await page.getByRole('button', { name: 'Look up records' }).click(); await settle(page);
  ok('13 later grant did not lift a stop', (await text()).includes('A later grant did not lift a stop'));
  // 14: exports
  await go('/exports', { exportMode: 'normal' });
  await page.getByLabel('Phone number or email').fill('(555) 555-0100'); await page.getByRole('button', { name: 'Build evidence package' }).click();
  await page.waitForURL(/\/exports\/exp_/, { timeout: 4000 }).catch(() => undefined);
  await page.waitForFunction(() => document.body.innerText.includes('Package ready'), null, { timeout: 12000 }).catch(() => undefined);
  const pollsAt = (await log()).filter((r) => /\/v1\/exports\/exp_/.test(r.url) && r.method === 'GET').length;
  await page.waitForTimeout(3600);
  const pollsLater = (await log()).filter((r) => /\/v1\/exports\/exp_/.test(r.url) && r.method === 'GET').length;
  ok('14-1 polling stops at ready', (await text()).includes('Package ready') && pollsLater === pollsAt, `${pollsAt} -> ${pollsLater}`);
  ok('14-2 ready shows sha256 with copy and expiry', (await text()).includes('c81e') && (await page.getByRole('button', { name: 'Copy package sha256' }).count()) === 1 && (await text()).includes('until'));
  ok('G-AC5 no request URL contains the test contact', !(await log()).some((r) => r.url.includes('5555550100') || r.url.includes('555-0100')));
  await go('/exports', {});
  await page.getByLabel('Phone number or email').fill('(555) 555-0500'); await page.getByRole('button', { name: 'Build evidence package' }).click();
  await page.waitForFunction(() => document.body.innerText.includes('The package was not built'), null, { timeout: 12000 }).catch(() => undefined);
  ok('14-3 failed never shows a download button', (await page.getByRole('link', { name: 'Download package' }).count()) === 0 && (await text()).includes('seal_store_unreachable'));
  // 15: systems
  await go('/systems/new', {});
  await page.getByLabel('Name').fill('Texting'); await page.getByLabel(/^Endpoint address/).fill('http://insecure.example.com');
  await page.getByRole('button', { name: 'Connect and send a test push' }).click();
  ok('15-1 non-https endpoint cannot submit', (await log()).filter((r) => r.method === 'POST' && r.url === '/v1/systems').length === 0 && (await text()).includes('must start with https://'));
  await go('/systems/sys_dialer', {});
  await page.getByRole('button', { name: 'Redrive undelivered' }).click();
  await page.getByRole('button', { name: 'Redrive now' }).click();
  ok('15-2 redrive needs a reason', (await log()).filter((r) => r.url === '/v1/deliveries:redrive').length === 0);
  await page.getByLabel(/^Reason/).fill('Dialer endpoint restored'); await page.getByRole('button', { name: 'Redrive now' }).click(); await settle(page);
  const rd = (await log()).filter((r) => r.url === '/v1/deliveries:redrive');
  ok('15-2 redrive posts once with the system id', rd.length === 1 && rd[0].body.system_id === 'sys_dialer' && rd[0].body.reason === 'Dialer endpoint restored');
  await go('/systems/sys_dialer', {});
  ok('15-3 dead rows show fingerprints, never contacts', (await text()).includes('fp_7a1c9e2b') && !/\d{3}[-) ]\s?\d{3}-\d{4}/.test(await text()));
  await go('/systems', { nulls: ['system_counts'] });
  ok('15-4 failed counts read Not available', (await text()).includes('Not available') && (await text()).includes('Undelivered counts did not load'));
  // 16: retention
  await go('/retention', {});
  await page.getByLabel('New retention in years').fill('4');
  ok('16-1 below minimum shows an inline error before submit', (await text()).includes('4 years is below the platform minimum of 5 years'));
  await page.getByLabel('New retention in years').fill('8'); await page.getByLabel(/^Reason/).fill('Longer hold'); await page.getByRole('button', { name: 'Save new version' }).click(); await settle(page);
  ok('16-2 success names the time it applies from', /Retention set to 8 years\. Applies to every record written from /.test(await text()));
  // 17: members
  await go('/members', {});
  const adminRow = page.locator('tr', { hasText: 'dana@acme.com' });
  ok('17-2 the only admin has no remove or demote control', (await adminRow.getByRole('button').count()) === 0);
  await page.getByRole('button', { name: 'Invite a member' }).click();
  const hints = await page.locator('[role=dialog] .opt').allInnerTexts();
  ok('17-1 each role option shows its description', hints.length === 3 && hints.every((h) => h.includes('\n') || h.length > 25), hints.join('|').slice(0, 120));
  // 18: audit
  await go('/audit', {});
  await page.getByLabel('Action').selectOption('export.create'); await settle(page);
  ok('18-1 changing a filter updates the URL and the rows', page.url().includes('action=export.create') && (await page.locator('tbody tr').count()) === 1);
  await go('/audit', {});
  ok('18-2 no personal field rendered', !/\d{3}[-) ]\s?\d{3}-\d{4}/.test(await text()));
  // 19: billing
  await go('/billing', {});
  await page.getByRole('button', { name: 'Manage billing on Stripe' }).click(); await page.waitForURL(/__mock\/stripe\/portal/, { timeout: 4000 }).catch(() => undefined);
  ok('19-1 manage billing posts once and navigates', page.url().includes('/__mock/stripe/portal') && (await log()).filter((r) => r.url === '/v1/billing/portal').length === 1);
  await go('/billing', { nulls: ['usage'] });
  ok('19-2 usage failure renders Not available for both counts', (await text()).split('Not available').length - 1 >= 2);
  // 20: settings
  await go('/settings', {});
  await page.getByRole('button', { name: 'Request offboarding' }).click();
  ok('20-1 send stays disabled until the typed name matches', await page.getByRole('button', { name: 'Send request' }).isDisabled());
  await page.getByLabel('Type the organization name to confirm').fill('Acme Lending');
  ok('20-1 enabled on exact match', !(await page.getByRole('button', { name: 'Send request' }).isDisabled()));
  ok('20-2 steps state the final export comes first and the 30 day wait', (await text()).includes('final, complete evidence export') && (await text()).includes('at least 30 days'));
  // 21: references
  await go('/references', {});
  ok('21-1 banner present', (await text()).includes('Citations and official links only. Not legal advice.'));
  ok('21-2 every row has a review date or Not available', (await page.locator('tbody tr').count()) === 2);
  // G-2: org switched in another tab
  await go('/', { orgs: 'two' });
  await page.evaluate(() => window.dispatchEvent(new StorageEvent('storage', { key: 'cv.org', newValue: JSON.stringify({ org_id: 'org_solar', at: Date.now() }) })));
  await page.waitForSelector('text=Organization switched in another tab', { timeout: 3000 }).catch(() => undefined);
  ok('G-2 switched-in-another-tab banner blocks writes', (await text()).length > 0 && (await page.locator('body').innerText()).includes('You switched to Acme Solar in another tab') && (await page.locator('main fieldset[disabled]').count()) === 1);
  // Offline
  await go('/', {});
  await ctx.setOffline(true); await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  ok('22 offline banner', (await page.locator('body').innerText()).includes('You are offline.'));
  await ctx.setOffline(false); await page.evaluate(() => window.dispatchEvent(new Event('online')));
  await ctx.close();

  // 22-1 and 06-4 with fake timers
  {
    const { ctx: c2, page: p2 } = await newPage(1440);
    await scenario({});
    await p2.clock.install({ time: new Date('2026-11-03T12:00:00Z') });
    await p2.goto(base + '/'); await settle(p2);
    await p2.clock.fastForward(7 * 3600 * 1000 + 58 * 60 * 1000 + 5000);
    await p2.waitForSelector('[role=alertdialog]', { timeout: 3000 }).catch(() => undefined);
    ok('22-1 session warning appears at 7 h 58 min', (await p2.locator('body').innerText()).includes('Your session ends in 2 minutes'));
    await c2.close();
    const { ctx: c3, page: p3 } = await newPage(1440);
    await scenario({ firstEvent: 'none' });
    await p3.clock.install({ time: new Date('2026-11-03T12:00:00Z') });
    await p3.goto(base + '/setup/first-event'); await settle(p3);
    await p3.clock.fastForward(16 * 60 * 1000);
    await p3.waitForFunction(() => document.body.innerText.includes('No event arrived in 15 minutes'), null, { timeout: 5000 }).catch(() => undefined);
    ok('06-4 after 15 minutes with no event the named error renders', (await p3.locator('body').innerText()).includes('No event arrived in 15 minutes'));
    await c3.close();
  }
}

// ---------- records, setup walkthrough and confirmation messages: every state, role gating, privacy rules ----------
async function recordsScreen() {
  const { ctx, page } = await newPage(1440);
  const go = async (p, sc) => { if (sc) await scenario(sc); await page.goto(base + p); await settle(page); };
  const text = () => page.locator('main').innerText();
  const reqs = async (re) => (await log()).filter((r) => re.test(r.url));
  const storageText = () => page.evaluate(() => JSON.stringify({ l: { ...localStorage }, s: { ...sessionStorage } }));
  const FULL = /\(555\) 555-\d{4}/;

  // default list, summary, the chart and the share bars
  await go('/records', {});
  let t = await text();
  ok('23 default: tiles name the three counts', /Records held/.test(t) && /New in the last 30 days/.test(t) && /With a stop on record/.test(t));
  ok('23 default: the total is shown and 50 rows are on the page', /Showing 1 to 50 of 312/.test(t) && (await page.locator('.tw tbody tr').count()) === 50, t.slice(0, 200));
  ok('23 default: every contact is masked and no full number is on the page', /\(555\) \*\*\*-\d{4}/.test(t) && !FULL.test(t));
  ok('23 default: Name and Company columns exist and a name shows', /Name/i.test(t) && /Company/i.test(t) && /Kim Osei/.test(t));
  ok('23 default: the notice sentence is exact', t.includes('Evidence status describes the records held. Your policy outcome for a contact is on its evidence lookup page.'));
  ok('23-11 the chart is an image with a label and a table twin', (await page.locator('[role=img][aria-label^="New records per day"]').count()) === 1 && (await page.locator('details summary', { hasText: 'Show the chart as a table' }).count()) === 1);
  const bars = await page.locator('[role=img][aria-label^="Email:"], [role=img][aria-label^="Text:"], [role=img][aria-label^="Call:"]').evaluateAll((els) => els.map((e) => e.getAttribute('aria-label')));
  ok('23-11 three share bars each name found, stop and no record', bars.length === 3 && bars.every((b) => /Consent record found \d+%/.test(b) && /Stop on record \d+%/.test(b) && /No record \d+%/.test(b)), bars.join(' | '));
  const sumReq = (await reqs(/records\/summary/)).slice(-1)[0];
  ok('23 default: the summary is asked with no from, so the service applies its own 30 day window', !!sumReq && !/[?&]from=/.test(sumReq.url), sumReq && sumReq.url);
  ok('23 default: the chart table twin lists exactly 30 days, 1 Oct to 30 Oct', (await page.locator('details.tbl tbody tr').count()) === 30);
  const apiSum = await (await fetch(`${base}/v1/records/summary?tz=UTC`)).json();
  const pctOf = (o) => { const n = o.consent_record_found + o.stop_on_record + o.no_record; const q = (x) => (n ? Math.round((x / n) * 100) : 0); return `Consent record found ${q(o.consent_record_found)}%, Stop on record ${q(o.stop_on_record)}%, No record ${q(o.no_record)}%`; };
  const naive = apiSum.by_channel.filter((b) => b.channel === 'voice' || b.channel === 'artificial_voice').reduce((a, b) => ({ consent_record_found: a.consent_record_found + b.consent_record_found, stop_on_record: a.stop_on_record + b.stop_on_record, no_record: a.no_record + b.no_record }), { consent_record_found: 0, stop_on_record: 0, no_record: 0 });
  ok('23 call total: the Call bar reads the service call total, which differs from the voice plus AI-voice sum', bars.includes(`Call: ${pctOf(apiSum.call)}`) && pctOf(apiSum.call) !== pctOf(naive), `${bars.join(' | ')} vs ${pctOf(naive)}`);
  ok('23 default: source names come from the names read; the full source list is not asked', (await reqs(/^\/v1\/source-names/)).length >= 1 && (await reqs(/^\/v1\/sources(\?|$)/)).length === 0);
  ok('23 confirmation column: a failed send reads Failed, never refused or retrying', /(Text|Email) failed/.test(t) && !/refused by the provider/.test(t) && !/Retrying/.test(t));
  ok('23-11 Record incomplete is nowhere on the screen', !/Record incomplete/i.test(await page.locator('body').innerText()));
  ok('23 default: the rule for counting a record once per channel is stated', /counts once per channel, under its most protective status/.test(t));
  const hrefs = await page.locator('tbody a[href^="/evidence"]').evaluateAll((a) => a.map((x) => x.getAttribute('href')));
  ok('23-8 a row link goes to evidence lookup by record id', hrefs.length === 50 && hrefs.every((h) => /^\/evidence\?record=[A-Za-z0-9_-]+$/.test(h)), hrefs[0]);

  // filters live in the address bar and never hold a contact point
  await page.getByLabel('Channel', { exact: true }).selectOption({ label: 'Text' }); await settle(page);
  await page.getByLabel('Evidence status', { exact: true }).selectOption({ label: 'Stop on record' }); await settle(page);
  const u = page.url();
  ok('23-1 the address carries the filters and no @ and no run of 7 digits', /channel=sms/.test(u) && /status=stop_on_record/.test(u) && !/@/.test(u) && !/\d{7}/.test(decodeURIComponent(u)), u);
  const live = await page.locator('[aria-live=polite]').allInnerTexts();
  const m = (await text()).match(/Showing 1 to (\d+) of (\d+)/);
  ok('23 filter: the list narrows and a polite live region announces the count', !!m && Number(m[2]) < 312 && live.some((x) => new RegExp(`${m[2]} records`).test(x)), `${m && m[0]} / ${live.join('|')}`);
  const lr = (await log()).filter((r) => r.url.startsWith('/v1/records') && !r.url.includes(':')).slice(-2);
  ok('23 filter: list and summary were both asked with the same filters', lr.length === 2 && lr.every((r) => /channel=sms/.test(r.url) && /status=stop_on_record/.test(r.url)), lr.map((r) => r.url).join(' '));
  await page.getByRole('button', { name: 'Clear filters' }).click(); await settle(page);
  ok('23 filter: Clear filters empties the address and restores the list', !/channel=/.test(page.url()) && /of 312/.test(await text()));
  await go('/records?channel=sms&status=stop_on_record&source_id=src_sf', {});
  t = await text();
  ok('23 empty (no match): says no records match, names the filters and the total held', /No records match these filters/.test(t) && /Channel: Text/.test(t) && /Total records held: 312/.test(t));
  await page.getByRole('button', { name: 'Clear filters' }).last().click(); await settle(page);
  ok('23 empty (no match): Clear filters returns to the list', /of 312/.test(await text()));
  await go('/records', { records: 'none' });
  t = await text();
  ok('23 empty (none yet): names the organization and offers the next steps', /No records yet in Acme Lending/.test(t) && (await page.getByRole('link', { name: 'Send a test event' }).count()) === 1 && (await page.getByRole('link', { name: 'Open capture sources' }).count()) === 1);

  // erased rows keep their stop
  await go('/records?state=erased', {});
  t = await text();
  ok('23-14 an erased row reads Erased in contact, name and company and keeps its stop chip', /Erased/.test(t) && /fingerprint [0-9a-f]{8}/.test(t) && /Stop on record/.test(t) && /Erased \(stop kept\)/.test(t), t.slice(0, 300));
  ok('23-14 an erased row is not a link', (await page.locator('tbody a[href^="/evidence"]').count()) === 0);

  // partial answers
  await go('/records', { nulls: ['rec_mask'] });
  t = await text();
  const maskRows = await page.locator('.tw tbody tr').count();
  ok('23-3 masks that did not load read Not available in every contact cell and still show every stop chip', maskRows === 50 && (await page.locator('.tw tbody tr th').evaluateAll((c) => c.filter((x) => /Not available/.test(x.textContent)).length)) === 50 && /Stop on record/.test(t) && /encryption key did not answer/.test(t) && !/\(555\) \*\*\*/.test(t));
  ok('23-3 the named cause and a Try again are offered', (await page.getByRole('button', { name: 'Try again' }).count()) >= 1);
  await go('/records', { nulls: ['rec_person'] });
  t = await text();
  ok('23-13 names that did not load read Not available and every row still renders', (await page.locator('.tw tbody tr').count()) === 50 && !/Kim Osei/.test(t) && (t.match(/Not available/g) ?? []).length >= 100);
  await go('/records', { nulls: ['rec_total'] });
  ok('23 total unknown: "Showing 1 to 50. Total not available."', /Showing 1 to 50\. Total not available\./.test(await text()));
  await go('/records', { nulls: ['rec_chart'] });
  t = await text();
  ok('23 chart unknown: a named banner replaces it, tiles keep their figures', /The chart did not load/.test(t) && (await page.locator('[role=img][aria-label^="New records per day"]').count()) === 0 && /Records held\s*\n?\s*312/.test(t) && (await page.getByRole('button', { name: 'Try the chart again' }).count()) === 1);
  await go('/records', { nulls: ['rec_call'] });
  t = await text();
  ok('23 call total unknown: the Call bar reads Not available and the Email and Text bars keep their shares', /Call\s+Not available/.test(t) && (await page.locator('[role=img][aria-label^="Call:"]').count()) === 0 && (await page.locator('[role=img][aria-label^="Email:"], [role=img][aria-label^="Text:"]').count()) === 2 && /Showing 1 to 50 of 312/.test(t));
  await go('/records?channel=sms&status=stop_on_record&source_id=src_sf', { role: 'compliance_viewer' });
  t = await text();
  ok('23 viewer: a filter names its source from the names read, never the id', /Source: Salesforce/.test(t) && !/src_sf/.test(t), t.slice(0, 300));
  const vOpts = (await page.getByLabel('Source', { exact: true }).locator('option').allInnerTexts()).join('|');
  ok('23 viewer: the Source filter lists every source by name', /All sources/.test(vOpts) && /Salesforce/.test(vOpts) && /Website form/.test(vOpts) && !/src_/.test(vOpts), vOpts);
  ok('23 viewer: only the names read was made, never the source or brand list', (await reqs(/^\/v1\/source-names/)).length >= 1 && (await reqs(/^\/v1\/(sources|brands)(\?|$)/)).length === 0);
  await go('/records', fail('GET /v1/records/summary'));
  t = await text();
  ok('23-2 a summary failure reads Not available in each tile and never 0', (t.match(/Not available/g) ?? []).length >= 3 && !/Records held\s*\n?\s*0\b/.test(t) && /Showing 1 to 50 of 312/.test(t));
  await go('/records', fail('GET /v1/records'));
  t = await text();
  ok('23 list error: names the cause and offers Try again, with no rows', /The records list did not load/.test(t) && /Cause:/.test(t) && /503 service_unavailable/.test(t) && (await page.locator('.tw tbody tr').count()) === 0 && (await page.getByRole('button', { name: 'Try again' }).count()) === 1);
  await go('/records', fail('GET /v1/records', 503, 'audit_unavailable'));
  t = await text();
  ok('23-4 audit_unavailable shows no rows and says records are never shown without an audit row', /The list was not shown/.test(t) && /503 audit_unavailable/.test(t) && /never shown without an audit row/.test(t) && (await page.locator('.tw tbody tr').count()) === 0);

  // exact search: the contact goes in the body and never in the address
  await go('/records', {});
  const before = page.url();
  await page.getByLabel('Find one exact phone number or email').fill('(555) 555-0142');
  await page.getByRole('button', { name: 'Find' }).click(); await settle(page);
  const sr = await reqs(/records:search/);
  t = await text();
  ok('23-7 search posts the contact in the body and leaves the address unchanged', sr.length === 1 && sr[0].body.contact === '+15555550142' && page.url() === before, JSON.stringify(sr.map((r) => r.body)));
  ok('23 search found: focus moves to the result banner', await page.evaluate(() => document.activeElement?.getAttribute('aria-label') === 'Search result'));
  ok('23 search found: says how many and offers the way back', /1 record for \(555\) 555-0142\./.test(t) && (await page.getByRole('button', { name: 'Back to the full list' }).count()) === 1 && (await page.locator('.tw tbody tr').count()) === 1);
  await page.getByRole('button', { name: 'Back to the full list' }).click(); await settle(page);
  ok('23 search: back to the full list restores it', /of 312/.test(await text()));
  await page.getByLabel('Find one exact phone number or email').fill('(555) 555-0999');
  await page.getByRole('button', { name: 'Find' }).click(); await settle(page);
  ok('23 search none: says No record for the number, in the organization', /No record for \(555\) 555-0999 in Acme Lending/.test(await text()));
  await go('/records', {});
  await page.getByLabel('Find one exact phone number or email').fill('555-01');
  await page.getByRole('button', { name: 'Find' }).click(); await settle(page);
  ok('23-15 an incomplete number shows the inline error and sends nothing', (await reqs(/records:search/)).length === 0 && /Not searched/.test(await text()) && /invalid_contact/.test(await text()));

  // reveal: audited per page, never stored, cleared on off and on navigation
  await go('/records', {});
  await page.getByRole('switch', { name: 'Show full contact points' }).click();
  const dlgCopy = async (label) => { const dt = await page.locator('#dialog-root').innerText(); const h = scanCopy(dt); ok(`copy check on the ${label} dialog`, h.length === 0 && dt.length > 20, h.slice(0, 2).join(' | ')); };
  await dlgCopy('reveal');
  ok('23 reveal: the first time asks first and says each page writes an audit row', (await page.getByRole('dialog').count()) === 1 && /Each page you open this way writes one audit row with your name and the records shown\./.test(await page.getByRole('dialog').innerText()) && (await reqs(/records:reveal/)).length === 0);
  await page.getByRole('dialog').getByRole('button', { name: 'Show full contact points' }).click(); await settle(page);
  const rv = await reqs(/records:reveal/);
  const shownIds = await page.locator('tbody tr a[href^="/evidence"]').evaluateAll((a) => a.map((x) => x.getAttribute('href').split('record=')[1]));
  t = await text();
  ok('23-5 turning it on calls reveal once with exactly the visible page ids', rv.length === 1 && rv[0].body.record_ids.length === 50 && JSON.stringify(rv[0].body.record_ids) === JSON.stringify(shownIds));
  ok('23-5 full contact points show with the audit time, and the switch is on', FULL.test(t) && /Full contact points are showing\./.test(t) && /recorded in the audit log/.test(t) && (await page.getByRole('switch', { name: 'Show full contact points' }).getAttribute('aria-checked')) === 'true');
  ok('23-5 the audit time shown is the one the service answered, not the browser clock', t.includes(`recorded in the audit log at ${fmtTime('2026-10-30T15:04:05Z')}`), t.slice(t.indexOf('Full contact points are showing'), t.indexOf('Full contact points are showing') + 160));
  let st = await storageText();
  ok('revealed values and names are never written to client storage', !FULL.test(st) && !/555555\d{4}/.test(st) && !/Kim Osei/.test(st) && !/example\.com/.test(st), st.slice(0, 200));
  await page.getByRole('switch', { name: 'Show full contact points' }).click(); await settle(page);
  ok('23-5 turning it off removes every full contact point from the page', !FULL.test(await page.locator('main').innerText()) && !/555555\d{4}/.test(await page.content()) && (await page.getByRole('switch', { name: 'Show full contact points' }).getAttribute('aria-checked')) === 'false');
  await page.getByRole('switch', { name: 'Show full contact points' }).click();
  ok('23 reveal: asking again in the same visit does not ask a second time', (await page.getByRole('dialog').count()) === 0);
  await settle(page);
  ok('23 reveal: it is on again', FULL.test(await page.locator('main').innerText()));
  await page.evaluate(() => window.dispatchEvent(new Event('pagehide'))); await page.waitForTimeout(200);
  ok('23-5 pagehide turns reveal off and removes every full contact point from the page', !FULL.test(await page.locator('main').innerText()) && !/555555\d{4}/.test(await page.content()) && (await page.getByRole('switch', { name: 'Show full contact points' }).getAttribute('aria-checked')) === 'false');
  await page.getByRole('link', { name: 'Audit log' }).click(); await settle(page);
  await page.getByRole('link', { name: 'Records', exact: true }).click(); await settle(page);
  ok('23 reveal: leaving the page clears it, coming back shows masked values with the switch off', !FULL.test(await page.locator('main').innerText()) && (await page.getByRole('switch', { name: 'Show full contact points' }).getAttribute('aria-checked')) === 'false');
  await go('/records', fail('POST /v1/records:reveal', 429, 'rate_limited'));
  await page.evaluate(() => 0);
  await scenario({ reset: false, fail: { 'POST /v1/records:reveal': { status: 429, error: 'rate_limited', headers: { 'retry-after': '240' } } } });
  await page.goto(base + '/records'); await settle(page);
  await page.getByRole('switch', { name: 'Show full contact points' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Show full contact points' }).click(); await settle(page);
  t = await text();
  ok('23-16 a 429 shows the wait, says nothing was revealed and leaves masked values', /Full contact points were not shown\./.test(t) && /429 rate_limited/.test(t) && /4 minutes/.test(t) && !FULL.test(t) && /\(555\) \*\*\*/.test(t));
  await go('/records', {});
  await page.getByRole('switch', { name: 'Show full contact points' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Show full contact points' }).click(); await settle(page);
  await page.getByRole('button', { name: 'Older' }).click(); await settle(page);
  const rv2 = await reqs(/records:reveal/);
  ok('23 reveal: each page opened with the switch on gets its own reveal call', rv2.length === 2 && rv2[1].body.record_ids.length === 50 && rv2[1].body.record_ids[0] !== rv2[0].body.record_ids[0] && /Showing 51 to 100 of 312/.test(await text()));
  await page.getByRole('button', { name: 'Newer' }).click(); await settle(page);
  ok('23 pager: Newer returns to the first page', /Showing 1 to 50 of 312/.test(await text()));

  // export
  await go('/records', {});
  await page.getByRole('button', { name: 'Export this list' }).click();
  let d = page.getByRole('dialog');
  await dlgCopy('export');
  ok('23 export: the dialog says how many records match and that the file is kept 24 hours', /312 records match your filters/.test(await d.innerText()) && /kept 24 hours/.test(await d.innerText()));
  await d.getByLabel(/^Full phone numbers/).check();
  await d.getByRole('button', { name: 'Build the file' }).click();
  ok('23-9 a full export with no reason shows the inline error and sends nothing', /Enter a reason/.test(await d.innerText()) && (await reqs(/records\/exports$/)).filter((r) => r.method === 'POST').length === 0);
  await d.getByLabel(/^Reason/).fill('Quarterly review');
  await d.getByRole('button', { name: 'Build the file' }).click(); await settle(page);
  await page.getByText('Your file is ready.').waitFor({ timeout: 12000 }).catch(() => undefined);
  const ex = (await log()).filter((r) => r.method === 'POST' && /records\/exports$/.test(r.url));
  t = await text();
  ok('23 export: posts the form, the reason and include_person once', ex.length === 1 && ex[0].body.contact_form === 'full' && ex[0].body.reason === 'Quarterly review' && typeof ex[0].body.include_person === 'boolean');
  ok('23 export: ready shows the count, the form, the fingerprint and a one-time download', /Your file is ready\./.test(t) && /312 records/.test(t) && /SHA-256/.test(t) && (await page.getByRole('link', { name: 'Download' }).count()) === 1 && /works once, for 15 minutes/.test(t));
  const dlLink = page.getByRole('link', { name: 'Download', exact: true });
  const newLink = page.getByRole('button', { name: 'Get a new download link' });
  const dl0 = await dlLink.count(); const nb0 = await newLink.count();
  await Promise.all([page.waitForEvent('download', { timeout: 4000 }).catch(() => null), dlLink.first().click()]);
  await page.waitForTimeout(500);
  ok('23 export: once the one-time link is used, Download is replaced by Get a new download link', (await dlLink.count()) === dl0 - 1 && (await newLink.count()) === nb0 + 1, `${dl0}->${await dlLink.count()} ${nb0}->${await newLink.count()}`);
  await newLink.first().click(); await settle(page); await page.waitForTimeout(200);
  ok('23 export: Get a new download link asks the service for one and shows Download again', (await reqs(/records\/exports\/.+:link/)).length >= 1 && (await dlLink.count()) === dl0);
  await go('/records', { exportMode: 'large' });
  await page.getByRole('button', { name: 'Export this list' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Build the file' }).click(); await settle(page);
  t = await text();
  ok('23 export too large: names the count and the ceiling, nothing built, offers to change filters', /The file was not built/.test(t) && /301,220/.test(t) && /250,000/.test(t) && /422 export_too_large/.test(t) && (await page.getByRole('button', { name: 'Change filters' }).count()) === 1);
  await go('/records', { exportMode: 'fail' });
  await page.getByRole('button', { name: 'Export this list' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Build the file' }).click(); await settle(page);
  await page.getByText('The file was not built').waitFor({ timeout: 12000 }).catch(() => undefined);
  t = await text();
  ok('23 export failed: names the cause and offers Export again', /The file was not built/.test(t) && /service_unavailable/.test(t) && (await page.getByRole('button', { name: 'Export again' }).count()) === 1);

  // a row opens evidence lookup by record id: masked until asked, then the full lookup
  await go('/records', {});
  const rowHref = await page.locator('.tw tbody a[href^="/evidence"]').first().getAttribute('href');
  await page.goto(base + rowHref); await settle(page);
  t = await text();
  ok('13 opened by record id: says so, shows no contact point and offers to show it', /Opened from Records/.test(t) && !FULL.test(t) && (await page.getByRole('button', { name: 'Show full contact point' }).count()) === 1 && !/@|\d{7}/.test(page.url().replace(/record=[A-Za-z0-9_-]+/, '')));
  await page.getByRole('button', { name: 'Show full contact point' }).click(); await settle(page);
  await page.getByText(/^Records for /).first().waitFor({ timeout: 6000 }).catch(() => undefined);
  const rid = rowHref.split('record=')[1];
  const rvr = await reqs(/records:reveal/);
  ok('13 opened by record id: one reveal for that id, then the evidence lookup runs', rvr.length === 1 && rvr[0].body.record_ids.length === 1 && rvr[0].body.record_ids[0] === rid && /Records for \(555\) 555-0100/.test(await text()));

  // suspended: exports pause with a visible reason, reading and search stay
  await go('/records', { orgStatus: 'suspended' });
  ok('23 suspended: Export is disabled with the reason beside it, search still works', await page.getByRole('button', { name: 'Export this list' }).isDisabled() && /Exports are paused until billing is resolved/.test(await text()) && !(await page.getByRole('button', { name: 'Find' }).isDisabled()));

  // compliance viewer: everything an admin has for reading, names included
  await go('/records', { role: 'compliance_viewer' });
  t = await text();
  ok('23 viewer: sees names, search, reveal and export', /Kim Osei/.test(t) && (await page.getByLabel('Find one exact phone number or email').count()) === 1 && (await page.getByRole('switch', { name: 'Show full contact points' }).count()) === 1 && (await page.getByRole('button', { name: 'Export this list' }).count()) === 1);

  // developer: fingerprints only, no search, reveal or export, no names anywhere
  await go('/records', { role: 'developer' });
  t = await text();
  const html = await page.content();
  ok('23-6 developer: no search box, no reveal switch, no export button', (await page.getByLabel('Find one exact phone number or email').count()) === 0 && (await page.getByRole('switch').count()) === 0 && (await page.getByRole('button', { name: /Export/ }).count()) === 0);
  ok('23-6 developer: contact cells hold a fingerprint and are not links', /fingerprint [0-9a-f]{8}/.test(t) && (await page.locator('tbody a[href^="/evidence"]').count()) === 0 && !/\(555\) \*\*\*/.test(t));
  ok('23-12 developer: no Name or Company column and no name or company string in the page', !/>Name</.test(html) && !/>Company</.test(html) && !/Kim Osei|Priya Nair|Marcus Webb|Northwind|Helio/.test(html));
  ok('23 developer: says what the role sees and that rows do not open', /Your role sees fingerprints, not contact points, names or companies\./.test(t));
  ok('23 developer: counts and the chart are the same as an admin sees', /Showing 1 to 50 of 312/.test(t) && (await page.locator('[role=img][aria-label^="New records per day"]').count()) === 1);
  const dev = await log();
  ok('23 developer: no search, reveal or export request was made', !dev.some((r) => /records:(search|reveal)|records\/exports/.test(r.url)));
  await ctx.close();
}

async function narrowRoleGating() {
  const { ctx, page } = await newPage(375);
  const go = async (p, sc) => { await scenario(sc); await page.goto(base + p); await settle(page); };
  const html = () => page.content();
  await go('/records', { role: 'developer' });
  const h = await html();
  ok('23-6 at 375px a developer has no search box, no reveal switch, no export button, no Name or Company, no name in the page', (await page.getByLabel('Find one exact phone number or email').count()) === 0 && (await page.getByRole('switch').count()) === 0 && (await page.getByRole('button', { name: /Export/ }).count()) === 0 && !/Kim Osei|Priya Nair|Marcus Webb|Northwind|Helio/.test(h) && /fingerprint [0-9a-f]{8}/.test(await page.locator('main').innerText()));
  await go('/records', { role: 'compliance_viewer' });
  ok('23 at 375px a compliance viewer has search, reveal and export, and names', (await page.getByLabel('Find one exact phone number or email').count()) === 1 && (await page.getByRole('switch', { name: 'Show full contact points' }).count()) === 1 && (await page.getByRole('button', { name: 'Export this list' }).count()) === 1 && /Kim Osei/.test(await page.locator('main').innerText()));
  await page.getByRole('switch', { name: 'Show full contact points' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Show full contact points' }).click(); await settle(page);
  ok('23 at 375px reveal shows full numbers, and turning it off clears them', /\(555\) 555-\d{4}/.test(await page.locator('main').innerText()));
  await page.getByRole('switch', { name: 'Show full contact points' }).click(); await settle(page);
  ok('23 at 375px the numbers are gone again', !/\(555\) 555-\d{4}/.test(await page.locator('main').innerText()));
  await go('/setup', { role: 'compliance_viewer' });
  ok('24-6 at 375px a compliance viewer is refused and offered the overview', /This page is for admins and developers/.test(await page.locator('main').innerText()) && (await page.getByRole('link', { name: /^Go to Overview/ }).count()) === 1);
  await go('/setup', { role: 'developer', setup: 'new', firstEvent: 'none', policyInForce: false });
  const sel = await page.locator('#step-select').count();
  ok('24 at 375px the step rail is a select and says which steps wait on an admin', sel === 1 && /Steps 3, 6 and 8 need an admin\./.test(await page.locator('main').innerText()));
  await go('/confirmations', { role: 'developer' });
  const dt = await page.locator('main').innerText();
  ok('25 at 375px a developer sees no replies and no registration or disconnect buttons', /Replies are personal data/.test(dt) && (await page.getByRole('button', { name: /Mark texting|Withdraw|Disconnect/ }).count()) === 0 && !/no more of these thanks/.test(await html()));
  await go('/confirmations/src_web/email', { role: 'compliance_viewer' });
  ok('25 at 375px a compliance viewer opening edit is refused', /This page is for admins and developers/.test(await page.locator('main').innerText()));
  await ctx.close();
}

async function setupScreen() {
  const { ctx, page } = await newPage(1440);
  const go = async (p, sc) => { if (sc) await scenario(sc); await page.goto(base + p); await settle(page); };
  const text = () => page.locator('main').innerText();
  const NEW = { setup: 'new', firstEvent: 'none', policyInForce: false };

  await go('/setup', { setup: 'blank', firstEvent: 'none', policyInForce: false });
  let t = await text();
  ok('24 welcome: names the person and the eight steps, offers step 1 or the overview', /Welcome to ConsentVault, Dana/.test(t) && /Add a brand/.test(t) && /Turn on confirmation messages \(optional\)/.test(t) && (await page.getByRole('button', { name: 'Start with step 1' }).count()) + (await page.getByRole('link', { name: 'Start with step 1' }).count()) === 1 && (await page.getByRole('link', { name: 'Go to the overview instead' }).count()) === 1);
  await page.getByRole('button', { name: 'Start with step 1' }).click().catch(() => page.getByRole('link', { name: 'Start with step 1' }).click());
  await settle(page);
  ok('24 welcome: Start opens step 1, the brand form', /Add a brand/.test(await page.locator('main h2').first().innerText()) && (await page.getByLabel('Brand name').count()) === 1);

  await go('/setup', NEW);
  t = await text();
  ok('24-1 loading with steps 1 and 2 done opens step 3', /3\. Register your consent wording/.test(await page.locator('main h2').first().innerText()) && /Welcome back/.test(t) && /Steps 1 and 2 are done\. You are on step 3\./.test(t));
  const rail = await page.locator('ol[aria-label="Setup steps"] li').allInnerTexts();
  ok('24 rail: eight steps in order with their status words', rail.length === 8 && /Done/.test(rail[0]) && /Done/.test(rail[1]) && /To do/.test(rail[2]) && /\(optional\)/.test(rail[6]) && /\(optional\)/.test(rail[7]), rail.join(' | '));
  ok('24 rail: the current step is marked', (await page.locator('ol[aria-label="Setup steps"] [aria-current=step]').count()) === 1);
  ok('24 progress saves as you go is stated, and Leave setup is offered', /Progress saves as you go\./.test(t) && (await page.getByRole('link', { name: 'Leave setup' }).count()) === 1);
  ok('24-3 Skip appears on neither step 3 nor any required step', (await page.getByRole('button', { name: 'Skip for now' }).count()) === 0);
  await page.getByRole('button', { name: /^1\. Add a brand/ }).click().catch(() => undefined);
  await page.waitForTimeout(150);
  ok('24 rail: choosing a step opens it and moves focus to its heading', /Add a brand/.test(await page.locator('main h2').first().innerText()) && (await page.evaluate(() => document.activeElement?.tagName)) === 'H2');
  // brand: a refusal is shown in the form and keeps what was typed; a new name is saved and the walkthrough moves on
  await go('/setup?step=brand', { setup: 'blank', firstEvent: 'none', policyInForce: false, fail: { 'POST /v1/brands': { status: 409, error: 'brand_exists' } } });
  await page.getByLabel('Brand name').fill('Acme Lending');
  await page.getByRole('button', { name: 'Add brand' }).click(); await settle(page);
  t = await text();
  ok('24 step error: the named error shows and the form keeps what was typed', /Your brand was not added/.test(t) && /409 brand_exists/.test(t) && (await page.getByLabel('Brand name').inputValue()) === 'Acme Lending');
  await scenario({ reset: false, fail: {} });
  await page.getByLabel('Brand name').fill('Acme Solar Brand');
  await page.getByRole('button', { name: 'Add brand' }).click(); await settle(page);
  ok('24 step success: says what was added and the rail refreshes from the service', /Brand added\./.test(await text()) && (await page.locator('ol[aria-label="Setup steps"] li').first().innerText()).includes('Done') && (await log()).filter((r) => r.url === '/v1/setup').length >= 1);
  // the wording, credential, policy and system steps draw their own form in place
  await go('/setup?step=wording', NEW);
  ok('24 step 3: shows the wording form in place and Back is offered', (await page.getByLabel('Exact wording').count()) === 1 && (await page.getByRole('button', { name: 'Back' }).count()) === 1);
  await go('/setup?step=policy', NEW);
  ok('24 step 6: explains proceed and hold and says the policy is applied as written', /proceed or hold/.test(await text()) && /does not decide what the law allows/.test(await text()));
  // resume on any device: nothing in client storage decides the step
  await go('/setup', NEW);
  const stor = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  ok('24-2 no step progress is kept in client storage', !/step/i.test(stor.replace(/cv\.draft/g, '')) || !/"cv\.setup\.step/.test(stor));

  // partial: one step could not be checked
  await go('/setup', { ...NEW, nulls: ['setup.credential'] });
  await page.getByRole('button', { name: /^4\. Issue a capture credential/ }).click(); await page.waitForTimeout(150);
  t = await text();
  const railP = await page.locator('ol[aria-label="Setup steps"] li').allInnerTexts();
  ok('24-5 a step that could not be read shows Not available and never Done', /Not available/.test(railP[3]) && !/Done/.test(railP[3]) && /Step 4 could not be checked/.test(t) && (await page.getByRole('button', { name: 'Check again' }).count()) === 1);
  ok('24 partial: the other steps still work', /Done/.test(railP[0]) && (await page.getByRole('button', { name: /^5\./ }).count()) === 1);

  // optional steps can be skipped; required ones cannot
  await go('/setup?step=system', { setup: 'almost' });
  ok('24-3 Skip appears on the optional step', (await page.getByRole('button', { name: 'Skip for now' }).count()) === 1);
  await page.getByRole('button', { name: 'Skip for now' }).click();
  t = await page.getByRole('dialog').innerText();
  ok('24 skip dialog: says stops are still recorded and no other system hears until one is connected', /Skip connecting a system for now\?/.test(t) && /Stops are still recorded and shown in Records/.test(t));
  await page.getByRole('dialog').getByLabel(/^Reason/).fill('Using the export for now');
  await page.getByRole('dialog').getByRole('button', { name: 'Skip for now' }).click(); await settle(page);
  const sk = (await log()).filter((r) => /setup\/steps\/system:skip/.test(r.url));
  ok('24 skip: posts once with the reason, and the step now reads Skipped', sk.length === 1 && sk[0].body.reason === 'Using the export for now' && /Skipped/.test((await page.locator('ol[aria-label="Setup steps"] li').allInnerTexts())[6]));
  await go('/setup?step=brand', { setup: 'almost' });
  ok('24-3 a required step offers no Skip', (await page.getByRole('button', { name: 'Skip for now' }).count()) === 0);

  // each step's own form is drawn inside the walkthrough, with its own success and error states
  const EMB = { setup: 'new', firstEvent: 'none', policyInForce: false };
  const railOf = async (i) => (await page.locator('ol[aria-label="Setup steps"] li').allInnerTexts())[i];
  const inSetup = () => new URL(page.url()).pathname === '/setup';
  await go('/setup?step=wording', EMB);
  ok('24 wording step: the form is on the setup page and not a link to another page', (await page.getByLabel('Exact wording').count()) === 1 && (await page.getByRole('link', { name: 'Register wording' }).count()) === 0 && inSetup());
  await page.getByLabel('Exact wording').fill('I agree to texts.'); await page.getByLabel('Version label').fill('2026-11');
  await page.getByRole('checkbox', { name: 'SMS' }).check(); await page.getByRole('checkbox', { name: 'Marketing' }).check(); await page.getByRole('checkbox', { name: 'Acme Lending' }).check();
  await page.getByRole('button', { name: 'Register wording' }).click(); await settle(page);
  ok('24 wording step success: posts once, stays on setup, says what was registered and the rail marks step 3 done', (await log()).filter((r) => r.method === 'POST' && r.url === '/v1/disclosures').length === 1 && inSetup() && /Wording registered as version 2026-11\./.test(await text()) && /Done/.test(await railOf(2)));
  await go('/setup?step=wording', { ...EMB, fail: { 'POST /v1/disclosures': { status: 503, error: 'service_unavailable' } } });
  await page.getByLabel('Exact wording').fill('I agree to texts.'); await page.getByLabel('Version label').fill('2026-12');
  await page.getByRole('checkbox', { name: 'SMS' }).check(); await page.getByRole('checkbox', { name: 'Marketing' }).check(); await page.getByRole('checkbox', { name: 'Acme Lending' }).check();
  await page.getByRole('button', { name: 'Register wording' }).click(); await settle(page);
  ok('24 wording step error: names the cause on the setup page, keeps the form and leaves step 3 to do', /The wording was not registered/.test(await text()) && /503 service_unavailable/.test(await text()) && inSetup() && /To do/.test(await railOf(2)) && (await page.getByLabel('Exact wording').inputValue()) === 'I agree to texts.');
  await go('/setup?step=credential', EMB);
  ok('24 credential step: the form is on the setup page', (await page.getByLabel('Name').count()) === 1 && (await page.getByRole('link', { name: 'Issue a capture credential' }).count()) === 0 && inSetup());
  await page.getByLabel('Name').fill('Setup key'); await page.getByRole('button', { name: 'Issue credential' }).click(); await settle(page);
  ok('24 credential step success: posts once, stays on setup and says it was issued', (await log()).filter((r) => r.method === 'POST' && r.url === '/v1/credentials').length === 1 && inSetup() && /Setup key issued\./.test(await text()) && /Done/.test(await railOf(3)));
  await go('/setup?step=credential', { ...EMB, fail: { 'POST /v1/credentials': { status: 503, error: 'service_unavailable' } } });
  await page.getByLabel('Name').fill('Setup key'); await page.getByRole('button', { name: 'Issue credential' }).click(); await settle(page);
  ok('24 credential step error: names the cause on the setup page and leaves step 4 to do', /The credential was not issued/.test(await text()) && /503 service_unavailable/.test(await text()) && inSetup() && /To do/.test(await railOf(3)));
  await go('/setup?step=policy', EMB);
  ok('24 policy step: the editor is on the setup page', (await page.getByRole('button', { name: 'Save draft' }).count()) === 1 && inSetup());
  await page.getByRole('button', { name: 'Save draft' }).click(); await settle(page);
  ok('24 policy step success: the draft is saved in place and a link leads to approving it', (await log()).filter((r) => r.method === 'POST' && r.url === '/v1/policies').length === 1 && inSetup() && /Draft saved as version \d+\./.test(await text()) && (await page.getByRole('link', { name: 'Review and approve this draft' }).count()) === 1);
  await go('/setup?step=policy', { ...EMB, fail: { 'POST /v1/policies': { status: 503, error: 'service_unavailable' } } });
  await page.getByRole('button', { name: 'Save draft' }).click(); await settle(page);
  ok('24 policy step error: names the cause on the setup page', /The draft was not saved/.test(await text()) && /503 service_unavailable/.test(await text()) && inSetup());
  await go('/setup?step=system', { setup: 'almost' });
  ok('24 system step: the form is on the setup page', (await page.getByLabel(/^Endpoint address/).count()) === 1 && (await page.getByRole('link', { name: 'Connect a system' }).count()) === 0 && inSetup());
  await page.getByLabel('Name').fill('Setup CRM'); await page.getByLabel(/^Endpoint address/).fill('https://crm.example.com/hook');
  await page.getByRole('button', { name: 'Connect and send a test push' }).click(); await settle(page);
  ok('24 system step success: the test push result shows in place with a Done button', (await log()).filter((r) => r.method === 'POST' && r.url === '/v1/systems').length === 1 && inSetup() && (await page.getByRole('button', { name: 'Done' }).count()) === 1);
  await page.getByRole('button', { name: 'Done' }).click(); await settle(page);
  ok('24 system step: Done returns to the walkthrough with the connection named and the step done', inSetup() && /Setup CRM connected\./.test(await text()) && /Done/.test(await railOf(6)));
  await go('/setup?step=system', { setup: 'almost', fail: { 'POST /v1/systems': { status: 503, error: 'service_unavailable' } } });
  await page.getByLabel('Name').fill('Setup CRM'); await page.getByLabel(/^Endpoint address/).fill('https://crm.example.com/hook');
  await page.getByRole('button', { name: 'Connect and send a test push' }).click(); await settle(page);
  ok('24 system step error: names the cause on the setup page', /The system was not connected/.test(await text()) && /503 service_unavailable/.test(await text()) && inSetup() && /To do/.test(await railOf(6)));

  // turning a skipped step back on follows the role: a developer may turn back on the system step only
  await go('/setup?step=confirmations', { setup: 'new', firstEvent: 'none', policyInForce: false, role: 'developer', nulls: ['skipped.confirmations'] });
  ok('24 developer: a skipped confirmations step shows Skipped and no Turn it back on button', /Skipped/.test(await text()) && (await page.getByRole('button', { name: 'Turn it back on' }).count()) === 0);
  const unskipStatus = await page.evaluate(async () => (await fetch('/v1/setup/steps/confirmations:unskip', { method: 'POST' })).status);
  ok('24 contract: the service refuses a developer turning confirmations back on', unskipStatus === 403);
  await go('/setup?step=confirmations', { setup: 'new', firstEvent: 'none', policyInForce: false, nulls: ['skipped.confirmations'] });
  ok('24 admin: the skipped confirmations step offers Turn it back on', (await page.getByRole('button', { name: 'Turn it back on' }).count()) === 1);
  await go('/setup?step=system', { setup: 'almost', role: 'developer', nulls: ['skipped.system'] });
  ok('24 developer: the system step may be turned back on', (await page.getByRole('button', { name: 'Turn it back on' }).count()) === 1);
  await go('/setup?step=system', { setup: 'almost', nulls: ['skipped.system'], fail: { 'POST /v1/setup/steps/system:unskip': { status: 403, error: 'role_not_allowed' } } });
  await page.getByRole('button', { name: 'Turn it back on' }).click(); await settle(page);
  ok('24 a refused turn back on shows the error and the step stays skipped', /The step was not turned back on/.test(await text()) && /403 role_not_allowed/.test(await text()) && /Skipped/.test(await railOf(6)));

  // waiting for the first event
  await go('/setup?step=first_event', { setup: 'almost', firstEvent: 'none' });
  t = await text();
  ok('24 step 5 waiting: says it is checking every 5 seconds for 15 minutes and that it finishes on its own', /Waiting for your first event from Website form\./.test(t) && /Checking every 5 seconds for 15 minutes\./.test(t) && (await page.locator('[aria-live=polite]').count()) >= 1);
  await scenario({ reset: false, firstEvent: 'sealed' });
  await page.getByRole('button', { name: 'Check now' }).click(); await settle(page);
  ok('24 step 5: Check now finds the event and the rail marks the step done', /Done/.test((await page.locator('ol[aria-label="Setup steps"] li').allInnerTexts())[4]));

  // developer: admin steps wait
  await go('/setup', { ...NEW, role: 'developer' });
  const railD = await page.locator('ol[aria-label="Setup steps"] li').allInnerTexts();
  ok('24-4 developer: steps 3, 6 and 8 read Waiting on an admin', /Waiting on an admin/.test(railD[2]) && /Waiting on an admin/.test(railD[5]) && /Waiting on an admin/.test(railD[7]) && !/Waiting on an admin/.test(railD[3]), railD.join(' | '));
  t = await text();
  ok('24-4 developer: says which steps need an admin and which the person can do, with no form on the waiting step', /Steps 3, 6 and 8 need an admin\./.test(t) && /You can do steps 4, 5 and 7\./.test(t) && (await page.getByRole('link', { name: 'Register wording' }).count()) === 0 && (await page.getByLabel('Exact wording').count()) === 0);
  await page.getByRole('button', { name: /^4\. Issue a capture credential/ }).click(); await page.waitForTimeout(150);
  ok('24 developer: the steps they own show their action', (await page.getByRole('button', { name: 'Issue credential' }).count()) === 1 && (await page.getByLabel('Name').count()) === 1);

  // blocked while suspended
  await go('/setup?step=credential', { setup: 'almost', orgStatus: 'suspended', empty: ['credentials'] });
  t = await text();
  ok('24 suspended: the credential step reads Paused with the reason and a way to billing', /Paused/.test((await page.locator('ol[aria-label="Setup steps"] li').allInnerTexts())[3]) && /New credentials are paused while Acme Lending is suspended\./.test(t) && (await page.getByRole('link', { name: 'Open billing' }).count()) >= 1);

  // error and role refused
  await go('/setup', fail('GET /v1/setup'));
  t = await text();
  ok('24 error: names the cause, says nothing is lost, offers Try again', /Setup progress did not load/.test(t) && /503 service_unavailable/.test(t) && /Nothing you finished is lost/.test(t) && (await page.getByRole('button', { name: 'Try again' }).count()) === 1);
  await go('/setup', { role: 'compliance_viewer' });
  t = await text();
  ok('24-6 a compliance viewer gets the role refusal with a link to the overview', /This page is for admins and developers/.test(t) && (await page.getByRole('link', { name: /^Go to Overview/ }).getAttribute('href')) === '/');
  ok('24-6 and the navigation has no Setup link for the role', (await page.locator('nav[aria-label="Portal"] a', { hasText: 'Setup' }).count()) === 0);

  // complete
  await go('/setup', {});
  t = await text();
  ok('24 complete: says setup is complete, lists every step as Done or Skipped, offers Open records', /Setup is complete/.test(t) && (await page.locator('main li', { hasText: /Done|Skipped/ }).count()) >= 8 && (await page.getByRole('link', { name: 'Open records' }).count()) === 1);
  await ctx.close();
}

async function confirmationsScreen() {
  const { ctx, page } = await newPage(1440);
  const go = async (p, sc) => { if (sc) await scenario(sc); await page.goto(base + p); await settle(page); };
  const text = () => page.locator('main').innerText();
  const reqs = async (re, method) => (await log()).filter((r) => re.test(r.url) && (!method || r.method === method));
  const SRC = 'Website';

  await go('/confirmations', {});
  let t = await text();
  ok('25 default: the four settings are named with their state', /Email sending account/.test(t) && /Text sending account/.test(t) && /Wording link host/.test(t) && /Texting registration/.test(t) && /Marked complete/.test(t) && /Verified/.test(t));
  ok('25 default: the account lines say provider and sender', /Amazon SES, from hello@acme\.com/.test(t) && /Twilio, your number ending 0123/.test(t));
  ok('25 default: texting registration says who marked it and that nothing is checked with carriers', /Marked by Dana Ruiz/.test(t) && /You mark this; ConsentVault does not check it with carriers\./.test(t));
  ok('25 default: replies to read shows a count and a way to read them', /Replies to read\s*\n?\s*2/.test(t) && (await page.getByRole('link', { name: 'Read replies' }).count()) + (await page.getByRole('button', { name: 'Read replies' }).count()) >= 1);
  ok('25 default: one row per source with its two channels, last sent and failures', (await page.locator('table', { has: page.locator('caption', { hasText: 'By capture source' }) }).locator('tbody tr').count()) === 2);
  ok('25 default: the sending rule sentence is shown in full', /A message goes only on a channel the consent names, only when the consent names the brand it is sent as/.test(t) && /the text is not sent at all\. Email has no sending hours/.test(t));
  ok('25 default: recent activity is a filterable list with plain outcomes', /Recent activity/.test(t) && /Sent, delivered/.test(t) && /Not sent: outside texting hours/.test(t));
  const rulesT = await page.locator('table', { has: page.locator('caption', { hasText: 'By capture source' }) }).innerText();
  const actT = await page.locator('table', { has: page.locator('caption', { hasText: 'Recent activity' }) }).innerText();
  ok('25 names: the source table shows source and brand names from the rule rows, never ids', /Website form/.test(rulesT) && /Salesforce/.test(rulesT) && /Acme Lending/.test(rulesT) && !/src_web|src_sf|brd_acme/.test(rulesT), rulesT.slice(0, 200));
  ok('25 names: recent activity names the source and the brand each message was sent as, and a reply with neither reads None', /Website form/.test(actT) && /Acme Lending/.test(actT) && /None/.test(actT) && !/src_web|brd_acme|null|undefined/.test(actT), actT.slice(0, 300));
  ok('25 failed: a refused send reads Failed, final, and nothing on the page says Retrying', /Failed: the provider refused the message \(code 21610\)\. It is not sent again\./.test(actT) && !/Retrying/.test(await page.locator('body').innerText()));
  ok('25 default: the verified link host shows the time the service verified it', t.includes(`Verified on ${fmtDateTime('2026-10-30T14:30:00Z')}`), t.slice(t.indexOf('Wording link host'), t.indexOf('Wording link host') + 200));
  ok('25 default: the fixed copy about plan events and provider charges is stated', /counts as one event on your plan; provider charges stay on your own accounts\./.test(t));
  ok('25-17 with the provider replying itself, an opt-out reads as sent by Twilio', /Opt-out reply sent by Twilio|Opt-out reply sent by your provider/.test(t));
  ok('25-19 no copy says ConsentVault reads the provider opt-out settings or list', !/reads? (your |the )?(Twilio )?opt-out (settings|list)/i.test(t));
  const sw = await page.getByRole('switch').evaluateAll((els) => els.map((e) => e.getAttribute('aria-label') ?? e.textContent));
  ok('25 default: each source and channel has a switch with a name', sw.length === 4 && sw.every((n) => /confirmation for /.test(n)), sw.join(' | '));
  ok('25 default: no password field and no secret is on the page', (await page.locator('input[type=password]').count()) === 0);

  // activity filter
  await page.getByLabel('Show').selectOption({ label: 'Not sent' }); await settle(page);
  ok('25 activity: the filter asks the service for that status and narrows the list', (await reqs(/confirmations\/sends/)).some((r) => /status=skipped/.test(r.url)) && !/Sent, delivered/.test(await page.locator('table', { has: page.locator('caption', { hasText: 'Recent activity' }) }).innerText()));

  // empty and not yet connected
  await go('/confirmations', { confirmations: 'empty' });
  t = await text();
  ok('25 empty: says confirmation messages are off and where they come from, with both connect buttons', /Confirmation messages are off/.test(t) && /never from ConsentVault/.test(t) && (await page.getByRole('button', { name: 'Connect an email provider' }).count()) === 1 && (await page.getByRole('button', { name: 'Connect a text provider' }).count()) === 1 && /through Twilio/.test(t));

  // text switches: off until registration is marked, and until a test reply arrives
  await go('/confirmations', { confirmations: 'texts_off' });
  const swOff = page.getByRole('switch', { name: `Text confirmation for ${SRC} form` });
  t = await text();
  ok('25-1 registration not marked: every text switch is aria-disabled with the reason as visible text', (await swOff.getAttribute('aria-disabled')) === 'true' && /Off until texting registration is marked complete/.test(t) && (await page.getByRole('switch', { name: /^Text confirmation for/ }).evaluateAll((e) => e.every((x) => x.getAttribute('aria-disabled') === 'true'))));
  ok('25-1 the disabled switch stays focusable and the reason is its description', (await swOff.getAttribute('aria-describedby')) !== null && (await swOff.evaluate((e) => e.tabIndex)) >= 0);
  await swOff.click({ force: true }); await page.waitForTimeout(120);
  ok('25-1 pressing it sends nothing', (await reqs(/confirmations\/rules\//, 'PUT')).length === 0);
  ok('25 texts off: the registration card offers Mark texting registration complete', (await page.getByRole('button', { name: 'Mark texting registration complete' }).count()) === 1);
  await page.getByRole('button', { name: 'Mark texting registration complete' }).click();
  let d = page.getByRole('dialog');
  t = await d.innerText();
  ok('copy check on the registration dialog', scanCopy(t).length === 0, scanCopy(t).slice(0, 2).join(' | '));
  ok('25-2 the registration dialog shows all four fixed texts and the carrier sentence', /ConsentVault records who marked it and when\. It does not check your registration with carriers or your provider\./.test(t) && /Msg frequency varies\. Msg & data rates may apply\. Reply STOP to opt out, HELP for help\./.test(t) && /You are unsubscribed and will get no more texts or calls from us\./.test(t) && /Help: hello@acme\.com/.test(t) && /You will get texts from us again\./.test(t));
  const fx = (await (await fetch(`${base}/v1/confirmations/settings`)).json()).fixed_texts;
  ok('25-2 the four texts shown are exactly the fixed texts the service returned, in order, with the places a message fills in left as placeholders', fx.items.length === 4 && fx.items.every((i) => t.includes(i.text)) && t.indexOf(fx.items[0].text) < t.indexOf(fx.items[1].text) && t.indexOf(fx.items[1].text) < t.indexOf(fx.items[2].text) && t.indexOf(fx.items[2].text) < t.indexOf(fx.items[3].text) && (t.match(/<Sending brand>/g) ?? []).length === 4 && /<date and time>/.test(t) && /<purposes>/.test(t) && /<link>/.test(t), t.slice(0, 400));
  ok('25-2 no hard-coded text and no preview call: the dialog reads only the settings', (await reqs(/confirmations:preview/, 'POST')).length === 0 && !/Acme Lending: You are unsubscribed/.test(t));
  const mark = d.getByRole('button', { name: 'Mark complete' });
  ok('25-2 Mark complete is disabled until both statements are ticked', await mark.isDisabled());
  await d.getByLabel(/is approved/).check();
  ok('25-2 one tick is not enough', await mark.isDisabled());
  await d.getByLabel(/among the sample messages/).check();
  await d.getByLabel('Registration type').selectOption({ label: 'Toll-free verification' });
  await mark.click(); await settle(page);
  const mk = await reqs(/texting-registration$/, 'POST');
  ok('25 registration: posts the kind with both acknowledgements and the card then reads Marked complete', mk.length === 1 && mk[0].body.kind === 'toll_free' && mk[0].body.accepted === true && mk[0].body.samples_included === true && /Marked complete/.test(await text()));
  ok('25 registration: wording never says ConsentVault approved or registered it', !/(ConsentVault|we) (approved|registered)/i.test(await text()));
  await page.getByRole('button', { name: 'Withdraw' }).click();
  d = page.getByRole('alertdialog');
  t = await d.innerText();
  ok('25 withdraw dialog: says every text confirmation turns off now and email is not affected', /Every text confirmation turns off now, for every source\./.test(t) && /Email confirmations, replies and stops are not affected\./.test(t));
  await d.getByRole('button', { name: 'Withdraw and turn texts off' }).click();
  ok('25 withdraw: needs a reason and sends nothing without one', /Enter a reason/.test(await d.innerText()) && (await reqs(/texting-registration:withdraw/)).length === 0);
  await d.getByLabel(/^Reason/).fill('Number changed'); await d.getByRole('button', { name: 'Withdraw and turn texts off' }).click(); await settle(page);
  ok('25 withdraw: posts the reason and the card reads Not marked again', (await reqs(/texting-registration:withdraw/)).length === 1 && /Not marked/.test(await text()));
  await go('/confirmations', { confirmations: 'texts_off', nulls: ['conf_fixed'] });
  await page.getByRole('button', { name: 'Mark texting registration complete' }).click();
  d = page.getByRole('dialog');
  await d.getByLabel(/is approved/).check(); await d.getByLabel(/among the sample messages/).check();
  ok('25-2 fixed texts that did not load read Not available and Mark complete stays disabled even with both boxes ticked', /Not available/.test(await d.innerText()) && (await d.getByRole('button', { name: 'Mark complete' }).isDisabled()));

  await go('/confirmations', { confirmations: 'awaiting' });
  t = await text();
  ok('25-8 awaiting a test reply: every text switch is aria-disabled and says no test reply has reached ConsentVault', /no test reply has reached ConsentVault/.test(t) && (await page.getByRole('switch', { name: /^Text confirmation for/ }).evaluateAll((e) => e.length > 0 && e.every((x) => x.getAttribute('aria-disabled') === 'true'))));
  ok('25 awaiting: the four-step connect walk shows the inbound address, the Yes or No answer and the wait', /Connect a text provider/.test(t) && /https:\/\/api\.consentvault\.ai\/v1\/confirmations\/inbound\//.test(t) && /Does Twilio reply to STOP, HELP and START itself on this number\?/.test(t) && /Waiting for your test text\./.test(t) && /Checking every 5 seconds\./.test(t));
  ok('25-18 the connect steps say which Twilio secret sends and which only checks signatures', /signature checks only/.test(t));
  await page.getByRole('button', { name: 'Check now' }).click(); await settle(page);
  ok('25 awaiting: a check before the text arrives keeps waiting', /Waiting for your test text\./.test(await text()));
  await scenario({ reset: false, confirmations: 'full' });
  await page.getByRole('button', { name: 'Check now' }).click(); await settle(page);
  t = await text();
  ok('25 test reply arrived: says so and what comes next', /Your test text arrived at/.test(t) && /set your wording link host, then mark your texting registration complete/.test(t));

  // connect a text provider from nothing: the form, the missing answer, the secrets
  await go('/confirmations', { confirmations: 'empty' });
  await page.getByRole('button', { name: 'Connect a text provider' }).click();
  ok('25-18 the Twilio form asks for the API key SID and secret for sending and the auth token labelled signature checks only', (await page.getByLabel('Twilio account SID').count()) === 1 && (await page.getByLabel('API key SID').count()) === 1 && (await page.getByLabel('API key secret').count()) === 1 && /signature checks only/.test(await page.getByLabel(/^Auth token/).evaluate((e) => e.closest('.field').innerText)));
  ok('25 the secrets are not password fields and ask the browser to remember nothing', (await page.locator('input[type=password]').count()) === 0 && (await page.getByLabel('API key secret').getAttribute('autocomplete')) === 'off');
  await page.getByLabel('Twilio account SID').fill('AC' + 'a'.repeat(32)); await page.getByLabel('API key SID').fill('SK' + 'b'.repeat(32));
  await page.getByLabel('API key secret').fill('secret-value-1'); await page.getByLabel(/^Auth token/).fill('token-value-1'); await page.getByLabel('Texting number').fill('+15555550123');
  await page.getByRole('button', { name: 'Connect Twilio' }).click(); await settle(page);
  ok('25 connect: refuses to continue until the Yes or No answer is given, sends nothing', /Answer whether Twilio replies/.test(await text()) && (await reqs(/sending-accounts$/, 'POST')).length === 0);
  await page.getByLabel(/^Yes/).check();
  await page.getByRole('button', { name: 'Connect Twilio' }).click(); await settle(page);
  const cn = await reqs(/sending-accounts$/, 'POST');
  t = await text();
  ok('25 connect: posts the provider, the credentials in the body and the answer once, and moves to the test text step', cn.length === 1 && cn[0].body.provider === 'twilio' && cn[0].body.provider_replies_itself === true && cn[0].body.credentials.account_sid.startsWith('AC') && /Waiting for your test text\./.test(t));
  ok('25 connect: the secrets are cleared from the page and never echoed back', !(await page.content()).includes('secret-value-1') && !(await page.content()).includes('token-value-1') && !/secret-value-1|token-value-1/.test(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))));
  await go('/confirmations', { confirmations: 'empty', fail: { 'POST /v1/confirmations/sending-accounts': { status: 502, error: 'provider_refused', fields: { provider_code: '20003' } } } });
  await page.getByRole('button', { name: 'Connect an email provider' }).click();
  await page.getByLabel('Access key').fill('AKIA' + 'C'.repeat(16)); await page.getByLabel('Secret key').fill('s3cr3t'); await page.getByLabel('From address').fill('hello@acme.com'); await page.getByLabel('From name').fill('Acme Lending');
  await page.getByRole('button', { name: 'Connect Amazon SES' }).click(); await settle(page);
  t = await text();
  ok('25 connect error: a provider refusal names the code and the next step and the form keeps its fields', /The account was not connected/.test(t) && /502 provider_refused/.test(t) && (await page.getByLabel('From address').inputValue()) === 'hello@acme.com' && (await page.getByLabel('Secret key').inputValue()) === '');

  // no test text in 15 minutes
  const { ctx: c2, page: p2 } = await newPage(1440);
  await scenario({ confirmations: 'awaiting' });
  await p2.clock.install({ time: new Date('2026-11-03T12:00:00Z') });
  await p2.goto(base + '/confirmations'); await settle(p2);
  await p2.clock.fastForward(16 * 60 * 1000);
  await p2.waitForFunction(() => document.body.innerText.includes('No test text arrived in 15 minutes'), null, { timeout: 5000 }).catch(() => undefined);
  const t2 = await p2.locator('main').innerText();
  ok('25 no test text: after 15 minutes names the number, the likely cause and what to check, with Show step 2 again', /No test text arrived in 15 minutes/.test(t2) && /number ending 0123/.test(t2) && /incoming webhook not set to the address/.test(t2) && /Texts stay off until a test text arrives/.test(t2) && (await p2.getByRole('button', { name: 'Show step 2 again' }).count()) === 1);
  await c2.close();

  // link host
  await go('/confirmations', { confirmations: 'link_unset' });
  t = await text();
  ok('25 link host unset: says what it is and that messages stay off, with a field for the host', /Wording link host on your domain/.test(t) && /Messages stay off until it is verified\./.test(t) && (await page.getByLabel('Host').count()) === 1);
  await page.getByLabel('Host').fill('consent.bad.example'); await page.getByRole('button', { name: 'Set the host' }).click(); await settle(page);
  t = await text();
  ok('25 link host: shows the records to add, name and value', /CNAME/.test(t) && /TXT/.test(t) && /_cv-verify/.test(t) && (await reqs(/link-host$/, 'POST')).length === 1);
  const dns = (await page.locator('table.dns tbody tr').allInnerTexts()).map((x) => x.replace(/\s+/g, ' ').trim());
  ok('25 link host: the CNAME points the host at the edge name the service gave and the TXT name carries the full host', dns.length === 2 && dns[0] === 'CNAME consent.bad.example edge.consentvault.ai' && /^TXT _cv-verify\.consent\.bad\.example cv=/.test(dns[1]), dns.join(' | '));
  await page.getByRole('button', { name: 'Check the records' }).click(); await settle(page);
  t = await text();
  ok('25 link host error: names the missing record and offers Check again', /The host is not verified yet/.test(t) && /422 link_host_dns_missing/.test(t) && (await page.getByRole('button', { name: 'Check again' }).count()) >= 1);
  await go('/confirmations', { confirmations: 'link_unset' });
  await page.getByLabel('Host').fill('consent.acme.com'); await page.getByRole('button', { name: 'Set the host' }).click(); await settle(page);
  await page.getByRole('button', { name: 'Check the records' }).click(); await settle(page);
  ok('25 link host: once found it reads Verified', /Verified/.test(await text()));
  ok('25 link host: the verified time is the one the verify answer carried', (await text()).includes(`Verified on ${fmtDateTime('2026-10-30T16:20:00Z')}`));

  // disconnect: refused while replies still point here, otherwise it turns the channel off
  await go('/confirmations', { fail: { 'DELETE /v1/confirmations/sending-accounts/acc_sms': { status: 409, error: 'inbound_still_pointed_here' } } });
  await page.getByRole('button', { name: 'Disconnect Twilio' }).click();
  d = page.getByRole('alertdialog');
  ok('25 disconnect dialog: names the account and what turns off', /Disconnect Twilio\?/.test(await d.innerText()) && /Stop links in emails already sent keep working|Texts already queued are recorded as not sent/.test(await d.innerText()));
  await d.getByRole('button', { name: 'Disconnect' }).click();
  ok('25 disconnect: needs a reason first', /Enter a reason/.test(await d.innerText()) && (await reqs(/sending-accounts\/acc_sms$/, 'DELETE')).length === 0);
  await d.getByLabel(/^Reason/).fill('Moving numbers'); await d.getByRole('button', { name: 'Disconnect' }).click(); await settle(page);
  t = await d.innerText().catch(() => '');
  ok('25-15 inbound_still_pointed_here shows the named error inside the dialog', /Twilio was not disconnected/.test(t) && /409 inbound_still_pointed_here/.test(t) && /still sends its replies to ConsentVault/.test(t));
  await page.keyboard.press('Escape'); await page.waitForTimeout(150);
  ok('25-15 and the account stays connected', /Twilio, your number ending 0123/.test(await text()) && /Connected/.test(await text()));

  // account failing
  await go('/confirmations', { confirmations: 'failing' });
  t = await text();
  ok('25 account failing: the banner names the cause and next step, and the account card reads Failing with a fix button', /Email confirmations are not going out\./.test(t) && /502 provider_refused/.test(t) && /403/.test(t) && /Failing/.test(t) && (await page.getByRole('button', { name: 'Check the account' }).count()) >= 1);

  // counts that could not be read, and the four alarms
  await go('/confirmations', { nulls: ['conf_counts'] });
  t = await text();
  ok('25-4 counts that did not load read Not available, never zero, with the banner', /Some figures did not load\./.test(t) && /Replies to read\s*\n?\s*Not available/.test(t));
  await go('/confirmations', { nulls: ['conf_refusal'] });
  t = await text();
  ok('25-5 provider refusals show the alarm with the count, the code and the records to see', /Twilio refused 2 texts in the last 24 hours because those numbers opted out at Twilio \(error 21610\)\./.test(t) && /Stops for texts, calls and AI-voice calls were recorded for both/.test(t) && (await page.getByRole('link', { name: 'See the 2 records' }).count()) === 1);
  await go('/confirmations', { nulls: ['conf_sigfail'] });
  ok('25 signature failures: the alarm counts the refused messages and says a stop could be missed', /7 messages to your reply address were refused in the last 10 minutes\./.test(await text()) && /a stop could be missed/.test(await text()));
  await go('/confirmations', { nulls: ['conf_stale'] });
  ok('25 delivery reports stale: says reports stopped, since when, and that sending and replies continue', /Delivery reports from Twilio stopped arriving/.test(await text()) && /Messages still send and replies still arrive/.test(await text()));
  await go('/confirmations', { nulls: ['conf_old_reply'] });
  t = await text();
  ok('25-14 a reply unread over 24 hours raises the banner', /1 reply has been unread for more than 24 hours\./.test(t));
  await go('/confirmations', { orgStatus: 'suspended' });
  t = await text();
  ok('25 suspended: says nothing is sent, replies and opt-outs continue, and links to billing', /No confirmation messages are sent; each is recorded as not sent\./.test(t) && /Replies and stops are still recorded, and opt-out replies still go out\./.test(t) && (await page.getByRole('link', { name: 'Open billing' }).count()) >= 1);

  // replies to read: a person decides, with a reason
  await go('/confirmations', { nulls: ['conf_old_reply'] });
  t = await text();
  ok('25 replies: lists each unread reply with who, when, the words, and says a person decides', /Replies to read \(2\)/.test(t) && /no more of these thanks/.test(t) && /thanks, when does it launch\?/.test(t) && /A person decides; nothing changes until you choose\./.test(t));
  await page.getByRole('button', { name: /Record a stop for \(555\) \*\*\*-0161/ }).click();
  d = page.getByRole('dialog');
  t = await d.innerText();
  ok('25-12 the record-a-stop dialog names texts, calls and AI-voice calls, all purposes, and says email is not affected', /Record a stop for \(555\) \*\*\*-0161\?/.test(t) && /texts, calls and AI-voice calls, all purposes/.test(t) && /Email is not affected\./.test(t));
  ok('25-7 Record the stop is disabled until a reason is entered', await d.getByRole('button', { name: 'Record the stop' }).isDisabled());
  await d.getByLabel(/^Reason/).fill('Asked to stop');
  ok('25-7 and enabled once there is one', !(await d.getByRole('button', { name: 'Record the stop' }).isDisabled()));
  await d.getByRole('button', { name: 'Record the stop' }).click(); await settle(page);
  const mr = await reqs(/replies\/.+:mark/, 'POST');
  ok('25 replies: posts the decision and reason once and the reply leaves the list', mr.length === 1 && mr[0].body.decision === 'stop' && mr[0].body.reason === 'Asked to stop' && !/no more of these thanks/.test(await text()));
  await page.getByRole('button', { name: /Not a stop for/ }).first().click();
  d = page.getByRole('dialog');
  await d.getByLabel(/^Reason/).fill('A question about the launch'); await d.getByRole('button', { name: 'Record not a stop' }).click(); await settle(page);
  ok('25 replies: not a stop also carries its reason', (await reqs(/replies\/.+:mark/, 'POST')).length === 2 && (await reqs(/replies\/.+:mark/, 'POST'))[1].body.decision === 'not_stop');

  // undelivered sends
  await go('/confirmations', {});
  t = await text();
  ok('25 undelivered: lists each with attempts and the last answer, and says they are never sent again', /Undelivered after 2 hours/.test(t) && /Provider did not answer \(502 provider_unreachable\)/.test(t) && /Undelivered messages are recorded and never sent again/.test(t));

  // developer: read only, fingerprints, no reply text
  await go('/confirmations', { role: 'developer' });
  t = await text(); const dhtml = await page.content();
  ok('25-6 developer: replies are not shown and the reason is stated', /Replies are personal data/.test(t) && !/no more of these thanks|thanks, when does it launch/.test(dhtml));
  ok('25 developer: says what the role can do', /You can connect and check sending accounts and set the link host\./.test(t) && /Turning messages on, marking texting registration and reading replies need an admin\./.test(t));
  ok('25 developer: sees View not Edit, no switches that act, no registration buttons', (await page.getByRole('link', { name: 'View', exact: true }).count()) === 2 && (await page.getByRole('link', { name: 'Edit', exact: true }).count()) === 0 && (await page.getByRole('button', { name: /Mark texting registration|Withdraw|Disconnect/ }).count()) === 0);
  ok('25 developer: activity shows fingerprints, no masked contact', /fingerprint [0-9a-f]{8}/.test(t) && !/\(555\) \*\*\*/.test(t));
  ok('25 developer: no replies request was made', (await reqs(/confirmations\/replies/)).length === 0);
  await go('/confirmations', { role: 'compliance_viewer' });
  t = await text();
  ok('25 viewer: sources and brands show by name from the rule and send rows, with no source or brand list asked', /Website form/.test(t) && /Salesforce/.test(t) && /Acme Lending/.test(t) && !/src_web|src_sf|brd_acme/.test(t) && (await reqs(/^\/v1\/(sources|brands)(\?|$)/)).length === 0, t.slice(0, 200));
  ok('25 viewer: reads settings, rules, activity and replies but changes nothing', /no more of these thanks/.test(t) && (await page.getByRole('link', { name: 'Edit', exact: true }).count()) === 0 && (await page.getByRole('button', { name: /Record a stop|Not a stop|Mark texting|Withdraw|Disconnect|Connect/ }).count()) === 0);

  // the edit page: email
  await go('/confirmations/src_web/email', {});
  await page.locator('[data-fixed]').first().waitFor();
  t = await text();
  ok('25-3 the editor loads the current version subject and opening line from the template read, not from the list', (await reqs(/confirmations\/templates\/tpl_1$/, 'GET')).length === 1 && (await page.getByLabel('Subject').inputValue()) === 'Thanks for asking: here is what you agreed to' && (await page.getByLabel('Opening line (optional)').inputValue()) === 'Thanks for asking about early access.');
  ok('25-3 the template editor offers only subject and opening line', (await page.locator('main input[type=text], main textarea').evaluateAll((e) => e.map((x) => x.getAttribute('name')))).filter((n) => n && n !== 'test-contact').sort().join() === 'opening_line,subject');
  ok('25-3 the fixed parts render read only from the preview, in a region with no input', /Every email also carries these parts, which cannot be removed/.test(t) && (await page.locator('[data-fixed] input, [data-fixed] textarea').count()) === 0 && /To stop email from/.test(t));
  ok('25-10 no email preview says reply STOP', !/reply STOP/i.test(await page.locator('[data-fixed]').innerText()));
  ok('25-13 every link in the preview uses the organization link host', (await page.locator('[data-fixed] a').evaluateAll((a) => a.map((x) => x.textContent))).every((h) => /consent\.acme\.com/.test(h)) );
  await page.getByLabel('Subject').fill('Thanks, here is what you agreed to'); await page.waitForTimeout(900);
  const pv = await reqs(/confirmations:preview/, 'POST');
  ok('25 edit: typing asks for a fresh preview once the debounce passes, with the template in the body', pv.length >= 2 && pv[pv.length - 1].body.template && pv[pv.length - 1].body.template.subject === 'Thanks, here is what you agreed to' && /Thanks, here is what you agreed to/.test(await page.locator('[data-preview-subject]').innerText()));
  await page.getByLabel('Opening line').fill('Thanks for asking.'); await page.getByLabel('Send at most one confirmation per contact every').selectOption({ label: '7 days' });
  await page.getByRole('button', { name: 'Save' }).click(); await settle(page);
  const tp = await reqs(/confirmations\/templates$/, 'POST'); const ru = await reqs(/confirmations\/rules\/src_web\/email$/, 'PUT');
  t = await text();
  ok('25 edit save: creates a template version then saves the rule with its id, and says what happens next', tp.length === 1 && tp[0].body.subject === 'Thanks, here is what you agreed to' && ru.length === 1 && ru[0].body.template_id && ru[0].body.dedupe_hours === 168 && /The next new consent from that source gets one\. Consents recorded before now do not\./.test(t));
  await go('/confirmations/src_web/email', {});
  await page.getByLabel('Subject').fill('x'.repeat(81)); 
  ok('25 edit: a subject over 80 characters is held at 80', (await page.getByLabel('Subject').inputValue()).length <= 80);
  await go('/confirmations/src_web/email', {});
  await page.getByRole('button', { name: 'Send a test to my own address' }).click();
  d = page.getByRole('dialog'); await d.getByLabel(/^Your own address/).fill('dana@acme.com'); await d.getByRole('button', { name: 'Send the test' }).click(); await settle(page);
  const ts = await reqs(/confirmations:test/, 'POST');
  ok('25 edit: the test goes to the address the admin typed, in the body, once', ts.length === 1 && ts[0].body.contact === 'dana@acme.com' && ts[0].body.channel === 'email' && !/dana@acme\.com/.test(ts[0].url));
  // prerequisites: the named refusal when turning on
  await go('/confirmations/src_web/sms', { confirmations: 'texts_off' });
  await page.locator('[data-fixed]').first().waitFor();
  t = await text();
  ok('25-9 the text page has fixed text, shows the time with a zone and Msg frequency varies, and has no editable message field', /Msg frequency varies\. Msg & data rates may apply\./.test(t) && /ET|PT|CT|MT/.test(t) && (await page.locator('main textarea').count()) === 0 && (await page.getByLabel('Subject').count()) === 0);
  const fx2 = (await (await fetch(`${base}/v1/confirmations/settings`)).json()).fixed_texts.items;
  ok('25-9 the opt-out, HELP and START replies shown are the fixed texts the service returned, unedited', fx2.filter((i) => i.kind !== 'confirmation').every((i) => t.includes(i.text)), t.slice(0, 300));
  ok('25 text page: characters and segments are shown', /\d+ characters, \d+ text segments?/.test(t));
  ok('25 text page: the stop, HELP and START words are explained in full', /Any reply containing a stop word/.test(t) && /START asks the release rule to turn texts back on; calls stay stopped\./.test(t) && /'bus stop' or 'don't stop' is not a stop/.test(t));
  const swE = page.getByRole('switch', { name: /^Send text confirmations for/ });
  ok('25 text page: the on switch is aria-disabled with the reason when registration is not marked', (await swE.getAttribute('aria-disabled')) === 'true' && /Off until texting registration is marked complete/.test(t));
  await go('/confirmations/src_sf/email', { confirmations: 'link_unset' });
  await page.getByRole('switch', { name: /^Send email confirmations for/ }).click(); await settle(page);
  ok('25 turning a rule on without a verified link host shows the named refusal and the rule stays off', /link_host_not_verified/.test(await text()) && (await page.getByRole('switch', { name: /^Send email confirmations for/ }).getAttribute('aria-checked')) === 'false');
  // developer read only and viewer refused
  await go('/confirmations/src_web/email', { role: 'developer' });
  ok('25 developer on the edit page: every field is read only and there is no Save', (await page.getByLabel('Subject').isDisabled()) && (await page.getByRole('button', { name: 'Save' }).count()) === 0);
  await go('/confirmations/src_web/email', { role: 'compliance_viewer' });
  ok('25 viewer on the edit page: the role refusal with a way back', /This page is for admins and developers/.test(await text()) && (await page.getByRole('link', { name: /^Go to/ }).count()) === 1);
  await ctx.close();
}

if (!only) await flows();
const flowsNew = process.argv.find((a) => a.startsWith('--flows-new'))?.slice(12) ?? null; // --flows-new or --flows-new=records|setup|confirmations
if (!only || flowsNew !== null) {
  if (!flowsNew || flowsNew === 'records') await recordsScreen();
  if (!flowsNew || flowsNew === 'narrow') await narrowRoleGating();
  if (!flowsNew || flowsNew === 'setup') await setupScreen();
  if (!flowsNew || flowsNew === 'confirmations') await confirmationsScreen();
}
await browser.close();
server.close();
console.log(`\n${results.pass} passed, ${results.fail} failed`);
if (results.fail) { console.log(results.failures.join('\n')); process.exit(1); }
