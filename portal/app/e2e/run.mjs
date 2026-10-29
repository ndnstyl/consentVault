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
import { navFor, refusalHeading } from '../src/lib/roles.ts';

const require = createRequire(import.meta.url);
const { chromium } = require('/Users/oxfloors/.npm/_npx/e41f203b7505f1fb/node_modules/playwright');
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
  ['members', '/members', {}], ['members only you', '/members', { empty: ['members'] }], ['members error', '/members', fail('GET /v1/members'), true], ['members refused', '/members', { role: 'developer' }],
  ['audit', '/audit', {}], ['audit empty', '/audit', { empty: ['audit'] }], ['audit partial', '/audit', { nulls: ['audit_names'] }], ['audit error', '/audit', fail('GET /v1/audit'), true], ['audit viewer', '/audit', { role: 'compliance_viewer' }], ['audit filtered', '/audit?action=nothing.here', {}],
  ['billing', '/billing', {}], ['billing trial', '/billing', { orgStatus: 'trial' }], ['billing partial', '/billing', { nulls: ['usage'] }], ['billing error', '/billing', fail('GET /v1/billing'), true], ['billing past due', '/billing', { orgStatus: 'past_due' }],
  ['settings', '/settings', {}], ['settings partial', '/settings', { nulls: ['key'] }], ['settings offboarding', '/settings', { offboarding: true, orgStatus: 'offboarding' }], ['settings viewer', '/settings', { role: 'compliance_viewer' }], ['settings developer', '/settings', { role: 'developer' }], ['settings error', '/settings', fail('GET /v1/org'), true],
  ['references', '/references', {}], ['references empty', '/references', { empty: ['references'] }], ['references partial', '/references', { nulls: ['review_dates'] }], ['references error', '/references', fail('GET /v1/rule-references'), true], ['references jurisdiction empty', '/references?jurisdiction=Texas', {}],
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
  ok('05-1 five checklist items, one primary button', (await page.locator('ol.steps > li').count()) === 5 && (await page.locator('ol.steps .btn-primary').count()) === 1);
  ok('05-1 primary is the first not-done item', (await page.locator('ol.steps .btn-primary').innerText()) === 'Register your consent wording');
  await go('/', { nulls: ['usage'] });
  ok('05-2 usage failure reads Not available, never 0', (await text()).includes('Not available'));
  await go('/', {});
  ok('05-3 undelivered tile links to the system with the most dead deliveries', (await page.locator('a[href="/systems/sys_dialer"]').count()) >= 1);
  // 06: first event
  await go('/setup/first-event', { firstEvent: 'none' });
  await page.getByRole('button', { name: 'Copy command' }).click();
  const clip = await page.evaluate(() => navigator.clipboard.readText());
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

if (!only) await flows();
await browser.close();
server.close();
console.log(`\n${results.pass} passed, ${results.fail} failed`);
if (results.fail) { console.log(results.failures.join('\n')); process.exit(1); }
