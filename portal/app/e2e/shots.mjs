// Writes screenshots of key screens to e2e/shots for a visual review.  node e2e/shots.mjs [name]
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMock } from '../mock/server.ts';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const here = path.dirname(fileURLToPath(import.meta.url));
const mock = createMock();
const server = mock.server(path.resolve(here, '..', 'out'), null);
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;
const setScenario = (s) => fetch(`${base}/__mock/scenario`, { method: 'POST', body: JSON.stringify(s) });
const browser = await chromium.launch();
const list = [
  ['overview', '/', {}, 1440], ['overview-m', '/', {}, 375], ['overview-new', '/', { setup: 'new', firstEvent: 'none', orgStatus: 'trial' }, 1440],
  ['creds', '/credentials', {}, 1440], ['cred-new-m', '/credentials/new', {}, 375],
  ['system', '/systems/sys_dialer', {}, 1440], ['sign-in', '/sign-in', {}, 1440], ['first-event', '/setup/first-event', { firstEvent: 'none' }, 1440], ['sources-m', '/sources', {}, 375], ['audit', '/audit', {}, 1440],
];
const only = process.argv[2];
for (const [name, p, s, w] of list) {
  if (only && name !== only) continue;
  await setScenario(s);
  const ctx = await browser.newContext({ viewport: { width: w, height: w < 500 ? 800 : 900 }, colorScheme: process.env.DARK ? 'dark' : 'light' });
  const page = await ctx.newPage();
  await page.goto(base + p);
  await page.waitForFunction(() => !document.querySelector('[aria-busy="true"]'), null, { timeout: 5000 }).catch(() => undefined);
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(here, 'shots', `${name}${process.env.DARK ? '-dark' : ''}.png`), fullPage: true });
  await ctx.close();
}
await browser.close();
server.close();
