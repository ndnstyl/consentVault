// Renders the stop-notice pop-up against the mock at 1280 and 390 wide, saves two screenshots, and checks the pop-up closes only
// on acknowledgement.   node e2e/stop-notice-shots.mjs   (build first: npx next build)
import { createRequire } from 'node:module';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createMock } from '../mock/server.ts';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const out = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'out');
const shots = process.argv.find((a) => a.startsWith('--out='))?.slice(6) ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'shots');
fs.mkdirSync(shots, { recursive: true });
const NOTE = 'ConsentVault has recorded this stop. Acting on it in your own systems is up to you.';
const mock = createMock();
const server = mock.server(out, null);
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;
const scenario = (s) => fetch(`${base}/__mock/scenario`, { method: 'POST', body: JSON.stringify(s) });
const browser = await chromium.launch();
let bad = 0;
const check = (name, cond, detail = '') => { if (!cond) { bad++; console.log(`FAIL ${name} ${detail}`); } else console.log(`ok   ${name}`); };

for (const [label, width, height] of [['desktop', 1280, 900], ['phone', 390, 844]]) {
  await scenario({ reset: true, stopNotices: 'waiting' });
  const page = await (await browser.newContext({ viewport: { width, height } })).newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(base + '/');
  const dialog = page.getByRole('alertdialog');
  await dialog.waitFor({ timeout: 8000 });
  const text = await dialog.innerText();
  check(`${label}: masked phone shown`, text.includes('***-0177'));
  check(`${label}: the notify-only line shown`, text.includes(NOTE));
  check(`${label}: delivery words shown`, /CRM \(delivered\)/.test(text) && /Dialer \(waiting\)/.test(text) && /Text message/.test(text) && !/\bsms\b/.test(text) );
  check(`${label}: no full contact point`, !/\d{10}/.test(text) && !/[a-z]{2,}@example\.com/.test(text));
  check(`${label}: no horizontal scroll`, await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  check(`${label}: the page behind is dimmed`, await page.evaluate(() => getComputedStyle(document.querySelector('.overlay')).backgroundColor !== 'rgba(0, 0, 0, 0)'));
  await page.screenshot({ path: path.join(shots, `stop-notice-${label}.png`) });
  if (label === 'desktop') {
    await page.keyboard.press('Escape');
    await page.mouse.click(5, 5);
    await page.waitForTimeout(300);
    check('desktop: Escape and a click outside leave it open', await dialog.isVisible());
    await page.reload(); await dialog.waitFor({ timeout: 8000 });
    check('desktop: a reload brings it back (reading never clears it)', await dialog.isVisible());
    await page.getByRole('button', { name: 'I have seen this' }).click();
    await dialog.waitFor({ state: 'hidden', timeout: 8000 });
    check('desktop: acknowledging closes it', !(await dialog.isVisible()));
    await page.reload(); await page.waitForTimeout(1200);
    check('desktop: after acknowledging it stays gone', !(await dialog.isVisible()));
  }
  check(`${label}: no page errors`, errors.length === 0, errors.join('; '));
}
await browser.close(); server.close();
process.exit(bad ? 1 : 0);
