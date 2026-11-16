// Tutorials screen in a real browser: all eight videos present and loadable, no sideways scroll, axe clean, and screenshots at 375 and 1440.
//   node e2e/tutorials.mjs [--shots <folder>]     (build first: npm run build)
// Chromium from Playwright has no H.264 decoder, so the run uses installed Google Chrome when present; with neither a decoder nor Chrome the
// playback checks fail loudly rather than pass on metadata that was never read.
import { createRequire } from 'node:module';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createMock } from '../mock/server.ts';
import { TUTORIALS } from '../src/lib/tutorials.ts';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const axeSrc = fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const here = path.dirname(fileURLToPath(import.meta.url));
const shotsArg = process.argv.indexOf('--shots');
const shots = shotsArg > 0 ? path.resolve(process.argv[shotsArg + 1]) : path.join(here, 'shots');
fs.mkdirSync(shots, { recursive: true });
const mock = createMock();
const server = mock.server(path.resolve(here, '..', 'out'), null);
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;
const fails = [];
const ok = (n, c, d = '') => { if (!c) { fails.push(`${n}${d ? `: ${d}` : ''}`); console.log(`  FAIL ${n}${d ? `: ${d}` : ''}`); } else console.log(`  ok ${n}`); };
let browser;
try { browser = await chromium.launch({ channel: 'chrome' }); } catch { browser = await chromium.launch(); }
for (const [w, h] of [[375, 800], [1440, 900]]) for (const scheme of ['light', 'dark']) {
  const tag = `${w}-${scheme}`;
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, colorScheme: scheme });
  const page = await ctx.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(`${base}/tutorials`);
  await page.waitForSelector('h1:has-text("Tutorials")', { timeout: 8000 });
  ok(`${tag} eight videos`, (await page.locator('video').count()) === 8);
  ok(`${tag} header link`, (await page.locator('a.tutorials-btn').count()) === 1);
  ok(`${tag} no sideways scroll`, await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), await page.evaluate(() => `${document.documentElement.scrollWidth} > ${window.innerWidth}`));
  await page.waitForFunction(() => [...document.querySelectorAll('video')].every((v) => v.readyState >= 1 || v.error), null, { timeout: 15000 }).catch(() => undefined);
  const state = await page.evaluate(() => [...document.querySelectorAll('video')].map((v) => ({ d: v.duration, e: v.error ? v.error.code : 0 })));
  ok(`${tag} every video loads with a duration`, state.every((s) => s.e === 0 && s.d > 30), JSON.stringify(state));
  if (scheme === 'light') {
    const played = await page.evaluate(async () => {
      const v = document.querySelector('video'); v.muted = true;
      await v.play(); await new Promise((r) => setTimeout(r, 1500)); return { t: v.currentTime, paused: v.paused };
    });
    ok(`${tag} the first video plays`, played.t > 0.5 && !played.paused, JSON.stringify(played));
  }
  await page.evaluate(axeSrc);
  const axe = await page.evaluate(async () => (await window.axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21aa'] })).violations.map((v) => `${v.id}:${v.nodes.length}`));
  ok(`${tag} axe`, axe.length === 0, axe.join(','));
  ok(`${tag} console clean`, errors.length === 0, errors.join(' | '));
  if (scheme === 'light') await page.screenshot({ path: path.join(shots, `tutorials-${w}.png`), fullPage: true });
  await ctx.close();
}
await browser.close(); server.close();
console.log(fails.length ? `FAILED ${fails.length}` : `PASS (${TUTORIALS.length} videos)`);
process.exit(fails.length ? 1 : 0);
