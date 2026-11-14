// The dashboard's shipped headers file (public/_headers, served by the edge's static assets) isolates the page: no
// cross-origin embedding either way, no opener handle, and every browser feature off except writing to the clipboard
// (the copy buttons in src/components/ui.tsx).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const file = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public', '_headers');

function headersFor(pattern) {
  const out = {};
  let inBlock = false;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    if (!/^\s/.test(line)) { inBlock = line.trim() === pattern; continue; }
    if (inBlock) { const i = line.indexOf(':'); out[line.slice(0, i).trim()] = line.slice(i + 1).trim(); }
  }
  return out;
}

test('cross-origin isolation headers apply to every path', () => {
  const h = headersFor('/*');
  assert.equal(h['Cross-Origin-Opener-Policy'], 'same-origin');
  assert.equal(h['Cross-Origin-Resource-Policy'], 'same-origin');
  assert.equal(h['Cross-Origin-Embedder-Policy'], 'require-corp');
});

test('the permissions policy turns off every feature but clipboard writing', () => {
  const p = headersFor('/*')['Permissions-Policy'];
  assert.ok(p, 'no Permissions-Policy');
  const rules = Object.fromEntries(p.split(',').map((r) => r.trim().split('=')));
  assert.equal(rules['clipboard-write'], '(self)');
  for (const f of ['camera', 'microphone', 'geolocation', 'payment', 'usb', 'serial', 'bluetooth', 'hid', 'midi',
    'fullscreen', 'display-capture', 'clipboard-read', 'accelerometer', 'gyroscope', 'magnetometer', 'browsing-topics',
    'publickey-credentials-get', 'screen-wake-lock', 'xr-spatial-tracking', 'autoplay', 'encrypted-media', 'picture-in-picture']) {
    assert.equal(rules[f], '()', `${f} must be off`);
  }
  for (const [f, v] of Object.entries(rules)) if (f !== 'clipboard-write') assert.equal(v, '()', `${f} must be off`);
});
