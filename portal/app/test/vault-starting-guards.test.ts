import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import './support/register-tsx.mjs';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
const ui = await import('../src/components/ui.tsx');
const { ApiError } = await import('../src/lib/api/client.ts');
const src = (p: string) => readFileSync(new URL(`../src/${p}`, import.meta.url), 'utf8');
const starting = () => new ApiError(503, 'vault_starting', '', null);
const h = React.createElement;

test('1a a mutation error with no reload gets a static notice, no timer, no reload', () => {
  const html = renderToStaticMarkup(h(ui.ErrorBlock, { title: 'The role was not changed', err: starting(), next: 'Try again.', headingLevel: 3 }));
  assert.match(html, /Not saved\. ConsentVault is starting; try again in about two minutes\./);
  assert.doesNotMatch(html, /vault_starting|503|Cause:/);
});
test('1b nothing in ui.tsx reloads the page', () => {
  assert.doesNotMatch(src('components/ui.tsx'), /location\.reload/);
});
test('1c a dialog keeps its typed text: the dialog error path passes no onRetry, so it can only be the static notice', () => {
  const d = src('components/Dialog.tsx');
  assert.match(d, /<ErrorBlock[^>]*err=\{err\}/);
  assert.doesNotMatch(d, /onRetry/);
});
test('1d every load error spot hands its reload to ErrorBlock as onRetry', () => {
  const bad: string[] = [];
  for (const f of readdirSync(new URL('../src/screens/', import.meta.url))) {
    src(`screens/${f}`).split('\n').forEach((l, i) => {
      if (l.includes('<ErrorBlock') && /status === 'error'|status === 'error'/.test(l) && !l.includes('onRetry')) bad.push(`${f}:${i + 1}`);
    });
  }
  assert.deepEqual(bad, []);
});
test('2 the retry loop stops after five minutes and gives up', () => {
  mock.timers.enable({ apis: ['setInterval'] });
  let retries = 0, gaveUp = 0;
  ui.startRetryLoop(() => { retries++; }, () => { gaveUp++; });
  mock.timers.tick(15000 * 40);
  mock.timers.reset();
  assert.equal(gaveUp, 1);
  assert.ok(retries >= 15 && retries <= 20, `retries ${retries}`);
});
test('3 the chart banner never prints a raw code', () => {
  const r = src('screens/records.tsx');
  assert.doesNotMatch(r, /\$\{summary\.error\.status\} \$\{summary\.error\.code\}/);
  assert.match(r, /causeLine\(summary\.error\.status, summary\.error\.code\)/);
});
test('4 the starting block honours the heading level and never moves focus', () => {
  const html = renderToStaticMarkup(h(ui.ErrorBlock, { title: 't', err: starting(), next: 'n', headingLevel: 3, onRetry: () => {} }));
  assert.match(html, /<h3>ConsentVault is starting<\/h3>/);
  assert.doesNotMatch(src('components/ui.tsx').split('export function StartingBlock')[1].split('export function ErrorBlock')[0], /\.focus\(/);
});
test('5 an export that failed with vault_starting is a static notice, never a timer', () => {
  const r = src('screens/records.tsx');
  assert.match(r, /The file was not built" err=\{new ApiError\(503, e\.failed_cause[^\n]*startingNotice=/);
  const html = renderToStaticMarkup(h(ui.ErrorBlock, { title: 'x', err: starting(), next: 'n', startingNotice: 'The file was not built. Export again in about two minutes.' }));
  assert.match(html, /The file was not built\. Export again/);
});
