import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const src = (p: string) => readFileSync(new URL(`../src/${p}`, import.meta.url), 'utf8');

test('the error card swaps to the self-refreshing starting page on vault_starting', () => {
  const ui = src('components/ui.tsx');
  assert.match(ui, /err\.code === 'vault_starting'\) return <StartingBlock/);
  assert.match(ui, /setInterval\(retry, 15000\)/);
  assert.match(ui, /window\.location\.reload\(\)/);
  assert.match(ui, /ConsentVault is starting/);
});

test('the shell and the overview hand the reload to the error card so the starting page polls', () => {
  assert.match(src('components/Shell.tsx'), /err=\{s\.error\} onRetry=\{s\.reload\}/);
  assert.match(src('screens/overview.tsx'), /err=\{res\.error\} onRetry=\{res\.reload\}/);
});

// Rendered, not read: every screen that passes only a "Try again" button in `actions` must still show the starting page.
import './support/register-tsx.mjs';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
const { ErrorBlock } = await import('../src/components/ui.tsx');
const { causeLine } = await import('../src/lib/copy.ts');
const { ApiError } = await import('../src/lib/api/client.ts');

const starting = () => new ApiError(503, 'vault_starting', '', null);

test('ErrorBlock with only actions (no onRetry) shows the starting page, not the red error', () => {
  const html = renderToStaticMarkup(React.createElement(ErrorBlock, { title: 'Billing did not load', err: starting(), next: 'Try again.', actions: React.createElement('button', null, 'Try again') }));
  assert.match(html, /ConsentVault is starting/);
  assert.doesNotMatch(html, /vault_starting|banner danger|role="alert"|Cause:/);
});

test('the records list error, as the Records screen renders it, shows the starting page on vault_starting', () => {
  const html = renderToStaticMarkup(React.createElement(ErrorBlock, { title: 'The records list did not load', err: starting(), override: undefined, next: 'Try again. Capture keeps recording while this page is down.', actions: React.createElement('button', null, 'Try again') }));
  assert.match(html, /ConsentVault is starting/);
  assert.doesNotMatch(html, /did not load|503|vault_starting/);
});

test('other errors still show the red error with the cause', () => {
  const html = renderToStaticMarkup(React.createElement(ErrorBlock, { title: 'Billing did not load', err: new ApiError(503, 'service_unavailable', '', null), next: 'Try again.' }));
  assert.match(html, /banner danger/);
});

test('a bare cause line (sign-in, invitations, confirmations) never carries the raw code', () => {
  assert.doesNotMatch(causeLine(503, 'vault_starting'), /503|vault_starting/);
  assert.match(causeLine(503, 'vault_starting'), /ConsentVault is starting/);
});
