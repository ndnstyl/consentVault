import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const src = (p: string) => readFileSync(new URL(`../src/${p}`, import.meta.url), 'utf8');

test('the error card swaps to the self-refreshing starting page on vault_starting', () => {
  const ui = src('components/ui.tsx');
  assert.match(ui, /err\.code === 'vault_starting' && onRetry\) return <StartingBlock/);
  assert.match(ui, /setInterval\(onRetry, 15000\)/);
  assert.match(ui, /ConsentVault is starting/);
});

test('the shell and the overview hand the reload to the error card so the starting page polls', () => {
  assert.match(src('components/Shell.tsx'), /err=\{s\.error\} onRetry=\{s\.reload\}/);
  assert.match(src('screens/overview.tsx'), /err=\{res\.error\} onRetry=\{res\.reload\}/);
});
