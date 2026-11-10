import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { scanCopy } from '../src/lib/copycheck.ts';

const SRC = new URL('../src', import.meta.url).pathname;
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => { const p = join(dir, n); return statSync(p).isDirectory() ? files(p) : [p]; });
}
const all = files(SRC).filter((f) => /\.(ts|tsx|css)$/.test(f));
const hits = (re: RegExp, skip: RegExp[] = []) => all.filter((f) => !skip.some((s) => s.test(f))).flatMap((f) => readFileSync(f, 'utf8').split('\n').map((l, i) => ({ f, i, l })).filter(({ l }) => re.test(l)).map(({ f: ff, i }) => `${ff}:${i + 1}`));

test('X1: no link to /policies anywhere in src', () => {
  assert.deepEqual(hits(/\/policies/), []);
});

test('X3: no proceed-or-hold chip, label or style in src', () => {
  assert.deepEqual(hits(/PolicyChip|policyLabel|pol-proceed|pol-hold|'proceed'|'hold'/), []);
});

test('X4: the copy scan refuses gate check and your policy wording', () => {
  assert.ok(scanCopy('Gate checks this period').length > 0);
  assert.ok(scanCopy('Your policy: proceed').length > 0);
  assert.deepEqual(scanCopy('Contact checks this period'), []);
});

test('X4: no rendered source string says gate check or your policy', () => {
  assert.deepEqual(hits(/gate check|your policy/i, [/copycheck\.ts$/]), []);
});

test('X5: checklists carry no tie to policies', () => {
  assert.deepEqual(hits(/for holds|usedBy/), []);
});

test('X6: the attestation template is gone', () => {
  assert.deepEqual(hits(/ATTESTATION_TEMPLATE|ATTEST_RE/), []);
  const rules = join(SRC, '../../design/copy-rules.md');
  if (existsSync(rules)) assert.doesNotMatch(readFileSync(rules, 'utf8'), /your policy: proceed|ATTESTATION_TEMPLATE|attestation text/i);
});
