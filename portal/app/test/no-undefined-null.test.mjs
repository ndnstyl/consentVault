import './support/register-tsx.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const { SessionContext } = await import('../src/lib/session.tsx');
const { RouterContext } = await import('../src/lib/router.tsx');
const { SetupView } = await import('../src/screens/setup.tsx');
const { RetentionHistory, retentionInForce, safeTarget } = await import('../src/screens/org.tsx');

// What a client must never read as text: a JavaScript hole, or a phone mask on something that is not a phone.
const HOLE = /\b(undefined|null|NaN)\b/;
const textOf = (html) => html.replace(/<[^>]*>/g, ' ').replace(/&#x27;|&quot;|&amp;/g, ' ');

// ---- the vault's own answers, built the way its handlers build them (src/consentvault/tenancy/setup.py, admin.py) ----
const ORDER = ['brand', 'source', 'wording', 'credential', 'first_event', 'policy', 'system', 'confirmations'];
const ROLES = { brand: ['admin'], source: ['admin', 'developer'], wording: ['admin'], credential: ['admin', 'developer'], first_event: ['admin', 'developer'], policy: ['admin'], system: ['admin', 'developer'], confirmations: ['admin'] };
const stepObj = (step, status) => ({
  step, status, required: step !== 'system' && step !== 'confirmations',
  evidence: status === 'done' ? { kind: step, id: null, at: '2026-11-09T12:43:38.657299Z' } : null,
  blocked_reason: null, skipped_by: null, skipped_at: null, skip_reason: null, roles: ROLES[step],
});
const setupAnswer = (doneSteps) => {
  const steps = ORDER.map((s) => stepObj(s, doneSteps.includes(s) ? 'done' : 'to_do'));
  const current = steps.find((s) => s.status !== 'done')?.step ?? null;
  return { steps, current_step: current, complete: steps.filter((s) => s.required).every((s) => s.status === 'done'), partial: [] };
};
const VAULT_SETUP = {
  untouched: setupAnswer([]),
  midway: setupAnswer(['brand', 'source', 'wording']),
  atPolicy: setupAnswer(['brand', 'source', 'wording', 'credential', 'first_event']),
  allPortalStepsDone: setupAnswer(['brand', 'source', 'wording', 'credential', 'first_event', 'system', 'confirmations']),
};

const session = { api: {}, phase: 'ready', error: null, user: { display_name: 'Dana Ruiz', email: 'dana@example.com' }, memberships: [], org: null, orgId: 'o1', orgName: 'Acme Roofing', role: 'admin', status: 'active', elsewhere: null, sessionEnding: false };
const router = (qs = '') => ({ path: '/setup', search: new URLSearchParams(qs), matched: null, navigations: 0, navigate() {} });
const renderSetup = (answer, qs) => {
  const res = { status: 'ok', data: answer, error: null, reload() {}, refresh() {}, setData() {} };
  return renderToStaticMarkup(React.createElement(SessionContext.Provider, { value: session },
    React.createElement(RouterContext.Provider, { value: router(qs) }, React.createElement(SetupView, { res }))));
};

test('Setup: the vault answers eight steps and no screen reads "0. undefined" or "step 0 of 8"', () => {
  for (const [name, a] of Object.entries(VAULT_SETUP)) {
    for (const qs of ['', ...ORDER.map((s) => `step=${s}`)]) {
      const text = textOf(renderSetup(a, qs));
      assert.doesNotMatch(text, HOLE, `${name} ${qs}`);
      assert.doesNotMatch(text, /\b0\. |Step 0\b|step 0\b/, `${name} ${qs}`);
    }
  }
});

test('Setup: the step counter and the welcome count agree with the steps the portal can show', () => {
  const html = textOf(renderSetup(VAULT_SETUP.atPolicy, ''));
  const m = /Step (\d+) of (\d+)/.exec(html);
  assert.ok(m, 'a step counter is shown');
  assert.ok(Number(m[1]) >= 1 && Number(m[1]) <= Number(m[2]));
  const railItems = (renderSetup(VAULT_SETUP.atPolicy, '').match(/<ol class="rail"[\s\S]*?<\/ol>/)?.[0].match(/<li /g) ?? []).length;
  assert.equal(Number(m[2]), railItems);
});

test('Setup: when every step the portal can show is done, setup reads complete', () => {
  assert.match(textOf(renderSetup(VAULT_SETUP.allPortalStepsDone, '')), /Setup is complete/);
});

// ---- Retention: the vault sends set_by as null when nobody is recorded (admin.py _retention_obj) ----
const RETENTION = (set_by) => ({
  current: { version: 2, evidence_years: 7, applies_from: '2026-11-01T00:00:00Z', set_by },
  platform_minimum_years: 5,
  items: [
    { version: 2, evidence_years: 7, applies_from: '2026-11-01T00:00:00Z', set_by },
    { version: 1, evidence_years: 5, applies_from: '2026-10-01T00:00:00Z', set_by: null },
  ],
  next_cursor: null,
});

test('Retention: a null set_by never prints "set by null"', () => {
  for (const by of [null, undefined]) {
    const d = RETENTION(by);
    assert.doesNotMatch(retentionInForce(d, 7, 5), HOLE);
    assert.doesNotMatch(textOf(renderToStaticMarkup(React.createElement(RetentionHistory, { d, inForce: 7 }))), HOLE);
  }
  assert.doesNotMatch(retentionInForce(RETENTION(null), 7, 5), / by /, 'no setter recorded: the line says when it was set and names no one');
});

test('Retention: a recorded set_by is shown as the record holds it', () => {
  const by = '3f1c2a52-7d44-4e0b-9a0e-1c2d3e4f5a6b';
  assert.match(retentionInForce(RETENTION(by), 7, 5), new RegExp(`by ${by}`));
});

// ---- Audit: a target is what the record holds, never a phone guessed from digits ----
const NOT_PHONE = [
  { kind: 'export', id: '50780123-4562-4210-8a11-340112342210' },
  { kind: 'export', id: '12345678-2210-4abc-9def-001122334455' },
  { kind: 'credential', id: '2026110912584755' },
  { kind: 'setup_step', id: 'system' },
  { kind: 'contact', id: '78012345' },
  { kind: 'export', id: null },
];
test('Audit: no non-phone target is shown with a phone mask', () => {
  for (const t of NOT_PHONE) {
    const s = safeTarget(t);
    assert.doesNotMatch(s, /\*\*\*/, JSON.stringify(t));
    assert.doesNotMatch(s, HOLE, JSON.stringify(t));
    if (t.id) assert.ok(s.includes(t.id), `${JSON.stringify(t)} shows what the record holds`);
  }
  assert.equal(safeTarget({ kind: 'org', id: 'x' }), 'This organization');
  assert.equal(safeTarget({ kind: 'export', id: null }), 'export');
});

test('Audit: a contact point that really is one is still masked', () => {
  assert.doesNotMatch(safeTarget({ kind: 'contact', id: '+15555550100' }), /5550100/);
  assert.doesNotMatch(safeTarget({ kind: 'contact', id: 'dana@acme.com' }), /dana@/);
});

// ---- the class: no source line may print a nullable field straight into a string ----
const SRC = new URL('../src', import.meta.url).pathname;
const files = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]));
test('no screen interpolates a nullable record field into text without a guard or the shared rec()', () => {
  const NULLABLE = ['set_by', 'skipped_by', 'approved_by', 'created_by', 'updated_by', 'marked_by', 'version_label', 'http_status', 'latency_ms'];
  const re = new RegExp(`\\$\\{([A-Za-z_][\\w.]*\\.(?:${NULLABLE.join('|')}))\\}`, 'g');
  const guarded = (line, path) => [`${path} != null`, `${path} !== null`, `${path} ? `, `${path} && `].some((g) => line.includes(g));
  const bad = files(join(SRC, 'screens')).flatMap((f) => readFileSync(f, 'utf8').split('\n').map((l, i) => ({ f, i, l }))
    .filter(({ l }) => [...l.matchAll(re)].some((m) => !guarded(l, m[1])))
    .map(({ f: ff, i, l }) => `${ff}:${i + 1}: ${l.trim().slice(0, 120)}`));
  assert.deepEqual(bad, []);
});
test('no table column renders a bare set_by', () => {
  const bad = files(join(SRC, 'screens')).flatMap((f) => readFileSync(f, 'utf8').split('\n').map((l, i) => ({ f, i, l })).filter(({ l }) => /=> (r|v|x)\.(set_by|approved_by|created_by|marked_by) \}/.test(l)).map(({ f: ff, i }) => `${ff}:${i + 1}`));
  assert.deepEqual(bad, []);
});

test('rec() turns every hole into "Not recorded" and keeps real values', async () => {
  const { rec, targetLine, maskContact, prettyContact } = await import('../src/lib/format.ts');
  for (const v of [null, undefined, '', '  ', 'null', 'undefined', NaN]) assert.equal(rec(v), 'Not recorded');
  assert.equal(rec(0), '0');
  assert.equal(rec('Dana'), 'Dana');
  assert.equal(rec(null, 'None yet'), 'None yet');
  assert.equal(targetLine(null), 'Not recorded');
  assert.equal(maskContact('50780123-4562-4210-8a11-340112342210'), '***');
  assert.equal(prettyContact('50780123-4562-4210-8a11-340112342210'), '50780123-4562-4210-8a11-340112342210');
});
