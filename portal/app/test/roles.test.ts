import test from 'node:test';
import assert from 'node:assert/strict';
import { canView, canDo, navFor, refusalHeading, fallbackFor, VIEW_ROLES, NAV } from '../src/lib/roles.ts';
import { matchRoute, ROUTES, staticPaths } from '../src/lib/routes.ts';

const ids = (r: Parameters<typeof navFor>[0]) => navFor(r).flatMap((g) => g.items.map((i) => i.id));

test('admin sees every navigation item', () => {
  const all = NAV.flatMap((g) => g.items.map((i) => i.id));
  assert.deepEqual(ids('admin'), all);
});

test('developer never sees personal-data, members, audit, billing or retention screens', () => {
  const d = ids('developer');
  for (const hidden of ['evidence', 'exports', 'members', 'audit', 'billing', 'retention'] as const) assert.equal(d.includes(hidden), false, hidden);
  for (const shown of ['overview', 'first-event', 'brands', 'sources', 'credentials', 'systems', 'wording', 'checklists', 'settings', 'references'] as const) assert.equal(d.includes(shown), true, shown);
});

test('compliance viewer sees evidence, packages, audit, retention and read pages only', () => {
  const v = ids('compliance_viewer');
  assert.deepEqual(v, ['overview', 'records', 'evidence', 'exports', 'wording', 'checklists', 'systems', 'confirmations', 'retention', 'audit', 'settings', 'references']);
});

test('write actions follow the role matrix', () => {
  assert.equal(canDo('admin', 'wording.register'), true);
  assert.equal(canDo('developer', 'wording.register'), false);
  assert.equal(canDo('compliance_viewer', 'export.build'), true);
  assert.equal(canDo('developer', 'export.build'), false);
  assert.equal(canDo('developer', 'credential.issue'), true);
  assert.equal(canDo('developer', 'credential.issue.gate_read'), false);
  assert.equal(canDo('compliance_viewer', 'system.write'), false);
  assert.equal(canDo(null, 'brand.create'), false);
  assert.equal(canView(null, 'overview'), false);
});

test('refusal heading names who the page is for', () => {
  assert.equal(refusalHeading('members'), 'This page is for admins');
  assert.equal(refusalHeading('evidence'), 'This page is for admins and compliance viewers');
  assert.equal(refusalHeading('sources'), 'This page is for admins and developers');
});

test('the refusal button always lands on a page the role may open', () => {
  for (const r of ['admin', 'developer', 'compliance_viewer'] as const) assert.equal(canView(r, fallbackFor(r).id), true);
});

test('every route has an access row and every nav item is a route', () => {
  for (const r of ROUTES) assert.ok(VIEW_ROLES[r.id], r.id);
  for (const g of NAV) for (const i of g.items) assert.ok(ROUTES.find((r) => r.id === i.id && r.pattern === i.href), i.id);
});

test('route matching prefers static segments over params', () => {
  assert.equal(matchRoute('/wording/new')?.route.id, 'wording-new');
  assert.equal(matchRoute('/wording/9f2c')?.route.id, 'wording-detail');
  assert.equal(matchRoute('/wording/9f2c')?.params.sha256, '9f2c');
  assert.equal(matchRoute('/policies/4/approve'), null);
  assert.equal(matchRoute('/policies/new'), null);
  assert.equal(matchRoute('/systems/new')?.route.id, 'system-new');
  assert.equal(matchRoute('/sources/src_1/')?.params.source_id, 'src_1');
  assert.equal(matchRoute('/nope'), null);
  assert.equal(matchRoute('/')?.route.id, 'overview');
});

test('static paths exclude dynamic routes', () => {
  assert.ok(staticPaths().includes('/'));
  assert.ok(!staticPaths().some((p) => p.includes(':')));
});

test('records, setup and confirmation messages follow the role matrix (roles.md additions 2026-10-30)', () => {
  assert.equal(canView('developer', 'records'), true);
  assert.equal(canDo('developer', 'records.search'), false);
  assert.equal(canDo('developer', 'records.reveal'), false);
  assert.equal(canDo('developer', 'records.export'), false);
  assert.equal(canDo('developer', 'records.person'), false);
  for (const a of ['records.search', 'records.reveal', 'records.export', 'records.person'] as const) {
    assert.equal(canDo('admin', a), true, a);
    assert.equal(canDo('compliance_viewer', a), true, a);
  }
  assert.equal(canView('compliance_viewer', 'setup'), false);
  assert.equal(canView('developer', 'setup'), true);
  assert.equal(canDo('developer', 'setup.skip'), true);
  assert.equal(canView('compliance_viewer', 'confirmation-edit'), false);
  assert.equal(canView('developer', 'confirmation-edit'), true);
  assert.equal(canDo('developer', 'confirmations.account'), true);
  assert.equal(canDo('developer', 'confirmations.manage'), false);
  assert.equal(canDo('developer', 'confirmations.replies'), false);
  assert.equal(canDo('compliance_viewer', 'confirmations.replies'), true);
  assert.equal(canDo('compliance_viewer', 'confirmations.manage'), false);
});

test('the new routes match, and the dynamic edit route reads source and channel', () => {
  assert.equal(matchRoute('/records')?.route.id, 'records');
  assert.equal(matchRoute('/setup')?.route.id, 'setup');
  assert.equal(matchRoute('/setup/first-event')?.route.id, 'first-event');
  assert.equal(matchRoute('/confirmations')?.route.id, 'confirmations');
  const m = matchRoute('/confirmations/src_web/sms');
  assert.equal(m?.route.id, 'confirmation-edit');
  assert.deepEqual(m?.params, { source_id: 'src_web', channel: 'sms' });
  assert.equal(staticPaths().includes('/records') && staticPaths().includes('/setup') && staticPaths().includes('/confirmations'), true);
  assert.equal(staticPaths().some((p) => p.includes(':')), false);
});

test('no policy route or nav item', () => {
  for (const id of ['policies', 'policy-new', 'policy-detail', 'policy-approve']) assert.equal(ROUTES.some((r) => r.id === (id as never)), false, id);
  assert.equal(NAV.flatMap((g) => g.items).some((i) => /polic/i.test(i.label) || /polic/i.test(i.href)), false);
  assert.equal(matchRoute('/policies'), null);
});
