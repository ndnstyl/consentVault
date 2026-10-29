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
  for (const shown of ['overview', 'first-event', 'brands', 'sources', 'credentials', 'systems', 'wording', 'policies', 'checklists', 'settings', 'references'] as const) assert.equal(d.includes(shown), true, shown);
});

test('compliance viewer sees evidence, packages, audit, retention and read pages only', () => {
  const v = ids('compliance_viewer');
  assert.deepEqual(v, ['overview', 'evidence', 'exports', 'wording', 'policies', 'checklists', 'systems', 'retention', 'audit', 'settings', 'references']);
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
  assert.equal(matchRoute('/policies/4/approve')?.route.id, 'policy-approve');
  assert.equal(matchRoute('/policies/new')?.route.id, 'policy-new');
  assert.equal(matchRoute('/systems/new')?.route.id, 'system-new');
  assert.equal(matchRoute('/sources/src_1/')?.params.source_id, 'src_1');
  assert.equal(matchRoute('/nope'), null);
  assert.equal(matchRoute('/')?.route.id, 'overview');
});

test('static paths exclude dynamic routes', () => {
  assert.ok(staticPaths().includes('/'));
  assert.ok(!staticPaths().some((p) => p.includes(':')));
});
