import './support/register-tsx.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { TUTORIALS, TUTORIALS_COPY, tutorialSrc } from '../src/lib/tutorials.ts';
import { ROUTES, matchRoute } from '../src/lib/routes.ts';
import { VIEW_ROLES, canView } from '../src/lib/roles.ts';
import { scanCopy } from '../src/lib/copycheck.ts';

test('tutorials are numbered in order from one, each with a distinct video file and id', () => {
  const n = TUTORIALS.length;
  assert.deepEqual(TUTORIALS.map((t) => t.number), Array.from({ length: n }, (_, i) => i + 1));
  assert.equal(new Set(TUTORIALS.map((t) => t.file)).size, n);
  assert.equal(new Set(TUTORIALS.map((t) => t.id)).size, n);
});

test('the Tutorials route exists, is open to every role and is not in the side menu', () => {
  assert.equal(matchRoute('/tutorials')?.route.id, 'tutorials');
  assert.deepEqual(VIEW_ROLES.tutorials, ['admin', 'developer', 'compliance_viewer']);
  assert.equal(ROUTES.filter((r) => r.pattern === '/tutorials').length, 1);
});

test('every summary and fixed string passes the portal copy check and carries no dash', () => {
  for (const t of TUTORIALS) for (const s of [t.title, t.tagline, t.summary]) assert.deepEqual(scanCopy(s), [], t.id);
  for (const v of Object.values(TUTORIALS_COPY)) assert.deepEqual(scanCopy(typeof v === 'function' ? v('Records') : v), []);
  assert.ok(!/[–—]/.test(fs.readFileSync('src/lib/tutorials.ts', 'utf8')));
});

test('the screen renders every video once, with a captions note, a summary, and a screen link only where the role may open it', async () => {
  const { Tutorials } = await import('../src/screens/tutorials.tsx');
  const { SessionContext } = await import('../src/lib/session.tsx');
  const { RouterContext } = await import('../src/lib/router.tsx');
  const router = { path: '/tutorials', search: new URLSearchParams(), matched: null, navigations: 0, navigate: () => {} };
  const render = (role: string) => renderToStaticMarkup(React.createElement(RouterContext.Provider, { value: router as never }, React.createElement(SessionContext.Provider, { value: { role } as never }, React.createElement(Tutorials))));
  const admin = render('admin');
  for (const t of TUTORIALS) {
    assert.ok(admin.includes(`src="${tutorialSrc(t)}"`), t.id);
    assert.ok(admin.includes(t.summary), t.id);
  }
  assert.equal((admin.match(/<video /g) ?? []).length, TUTORIALS.length);
  assert.equal((admin.match(/This video has no voice-over yet/g) ?? []).length, TUTORIALS.filter((t) => !t.voiced).length);
  assert.match(admin, /<a href="\/sources">Open Capture sources<\/a>/);
  const viewer = render('compliance_viewer');
  assert.equal((viewer.match(/<video /g) ?? []).length, TUTORIALS.length);
  assert.doesNotMatch(viewer, /Open Capture sources/);
  assert.match(viewer, /<a href="\/records">Open Records<\/a>/);
});

test('the compliance viewer is not offered a link to a screen the role cannot open', () => {
  const t = TUTORIALS.find((x) => x.screen.id === 'sources')!;
  assert.equal(canView('compliance_viewer', t.screen.id), false);
  assert.equal(canView('admin', t.screen.id), true);
});

test('the build copies every video and refuses a missing or oversized one', () => {
  const s = fs.readFileSync('scripts/copy-tutorials.mjs', 'utf8');
  assert.match(s, /25 \* 1024 \* 1024/);
  assert.match(s, /process\.exit\(3\)/);
  assert.match(JSON.parse(fs.readFileSync('package.json', 'utf8')).scripts.build, /^node scripts\/copy-tutorials\.mjs && next build/);
});
