import './support/register-tsx.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const { PermissionsTable, chainLine, statusOf } = await import('../src/screens/evidence.tsx');
const { SuccessLine, firstNameOf } = await import('../src/screens/setup.tsx');
const { sessionUser } = await import('../src/lib/session.tsx');
const { evidenceLabel, RECORDS_NOTICE, GATE_NOTICE } = await import('../src/lib/copy.ts');

// The exact answers the running service gave (PORTAL-RUNBOOK.md, Known defects 3 and 4, re-read from the live demo).
const PROOF = {
  found: true, partial: [], notice: 'The records held for this contact point, as recorded. ConsentVault records consent and does not decide.',
  permissions: [{ basis_event_ids: ['3837bfc0-2334-4287-b659-43428ed7d89f'], channel: 'sms', purpose: 'marketing', status: 'records_found' }],
  chain: { anchors: [{ anchor_id: 'b34bc8fa', anchored_at: '2026-11-09T12:58:47.553247Z', row_hash: 'x', seq: 7, sink: '/demo' }], events: { e1: { row_hash: 'h', seq: 1 } }, head: { row_hash: 'h', seq: 7 }, path: [] },
};
const SETUP_FIRST_EVENT = { blocked_reason: null, evidence: { at: '2026-11-09T12:43:38.657299Z', id: null, kind: 'event' }, required: true, roles: ['admin', 'developer'], skip_reason: null, skipped_at: null, skipped_by: null, status: 'done', step: 'first_event' };
const SESSION = { expires_at: '2026-11-09T13:07:47Z', items: [], next_cursor: null, user: { display_name: null, email: 'admin@example.com' } };

test('the lookup table shows the recorded status the service answers in status, without throwing', () => {
  const html = renderToStaticMarkup(React.createElement(PermissionsTable, { permissions: PROOF.permissions }));
  assert.match(html, /Records found/);
  assert.match(html, /SMS/);
  assert.doesNotMatch(html, /Not available/);
});

test('an older answer that still uses evidence_status renders the same way', () => {
  const html = renderToStaticMarkup(React.createElement(PermissionsTable, { permissions: [{ channel: 'sms', purpose: 'marketing', evidence_status: 'stop_on_record', basis_event_ids: [] }] }));
  assert.match(html, /Stop on record/);
});

test('a permission with no status at all renders without throwing', () => {
  assert.equal(statusOf({ channel: 'sms', purpose: 'marketing', basis_event_ids: [] }), '');
  assert.doesNotThrow(() => renderToStaticMarkup(React.createElement(PermissionsTable, { permissions: [{ channel: 'sms', purpose: 'marketing', basis_event_ids: [] }] })));
});

test('no lookup label or notice turns a status into proceed or hold language', () => {
  const html = renderToStaticMarkup(React.createElement(PermissionsTable, { permissions: PROOF.permissions }));
  for (const text of [html, evidenceLabel('records_found').text, evidenceLabel('no_record_found').text, RECORDS_NOTICE, GATE_NOTICE]) assert.doesNotMatch(text, /proceed|hold|policy/i);
});

test('the chain line reads the anchor the service sends and claims no verification it was not given', () => {
  const html = renderToStaticMarkup(React.createElement('p', null, chainLine(PROOF.chain)));
  assert.match(html, /Last outside anchor/);
  assert.match(html, /2026|Nov/);
  assert.doesNotMatch(html, /Verified|failed/);
});

test('the setup success line renders for a first event whose evidence id is null', () => {
  const html = renderToStaticMarkup(React.createElement(SuccessLine, { step: SETUP_FIRST_EVENT }));
  assert.match(html, /Your first event was recorded\./);
});

test('a session user with a null display name falls back to the address, so Setup can greet without throwing', () => {
  const u = sessionUser(SESSION.user);
  assert.equal(u.display_name, 'admin@example.com');
  assert.doesNotThrow(() => firstNameOf(SESSION.user));
  assert.equal(firstNameOf(u), 'admin@example.com');
  assert.equal(firstNameOf(null), '');
});
