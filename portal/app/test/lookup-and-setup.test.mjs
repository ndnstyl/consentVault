import './support/register-tsx.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const { PermissionsTable, chainLine, statusOf } = await import('../src/screens/evidence.tsx');
const { SuccessLine, firstNameOf, ORDER } = await import('../src/screens/setup.tsx');
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

// ---- reviewer round: wording, erased stop, lookup status table, audit names ----
const { actorName, actionLabel, wordingName, eventOrigin, purposeWords, memberName } = await import('../src/lib/labels.ts');
const { permissionsFromRecord } = await import('../src/screens/evidence.tsx');
const { fmtDate } = await import('../src/lib/format.ts');

const ADMIN = { id: '71a22cbf-3f56-4f4c-9494-c9daff93dd4c', display_name: null, email: 'admin@example.com' };
const V2 = { label: 'estimate-form-v2', version_label: null, effective_from: '2026-01-01T00:00:00Z' };

test('a wording version with a null version_label is named by its label, and midnight UTC reads as that calendar day', () => {
  assert.equal(wordingName(V2), 'estimate-form-v2');
  assert.equal(wordingName({ label: 'x', version_label: 'v9' }), 'v9');
  assert.equal(fmtDate(V2.effective_from), 'Jan 1, 2026');
});

test('a member is shown by name or address, never by id', () => {
  const members = new Map([[ADMIN.id, ADMIN]]);
  assert.equal(memberName(ADMIN), 'admin@example.com');
  assert.equal(actorName({ kind: 'member', id: ADMIN.id, display_name: null }, members), 'admin@example.com');
  assert.equal(actorName({ kind: 'member', id: 'unknown', display_name: null }, members), null);
  assert.equal(actorName({ kind: 'operator', id: 'o', display_name: null }, members), 'The platform operator');
});

test('an audit action reads as the service label, else as words, never the raw code', () => {
  const labels = new Map([['brand.created', 'Brand added']]);
  assert.equal(actionLabel('brand.created', labels), 'Brand added');
  assert.equal(actionLabel('session.opened', labels), 'Session opened');
});

test('the lookup status table shows the stop the Records page shows, from the same record data', () => {
  const rec = { channels: { sms: { counts: {}, purposes: [{ purpose: '*', evidence_status: 'stop_on_record' }] }, email: { counts: {}, purposes: [{ purpose: 'marketing', evidence_status: 'no_record' }] } } };
  const html = renderToStaticMarkup(React.createElement(PermissionsTable, { permissions: permissionsFromRecord(rec) }));
  assert.match(html, /Stop on record/);
  assert.match(html, /All purposes/);
  assert.match(html, /No record/);
  assert.doesNotMatch(html, /Records found/);
});

test('an event with no brand and no source is an erasure request; a missing brand elsewhere reads Not recorded', () => {
  const name = (id) => id;
  assert.deepEqual(eventOrigin({ brand_ids: [], source_id: null }, name), { brand: 'erasure request', source: 'erasure request' });
  assert.deepEqual(eventOrigin({ brand_ids: [], source_id: 'estimate-form' }, name), { brand: 'Not recorded', source: 'estimate-form' });
  assert.equal(purposeWords('*'), 'All purposes');
});

test('no reading of a rule-set is written as a fact in the portal copy', async () => {
  const { readFileSync } = await import('node:fs');
  for (const f of ['../src/screens/records.tsx', '../src/screens/evidence.tsx', '../src/screens/confirmations.tsx']) {
    const t = readFileSync(new URL(f, import.meta.url), 'utf8');
    assert.doesNotMatch(t, /most protective status|keeps being honored|did not lift a stop|covers texts and calls|never when a stop is on record/, f);
  }
});

test('setup has no policy step', () => {
  assert.equal(ORDER.includes('policy'), false);
  assert.equal(ORDER.length, 7);
});
