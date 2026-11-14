import './support/register-tsx.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const { PermissionsTable, relevantPermissions } = await import('../src/screens/evidence.tsx');

const CHANNELS = ['sms', 'voice', 'artificial_voice', 'email'];
const PURPOSES = ['marketing', 'customer_care', 'onboarding', 'early_access'];
const GRID = CHANNELS.flatMap((channel) => PURPOSES.map((purpose) => ({ channel, purpose, status: 'no_record', basis_event_ids: [] })));
const withEmailGrant = GRID.map((p) => (p.channel === 'email' && p.purpose === 'early_access' ? { ...p, status: 'consent_record_found' } : p));
const WORDINGS = [{ channels: ['email', 'sms', 'voice'], purposes: ['early_access'] }, { channels: ['sms', 'voice', 'artificial_voice'], purposes: ['marketing'] }];
const rows = (html) => (html.match(/<tbody>[\s\S]*<\/tbody>/)?.[0].match(/<tr/g) ?? []).length;
const render = (props) => renderToStaticMarkup(React.createElement(PermissionsTable, props));

test('an email address with one early_access grant shows only the email row its wording offers, and the hidden count', () => {
  const html = render({ permissions: withEmailGrant, contactKind: 'email', wordings: WORDINGS });
  assert.equal(rows(html), 1);
  assert.match(html, /Email/);
  assert.match(html, /Consent record found/);
  assert.match(html, /Showing the channels and purposes your wording covers\. 15 other combinations have no wording and no record\./);
  assert.match(html, /Show all/);
});

test('a phone number shows only sms, voice and artificial voice rows its wording covers, never email', () => {
  const phone = GRID.map((p) => ({ ...p }));
  const html = render({ permissions: phone, contactKind: 'phone', wordings: WORDINGS });
  assert.equal(rows(html), 5); // sms+voice early_access, sms+voice+artificial_voice marketing
  assert.doesNotMatch(html, /Email/);
});

test('a pair with any record is listed first even when no wording offers it', () => {
  const perms = GRID.map((p) => (p.channel === 'sms' && p.purpose === 'onboarding' ? { ...p, status: 'stop_on_record' } : p));
  const html = render({ permissions: perms, contactKind: 'phone', wordings: WORDINGS });
  const first = html.match(/<tbody>[\s\S]*?<\/tr>/)[0];
  assert.match(first, /Stop on record/);
});

test('with no wording list loaded nothing is hidden and no line is shown', () => {
  const html = render({ permissions: GRID, contactKind: 'email' });
  assert.equal(rows(html), 16);
  assert.doesNotMatch(html, /Show all/);
});

test('relevantPermissions counts the hidden pairs', () => {
  const r = relevantPermissions(withEmailGrant, 'email', WORDINGS);
  assert.equal(r.shown.length, 1);
  assert.equal(r.hidden, 15);
});
