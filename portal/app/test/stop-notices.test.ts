import test from 'node:test';
import assert from 'node:assert/strict';
import { initialPopup, popupReducer, deliveryLines, channelWords, stopNote, STOP_NOTE } from '../src/lib/stop-notices.ts';
import type { StopNotice } from '../src/lib/api/types.ts';

const n = (id: string, delivery: StopNotice['delivery'] = []): StopNotice => ({
  notice_id: id, contact: '(555) ***-0177', channels: ['sms'], purposes: ['marketing'], stopped_at: '2026-11-19T12:00:00Z', delivery, records_path: '/records?has_stop=true',
});

test('the pop-up opens when notices exist, stays open through every attempt to dismiss it, and clears only when they are acknowledged', () => {
  let s = popupReducer(initialPopup, { type: 'loaded', notices: [n('a'), n('b')] });
  assert.equal(s.phase, 'open');
  assert.equal(popupReducer(s, { type: 'dismiss_attempt' }), s);
  s = popupReducer(s, { type: 'acknowledging' });
  s = popupReducer(s, { type: 'acknowledge_failed', error: 'down' });
  assert.equal(s.phase, 'open');                     // a failed acknowledgement leaves the notices in front of the admin
  assert.equal((s as { error: string }).error, 'down');
  s = popupReducer(s, { type: 'acknowledged', ids: ['a'] });
  assert.equal(s.phase, 'open');
  assert.deepEqual(s.notices.map((x) => x.notice_id), ['b']);
  s = popupReducer(s, { type: 'acknowledged', ids: ['b'] });
  assert.equal(s.phase, 'clear');
});

test('no notices means no pop-up, and a load failure is shown rather than read as nothing to see', () => {
  assert.equal(popupReducer(initialPopup, { type: 'loaded', notices: [] }).phase, 'clear');
  assert.equal(popupReducer(initialPopup, { type: 'load_failed', error: 'x' }).phase, 'failed');
});

test('a notice only notifies: the words say acting is the customer\'s, and each system shows delivered, waiting, refused or none connected', () => {
  assert.equal(stopNote(1), STOP_NOTE);
  assert.match(stopNote(3), /up to you/);
  assert.doesNotMatch(stopNote(1) + stopNote(2), /we (have )?(blocked|removed|stopped|updated)/i);
  assert.deepEqual(deliveryLines(n('a', [{ system: 'CRM', status: 'delivered' }, { system: 'Dialer', status: 'refused' }])), ['CRM (delivered)', 'Dialer (refused)']);
  assert.deepEqual(deliveryLines(n('a', [{ system: null, status: 'none_connected' }])), ['none connected']);
  assert.equal(channelWords(['sms', 'voice', 'email']), 'Text message, Phone call, Email');
});
