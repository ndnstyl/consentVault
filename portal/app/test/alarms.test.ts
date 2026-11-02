import test from 'node:test';
import assert from 'node:assert/strict';
import { ALARM_NAMES, alarmCopy } from '../src/lib/alarms.ts';

test('every alarm a customer can be shown has plain words for what happened, and uses the next action the vault sends', () => {
  assert.deepEqual([...ALARM_NAMES].sort(), ['billing.second_live_subscription', 'delivery_reports_stale', 'inbound_signature_failures', 'link_host_failing',
    'optout_reply_dead', 'provider_refusal_stop', 'replies_unread_24h', 'restore.stops_unconfirmed', 'reveal_volume', 'send_cap_reached', 'sending_account_failing', 'sso.required_lifted']);
  for (const name of ALARM_NAMES) {
    const c = alarmCopy({ name, since: '2026-10-30T10:00:00Z', count: 3, next_action: 'Do the thing the vault said.' });
    assert.ok(c.title.length > 5 && c.what.length > 20, name);
    assert.equal(c.next, 'Do the thing the vault said.');
    assert.ok(!/[a-z][._][a-z]/.test(c.title + ' ' + c.what), `${name}: no internal names in the words`);
  }
});

test('the count is put into the sentence', () => {
  assert.match(alarmCopy({ name: 'restore.stops_unconfirmed', since: 'x', count: 2, next_action: 'n' }).what, /2 stops/);
  assert.match(alarmCopy({ name: 'restore.stops_unconfirmed', since: 'x', count: 1, next_action: 'n' }).what, /1 stop was/);
  assert.match(alarmCopy({ name: 'reveal_volume', since: 'x', count: 5200, next_action: 'n' }).what, /5,200 records/);
  assert.match(alarmCopy({ name: 'billing.second_live_subscription', since: 'x', count: null, next_action: 'n' }).what, /two live subscriptions/);
});

test('a name the page does not know is still shown, in words that say so, never dropped', () => {
  const c = alarmCopy({ name: 'something_new', since: 'x', count: null, next_action: 'Tell support.' });
  assert.match(c.what, /something_new/);
  assert.equal(c.next, 'Tell support.');
});
