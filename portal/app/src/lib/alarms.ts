// Alarms a customer's admins and compliance viewers read (GET /v1/health `alarms: [{name, since, count|null, next_action}]`,
// filtered by role by the vault). The vault supplies the next action; this file supplies what happened, in plain words. No
// alarm can be acknowledged from the page: each one leaves the list when its cause is fixed.
import type { OrgAlarm } from './api/types.ts';

export interface AlarmCopy { title: string; what: string; next: string; href?: string }

const num = (v: number | null) => (v === null ? 'Many' : v.toLocaleString('en-US'));

const WHAT: Record<string, { title: string; what: (count: number | null) => string; href?: string }> = {
  'restore.stops_unconfirmed': {
    title: 'Some stops were restored without their confirmation',
    what: (n) => (n === 1 ? '1 stop was put back after a restore without the confirmation behind it, and still stands.' : `${num(n)} stops were put back after a restore without the confirmation behind them, and still stand.`),
    href: '/evidence',
  },
  'billing.second_live_subscription': {
    title: 'Your organization has two subscriptions',
    what: () => 'Your organization has two live subscriptions, and only one is in use.',
    href: '/billing',
  },
  'sso.required_lifted': { title: 'The company sign-in requirement was lifted', what: () => 'An operator turned off the company sign-in requirement because your identity provider could not be reached.', href: '/sso' },
  reveal_volume: { title: 'Unusually many records were revealed', what: (n) => `${num(n)} records were revealed in a short time.`, href: '/audit' },
  sending_account_failing: { title: 'A sending account is failing', what: () => 'A sending account was refused five times in a row, so confirmation messages are being skipped.' },
  inbound_signature_failures: { title: 'Replies with a bad signature keep arriving', what: () => 'Five replies in ten minutes did not carry a valid signature from your sending account, so they were ignored.' },
  replies_unread_24h: { title: 'Replies have waited a day', what: () => 'At least one reply to a confirmation message has been unread for 24 hours.' },
  delivery_reports_stale: { title: 'Delivery reports stopped', what: () => 'No delivery report has come back from your provider for some time, so you cannot tell whether messages arrive.' },
  link_host_failing: { title: 'The link address in your messages is failing', what: () => 'The address used for links in confirmation messages stopped answering, so messages that carry a link are being skipped.' },
  optout_reply_dead: { title: 'A stop reply could not be sent', what: () => "A reply confirming someone's opt-out was not sent within five minutes and was given up on." },
  provider_refusal_stop: { title: 'Your provider refused a message because the person opted out', what: () => 'Your provider told us the person had opted out with them, so we recorded a stop.' },
  send_cap_reached: { title: 'The hourly sending limit was reached', what: () => 'Confirmation messages were held back because the hourly sending limit was reached.' },
};

export const ALARM_NAMES = Object.keys(WHAT);

export function alarmCopy(a: OrgAlarm): AlarmCopy {
  const w = WHAT[a.name];
  if (w) return { title: w.title, what: w.what(a.count), next: a.next_action, href: w.href };
  return { title: 'An alert was raised', what: `ConsentVault raised a kind of alert (${a.name}) that this page has no words for yet.`, next: a.next_action };
}
