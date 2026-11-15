import './support/register-tsx.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';

// Record links (competitive-builds spec, Build 1, T031): the Share action, the scope dialog's defaults, the preview shown exactly as
// the preview endpoint returned it, the list with counts and a withdraw action. Rendered statically, with the API client run over a
// mocked fetch. Every new string passes copycheck.

const { createClient } = await import('../src/lib/api/client.ts');
const { SessionContext } = await import('../src/lib/session.tsx');
const { RouterContext } = await import('../src/lib/router.tsx');
const { scanCopy } = await import('../src/lib/copycheck.ts');
const RL = await import('../src/screens/record-links.tsx');
const { canDo } = await import('../src/lib/roles.ts');

const h = React.createElement;
const noop = () => {};
const text = (html) => html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').replace(/&#x27;/g, "'").replace(/&quot;/g, '"');
const session = (api, role = 'admin') => ({ api, phase: 'ready', error: null, user: { display_name: 'Dana Ruiz', email: 'dana@example.com' }, memberships: [], org: null, orgId: 'o1', orgName: 'Acme Roofing', role, status: 'active', elsewhere: null, sessionEnding: false, refreshOrg: async () => {} });
const router = { path: '/x', search: new URLSearchParams(), matched: null, navigations: 0, navigate: noop };
const render = (el, role = 'admin') => renderToStaticMarkup(h(SessionContext.Provider, { value: session({}, role) }, h(RouterContext.Provider, { value: router }, el)));

function mockApi(answers) {
  const calls = [];
  const fetch = async (url, init) => {
    const u = new URL(url, 'https://portal.example');
    calls.push({ method: init.method, path: u.pathname, body: init.body ? JSON.parse(init.body) : undefined });
    const a = answers[`${init.method} ${u.pathname}`];
    if (!a) return new Response('{"error":"not_found"}', { status: 404, headers: { 'content-type': 'application/json' } });
    return typeof a === 'string' ? new Response(a, { status: 200, headers: { 'content-type': 'text/html' } }) : new Response(JSON.stringify(a.body), { status: a.status ?? 200, headers: { 'content-type': 'application/json' } });
  };
  return { api: createClient({ fetch, orgId: () => 'o1' }), calls };
}

const EVENT = 'e0000000-0000-0000-0000-000000000001';

test('scope defaults follow the spec: organization name on, match on, contact, page address and bot check off', () => {
  assert.deepEqual(RL.SCOPE_DEFAULTS, { show_org_name: true, show_contact: false, allow_contact_match: true, show_page_url: false, show_bot_check: false });
  const html = render(h(RL.ShareForm, { scope: RL.SCOPE_DEFAULTS, ack: '', note: '', preview: { status: 'idle' }, onScope: noop, onAck: noop, onNote: noop }));
  const box = (name) => new RegExp(`<input[^>]*name="${name}"[^>]*>`).exec(html)?.[0] ?? '';
  assert.match(box('show_org_name'), /checked/);
  assert.match(box('allow_contact_match'), /checked/);
  for (const n of ['show_contact', 'show_page_url', 'show_bot_check']) { assert.ok(box(n), n); assert.doesNotMatch(box(n), /checked/, n); }
});

test('turning on the contact point asks for a typed acknowledgement; it is not shown while the contact point is off', () => {
  const off = render(h(RL.ShareForm, { scope: RL.SCOPE_DEFAULTS, ack: '', note: '', preview: { status: 'idle' }, onScope: noop, onAck: noop, onNote: noop }));
  assert.doesNotMatch(off, /name="contact_ack"/);
  const on = render(h(RL.ShareForm, { scope: { ...RL.SCOPE_DEFAULTS, show_contact: true }, ack: '', note: '', preview: { status: 'idle' }, onScope: noop, onAck: noop, onNote: noop }));
  assert.match(on, /name="contact_ack"/);
  assert.match(text(on), /Anyone who holds this link will see the phone number or email address/);
});

test('the body is refused until the acknowledgement is typed exactly, and never carries it when the contact point is off', () => {
  const base = { eventId: EVENT, scope: RL.SCOPE_DEFAULTS, ack: '', note: 'Lead 41 for Orion' };
  const plain = RL.buildBody(base);
  assert.equal(plain.ok, true);
  assert.deepEqual(plain.body, { event_id: EVENT, ...RL.SCOPE_DEFAULTS, note: 'Lead 41 for Orion' });
  const withContact = { ...base, scope: { ...RL.SCOPE_DEFAULTS, show_contact: true } };
  assert.equal(RL.buildBody(withContact).ok, false);
  assert.equal(RL.buildBody({ ...withContact, ack: 'show it' }).ok, false);
  const ok = RL.buildBody({ ...withContact, ack: `  ${RL.ACK_PHRASE.toUpperCase()} ` });
  assert.equal(ok.ok, true);
  assert.equal(ok.body.contact_ack, RL.ACK_SENTENCE);
  assert.equal(RL.buildBody({ ...base, ack: 'show contact' }).body.contact_ack, undefined);
});

test('the preview is the endpoint\'s HTML shown exactly: in a script-free frame, and as the same text beside it', async () => {
  const PAGE = '<!doctype html><html><body><p>5 &amp; 6 <b>as sent</b></p><script>alert(1)</script></body></html>';
  const { api, calls } = mockApi({ 'POST /v1/record-links/preview': PAGE });
  const got = await RL.previewLink(api, { event_id: EVENT, ...RL.SCOPE_DEFAULTS });
  assert.equal(got, PAGE);
  assert.equal(calls[0].method, 'POST');
  assert.equal(calls[0].body.event_id, EVENT);
  const html = render(h(RL.ShareForm, { scope: RL.SCOPE_DEFAULTS, ack: '', note: '', preview: { status: 'ok', html: got }, onScope: noop, onAck: noop, onNote: noop }));
  const frame = /<iframe[^>]*>/.exec(html)?.[0] ?? '';
  assert.match(frame, /sandbox=""/);
  assert.match(frame, /srcDoc=|srcdoc=/i);
  assert.ok(html.includes('alert(1)') && !html.includes('<script>alert'), 'the page text appears escaped, never as an element');
  assert.match(html, /&lt;p&gt;5 &amp;amp; 6/);
});

test('create sends the body and returns the link once; the list, withdraw and reset call the admin routes', async () => {
  const { api, calls } = mockApi({
    'POST /v1/record-links': { status: 201, body: { share_id: 's1', link: 'https://verify.example/p/cvp_abc' } },
    [`GET /v1/record-links`]: { body: { items: [{ share_id: 's1', event_id: EVENT, note: null, created_at: '2026-11-15T10:00:00Z', view_count: 3, withdrawn_at: null }], next_cursor: null } },
    'POST /v1/record-links/s1/revoke': { body: {} },
    'POST /v1/record-links/s1/reset-match': { body: {} },
  });
  const made = await RL.createLink(api, { event_id: EVENT, ...RL.SCOPE_DEFAULTS });
  assert.equal(made.link, 'https://verify.example/p/cvp_abc');
  assert.equal((await api.recordLinks.list()).items[0].view_count, 3);
  await api.recordLinks.revoke('s1');
  await api.recordLinks.resetMatch('s1');
  assert.deepEqual(calls.map((c) => `${c.method} ${c.path}`), ['POST /v1/record-links', 'GET /v1/record-links', 'POST /v1/record-links/s1/revoke', 'POST /v1/record-links/s1/reset-match']);
});

test('the list shows created, views, state and a Withdraw action only on a live link', () => {
  const links = [
    { share_id: 's1', event_id: EVENT, note: 'Orion lead', created_at: '2026-11-15T10:00:00Z', view_count: 3, withdrawn_at: null },
    { share_id: 's2', event_id: EVENT, note: null, created_at: '2026-11-14T10:00:00Z', view_count: 0, withdrawn_at: '2026-11-15T11:00:00Z' },
  ];
  const html = render(h(RL.RecordLinksTable, { links, busy: null, onWithdraw: noop, onReset: noop }));
  const t = text(html);
  assert.match(t, /Orion lead/);
  assert.match(t, /Withdrawn/);
  assert.match(t, /Active/);
  const only = (l) => (render(h(RL.RecordLinksTable, { links: [l], busy: null, onWithdraw: noop, onReset: noop })).match(/>Withdraw</g) ?? []).length;
  assert.ok(only(links[0]) > 0);
  assert.equal(only(links[1]), 0);
  assert.equal((html.match(/>Withdraw</g) ?? []).length, only(links[0]));
});

test('the empty list says so, and a compliance viewer is not offered the action', () => {
  assert.match(text(render(h(RL.RecordLinksTable, { links: [], busy: null, onWithdraw: noop, onReset: noop }))), /No record links yet/);
  assert.equal(canDo('compliance_viewer', 'recordlink.manage'), false);
  assert.equal(canDo('developer', 'recordlink.manage'), false);
  assert.equal(canDo('admin', 'recordlink.manage'), true);
});

test('the screens wire it in: Records lists the links, the evidence timeline offers Share this record', () => {
  const src = (p) => readFileSync(new URL(`../src/${p}`, import.meta.url), 'utf8');
  assert.match(src('screens/records.tsx'), /RecordLinksPanel/);
  assert.match(src('screens/evidence.tsx'), /Share this record/);
  assert.match(src('screens/evidence.tsx'), /ShareDialog/);
});

test('every new string passes copycheck and never says proof', () => {
  const html = [
    render(h(RL.ShareForm, { scope: { ...RL.SCOPE_DEFAULTS, show_contact: true }, ack: '', note: '', preview: { status: 'idle' }, onScope: noop, onAck: noop, onNote: noop })),
    render(h(RL.RecordLinksTable, { links: [{ share_id: 's1', event_id: EVENT, note: 'x', created_at: '2026-11-15T10:00:00Z', view_count: 1, withdrawn_at: null }], busy: null, onWithdraw: noop, onReset: noop })),
    render(h(RL.RecordLinksTable, { links: [], busy: null, onWithdraw: noop, onReset: noop })),
  ].map(text).join(' ') + ' ' + [RL.ACK_SENTENCE, ...Object.values(RL.COPY)].join(' ');
  assert.deepEqual(scanCopy(html), []);
  assert.doesNotMatch(html, /\bproof\b/i);
});
