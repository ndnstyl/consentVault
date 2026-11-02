import test, { before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { createMock } from '../mock/server.ts';
import { ApiError, allPages, createClient } from '../src/lib/api/client.ts';
import { causeLine } from '../src/lib/copy.ts';

const mock = createMock();
const srv = mock.server(null, null);
let base = '';
before(async () => { await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r)); base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`; });
after(() => srv.close());
async function scenario(s: Record<string, unknown>) {
  await fetch(`${base}/__mock/scenario`, { method: 'POST', body: JSON.stringify(s) });
}
const log = async () => (await (await fetch(`${base}/__mock/log`)).json()) as { method: string; url: string; body: any }[];
beforeEach(async () => { await scenario({}); });

test('reads the session and the organization', async () => {
  const api = createClient({ baseUrl: base });
  const s = await api.session.get();
  assert.equal(s.items[0].role, 'admin');
  const o = await api.session.org();
  assert.equal(o.name, 'Acme Lending');
});

test('an API error becomes an ApiError with status, code, detail and fields', async () => {
  const api = createClient({ baseUrl: base });
  await assert.rejects(api.brands.create('Acme Lending'), (e: unknown) => {
    assert.ok(e instanceof ApiError);
    assert.equal(e.status, 409);
    assert.equal(e.code, 'brand_exists');
    return true;
  });
  await assert.rejects(api.disclosures.register({ body: 'x', label: 'a', channels: ['sms'], purposes: ['marketing'], brand_ids: ['brd_acme'], effective_from: '2026-11-01' }).then(async (d) => api.disclosures.register({ body: 'x', label: 'b', channels: ['sms'], purposes: ['marketing'], brand_ids: ['brd_acme'], effective_from: '2026-11-01' }).catch((e) => { assert.ok(d.sha256); throw e; })),
    (e: unknown) => e instanceof ApiError && e.code === 'disclosure_exists' && typeof e.fields.sha256 === 'string');
});

test('a 401 calls the unauthenticated hook once and still throws', async () => {
  await scenario({ signedOut: true });
  let calls = 0;
  const api = createClient({ baseUrl: base, onUnauthenticated: () => { calls++; } });
  await assert.rejects(api.brands.list(), (e: unknown) => e instanceof ApiError && e.status === 401 && e.code === 'unauthenticated');
  assert.equal(calls, 1);
});

test('204 answers resolve to undefined', async () => {
  const api = createClient({ baseUrl: base });
  await api.members.list({ include: 'invites' });
  assert.equal(await api.invites.withdraw('inv_sam'), undefined);
});

test('the contact point travels in the POST body, never in the URL', async () => {
  const api = createClient({ baseUrl: base });
  const contact = '+15555550100';
  const p = await api.evidence.lookup(contact);
  assert.equal(p.found, true);
  const e = await api.exports.create(contact);
  assert.equal(e.status, 'building');
  await api.evidence.deliveriesFor(contact, 'sys_crm');
  await api.erasure.request(contact, 'requested by the person');
  for (const r of await log()) assert.equal(r.url.includes('5555550100'), false, r.url);
  const proof = (await log()).find((r) => r.url === '/v1/proof');
  assert.equal(proof?.method, 'POST');
  assert.equal(proof?.body.contact, contact);
});

test('a wrong role is refused by the server with role_not_allowed', async () => {
  await scenario({ role: 'developer' });
  const api = createClient({ baseUrl: base });
  await assert.rejects(api.evidence.lookup('+15555550100'), (e: unknown) => e instanceof ApiError && e.code === 'role_not_allowed' && e.fields.role === 'developer');
});

test('an unreachable service is a named error, not a hang', async () => {
  const api = createClient({ baseUrl: 'http://127.0.0.1:9' });
  await assert.rejects(api.brands.list(), (e: unknown) => e instanceof ApiError && e.code === 'unreachable' && e.status === 0);
});

test('a slow service hits the client timeout', async () => {
  await scenario({ delayMs: 400 });
  const api = createClient({ baseUrl: base, timeoutMs: 50 });
  await assert.rejects(api.brands.list(), (e: unknown) => e instanceof ApiError && e.code === 'timeout');
});

test('allPages follows next_cursor to the end', async () => {
  const api = createClient({ baseUrl: base });
  const rows = await allPages((cursor) => api.audit.list({ limit: 2, cursor }));
  assert.equal(rows.length, 3);
});

test('wording text is sent byte for byte, spaces included', async () => {
  const api = createClient({ baseUrl: base });
  const text = '  Leading and trailing spaces “quoted”  ';
  const d = await api.disclosures.register({ body: text, label: '2026-11', channels: ['sms'], purposes: ['marketing'], brand_ids: ['brd_acme'], effective_from: '2026-11-01' });
  assert.equal(d.body, text);
  const sent = (await log()).find((r) => r.method === 'POST' && r.url === '/v1/disclosures');
  assert.equal(sent?.body.body, text);
});

test('the revoke call is a POST with a reason, not a DELETE', async () => {
  const api = createClient({ baseUrl: base });
  await api.credentials.revoke('crd_web', 'rotating');
  const sent = (await log()).find((r) => r.url.includes(':revoke'));
  assert.equal(sent?.method, 'POST');
  assert.equal(sent?.body.reason, 'rotating');
});

test('error cause lines follow the formula and never hide an unknown name', () => {
  assert.equal(causeLine(503, 'service_unavailable'), 'The service did not answer (503 service_unavailable)');
  assert.equal(causeLine(418, 'teapot'), 'The service answered 418 teapot');
  assert.equal(causeLine(0, 'unreachable'), 'The service could not be reached (unreachable)');
});

test('the admin confirms the final export by posting the fingerprint of the file they received', async () => {
  const sha = 'a'.repeat(64);
  const seen: { url: string; method: string; body: unknown }[] = [];
  const stub = (async (url: string | URL | Request, init?: RequestInit) => {
    seen.push({ url: String(url), method: String(init?.method), body: JSON.parse(String(init?.body)) });
    return new Response(JSON.stringify({ request_id: 'req 1', final_export_delivered: { status: 'done', at: '2026-10-29T00:00:00Z', sha256: sha, via: 'link 1234abcd', confirmed_by: 'mem_1' } }), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  const api = createClient({ baseUrl: 'http://vault.test', fetch: stub });
  const out = await api.session.confirmFinalExport('req 1', sha);
  assert.equal(out.final_export_delivered.sha256, sha);
  assert.deepEqual(seen, [{ url: 'http://vault.test/v1/offboarding/req%201/final-export:confirm', method: 'POST', body: { sha256: sha } }]);
});

test('a fingerprint that does not match is a named error the screen can show', async () => {
  const stub = (async () => new Response(JSON.stringify({ error: 'validation_failed', detail: 'the digest does not match the final export; download it again with a new link', request_id: 'r1', fields: { sha256: 'mismatch' } }), { status: 422 })) as typeof fetch;
  const api = createClient({ baseUrl: 'http://vault.test', fetch: stub });
  await assert.rejects(api.session.confirmFinalExport('req1', 'b'.repeat(64)), (e: unknown) => e instanceof ApiError && e.code === 'validation_failed' && e.fields.sha256 === 'mismatch');
});

test('records: a contact point travels only in a POST body, filters only in the address', async () => {
  const api = createClient({ baseUrl: base });
  const r = await api.records.search('+15555550142');
  assert.equal(r.items.length, 1);
  const rv = await api.records.reveal(r.items.map((x) => x.record_id), 'review');
  assert.equal(rv.items[0].contact, '+15555550142');
  await api.records.list({ channel: 'sms', status: 'stop_on_record', limit: 5 });
  const l = await log();
  const search = l.find((x) => x.url.includes('records:search'))!;
  assert.equal(search.method, 'POST');
  assert.equal(search.url, '/v1/records:search');
  assert.equal(search.body.contact, '+15555550142');
  const list = l.find((x) => x.url.startsWith('/v1/records?'))!;
  assert.ok(!/\d{7}/.test(list.url) && !list.url.includes('@'));
});

test('records: a developer gets fingerprints and no names, and may not search or reveal', async () => {
  await scenario({ role: 'developer' });
  const api = createClient({ baseUrl: base });
  const p = await api.records.list({ limit: 3 });
  assert.ok(p.items.every((x) => x.contact.masked === null && x.person === null && /^[0-9a-f]{8}$/.test(x.contact.fp_hint)));
  await assert.rejects(api.records.search('+15555550142'), (e: unknown) => e instanceof ApiError && e.code === 'role_not_allowed');
  await assert.rejects(api.records.reveal([p.items[0].record_id]), (e: unknown) => e instanceof ApiError && e.status === 403);
  await assert.rejects(api.records.exportCreate({ filters: {}, contact_form: 'masked', include_person: false }), (e: unknown) => e instanceof ApiError && e.status === 403);
});

test('setup: skip is for the optional steps only', async () => {
  const api = createClient({ baseUrl: base });
  await scenario({ setup: 'almost' });
  const s = await api.setup.get();
  assert.equal(s.steps.length, 8);
  await assert.rejects(api.setup.skip('brand'), (e: unknown) => e instanceof ApiError && e.code === 'step_not_skippable');
  const k = await api.setup.skip('system', 'later');
  assert.equal(k.status, 'skipped');
  assert.equal((await api.setup.unskip('system')).status, 'to_do');
});

test('confirmations: a rule refuses to turn on until its prerequisites exist, in the contract order', async () => {
  await scenario({ confirmations: 'empty' });
  const api = createClient({ baseUrl: base });
  await assert.rejects(api.confirmations.saveRule('src_web', 'sms', { enabled: true, sending_brand_id: 'brd_acme' }), (e: unknown) => e instanceof ApiError && e.code === 'no_sending_account');
  await assert.rejects(api.confirmations.saveRule('src_web', 'email', { enabled: true, sending_brand_id: 'brd_acme' }), (e: unknown) => e instanceof ApiError && e.code === 'no_sending_account');
  await scenario({ confirmations: 'link_unset' });
  await assert.rejects(api.confirmations.saveRule('src_web', 'email', { enabled: true, sending_brand_id: 'brd_acme' }), (e: unknown) => e instanceof ApiError && e.code === 'link_host_not_verified');
  const off = await api.confirmations.saveRule('src_web', 'email', { enabled: false, sending_brand_id: 'brd_acme' });
  assert.equal(off.enabled, false);
});

test('confirmations: a developer sees sends by fingerprint and may not read replies', async () => {
  await scenario({ role: 'developer' });
  const api = createClient({ baseUrl: base });
  const sends = await api.confirmations.sends({ limit: 5 });
  assert.ok(sends.items.every((x) => x.contact.masked === null));
  await assert.rejects(api.confirmations.replies({ state: 'to_read' }), (e: unknown) => e instanceof ApiError && e.status === 403);
  await assert.rejects(api.confirmations.markReply('rpl_1', 'stop', 'x'), (e: unknown) => e instanceof ApiError && e.status === 403);
});

test('every request, read or write, is sent with cache no-store so a record response is never kept by the browser', async () => {
  const seen: (RequestInit | undefined)[] = [];
  const api = createClient({ baseUrl: base, fetch: (u, i) => { seen.push(i); return fetch(u, i); } });
  await api.session.get();
  await api.records.list({ limit: 5 });
  await api.records.search('+15555550142');
  await api.records.reveal(['rec_000']);
  assert.equal(seen.length, 4);
  assert.ok(seen.every((i) => i?.cache === 'no-store'), JSON.stringify(seen.map((i) => i?.cache)));
});
