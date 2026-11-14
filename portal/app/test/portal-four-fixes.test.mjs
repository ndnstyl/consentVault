import './support/register-tsx.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';

const { SessionContext } = await import('../src/lib/session.tsx');
const { RouterContext } = await import('../src/lib/router.tsx');
const { DownloadPanel, PackageFacts, EXPORT_COLUMNS } = await import('../src/screens/evidence.tsx');
const { CredentialNewView } = await import('../src/screens/config.tsx');
const { WordingTable, WordingFacts } = await import('../src/screens/wording.tsx');
const { CompanySignIn } = await import('../src/screens/org.tsx');

const h = React.createElement;
const noop = () => {};
const session = (over = {}) => ({ api: { session: { org: () => new Promise(() => {}) } }, phase: 'ready', error: null, user: { display_name: 'Dana Ruiz', email: 'dana@example.com' }, memberships: [], org: null, orgId: 'o1', orgName: 'Acme Roofing', role: 'admin', status: 'active', elsewhere: null, sessionEnding: false, refreshOrg: async () => {}, ...over });
const router = { path: '/x', search: new URLSearchParams(), matched: null, navigations: 0, navigate: noop };
const render = (el, sess = session()) => renderToStaticMarkup(h(SessionContext.Provider, { value: sess }, h(RouterContext.Provider, { value: router }, el)));
const text = (html) => html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').replace(/&#x27;/g, "'");

// ---- 1. Evidence packages. expires_at on a package is its retention date; a new link's expires_at is 15 minutes out (evidence.py).
const RETAINED = '2026-12-14T12:00:00Z';
const READY = { export_id: 'e1', status: 'ready', progress: null, failed_cause: null, download_url: '/v1/exports/e1/download?link=abc', sha256: 'a'.repeat(64), signature: 'k1', expires_at: RETAINED, downloaded_at: null };
const panel = (over) => text(render(h(DownloadPanel, { d: READY, spent: false, clicks: 0, linkUntil: null, suspended: false, linkBusy: false, onDownloadClick: noop, onNewLink: noop, ...over })));

test('Evidence: the first click on Download says "Download started", never "used or expired"', () => {
  const t = panel({ clicks: 1 });
  assert.match(t, /Download started/);
  assert.doesNotMatch(t, /used or expired/);
});
test('Evidence: once Download is clicked, no Download package button or ready banner is offered beside "Download started"', () => {
  for (const over of [{ clicks: 1 }, { clicks: 1, spent: true, d: { ...READY, download_url: null } }]) {
    const html = render(h(DownloadPanel, { d: READY, spent: false, clicks: 0, linkUntil: null, suspended: false, linkBusy: false, onDownloadClick: noop, onNewLink: noop, ...over }));
    assert.match(text(html), /Download started/);
    assert.doesNotMatch(html, /Download package/);
    assert.doesNotMatch(text(html), /Package ready/);
    assert.match(text(html), /Get a new link/);
  }
  assert.match(panel({ clicks: 0 }), /Download package/);
});
test('Evidence: after the first download the list refreshes to spent and the screen still says started', () => {
  const t = panel({ clicks: 1, spent: true, d: { ...READY, download_url: null, downloaded_at: '2026-11-14T15:01:00Z' } });
  assert.match(t, /Download started/);
  assert.doesNotMatch(t, /used or expired/);
});
test('Evidence: a second attempt, or opening a package whose link is already spent, shows the used notice', () => {
  assert.match(panel({ clicks: 2 }), /used or expired/);
  assert.match(panel({ clicks: 0, spent: true, d: { ...READY, download_url: null } }), /used or expired/);
});
test('Evidence: the ready banner states the link rule and never prints the retention date as the link expiry', () => {
  const t = panel({});
  assert.match(t, /works once/);
  assert.match(t, /15 minutes/);
  assert.doesNotMatch(t, /Dec 14|2026-12-14/);
});
test('Evidence: a freshly issued link names its own expiry', async () => {
  const { fmtDateTime } = await import('../src/lib/format.ts');
  assert.ok(panel({ linkUntil: '2026-11-14T15:15:00Z' }).includes(`until ${fmtDateTime('2026-11-14T15:15:00Z')}`));
});
test('Evidence: the package page shows the link rule and the retention date as two labelled facts', () => {
  const t = text(render(h(PackageFacts, { d: READY })));
  assert.match(t, /Package kept until\s*Dec 14, 2026/);
  assert.match(t, /Download link\s*Works once, for 15 minutes/);
  assert.doesNotMatch(t, /Link expires/);
});
test('Evidence: the list column is the retention date and says so', () => {
  const col = EXPORT_COLUMNS.find((c) => c.key === 'x');
  assert.equal(col.header, 'Kept until');
  const cell = text(render(h('div', null, col.render({ expires_at: RETAINED, downloaded_at: null, status: 'ready' }))));
  assert.match(cell, /Dec 14, 2026/);
});

// ---- 2. Credential kind follows the source
const SRC = (kind) => ({ source_id: 's1', name: 'Main', kind, brand_ids: [], allowed_origins: [], status: 'active', created_at: '2026-11-01T00:00:00Z', last_event_at: null, last_event_seq: null, last_event_sealed: null });
const kindChecked = (sources, qs = '') => {
  const res = { status: 'ok', data: { sources }, error: null, reload: noop, refresh: noop, setData: noop };
  const r = { ...router, search: new URLSearchParams(qs) };
  const html = renderToStaticMarkup(h(SessionContext.Provider, { value: session() }, h(RouterContext.Provider, { value: r }, h(CredentialNewView, { res }))));
  return [...html.matchAll(/<label[^>]*class="opt"[^>]*>\s*<input([^>]*)>\s*<span><b>(.*?)<\/b>/g)].filter((m) => /name="kind"/.test(m[1]) && /checked/.test(m[1])).map((m) => m[2]);
};
test('Credential: a server source defaults to the public key kind', () => {
  assert.deepEqual(kindChecked([SRC('server')]), ['Public key for a server (you keep the private key)']);
});
test('Credential: a website source defaults to the site key kind', () => {
  assert.deepEqual(kindChecked([SRC('site_key')]), ['Site key for a website form']);
});
test('Credential: a source chosen by address defaults to its own kind', () => {
  const two = [SRC('site_key'), { ...SRC('server'), source_id: 's2', name: 'Back end' }];
  assert.deepEqual(kindChecked(two, 'source=s2'), ['Public key for a server (you keep the private key)']);
});
test('Credential: no source, or a kind it does not know, leaves no kind chosen', () => {
  assert.deepEqual(kindChecked([]), []);
  assert.deepEqual(kindChecked([SRC('something_new')]), []);
});

// ---- 3. Wording dates
const WORD = { sha256: 'b'.repeat(64), label: 'Form text', version_label: '1', channels: ['sms'], purposes: ['marketing'], brand_ids: [], supersedes_sha256: null, superseded_by_sha256: null, effective_from: '2026-11-01T00:00:00Z', registered_by: 'm1', registered_at: '2026-11-14T12:00:00Z', body: 'x' };
test('Wording list: the two dates carry labels that cannot read as a contradiction, with one hint', () => {
  const t = text(render(h(WordingTable, { rows: [WORD], l: null })));
  assert.match(t, /In use from/);
  assert.match(t, /Added to ConsentVault on/);
  assert.doesNotMatch(t, /Shown from/);
  assert.match(t, /Nov 1, 2026/);
  assert.match(t, /Nov 14, 2026/);
  assert.equal((t.match(/numbered in the order/gi) ?? []).length, 1);
});
test('Wording page: the same two labels and one hint', () => {
  const t = text(render(h(WordingFacts, { d: WORD, by: 'Dana Ruiz', l: null, link: () => null })));
  assert.match(t, /In use from\s*Nov 1, 2026/);
  assert.match(t, /Added to ConsentVault on\s*Nov 14, 2026/);
  assert.doesNotMatch(t, /Shown from|Registered\s/);
  assert.equal((t.match(/numbered in the order/gi) ?? []).length, 1);
});

// ---- 4. Company sign-in: the session already holds the organization, so nothing loads
test('Company sign-in: with the organization in hand there is no loading placeholder', () => {
  const org = { org_id: 'o1', name: 'Acme Roofing', status: 'active', sso: { connected: true, connection_id: 'c1', required: false, verified: true } };
  const t = text(render(h(CompanySignIn), session({ org })));
  assert.doesNotMatch(t, /Loading/);
  assert.match(t, /Connected and confirmed/);
});
test('Company sign-in: with nothing in hand yet it shows the shared skeleton', () => {
  assert.match(text(render(h(CompanySignIn), session({ org: null }))), /Loading company sign-in/);
});

// ---- review warning: the company sign-in re-read after a save
const { ApiError } = await import('../src/lib/api/client.ts');
const { saveThenRead } = await import('../src/screens/org.tsx');
test('Company sign-in: a saved setting that cannot be read back is an error naming the failure, never "saved"', async () => {
  const failure = new ApiError(503, 'service_unavailable', '', null);
  const o = await saveThenRead(async () => ({ ok: true }), async () => failure, 'Company sign-in is now required for everyone.');
  assert.equal(o.saved, null);
  assert.equal(o.readFailed, failure);
});
test('Company sign-in: a clean save and read-back says saved; a refused save says neither', async () => {
  const done = 'Company sign-in is now required for everyone.';
  assert.deepEqual(await saveThenRead(async () => ({ ok: true }), async () => null, done), { saved: done, readFailed: null });
  assert.deepEqual(await saveThenRead(async () => ({ ok: false }), async () => { throw new Error('must not read'); }, done), { saved: null, readFailed: null });
});
test('Session: refreshOrg reports a failed read instead of swallowing it', () => {
  const src = readFileSync(new URL('../src/lib/session.tsx', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /catch \{ \/\* the page that asked shows its own error \*\/ \}/);
  assert.match(src, /refreshOrg: \(\) => Promise<ApiError \| null>/);
});

// ---- the vault refuses a public key for a website source, so the form does not offer it
const kindInputs = (sources) => {
  const res = { status: 'ok', data: { sources }, error: null, reload: noop, refresh: noop, setData: noop };
  const html = renderToStaticMarkup(h(SessionContext.Provider, { value: session() }, h(RouterContext.Provider, { value: router }, h(CredentialNewView, { res }))));
  return [...html.matchAll(/<label[^>]*class="opt"[^>]*>\s*<input([^>]*)>\s*<span><b>(.*?)<\/b>(.*?)<\/span>/g)].filter((m) => /name="kind"/.test(m[1])).map((m) => ({ label: m[2], disabled: /disabled/.test(m[1]), hint: m[3] }));
};
test('Credential: for a website source the public key option is off and says why; for a server source it is on', () => {
  const web = kindInputs([SRC('site_key')]).find((k) => /Public key/.test(k.label));
  assert.equal(web.disabled, true);
  assert.match(web.hint, /website form/i);
  assert.equal(kindInputs([SRC('server')]).find((k) => /Public key/.test(k.label)).disabled, false);
});
