import test, { before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { createMock } from '../mock/server.ts';
import { ApiError, createClient } from '../src/lib/api/client.ts';
import { EMPTY_FORM, fieldMapBody, fieldMapErrors, splitLines } from '../src/lib/fieldmap.ts';
import { canDo, canView } from '../src/lib/roles.ts';
import { matchRoute } from '../src/lib/routes.ts';
import { scanCopy } from '../src/lib/copycheck.ts';
import { FIELD_MAP_COPY } from '../src/lib/copy.ts';

const mock = createMock();
const srv = mock.server(null, null);
let base = '';
before(async () => { await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r)); base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`; });
after(() => srv.close());
async function scenario(s: Record<string, unknown>) { await fetch(`${base}/__mock/scenario`, { method: 'POST', body: JSON.stringify(s) }); }
beforeEach(async () => { await scenario({}); });

const form = { ...EMPTY_FORM, body_format: 'form_urlencoded' as const, consent_paths: 'tcpa_box\nbox_two', consent_ticked_value: 'on', decision_time_path: 'submitted_at', contact_paths: 'phone: phone\nemail: email' };

test('lines are split, trimmed and empty lines dropped', () => {
  assert.deepEqual(splitLines('  a \n\n b\r\n'), ['a', 'b']);
  assert.deepEqual(splitLines(''), []);
});

test('the request body carries each stated path exactly as typed and leaves unstated ones out', () => {
  const b = fieldMapBody(form);
  assert.deepEqual(b, {
    body_format: 'form_urlencoded', consent_paths: ['tcpa_box', 'box_two'], consent_ticked_value: 'on', decision_time_path: 'submitted_at',
    contact_paths: [{ path: 'phone', kind: 'phone' }, { path: 'email', kind: 'email' }],
  });
  assert.equal('wording_path' in b, false);
  assert.equal('seller_paths' in b, false);
});

test('a ticked value is sent as typed, spaces and all, and an empty one is not sent', () => {
  assert.equal(fieldMapBody({ ...form, consent_ticked_value: ' on ' }).consent_ticked_value, ' on ');
  assert.equal('consent_ticked_value' in fieldMapBody({ ...form, consent_ticked_value: '' }), false);
});

test('the form needs a consent path and a well-formed contact line, and names each problem', () => {
  assert.deepEqual(fieldMapErrors(form), []);
  assert.equal(fieldMapErrors({ ...form, consent_paths: ' \n' }).length, 1);
  const bad = fieldMapErrors({ ...form, contact_paths: 'phone: fax\nnothing' });
  assert.equal(bad.length, 2);
  assert.ok(bad[0].message.includes('fax'));
});

test('the version screen is for admins and developers and has its own route', () => {
  assert.equal(matchRoute('/sources/src_1/field-maps')?.route.id, 'source-field-maps');
  assert.equal(matchRoute('/sources/src_1/field-maps')?.params.source_id, 'src_1');
  assert.equal(canView('admin', 'source-field-maps'), true);
  assert.equal(canView('developer', 'source-field-maps'), true);
  assert.equal(canView('compliance_viewer', 'source-field-maps'), false);
  assert.equal(canDo('developer', 'fieldmap.add'), true);
  assert.equal(canDo('compliance_viewer', 'fieldmap.add'), false);
});

test('the screen copy breaks no copy rule', () => {
  for (const text of Object.values(FIELD_MAP_COPY)) assert.deepEqual(scanCopy(text), [], text);
});

test('reads the versions newest first with the built-in widget map, and adds one that is never an edit', async () => {
  const api = createClient({ baseUrl: base });
  const first = await api.sources.fieldMaps.list('src_web');
  assert.deepEqual(first.items, []);
  assert.equal(first.built_in.label, 'built_in:widget');
  assert.deepEqual(first.built_in.consent_paths, ['/checked']);
  const a = await api.sources.fieldMaps.add('src_web', fieldMapBody(form));
  assert.equal(a.map_version, 1);
  assert.ok(a.set_by);
  const b = await api.sources.fieldMaps.add('src_web', { ...fieldMapBody(form), consent_paths: ['other'] });
  assert.equal(b.map_version, 2);
  const list = await api.sources.fieldMaps.list('src_web');
  assert.deepEqual(list.items.map((i) => i.map_version), [2, 1]);
  assert.deepEqual(list.items[1].consent_paths, ['tcpa_box', 'box_two']);
  for (const method of ['PUT', 'PATCH', 'DELETE']) {
    const r = await fetch(`${base}/v1/sources/src_web/field-maps/1`, { method, body: '{}' });
    assert.ok(r.status === 404 || r.status === 405, method);
  }
});

test('an unknown source and a missing consent path are refused with a named error', async () => {
  const api = createClient({ baseUrl: base });
  await assert.rejects(api.sources.fieldMaps.list('src_nope'), (e: unknown) => e instanceof ApiError && e.status === 404);
  await assert.rejects(api.sources.fieldMaps.add('src_web', { ...fieldMapBody(form), consent_paths: [] }), (e: unknown) => e instanceof ApiError && e.code === 'validation_failed');
});
