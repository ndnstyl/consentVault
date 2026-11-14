import test from 'node:test';
import assert from 'node:assert/strict';
import { interpretLogout } from '../src/lib/logout.ts';

test('a good sign-out answer goes to the provider address or the sign-in page', () => {
  assert.deepEqual(interpretLogout(200, { redirect: 'https://api.workos.com/user_management/sessions/logout?session_id=s' }), { go: 'https://api.workos.com/user_management/sessions/logout?session_id=s' });
  assert.deepEqual(interpretLogout(200, { redirect: '/sign-in' }), { go: '/sign-in' });
  assert.deepEqual(interpretLogout(200, {}), { go: '/sign-in' });
});

test('an address that is not a path or a web address is never followed', () => {
  assert.deepEqual(interpretLogout(200, { redirect: 'javascript:alert(1)' }), { go: '/sign-in' });
});

test('a failed sign-out is shown as an error and the page stays put (it is not treated as signed out)', () => {
  for (const status of [500, 502, 503]) {
    const r = interpretLogout(status, { error: 'session_unavailable', message: 'The session store did not answer.' });
    assert.ok('error' in r && /could not be signed out|did not finish/i.test(r.error) && /session store/i.test(r.error), String(status));
  }
  assert.ok('error' in interpretLogout(0, null));
});

test('sign-out is sent as a POST with cache no-store and credentials included', async () => {
  const { postLogout } = await import('../src/lib/logout.ts');
  const seen: { url: string; init: RequestInit | undefined }[] = [];
  const g = globalThis as unknown as { fetch: unknown; window: unknown };
  const saved = { fetch: g.fetch, window: g.window };
  g.fetch = async (url: string, init?: RequestInit) => { seen.push({ url, init }); return new Response(JSON.stringify({ redirect: '/sign-in' }), { status: 200 }); };
  let went = '';
  g.window = { location: { assign: (u: string) => { went = u; } } };
  try {
    assert.equal(await postLogout(), null);
  } finally { g.fetch = saved.fetch; g.window = saved.window; }
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, '/auth/logout');
  assert.equal(seen[0].init?.method, 'POST');
  assert.equal(seen[0].init?.cache, 'no-store');
  assert.equal(seen[0].init?.credentials, 'include');
  assert.equal(went, '/sign-in');
});
