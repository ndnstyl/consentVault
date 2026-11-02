import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { judgeAssertion, judgeClearedCookie, judgeSessionCookie, judgeToken, multiFactor, parseEnv } from '../e2e/real/workos-smoke-lib.mjs';

const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'k1' };
function token(claims, key = pair.privateKey) {
  const h = enc({ alg: 'RS256', kid: 'k1' }); const p = enc(claims);
  return `${h}.${p}.${crypto.sign('RSA-SHA256', Buffer.from(`${h}.${p}`), key).toString('base64url')}`;
}
const NOW = 1_800_000_000;
const good = { iss: 'https://api.workos.com/user_management/client_1', client_id: 'client_1', sub: 'user_1', sid: 's1', exp: NOW + 300 };
const failing = (rows) => rows.filter((r) => !r.ok).map((r) => r.name);

test('the env file is read by name and comments are skipped', () => {
  assert.deepEqual(parseEnv('# note\nWORKOS_API_KEY=a=b\n\nWORKOS_CLIENT_ID = c1\n'), { WORKOS_API_KEY: 'a=b', WORKOS_CLIENT_ID: 'c1' });
});

test('the vault\'s second-factor rule: a passkey, mfa, or a possession plus a knowledge factor; a password alone is not', () => {
  assert.ok(multiFactor(['hwk', 'user']) && multiFactor(['mfa']) && multiFactor(['otp', 'pwd']));
  for (const bad of [[], ['pwd'], ['otp'], ['hwk'], undefined, 'mfa']) assert.ok(!multiFactor(bad), JSON.stringify(bad));
});

test('a good session cookie passes every check; each missing attribute is named', () => {
  const ok = '__Host-cv_session=abc123; Max-Age=28800; Path=/; HttpOnly; Secure; SameSite=Lax';
  assert.deepEqual(failing(judgeSessionCookie([ok])), []);
  assert.ok(failing(judgeSessionCookie([ok.replace('; HttpOnly', '')])).some((n) => /HttpOnly/.test(n)));
  assert.ok(failing(judgeSessionCookie([ok.replace('; Secure', '')])).some((n) => /Secure/.test(n)));
  assert.ok(failing(judgeSessionCookie([ok.replace('Lax', 'None')])).some((n) => /Lax/.test(n)));
  assert.ok(failing(judgeSessionCookie([ok + '; Domain=example.com'])).some((n) => /no Domain/.test(n)));
  assert.ok(failing(judgeSessionCookie(['__Host-cv_session=eyJ.a.b; Max-Age=28800; Path=/; HttpOnly; Secure; SameSite=Lax'])).some((n) => /opaque/.test(n)));
  assert.ok(failing(judgeSessionCookie(['other=1'])).length > 0);
});

test('the cleared cookie is an empty value with Max-Age=0', () => {
  assert.deepEqual(failing(judgeClearedCookie(['__Host-cv_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax'])), []);
  assert.equal(failing(judgeClearedCookie(['__Host-cv_session=abc; Max-Age=28800'])).length, 1);
  assert.equal(failing(judgeClearedCookie([])).length, 1);
});

test('the token: a WorkOS-shaped token passes; a wrong client, a bad signature or an expired one is named', () => {
  const jwks = { keys: [jwk] };
  const r = judgeToken(token(good), 'client_1', jwks, NOW);
  assert.deepEqual(failing(r.rows), []);
  assert.ok(r.claimNames.includes('client_id'));
  assert.ok(failing(judgeToken(token({ ...good, client_id: 'other' }), 'client_1', jwks, NOW).rows).some((n) => /names this client/.test(n)));
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.ok(failing(judgeToken(token(good, other.privateKey), 'client_1', jwks, NOW).rows).some((n) => /signature/.test(n)));
  assert.ok(failing(judgeToken(token({ ...good, exp: NOW - 1 }), 'client_1', jwks, NOW).rows).some((n) => /expired/.test(n)));
  assert.ok(failing(judgeToken(token(good), 'client_1', null, NOW).rows).some((n) => /signature/.test(n)));
});

test('the assertion: verified under the edge key, for this token and person, with a second factor', () => {
  const edge = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const tok = token(good);
  const make = (over = {}, key = edge.privateKey) => {
    const h = enc({ alg: 'ES256', kid: 'e' });
    const p = enc({ iss: 'consentvault-portal-edge', aud: 'consentvault-vault', sub: 'user_1', tok: crypto.createHash('sha256').update(tok).digest('hex'), amr: ['hwk', 'user'], method: 'Passkey', email: 'a@b.example', email_verified: true, iat: NOW, exp: NOW + 60, ...over });
    return `${h}.${p}.${crypto.sign('sha256', Buffer.from(`${h}.${p}`), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
  };
  const ok = judgeAssertion(make(), tok, edge.publicKey);
  assert.deepEqual(failing(ok.rows), []);
  assert.equal(ok.method, 'Passkey');
  assert.deepEqual(ok.amr, ['hwk', 'user']);
  assert.ok(failing(judgeAssertion(make({ email: undefined }), tok, edge.publicKey).rows).some((n) => /address/.test(n)));
  assert.ok(failing(judgeAssertion(make({ amr: [] }), tok, edge.publicKey).rows).some((n) => /passkey or second factor/.test(n)));
  assert.ok(failing(judgeAssertion(make({ tok: '0'.repeat(64) }), tok, edge.publicKey).rows).some((n) => /this token/.test(n)));
  assert.ok(failing(judgeAssertion(make({}, crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey), tok, edge.publicKey).rows).some((n) => /verifies/.test(n)));
});
