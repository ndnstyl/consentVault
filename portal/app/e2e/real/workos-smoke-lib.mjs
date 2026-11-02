// The smoke test's own judgement, as pure functions so it can be unit tested (test/smoke-lib.test.mjs). Nothing here
// touches the network, the disk or a secret; every function returns data the script prints.
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

export const SESSION = '__Host-cv_session';

export function parseEnv(text) {
  return Object.fromEntries(text.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#') && l.includes('=')).map((l) => [l.slice(0, l.indexOf('=')).trim(), l.slice(l.indexOf('=') + 1).trim()]));
}

const MFA_POSSESSION = new Set(['hwk', 'swk', 'otp', 'sc', 'sms', 'tel']);
const MFA_SECOND = new Set(['pwd', 'pin', 'kba', 'bio', 'fpt', 'face', 'iris', 'retina', 'vbm', 'user']);
// The vault's own rule (providers/identity.py amr_is_multi_factor).
export const multiFactor = (amr) => Array.isArray(amr) && (amr.includes('mfa') || (amr.some((a) => MFA_POSSESSION.has(a)) && amr.some((a) => MFA_SECOND.has(a))));

export const b64 = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
const row = (name, ok, detail = '') => ({ name, ok: !!ok, detail });

// A Set-Cookie line as the edge sent it (value never kept by the caller; only attributes are judged).
export function parseSetCookie(line) {
  const [pair, ...attrs] = line.split(';').map((p) => p.trim());
  const eq = pair.indexOf('=');
  const flags = Object.fromEntries(attrs.map((a) => { const i = a.indexOf('='); return i < 0 ? [a.toLowerCase(), true] : [a.slice(0, i).toLowerCase(), a.slice(i + 1)]; }));
  return { name: pair.slice(0, eq), value: pair.slice(eq + 1), flags };
}

export function judgeSessionCookie(lines) {
  const c = lines.map(parseSetCookie).find((x) => x.name === SESSION && x.value !== '');
  if (!c) return [row('the edge set the session cookie', false, 'no Set-Cookie for it')];
  const f = c.flags;
  return [
    row('the session cookie is HttpOnly', f.httponly === true),
    row('the session cookie is Secure', f.secure === true),
    row('the session cookie is SameSite=Lax', String(f.samesite).toLowerCase() === 'lax', String(f.samesite)),
    row('the session cookie is Path=/ with no Domain (a __Host- cookie)', f.path === '/' && f.domain === undefined),
    row('the session cookie lasts eight hours', f['max-age'] === '28800', String(f['max-age'])),
    row('the session cookie value is opaque (not a token)', !c.value.includes('.') && !/^(eyJ|v1\.)/.test(c.value)),
  ];
}

export function judgeClearedCookie(lines) {
  const c = lines.map(parseSetCookie).find((x) => x.name === SESSION);
  return [row('sign-out cleared the session cookie', !!c && c.value === '' && c.flags['max-age'] === '0')];
}

// The identity token: judged from its own claims plus the key set the caller fetched (null when it could not be).
export function judgeToken(token, clientId, jwks, nowSec = Math.floor(Date.now() / 1000)) {
  const [h, p, s] = token.split('.');
  const head = b64(h); const claims = b64(p);
  const out = [row('the token uses an algorithm the vault allows (RS256 or ES256)', ['RS256', 'ES256'].includes(head.alg), head.alg)];
  let sigOk = false; let why = '';
  const jwk = jwks?.keys?.find((k) => k.kid === head.kid);
  if (!jwks) why = 'the provider key set could not be fetched';
  else if (!jwk) why = `no key ${head.kid} in the published key set`;
  else {
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const data = Buffer.from(`${h}.${p}`);
    sigOk = head.alg === 'ES256' ? crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url')) : crypto.verify('RSA-SHA256', data, key, Buffer.from(s, 'base64url'));
  }
  out.push(row('the signature verifies against the provider\'s published keys', sigOk, why));
  const auds = typeof claims.aud === 'string' ? [claims.aud] : Array.isArray(claims.aud) ? claims.aud : [];
  out.push(row('the token names this client: aud, or the client_id claim (accepted in its place when configured)', auds.includes(clientId) || (claims.aud === undefined && claims.client_id === clientId), `aud=${JSON.stringify(claims.aud)} client_id=${claims.client_id === clientId ? 'matches' : String(claims.client_id)}`));
  out.push(row('the token carries no amr of its own, so the vault relies on the edge assertion', claims.amr === undefined, claims.amr === undefined ? 'no amr claim' : 'an amr is present; the vault ignores it when assertions are on'));
  out.push(row('the token carries a subject', typeof claims.sub === 'string' && claims.sub.length > 0));
  out.push(row('the token has not expired', typeof claims.exp === 'number' && claims.exp > nowSec));
  return { rows: out, claimNames: Object.keys(claims).sort(), header: head, iss: claims.iss };
}

// The edge's signed sign-in-method statement, as the vault would judge it.
export function judgeAssertion(assertion, token, edgePublicKey) {
  const [ah, ap, as] = assertion.split('.');
  const c = b64(ap);
  const sigOk = crypto.verify('sha256', Buffer.from(`${ah}.${ap}`), { key: edgePublicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(as, 'base64url'));
  const rows = [
    row('the assertion verifies under the edge key', sigOk),
    row('the assertion is for this token and this person', c.tok === crypto.createHash('sha256').update(token).digest('hex') && c.sub === b64(token.split('.')[1]).sub),
    row('the assertion is for the vault and short-lived (60 s)', c.aud === 'consentvault-vault' && c.iss === 'consentvault-portal-edge' && c.exp - c.iat === 60),
    row('the sign-in methods show a passkey or second factor (the vault requires it)', multiFactor(c.amr), JSON.stringify(c.amr)),
    row('the assertion carries the address the provider verified (tokens carry none)', typeof c.email === 'string' && c.email.includes('@') && c.email_verified === true, c.email ? `${c.email_verified === true ? 'verified' : 'NOT verified'} address present` : 'no address'),
  ];
  return { rows, method: c.method, amr: c.amr };
}

// Who is listening on a TCP port (pid and command), or null when it is free. Read with lsof, never guessed.
export function describePortHolder(port) {
  const r = spawnSync('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-Fpc'], { encoding: 'utf8' });
  if (r.error) throw new Error(`could not run lsof to check port ${port}: ${r.error.message}`);
  const pid = /^p(\d+)$/m.exec(r.stdout); const cmd = /^c(.+)$/m.exec(r.stdout);
  return pid ? { pid: Number(pid[1]), command: cmd ? cmd[1] : 'unknown' } : null;
}

// A child started with detached:true leads its own process group; a negative pid signals the whole group.
export function killGroupSync(child, signal = 'SIGKILL') {
  if (!child?.pid) return;
  try { process.kill(-child.pid, signal); } catch (e) { if (e.code !== 'ESRCH') console.error(`could not signal the process group ${child.pid}: ${e.message}`); }
}

export async function stopGroup(child, graceMs = 15_000) {
  if (!child?.pid) return;
  killGroupSync(child, 'SIGTERM');
  const end = Date.now() + graceMs;
  const alive = () => { try { process.kill(-child.pid, 0); return true; } catch { return false; } };
  while (alive() && Date.now() < end) await new Promise((r) => setTimeout(r, 100));
  if (alive()) killGroupSync(child, 'SIGKILL');
}
