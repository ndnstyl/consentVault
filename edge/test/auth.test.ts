import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { handleAuth, type AuthDeps, type AuthEnv } from "../src/auth.ts";
import { SESSION_COOKIE, LOGIN_COOKIE, loadSession } from "../src/session.ts";
import { AUTH_ENV_BASE, NOW_MS, cookieNamed, cookieValueOf, jwt, memKV, nowSec, setCookies } from "./support/portal.ts";

import crypto from "node:crypto";
const PRIVATE_JWK = JSON.stringify({ ...crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }), kid: "edge1" });
const claimsOf = (a: string) => JSON.parse(Buffer.from(a.split(".")[1], "base64url").toString("utf8"));
const IDT = jwt({ sub: "user_1", sid: "provider_sess_1", exp: nowSec() + 300 });

function mk(opts: { exchange?: () => Response; vault?: () => Response } = {}) {
  const kv = memKV();
  const env: AuthEnv = { ...AUTH_ENV_BASE, SESSIONS: kv, ASSERTION_KEY_JWK: PRIVATE_JWK };
  const calls: { url: string; init: RequestInit }[] = [];
  const vaultCalls: { path: string; auth: string | null; headers?: Record<string, string> }[] = [];
  const deps: AuthDeps = {
    now: () => NOW_MS,
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      return opts.exchange ? opts.exchange() : new Response(JSON.stringify({ id_token: IDT, access_token: "opaque-access", refresh_token: "rt_1" }), { status: 200 });
    }) as unknown as typeof fetch,
    vault: async (path, token, headers) => {
      vaultCalls.push({ path, auth: token, headers });
      return opts.vault ? opts.vault() : new Response(JSON.stringify({ items: [] }), { status: 200 });
    },
  };
  return { kv, env, deps, calls, vaultCalls };
}
const req = (path: string, init: RequestInit = {}) => new Request("https://app.example.com" + path, init);

async function startLogin(m: ReturnType<typeof mk>, query = "") {
  const res = await handleAuth(req("/auth/login" + query), m.env, m.deps);
  assert.ok(res);
  const loc = new URL(res.headers.get("location")!);
  return { res, loc, state: loc.searchParams.get("state")!, cookie: cookieNamed(res, LOGIN_COOKIE)! };
}

test("login redirects to the provider with a code request, PKCE (S256) and a state, and binds the browser with a __Host- cookie", async () => {
  const m = mk();
  const { res, loc, state, cookie } = await startLogin(m, "?method=passkey&return=%2Fevidence");
  assert.equal(res.status, 302);
  assert.equal(loc.origin + loc.pathname, "https://idp.example/user_management/authorize");
  assert.equal(loc.searchParams.get("response_type"), "code");
  assert.equal(loc.searchParams.get("client_id"), "client_test");
  assert.equal(loc.searchParams.get("redirect_uri"), "https://app.example.com/auth/callback");
  assert.equal(loc.searchParams.get("provider"), "authkit");
  assert.equal(loc.searchParams.get("code_challenge_method"), "S256");
  assert.ok(state.length >= 32);
  const rec = JSON.parse([...m.kv.data.values()][0]);
  assert.equal(loc.searchParams.get("code_challenge"), createHash("sha256").update(rec.verifier).digest("base64url"));
  assert.equal(rec.ret, "/evidence");
  assert.ok(rec.verifier.length >= 43 && !loc.search.includes(rec.verifier), "the verifier never leaves the edge");
  assert.equal(cookieValueOf(cookie), state);
  for (const a of ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"]) assert.ok(cookie.includes(a), a);
  assert.ok(!/Domain=/i.test(cookie), "a __Host- cookie has no Domain");
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.ok(![...m.kv.data.keys()].some((k) => k.includes(state)), "the stored key is not the raw state");
});

test("only the hosted sign-in is ever requested, and an unsafe return address becomes the home page", async () => {
  const m = mk();
  // passkey and company sign-in both go through the hosted page, which sends a company address to its connection; a personal
  // Google or Microsoft account is not offered, and asking for one by name is not honoured
  assert.equal((await startLogin(m, "?method=sso")).loc.searchParams.get("provider"), "authkit");
  assert.equal((await startLogin(m, "?method=google")).loc.searchParams.get("provider"), "authkit");
  assert.equal((await startLogin(m, "?method=microsoft")).loc.searchParams.get("provider"), "authkit");
  assert.equal((await startLogin(m, "?method=whatever")).loc.searchParams.get("provider"), "authkit");
  for (const bad of ["https://evil.example", "//evil.example", "/\\evil.example", "javascript:alert(1)"]) {
    const m2 = mk();
    await startLogin(m2, "?return=" + encodeURIComponent(bad));
    assert.equal(JSON.parse([...m2.kv.data.values()][0]).ret, "/", bad);
  }
});

test("callback: checks the state, exchanges the code with the verifier on the server, sets a cookie that holds no tenant data", async () => {
  const m = mk();
  const { state, cookie } = await startLogin(m, "?return=%2Fbrands");
  const verifier = JSON.parse([...m.kv.data.values()][0]).verifier;
  const res = (await handleAuth(req(`/auth/callback?code=abc&state=${state}`, { headers: { cookie: `${LOGIN_COOKIE}=${cookieValueOf(cookie)}` } }), m.env, m.deps))!;
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), "/auth/callback?return=%2Fbrands");
  const ex = m.calls[0];
  assert.equal(ex.url, "https://idp.example/user_management/authenticate");
  assert.deepEqual(JSON.parse(String(ex.init.body)), { client_id: "client_test", client_secret: "test-only-client-credential", grant_type: "authorization_code", code: "abc", code_verifier: verifier });
  assert.deepEqual(m.vaultCalls.map((c) => [c.path, c.auth]), [["/v1/session?limit=1", IDT]]);
  const sc = cookieNamed(res, SESSION_COOKIE)!;
  for (const a of ["HttpOnly", "Secure", "SameSite=Lax", "Path=/", "Max-Age=28800"]) assert.ok(sc.includes(a), a);
  assert.ok(!/Domain=/i.test(sc));
  const sid = cookieValueOf(sc);
  assert.ok(!IDT.includes(sid) && !sid.includes("user_1") && sid.length >= 32, "an opaque id, no token or tenant data");
  const stored = [...m.kv.data.entries()].filter(([k]) => k.startsWith("sess:"));
  assert.equal(stored.length, 1);
  assert.equal(m.kv.ttl.get(stored[0][0]), 28800);
  assert.equal(JSON.parse(stored[0][1]).token, IDT);
  assert.ok(cookieNamed(res, LOGIN_COOKIE)!.includes("Max-Age=0"), "the login cookie is spent");
  assert.ok(![...m.kv.data.keys()].some((k) => k.startsWith("login:")), "the login record is single use");
});

test("callback refuses a wrong, missing or replayed state without calling the provider", async () => {
  const m = mk();
  const { state, cookie } = await startLogin(m);
  const wrong = await handleAuth(req(`/auth/callback?code=abc&state=${state}`, { headers: { cookie: `${LOGIN_COOKIE}=other` } }), m.env, m.deps);
  const none = await handleAuth(req(`/auth/callback?code=abc&state=${state}`), m.env, m.deps);
  const forged = await handleAuth(req(`/auth/callback?code=abc&state=zzz`, { headers: { cookie: `${LOGIN_COOKIE}=zzz` } }), m.env, m.deps);
  for (const r of [wrong, none, forged]) {
    assert.equal(r!.status, 400);
    assert.equal(cookieNamed(r!, SESSION_COOKIE), undefined);
  }
  assert.equal(m.calls.length, 0);
  const ok = await handleAuth(req(`/auth/callback?code=abc&state=${state}`, { headers: { cookie: `${LOGIN_COOKIE}=${cookieValueOf(cookie)}` } }), m.env, m.deps);
  assert.equal(ok!.status, 302);
  const replay = await handleAuth(req(`/auth/callback?code=abc&state=${state}`, { headers: { cookie: `${LOGIN_COOKIE}=${cookieValueOf(cookie)}` } }), m.env, m.deps);
  assert.equal(replay!.status, 400);
  assert.equal(m.calls.length, 1);
});

test("callback: a provider refusal returns to sign-in; a failed exchange or a vault that rejects the token sets no cookie", async () => {
  const m = mk();
  const denied = (await handleAuth(req("/auth/callback?error=access_denied"), m.env, m.deps))!;
  assert.equal(denied.status, 302);
  assert.equal(denied.headers.get("location"), "/sign-in");
  assert.equal(m.calls.length, 0);

  const bad = mk({ exchange: () => new Response('{"error":"invalid_grant"}', { status: 400 }) });
  const s1 = await startLogin(bad);
  const r1 = (await handleAuth(req(`/auth/callback?code=x&state=${s1.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s1.state}` } }), bad.env, bad.deps))!;
  assert.equal(r1.status, 401);
  assert.equal(cookieNamed(r1, SESSION_COOKIE), undefined);

  const down = mk({ exchange: () => { throw new Error("net"); } });
  const s2 = await startLogin(down);
  const r2 = (await handleAuth(req(`/auth/callback?code=x&state=${s2.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s2.state}` } }), down.env, down.deps))!;
  assert.equal(r2.status, 502);

  const reject = mk({ vault: () => new Response('{"error":"unauthenticated"}', { status: 401 }) });
  const s3 = await startLogin(reject);
  const r3 = (await handleAuth(req(`/auth/callback?code=x&state=${s3.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s3.state}` } }), reject.env, reject.deps))!;
  assert.equal(r3.status, 401);
  assert.equal(cookieNamed(r3, SESSION_COOKIE), undefined);
  assert.ok(![...reject.kv.data.keys()].some((k) => k.startsWith("sess:")));

  const dead = mk({ vault: () => { throw new Error("origin down"); } });
  const s4 = await startLogin(dead);
  const r4 = (await handleAuth(req(`/auth/callback?code=x&state=${s4.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s4.state}` } }), dead.env, dead.deps))!;
  assert.equal(r4.status, 502);
});

test("callback: a token without a second factor still gets a session so the portal can explain", async () => {
  const m = mk({ vault: () => new Response('{"error":"second_factor_required"}', { status: 403 }) });
  const s = await startLogin(m);
  const r = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), m.env, m.deps))!;
  assert.equal(r.status, 302);
  assert.ok(cookieNamed(r, SESSION_COOKIE));
});

test("callback: the sign-in method the provider reports reaches the vault only as a signed assertion, and a password alone is signed as no second factor", async () => {
  const cases: [Record<string, unknown>, string[]][] = [
    [{ authentication_method: "Passkey" }, ["hwk", "user"]],
    [{ authentication_method: "Password", authentication_factors: [{ type: "totp" }] }, []],
    [{ authentication_method: "MagicAuth" }, []],
    [{ authentication_method: "Password" }, []],
  ];
  for (const [answer, amr] of cases) {
    const m = mk({ exchange: () => new Response(JSON.stringify({ id_token: IDT, refresh_token: "rt_1", user: { id: "user_1", email: "dana@acme.example", email_verified: true }, ...answer }), { status: 200 }) });
    const s = await startLogin(m);
    const r = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), m.env, m.deps))!;
    assert.equal(r.status, 302);
    const a = m.vaultCalls[0].headers!["x-consentvault-edge-assertion"];
    assert.deepEqual(claimsOf(a).amr, amr, JSON.stringify(answer));
    assert.equal(claimsOf(a).sub, "user_1");
    const rec = JSON.parse([...m.kv.data.entries()].find(([k]) => k.startsWith("sess:"))![1]);
    assert.equal(rec.email, "dana@acme.example");
    assert.equal(claimsOf(a).email, "dana@acme.example", "the provider-verified address rides in the signed assertion");
    assert.equal(claimsOf(a).email_verified, true);
    assert.deepEqual(rec.amr, amr, "kept in the Worker's store for later calls, never in the cookie");
    assert.ok(!cookieNamed(r, SESSION_COOKIE)!.includes("amr"));
  }
});

test("callback with neither code nor error is the portal's own page and falls through", async () => {
  const m = mk();
  assert.equal(await handleAuth(req("/auth/callback?return=%2F"), m.env, m.deps), null);
  assert.equal(await handleAuth(req("/brands"), m.env, m.deps), null);
});

test("logout clears the cookie, deletes the stored session and ends the provider session", async () => {
  const m = mk();
  const s = await startLogin(m);
  const cb = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), m.env, m.deps))!;
  const sid = cookieValueOf(cookieNamed(cb, SESSION_COOKIE)!);
  const out = (await handleAuth(req("/auth/logout", { method: "POST", headers: { cookie: `${SESSION_COOKIE}=${sid}`, origin: "https://app.example.com" } }), m.env, m.deps))!;
  assert.equal(out.status, 302);
  const loc = new URL(out.headers.get("location")!);
  assert.equal(loc.origin + loc.pathname, "https://idp.example/user_management/sessions/logout");
  assert.equal(loc.searchParams.get("session_id"), "provider_sess_1");
  assert.equal(loc.searchParams.get("return_to"), "https://app.example.com/sign-in");
  assert.ok(cookieNamed(out, SESSION_COOKIE)!.includes("Max-Age=0"));
  assert.ok(![...m.kv.data.keys()].some((k) => k.startsWith("sess:")));
  const again = (await handleAuth(req("/auth/logout", { method: "POST", headers: { origin: "https://app.example.com" } }), m.env, m.deps))!;
  assert.equal(again.headers.get("location"), "/sign-in");
  assert.deepEqual(setCookies(again).length, 1);
});

test("a missing provider setting is a named error, not a half sign-in", async () => {
  const m = mk();
  const res = (await handleAuth(req("/auth/login"), { ...m.env, AUTH_CLIENT_ID: "" }, m.deps))!;
  assert.equal(res.status, 500);
  assert.match(await res.text(), /AUTH_CLIENT_ID/);
});

test("logout changes state, so it is a POST from the portal's own origin; a followed link or another site cannot sign anyone out", async () => {
  const m = mk();
  const s = await startLogin(m);
  const cb = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), m.env, m.deps))!;
  const sid = cookieValueOf(cookieNamed(cb, SESSION_COOKIE)!);
  const cookie = `${SESSION_COOKIE}=${sid}`;
  assert.equal((await handleAuth(req("/auth/logout", { headers: { cookie } }), m.env, m.deps))!.status, 405);
  for (const origin of [undefined, "https://evil.example", "null"]) {
    const res = (await handleAuth(req("/auth/logout", { method: "POST", headers: origin ? { cookie, origin } : { cookie } }), m.env, m.deps))!;
    assert.equal(res.status, 403, String(origin));
  }
  assert.ok([...m.kv.data.keys()].some((k) => k.startsWith("sess:")), "the session survived every refused attempt");
});

test("a sign-out the dashboard makes over fetch gets the provider address in the body, not a redirect its own policy would block", async () => {
  const m = mk();
  const s = await startLogin(m);
  const cb = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), m.env, m.deps))!;
  const cookie = `${SESSION_COOKIE}=${cookieValueOf(cookieNamed(cb, SESSION_COOKIE)!)}`;
  const out = (await handleAuth(req("/auth/logout", { method: "POST", headers: { cookie, origin: "https://app.example.com", accept: "application/json" } }), m.env, m.deps))!;
  assert.equal(out.status, 200);
  assert.equal(out.headers.get("location"), null);
  assert.match(((await out.json()) as { redirect: string }).redirect, /^https:\/\/idp\.example\/user_management\/sessions\/logout\?session_id=provider_sess_1/);
  assert.ok(cookieNamed(out, SESSION_COOKIE)!.includes("Max-Age=0"));
});

test("callback: a company single sign-on is signed with its connection and organization; one the provider reports less for is signed as no second factor", async () => {
  const conn = "conn_01E4ZCR3C56J083X43JQXF3JK5", org = "org_01E4ZCR3C56J083X43JQXF3JK5";
  for (const [answer, amr, sso] of [
    [{ authentication_method: "SSO", sso_connection_id: conn, organization_id: org }, ["sso"], conn],
    [{ authentication_method: "SSO", sso_connection_id: conn }, [], undefined],
    [{ authentication_method: "SSO" }, [], undefined],
    [{ authentication_method: "GoogleOAuth", sso_connection_id: conn, organization_id: org }, [], undefined],
  ] as [Record<string, unknown>, string[], string | undefined][]) {
    const m = mk({ exchange: () => new Response(JSON.stringify({ id_token: IDT, refresh_token: "rt_1", user: { id: "user_1", email: "dana@acme.example", email_verified: true }, ...answer }), { status: 200 }) });
    const s = await startLogin(m);
    await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), m.env, m.deps);
    const c = claimsOf(m.vaultCalls[0].headers!["x-consentvault-edge-assertion"]);
    assert.deepEqual(c.amr, amr, JSON.stringify(answer));
    assert.equal(c.sso_connection_id, sso);
    assert.equal(c.sso_organization_id, sso ? org : undefined);
  }
});

test("a missing signing key is a 500 'not configured' on every sign-in route, never a session that lacks a second factor", async () => {
  const m = mk();
  for (const path of ["/auth/login", "/auth/callback?code=x&state=s", "/auth/logout"]) {
    const res = (await handleAuth(req(path, path.endsWith("logout") ? { method: "POST", headers: { origin: "https://app.example.com" } } : {}), { ...m.env, ASSERTION_KEY_JWK: undefined }, m.deps))!;
    assert.equal(res.status, 500, path);
    assert.match(await res.text(), /ASSERTION_KEY_JWK/);
  }
});

test("sign-out sends the browser to the provider's sign-out address for the session's id, even when the stored copy lacks it", async () => {
  const m = mk();
  const s = await startLogin(m);
  const cb = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), m.env, m.deps))!;
  const sidv = cookieValueOf(cookieNamed(cb, SESSION_COOKIE)!);
  const key = [...m.kv.data.keys()].find((k) => k.startsWith("sess:"))!;
  m.kv.data.set(key, JSON.stringify({ ...JSON.parse(m.kv.data.get(key)!), provider_sid: null }));
  const out = (await handleAuth(req("/auth/logout", { method: "POST", headers: { cookie: `${SESSION_COOKIE}=${sidv}`, origin: "https://app.example.com", accept: "application/json" } }), m.env, m.deps))!;
  assert.equal(new URL(((await out.json()) as { redirect: string }).redirect).searchParams.get("session_id"), "provider_sess_1");
});

test("logout revokes the session even if the store's delete is slow to reach every location", async () => {
  const m = mk();
  const lagging = { ...m.kv, delete: async () => undefined };
  const env = { ...m.env, SESSIONS: lagging };
  const s = await startLogin({ ...m, env });
  const cb = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), env, m.deps))!;
  const cookie = `${SESSION_COOKIE}=${cookieValueOf(cookieNamed(cb, SESSION_COOKIE)!)}`;
  assert.ok(await loadSession(lagging, cookie));
  await handleAuth(req("/auth/logout", { method: "POST", headers: { cookie, origin: "https://app.example.com" } }), env, m.deps);
  assert.ok([...m.kv.data.keys()].some((k) => k.startsWith("sess:")), "the record is still there");
  assert.equal(await loadSession(lagging, cookie), null, "but the revocation marker refuses it");
});

test("a failing session store at sign-out is a styled 503 that still clears the cookie, and the browser is told it failed", async () => {
  const m = mk();
  const s = await startLogin(m);
  const cb = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), m.env, m.deps))!;
  const cookie = `${SESSION_COOKIE}=${cookieValueOf(cookieNamed(cb, SESSION_COOKIE)!)}`;
  const broken = { ...m.env, SESSIONS: { ...m.kv, get: async (k: string) => { if (k.startsWith("sess:") || k.startsWith("revoked:")) throw new Error("storage down"); return m.kv.get(k); } } };
  for (const accept of ["application/json", "text/html"]) {
    const out = (await handleAuth(req("/auth/logout", { method: "POST", headers: { cookie, origin: "https://app.example.com", accept } }), broken, m.deps))!;
    assert.equal(out.status, 503, accept);
    assert.ok(cookieNamed(out, SESSION_COOKIE)!.includes("Max-Age=0"), "the cookie is cleared even though the store failed");
    assert.equal(out.headers.get("location"), null);
    assert.match(await out.text(), accept === "text/html" ? /<h1>/ : /session_unavailable/);
  }
});

test("a failing session store at the end of sign-in is a styled 503 with no session cookie", async () => {
  const m = mk();
  const s = await startLogin(m);
  const broken = { ...m.env, SESSIONS: { ...m.kv, put: async (k: string, v: string, o?: { expirationTtl?: number }) => { if (k.startsWith("sess:")) throw new Error("storage down"); return m.kv.put(k, v, o); } } };
  const out = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), broken, m.deps))!;
  assert.equal(out.status, 503);
  assert.equal(cookieNamed(out, SESSION_COOKIE), undefined);
  assert.match(out.headers.get("content-type")!, /html/);
});

const FACTOR_URL = "https://idp.example/user_management/users/user_1/auth_factors";
async function signInPassword(flag: string | undefined, factors: () => Response) {
  const m = mk({ exchange: () => new Response(JSON.stringify({ id_token: IDT, refresh_token: "rt_1", authentication_method: "Password" }), { status: 200 }) });
  const base = m.deps.fetch;
  m.deps.fetch = (async (url: string, init: RequestInit) => (String(url) === FACTOR_URL ? (m.calls.push({ url: String(url), init }), factors()) : base(url, init))) as unknown as typeof fetch;
  if (flag !== undefined) m.env.PROVIDER_MFA_REQUIRED = flag;
  m.env.AUTH_CLIENT_SECRET = "edge-test-api-key";
  const s = await startLogin(m);
  const r = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), m.env, m.deps))!;
  return { m, r };
}
const totp = () => new Response(JSON.stringify({ data: [{ type: "totp", id: "f1" }] }), { status: 200 });

test("a password with an authenticator-app factor counts as password plus code only when the operator declared multi-factor", async () => {
  const on = await signInPassword("true", totp);
  assert.equal(on.r.status, 302);
  assert.deepEqual(claimsOf(on.m.vaultCalls[0].headers!["x-consentvault-edge-assertion"]).amr, ["pwd", "otp"]);
  const call = on.m.calls.find((c) => c.url === FACTOR_URL)!;
  assert.equal((call.init.headers as Record<string, string>).authorization, "Bearer edge-test-api-key");
  for (const [flag, factors] of [["true", () => new Response(JSON.stringify({ data: [] }), { status: 200 })], [undefined, totp], ["false", totp]] as const) {
    const o = await signInPassword(flag, factors);
    assert.deepEqual(claimsOf(o.m.vaultCalls[0].headers!["x-consentvault-edge-assertion"]).amr, [], String(flag));
    if (flag !== "true") assert.equal(o.m.calls.some((c) => c.url === FACTOR_URL), false, "no lookup unless declared");
  }
});

test("a factor lookup that fails is a named refusal with no session and no vault call", async () => {
  for (const f of [() => new Response("{}", { status: 500 }), () => { throw new Error("down"); }, () => new Response("{}", { status: 200 })]) {
    const { m, r } = await signInPassword("true", f);
    assert.equal(r.status, 502);
    assert.equal(cookieNamed(r, SESSION_COOKIE), undefined);
    assert.equal(m.vaultCalls.length, 0);
    assert.ok((await r.text()).includes("second factor"));
  }
});

test("logout with next goes through the provider's sign-out and returns to the sign-in start; with no session it goes straight there", async () => {
  const m = mk();
  const s = await startLogin(m);
  const cb = (await handleAuth(req(`/auth/callback?code=x&state=${s.state}`, { headers: { cookie: `${LOGIN_COOKIE}=${s.state}` } }), m.env, m.deps))!;
  const sid = cookieValueOf(cookieNamed(cb, SESSION_COOKIE)!);
  const out = (await handleAuth(req("/auth/logout?next=passkey&return=%2Fbrands", { method: "POST", headers: { cookie: `${SESSION_COOKIE}=${sid}`, origin: "https://app.example.com" } }), m.env, m.deps))!;
  const loc = new URL(out.headers.get("location")!);
  assert.equal(loc.origin + loc.pathname, "https://idp.example/user_management/sessions/logout");
  assert.equal(loc.searchParams.get("return_to"), "https://app.example.com/auth/login?method=passkey&return=%2Fbrands");
  const bare = (await handleAuth(req("/auth/logout?next=login", { method: "POST", headers: { origin: "https://app.example.com" } }), m.env, m.deps))!;
  assert.equal(bare.headers.get("location"), "/auth/login?return=%2F");
});
