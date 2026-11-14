import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { handlePortal, type PortalEnv } from "../src/portal.ts";
import { AUTH_ENV_BASE, NOW_MS, cookieNamed, jwt, memKV, nowSec } from "./support/portal.ts";
import { saveSession, LOGIN_COOKIE, SESSION_COOKIE, type SessionRecord } from "../src/session.ts";

const JWK = JSON.stringify({ ...crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }), kid: "e" });
const WAKE = "https://wake.example.test/";

function mk(opts: { origin: "down-throw" | "down-530" | "up"; wake?: "ok" | "fail" | "unset" }) {
  const calls: string[] = [];
  const kv = memKV();
  const env: PortalEnv = {
    ORIGIN_URL: "https://origin.example.com", ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec", ...AUTH_ENV_BASE, SESSIONS: kv, ASSERTION_KEY_JWK: JWK,
    ...(opts.wake === "unset" ? {} : { CV_WAKE_URL: WAKE, CV_WAKE_KEY: "k" }),
    ASSETS: { fetch: async (r: Request) => { calls.push("assets " + new URL(r.url).pathname); return new Response("<html>shell</html>", { status: 200 }); } },
  };
  const deps = {
    now: () => NOW_MS,
    fetch: (async (u: string) => {
      const url = String(u);
      if (url.startsWith(WAKE)) {
        calls.push("wake");
        return opts.wake === "fail" ? new Response('{"error":"x"}', { status: 500 }) : new Response('{"services":{"vault":{"desired":1,"running":0}}}', { status: 200 });
      }
      calls.push("origin " + new URL(url).pathname);
      if (opts.origin === "down-throw") throw new TypeError("connect failed");
      if (opts.origin === "down-530") return new Response("error code: 1033", { status: 530 });
      return new Response("{}", { status: 401 });
    }) as unknown as typeof fetch,
  };
  return { env, deps, calls, kv };
}
const SID = "sid-test-1";
const REC: SessionRecord = { token: "t", token_exp: nowSec() + 300, refresh: "r", provider_sid: "p", org_id: null, tenant: null, until: nowSec() + 28800, iat: nowSec(), amr: ["hwk"], method: "Passkey", email: null, email_verified: false };
async function signedIn(m: { kv: ReturnType<typeof memKV> }) { await saveSession(m.kv, SID, REC, NOW_MS); }
const cookie = { cookie: `${SESSION_COOKIE}=${SID}` };
const nav = (p: string, c: Record<string, string> = cookie) => new Request("https://app.example.com" + p, { headers: { accept: "text/html,application/xhtml+xml", ...c } });
const api = (p: string, c: Record<string, string> = cookie) => new Request("https://app.example.com" + p, { headers: { accept: "application/json", ...c } });
const wakes = (c: string[]) => c.filter((x) => x === "wake").length;

test("a page visit with the vault parked wakes it and shows the starting page that refreshes itself", async () => {
  const m = mk({ origin: "down-530" });
  await signedIn(m);
  const res = await handlePortal(nav("/brands"), m.env, m.deps);
  assert.equal(res.status, 503);
  assert.match(res.headers.get("content-type") ?? "", /text\/html/);
  assert.equal(res.headers.get("retry-after"), "15");
  assert.equal(res.headers.get("cache-control"), "no-store");
  const html = await res.text();
  assert.match(html, /ConsentVault is starting/);
  assert.match(html, /about two minutes/);
  assert.match(html, /<meta http-equiv="refresh" content="15"/);
  assert.equal(wakes(m.calls), 1);
  assert.ok(!m.calls.includes("assets /brands"), "the dashboard shell is not served while the vault is down");
});

test("a thrown origin call (tunnel gone) counts as unreachable too", async () => {
  const m = mk({ origin: "down-throw" });
  await signedIn(m);
  const res = await handlePortal(nav("/"), m.env, m.deps);
  assert.equal(res.status, 503);
  assert.match(await res.text(), /ConsentVault is starting/);
  assert.equal(wakes(m.calls), 1);
});

test("wake is called once per cold period, not once per request", async () => {
  const m = mk({ origin: "down-530" });
  await signedIn(m);
  for (let i = 0; i < 5; i++) await handlePortal(nav("/brands"), m.env, m.deps);
  await handlePortal(api("/v1/session"), m.env, m.deps);
  assert.equal(wakes(m.calls), 1);
  assert.ok([...m.kv.ttl.values()].some((t) => t !== undefined && t >= 60), "the marker expires, so a later cold period wakes again");
});

test("an API call with the vault parked answers a 503 the dashboard can read, not a 502", async () => {
  const m = mk({ origin: "down-throw" });
  await signedIn(m);
  const res = await handlePortal(api("/v1/session/orgs"), m.env, m.deps);
  assert.equal(res.status, 503);
  assert.match(res.headers.get("content-type") ?? "", /application\/json/);
  const body = await res.json() as { error: string; message: string };
  assert.equal(body.error, "vault_starting");
  assert.match(body.message, /about two minutes/);
});

test("with the vault up nothing changes: the shell is served and wake is never called", async () => {
  const m = mk({ origin: "up" });
  const res = await handlePortal(nav("/brands"), m.env, m.deps);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), "<html>shell</html>");
  assert.equal(wakes(m.calls), 0);
});

test("a static asset is passed straight through with no probe of the vault", async () => {
  const m = mk({ origin: "down-530" });
  const res = await handlePortal(new Request("https://app.example.com/_next/static/a.js", { headers: { accept: "*/*" } }), m.env, m.deps);
  assert.equal(res.status, 200);
  assert.deepEqual(m.calls, ["assets /_next/static/a.js"]);
});

test("a failed wake is logged loudly and the page says it could not be started, never 'starting'", async () => {
  const m = mk({ origin: "down-530", wake: "fail" });
  await signedIn(m);
  const logged: unknown[][] = [];
  const orig = console.error; console.error = (...a: unknown[]) => { logged.push(a); };
  try {
    const res = await handlePortal(nav("/brands"), m.env, m.deps);
    assert.equal(res.status, 503);
    const html = await res.text();
    assert.doesNotMatch(html, /ConsentVault is starting/);
    assert.match(html, /could not be started/);
    assert.doesNotMatch(html, /http-equiv="refresh"/);
  } finally { console.error = orig; }
  assert.ok(logged.some((a) => String(a[0]).includes("WAKE_FAILED")), "the failure is written to the log");
  assert.equal(await m.kv.get("cv:wake:requested"), null, "a failed wake leaves no marker, so the next request tries again");
});

test("wake settings not set is the same loud failure", async () => {
  const m = mk({ origin: "down-530", wake: "unset" });
  await signedIn(m);
  const orig = console.error; const logged: string[] = []; console.error = (...a: unknown[]) => { logged.push(String(a[0])); };
  try {
    const res = await handlePortal(nav("/brands"), m.env, m.deps);
    assert.equal(res.status, 503);
    assert.match(await res.text(), /could not be started/);
  } finally { console.error = orig; }
  assert.ok(logged.some((l) => l.includes("WAKE_FAILED") && l.includes("CV_WAKE_URL")));
  assert.equal(wakes(m.calls), 0);
});

test("the vault's own 503 (gate fails closed) is an answer, not a parked vault", async () => {
  const m = mk({ origin: "up" });
  m.deps.fetch = (async () => { m.calls.push("origin"); return new Response('{"error":"gate"}', { status: 503 }); }) as unknown as typeof fetch;
  const res = await handlePortal(api("/v1/session"), m.env, m.deps);
  assert.equal(wakes(m.calls), 0);
  assert.notEqual(((await res.clone().json().catch(() => ({}))) as { error?: string }).error, "vault_starting");
});

test("a signed-out navigation while parked is sent to sign-in and never wakes the vault", async () => {
  for (const c of [{}, { cookie: `${SESSION_COOKIE}=not-a-session` }, { cookie: "other=1" }]) {
    const m = mk({ origin: "down-530" });
    await signedIn(m);
    const res = await handlePortal(nav("/brands", c), m.env, m.deps);
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "/auth/login?return=%2Fbrands");
    assert.equal(wakes(m.calls), 0);
  }
});

test("a signed-out JSON call while parked is 401 signin_required and never wakes the vault", async () => {
  for (const c of [{}, { cookie: `${SESSION_COOKIE}=not-a-session` }, { cookie: "other=1" }]) {
    const m = mk({ origin: "down-530" });
    await signedIn(m);
    const j = await handlePortal(api("/v1/session", c), m.env, m.deps);
    assert.equal(j.status, 401);
    assert.deepEqual(await j.json(), { error: "signin_required" });
    assert.equal(wakes(m.calls), 0);
  }
});

test("an /auth/ request while parked reaches the sign-in code instead of the starting page", async () => {
  const m = mk({ origin: "down-530" });
  const res = await handlePortal(nav("/auth/login?return=%2Fbrands", {}), m.env, m.deps);
  assert.equal(res.status, 302);
  assert.match(res.headers.get("location") ?? "", /^https:\/\/idp\.example\/user_management\/authorize/);
  assert.equal(wakes(m.calls), 0);
});

const subjectHash = (sub: string) => crypto.createHmac("sha256", AUTH_ENV_BASE.AUTH_CLIENT_SECRET).update("cv-known-member-v1:" + sub).digest("hex");
const bareHash = (sub: string) => crypto.createHash("sha256").update(sub).digest("hex");
async function known(m: { kv: ReturnType<typeof memKV> }, sub: string) { await m.kv.put("cv:member:" + subjectHash(sub), "1", { expirationTtl: 400 * 86400 }); }

async function signIn(m: ReturnType<typeof mk>, o: { idp?: "ok" | "refused" | "down"; sub?: string | null; vaultSession?: "ok" | "origin" | "502" } = {}) {
  const idt = jwt({ ...(o.sub === null ? {} : { sub: o.sub ?? "user_1" }), sid: "provider_sess_1", exp: nowSec() + 300 });
  const inner = m.deps.fetch;
  m.deps.fetch = (async (u: string, init?: RequestInit) => {
    const url = String(u);
    if (url.startsWith("https://idp.example/")) {
      if (o.idp === "down") throw new TypeError("idp unreachable");
      if (o.idp === "refused") return new Response("{}", { status: 400 });
      return new Response(JSON.stringify({ id_token: idt, access_token: "a", refresh_token: "r" }), { status: 200 });
    }
    if (o.vaultSession === "ok" && new URL(url).pathname === "/v1/session") { m.calls.push("origin /v1/session"); return new Response(JSON.stringify({ items: [] }), { status: 200 }); }
    if (o.vaultSession === "502" && new URL(url).pathname === "/v1/session") { m.calls.push("origin /v1/session"); return new Response('{"error":"its own"}', { status: 502 }); }
    return inner(u as never, init as never);
  }) as unknown as typeof fetch;
  const start = await handlePortal(nav("/auth/login?return=%2Fbrands", {}), m.env, m.deps);
  const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
  const loginCookie = cookieNamed(start, LOGIN_COOKIE)!.split(";")[0];
  return handlePortal(nav(`/auth/callback?code=abc&state=${state}`, { cookie: loginCookie }), m.env, m.deps);
}

test("a completed sign-in with the vault up creates the session, asks for no wake and makes no extra health call", async () => {
  const m = mk({ origin: "up" });
  const res = await signIn(m, { vaultSession: "ok" });
  assert.equal(res.status, 302);
  assert.ok(cookieNamed(res, SESSION_COOKIE), "the session was created");
  assert.equal(wakes(m.calls), 0);
  assert.ok(!m.calls.includes("origin /v1/health"), "the vault check just succeeded, so no health probe");
  assert.equal(res.headers.get("x-cv-vault-unreachable"), null);
});

test("a sign-in the parked vault kept from finishing says so, asks for one wake, and leaks no internal header", async () => {
  const m = mk({ origin: "down-530" });
  await known(m, "user_1");
  const res = await signIn(m);
  assert.equal(res.status, 503);
  assert.equal(cookieNamed(res, SESSION_COOKIE), undefined);
  const html = await res.text();
  assert.match(html, /ConsentVault is starting/);
  assert.match(html, /href="\/auth\/login"/);
  assert.doesNotMatch(html, /http-equiv="refresh"/);
  assert.equal(wakes(m.calls), 1);
  assert.equal(res.headers.get("x-cv-vault-unreachable"), null);
  assert.equal(res.headers.get("x-cv-subject-hash"), null);
});

test("a refused sign-in code never wakes the vault", async () => {
  const m = mk({ origin: "down-530" });
  const res = await signIn(m, { idp: "refused" });
  assert.equal(res.status, 401);
  assert.equal(wakes(m.calls), 0);
});

test("an unreachable identity provider never wakes the vault", async () => {
  const m = mk({ origin: "down-530" });
  const res = await signIn(m, { idp: "down" });
  assert.equal(res.status, 502);
  assert.equal(wakes(m.calls), 0);
});

test("one identity-provider subject can ask for at most 2 wakes a day, so one person cannot use up the shared cap", async () => {
  const m = mk({ origin: "down-530" });
  await known(m, "user_stranger"); await known(m, "user_other");
  for (let i = 0; i < 4; i++) { await m.kv.delete("cv:wake:requested"); await signIn(m, { sub: "user_stranger" }); }
  assert.equal(wakes(m.calls), 2);
  await m.kv.delete("cv:wake:requested");
  await signIn(m, { sub: "user_other" });
  assert.equal(wakes(m.calls), 3, "a different person still has their own allowance");
});

test("a created session records its identity as a known member", async () => {
  const m = mk({ origin: "up" });
  await signIn(m, { vaultSession: "ok", sub: "user_member" });
  assert.ok(await m.kv.get("cv:member:" + subjectHash("user_member")));
  assert.ok((m.kv.ttl.get("cv:member:" + subjectHash("user_member")) ?? 0) >= 399 * 86400);
});

test("25 unknown identities cause 0 wakes and get the honest could-not-finish page; a known one still wakes", async () => {
  const m = mk({ origin: "down-530" });
  let page = "";
  for (let i = 0; i < 25; i++) { const r = await signIn(m, { sub: "stranger_" + i }); assert.equal(r.status, 503); page = await r.text(); }
  assert.equal(wakes(m.calls), 0);
  assert.match(page, /could not be finished/);
  assert.match(page, /two minutes/);
  assert.doesNotMatch(page, /ConsentVault is starting/);
  await known(m, "user_member");
  await signIn(m, { sub: "user_member" });
  assert.equal(wakes(m.calls), 1);
});

test("a running vault answering its own 502 during sign-in does not wake it", async () => {
  const m = mk({ origin: "up" });
  await known(m, "user_1");
  const res = await signIn(m, { vaultSession: "502" });
  assert.equal(wakes(m.calls), 0);
  assert.equal(res.status, 502);
});

test("two failed wakes do not use up the person's allowance", async () => {
  const m = mk({ origin: "down-530", wake: "fail" });
  await known(m, "user_1");
  const orig = console.error; console.error = () => {};
  try { for (let i = 0; i < 4; i++) { await m.kv.delete("cv:wake:requested"); await signIn(m); } } finally { console.error = orig; }
  assert.equal(wakes(m.calls), 4);
});

test("a token with no subject never wakes the vault", async () => {
  const m = mk({ origin: "down-530" });
  const res = await signIn(m, { sub: null });
  assert.equal(wakes(m.calls), 0);
  assert.notEqual(res.status, 200);
});

const memberRec = (sub: string): SessionRecord => ({ ...REC, token: jwt({ sub, sid: "p", exp: nowSec() + 300 }) });

test("a request that carries a live session records the member mark, keyed, once a day", async () => {
  const m = mk({ origin: "up" });
  await saveSession(m.kv, SID, memberRec("user_live"), NOW_MS);
  await handlePortal(nav("/brands"), m.env, m.deps);
  const key = "cv:member:" + subjectHash("user_live");
  assert.ok(await m.kv.get(key), "the mark is written");
  assert.ok((m.kv.ttl.get(key) ?? 0) >= 399 * 86400);
  assert.equal(await m.kv.get("cv:member:" + bareHash("user_live")), null, "the stored key is not the bare SHA-256 of the subject");
  assert.ok(![...m.kv.data.keys()].some((k) => k.includes(bareHash("user_live"))));
  let puts = 0; const put = m.kv.put.bind(m.kv); m.kv.put = async (k, v, o) => { if (k.startsWith("cv:member:")) puts++; return put(k, v, o); };
  await handlePortal(nav("/brands"), m.env, m.deps);
  await handlePortal(api("/v1/session"), m.env, m.deps);
  assert.equal(puts, 0, "checked before put, so no second write the same day");
});

test("a member whose session was live after deploy signs in after it expires, while parked, and gets exactly one wake", async () => {
  const m = mk({ origin: "down-530" });
  await saveSession(m.kv, SID, memberRec("user_1"), NOW_MS);
  await handlePortal(api("/v1/session"), m.env, m.deps);
  await m.kv.delete("cv:wake:requested");
  m.calls.length = 0;
  await m.kv.delete("sess:" + crypto.createHash("sha256").update(SID).digest("hex"));
  const res = await signIn(m, { sub: "user_1" });
  assert.equal(res.status, 503);
  assert.match(await res.text(), /ConsentVault is starting/);
  assert.equal(wakes(m.calls), 1);
});

test("an expired session does not wake the vault", async () => {
  const m = mk({ origin: "down-530" });
  await saveSession(m.kv, SID, { ...REC, until: nowSec() - 10 }, NOW_MS);
  await handlePortal(nav("/brands"), m.env, m.deps);
  assert.equal(wakes(m.calls), 0);
});

test("the edge asks for at most 20 wakes a day, logs when the cap is hit, and says it could not start", async () => {
  const m = mk({ origin: "down-530" });
  await signedIn(m);
  const orig = console.error; const logged: string[] = []; console.error = (...a: unknown[]) => { logged.push(String(a[0])); };
  let capped = "";
  try {
    for (let i = 0; i < 25; i++) { await m.kv.delete("cv:wake:requested"); capped = await (await handlePortal(nav("/brands"), m.env, m.deps)).text(); }
  } finally { console.error = orig; }
  assert.match(capped, /could not be started/);
  assert.equal(wakes(m.calls), 20);
  assert.ok(logged.some((l) => l.includes("WAKE_CAP_REACHED")));
  const day = [...m.kv.data.keys()].find((k) => k.startsWith("cv:wake:day:"));
  assert.ok(day, "the counter is a key per day");
  assert.ok((m.kv.ttl.get(day!) ?? 0) >= 86400, "it outlives the day");
});

test("a sign-in held only in the session's Durable Object still wakes the vault on a dashboard API call", async () => {
  const m = mk({ origin: "down-throw" });
  const ops: string[] = [];
  const ns = { idFromName: (n: string) => n, get: () => ({ fetch: async (q: Request) => { const b = (await q.json()) as { op: string }; ops.push(b.op); return new Response(JSON.stringify(b.op === "load" ? REC : null)); } }) };
  const env = { ...m.env, SESSION_GATE: ns };
  const res = await handlePortal(api("/v1/session"), env, m.deps);
  assert.equal(res.status, 503);
  assert.equal(((await res.json()) as { error: string }).error, "vault_starting");
  assert.equal(wakes(m.calls), 1);
  await handlePortal(api("/v1/session"), env, m.deps);
  assert.equal(wakes(m.calls), 1, "once per cold period");
  assert.ok(ops.includes("load"));
});
