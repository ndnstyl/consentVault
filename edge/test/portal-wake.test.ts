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

async function completeSignIn(vaultSession: "ok" | "parked") {
  const m = mk({ origin: "down-530" });
  const idt = jwt({ sub: "user_1", sid: "provider_sess_1", exp: nowSec() + 300 });
  const inner = m.deps.fetch;
  m.deps.fetch = (async (u: string, init?: RequestInit) => {
    const url = String(u);
    if (url.startsWith("https://idp.example/")) return new Response(JSON.stringify({ id_token: idt, access_token: "a", refresh_token: "r" }), { status: 200 });
    if (vaultSession === "ok" && new URL(url).pathname === "/v1/session") { m.calls.push("origin /v1/session"); return new Response(JSON.stringify({ items: [] }), { status: 200 }); }
    return inner(u as never, init as never);
  }) as unknown as typeof fetch;
  const start = await handlePortal(nav("/auth/login?return=%2Fbrands", {}), m.env, m.deps);
  const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
  const loginCookie = cookieNamed(start, LOGIN_COOKIE)!.split(";")[0];
  const res = await handlePortal(nav(`/auth/callback?code=abc&state=${state}`, { cookie: loginCookie }), m.env, m.deps);
  return { m, res };
}

test("a completed sign-in while parked asks for exactly one wake and lands on the starting page", async () => {
  const { m, res } = await completeSignIn("ok");
  assert.equal(res.status, 302);
  const sessionCookie = cookieNamed(res, SESSION_COOKIE);
  assert.ok(sessionCookie, "the session was created");
  assert.equal(wakes(m.calls), 1);
  assert.ok(await m.kv.get("cv:wake:requested"), "the wake went through the counted path and left its marker");
  const day = [...m.kv.data.keys()].find((k) => k.startsWith("cv:wake:day:"));
  assert.equal(m.kv.data.get(day!), "1");
  const next = await handlePortal(nav("/brands", { cookie: sessionCookie!.split(";")[0] }), m.env, m.deps);
  assert.equal(next.status, 503);
  assert.match(await next.text(), /ConsentVault is starting/);
  assert.equal(wakes(m.calls), 1, "once per cold period");
});

test("a sign-in that cannot finish because the vault is parked says so, names the cause, and asks for the wake", async () => {
  const { m, res } = await completeSignIn("parked");
  assert.equal(res.status, 503);
  assert.equal(cookieNamed(res, SESSION_COOKIE), undefined);
  const html = await res.text();
  assert.match(html, /ConsentVault is starting/);
  assert.match(html, /href="\/auth\/login"/);
  assert.doesNotMatch(html, /http-equiv="refresh"/);
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
