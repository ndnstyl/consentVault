import test from "node:test";
import assert from "node:assert/strict";
import { handleGateway, type GatewayEnv, type GatewayDeps } from "../src/gateway.ts";
import { SESSION_COOKIE, TENANT_TOKEN_HEADER, saveSession, sessionKey, type SessionRecord } from "../src/session.ts";
import { AUTH_ENV_BASE, NOW_MS, cookieNamed, jwt, memKV, nowSec } from "./support/portal.ts";

import crypto from "node:crypto";
const PRIVATE_JWK = JSON.stringify({ ...crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }), kid: "edge1" });
const claimsOf = (a: string) => JSON.parse(Buffer.from(a.split(".")[1], "base64url").toString("utf8"));
const SID = "sid-test-0123456789012345678901234567";
const ORG = "11111111-1111-4111-8111-111111111111";
const IDT = jwt({ sub: "user_1", sid: "ps_1", exp: nowSec() + 300 });
const TENANT = "v1.k1.abcdef.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ORIGIN = "https://app.example.com";

type Call = { url: string; method: string; headers: Headers; body: string };

function mk(opts: { rec?: Partial<SessionRecord> | null; origin?: (c: Call) => Response; refresh?: (body: Record<string, string>) => Response | Promise<Response> } = {}) {
  const kv = memKV();
  const env: GatewayEnv = { ORIGIN_URL: "https://origin.example.com/", ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec", ...AUTH_ENV_BASE, SESSIONS: kv, ASSERTION_KEY_JWK: PRIVATE_JWK };
  const calls: Call[] = [];
  const refreshes: Record<string, string>[] = [];
  const deps: GatewayDeps = {
    now: () => NOW_MS,
    fetch: (async (url: string, init: RequestInit) => {
      if (String(url).endsWith("/authenticate")) {
        const body = JSON.parse(String(init.body));
        refreshes.push(body);
        return opts.refresh ? opts.refresh(body) : new Response(JSON.stringify({ id_token: jwt({ sub: "user_1", sid: "ps_1", exp: nowSec() + 300, jti: "refreshed" }), refresh_token: "rt_2" }), { status: 200 });
      }
      const c = { url: String(url), method: String(init.method), headers: init.headers as Headers, body: typeof init.body === "string" ? init.body : init.body ? new TextDecoder().decode(init.body as ArrayBuffer) : "" };
      calls.push(c);
      return opts.origin ? opts.origin(c) : new Response('{"ok":true}', { status: 200, headers: { "set-cookie": "a=b" } });
    }) as unknown as typeof fetch,
  };
  const ready = (async () => {
    if (opts.rec !== null) {
      const rec: SessionRecord = { token: IDT, token_exp: nowSec() + 300, refresh: "rt_1", provider_sid: "ps_1", org_id: null, tenant: null, until: nowSec() + 28800, iat: nowSec(), amr: ["hwk", "user"], method: "Passkey", ...opts.rec };
      await saveSession(kv, SID, rec, NOW_MS);
    }
  })();
  return { kv, env, deps, calls, refreshes, ready, key: undefined as string | undefined };
}
const r = (path: string, init: RequestInit & { cookie?: boolean; origin?: string | null; org?: string | null } = {}) => {
  const { cookie = true, origin, org = ORG, ...rest } = init;
  const h = new Headers(rest.headers);
  if (org) h.set("x-cv-org", org);
  if (cookie) h.set("cookie", `${SESSION_COOKIE}=${SID}`);
  const method = rest.method ?? "GET";
  if (method !== "GET" && origin !== null) h.set("origin", origin ?? ORIGIN);
  return new Request("https://app.example.com" + path, { ...rest, headers: h });
};
const stored = async (m: ReturnType<typeof mk>) => JSON.parse((await m.kv.get(await sessionKey(SID)))!) as SessionRecord;
const bearer = (c: Call) => c.headers.get("authorization");

test("a session cookie becomes the identity token for the sign-in endpoints, and the cookie never reaches the origin", async () => {
  const m = mk(); await m.ready;
  const res = await handleGateway(r("/v1/session?limit=5"), m.env, m.deps);
  assert.equal(res.status, 200);
  assert.equal(m.calls[0].url, "https://origin.example.com/v1/session?limit=5");
  assert.equal(bearer(m.calls[0]), `Bearer ${IDT}`);
  assert.equal(m.calls[0].headers.get("cookie"), null);
  assert.equal(m.calls[0].headers.get("cf-access-client-id"), "cid");
  assert.equal(res.headers.get("set-cookie"), null);
});

test("choosing an organization keeps the tenant token in the Worker and never in the answer", async () => {
  const exp = nowSec() + 300;
  const m = mk({ origin: () => new Response(JSON.stringify({ org_id: ORG, name: "Acme", role: "admin", status: "active", expires_at: new Date(exp * 1000).toISOString() }), { status: 200, headers: { [TENANT_TOKEN_HEADER]: TENANT, "set-cookie": "x=y" } }) });
  await m.ready;
  const res = await handleGateway(r("/v1/session/org", { method: "POST", body: JSON.stringify({ org_id: ORG }) }), m.env, m.deps);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get(TENANT_TOKEN_HEADER), null);
  assert.ok(!(await res.text()).includes(TENANT));
  assert.equal(bearer(m.calls[0]), `Bearer ${IDT}`);
  const rec = await stored(m);
  assert.equal(rec.org_id, ORG);
  assert.deepEqual(rec.tenant, { token: TENANT, exp });
  assert.equal(m.kv.ttl.get(await sessionKey(SID)), 28800, "the sign-in's end is not extended");

  m.calls.length = 0;
  await handleGateway(r("/v1/org"), m.env, m.deps);
  assert.equal(bearer(m.calls[0]), `Bearer ${TENANT}`);
});

test("a refused choice stores nothing", async () => {
  const m = mk({ origin: () => new Response('{"error":"not_a_member"}', { status: 403 }) }); await m.ready;
  const res = await handleGateway(r("/v1/session/org", { method: "POST", body: JSON.stringify({ org_id: ORG }) }), m.env, m.deps);
  assert.equal(res.status, 403);
  assert.equal((await stored(m)).org_id, null);
});

test("no organization chosen: tenant routes answer no_org_selected and never reach the vault", async () => {
  const m = mk(); await m.ready;
  const res = await handleGateway(r("/v1/org"), m.env, m.deps);
  assert.equal(res.status, 409);
  assert.equal(((await res.json()) as { error: string }).error, "no_org_selected");
  assert.equal(m.calls.length, 0);
  const cur = await handleGateway(r("/v1/session/current-org"), m.env, m.deps);
  assert.equal(cur.status, 200, "current-org asks the vault, which names the missing choice itself");
  assert.equal(bearer(m.calls[0]), `Bearer ${IDT}`);
});

test("an expired tenant token is minted again for the chosen organization", async () => {
  const fresh = "v1.k1.bbbbbb.1111111111111111111111111111111111111111111111111111111111111111";
  const m = mk({
    rec: { org_id: ORG, tenant: { token: TENANT, exp: nowSec() + 5 } },
    origin: (c) => c.url.endsWith("/v1/session/org")
      ? new Response(JSON.stringify({ org_id: ORG, expires_at: new Date((nowSec() + 300) * 1000).toISOString() }), { status: 200, headers: { [TENANT_TOKEN_HEADER]: fresh } })
      : new Response('{"ok":true}', { status: 200 }),
  });
  await m.ready;
  const res = await handleGateway(r("/v1/brands"), m.env, m.deps);
  assert.equal(res.status, 200);
  assert.equal(m.calls.length, 2);
  assert.equal(m.calls[0].url, "https://origin.example.com/v1/session/org");
  assert.equal(JSON.parse(m.calls[0].body).org_id, ORG);
  assert.equal(bearer(m.calls[0]), `Bearer ${IDT}`);
  assert.equal(bearer(m.calls[1]), `Bearer ${fresh}`);
});

test("an identity token about to expire is refreshed server side; a failed refresh ends the session", async () => {
  const m = mk({ rec: { token_exp: nowSec() + 10 } }); await m.ready;
  const res = await handleGateway(r("/v1/session"), m.env, m.deps);
  assert.equal(res.status, 200);
  assert.deepEqual(m.refreshes[0], { client_id: "client_test", client_secret: "test-only-client-credential", grant_type: "refresh_token", refresh_token: "rt_1" });
  assert.notEqual(bearer(m.calls[0]), `Bearer ${IDT}`);
  assert.equal((await stored(m)).refresh, "rt_2");

  const dead = mk({ rec: { token_exp: nowSec() - 5 }, refresh: () => new Response('{"error":"invalid_grant"}', { status: 400 }) }); await dead.ready;
  const out = await handleGateway(r("/v1/session"), dead.env, dead.deps);
  assert.equal(out.status, 401);
  assert.equal(((await out.json()) as { error: string }).error, "unauthenticated");
  assert.ok(cookieNamed(out, SESSION_COOKIE)!.includes("Max-Age=0"));
  assert.equal(await dead.kv.get(await sessionKey(SID)), null);
  assert.equal(dead.calls.length, 0);
});

test("an unknown or expired session cookie is unauthenticated and is cleared", async () => {
  const m = mk({ rec: null }); await m.ready;
  const res = await handleGateway(r("/v1/session"), m.env, m.deps);
  assert.equal(res.status, 401);
  assert.equal(((await res.json()) as { error: string }).error, "unauthenticated");
  assert.ok(cookieNamed(res, SESSION_COOKIE)!.includes("Max-Age=0"));
  assert.equal(m.calls.length, 0);
});

test("a state-changing call from the session cookie must come from the portal's own origin", async () => {
  const m = mk({ rec: { org_id: ORG, tenant: { token: TENANT, exp: nowSec() + 200 } } }); await m.ready;
  for (const origin of [null, "https://evil.example", "null"]) {
    const res = await handleGateway(r("/v1/brands", { method: "POST", body: "{}", origin }), m.env, m.deps);
    assert.equal(res.status, 403, String(origin));
    assert.equal(((await res.json()) as { error: string }).error, "origin_refused");
  }
  assert.equal(m.calls.length, 0);
  assert.equal((await handleGateway(r("/v1/brands", { method: "POST", body: "{}" }), m.env, m.deps)).status, 200);
});

test("an Authorization header still wins and the cookie is never forwarded (machine path unchanged)", async () => {
  const m = mk(); await m.ready;
  await handleGateway(r("/v1/events", { method: "POST", body: "{}", headers: { authorization: "Bearer aaa.bbb.ccc" }, origin: null }), m.env, m.deps);
  assert.equal(bearer(m.calls[0]), "Bearer aaa.bbb.ccc");
  assert.equal(m.calls[0].headers.get("cookie"), null);
  const none = mk(); await none.ready;
  const res = await handleGateway(r("/v1/events", { method: "POST", body: "{}", cookie: false }), none.env, none.deps);
  assert.equal(((await res.json()) as { error: string }).error, "bearer_missing");
});

test("a one-time export download link is its own credential: it passes with no session at all", async () => {
  const m = mk({ rec: null }); await m.ready;
  const res = await handleGateway(r("/v1/exports/5b1f2c3a-0000-4000-8000-000000000001/download?link=abc.def", { cookie: false }), m.env, m.deps);
  assert.equal(res.status, 200);
  assert.equal(m.calls[0].headers.get("authorization"), null);
  assert.equal(m.calls[0].url, "https://origin.example.com/v1/exports/5b1f2c3a-0000-4000-8000-000000000001/download?link=abc.def");
  const other = await handleGateway(r("/v1/exports/5b1f2c3a-0000-4000-8000-000000000001", { cookie: false }), m.env, m.deps);
  assert.equal(other.status, 401);
});

test("a tenant call must name the organization the tab shows; a different or missing one is refused before the vault", async () => {
  const m = mk({ rec: { org_id: ORG, tenant: { token: TENANT, exp: nowSec() + 200 } } }); await m.ready;
  const OTHER = "22222222-2222-4222-8222-222222222222";
  for (const org of [OTHER, null]) {
    const res = await handleGateway(r("/v1/brands", { method: "POST", body: "{}", org }), m.env, m.deps);
    assert.equal(res.status, 409, String(org));
    assert.equal(((await res.json()) as { error: string }).error, "org_mismatch");
  }
  assert.equal(m.calls.length, 0);
  assert.equal((await handleGateway(r("/v1/brands", { method: "POST", body: "{}" }), m.env, m.deps)).status, 200);
  assert.equal((await handleGateway(r("/v1/org", { org: null }), m.env, m.deps)).status, 200, "a fresh tab may read before it knows its organization");
  assert.equal((await handleGateway(r("/v1/org", { org: OTHER }), m.env, m.deps)).status, 409, "but a named, different organization is refused on a read too");
});

test("a re-mint that finishes after another tab chose a different organization is discarded, never saved over it", async () => {
  const OTHER = "22222222-2222-4222-8222-222222222222";
  const OTHER_TOKEN = "v1.k1.cccccc.2222222222222222222222222222222222222222222222222222222222222222";
  const m = mk({ rec: { org_id: ORG, tenant: { token: TENANT, exp: nowSec() + 5 } }, origin: (c) => {
    if (c.url.endsWith("/v1/session/org")) {
      // while the vault answers, the other tab switches the session to organization B
      m.kv.data.set(m.key!, JSON.stringify({ ...JSON.parse(m.kv.data.get(m.key!)!), org_id: OTHER, tenant: { token: OTHER_TOKEN, exp: nowSec() + 250 } }));
      return new Response(JSON.stringify({ org_id: ORG, expires_at: new Date((nowSec() + 300) * 1000).toISOString() }), { status: 200, headers: { [TENANT_TOKEN_HEADER]: "v1.k1.aaaaaa.1111111111111111111111111111111111111111111111111111111111111111" } });
    }
    return new Response("{}", { status: 200 });
  } });
  await m.ready;
  m.key = await sessionKey(SID);
  const res = await handleGateway(r("/v1/brands", { method: "POST", body: "{}" }), m.env, m.deps);
  assert.equal(res.status, 409);
  assert.equal(m.calls.length, 1, "the write never reached the vault");
  const rec = await stored(m);
  assert.equal(rec.org_id, OTHER);
  assert.equal(rec.tenant!.token, OTHER_TOKEN);
});

test("concurrent calls with an expiring identity token refresh it once; the single-use refresh token is spent once", async () => {
  let used = 0;
  const m = mk({ rec: { token_exp: nowSec() + 5 }, refresh: async (b) => {
    used += 1;
    await new Promise((ok) => setTimeout(ok, 20));
    return b.refresh_token === "rt_1" && used === 1
      ? new Response(JSON.stringify({ id_token: jwt({ sub: "user_1", sid: "ps_1", exp: nowSec() + 300, jti: "once" }), refresh_token: "rt_2" }), { status: 200 })
      : new Response('{"error":"invalid_grant"}', { status: 400 });
  } });
  await m.ready;
  const all = await Promise.all([1, 2, 3, 4, 5].map(() => handleGateway(r("/v1/session"), m.env, m.deps)));
  assert.deepEqual(all.map((x) => x.status), [200, 200, 200, 200, 200]);
  assert.equal(used, 1);
  assert.equal((await stored(m)).refresh, "rt_2");
});

test("a revoked session is refused even when the store still returns the old record", async () => {
  const m = mk(); await m.ready;
  await m.kv.put("revoked:" + (await sessionKey(SID)).slice(5), String(nowSec() + 1));
  const res = await handleGateway(r("/v1/session"), m.env, m.deps);
  assert.equal(res.status, 401);
  assert.equal(m.calls.length, 0);
});

test("calls that carry the identity token carry the edge's signed assertion; a header the browser sends is never passed on", async () => {
  const m = mk({ origin: () => new Response(JSON.stringify({ org_id: ORG, expires_at: new Date((nowSec() + 300) * 1000).toISOString() }), { status: 200, headers: { [TENANT_TOKEN_HEADER]: TENANT } }) }); await m.ready;
  await handleGateway(r("/v1/session", { headers: { "x-consentvault-edge-assertion": "forged" } }), m.env, m.deps);
  const a = m.calls[0].headers.get("x-consentvault-edge-assertion")!;
  assert.notEqual(a, "forged");
  assert.deepEqual(claimsOf(a).amr, ["hwk", "user"]);
  assert.equal(claimsOf(a).sub, "user_1");
  await handleGateway(r("/v1/session/org", { method: "POST", body: JSON.stringify({ org_id: ORG }) }), m.env, m.deps);
  assert.ok(m.calls[1].headers.get("x-consentvault-edge-assertion"));
  m.calls.length = 0;
  await handleGateway(r("/v1/brands", { headers: { "x-consentvault-edge-assertion": "forged" } }), m.env, m.deps);
  assert.equal(m.calls[0].headers.get("x-consentvault-edge-assertion"), null, "tenant calls carry none, and the forged one is dropped");
});

test("a missing signing key answers 500 misconfigured for a portal call, not a quiet 'no second factor'", async () => {
  const m = mk(); await m.ready;
  for (const key of [undefined, "", "{bad"]) {
    const res = await handleGateway(r("/v1/session"), { ...m.env, ASSERTION_KEY_JWK: key }, m.deps);
    assert.equal(res.status, 500);
    assert.equal(((await res.json()) as { error: string }).error, "misconfigured");
  }
  assert.equal(m.calls.length, 0);
});

test("an invitation's public view needs no sign-in (the person has not joined yet); nothing else under /v1/invites does", async () => {
  const m = mk({ rec: null }); await m.ready;
  const view = await handleGateway(r("/v1/invites/abc123.def456", { cookie: false }), m.env, m.deps);
  assert.equal(view.status, 200);
  assert.equal(m.calls[0].headers.get("authorization"), null);
  assert.equal((await handleGateway(r("/v1/invites/abc123:accept", { method: "POST", body: "{}", cookie: false, origin: null }), m.env, m.deps)).status, 401);
  assert.equal((await handleGateway(r("/v1/invites/abc123", { method: "DELETE", cookie: false, origin: null }), m.env, m.deps)).status, 401);
});

test("the assertion states the address as the provider reported it: unverified stays unverified, and no address means none", async () => {
  const cases: [Partial<SessionRecord>, boolean | undefined, string | undefined][] = [
    [{ email: "a@b.example", email_verified: false }, false, "a@b.example"],
    [{ email: "a@b.example", email_verified: true }, true, "a@b.example"],
    [{ email: null, email_verified: false }, undefined, undefined],
  ];
  for (const [rec, verified, email] of cases) {
    const m = mk({ rec }); await m.ready;
    await handleGateway(r("/v1/session"), m.env, m.deps);
    const c = claimsOf(m.calls[0].headers.get("x-consentvault-edge-assertion")!);
    assert.equal(c.email_verified, verified, JSON.stringify(rec));
    assert.equal(c.email, email);
  }
});

test("a missing signing key is refused on tenant routes too, not only where an assertion happens to be signed", async () => {
  const m = mk({ rec: { org_id: ORG, tenant: { token: TENANT, exp: nowSec() + 200 } } }); await m.ready;
  const res = await handleGateway(r("/v1/brands"), { ...m.env, ASSERTION_KEY_JWK: undefined }, m.deps);
  assert.equal(res.status, 500);
  assert.equal(((await res.json()) as { error: string }).error, "misconfigured");
  assert.equal(m.calls.length, 0);
});

test("with a Durable Object bound, the gateway reads and writes the session only through it", async () => {
  const m = mk({ rec: null }); await m.ready;
  const ops: string[] = [];
  const rec: SessionRecord = { token: IDT, token_exp: nowSec() + 300, refresh: "rt", provider_sid: "ps_1", org_id: null, tenant: null, amr: ["hwk", "user"], method: "Passkey", email: null, email_verified: false, until: nowSec() + 1000, iat: nowSec() };
  const ns = { idFromName: (n: string) => n, get: () => ({ fetch: async (q: Request) => { const b = (await q.json()) as { op: string }; ops.push(b.op); return new Response(JSON.stringify(b.op === "load" ? rec : null)); } }) };
  const res = await handleGateway(r("/v1/session"), { ...m.env, SESSION_GATE: ns }, m.deps);
  assert.equal(res.status, 200);
  assert.deepEqual(ops, ["load"]);
  assert.equal(m.kv.data.size, 0);
});

test("a failing session store is a 503 the dashboard can show, never a 500 or a silent pass", async () => {
  const m = mk(); await m.ready;
  const broken = { ...m.kv, get: async () => { throw new Error("storage down"); } };
  const res = await handleGateway(r("/v1/session"), { ...m.env, SESSIONS: broken }, m.deps);
  assert.equal(res.status, 503);
  assert.equal(((await res.json()) as { error: string }).error, "session_unavailable");
  assert.equal(m.calls.length, 0);
});
