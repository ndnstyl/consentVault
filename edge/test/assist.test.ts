import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { handleAssist, TOOLS, FORBIDDEN_PREFIXES, FORBIDDEN_SUFFIXES, MARKER_HEADER, CAPABILITY_HEADER, QUESTION_HEADER, type AssistEnv } from "../src/assist.ts";
import { handlePortal } from "../src/portal.ts";
import { SessionGate } from "../src/session-gate.ts";
import { sessionStoreFor } from "../src/session-store.ts";
import { SESSION_COOKIE, sessionKey, sha256Hex, type SessionRecord } from "../src/session.ts";
import { AUTH_ENV_BASE, NOW_MS, jwt, memKV, nowSec } from "./support/portal.ts";

const PRIVATE_JWK = JSON.stringify({ ...crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }), kid: "edge1" });
const MARKER = "marker-value-for-tests-0123456789";
const ORG_A = "11111111-1111-4111-8111-111111111111";
const ORG_B = "22222222-2222-4222-8222-222222222222";
const SID_A = "sid-aaaa-0123456789012345678901234567";
const SID_B = "sid-bbbb-0123456789012345678901234567";
const TENANT_A = "v1.k1.tenantA.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TENANT_B = "v1.k1.tenantB.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ORIGIN = "https://app.example.com";

// A Durable Object namespace made of the real SessionGate class over in-memory storage. Each object handles one request at a time, as a real one does.
function fakeNamespace(env: any) {
  const objects = new Map<string, { gate: SessionGate; tail: Promise<unknown> }>();
  const gets: string[] = [];
  const mk = (id: string) => {
    if (!objects.has(id)) {
      const data = new Map<string, string>();
      const storage = { get: async (k: string) => data.get(k), put: async (k: string, v: string) => { data.set(k, v); }, delete: async (k: string) => data.delete(k), setAlarm: async () => {}, deleteAll: async () => data.clear() };
      objects.set(id, { gate: new SessionGate({ storage } as any, env), tail: Promise.resolve() });
    }
    return objects.get(id)!;
  };
  return {
    gets,
    idFromName: (name: string) => ({ toString: () => crypto.createHash("sha256").update("do:" + name).digest("hex") }),
    idFromString: (s: string) => { if (!/^[0-9a-f]{64}$/.test(s)) throw new Error("invalid object id"); return { toString: () => s }; },
    get(id: any) {
      const key = String(id); gets.push(key);
      const o = mk(key);
      return { fetch: (req: Request) => { const run = o.tail.then(() => o.gate.fetch(req)); o.tail = run.catch(() => undefined); return run; } };
    },
  };
}

type Call = { url: string; headers: Headers };
function setup(opts: { origin?: (c: Call) => Response; core?: (body: any, headers: Headers) => Response } = {}) {
  const ns = fakeNamespace({ ...AUTH_ENV_BASE });
  const calls: Call[] = [];
  const coreCalls: Array<{ body: any; headers: Headers }> = [];
  let now = NOW_MS;
  const env: AssistEnv = {
    ORIGIN_URL: "https://origin.example.com/", ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec", ...AUTH_ENV_BASE,
    SESSIONS: memKV(), SESSION_GATE: ns as any, ASSERTION_KEY_JWK: PRIVATE_JWK, ASSIST_MARKER: MARKER,
    SUPPORT: { fetch: async (req: Request) => { const body = await req.json(); coreCalls.push({ body, headers: req.headers }); return opts.core ? opts.core(body, req.headers) : new Response(JSON.stringify({ kind: "answer", text: "ok" }), { status: 200 }); } },
  };
  const deps = {
    now: () => now,
    fetch: (async (url: string, init: RequestInit) => {
      const h = new Headers(init.headers as any);
      const c = { url: String(url), headers: h };
      calls.push(c);
      if (opts.origin) return opts.origin(c);
      if (c.url.endsWith("/v1/session")) return new Response(JSON.stringify({ items: [{ org_id: ORG_A, name: "Acme", role: "admin", status: "active" }, { org_id: ORG_B, name: "Other Co", role: "viewer", status: "active" }] }), { status: 200 });
      if (c.url.endsWith("/v1/org")) return new Response(JSON.stringify({ org_id: ORG_A, name: "Acme", status: "active", region: "us", role: "admin" }), { status: 200 });
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch,
  };
  const store = sessionStoreFor({ SESSIONS: env.SESSIONS!, SESSION_GATE: ns as any, ...AUTH_ENV_BASE } as any, deps.fetch);
  const make = async (sid: string, org: string, tenant: string) => {
    const rec: SessionRecord = { token: jwt({ sub: "user_" + sid.slice(4, 8), sid: "ps", exp: nowSec() + 600 }), token_exp: nowSec() + 600, refresh: "rt", provider_sid: "ps", org_id: org, tenant: { token: tenant, exp: nowSec() + 600 }, until: nowSec() + 28800, iat: nowSec(), amr: ["hwk"], method: "Passkey", email: "member@example.com", email_verified: true };
    await store.create(sid, rec, now);
  };
  return { env, deps, ns, calls, coreCalls, make, advance: (ms: number) => { now += ms; } };
}

const ask = (sid: string | null, body: unknown, over: { org?: string | null; origin?: string | null } = {}) => {
  const h = new Headers({ "content-type": "application/json" });
  if (sid) h.set("cookie", `${SESSION_COOKIE}=${sid}`);
  if (over.org !== null) h.set("x-cv-org", over.org ?? ORG_A);
  if (over.origin !== null) h.set("origin", over.origin ?? ORIGIN);
  return new Request(ORIGIN + "/assist/ask", { method: "POST", headers: h, body: JSON.stringify(body) });
};
const Q = { conversation_id: "c_" + "a".repeat(32), question: "Why does setup say my form is not connected?" };
const readReq = (tool: string, cap: string, q: string, extra: Record<string, string> = {}) =>
  new Request(`${ORIGIN}/assist/read/${tool}`, { method: "GET", headers: { [MARKER_HEADER]: MARKER, [CAPABILITY_HEADER]: cap, [QUESTION_HEADER]: q, ...extra } });

async function start(t: ReturnType<typeof setup>, sid = SID_A, org = ORG_A, tenant = TENANT_A) {
  await t.make(sid, org, tenant);
  const res = await handleAssist(ask(sid, Q, { org }), t.env, t.deps);
  assert.equal(res.status, 200, await res.clone().text());
  const sent = t.coreCalls[t.coreCalls.length - 1].body;
  return { cap: sent.capability as string, q: sent.question_id as string, sent };
}

test("without a cookie the ask is 401 no_session, from the wrong origin 403, from another tab's organization 409", async () => {
  const t = setup();
  await t.make(SID_A, ORG_A, TENANT_A);
  assert.equal((await handleAssist(ask(null, Q), t.env, t.deps)).status, 401);
  assert.equal((await handleAssist(ask(SID_A, Q, { origin: "https://evil.example" }), t.env, t.deps)).status, 403);
  assert.equal((await handleAssist(ask(SID_A, Q, { org: ORG_B }), t.env, t.deps)).status, 409);
  assert.equal((await handleAssist(ask(SID_A, Q, { org: null }), t.env, t.deps)).status, 409);
  assert.equal(t.coreCalls.length, 0, "no question reached the core");
});

test("an ask forwards the vault's role for this organization, never the browser's, and a capability that is not in the answer", async () => {
  const t = setup({ core: () => new Response(JSON.stringify({ kind: "answer", text: "fine" }), { status: 200 }) });
  await t.make(SID_A, ORG_A, TENANT_A);
  const res = await handleAssist(ask(SID_A, { ...Q, role: "viewer", capability: "x.y" }), t.env, t.deps);
  assert.equal(res.status, 200);
  const sent = t.coreCalls[0].body;
  assert.equal(sent.surface, "portal");
  assert.equal(sent.role, "admin");
  assert.deepEqual(sent.contact, { org_id: ORG_A, email: "member@example.com" });
  assert.ok(!(await res.text()).includes(sent.capability));
  assert.equal(t.coreCalls[0].headers.get(MARKER_HEADER), MARKER);
  assert.ok(!JSON.stringify(sent).includes(SID_A), "the cookie value never travels to the core");
  assert.ok(!JSON.stringify(sent).includes(await sha256Hex(SID_A)), "nor its hash");
});

test("the capability string holds neither the cookie value nor the hash the session store keys by, and names the object the session lives in", async () => {
  const t = setup();
  const { cap } = await start(t);
  const keyHash = (await sessionKey(SID_A)).replace("sess:", "");
  assert.ok(!cap.includes(SID_A) && !cap.includes(await sha256Hex(SID_A)) && !cap.includes(keyHash));
  const [obj, random] = cap.split(".");
  assert.equal(obj, String(t.ns.idFromName(SID_A)));
  assert.ok(random.length >= 40);
});

test("a read within its limits returns only the listed fields and names the screen", async () => {
  const t = setup({
    origin: (c) => c.url.endsWith("/v1/sources")
      ? new Response(JSON.stringify({ items: [{ source_id: "s1", name: "Landing page " + "x".repeat(100), kind: "site_key", brand_ids: ["b1"], allowed_origins: ["https://hidden.example"], status: "active", created_at: "t", last_event_at: "2026-11-01T00:00:00Z", last_event_seq: 9, last_event_sealed: true }], next_cursor: null }), { status: 200 })
      : c.url.endsWith("/v1/session") ? new Response(JSON.stringify({ items: [{ org_id: ORG_A, name: "Acme", role: "admin" }] }), { status: 200 }) : new Response("{}", { status: 200 }),
  });
  const { cap, q } = await start(t);
  const res = await handleAssist(readReq("sources_summary", cap, q), t.env, t.deps);
  assert.equal(res.status, 200);
  const j = (await res.json()) as any;
  assert.equal(j.screen, "/sources");
  assert.equal(j.fact_id, "f_sources_summary");
  assert.deepEqual(Object.keys(j.data.items[0]).sort(), ["kind", "last_event_at", "name", "status"]);
  assert.equal(j.data.items[0].name.length, 80);
  const text = JSON.stringify(j);
  for (const leaked of ["hidden.example", "\"s1\"", "b1", "last_event_seq", "sealed"]) assert.ok(!text.includes(leaked), `leaked ${leaked}`);
});

test("a fifth read is refused as spent, a read after 60 seconds as expired, a read for another question as wrong_question", async () => {
  const t = setup();
  const { cap, q } = await start(t);
  for (let i = 0; i < 4; i++) assert.equal((await handleAssist(readReq("org_status", cap, q), t.env, t.deps)).status, 200, `read ${i + 1}`);
  const fifth = await handleAssist(readReq("org_status", cap, q), t.env, t.deps);
  assert.equal(fifth.status, 403);
  assert.equal(((await fifth.json()) as any).reason, "spent");

  const t2 = setup();
  const s2 = await start(t2);
  assert.equal(((await (await handleAssist(readReq("org_status", s2.cap, "q_other"), t2.env, t2.deps)).json()) as any).reason, "wrong_question");
  t2.advance(61_000);
  const late = await handleAssist(readReq("org_status", s2.cap, s2.q), t2.env, t2.deps);
  assert.equal(late.status, 403);
  assert.equal(((await late.json()) as any).reason, "expired");
});

test("six reads at once spend exactly four", async () => {
  const t = setup();
  const { cap, q } = await start(t);
  const all = await Promise.all(Array.from({ length: 6 }, () => handleAssist(readReq("org_status", cap, q), t.env, t.deps)));
  assert.deepEqual(all.map((r) => r.status).sort(), [200, 200, 200, 200, 403, 403]);
});

test("another session's object cannot spend this capability, and a malformed object id never reaches a Durable Object", async () => {
  const t = setup();
  const a = await start(t, SID_A, ORG_A, TENANT_A);
  await t.make(SID_B, ORG_B, TENANT_B);
  const b = await handleAssist(ask(SID_B, Q, { org: ORG_B }), t.env, t.deps);
  assert.equal(b.status, 200);
  const bcap = t.coreCalls[1].body.capability as string;
  // A's random part presented under B's object id, and B's under A's object id: both unknown.
  const swapped1 = String(t.ns.idFromName(SID_B)) + "." + a.cap.split(".")[1];
  const swapped2 = String(t.ns.idFromName(SID_A)) + "." + bcap.split(".")[1];
  for (const c of [swapped1, swapped2]) {
    const r = await handleAssist(readReq("org_status", c, a.q), t.env, t.deps);
    assert.equal(((await r.json()) as any).reason, "unknown");
  }
  const before = t.ns.gets.length;
  for (const bad of ["notanid.rest", ".rest", "abc.", "../../x.y", "a".repeat(300)]) {
    assert.equal((await handleAssist(readReq("org_status", bad, a.q), t.env, t.deps)).status, 403);
  }
  assert.equal(t.ns.gets.length, before, "a malformed capability names no object");
  assert.deepEqual([...new Set(t.ns.gets)].sort(), [String(t.ns.idFromName(SID_A)), String(t.ns.idFromName(SID_B))].sort(), "every lookup went to a session object");
});

test("a session that ended since minting answers wrong_session", async () => {
  const t = setup();
  const { cap, q } = await start(t);
  await sessionStoreFor({ SESSIONS: t.env.SESSIONS!, SESSION_GATE: t.ns as any, ...AUTH_ENV_BASE } as any, t.deps.fetch).revoke(SID_A, NOW_MS + 1000);
  t.advance(2000);
  const r = await handleAssist(readReq("org_status", cap, q), t.env, t.deps);
  assert.equal(((await r.json()) as any).reason, "wrong_session");
});

test("without the marker, a public request learns nothing: 404 whatever it carries", async () => {
  const t = setup();
  const { cap, q } = await start(t);
  t.calls.length = 0;
  for (const marker of [null, "", "wrong", MARKER + "x", MARKER.slice(1)]) {
    const req = new Request(`${ORIGIN}/assist/read/org_status`, { headers: { ...(marker === null ? {} : { [MARKER_HEADER]: marker }), [CAPABILITY_HEADER]: cap, [QUESTION_HEADER]: q } });
    assert.equal((await handleAssist(req, t.env, t.deps)).status, 404);
  }
  assert.equal(t.calls.length, 0, "no vault call was made");
});

test("a core call that adds a cookie, a session or an organization header changes nothing: the object's session and the record's organization decide", async () => {
  const t = setup();
  const { cap, q } = await start(t, SID_A, ORG_A, TENANT_A);
  await t.make(SID_B, ORG_B, TENANT_B);
  t.calls.length = 0;
  const res = await handleAssist(readReq("org_status", cap, q, { cookie: `${SESSION_COOKIE}=${SID_B}`, "x-cv-session": SID_B, "x-cv-org": ORG_B, authorization: `Bearer ${TENANT_B}` }), t.env, t.deps);
  assert.equal(res.status, 200);
  const toVault = t.calls.find((c) => c.url.endsWith("/v1/org"))!;
  assert.equal(toVault.headers.get("authorization"), `Bearer ${TENANT_A}`);
  assert.equal(toVault.headers.get("cookie"), null);
  assert.equal(toVault.headers.get("x-cv-org"), null, "the gateway never forwards an organization header");
  assert.ok(!JSON.stringify([...toVault.headers.entries()]).includes(TENANT_B));
});

test("session_role keeps only the organization the capability names", async () => {
  const t = setup();
  const { cap, q } = await start(t);
  const j = (await (await handleAssist(readReq("session_role", cap, q), t.env, t.deps)).json()) as any;
  assert.deepEqual(j.data, { role: "admin", name: "Acme" });
  assert.ok(!JSON.stringify(j).includes("Other Co") && !JSON.stringify(j).includes(ORG_B));
});

test("the vault's own refusal for a role is the answer, passed through with no figure", async () => {
  const t = setup({ origin: (c) => c.url.endsWith("/v1/billing") ? new Response(JSON.stringify({ error: "role_not_allowed", message: "only an organization admin may use billing" }), { status: 403 }) : c.url.endsWith("/v1/session") ? new Response(JSON.stringify({ items: [{ org_id: ORG_A, name: "Acme", role: "compliance_viewer" }] }), { status: 200 }) : new Response("{}", { status: 200 }) });
  const { cap, q, sent } = await start(t);
  assert.equal(sent.role, "compliance_viewer");
  const j = (await (await handleAssist(readReq("plan_and_usage", cap, q), t.env, t.deps)).json()) as any;
  assert.equal(j.refused, "role_not_allowed");
  assert.equal(j.data, undefined);
  assert.equal(j.fact_id, null);
});

test("a vault answer that lacks an expected field is a named 502, never an empty object", async () => {
  const t = setup({ origin: (c) => c.url.endsWith("/v1/billing") ? new Response(JSON.stringify({ status: "active" }), { status: 200 }) : c.url.endsWith("/v1/session") ? new Response(JSON.stringify({ items: [{ org_id: ORG_A, name: "Acme", role: "admin" }] }), { status: 200 }) : new Response("{}", { status: 200 }) });
  const { cap, q } = await start(t);
  const res = await handleAssist(readReq("plan_and_usage", cap, q), t.env, t.deps);
  assert.equal(res.status, 502);
  assert.equal(((await res.json()) as any).error, "field_missing");
});

test("an unknown tool, a tool with a query string or a post to the reader never reaches the vault", async () => {
  const t = setup();
  const { cap, q } = await start(t);
  t.calls.length = 0;
  assert.equal((await handleAssist(readReq("records", cap, q), t.env, t.deps)).status, 404);
  assert.equal((await handleAssist(readReq("constructor", cap, q), t.env, t.deps)).status, 404);
  const withQuery = new Request(`${ORIGIN}/assist/read/org_status?org=${ORG_B}`, { headers: { [MARKER_HEADER]: MARKER, [CAPABILITY_HEADER]: cap, [QUESTION_HEADER]: q } });
  assert.equal((await handleAssist(withQuery, t.env, t.deps)).status, 404);
  assert.equal((await handleAssist(new Request(`${ORIGIN}/assist/read/org_status`, { method: "POST", headers: { [MARKER_HEADER]: MARKER } }), t.env, t.deps)).status, 405);
  assert.equal(t.calls.length, 0);
});

test("the portal Worker routes /assist/* to the assistant and answers 503 by name while the bindings are not set", async () => {
  const t = setup();
  const bare = { ...t.env, SUPPORT: undefined, ASSIST_MARKER: undefined } as any;
  const res = await handlePortal(ask(SID_A, Q), bare, t.deps);
  assert.equal(res.status, 503);
  assert.equal(((await res.json()) as any).error, "assist_not_configured");
  await t.make(SID_A, ORG_A, TENANT_A);
  assert.equal((await handlePortal(ask(SID_A, Q), t.env as any, t.deps)).status, 200);
});

// ---- the tool table against the vault's own route table (FR-B04, FR-016 product half)
const root = new URL("../../src/consentvault/", import.meta.url);
const routeText = ["tenancy/admin_routes.py", "billing/routes.py"].map((f) => readFileSync(new URL(f, root), "utf8")).join("\n");
const vaultGets = new Set<string>([...routeText.matchAll(/_r\("GET", "(\/v1\/[^"]+)"/g)].map((m) => m[1]).concat([...routeText.matchAll(/\("GET", "(\/v1\/[^"]+)"\)/g)].map((m) => m[1])));

test("every tool is one fixed GET that exists in the vault, with no parameter, and none touches a forbidden prefix", () => {
  assert.ok(vaultGets.size > 10, "the vault's route table was read");
  assert.equal(Object.keys(TOOLS).length, 8);
  for (const [name, tool] of Object.entries(TOOLS)) {
    assert.ok(vaultGets.has(tool.path), `${name}: ${tool.path} is a GET in the vault's route table`);
    assert.ok(!tool.path.includes(":") && !tool.path.includes("{") && !tool.path.includes("?"), `${name}: no parameter`);
    for (const p of FORBIDDEN_PREFIXES) assert.ok(!(tool.path === p || tool.path.startsWith(p + "/")), `${name} touches ${p}`);
    for (const s of FORBIDDEN_SUFFIXES) assert.ok(!tool.path.endsWith(s), `${name} ends ${s}`);
  }
});

test("the forbidden list covers every record-bearing GET the vault has, so a new route cannot slip in as a tool unnoticed", () => {
  const sensitive = [...vaultGets].filter((p) => /^\/v1\/(records|evidence|proof|exports|audit|members|invites|erasures|offboarding|events|capture|confirmations)/.test(p) || p.endsWith("/deliveries"));
  assert.ok(sensitive.length > 0, "the vault has such routes");
  const tools = new Set(Object.values(TOOLS).map((t) => t.path));
  const covered = (p: string) => FORBIDDEN_PREFIXES.some((x) => p === x || p.startsWith(x + "/")) || FORBIDDEN_SUFFIXES.some((s) => p.endsWith(s));
  for (const p of sensitive) {
    assert.ok(!tools.has(p), `${p} must not be a tool`);
    assert.ok(covered(p), `${p} is not on the forbidden list`);
  }
});

test("assist.ts calls the vault only as a GET through the gateway", () => {
  const src = readFileSync(new URL("../src/assist.ts", import.meta.url), "utf8");
  assert.ok(!/method:\s*["'](POST|PUT|PATCH|DELETE)["'][^}]*\/v1\//.test(src));
  assert.equal((src.match(/viaGateway\(/g) ?? []).length, 3, "the definition and the two callers (role lookup, reader)");
});
