import test from "node:test";
import assert from "node:assert/strict";
import { drainInboundSpool, handleGateway, SPOOL_PER_KEY, SPOOL_SQL, SPOOL_TOTAL, LINK_HOST_HEADER, type D1Like, type GatewayEnv, type GatewayDeps, type RateLimiter } from "../src/gateway.ts";

// The confirmation service's two public doors (marketing/specs/confirmations-go-live):
//  - the text provider's inbound posts, POST /v1/confirmations/inbound/<key>: admitted with no bearer (Twilio sends none; the
//    vault checks the X-Twilio-Signature over the address it stored), the raw body and the provider's headers unchanged,
//    rate limited per inbound key;
//  - the person's pages on an organisation's own link host, /c/r/<token> and /c/stop/<token>: forwarded with the request's own
//    host name in X-ConsentVault-Link-Host (a client copy is dropped), rate limited per client address.
const KEY = "Abc_def-0123456789abcdefghijklmnopqrstuvwxyz";
const PATH = `/v1/confirmations/inbound/${KEY}`;
const RAW = "AccountSid=AC00&Body=STOP&From=%2B15555550100&MessageSid=SM1&To=%2B15555550199";
const TWILIO = { "x-twilio-signature": "c2lnbmF0dXJl", "content-type": "application/x-www-form-urlencoded", "i-twilio-idempotency-token": "tok" };

class Limiter implements RateLimiter {
  keys: string[] = [];
  allow: boolean;
  constructor(allow = true) { this.allow = allow; }
  async limit({ key }: { key: string }) {
    this.keys.push(key);
    return { success: this.allow };
  }
}

const SESSIONS_UNTOUCHED = {
  get: async () => { throw new Error("the session store was read on a provider or page request"); },
  put: async () => { throw new Error("the session store was written"); },
  delete: async () => { throw new Error("the session store was written"); },
};

function mk(env: Partial<GatewayEnv> = {}) {
  const calls: { url: string; init: RequestInit }[] = [];
  const alarms: string[] = [];
  const d: GatewayDeps = {
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch,
    alarm: (name) => alarms.push(name),
  };
  const full: GatewayEnv = {
    ORIGIN_URL: "https://origin.example.com/", ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec",
    INBOUND_LIMITER: new Limiter(), PAGE_LIMITER: new Limiter(), SESSIONS: SESSIONS_UNTOUCHED as unknown as GatewayEnv["SESSIONS"], ...env,
  };
  return { d, calls, alarms, env: full };
}
const at = (host: string, path: string, init: RequestInit = {}) => new Request(`https://${host}${path}`, init);

// ---- the provider door ----------------------------------------------------------------------------------------------------
test("a provider post is admitted with no bearer and reaches the vault byte for byte with its headers", async () => {
  const { d, calls, env } = mk();
  const res = await handleGateway(at("api.consentvault.ai", PATH, { method: "POST", headers: { ...TWILIO, cookie: "__Host-cv=x", authorization: "Bearer someone" }, body: RAW }), env, d);
  assert.equal(res.status, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://origin.example.com" + PATH);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(new TextDecoder().decode(calls[0].init.body as ArrayBuffer), RAW);
  const h = calls[0].init.headers as Headers;
  for (const [k, v] of Object.entries(TWILIO)) assert.equal(h.get(k), v, k);
  assert.equal(h.get("authorization"), null);
  assert.equal(h.get("cookie"), null);
  assert.equal(h.get("cf-access-client-id"), "cid");
  assert.equal(h.get("cf-access-client-secret"), "csec");
});

test("only POST to the exact inbound path skips the bearer check", async () => {
  for (const [method, path] of [["GET", PATH], ["PUT", PATH], ["POST", PATH + "/x"], ["POST", "/v1/confirmations/inbound/"],
    ["POST", "/v1/confirmations/inbound/short"], ["POST", "/v1/confirmations/inbound/has%20space0123456789abc"], ["POST", "/v1/confirmations/settings"]]) {
    const { d, calls, env } = mk();
    const res = await handleGateway(at("api.consentvault.ai", path, { method, headers: TWILIO, body: method === "GET" ? undefined : RAW }), env, d);
    assert.ok(res.status === 401 || res.status === 405, `${method} ${path} answered ${res.status}`);
    assert.equal(calls.length, 0, `${method} ${path} reached the vault`);
  }
});

test("the inbound door is never refused: over the limit it still forwards and raises a named alarm", async () => {
  const limiter = new Limiter(false);
  const { d, calls, alarms, env } = mk({ INBOUND_LIMITER: limiter });
  const res = await handleGateway(at("api.consentvault.ai", PATH, { method: "POST", headers: TWILIO, body: RAW }), env, d);
  assert.equal(res.status, 200);
  assert.equal(calls.length, 1);
  assert.deepEqual(alarms, ["confirmations.inbound_rate_limited"]);
});

test("delivery reports and replies are counted under separate keys, so a send burst cannot use up the replies' allowance", async () => {
  const limiter = new Limiter(true);
  const { d, env } = mk({ INBOUND_LIMITER: limiter });
  await handleGateway(at("api.consentvault.ai", PATH, { method: "POST", headers: TWILIO, body: "MessageSid=SM2&MessageStatus=delivered&To=%2B1555" }), env, d);
  await handleGateway(at("api.consentvault.ai", PATH, { method: "POST", headers: TWILIO, body: RAW }), env, d);
  assert.deepEqual(limiter.keys, [`inbound:${KEY}:report`, `inbound:${KEY}:reply`]);
});

test("without the rate-limit binding the post still goes through and a named alarm is raised", async () => {
  const { d, calls, alarms, env } = mk({ INBOUND_LIMITER: undefined });
  const res = await handleGateway(at("api.consentvault.ai", PATH, { method: "POST", headers: TWILIO, body: RAW }), env, d);
  assert.equal(res.status, 200);
  assert.equal(calls.length, 1);
  assert.deepEqual(alarms, ["confirmations.inbound_rate_limit_unbound"]);
});

test("the inbound body cap is 64 KB (the vault refuses over 16 KB itself and counts it)", async () => {
  const { d, calls, env } = mk();
  const res = await handleGateway(at("api.consentvault.ai", PATH, { method: "POST", headers: TWILIO, body: "a=" + "x".repeat(64 * 1024) }), env, d);
  assert.equal(res.status, 413);
  assert.equal(calls.length, 0);
  const ok = await handleGateway(at("api.consentvault.ai", PATH, { method: "POST", headers: TWILIO, body: "a=" + "x".repeat(20000) }), env, d);
  assert.equal(ok.status, 200);
});

// ---- the public pages -----------------------------------------------------------------------------------------------------
test("a wording page is forwarded with the request's own host as the link host, never the client's copy", async () => {
  const { d, calls, env } = mk();
  const res = await handleGateway(at("consent.acme.example", "/c/r/tok_abc-12345", {
    headers: { [LINK_HOST_HEADER]: "consent.other.example", cookie: "__Host-cv=x", authorization: "Bearer t" },
  }), env, d);
  assert.equal(res.status, 200);
  assert.equal(calls[0].url, "https://origin.example.com/c/r/tok_abc-12345");
  const h = calls[0].init.headers as Headers;
  assert.equal(h.get(LINK_HOST_HEADER), "consent.acme.example");
  assert.equal(h.get("cookie"), null);
  assert.equal(h.get("authorization"), null);
  assert.equal(h.get("cf-access-client-id"), "cid");
});

test("the stop page takes GET and POST with its body; the wording page takes GET only", async () => {
  const { d, calls, env } = mk();
  assert.equal((await handleGateway(at("consent.acme.example", "/c/stop/tok_abc-12345"), env, d)).status, 200);
  const post = await handleGateway(at("consent.acme.example", "/c/stop/tok_abc-12345", { method: "POST", body: "scope=email", headers: { "content-type": "application/x-www-form-urlencoded" } }), env, d);
  assert.equal(post.status, 200);
  assert.equal(new TextDecoder().decode(calls[1].init.body as ArrayBuffer), "scope=email");
  const wrong = await handleGateway(at("consent.acme.example", "/c/r/tok_abc-12345", { method: "POST", body: "x" }), env, d);
  assert.equal(wrong.status, 405);
  assert.equal(calls.length, 2);
});

test("a page path that is not a token path is not forwarded", async () => {
  for (const path of ["/c/r/short", "/c/x/tok_abc-12345", "/c/r/tok_abc-12345/more", "/c/"]) {
    const { d, calls, env } = mk();
    const res = await handleGateway(at("consent.acme.example", path), env, d);
    assert.equal(res.status, 404, path);
    assert.equal(calls.length, 0, path);
  }
});

test("the wording page and the stop form are limited per client address", async () => {
  const limiter = new Limiter(false);
  const { d, calls, env } = mk({ PAGE_LIMITER: limiter });
  const res = await handleGateway(at("consent.acme.example", "/c/stop/tok_abc-12345", { headers: { "cf-connecting-ip": "203.0.113.9" } }), env, d);
  assert.equal(res.status, 429);
  assert.equal(calls.length, 0);
  assert.deepEqual(limiter.keys, ["page:203.0.113.9"]);
});

test("a stop posted to the stop page (the email's one-click unsubscribe) is limited per token, never per client address", async () => {
  const limiter = new Limiter(true);
  const { d, calls, env } = mk({ PAGE_LIMITER: limiter });
  await handleGateway(at("consent.acme.example", "/c/stop/tok_abc-12345", { method: "POST", body: "List-Unsubscribe=One-Click", headers: { "cf-connecting-ip": "203.0.113.9" } }), env, d);
  assert.deepEqual(limiter.keys, ["stop:tok_abc-12345"]);
  assert.equal(calls.length, 1);
});

test("the link-host probe is forwarded with the link host", async () => {
  const { d, calls, env } = mk();
  const res = await handleGateway(at("consent.acme.example", "/c/ping"), env, d);
  assert.equal(res.status, 200);
  assert.equal((calls[0].init.headers as Headers).get(LINK_HOST_HEADER), "consent.acme.example");
});

// ---- the fallback door: stored in D1 before the vault is asked ----------------------------------------------------------------
// A stand-in for D1 that answers exactly the statements the gateway sends (SPOOL_SQL); any other statement fails the test.
type Row = { id: string; number_key: string; received_at: string; path: string; body_b64: string; headers_json: string; attempts: number; last_status: number | null; drained_at: string | null };
class FakeD1 implements D1Like {
  rows: Row[] = [];
  fail: Set<string> = new Set(); // statement names that throw
  seen: string[] = [];
  prepare(sql: string) {
    const name = (Object.entries(SPOOL_SQL).find(([, v]) => v === sql) ?? [])[0];
    if (!name) throw new Error(`unexpected statement: ${sql}`);
    const db = this;
    const run = async (args: unknown[]) => {
      db.seen.push(name);
      if (db.fail.has(name)) throw new Error(`D1_ERROR ${name}`);
      const open = db.rows.filter((r) => r.drained_at === null);
      switch (name) {
        case "countKey": return { results: [{ n: open.filter((r) => r.number_key === args[0]).length }] };
        case "countAll": return { results: [{ n: open.length }] };
        case "insert": db.rows.push({ id: String(args[0]), number_key: String(args[1]), received_at: String(args[2]), path: String(args[3]), body_b64: String(args[4]), headers_json: String(args[5]), attempts: 0, last_status: null, drained_at: null }); return { results: [] };
        case "pending": return { results: [...open].sort((a, b) => a.received_at.localeCompare(b.received_at)) };
        case "markDrained": { const r = db.rows.find((x) => x.id === args[2])!; r.drained_at = String(args[0]); r.attempts++; r.last_status = Number(args[1]); return { results: [] }; }
        case "markAttempt": { const r = db.rows.find((x) => x.id === args[1])!; r.attempts++; r.last_status = Number(args[0]); return { results: [] }; }
        case "purge": db.rows = db.rows.filter((r) => !(r.drained_at !== null && r.drained_at < String(args[0]))); return { results: [] };
      }
      throw new Error(name);
    };
    return { bind: (...args: unknown[]) => ({ run: () => run(args), all: () => run(args) }) };
  }
}
const FPATH = `/v1/confirmations/inbound-fallback/${KEY}`;
const open = (db: FakeD1) => db.rows.filter((r) => r.drained_at === null);

function down(calls: { url: string; init: RequestInit }[] = []): typeof fetch {
  return (async (url: string, init: RequestInit) => { calls.push({ url: String(url), init }); throw new TypeError("network"); }) as unknown as typeof fetch;
}
const answering = (status: number, calls: { url: string; init: RequestInit }[] = []) =>
  (async (url: string, init: RequestInit) => { calls.push({ url: String(url), init }); return new Response("{}", { status }); }) as unknown as typeof fetch;

test("a fallback post while the vault is down is stored and Twilio is told it was received", async () => {
  const db = new FakeD1();
  const { env, alarms } = mk({ INBOUND_SPOOL: db });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: (n) => alarms.push(n) });
  assert.equal(res.status, 200);
  assert.equal(open(db).length, 1);
  const row = open(db)[0];
  assert.equal(row.number_key, KEY);
  assert.equal(row.path, FPATH);
  assert.equal(atob(row.body_b64), RAW);
  assert.equal(JSON.parse(row.headers_json)["x-twilio-signature"], TWILIO["x-twilio-signature"]);
  assert.deepEqual(alarms, ["confirmations.inbound_spooled"]);
});

test("a fallback post the vault takes at once is marked drained, never left open", async () => {
  const db = new FakeD1();
  const calls: { url: string; init: RequestInit }[] = [];
  const { env } = mk({ INBOUND_SPOOL: db });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: answering(200, calls), alarm: () => {} });
  assert.equal(res.status, 200);
  assert.equal(calls[0].url, "https://origin.example.com" + FPATH);
  assert.equal(open(db).length, 0);
  assert.equal(db.rows[0].last_status, 200);
});

test("a store write that fails raises a named alarm and the post still goes to the vault", async () => {
  const db = new FakeD1();
  db.fail.add("insert");
  const alarms: string[] = [];
  const calls: { url: string; init: RequestInit }[] = [];
  const { env } = mk({ INBOUND_SPOOL: db });
  const ok = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: answering(200, calls), alarm: (n) => alarms.push(n) });
  assert.equal(ok.status, 200);
  assert.equal(calls.length, 1);
  assert.ok(alarms.includes("confirmations.inbound_spool_unwritable"));
  const lost = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: (n) => alarms.push(n) });
  assert.equal(lost.status, 503, "neither stored nor delivered: Twilio is told, never a false 200");
});

test("a failed cap count still stores the post (a STOP is kept rather than refused) and alarms", async () => {
  const db = new FakeD1();
  db.fail.add("countKey");
  const alarms: string[] = [];
  const { env } = mk({ INBOUND_SPOOL: db });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: (n) => alarms.push(n) });
  assert.equal(res.status, 200);
  assert.equal(open(db).length, 1);
  assert.ok(alarms.includes("confirmations.inbound_spool_unreadable"));
});

test("the drain selects open rows every minute with no flag and no listing, and marks one drained only on the vault's 2xx", async () => {
  const db = new FakeD1();
  const { env } = mk({ INBOUND_SPOOL: db });
  await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: () => {} });
  assert.deepEqual(await drainInboundSpool(env, { fetch: down(), alarm: () => {} }), { delivered: 0, kept: 1 });
  assert.equal(db.rows[0].attempts, 0, "no answer: no write spent on the attempt");
  const calls: { url: string; init: RequestInit }[] = [];
  assert.deepEqual(await drainInboundSpool(env, { fetch: answering(202, calls), alarm: () => {} }), { delivered: 1, kept: 0 });
  assert.equal(open(db).length, 0);
  assert.equal(calls[0].url, "https://origin.example.com" + FPATH);
  assert.equal(new TextDecoder().decode(calls[0].init.body as ArrayBuffer), RAW);
  const h = calls[0].init.headers as Headers;
  assert.equal(h.get("x-twilio-signature"), TWILIO["x-twilio-signature"]);
  assert.equal(h.get("cf-access-client-id"), "cid");
  assert.ok(!db.seen.some((s) => /list|flag|marker/i.test(s)));
});

test("only a 2xx from the vault ends a stored post: a 404, 401, 403, 409 or redirect keeps it and alarms", async () => {
  for (const status of [404, 401, 403, 409, 302]) {
    const db = new FakeD1();
    const alarms: string[] = [];
    const { env } = mk({ INBOUND_SPOOL: db });
    await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: () => {} });
    const out = await drainInboundSpool(env, { fetch: answering(status), alarm: (n) => alarms.push(n) });
    assert.deepEqual(out, { delivered: 0, kept: 1 }, String(status));
    assert.ok(alarms.includes("confirmations.inbound_spool_refused"), String(status));
    assert.equal(db.rows[0].last_status, status);
  }
});

test("a fallback post the vault answers with anything but 2xx stays stored, and Twilio is still told it was received", async () => {
  const db = new FakeD1();
  const alarms: string[] = [];
  const { env } = mk({ INBOUND_SPOOL: db });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: answering(404), alarm: (n) => alarms.push(n) });
  assert.equal(res.status, 200);
  assert.equal(open(db).length, 1);
  assert.ok(alarms.includes("confirmations.inbound_spool_refused"));
});

test("a stored post older than 10 minutes raises a named alarm", async () => {
  const db = new FakeD1();
  const alarms: string[] = [];
  const { env } = mk({ INBOUND_SPOOL: db });
  const t0 = Date.parse("2026-11-14T12:00:00Z");
  await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: () => {}, now: () => t0 });
  await drainInboundSpool(env, { fetch: down(), alarm: (n) => alarms.push(n), now: () => t0 + 11 * 60_000 });
  assert.ok(alarms.includes("confirmations.inbound_spool_stale"));
});

test("a drain whose read fails raises a named alarm and throws nothing", async () => {
  const db = new FakeD1();
  db.fail.add("pending");
  const alarms: string[] = [];
  const { env } = mk({ INBOUND_SPOOL: db });
  assert.deepEqual(await drainInboundSpool(env, { fetch: down(), alarm: (n) => alarms.push(n) }), { delivered: 0, kept: 0 });
  assert.ok(alarms.includes("confirmations.inbound_spool_unreadable"));
});

test("a drain whose drained-mark fails raises a named alarm (the post is delivered again next run; the vault takes a repeat once)", async () => {
  const db = new FakeD1();
  const alarms: string[] = [];
  const { env } = mk({ INBOUND_SPOOL: db });
  await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: () => {} });
  db.fail.add("markDrained");
  await drainInboundSpool(env, { fetch: answering(200), alarm: (n) => alarms.push(n) });
  assert.ok(alarms.includes("confirmations.inbound_spool_unwritable"));
  assert.equal(open(db).length, 1);
});

test("the store holds at most SPOOL_PER_KEY open posts for one number and SPOOL_TOTAL in all; past a cap it forwards only", async () => {
  const db = new FakeD1();
  const base = { path: FPATH, body_b64: "", headers_json: "{}", attempts: 0, last_status: null, drained_at: null };
  for (let i = 0; i < SPOOL_PER_KEY; i++) db.rows.push({ ...base, id: `a${i}`, number_key: KEY, received_at: "2026-11-14T00:00:00Z" });
  const alarms: string[] = [];
  const { env } = mk({ INBOUND_SPOOL: db });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: (n) => alarms.push(n) });
  assert.equal(res.status, 503);
  assert.equal(open(db).length, SPOOL_PER_KEY);
  assert.ok(alarms.includes("confirmations.inbound_spool_full"));
  const other = new FakeD1();
  for (let i = 0; i < SPOOL_TOTAL; i++) other.rows.push({ ...base, id: `b${i}`, number_key: `k${i}`, received_at: "2026-11-14T00:00:00Z" });
  const r2 = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), mk({ INBOUND_SPOOL: other }).env, { fetch: down(), alarm: () => {} });
  assert.equal(r2.status, 503);
  assert.equal(open(other).length, SPOOL_TOTAL);
});

test("a fallback body over 16 KB is refused and never stored", async () => {
  const db = new FakeD1();
  const { d, calls, env } = mk({ INBOUND_SPOOL: db });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: "a=" + "x".repeat(16 * 1024) }), env, d);
  assert.equal(res.status, 413);
  assert.equal(db.rows.length, 0);
  assert.equal(calls.length, 0);
});

test("without the store binding the fallback post is forwarded and a named alarm raised", async () => {
  const { d, calls, alarms, env } = mk({ INBOUND_SPOOL: undefined });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, d);
  assert.equal(res.status, 200);
  assert.equal(calls.length, 1);
  assert.ok(alarms.includes("confirmations.inbound_spool_unbound"));
});

test("drained rows are purged after seven days", async () => {
  const db = new FakeD1();
  const base = { path: FPATH, body_b64: "", headers_json: "{}", attempts: 1, last_status: 200, number_key: KEY, received_at: "2026-11-01T00:00:00Z" };
  db.rows.push({ ...base, id: "old", drained_at: "2026-11-01T00:00:00Z" }, { ...base, id: "new", drained_at: "2026-11-14T11:00:00Z" });
  const { env } = mk({ INBOUND_SPOOL: db });
  await drainInboundSpool(env, { fetch: down(), alarm: () => {}, now: () => Date.parse("2026-11-14T12:00:00Z") });
  assert.deepEqual(db.rows.map((r) => r.id), ["new"]);
});
