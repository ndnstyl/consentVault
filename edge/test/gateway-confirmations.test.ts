import test from "node:test";
import assert from "node:assert/strict";
import { drainInboundSpool, handleGateway, SPOOL_PER_KEY, SPOOL_TOTAL, LINK_HOST_HEADER, type GatewayEnv, type GatewayDeps, type RateLimiter, type SpoolKV } from "../src/gateway.ts";

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

// ---- the fallback door: spooled at the edge before the vault is asked -------------------------------------------------------
class Spool implements SpoolKV {
  data = new Map<string, string>();
  failPut = false;
  async get(k: string) { return this.data.get(k) ?? null; }
  async put(k: string, v: string) { if (this.failPut) throw new Error("kv down"); this.data.set(k, v); }
  async delete(k: string) { this.data.delete(k); }
  async list(o: { prefix: string }) { return { keys: [...this.data.keys()].filter((k) => k.startsWith(o.prefix)).sort().map((name) => ({ name })) }; }
}
const FPATH = `/v1/confirmations/inbound-fallback/${KEY}`;

function down(calls: { url: string; init: RequestInit }[] = []): typeof fetch {
  return (async (url: string, init: RequestInit) => { calls.push({ url: String(url), init }); throw new TypeError("network"); }) as unknown as typeof fetch;
}

test("a fallback post while the vault is down is kept at the edge and Twilio is told it was received", async () => {
  const spool = new Spool();
  const { env, alarms } = mk({ INBOUND_SPOOL: spool });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: (n) => alarms.push(n) });
  assert.equal(res.status, 200);
  assert.equal([...spool.data.keys()].filter((k) => k.startsWith("inbound:")).length, 1);
  const kept = JSON.parse([...spool.data.entries()].find(([k]) => k.startsWith("inbound:"))![1]);
  assert.equal(kept.path, FPATH);
  assert.equal(atob(kept.body_b64), RAW);
  assert.equal(kept.headers["x-twilio-signature"], TWILIO["x-twilio-signature"]);
  assert.deepEqual(alarms, ["confirmations.inbound_spooled"]);
});

test("a fallback post the vault answers at once is not left in the spool", async () => {
  const spool = new Spool();
  const { d, calls, env } = mk({ INBOUND_SPOOL: spool });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, d);
  assert.equal(res.status, 200);
  assert.equal(calls[0].url, "https://origin.example.com" + FPATH);
  assert.equal([...spool.data.keys()].filter((k) => k.startsWith("inbound:")).length, 0);
});

test("a fallback post that can be neither kept nor delivered answers 503 and alarms", async () => {
  const spool = new Spool();
  spool.failPut = true;
  const { env, alarms } = mk({ INBOUND_SPOOL: spool });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: (n) => alarms.push(n) });
  assert.equal(res.status, 503);
  assert.ok(alarms.includes("confirmations.inbound_spool_unwritable"));
});

test("the drain delivers each kept post to the vault's fallback door byte for byte and keeps it while the vault is down", async () => {
  const spool = new Spool();
  const { env } = mk({ INBOUND_SPOOL: spool });
  await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: () => {} });
  const left = await drainInboundSpool(env, { fetch: down(), alarm: () => {} });
  assert.equal(left.kept, 1);
  assert.equal([...spool.data.keys()].filter((k) => k.startsWith("inbound:")).length, 1);
  const calls: { url: string; init: RequestInit }[] = [];
  const up = (async (url: string, init: RequestInit) => { calls.push({ url: String(url), init }); return new Response("{}", { status: 200 }); }) as unknown as typeof fetch;
  const done = await drainInboundSpool(env, { fetch: up, alarm: () => {} });
  assert.deepEqual(done, { delivered: 1, kept: 0 });
  assert.equal([...spool.data.keys()].filter((k) => k.startsWith("inbound:")).length, 0, "only the vault's 2xx ends a kept post");
  assert.equal(calls[0].url, "https://origin.example.com" + FPATH);
  assert.equal(new TextDecoder().decode(calls[0].init.body as ArrayBuffer), RAW);
  const h = calls[0].init.headers as Headers;
  assert.equal(h.get("x-twilio-signature"), TWILIO["x-twilio-signature"]);
  assert.equal(h.get("cf-access-client-id"), "cid");
});

test("without the spool binding the fallback post is forwarded and a named alarm raised", async () => {
  const { d, calls, alarms, env } = mk({ INBOUND_SPOOL: undefined });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, d);
  assert.equal(res.status, 200);
  assert.equal(calls.length, 1);
  assert.ok(alarms.includes("confirmations.inbound_spool_unbound"));
});

test("a client copy of the link-host header never reaches the vault on any other route", async () => {
  const { d, calls, env } = mk();
  await handleGateway(at("api.consentvault.ai", "/v1/systems", { headers: { authorization: "Bearer abc.def", [LINK_HOST_HEADER]: "consent.acme.example" } }), env, d);
  assert.equal((calls[0].init.headers as Headers).get(LINK_HOST_HEADER), null);
});

test("only a 2xx from the vault ends a kept post: a 404, 401 or 403 keeps it and raises an alarm", async () => {
  for (const status of [404, 401, 403, 409, 302]) {
    const spool = new Spool();
    const alarms: string[] = [];
    const { env } = mk({ INBOUND_SPOOL: spool });
    await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: () => {} });
    const answer = (async () => new Response("{}", { status })) as unknown as typeof fetch;
    const out = await drainInboundSpool(env, { fetch: answer, alarm: (n) => alarms.push(n) });
    assert.deepEqual(out, { delivered: 0, kept: 1 }, String(status));
    assert.ok(alarms.includes("confirmations.inbound_spool_refused"), String(status));
  }
});

test("a fallback post the vault answers with anything but 2xx stays kept, and Twilio is still told it was received", async () => {
  const spool = new Spool();
  const alarms: string[] = [];
  const { env } = mk({ INBOUND_SPOOL: spool });
  const answer = (async () => new Response("{}", { status: 404 })) as unknown as typeof fetch;
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: answer, alarm: (n) => alarms.push(n) });
  assert.equal(res.status, 200);
  assert.equal([...spool.data.keys()].filter((k) => k.startsWith("inbound:")).length, 1);
  assert.ok(alarms.includes("confirmations.inbound_spool_refused"));
});

test("the spool holds at most SPOOL_PER_KEY posts for one number and SPOOL_TOTAL in all; past a cap the post is forwarded, not kept", async () => {
  const spool = new Spool();
  for (let i = 0; i < SPOOL_PER_KEY; i++) spool.data.set(`inbound:${KEY}:2026-11-14T00:00:${String(i).padStart(4, "0")}:x`, "{}");
  const alarms: string[] = [];
  const { env } = mk({ INBOUND_SPOOL: spool });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: (n) => alarms.push(n) });
  assert.equal(res.status, 503);
  assert.equal([...spool.data.keys()].filter((k) => k.startsWith("inbound:")).length, SPOOL_PER_KEY);
  assert.ok(alarms.includes("confirmations.inbound_spool_full"));
  const other = new Spool();
  for (let i = 0; i < SPOOL_TOTAL; i++) other.data.set(`inbound:k${i}xxxxxxxxxxxxxxxxxxxxxxx:t:x`, "{}");
  const e2 = mk({ INBOUND_SPOOL: other }).env;
  const r2 = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), e2, { fetch: down(), alarm: () => {} });
  assert.equal(r2.status, 503);
  assert.equal(other.data.size, SPOOL_TOTAL);
});

test("a fallback body over 16 KB is refused and never kept (the vault takes no more)", async () => {
  const spool = new Spool();
  const { d, calls, env } = mk({ INBOUND_SPOOL: spool });
  const res = await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: "a=" + "x".repeat(16 * 1024) }), env, d);
  assert.equal(res.status, 413);
  assert.equal(spool.data.size, 0);
  assert.equal(calls.length, 0);
});

test("the drain reads one marker and lists nothing while the spool is empty (the KV list quota)", async () => {
  let lists = 0;
  const spool = new Spool();
  const orig = spool.list.bind(spool);
  spool.list = async (o) => { lists++; return orig(o); };
  const { env } = mk({ INBOUND_SPOOL: spool });
  await drainInboundSpool(env, { fetch: down(), alarm: () => {} });
  assert.equal(lists, 0);
});

test("a post kept between the drain's listing and its flag check is still drained on the next run", async () => {
  const spool = new Spool();
  const { env } = mk({ INBOUND_SPOOL: spool });
  let t = Date.parse("2026-11-14T12:00:00Z");
  const clock = () => t;
  // something was kept long ago and has been delivered, so the flag is old and the spool empty
  spool.data.set("meta:pending", new Date(t - 3_600_000).toISOString());
  const origList = spool.list.bind(spool);
  let lists = 0;
  spool.list = async (o) => {
    const out = await origList(o);
    lists++;
    if (lists === 1) {
      // a fallback post arrives right after the drain's first listing read empty
      await handleGateway(at("api.consentvault.ai", FPATH, { method: "POST", headers: TWILIO, body: RAW }), env, { fetch: down(), alarm: () => {}, now: clock });
    }
    return out;
  };
  await drainInboundSpool(env, { fetch: down(), alarm: () => {}, now: clock, sleep: async () => {} });
  assert.notEqual(spool.data.get("meta:pending"), undefined, "the flag must survive: a post was kept during the drain");
  spool.list = origList;
  t += 60_000;
  const calls: { url: string }[] = [];
  const up = (async (url: string) => { calls.push({ url: String(url) }); return new Response("{}", { status: 200 }); }) as unknown as typeof fetch;
  const next = await drainInboundSpool(env, { fetch: up, alarm: () => {}, now: clock, sleep: async () => {} });
  assert.equal(next.delivered, 1);
});

test("the flag is removed only after two empty listings and once it is older than the settle time", async () => {
  const spool = new Spool();
  const { env } = mk({ INBOUND_SPOOL: spool });
  const t = Date.parse("2026-11-14T12:00:00Z");
  spool.data.set("meta:pending", new Date(t - 30_000).toISOString());
  await drainInboundSpool(env, { fetch: down(), alarm: () => {}, now: () => t, sleep: async () => {} });
  assert.notEqual(spool.data.get("meta:pending"), undefined, "a young flag stays (KV listings can lag a fresh write)");
  spool.data.set("meta:pending", new Date(t - 600_000).toISOString());
  await drainInboundSpool(env, { fetch: down(), alarm: () => {}, now: () => t, sleep: async () => {} });
  assert.equal(spool.data.get("meta:pending"), undefined);
});
