import test from "node:test";
import assert from "node:assert/strict";
import { handleGateway, LINK_HOST_HEADER, type GatewayEnv, type GatewayDeps, type RateLimiter } from "../src/gateway.ts";

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

test("the inbound door is limited per inbound key and an over-limit post never reaches the vault", async () => {
  const limiter = new Limiter(false);
  const { d, calls, env } = mk({ INBOUND_LIMITER: limiter });
  const res = await handleGateway(at("api.consentvault.ai", PATH, { method: "POST", headers: TWILIO, body: RAW }), env, d);
  assert.equal(res.status, 429);
  assert.equal(calls.length, 0);
  assert.deepEqual(limiter.keys, [`inbound:${KEY}`]);
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

test("pages are limited per client address", async () => {
  const limiter = new Limiter(false);
  const { d, calls, env } = mk({ PAGE_LIMITER: limiter });
  const res = await handleGateway(at("consent.acme.example", "/c/stop/tok_abc-12345", { headers: { "cf-connecting-ip": "203.0.113.9" } }), env, d);
  assert.equal(res.status, 429);
  assert.equal(calls.length, 0);
  assert.deepEqual(limiter.keys, ["page:203.0.113.9"]);
});

test("a client copy of the link-host header never reaches the vault on any other route", async () => {
  const { d, calls, env } = mk();
  await handleGateway(at("api.consentvault.ai", "/v1/systems", { headers: { authorization: "Bearer abc.def", [LINK_HOST_HEADER]: "consent.acme.example" } }), env, d);
  assert.equal((calls[0].init.headers as Headers).get(LINK_HOST_HEADER), null);
});
