import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash } from "node:crypto";
import { handleConsent, type Env, type Deps } from "../src/worker.ts";
import type { Durable } from "../src/envelope.ts";

const TEXT = "I agree to be contacted by example.com about my account.";
const HASH = createHash("sha256").update(TEXT).digest("hex");
const ENV: Env = {
  ALLOWED_ORIGINS: "https://www.example.com, https://example.org",
  VAULT_URL: "https://vault.example.com/",
  SIGNING_SECRET: "test-key",
  SOURCE_ID: "unit",
};
const NOW = new Date("2026-01-02T03:04:05.000Z");
const RECEIPT = { stored: true, post_id: "p", receipt: { seq: 1 } };

function good(over: Record<string, unknown> = {}) {
  return { contact: "+15555550100", checked: true, disclosure_sha256: HASH, channels: ["sms", "email"], purposes: ["marketing"],
    page_url: "https://www.example.com/signup", session: "s-1", ...over };
}
function req(body: unknown, headers: Record<string, string> = {}, method = "POST", raw?: string, path = "/consent") {
  return new Request("https://edge.example.com" + path, {
    method,
    headers: { origin: "https://www.example.com", "cf-connecting-ip": "203.0.113.9", "user-agent": "UA/1", ...headers },
    body: method === "POST" || method === "PUT" ? (raw ?? JSON.stringify(body)) : undefined,
  });
}
type Call = { url: string; init: RequestInit };
function deps(handler?: (url: string, init: RequestInit) => Response | Promise<Response>, extra: Partial<Deps> = {}) {
  const calls: Call[] = [];
  const d: Deps = {
    now: () => NOW,
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      return handler ? handler(String(url), init) : new Response(JSON.stringify(RECEIPT), { status: 201 });
    }) as unknown as typeof fetch,
    ...extra,
  };
  return { d, calls };
}
const envelopeOf = (c: Call) => JSON.parse(c.init.body as string) as { method: string; path: string; headers: [string, string][]; body_b64: string; body_sha256: string; edge_facts: Record<string, any> };

test("a consent post is forwarded whole in one signed envelope and answered with the receipt", async () => {
  const { d, calls } = deps();
  const raw = JSON.stringify(good());
  const res = await handleConsent(req(null, {}, "POST", raw), ENV, d);
  assert.equal(res.status, 201);
  assert.deepEqual(await res.json(), RECEIPT);
  assert.equal(res.headers.get("access-control-allow-origin"), "https://www.example.com");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://vault.example.com/v1/events");
  const h = calls[0].init.headers as Record<string, string>;
  const text = calls[0].init.body as string;
  assert.equal(h["x-consentvault-signature"], createHmac("sha256", "test-key").update(`${h["x-consentvault-timestamp"]}.${text}`).digest("hex"));
  assert.equal(h["x-consentvault-timestamp"], String(Math.floor(NOW.getTime() / 1000)));
  const env = envelopeOf(calls[0]);
  assert.equal(Buffer.from(env.body_b64, "base64").toString(), raw);
  assert.equal(env.body_sha256, createHash("sha256").update(raw).digest("hex"));
  assert.equal(env.edge_facts.client_ip, "203.0.113.9");
  assert.equal(env.edge_facts.edge_received_at, NOW.toISOString());
  assert.equal(env.edge_facts.source_label, "unit");
  assert.equal(env.edge_facts.origin_on_list, true);
  assert.ok(env.headers.some(([n, v]) => n === "user-agent" && v === "UA/1"));
});

test("the Worker sets no box value and adds no field to what the browser sent", async () => {
  for (const checked of [true, false, "on", 0, null]) {
    const { d, calls } = deps();
    await handleConsent(req(good({ checked })), ENV, d);
    assert.deepEqual(JSON.parse(Buffer.from(envelopeOf(calls[0]).body_b64, "base64").toString()).checked, checked);
  }
  const { d, calls } = deps();
  await handleConsent(req(good({ checked: undefined })), ENV, d);
  assert.equal("checked" in JSON.parse(Buffer.from(envelopeOf(calls[0]).body_b64, "base64").toString()), false);
});

test("a post the old Worker refused is stored: wording text, a bad hash, a bad channel, a list, text that is not JSON", async () => {
  for (const raw of [JSON.stringify(good({ disclosure_text: TEXT })), JSON.stringify(good({ disclosure_sha256: "abc" })),
    JSON.stringify(good({ channels: ["pigeon"] })), "[1,2]", "not json at all", "", JSON.stringify(good({ contact: " " }))]) {
    const { d, calls } = deps();
    const res = await handleConsent(req(null, {}, "POST", raw), ENV, d);
    assert.equal(res.status, 201, raw);
    assert.equal(Buffer.from(envelopeOf(calls[0]).body_b64, "base64").toString(), raw);
  }
});

test("an origin that is not on the list, a missing client address, any path and any method are stored with the facts", async () => {
  const cases: [Request, (f: Record<string, any>) => void][] = [
    [req(good(), { origin: "https://evil.com" }), (f) => assert.equal(f.origin_on_list, false)],
    [new Request("https://edge.example.com/consent", { method: "POST", body: JSON.stringify(good()) }), (f) => assert.equal(f.client_ip, undefined)],
    [req(good(), {}, "POST", undefined, "/somewhere/else"), () => {}],
    [req(good(), {}, "PUT"), () => {}],
    [req(null, {}, "GET"), () => {}],
  ];
  for (const [r, check] of cases) {
    const { d, calls } = deps();
    assert.equal((await handleConsent(r, ENV, d)).status, 201);
    assert.equal(calls.length, 1);
    check(envelopeOf(calls[0]).edge_facts);
  }
});

test("a permission check is answered 204 for any origin and stored", async () => {
  const { d, calls } = deps();
  const res = await handleConsent(req(null, { origin: "https://other.example", "access-control-request-method": "POST" }, "OPTIONS"), ENV, d);
  assert.equal(res.status, 204);
  assert.equal(res.headers.get("access-control-allow-origin"), "https://other.example");
  assert.equal(envelopeOf(calls[0]).method, "OPTIONS");
});

test("a missing setting cannot store and says so", async () => {
  const alarms: string[] = [];
  const { d, calls } = deps(undefined, { alarm: (n) => alarms.push(n) });
  const res = await handleConsent(req(good()), { ...ENV, SIGNING_SECRET: "" }, d);
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error, "store_unavailable");
  assert.equal(calls.length, 0);
  assert.deepEqual(alarms, ["capture.store_unavailable"]);
});

test("a vault that is down queues the request when the edge has a durable store, and says nothing was stored when it has none", async () => {
  const bodies = new Map<string, Uint8Array>();
  const messages: string[] = [];
  const durable: Durable = { putBody: async (k, b) => { bodies.set(k, b); }, enqueue: async (m) => { messages.push(m); return "q-1"; } };
  const down = deps(() => { throw new Error("connect refused"); }, { durable });
  const queued = await handleConsent(req(good()), ENV, down.d);
  assert.equal(queued.status, 202);
  const q = await queued.json();
  assert.deepEqual([q.stored, q.queued, q.queue_id], [false, true, "q-1"]);
  assert.equal(bodies.size, 1);

  const alarms: string[] = [];
  const none = deps(() => new Response("no", { status: 401 }), { alarm: (n) => alarms.push(n) });
  const lost = await handleConsent(req(good()), ENV, none.d);
  assert.equal(lost.status, 503);
  assert.equal((await lost.json()).stored, false);
  assert.deepEqual(alarms, ["capture.store_unavailable"]);
});

test("bot check: the provider's answer is a fact exactly as given, and a failed or missing check changes nothing", async () => {
  const env = { ...ENV, TURNSTILE_SECRET: "ts" };
  const pass = deps((url) => (url.includes("siteverify") ? new Response(JSON.stringify({ success: true, hostname: "www.example.com", action: "x" })) : new Response(JSON.stringify(RECEIPT), { status: 201 })));
  assert.equal((await handleConsent(req(good({ turnstile_token: "tok" })), env, pass.d)).status, 201);
  assert.deepEqual(envelopeOf(pass.calls[1]).edge_facts.bot_check_answer, { success: true, hostname: "www.example.com", action: "x" });
  const fail = deps((url) => (url.includes("siteverify") ? new Response(JSON.stringify({ success: false, "error-codes": ["invalid-input-response"] })) : new Response(JSON.stringify(RECEIPT), { status: 201 })));
  assert.equal((await handleConsent(req(good({ turnstile_token: "tok" })), env, fail.d)).status, 201);
  assert.equal(envelopeOf(fail.calls[1]).edge_facts.bot_check_answer.success, false);
  const none = deps();
  assert.equal((await handleConsent(req(good()), env, none.d)).status, 201);
  assert.equal(envelopeOf(none.calls[0]).edge_facts.bot_check_answer.error, "no_token_sent");
});
