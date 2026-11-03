import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { handleCapture, MemoryRateLimiter, type CaptureEnv, type CaptureDeps } from "../src/capture.ts";
import { deliverQueued, type Durable, type QueuedMessage } from "../src/envelope.ts";

const HASH = createHash("sha256").update("wording").digest("hex");
const KEY = "cv_site_abcdefgh1234";
const NOW = new Date("2026-01-02T03:04:05.000Z");
const RECEIPT = { stored: true, post_id: "p-1", received_at: "2026-01-02T03:04:05.100000Z", body_sha256: "x", body_bytes: 1, unusual_size: false, receipt: { seq: 1 } };
const ENV: CaptureEnv = {
  SITE_KEYS: JSON.stringify({
    [KEY]: { active: true, source_id: "src-1", allowed_origins: ["https://www.acme.com"] },
    cv_site_inactive000: { active: false, source_id: "src-2", allowed_origins: ["https://www.acme.com"] },
    cv_site_lowlimit000: { active: true, source_id: "src-3", allowed_origins: ["https://www.acme.com"], rate_limit_per_minute: 1 },
  }),
  VAULT_URL: "https://vault.example.com/",
  SIGNING_SECRET: "sek",
  TURNSTILE_SECRET: "ts",
  ACCESS_CLIENT_ID: "cid",
  ACCESS_CLIENT_SECRET: "csec",
};

function good(over: Record<string, unknown> = {}) {
  return { contact: "+15555550100", checked: true, disclosure_sha256: HASH, channels: ["sms"], purposes: ["marketing"],
    page_url: "https://www.acme.com/x", session: "s1", turnstile_token: "tok", ...over };
}
function req(body: unknown, headers: Record<string, string> = {}, method = "POST", path = "/capture") {
  const init: RequestInit = {
    method,
    headers: { origin: "https://www.acme.com", "cf-connecting-ip": "203.0.113.9", "x-consentvault-site-key": KEY, ...headers },
  };
  if (method !== "GET" && method !== "OPTIONS") init.body = body instanceof Uint8Array ? body : typeof body === "string" ? body : JSON.stringify(body);
  return new Request("https://edge.example.com" + path, init);
}
type Opts = { turnstile?: unknown; turnstileStatus?: number; vaultStatus?: number; vaultThrow?: boolean; durable?: Durable; alarms?: string[] };
type Call = { url: string; init: RequestInit };
function mk(opts: Opts = {}) {
  const calls: Call[] = [];
  const d: CaptureDeps = {
    now: () => NOW,
    rateLimiter: new MemoryRateLimiter(),
    durable: opts.durable,
    alarm: (name) => opts.alarms?.push(name),
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      if (String(url).includes("siteverify")) {
        return new Response(JSON.stringify(opts.turnstile ?? { success: true, hostname: "www.acme.com" }), { status: opts.turnstileStatus ?? 200 });
      }
      if (opts.vaultThrow) throw new Error("down");
      return new Response(JSON.stringify(RECEIPT), { status: opts.vaultStatus ?? 201 });
    }) as unknown as typeof fetch,
  };
  return { d, calls };
}
const vaultCalls = (calls: Call[]) => calls.filter((c) => c.url.endsWith("/v1/events"));
type Envelope = { method: string; path: string; query: string; headers: [string, string][]; body_b64: string; body_sha256: string; body_bytes: number; edge_facts: Record<string, any> };
const envelopeOf = (call: Call) => JSON.parse(call.init.body as string) as Envelope;
const bodyOf = (call: Call) => Buffer.from(envelopeOf(call).body_b64, "base64");

class MemoryDurable implements Durable {
  bodies = new Map<string, Uint8Array>();
  messages: string[] = [];
  async putBody(key: string, body: Uint8Array) { this.bodies.set(key, body); }
  async enqueue(message: string) { this.messages.push(message); return `q-${this.messages.length}`; }
}

async function run(request: Request, opts: Opts = {}) {
  const { d, calls } = mk(opts);
  return { res: await handleCapture(request, ENV, d), calls };
}

test("a capture forwards one signed envelope holding the browser's exact bytes and answers with the vault's receipt", async () => {
  const { d, calls } = mk();
  const raw = JSON.stringify(good());
  const res = await handleCapture(req(raw), ENV, d);
  assert.equal(res.status, 201);
  assert.deepEqual(await res.json(), RECEIPT);
  assert.equal(res.headers.get("access-control-allow-origin"), "https://www.acme.com");
  const [v] = vaultCalls(calls);
  const h = v.init.headers as Record<string, string>;
  const text = v.init.body as string;
  assert.equal(h["x-consentvault-signature"], createHmac("sha256", "sek").update(`${h["x-consentvault-timestamp"]}.${text}`).digest("hex"));
  assert.equal(h["cf-access-client-id"], "cid");
  const env = envelopeOf(v);
  assert.equal(bodyOf(v).toString("utf8"), raw);
  assert.equal(env.body_sha256, createHash("sha256").update(raw).digest("hex"));
  assert.equal(env.body_bytes, Buffer.byteLength(raw));
  assert.equal(env.method, "POST");
  assert.equal(env.path, "/capture");
  assert.ok(env.headers.some(([n, val]) => n === "x-consentvault-site-key" && val === KEY));
  assert.equal(env.edge_facts.client_ip, "203.0.113.9");
  assert.equal(env.edge_facts.edge_received_at, NOW.toISOString());
  assert.equal(env.edge_facts.site_key_state, "active");
  assert.equal(env.edge_facts.origin_on_list, true);
  assert.equal(env.edge_facts.bot_check_answer.success, true);
});

const everyFormerRefusal: [string, () => Promise<{ res: Response; calls: Call[] }>, (f: Record<string, any>) => void][] = [
  ["site key missing", () => run(req(good(), { "x-consentvault-site-key": "" })), (f) => assert.equal(f.site_key_state, "missing")],
  ["site key unknown", () => run(req(good(), { "x-consentvault-site-key": "cv_site_unknown0000" })), (f) => assert.equal(f.site_key_state, "unknown")],
  ["site key inactive", () => run(req(good(), { "x-consentvault-site-key": "cv_site_inactive000" })), (f) => assert.equal(f.site_key_state, "inactive")],
  ["prototype key name", () => run(req(good(), { "x-consentvault-site-key": "cv_site___proto__" })), (f) => assert.equal(f.site_key_state, "unknown")],
  ["origin not for key", () => run(req(good(), { origin: "https://evil.com" })), (f) => assert.equal(f.origin_on_list, false)],
  ["origin missing", () => run(new Request("https://e.example.com/capture", { method: "POST", headers: { "x-consentvault-site-key": KEY, "cf-connecting-ip": "1.2.3.4" }, body: "{}" })), (f) => assert.equal(f.origin_on_list, false)],
  ["turnstile token missing", () => run(req(good({ turnstile_token: undefined }))), (f) => assert.equal(f.bot_check_answer.error, "no_token_sent")],
  ["turnstile fails", () => run(req(good()), { turnstile: { success: false } }), (f) => assert.equal(f.bot_check_answer.success, false)],
  ["turnstile hostname mismatch", () => run(req(good()), { turnstile: { success: true, hostname: "evil.com" } }), (f) => assert.equal(f.bot_check_hostname_on_list, false)],
  ["turnstile down", () => run(req(good()), { turnstileStatus: 500 }), (f) => assert.ok(f.bot_check_answer)],
  ["a body of 5 MiB", () => run(req(good({ pad: "x".repeat(5 * 1024 * 1024) }))), (f) => assert.equal(f.site_key_state, "active")],
  ["not JSON", () => run(req("this is {not json")), (f) => assert.equal(f.site_key_state, "active")],
  ["no client address", () => run(new Request("https://e.example.com/capture", { method: "POST", headers: { origin: "https://www.acme.com", "x-consentvault-site-key": KEY }, body: "{}" })), (f) => assert.equal(f.client_ip, undefined)],
  ["any other path", () => run(req(good(), {}, "POST", "/consent")), () => {}],
  ["a method that is not POST", () => run(req(null, {}, "PUT")), () => {}],
  ["a GET", () => run(req(null, {}, "GET", "/anything?x=1")), () => {}],
];
for (const [name, go, check] of everyFormerRefusal) {
  test(`what used to be refused is stored: ${name}`, async () => {
    const { res, calls } = await go();
    assert.equal(res.status, 201);
    assert.equal(((await res.json()) as { stored: boolean }).stored, true);
    const v = vaultCalls(calls);
    assert.equal(v.length, 1, "exactly one envelope reached the vault");
    check(envelopeOf(v[0]).edge_facts);
  });
}

test("the bytes are forwarded exactly, including bytes that are not text", async () => {
  const bytes = Uint8Array.from([0, 255, 254, 1, 2, 0xc3, 0x28, 123, 125]);
  const { res, calls } = await run(req(bytes, { "content-type": "application/octet-stream" }));
  assert.equal(res.status, 201);
  assert.deepEqual(Array.from(bodyOf(vaultCalls(calls)[0])), Array.from(bytes));
});

test("the box value is in the stored bytes as sent and the Worker adds none", async () => {
  for (const checked of [true, false, "true", 1, null]) {
    const { calls } = await run(req(good({ checked })));
    assert.deepEqual(JSON.parse(bodyOf(vaultCalls(calls)[0]).toString()).checked, checked);
  }
  const { calls } = await run(req(good({ checked: undefined })));
  assert.equal("checked" in JSON.parse(bodyOf(vaultCalls(calls)[0]).toString()), false);
});

test("a request over the rate limit is still stored and the fact says so", async () => {
  const { d, calls } = mk();
  const k = { "x-consentvault-site-key": "cv_site_lowlimit000" };
  assert.equal((await handleCapture(req(good(), k), ENV, d)).status, 201);
  assert.equal((await handleCapture(req(good(), k), ENV, d)).status, 201);
  const [a, b] = vaultCalls(calls).map((c) => envelopeOf(c).edge_facts.rate_count_window);
  assert.deepEqual([a.within, b.within], [true, false]);
});

test("a browser permission check is answered for any origin and stored as one", async () => {
  const { d, calls } = mk();
  const res = await handleCapture(req(null, { origin: "https://anywhere.example", "access-control-request-method": "POST", "access-control-request-headers": "content-type, x-consentvault-site-key" }, "OPTIONS"), ENV, d);
  assert.equal(res.status, 204);
  assert.equal(res.headers.get("access-control-allow-origin"), "https://anywhere.example");
  assert.equal(res.headers.get("access-control-allow-headers"), "content-type, x-consentvault-site-key");
  assert.equal(res.headers.get("vary"), "origin");
  const env = envelopeOf(vaultCalls(calls)[0]);
  assert.equal(env.method, "OPTIONS");
  assert.ok(env.headers.some(([n]) => n === "access-control-request-method"));
});

test("when the vault is down the request waits in the durable store and the browser is told with the fingerprint", async () => {
  const durable = new MemoryDurable();
  const raw = JSON.stringify(good());
  const { d } = mk({ vaultThrow: true, durable });
  const res = await handleCapture(req(raw), ENV, d);
  assert.equal(res.status, 202);
  const answer = (await res.json()) as { stored: boolean; queued: boolean; queue_id: string; body_sha256: string; body_bytes: number };
  assert.deepEqual([answer.stored, answer.queued], [false, true]);
  assert.equal(answer.body_sha256, createHash("sha256").update(raw).digest("hex"));
  assert.equal(answer.body_bytes, Buffer.byteLength(raw));
  // the queue message is small: a reference and the envelope without the body, never the body
  const message = JSON.parse(durable.messages[0]) as QueuedMessage;
  assert.ok(!("body_b64" in message.envelope));
  assert.ok(durable.messages[0].length < 4000);
  assert.equal(Buffer.from(durable.bodies.get(message.body_key)!).toString(), raw);
});

test("a queued request is delivered later with the same fingerprint and the two queue facts", async () => {
  const durable = new MemoryDurable();
  const raw = JSON.stringify(good({ checked: false }));
  const first = mk({ vaultThrow: true, durable });
  const answer = (await (await handleCapture(req(raw), ENV, first.d)).json()) as { body_sha256: string };
  const message = JSON.parse(durable.messages[0]) as QueuedMessage;
  const later = mk({ durable });
  const target = { VAULT_URL: ENV.VAULT_URL, SIGNING_SECRET: ENV.SIGNING_SECRET, ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec" };
  await deliverQueued(message, durable.bodies.get(message.body_key)!, target, { ...later.d, now: () => new Date("2026-01-02T03:09:05.000Z") });
  const env = envelopeOf(vaultCalls(later.calls)[0]);
  assert.equal(env.body_sha256, answer.body_sha256);
  assert.equal(createHash("sha256").update(bodyOf(vaultCalls(later.calls)[0])).digest("hex"), answer.body_sha256);
  assert.equal(env.edge_facts.queued_at_edge, NOW.toISOString());
  assert.equal(env.edge_facts.delivered_from_queue_at, "2026-01-02T03:09:05.000Z");
  assert.equal(env.edge_facts.edge_received_at, NOW.toISOString());
});

test("a vault answer that is not a receipt is treated as unavailable and the request is queued", async () => {
  const durable = new MemoryDurable();
  const { d } = mk({ vaultStatus: 500, durable });
  assert.equal((await handleCapture(req(good()), ENV, d)).status, 202);
  assert.equal(durable.messages.length, 1);
});

test("the vault down and no durable store says in so many words that nothing was stored, with an alarm", async () => {
  const alarms: string[] = [];
  const { d } = mk({ vaultThrow: true, alarms });
  const res = await handleCapture(req(good()), ENV, d);
  assert.equal(res.status, 503);
  assert.deepEqual(await res.json(), { stored: false, error: "store_unavailable", detail: "the record store could not be written; nothing was stored; send again" });
  assert.deepEqual(alarms, ["capture.store_unavailable"]);
});

test("a durable store that fails too is the same 503 with an alarm", async () => {
  const alarms: string[] = [];
  const broken: Durable = { putBody: async () => { throw new Error("r2 down"); }, enqueue: async () => "q" };
  const { d } = mk({ vaultThrow: true, durable: broken, alarms });
  assert.equal((await handleCapture(req(good()), ENV, d)).status, 503);
  assert.deepEqual(alarms, ["capture.store_unavailable"]);
});

test("a missing signing key cannot store and says so", async () => {
  const alarms: string[] = [];
  const { d, calls } = mk({ alarms });
  const res = await handleCapture(req(good()), { ...ENV, SIGNING_SECRET: "" }, d);
  assert.equal(res.status, 503);
  assert.equal(vaultCalls(calls).length, 0);
  assert.deepEqual(alarms, ["capture.store_unavailable"]);
});

test("the capture Workers hold no code that refuses a capture", () => {
  for (const f of ["../src/capture.ts", "../src/worker.ts", "../src/envelope.ts"]) {
    const text = readFileSync(new URL(f, import.meta.url), "utf8");
    assert.equal(/throw new Refusal\(/.test(text), false, `${f} throws a refusal`);
    assert.equal(/validateInput/.test(text), false, `${f} validates the input`);
  }
});

// ---- the Cloudflare bindings and the queue consumer ----------------------------------------------------------------------
import { deliverBatch, durableFrom, type QueueMessage } from "../src/envelope.ts";

class FakeR2 {
  objects = new Map<string, Uint8Array>();
  async put(key: string, value: Uint8Array) { this.objects.set(key, value); }
  async get(key: string) {
    const v = this.objects.get(key);
    return v ? { arrayBuffer: async () => v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength) as ArrayBuffer } : null;
  }
}
const target = { VAULT_URL: ENV.VAULT_URL, SIGNING_SECRET: ENV.SIGNING_SECRET, ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec" };

function queued(r2: FakeR2, sent: string[]) {
  return durableFrom({ BODY_STORE: r2, CAPTURE_QUEUE: { send: async (m) => { sent.push(m); } } })!;
}
function msg(body: string) {
  const log: string[] = [];
  const m: QueueMessage & { log: string[] } = { body, log, ack: () => log.push("ack"), retry: () => log.push("retry") };
  return m;
}

test("the durable store is built only when both bindings exist", () => {
  assert.equal(durableFrom({}), undefined);
  assert.equal(durableFrom({ BODY_STORE: new FakeR2() }), undefined);
  assert.ok(durableFrom({ BODY_STORE: new FakeR2(), CAPTURE_QUEUE: { send: async () => {} } }));
});

test("a request that waits in the bindings is delivered in arrival order and acknowledged", async () => {
  const r2 = new FakeR2();
  const sent: string[] = [];
  const first = mk({ vaultThrow: true, durable: queued(r2, sent) });
  await handleCapture(req(JSON.stringify(good({ session: "one" }))), ENV, first.d);
  await handleCapture(req(JSON.stringify(good({ session: "two" }))), ENV, first.d);
  assert.equal(sent.length, 2);
  assert.ok(sent.every((m) => JSON.parse(m).queue_id));
  const later = mk();
  const batch = sent.map(msg);
  await deliverBatch(batch, { BODY_STORE: r2, ...target }, later.d);
  assert.deepEqual(batch.map((m) => m.log), [["ack"], ["ack"]]);
  const order = vaultCalls(later.calls).map((c) => JSON.parse(bodyOf(c).toString()).session);
  assert.deepEqual(order, ["one", "two"]);
});

test("the first request the vault does not take stops the batch so a later one never lands before it", async () => {
  const r2 = new FakeR2();
  const sent: string[] = [];
  const first = mk({ vaultThrow: true, durable: queued(r2, sent) });
  for (const s of ["one", "two", "three"]) await handleCapture(req(JSON.stringify(good({ session: s }))), ENV, first.d);
  const down = mk({ vaultThrow: true });
  const batch = sent.map(msg);
  await deliverBatch(batch, { BODY_STORE: r2, ...target }, down.d);
  assert.deepEqual(batch.map((m) => m.log), [["retry"], ["retry"], ["retry"]]);
  assert.equal(vaultCalls(down.calls).length, 1, "only the first was tried");
});

test("a request still undelivered an hour after it was accepted raises the past-deadline alarm", async () => {
  const r2 = new FakeR2();
  const sent: string[] = [];
  const first = mk({ vaultThrow: true, durable: queued(r2, sent) });
  await handleCapture(req(JSON.stringify(good())), ENV, first.d);
  const alarms: string[] = [];
  const late = mk({ vaultThrow: true, alarms });
  await deliverBatch(sent.map(msg), { BODY_STORE: r2, ...target }, { ...late.d, now: () => new Date(NOW.getTime() + 61 * 60 * 1000) });
  assert.deepEqual(alarms, ["capture.queue_past_deadline"]);
});

test("a queued body that is missing from the store or a message that cannot be read is kept and retried loudly", async () => {
  const alarms: string[] = [];
  const d = mk({ alarms });
  const missing = msg(JSON.stringify({ body_key: "bodies/none", envelope: { edge_facts: {} }, queued_at: NOW.toISOString() }));
  await deliverBatch([missing], { BODY_STORE: new FakeR2(), ...target }, d.d);
  assert.deepEqual(missing.log, ["retry"]);
  const garbage = msg("not json");
  await deliverBatch([garbage], { BODY_STORE: new FakeR2(), ...target }, d.d);
  assert.deepEqual(garbage.log, ["retry"]);
  assert.deepEqual(alarms, ["capture.queue_unreadable"]);
});
