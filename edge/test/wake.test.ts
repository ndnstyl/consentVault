import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { callWake, WAKE_BODY } from "../src/wake.ts";

const URL_ = "https://wake.example.test/";
const KEY = "test-only-wake-key";
const NOW = Date.UTC(2026, 10, 10, 12, 0, 0);

test("a wake call is a signed POST whose signature covers the timestamp and the exact body", async () => {
  let seen: { url: string; init: RequestInit } | null = null;
  const f = (async (url: string, init: RequestInit) => {
    seen = { url, init };
    return new Response(JSON.stringify({ services: { vault: { desired: 1, running: 0 } } }), { status: 200 });
  }) as unknown as typeof fetch;
  const r = await callWake({ CV_WAKE_URL: URL_, CV_WAKE_KEY: KEY }, f, NOW);
  assert.equal(r.ok, true);
  assert.equal(seen!.url, URL_);
  assert.equal(seen!.init.method, "POST");
  assert.equal(seen!.init.body, WAKE_BODY);
  assert.equal(WAKE_BODY, '{"action":"wake"}');
  const h = seen!.init.headers as Record<string, string>;
  assert.equal(h["x-cv-timestamp"], String(Math.floor(NOW / 1000)));
  const expect = crypto.createHmac("sha256", KEY).update(`${h["x-cv-timestamp"]}.${WAKE_BODY}`).digest("hex");
  assert.equal(h["x-cv-signature"], expect);
  assert.ok(!JSON.stringify(r).includes(KEY), "the key is never in the result");
});

test("a missing setting is a named failure and nothing is sent", async () => {
  let called = false;
  const f = (async () => { called = true; return new Response("{}"); }) as unknown as typeof fetch;
  const r = await callWake({ CV_WAKE_URL: URL_ }, f, NOW);
  assert.deepEqual(r, { ok: false, reason: "CV_WAKE_KEY is not set" });
  assert.equal((await callWake({ CV_WAKE_KEY: KEY }, f, NOW)).ok, false);
  assert.equal(called, false);
});

test("a refusal, a server error and a network error each come back as a named failure, never a throw", async () => {
  const mk = (res: () => Promise<Response>) => (async () => res()) as unknown as typeof fetch;
  const env = { CV_WAKE_URL: URL_, CV_WAKE_KEY: KEY };
  const a = await callWake(env, mk(async () => new Response('{"error":"unauthorized"}', { status: 401 })), NOW);
  assert.equal(a.ok, false); assert.match((a as { reason: string }).reason, /http 401/);
  const b = await callWake(env, mk(async () => new Response('{"error":"x"}', { status: 502 })), NOW);
  assert.match((b as { reason: string }).reason, /http 502/);
  const c = await callWake(env, mk(async () => { throw new TypeError("network down"); }), NOW);
  assert.match((c as { reason: string }).reason, /unreachable/);
});

test("a 200 whose body is not the wake answer is a failure", async () => {
  const f = (async () => new Response("<html>", { status: 200 })) as unknown as typeof fetch;
  const r = await callWake({ CV_WAKE_URL: URL_, CV_WAKE_KEY: KEY }, f, NOW);
  assert.equal(r.ok, false);
});
