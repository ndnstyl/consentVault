import test from "node:test";
import assert from "node:assert/strict";
import { handleGateway, type GatewayEnv, type GatewayDeps } from "../src/gateway.ts";

// Stripe's live webhook: admitted without a bearer (the Stripe-Signature over the raw body is the credential), the raw body bytes
// and the Stripe-Signature header passed through untouched, any bearer or cookie dropped; every other path stays refused.
const ENV: GatewayEnv = { ORIGIN_URL: "https://origin.example.com/", ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec", MAX_BODY_BYTES: "1000000" };
function mk() {
  const calls: { url: string; init: RequestInit }[] = [];
  const d: GatewayDeps = {
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response('{"ok":true}', { status: 200 });
    }) as unknown as typeof fetch,
  };
  return { d, calls };
}
const PATH = "/v1/billing/webhook";
const SIG = "t=1793452584,v1=" + "ab".repeat(32);
const r = (path: string, init: RequestInit = {}) => new Request("https://api.example.com" + path, init);

test("the Stripe webhook is admitted with no bearer and the body bytes arrive unmodified", async () => {
  const { d, calls } = mk();
  const bytes = new Uint8Array([123, 34, 97, 34, 58, 32, 49, 44, 10, 32, 32, 34, 98, 34, 58, 34, 0xc3, 0xa9, 34, 125, 0x00, 0xff]);
  const res = await handleGateway(r(PATH, { method: "POST", headers: { "stripe-signature": SIG, authorization: "Bearer other", cookie: "cv=x" }, body: bytes }), ENV, d);
  assert.equal(res.status, 200);
  assert.deepEqual(new Uint8Array(calls[0].init.body as ArrayBuffer), bytes);
  const h = calls[0].init.headers as Headers;
  assert.equal(h.get("stripe-signature"), SIG);
  assert.equal(h.get("authorization"), null);
  assert.equal(h.get("cookie"), null);
  assert.equal(h.get("cf-access-client-id"), "cid");
  assert.equal(calls[0].url, "https://origin.example.com/v1/billing/webhook");
});

test("only POST to the exact Stripe path is admitted without a bearer", async () => {
  for (const [method, path] of [["GET", PATH], ["PUT", PATH], ["POST", PATH + "/x"], ["POST", "/v1/billing/webhooks"], ["POST", "/v1/billing/portal"], ["POST", "/v1/events"], ["POST", "/v1/permission"]]) {
    const { d, calls } = mk();
    const res = await handleGateway(r(path, { method, headers: { "stripe-signature": SIG }, body: method === "GET" ? undefined : "{}" }), ENV, d);
    assert.ok(res.status === 401 || res.status === 405, `${method} ${path} -> ${res.status}`);
    assert.equal(calls.length, 0, `${method} ${path} reached the origin`);
  }
});

test("the Stripe path takes the 256 KB cap", async () => {
  const res = await handleGateway(r(PATH, { method: "POST", headers: { "stripe-signature": SIG }, body: "x".repeat(256 * 1024 + 1) }), ENV, mk().d);
  assert.equal(res.status, 413);
});
