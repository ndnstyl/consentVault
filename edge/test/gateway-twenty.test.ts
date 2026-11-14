import test from "node:test";
import assert from "node:assert/strict";
import { handleGateway, type GatewayEnv, type GatewayDeps } from "../src/gateway.ts";

// The Twenty receiver path (twenty.md 3.1): admitted without a bearer (the signature over the raw body is the credential), the
// raw body bytes and the two X-Twenty-Webhook headers passed through untouched, a 256 KB cap, any bearer or cookie dropped.
const ENV: GatewayEnv = { ORIGIN_URL: "https://origin.example.com/", ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec", MAX_BODY_BYTES: "1000000" };
function mk() {
  const calls: { url: string; init: RequestInit }[] = [];
  const d: GatewayDeps = {
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response('{"ok":true}', { status: 202 });
    }) as unknown as typeof fetch,
  };
  return { d, calls };
}
const PATH = "/v1/connectors/twenty/AbC_dEf-123/webhook";
const RAW = '{"eventName":"person.updated", "record":{"id":"p"}}';
const r = (path: string, init: RequestInit = {}) => new Request("https://api.example.com" + path, init);
const hdrs = { "x-twenty-webhook-timestamp": "1793452584000", "x-twenty-webhook-signature": "ab".repeat(32), "x-twenty-webhook-nonce": "n" };

test("a webhook is admitted with no bearer and reaches the origin byte for byte with its headers", async () => {
  const { d, calls } = mk();
  const res = await handleGateway(r(PATH, { method: "POST", headers: { ...hdrs, authorization: "Bearer someone-elses", cookie: "cv=x" }, body: RAW }), ENV, d);
  assert.equal(res.status, 202);
  assert.equal(new TextDecoder().decode(calls[0].init.body as ArrayBuffer), RAW);
  const h = calls[0].init.headers as Headers;
  assert.equal(h.get("x-twenty-webhook-timestamp"), "1793452584000");
  assert.equal(h.get("x-twenty-webhook-signature"), "ab".repeat(32));
  assert.equal(h.get("authorization"), null);
  assert.equal(h.get("cookie"), null);
  assert.equal(h.get("cf-access-client-id"), "cid");
});

test("the body cap on the webhook path is 256 KB whatever the general cap", async () => {
  const res = await handleGateway(r(PATH, { method: "POST", headers: hdrs, body: "x".repeat(256 * 1024 + 1) }), ENV, mk().d);
  assert.equal(res.status, 413);
});

test("only POST to the exact receiver path is admitted without a bearer", async () => {
  for (const [method, path] of [["GET", PATH], ["POST", PATH + "/x"], ["POST", "/v1/connectors/twenty/a/b/webhook"], ["POST", "/v1/connectors/other/a/webhook"]]) {
    const res = await handleGateway(r(path, { method, headers: hdrs, body: method === "GET" ? undefined : RAW }), ENV, mk().d);
    assert.equal(res.status, 401, `${method} ${path}`);
  }
});
