import test from "node:test";
import assert from "node:assert/strict";
import { handleEgress, type EgressEnv, type EgressDeps } from "../src/egress.ts";

// POST /call (the Twenty connector, twenty.md 9): the same door as /push (https, public address, port 443, no redirects, one
// timeout) for a JSON API: GET, POST, PATCH or DELETE, three forwardable headers, and the receiver's status, its rate-limit
// headers and its JSON body (at most 256 KB) handed back. Nothing of the body is logged.
const ENV: EgressEnv = { EGRESS_SECRET: "es", TIMEOUT_MS: "50" };
function mk(answer: () => Response = () => new Response('{"data":{"people":[]}}', { status: 200, headers: { "retry-after": "3", "x-ratelimit-remaining": "79", "set-cookie": "x" } }), addrs = ["93.184.216.34"], hang = false) {
  const calls: { url: string; init: RequestInit }[] = [];
  const d: EgressDeps = {
    resolve: async () => addrs,
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      if (hang) return new Promise((_, rej) => init.signal!.addEventListener("abort", () => rej(Object.assign(new Error("aborted"), { name: "AbortError" }))));
      return answer();
    }) as unknown as typeof fetch,
  };
  return { d, calls };
}
const call = (b: unknown, auth = "Bearer es") => new Request("https://eg.example.com/call", { method: "POST", headers: { authorization: auth }, body: JSON.stringify(b) });
const body = (over: Record<string, unknown> = {}) => ({ target_url: "https://crm.example.com/rest/people?limit=1", method: "GET", headers: { Authorization: "Bearer k", Accept: "application/json" }, ...over });

test("a GET returns the receiver's status, rate-limit headers and JSON body", async () => {
  const { d, calls } = mk();
  const res = await handleEgress(call(body()), ENV, d);
  assert.equal(res.status, 200);
  const out = await res.json();
  assert.deepEqual(out, { receiver_status: 200, receiver_headers: { "retry-after": "3", "x-ratelimit-remaining": "79" }, receiver_body: { data: { people: [] } } });
  assert.equal(calls[0].init.method, "GET");
  assert.equal(calls[0].init.body, undefined);
  assert.equal((calls[0].init.headers as Headers).get("authorization"), "Bearer k");
  assert.equal(calls[0].init.redirect, "manual");
});

test("a PATCH sends the JSON payload; a receiver error status is still the receiver's answer", async () => {
  const { d, calls } = mk(() => new Response('{"error":"bad"}', { status: 404 }));
  const res = await handleEgress(call(body({ method: "PATCH", payload: { cvStatusSms: "denied" } })), ENV, d);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { receiver_status: 404, receiver_headers: {}, receiver_body: { error: "bad" } });
  assert.equal(calls[0].init.body, '{"cvStatusSms":"denied"}');
  assert.equal((calls[0].init.headers as Headers).get("content-type"), "application/json");
});

const refused: [string, Record<string, unknown>, number, string][] = [
  ["another method", { method: "PUT" }, 400, "method_refused"],
  ["a cookie header", { headers: { Cookie: "a" } }, 400, "header_refused"],
  ["http", { target_url: "http://crm.example.com/rest/people" }, 400, "target_not_https"],
  ["private address", {}, 403, "target_address_refused"],
];
for (const [name, over, status, code] of refused) {
  test(`refuses ${name}`, async () => {
    const res = await handleEgress(call(body(over)), ENV, mk(undefined, name === "private address" ? ["10.0.0.5"] : undefined).d);
    assert.equal(res.status, status);
    assert.equal((await res.json()).error, code);
  });
}

test("a redirect is not followed", async () => {
  const res = await handleEgress(call(body()), ENV, mk(() => new Response("", { status: 302, headers: { location: "https://elsewhere.example.com/" } })).d);
  assert.equal(res.status, 502);
  assert.equal((await res.json()).error, "receiver_redirect");
});

test("a body that is not JSON comes back as no body, and one over 256 KB is refused", async () => {
  let res = await handleEgress(call(body()), ENV, mk(() => new Response("<html>", { status: 500 })).d);
  assert.deepEqual(await res.json(), { receiver_status: 500, receiver_headers: {}, receiver_body: null });
  res = await handleEgress(call(body()), ENV, mk(() => new Response(JSON.stringify({ x: "a".repeat(300 * 1024) }), { status: 200 })).d);
  assert.equal(res.status, 502);
  assert.equal((await res.json()).error, "receiver_body_too_large");
});

test("the timeout is the door's and the caller must hold the door secret", async () => {
  let res = await handleEgress(call(body()), ENV, mk(undefined, undefined, true).d);
  assert.equal(res.status, 504);
  assert.equal((await res.json()).error, "receiver_timeout");
  res = await handleEgress(call(body(), "Bearer nope"), ENV, mk().d);
  assert.equal(res.status, 401);
});

test("every call names itself: a receiver's firewall refuses a request with no or a library user-agent", async () => {
  const { d, calls } = mk();
  await handleEgress(call(body()), ENV, d);
  assert.equal((calls[0].init.headers as Headers).get("user-agent"), "ConsentVault/1.0 (+https://consentvault.ai)");
});
