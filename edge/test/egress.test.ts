import test from "node:test";
import assert from "node:assert/strict";
import { handleEgress, isPublicAddress, type EgressEnv, type EgressDeps } from "../src/egress.ts";

const ENV: EgressEnv = { EGRESS_SECRET: "es", TIMEOUT_MS: "50" };
function mk(addrs: string[] = ["93.184.216.34"], status = 200, hang = false) {
  const calls: { url: string; init: RequestInit }[] = [];
  const d: EgressDeps = {
    resolve: async () => addrs,
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      if (hang) return new Promise((_, rej) => init.signal!.addEventListener("abort", () => rej(Object.assign(new Error("aborted"), { name: "AbortError" }))));
      return new Response("ok", { status });
    }) as unknown as typeof fetch,
  };
  return { d, calls };
}
const body = (over: Record<string, unknown> = {}) => ({ target_url: "https://hooks.acme.com/in", payload: '{"a":1}', headers: { "X-ConsentVault-Signature": "sig", "Idempotency-Key": "k" }, ...over });
const post = (b: unknown, auth = "Bearer es") => new Request("https://eg.example.com/push", { method: "POST", headers: { authorization: auth }, body: JSON.stringify(b) });

test("delivers and returns the receiver status", async () => {
  const { d, calls } = mk();
  const res = await handleEgress(post(body()), ENV, d);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { delivered: true, receiver_status: 200 });
  assert.equal(calls[0].init.body, '{"a":1}');
  assert.equal((calls[0].init.headers as Headers).get("x-consentvault-signature"), "sig");
});

test("receiver non-2xx is reported with its status", async () => {
  const res = await handleEgress(post(body()), ENV, mk(undefined, 503).d);
  assert.equal(res.status, 502);
  assert.deepEqual(await res.json(), { delivered: false, receiver_status: 503 });
});

const refusals: [string, Record<string, unknown>, string[] | undefined, number, string][] = [
  ["http", { target_url: "http://hooks.acme.com/in" }, undefined, 400, "target_not_https"],
  ["credentials in url", { target_url: "https://u:p@hooks.acme.com/in" }, undefined, 400, "target_has_credentials"],
  ["odd port", { target_url: "https://hooks.acme.com:8443/in" }, undefined, 400, "target_port_refused"],
  ["localhost name", { target_url: "https://localhost/in" }, undefined, 403, "target_address_refused"],
  ["loopback literal", { target_url: "https://127.0.0.1/in" }, undefined, 403, "target_address_refused"],
  ["metadata literal", { target_url: "https://169.254.169.254/latest" }, undefined, 403, "target_address_refused"],
  ["ipv6 loopback literal", { target_url: "https://[::1]/in" }, undefined, 403, "target_address_refused"],
  ["resolves private 10/8", {}, ["10.0.0.5"], 403, "target_address_refused"],
  ["resolves 192.168", {}, ["192.168.1.1"], 403, "target_address_refused"],
  ["resolves metadata", {}, ["169.254.169.254"], 403, "target_address_refused"],
  ["resolves loopback", {}, ["127.0.0.1"], 403, "target_address_refused"],
  ["one of two private", {}, ["93.184.216.34", "10.1.1.1"], 403, "target_address_refused"],
  ["ipv6 ULA", {}, ["fd00::1"], 403, "target_address_refused"],
  ["ipv4-mapped private", {}, ["::ffff:10.0.0.1"], 403, "target_address_refused"],
  ["no answer", {}, [], 502, "dns_no_answer"],
  ["bad target", { target_url: "not a url" }, undefined, 400, "bad_target"],
  ["missing payload", { payload: undefined }, undefined, 400, "bad_shape"],
  ["forbidden header", { headers: { Authorization: "x" } }, undefined, 400, "header_refused"],
];
for (const [name, over, addrs, status, code] of refusals) {
  test(`refuses: ${name}`, async () => {
    const { d, calls } = mk(addrs);
    const res = await handleEgress(post(body(over)), ENV, d);
    assert.equal(res.status, status);
    assert.equal(((await res.json()) as { error: string }).error, code);
    assert.equal(calls.length, 0);
  });
}

test("refuses an unauthorized caller", async () => {
  const res = await handleEgress(post(body(), "Bearer nope"), ENV, mk().d);
  assert.equal(res.status, 401);
});

test("DNS failure is a named error", async () => {
  const d = mk().d;
  d.resolve = async () => { throw new Error("servfail"); };
  const res = await handleEgress(post(body()), ENV, d);
  assert.equal(res.status, 502);
  assert.equal(((await res.json()) as { error: string }).error, "dns_failed");
});

test("times out", async () => {
  const res = await handleEgress(post(body()), ENV, mk(undefined, 200, true).d);
  assert.equal(res.status, 504);
  assert.equal(((await res.json()) as { error: string }).error, "receiver_timeout");
});

test("redirect is refused, not followed", async () => {
  const res = await handleEgress(post(body()), ENV, mk(undefined, 302).d);
  assert.equal(res.status, 502);
  assert.equal(((await res.json()) as { error: string }).error, "receiver_redirect");
});

test("address classifier", () => {
  for (const ip of ["0.0.0.0", "10.1.2.3", "100.64.0.1", "172.16.0.1", "172.31.255.1", "192.168.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "fc00::1", "ff02::1"]) {
    assert.equal(isPublicAddress(ip), false, ip);
  }
  for (const ip of ["93.184.216.34", "8.8.8.8", "172.32.0.1", "2606:4700:4700::1111"]) assert.equal(isPublicAddress(ip), true, ip);
});

test("every push names itself with the ConsentVault user-agent", async () => {
  const { d, calls } = mk();
  await handleEgress(post(body()), ENV, d);
  assert.equal((calls[0].init.headers as Headers).get("user-agent"), "ConsentVault/1.0 (+https://consentvault.ai)");
});
