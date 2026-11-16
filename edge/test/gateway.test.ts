import test from "node:test";
import assert from "node:assert/strict";
import { handleGateway, type GatewayEnv, type GatewayDeps } from "../src/gateway.ts";

const ENV: GatewayEnv = { ORIGIN_URL: "https://origin.example.com/", ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec", MAX_BODY_BYTES: "1000" };
const BEARER = "Bearer aaa.bbb.ccc";

function mk(status = 201, throwIt = false, waf?: GatewayDeps["waf"]) {
  const calls: { url: string; init: RequestInit }[] = [];
  const d: GatewayDeps = {
    waf,
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      if (throwIt) throw new Error("boom");
      return new Response('{"ok":true}', { status, headers: { "set-cookie": "a=b", "x-k": "v" } });
    }) as unknown as typeof fetch,
  };
  return { d, calls };
}
const r = (path: string, init: RequestInit = {}) => new Request("https://gw.example.com" + path, init);

test("passes the bearer through and adds the Access service token", async () => {
  const { d, calls } = mk();
  const res = await handleGateway(r("/v1/permission?x=1", { method: "POST", headers: { authorization: BEARER, "cf-access-client-id": "spoof" }, body: "{}" }), ENV, d);
  assert.equal(res.status, 201);
  assert.equal(res.headers.get("set-cookie"), null);
  assert.equal(res.headers.get("x-k"), "v");
  assert.equal(calls[0].url, "https://origin.example.com/v1/permission?x=1");
  const h = calls[0].init.headers as Headers;
  assert.equal(h.get("authorization"), BEARER);
  assert.equal(h.get("cf-access-client-id"), "cid");
  assert.equal(h.get("cf-access-client-secret"), "csec");
});

const cases: [string, () => Promise<Response>, number, string][] = [
  ["no bearer", async () => handleGateway(r("/v1/permission", { method: "POST", body: "{}" }), ENV, mk().d), 401, "bearer_missing"],
  ["basic auth", async () => handleGateway(r("/v1/permission", { method: "POST", headers: { authorization: "Basic abc" }, body: "{}" }), ENV, mk().d), 401, "bearer_malformed"],
  ["site key as bearer", async () => handleGateway(r("/v1/permission", { method: "POST", headers: { authorization: "Bearer cv_site_abcdefgh1234" }, body: "{}" }), ENV, mk().d), 401, "site_key_not_accepted"],
  ["declared oversize", async () => handleGateway(r("/v1/permission", { method: "POST", headers: { authorization: BEARER, "content-length": "5000" }, body: "x".repeat(10) }), ENV, mk().d), 413, "too_large"],
  ["actual oversize", async () => handleGateway(r("/v1/permission", { method: "POST", headers: { authorization: BEARER }, body: "x".repeat(2000) }), ENV, mk().d), 413, "too_large"],
  ["outside /v1/", async () => handleGateway(r("/admin", { headers: { authorization: BEARER } }), ENV, mk().d), 404, "not_found"],
  ["bad method", async () => handleGateway(r("/v1/permission", { method: "HEAD", headers: { authorization: BEARER } }), ENV, mk().d), 405, "method_not_allowed"],
  ["waf blocks", async () => handleGateway(r("/v1/permission", { headers: { authorization: BEARER } }), ENV, mk(201, false, async () => ({ status: 403, code: "waf_blocked", message: "blocked" })).d), 403, "waf_blocked"],
  ["origin down", async () => handleGateway(r("/v1/permission", { headers: { authorization: BEARER } }), ENV, mk(201, true).d), 502, "origin_unreachable"],
  ["missing setting", async () => handleGateway(r("/v1/permission", { headers: { authorization: BEARER } }), { ...ENV, ACCESS_CLIENT_SECRET: "" }, mk().d), 500, "misconfigured"],
];
for (const [name, run, status, code] of cases) {
  test(`refuses: ${name}`, async () => {
    const res = await run();
    assert.equal(res.status, status);
    assert.equal(((await res.json()) as { error: string }).error, code);
  });
}

test("origin non-2xx is passed through, not hidden", async () => {
  const res = await handleGateway(r("/v1/permission", { headers: { authorization: BEARER } }), ENV, mk(403).d);
  assert.equal(res.status, 403);
});

test("error bodies and console never contain the bearer or Access secret", async () => {
  const logs: string[] = [];
  const orig = [console.log, console.error, console.warn];
  console.log = console.error = console.warn = (...a: unknown[]) => { logs.push(a.join(" ")); };
  try {
    const res = await handleGateway(r("/v1/permission", { headers: { authorization: BEARER } }), ENV, mk(201, true).d);
    const text = await res.text();
    assert.equal(text.includes("aaa.bbb.ccc"), false);
    assert.equal(text.includes("csec"), false);
  } finally {
    [console.log, console.error, console.warn] = orig as never;
  }
  assert.deepEqual(logs, []);
});


// Capture routes: every request is forwarded whole and stored by the vault; what the gateway noticed is a fact header.
const facts = (calls: { init: RequestInit }[]) => JSON.parse((calls[0].init.headers as Headers).get("x-consentvault-gateway-facts")!);

test("a capture route forwards what used to be refused and records what the gateway noticed", async () => {
  const cases: [string, RequestInit, (f: Record<string, any>) => void][] = [
    ["no bearer", { method: "POST", body: "{}" }, (f) => assert.equal(f.bearer, "absent")],
    ["basic auth", { method: "POST", headers: { authorization: "Basic abc" }, body: "{}" }, (f) => assert.equal(f.bearer, "malformed")],
    ["site key as bearer", { method: "POST", headers: { authorization: "Bearer cv_site_abcdefgh1234" }, body: "{}" }, (f) => assert.equal(f.bearer, "site_key")],
    ["oversize", { method: "POST", headers: { authorization: BEARER }, body: "x".repeat(5000) }, (f) => assert.equal(f.bearer, "well_formed")],
    ["a method the gateway did not allow", { method: "OPTIONS", headers: { origin: "https://anywhere.example", "access-control-request-method": "POST" } }, (f) => assert.equal(f.method, "OPTIONS")],
  ];
  for (const [name, init, check] of cases) {
    const { d, calls } = mk(201);
    const res = await handleGateway(r("/v1/events", init), ENV, d);
    assert.equal(res.status, 201, name);
    assert.equal(calls.length, 1, name);
    check(facts(calls));
    const h = calls[0].init.headers as Headers;
    assert.equal(h.get("cf-access-client-id"), "cid");
  }
});

test("a capture route forwards a body up to 64 KiB whole and refuses a larger one with 413 before reading it", async () => {
  const { d, calls } = mk(201);
  const body = "y".repeat(64 * 1024);
  await handleGateway(r("/v1/events", { method: "POST", headers: { authorization: BEARER }, body }), ENV, d);
  assert.equal((calls[0].init.body as ArrayBuffer).byteLength, body.length);
  const big = "y".repeat(64 * 1024 + 1);
  for (const init of [
    { method: "POST", headers: { authorization: BEARER, "content-length": String(big.length) }, body: "{}" },
    { method: "POST", headers: { authorization: BEARER }, body: big },
  ]) {
    const { d: d2, calls: c2 } = mk(201);
    const res = await handleGateway(r("/v1/capture", init), ENV, d2);
    assert.equal(res.status, 413);
    assert.equal(((await res.json()) as { error: string }).error, "too_large");
    assert.equal(c2.length, 0);
  }
});

test("GET and HEAD on a capture route are refused with 405 and nothing is forwarded or stored", async () => {
  for (const path of ["/v1/events", "/v1/capture", "/v1/capture/x"]) {
    for (const method of ["GET", "HEAD"]) {
      const { d, calls } = mk(201);
      const res = await handleGateway(r(path, { method }), ENV, d);
      assert.equal(res.status, 405, `${method} ${path}`);
      assert.equal(res.headers.get("allow"), "POST, OPTIONS");
      assert.equal(calls.length, 0);
    }
  }
});

function counter(limit: number) {
  const n = new Map<string, number>();
  return { keys: n, limit: async ({ key }: { key: string }) => { n.set(key, (n.get(key) ?? 0) + 1); return { success: n.get(key)! <= limit }; } };
}

test("a client address that sends too many capture posts is refused with 429 before anything is forwarded", async () => {
  const lim = counter(2);
  const env = { ...ENV, CAPTURE_LIMITER: lim };
  const { d, calls } = mk(201);
  const post = () => handleGateway(r("/v1/events", { method: "POST", headers: { authorization: BEARER, "cf-connecting-ip": "203.0.113.70" }, body: "{}" }), env, d);
  assert.deepEqual([(await post()).status, (await post()).status, (await post()).status], [201, 201, 429]);
  assert.equal(calls.length, 2);
  const pre = await handleGateway(r("/v1/events", { method: "OPTIONS", headers: { "cf-connecting-ip": "203.0.113.70", origin: "https://a.example", "access-control-request-method": "POST" } }), env, d);
  assert.equal(pre.status, 201, "a permission check is not counted");
});

test("an address whose bearers keep failing is answered 429 after the limit, and then without asking the vault", async () => {
  const lim = counter(3);
  const env = { ...ENV, AUTH_FAIL_LIMITER: lim };
  const { d, calls } = mk(401);
  const ip = { "cf-connecting-ip": "203.0.113.71" };
  const bad = () => handleGateway(r("/v1/permission", { method: "POST", headers: { authorization: BEARER, ...ip }, body: "{}" }), env, { ...d, now: () => 1_000_000 });
  const got: number[] = [];
  for (let i = 0; i < 6; i++) got.push((await bad()).status);
  assert.deepEqual(got, [401, 401, 401, 429, 429, 429]);
  assert.equal(calls.length, 4, "after the block the vault is not asked");
  const res = await bad();
  assert.equal(res.headers.get("retry-after"), "60");
  assert.equal(((await res.json()) as { error: string }).error, "rate_limited");
  const other = await handleGateway(r("/v1/permission", { method: "POST", headers: { authorization: BEARER, "cf-connecting-ip": "203.0.113.72" }, body: "{}" }), env, { ...d, now: () => 1_000_000 });
  assert.equal(other.status, 401, "another address is not blocked");
});

test("a bearer the edge itself refuses counts as a failure, and a good answer is never counted", async () => {
  const lim = counter(100);
  const env = { ...ENV, AUTH_FAIL_LIMITER: lim };
  const ip = { "cf-connecting-ip": "203.0.113.73" };
  await handleGateway(r("/v1/permission", { method: "POST", headers: { authorization: "Basic abc", ...ip }, body: "{}" }), env, mk(201).d);
  assert.equal(lim.keys.get("authfail:203.0.113.73"), 1);
  await handleGateway(r("/v1/permission", { method: "POST", headers: { authorization: BEARER, ...ip }, body: "{}" }), env, mk(201).d);
  assert.equal(lim.keys.get("authfail:203.0.113.73"), 1);
});

test("a WAF verdict on a capture route is a fact, not a block", async () => {
  const { d, calls } = mk(201, false, async () => ({ status: 403, code: "waf_blocked", message: "blocked" }));
  const res = await handleGateway(r("/v1/events", { method: "POST", headers: { authorization: BEARER }, body: "{}" }), ENV, d);
  assert.equal(res.status, 201);
  assert.equal(facts(calls).waf.code, "waf_blocked");
});

test("an origin that does not answer a capture is reported as unknown whether stored, with the fingerprint to look up", async () => {
  const alarms: string[] = [];
  const { d } = mk(201, true);
  const res = await handleGateway(r("/v1/events", { method: "POST", headers: { authorization: BEARER }, body: "{}" }), ENV, { ...d, alarm: (n) => alarms.push(n) });
  assert.equal(res.status, 503);
  const body = (await res.json()) as { stored: string; error: string; body_sha256: string; detail: string };
  assert.equal(body.stored, "unknown");
  assert.equal(body.error, "store_unknown");
  assert.equal(body.body_sha256, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
  assert.match(body.detail, /unknown/);
  assert.match(body.detail, /recorded once/);
  assert.match((body as unknown as { request_id: string }).request_id, /^[0-9a-f-]{36}$/);
  assert.deepEqual(alarms, ["capture.store_unknown"]);
  const noSettings = await handleGateway(r("/v1/events", { method: "POST", body: "{}" }), { ...ENV, ORIGIN_URL: "" }, { ...d, alarm: (n) => alarms.push(n) });
  assert.equal(noSettings.status, 503);
});

test("POST /v1/oauth/token passes through with no bearer, and only that route", async () => {
  const { d, calls } = mk(200);
  const form = "grant_type=client_credentials&client_assertion=a.b.c";
  const res = await handleGateway(r("/v1/oauth/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form }), ENV, d);
  assert.equal(res.status, 200);
  assert.equal(calls[0].url, "https://origin.example.com/v1/oauth/token");
  assert.equal(calls[0].init.body instanceof ArrayBuffer ? new TextDecoder().decode(calls[0].init.body) : String(calls[0].init.body), form);
  assert.equal((calls[0].init.headers as Headers).get("cf-access-client-id"), "cid");
  for (const [path, method] of [["/v1/oauth/token", "GET"], ["/v1/oauth/token/x", "POST"], ["/v1/oauth/tokens", "POST"], ["/v1/permission", "POST"]] as const) {
    const o = mk(200);
    const x = await handleGateway(r(path, { method, ...(method === "POST" ? { body: "{}" } : {}) }), ENV, o.d);
    assert.equal(x.status, 401, `${method} ${path}`);
    assert.equal(o.calls.length, 0);
  }
});

test("/.well-known/security.txt answers 200 as plain text naming the contact and an expiry, on GET only", async () => {
  const { d, calls } = mk(201);
  const res = await handleGateway(r("/.well-known/security.txt"), ENV, d);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type")!, /^text\/plain/);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  const text = await res.text();
  assert.match(text, /^Contact: mailto:info@consentvault\.ai$/m);
  assert.match(text, /^Expires: 20\d\d-\d\d-\d\dT/m);
  assert.match(text, /^Canonical: https:\/\/gw\.example\.com\/\.well-known\/security\.txt$/m);
  assert.equal(calls.length, 0);
  assert.equal((await handleGateway(r("/.well-known/security.txt", { method: "POST", body: "{}" }), ENV, d)).status, 404);
});

test("every answer from the deployed gateway carries nosniff, errors included", async () => {
  const mod = await import("../src/gateway.ts");
  const res = await mod.default.fetch(r("/nowhere"), ENV);
  assert.equal(res.status, 404);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  const ok = await mod.default.fetch(r("/v1/events", { method: "GET" }), ENV);
  assert.equal(ok.status, 405);
  assert.equal(ok.headers.get("x-content-type-options"), "nosniff");
});
