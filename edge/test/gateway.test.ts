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

test("a capture route forwards the body unchanged however large", async () => {
  const { d, calls } = mk(201);
  const body = "y".repeat(3 * 1024 * 1024);
  await handleGateway(r("/v1/events", { method: "POST", headers: { authorization: BEARER }, body }), ENV, d);
  assert.equal((calls[0].init.body as ArrayBuffer).byteLength, body.length);
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
