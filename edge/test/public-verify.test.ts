import test from "node:test";
import assert from "node:assert/strict";
import { handleGateway, type GatewayEnv, type GatewayDeps, type RateLimiter } from "../src/gateway.ts";

// The public read class (competitive-builds spec, Build 1): GET /p/{id}, GET /p/{id}.json, GET /p/{id}/record.zip and
// POST /p/{id}/match, served only on the configured verify host, no bearer, its own per-IP limiter, the privacy headers on
// every response, and one fixed 404 for an unknown, a malformed and a misrouted id.
const VERIFY = "verify.consentvault.ai";
const ID = "cvp_abcdefghijklmnopqrstuvwxyz";
const ORIGIN = "https://origin.example.com";
const FIXED_404 = '{"error":"not_found","message":"no such record link"}';

class Limiter implements RateLimiter {
  keys: string[] = [];
  allow: boolean;
  constructor(allow = true) { this.allow = allow; }
  async limit({ key }: { key: string }) { this.keys.push(key); return { success: this.allow }; }
}

type Answer = (url: string, init: RequestInit) => Response | Promise<Response>;
function mk(answer: Answer, env: Partial<GatewayEnv> = {}) {
  const calls: { url: string; init: RequestInit }[] = [];
  const alarms: string[] = [];
  const d: GatewayDeps = {
    fetch: (async (url: string, init: RequestInit) => { calls.push({ url: String(url), init }); return answer(String(url), init); }) as unknown as typeof fetch,
    alarm: (n) => alarms.push(n),
  };
  const full: GatewayEnv = { ORIGIN_URL: ORIGIN + "/", ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec", VERIFY_HOST: VERIFY, VERIFY_LIMITER: new Limiter(), ...env };
  return { d, calls, alarms, env: full };
}
const html = () => new Response("<html>page</html>", { status: 200, headers: { "content-type": "text/html; charset=utf-8", "set-cookie": "a=b", "cache-control": "max-age=600" } });
const originNotFound = () => new Response('{"detail":"origin words"}', { status: 404, headers: { "content-type": "application/json" } });
const at = (host: string, path: string, init: RequestInit = {}) => new Request(`https://${host}${path}`, init);

function assertPrivacyHeaders(res: Response) {
  assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(res.headers.get("x-robots-tag"), "noindex, nofollow");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  const csp = res.headers.get("content-security-policy") ?? "";
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.equal(res.headers.get("set-cookie"), null);
}

test("the page route is forwarded to the origin path with no bearer and carries every privacy header", async () => {
  const { d, calls, env } = mk(html);
  const res = await handleGateway(at(VERIFY, `/p/${ID}`, { headers: { cookie: "x=1", authorization: "Bearer abc" } }), env, d);
  assert.equal(res.status, 200);
  assert.equal(calls[0].url, `${ORIGIN}/v1/public/record-link/${ID}`);
  assert.equal(calls[0].init.method, "GET");
  const h = calls[0].init.headers as Headers;
  assert.equal(h.get("authorization"), null);
  assert.equal(h.get("cookie"), null);
  assert.equal(h.get("cf-access-client-id"), "cid");
  assertPrivacyHeaders(res);
  assert.equal(await res.text(), "<html>page</html>");
});

test("the json, zip and match routes map to the origin paths", async () => {
  const { d, calls, env } = mk(() => new Response("x", { status: 200, headers: { "content-type": "application/zip" } }));
  await handleGateway(at(VERIFY, `/p/${ID}.json`), env, d);
  await handleGateway(at(VERIFY, `/p/${ID}/record.zip`), env, d);
  await handleGateway(at(VERIFY, `/p/${ID}/match`, { method: "POST", body: '{"contact":"x"}', headers: { "content-type": "application/json" } }), env, d);
  assert.deepEqual(calls.map((c) => [c.init.method, c.url]), [
    ["GET", `${ORIGIN}/v1/public/record-link/${ID}.json`],
    ["GET", `${ORIGIN}/v1/public/record-link/${ID}/record.zip`],
    ["POST", `${ORIGIN}/v1/public/record-link/${ID}/match`],
  ]);
  assert.equal(new TextDecoder().decode(calls[2].init.body as ArrayBuffer), '{"contact":"x"}');
});

test("record.zip is always an attachment, and the origin's cookie never passes", async () => {
  const { d, env } = mk(() => new Response("zip", { status: 200, headers: { "content-type": "application/zip", "set-cookie": "s=1" } }));
  const res = await handleGateway(at(VERIFY, `/p/${ID}/record.zip`), env, d);
  assert.match(res.headers.get("content-disposition") ?? "", /^attachment/);
  assertPrivacyHeaders(res);
});

test("the origin's own CSP is kept, and frame-ancestors is added when it lacks one", async () => {
  const a = mk(() => new Response("p", { status: 200, headers: { "content-security-policy": "default-src 'none'; script-src 'sha256-AAA'; frame-ancestors 'none'" } }));
  const ra = await handleGateway(at(VERIFY, `/p/${ID}`), a.env, a.d);
  assert.match(ra.headers.get("content-security-policy")!, /script-src 'sha256-AAA'/);
  const b = mk(() => new Response("p", { status: 200, headers: { "content-security-policy": "default-src 'none'; script-src 'sha256-AAA'" } }));
  const rb = await handleGateway(at(VERIFY, `/p/${ID}`), b.env, b.d);
  assert.match(rb.headers.get("content-security-policy")!, /script-src 'sha256-AAA'/);
  assert.match(rb.headers.get("content-security-policy")!, /frame-ancestors 'none'/);
});

test("withdrawn (410) and match locked (429) pass through with the privacy headers", async () => {
  for (const status of [410, 429]) {
    const { d, env } = mk(() => new Response("gone", { status }));
    const res = await handleGateway(at(VERIFY, `/p/${ID}/match`, { method: "POST", body: "{}" }), env, d);
    assert.equal(res.status, status);
    assertPrivacyHeaders(res);
  }
});

test("an unknown id, a malformed id, a wrong method and a stray path answer one identical 404, each with one origin call", async () => {
  const { d, calls, env } = mk(originNotFound);
  const cases: [string, RequestInit][] = [
    [`/p/cvp_zzzzzzzzzzzzzzzzzzzzzzzzzz`, {}],
    [`/p/not-an-id`, {}],
    [`/p/${"a".repeat(500)}`, {}],
    [`/p/%00%ff`, {}],
    [`/p/${ID}/other`, {}],
    [`/p/${ID}/record.zip/x`, {}],
    [`/p/${ID}`, { method: "DELETE" }],
    [`/p/${ID}/match`, { method: "GET" }],
    [`/p/`, {}],
    [`/p`, {}],
  ];
  const seen = new Set<string>();
  for (const [path, init] of cases) {
    const before = calls.length;
    const res = await handleGateway(at(VERIFY, path, init), env, d);
    assert.equal(res.status, 404, path);
    assertPrivacyHeaders(res);
    seen.add(await res.text());
    assert.equal(calls.length - before, 1, `${path} made one origin call`);
  }
  assert.deepEqual([...seen], [FIXED_404]);
});

test("a stray path never forwards the visitor's text to the origin", async () => {
  const { d, calls, env } = mk(originNotFound);
  await handleGateway(at(VERIFY, `/p/..%2f..%2fv1%2fevents`), env, d);
  assert.ok(!calls[0].url.includes("events"));
  assert.ok(!calls[0].url.includes(".."));
});

test("an origin 404 for a well-formed id is replaced by the fixed body", async () => {
  const { d, env } = mk(originNotFound);
  const res = await handleGateway(at(VERIFY, `/p/${ID}`), env, d);
  assert.equal(res.status, 404);
  assert.equal(await res.text(), FIXED_404);
});

test("the routes exist only on the verify host", async () => {
  const { d, calls, env } = mk(html);
  for (const host of ["api.consentvault.ai", "evil.example.com", `${VERIFY}.evil.com`]) {
    const res = await handleGateway(at(host, `/p/${ID}`), env, d);
    assert.equal(res.status, 404, host);
    assert.equal((await res.json() as { message: string }).message, "no such route");
  }
  assert.equal(calls.length, 0);
});

test("with no verify host configured the routes do not exist anywhere", async () => {
  const { d, calls, env } = mk(html, { VERIFY_HOST: undefined });
  const res = await handleGateway(at(VERIFY, `/p/${ID}`), env, d);
  assert.equal(res.status, 404);
  assert.equal(calls.length, 0);
});

test("the verify host answers nothing but the public read class", async () => {
  const { d, calls, env } = mk(html);
  for (const path of ["/v1/records", "/v1/events", "/c/r/abcdefgh12", "/"]) {
    const res = await handleGateway(at(VERIFY, path, { headers: { authorization: "Bearer abc" } }), env, d);
    assert.equal(res.status, 404, path);
    assertPrivacyHeaders(res);
  }
  assert.equal(calls.length, 0);
});

test("the host match is case-insensitive", async () => {
  const { d, env } = mk(html);
  const res = await handleGateway(at(VERIFY.toUpperCase(), `/p/${ID}`), env, d);
  assert.equal(res.status, 200);
});

test("a per-IP rate limit answers 429 with the privacy headers and never reaches the origin", async () => {
  const limiter = new Limiter(false);
  const { d, calls, env } = mk(html, { VERIFY_LIMITER: limiter });
  const res = await handleGateway(at(VERIFY, `/p/${ID}`, { headers: { "cf-connecting-ip": "203.0.113.9" } }), env, d);
  assert.equal(res.status, 429);
  assertPrivacyHeaders(res);
  assert.deepEqual(limiter.keys, ["verify:203.0.113.9"]);
  assert.equal(calls.length, 0);
});

test("the limiter runs before the id is looked at, so bad ids are counted too", async () => {
  const limiter = new Limiter(true);
  const { d, env } = mk(originNotFound, { VERIFY_LIMITER: limiter });
  await handleGateway(at(VERIFY, `/p/nope`, { headers: { "cf-connecting-ip": "203.0.113.9" } }), env, d);
  assert.equal(limiter.keys.length, 1);
});

test("an unbound limiter raises an alarm and the page is still served", async () => {
  const { d, alarms, env } = mk(html, { VERIFY_LIMITER: undefined });
  const res = await handleGateway(at(VERIFY, `/p/${ID}`), env, d);
  assert.equal(res.status, 200);
  assert.ok(alarms.includes("public_verify.rate_limit_unbound"));
});

test("a match body over 2 KB is refused with the privacy headers", async () => {
  const { d, calls, env } = mk(html);
  const res = await handleGateway(at(VERIFY, `/p/${ID}/match`, { method: "POST", body: "x".repeat(3000) }), env, d);
  assert.equal(res.status, 413);
  assertPrivacyHeaders(res);
  assert.equal(calls.length, 0);
});

test("an origin that cannot be reached answers 502 with the privacy headers and an alarm", async () => {
  const { d, alarms, env } = mk(() => { throw new TypeError("down"); });
  const res = await handleGateway(at(VERIFY, `/p/${ID}`), env, d);
  assert.equal(res.status, 502);
  assertPrivacyHeaders(res);
  assert.ok(alarms.includes("public_verify.origin_unreachable"));
});
