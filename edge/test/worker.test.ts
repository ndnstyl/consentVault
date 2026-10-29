import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash } from "node:crypto";
import { handleConsent, validateInput, type Env, type Deps } from "../src/worker.ts";

const TEXT = "I agree to be contacted by example.com about my account.";
const HASH = createHash("sha256").update(TEXT).digest("hex");
const ENV: Env = {
  ALLOWED_ORIGINS: "https://www.example.com, https://example.org",
  VAULT_URL: "https://vault.example.com/",
  SIGNING_SECRET: "test-secret",
  SOURCE_ID: "unit",
};
const NOW = new Date("2026-01-02T03:04:05.000Z");

function good(over: Record<string, unknown> = {}) {
  return {
    contact: "+15555550100",
    checked: true,
    disclosure_sha256: HASH,
    channels: ["sms", "email"],
    purposes: ["marketing"],
    page_url: "https://www.example.com/signup",
    session: "s-1",
    ...over,
  };
}

function req(body: unknown, headers: Record<string, string> = {}, method = "POST", raw?: string) {
  return new Request("https://edge.example.com/consent", {
    method,
    headers: { origin: "https://www.example.com", "cf-connecting-ip": "203.0.113.9", "user-agent": "UA/1", ...headers },
    body: method === "POST" ? (raw ?? JSON.stringify(body)) : undefined,
  });
}

function deps(handler?: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const calls: { url: string; init: RequestInit }[] = [];
  const d: Deps = {
    now: () => NOW,
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      return handler ? handler(String(url), init) : new Response("{}", { status: 201 });
    }) as unknown as typeof fetch,
  };
  return { d, calls };
}

test("a checked grant is signed and forwarded", async () => {
  const { d, calls } = deps();
  const res = await handleConsent(req(good()), ENV, d);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("access-control-allow-origin"), "https://www.example.com");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://vault.example.com/v1/events");
  const h = calls[0].init.headers as Record<string, string>;
  const body = calls[0].init.body as string;
  const expected = createHmac("sha256", "test-secret").update(`${h["x-consentvault-timestamp"]}.${body}`).digest("hex");
  assert.equal(h["x-consentvault-signature"], expected);
  assert.equal(h["x-consentvault-timestamp"], String(Math.floor(NOW.getTime() / 1000)));
  const ev = JSON.parse(body);
  assert.equal(ev.event_type, "grant");
  assert.equal(ev.checked, true);
  assert.equal(ev.contact_verification, "none");
  assert.equal(ev.client_ip, "203.0.113.9");
  assert.equal(ev.user_agent, "UA/1");
  assert.equal(ev.edge_received_at, NOW.toISOString());
  assert.equal(ev.bot_check, "none");
  assert.equal(ev.disclosure_sha256, HASH);
  assert.equal(ev.source, "unit");
  assert.match(ev.payload_sha256, /^[0-9a-f]{64}$/);
});

test("payload hash covers the exact body received", async () => {
  const { d, calls } = deps();
  const raw = JSON.stringify(good());
  await handleConsent(req(null, {}, "POST", raw), ENV, d);
  const ev = JSON.parse(calls[0].init.body as string);
  assert.equal(ev.payload_sha256, createHash("sha256").update(raw).digest("hex"));
});

test("an unchecked box is refused and never forwarded", async () => {
  for (const checked of [false, "true", 1, undefined]) {
    const { d, calls } = deps();
    const res = await handleConsent(req(good({ checked })), ENV, d);
    assert.equal(res.status, 422);
    assert.equal((await res.json()).error, "unchecked");
    assert.equal(calls.length, 0);
  }
});

test("wording sent on the wire is refused and never forwarded", async () => {
  const { d, calls } = deps();
  const res = await handleConsent(req(good({ disclosure_text: TEXT })), ENV, d);
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, "disclosure_text_refused");
  assert.equal(calls.length, 0);
});

test("the forwarded event carries the hash and no wording", async () => {
  const { d, calls } = deps();
  await handleConsent(req(good()), ENV, d);
  const ev = JSON.parse(calls[0].init.body as string);
  assert.equal(ev.disclosure_sha256, HASH);
  assert.equal("disclosure_text" in ev, false);
});

test("origin not on the list is refused", async () => {
  const { d, calls } = deps();
  const res = await handleConsent(req(good(), { origin: "https://evil.example.net" }), ENV, d);
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("access-control-allow-origin"), null);
  assert.equal(calls.length, 0);
});

test("preflight answers only for allowed origins", async () => {
  const { d } = deps();
  const ok = await handleConsent(req(null, {}, "OPTIONS"), ENV, d);
  assert.equal(ok.status, 204);
  const bad = await handleConsent(req(null, { origin: "https://x.example.net" }, "OPTIONS"), ENV, d);
  assert.equal(bad.status, 403);
});

test("bad shape, bad json, bad channel, bad hash are refused", async () => {
  const { d } = deps();
  assert.equal((await handleConsent(req(null, {}, "POST", "{nope"), ENV, d)).status, 400);
  assert.equal((await handleConsent(req(good({ contact: "" })), ENV, d)).status, 400);
  assert.equal((await handleConsent(req(good({ channels: ["pigeon"] })), ENV, d)).status, 400);
  assert.equal((await handleConsent(req(good({ channels: [] })), ENV, d)).status, 400);
  assert.equal((await handleConsent(req(good({ disclosure_sha256: "abc" })), ENV, d)).status, 400);
  assert.equal((await handleConsent(req([1, 2]), ENV, d)).status, 400);
});

test("missing client ip is refused", async () => {
  const { d } = deps();
  const r = new Request("https://edge.example.com/consent", {
    method: "POST",
    headers: { origin: "https://www.example.com" },
    body: JSON.stringify(good()),
  });
  assert.equal((await handleConsent(r, ENV, d)).status, 400);
});

test("missing settings fail with a named error", async () => {
  const { d } = deps();
  const res = await handleConsent(req(good()), { ...ENV, SIGNING_SECRET: "" }, d);
  assert.equal(res.status, 500);
  assert.equal((await res.json()).error, "misconfigured");
});

test("vault refusal or outage is surfaced, never reported as recorded", async () => {
  const refused = deps(() => new Response("no", { status: 401 }));
  const r1 = await handleConsent(req(good()), ENV, refused.d);
  assert.equal(r1.status, 502);
  assert.equal((await r1.json()).recorded, false);
  const down = deps(() => {
    throw new Error("connect refused");
  });
  const r2 = await handleConsent(req(good()), ENV, down.d);
  assert.equal(r2.status, 502);
  assert.equal((await r2.json()).error, "vault_unreachable");
});

test("bot check: required when configured, recorded when it passes, refused when it fails", async () => {
  const env = { ...ENV, TURNSTILE_SECRET: "ts" };
  const none = deps();
  assert.equal((await handleConsent(req(good()), env, none.d)).status, 403);

  const pass = deps((url) =>
    url.includes("siteverify") ? new Response(JSON.stringify({ success: true })) : new Response("{}", { status: 201 }),
  );
  const ok = await handleConsent(req(good({ turnstile_token: "tok" })), env, pass.d);
  assert.equal(ok.status, 200);
  assert.equal(JSON.parse(pass.calls[1].init.body as string).bot_check, "turnstile:pass");

  const fail = deps(() => new Response(JSON.stringify({ success: false })));
  const bad = await handleConsent(req(good({ turnstile_token: "tok" })), env, fail.d);
  assert.equal(bad.status, 403);
  assert.equal(fail.calls.length, 1);
});

test("validateInput normalizes and dedupes lists", () => {
  const v = validateInput(good({ channels: ["sms", "sms", "email"] }));
  assert.deepEqual(v.channels, ["email", "sms"]);
});
