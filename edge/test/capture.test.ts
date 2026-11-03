import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, createHash } from "node:crypto";
import { handleCapture, MemoryRateLimiter, type CaptureEnv, type CaptureDeps } from "../src/capture.ts";

const HASH = createHash("sha256").update("wording").digest("hex");
const KEY = "cv_site_abcdefgh1234";
const NOW = new Date("2026-01-02T03:04:05.000Z");
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
function req(body: unknown, headers: Record<string, string> = {}, method = "POST") {
  return new Request("https://edge.example.com/capture", {
    method,
    headers: { origin: "https://www.acme.com", "cf-connecting-ip": "203.0.113.9", "x-consentvault-site-key": KEY, ...headers },
    body: method === "POST" ? JSON.stringify(body) : undefined,
  });
}
function mk(opts: { turnstile?: unknown; turnstileStatus?: number; vaultStatus?: number; vaultThrow?: boolean } = {}) {
  const calls: { url: string; init: RequestInit }[] = [];
  const d: CaptureDeps = {
    now: () => NOW,
    rateLimiter: new MemoryRateLimiter(),
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      if (String(url).includes("siteverify")) {
        return new Response(JSON.stringify(opts.turnstile ?? { success: true, hostname: "www.acme.com" }), { status: opts.turnstileStatus ?? 200 });
      }
      if (opts.vaultThrow) throw new Error("down");
      return new Response("{}", { status: opts.vaultStatus ?? 201 });
    }) as unknown as typeof fetch,
  };
  return { d, calls };
}
async function err(res: Response) { return (await res.json()) as { error: string; recorded: boolean }; }

test("good capture is signed, carries Access token and source from the site key", async () => {
  const { d, calls } = mk();
  const res = await handleCapture(req(good()), ENV, d);
  assert.equal(res.status, 200);
  const v = calls.find((c) => c.url.endsWith("/v1/events"))!;
  const h = v.init.headers as Record<string, string>;
  const body = v.init.body as string;
  assert.equal(h["x-consentvault-signature"], createHmac("sha256", "sek").update(`${h["x-consentvault-timestamp"]}.${body}`).digest("hex"));
  assert.equal(h["cf-access-client-id"], "cid");
  const ev = JSON.parse(body);
  assert.equal(ev.source_id, "src-1");
  assert.equal(ev.bot_check, "turnstile:pass");
  assert.equal(ev.org_id, undefined);
});

const refusals: [string, () => Promise<Response>, number, string][] = [
  ["site key missing", async () => handleCapture(req(good(), { "x-consentvault-site-key": "" }), ENV, mk().d), 401, "site_key_missing"],
  ["site key unknown", async () => handleCapture(req(good(), { "x-consentvault-site-key": "cv_site_unknown0000" }), ENV, mk().d), 403, "site_key_unknown"],
  ["site key inactive", async () => handleCapture(req(good(), { "x-consentvault-site-key": "cv_site_inactive000" }), ENV, mk().d), 403, "site_key_inactive"],
  ["prototype key name", async () => handleCapture(req(good(), { "x-consentvault-site-key": "cv_site___proto__" }), ENV, mk().d), 403, "site_key_unknown"],
  ["origin not for key", async () => handleCapture(req(good(), { origin: "https://evil.com" }), ENV, mk().d), 403, "origin_refused"],
  ["origin missing", async () => handleCapture(new Request("https://e.example.com/capture", { method: "POST", headers: { "x-consentvault-site-key": KEY, "cf-connecting-ip": "1.2.3.4" }, body: "{}" }), ENV, mk().d), 403, "origin_refused"],
  ["turnstile token missing", async () => handleCapture(req(good({ turnstile_token: undefined })), ENV, mk().d), 403, "bot_check_missing"],
  ["turnstile fails", async () => handleCapture(req(good()), ENV, mk({ turnstile: { success: false } }).d), 403, "bot_check_failed"],
  ["turnstile hostname mismatch", async () => handleCapture(req(good()), ENV, mk({ turnstile: { success: true, hostname: "evil.com" } }).d), 403, "bot_check_hostname_mismatch"],
  ["turnstile hostname absent", async () => handleCapture(req(good()), ENV, mk({ turnstile: { success: true } }).d), 403, "bot_check_hostname_missing"],
  ["turnstile down", async () => handleCapture(req(good()), ENV, mk({ turnstileStatus: 500 }).d), 502, "bot_check_unreachable"],
  ["vault refuses", async () => handleCapture(req(good()), ENV, mk({ vaultStatus: 403 }).d), 502, "vault_refused"],
  ["vault unreachable", async () => handleCapture(req(good()), ENV, mk({ vaultThrow: true }).d), 502, "vault_unreachable"],
  ["oversize", async () => handleCapture(req(good({ pad: "x".repeat(20000) })), ENV, mk().d), 413, "too_large"],
  ["wrong method", async () => handleCapture(req(null, {}, "GET"), ENV, mk().d), 405, "method_not_allowed"],
  ["missing secret", async () => handleCapture(req(good()), { ...ENV, SIGNING_SECRET: "" }, mk().d), 500, "misconfigured"],
];
for (const [name, run, status, code] of refusals) {
  test(`refuses: ${name}`, async () => {
    const res = await run();
    assert.equal(res.status, status);
    const b = await err(res);
    assert.equal(b.error, code);
    assert.equal(b.recorded, false);
  });
}

test("the box value is forwarded exactly as sent, never set by the Worker", async () => {
  for (const checked of [true, false, "true", 1, null]) {
    const { d, calls } = mk();
    const res = await handleCapture(req(good({ checked })), ENV, d);
    assert.equal(res.status, 200);
    const v = calls.find((c) => c.url.endsWith("/v1/events"))!;
    assert.deepEqual(JSON.parse(v.init.body as string).checked, checked);
    assert.equal((v.init.headers as Record<string, string>)["x-consentvault-flags"], undefined);
  }
});

test("a post with no box field is forwarded without one and flagged, never defaulted to true", async () => {
  const { d, calls } = mk();
  const res = await handleCapture(req(good({ checked: undefined })), ENV, d);
  assert.equal(res.status, 200);
  const v = calls.find((c) => c.url.endsWith("/v1/events"))!;
  assert.equal("checked" in JSON.parse(v.init.body as string), false);
  assert.equal((v.init.headers as Record<string, string>)["x-consentvault-flags"], "box_missing");
});

test("refused requests never reach the vault", async () => {
  const { d, calls } = mk({ turnstile: { success: false } });
  await handleCapture(req(good()), ENV, d);
  assert.equal(calls.some((c) => c.url.endsWith("/v1/events")), false);
});

test("rate limit is per site key", async () => {
  const { d } = mk();
  const k = { "x-consentvault-site-key": "cv_site_lowlimit000" };
  assert.equal((await handleCapture(req(good(), k), ENV, d)).status, 200);
  const second = await handleCapture(req(good(), k), ENV, d);
  assert.equal(second.status, 429);
  assert.equal((await err(second)).error, "rate_limited");
  assert.equal((await handleCapture(req(good()), ENV, d)).status, 200);
});

test("preflight only for an origin some active key allows", async () => {
  const { d } = mk();
  assert.equal((await handleCapture(req(null, {}, "OPTIONS"), ENV, d)).status, 204);
  assert.equal((await handleCapture(req(null, { origin: "https://evil.com" }, "OPTIONS"), ENV, d)).status, 403);
});
