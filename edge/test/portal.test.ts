import test from "node:test";
import assert from "node:assert/strict";
import { handlePortal, type PortalEnv } from "../src/portal.ts";
import crypto from "node:crypto";
const JWK = JSON.stringify({ ...crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }), kid: "e" });
import { AUTH_ENV_BASE, NOW_MS, memKV } from "./support/portal.ts";

function mk() {
  const seen: string[] = [];
  const env: PortalEnv = {
    ORIGIN_URL: "https://origin.example.com", ACCESS_CLIENT_ID: "cid", ACCESS_CLIENT_SECRET: "csec", ...AUTH_ENV_BASE, SESSIONS: memKV(), ASSERTION_KEY_JWK: JWK,
    ASSETS: { fetch: async (r: Request) => { seen.push("assets " + new URL(r.url).pathname); return new Response("<html>", { status: 200 }); } },
  };
  const deps = { now: () => NOW_MS, fetch: (async (u: string) => { seen.push("origin " + new URL(String(u)).pathname); return new Response("{}", { status: 200 }); }) as unknown as typeof fetch };
  return { env, deps, seen };
}
const req = (p: string, init: RequestInit = {}) => new Request("https://app.example.com" + p, init);

test("the portal Worker sends /auth to sign-in, /v1 to the gateway, and every other path to the static dashboard", async () => {
  const m = mk();
  const login = await handlePortal(req("/auth/login"), m.env, m.deps);
  assert.equal(login.status, 302);
  assert.equal((await handlePortal(req("/v1/session"), m.env, m.deps)).status, 401); // no cookie, no bearer
  assert.equal((await handlePortal(req("/brands"), m.env, m.deps)).status, 200);
  assert.equal((await handlePortal(req("/auth/callback?return=%2F"), m.env, m.deps)).status, 200); // the portal's own page
  assert.deepEqual(m.seen, ["assets /brands", "assets /auth/callback"]);
});

test("a missing static host is a named error, not a blank page", async () => {
  const m = mk();
  const res = await handlePortal(req("/brands"), { ...m.env, ASSETS: undefined as never }, m.deps);
  assert.equal(res.status, 500);
});
