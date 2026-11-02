// Fakes for the portal edge tests: an in-memory session store and an unsigned JWT maker (the edge reads only exp and
// sid from a token, never trusts it; the vault verifies the signature).

import type { KV } from "../../src/session.ts";

export function memKV(): KV & { data: Map<string, string>; ttl: Map<string, number | undefined> } {
  const data = new Map<string, string>();
  const ttl = new Map<string, number | undefined>();
  return {
    data,
    ttl,
    async get(k) { return data.get(k) ?? null; },
    async put(k, v, o) { data.set(k, v); ttl.set(k, o?.expirationTtl); },
    async delete(k) { data.delete(k); ttl.delete(k); },
  };
}

const b64u = (s: string) => Buffer.from(s).toString("base64url");
export function jwt(claims: Record<string, unknown>): string {
  return `${b64u(JSON.stringify({ alg: "none" }))}.${b64u(JSON.stringify(claims))}.sig`;
}

export const NOW_MS = Date.UTC(2026, 9, 30, 12, 0, 0);
export const nowSec = () => Math.floor(NOW_MS / 1000);

export const AUTH_ENV_BASE = {
  AUTH_BASE_URL: "https://idp.example/user_management",
  AUTH_CLIENT_ID: "client_test",
  AUTH_CLIENT_SECRET: "test-only-client-credential",
  PUBLIC_URL: "https://app.example.com",
};

export function setCookies(res: Response): string[] {
  return res.headers.getSetCookie();
}
export function cookieNamed(res: Response, name: string): string | undefined {
  return setCookies(res).find((c) => c.startsWith(name + "="));
}
export const cookieValueOf = (c: string) => c.split(";")[0].split("=").slice(1).join("=");
