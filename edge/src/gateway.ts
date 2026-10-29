// Gateway Worker: bearer pass-through for machine clients. Does not mint or read tokens; the vault verifies them.
// Adds the Access service token toward the origin, enforces size limits and a WAF hook, and logs nothing.

import { Refusal } from "./worker.ts";

export interface GatewayEnv {
  ORIGIN_URL: string;
  ACCESS_CLIENT_ID: string;
  ACCESS_CLIENT_SECRET: string;
  MAX_BODY_BYTES?: string;
}

export interface GatewayDeps {
  fetch: typeof fetch;
  // WAF hook: return a Refusal-shaped object to block; undefined to allow.
  waf?: (request: Request) => Promise<{ status: number; code: string; message: string } | undefined>;
}

const DEFAULT_MAX_BODY = 256 * 1024;
const BEARER_RE = /^Bearer [A-Za-z0-9._~+\/-]+=*$/;
const DROP_REQUEST_HEADERS = ["cf-access-client-id", "cf-access-client-secret", "cf-access-jwt-assertion", "host", "connection", "x-forwarded-for"];
const ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

function err(status: number, code: string, message: string): Response {
  return new Response(JSON.stringify({ error: code, message }), { status, headers: { "content-type": "application/json" } });
}

export async function handleGateway(request: Request, env: GatewayEnv, deps: GatewayDeps): Promise<Response> {
  try {
    for (const k of ["ORIGIN_URL", "ACCESS_CLIENT_ID", "ACCESS_CLIENT_SECRET"] as const) {
      if (!env[k]) throw new Refusal(500, "misconfigured", `gateway setting ${k} is not set`);
    }
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/v1/")) throw new Refusal(404, "not_found", "no such route");
    if (!ALLOWED_METHODS.includes(request.method)) throw new Refusal(405, "method_not_allowed", "method not allowed");

    const auth = request.headers.get("authorization");
    if (!auth) throw new Refusal(401, "bearer_missing", "an Authorization: Bearer token is required");
    if (!BEARER_RE.test(auth)) throw new Refusal(401, "bearer_malformed", "Authorization header is not a well-formed bearer token");
    if (auth.slice(7).startsWith("cv_site_")) throw new Refusal(401, "site_key_not_accepted", "site keys are accepted only at the capture endpoint");

    const max = Number(env.MAX_BODY_BYTES || DEFAULT_MAX_BODY);
    const declared = request.headers.get("content-length");
    if (declared !== null && Number(declared) > max) throw new Refusal(413, "too_large", `body exceeds ${max} bytes`);

    let body: ArrayBuffer | undefined;
    if (request.method !== "GET" && request.method !== "DELETE") {
      body = await request.arrayBuffer();
      if (body.byteLength > max) throw new Refusal(413, "too_large", `body exceeds ${max} bytes`);
    }

    if (deps.waf) {
      const verdict = await deps.waf(request);
      if (verdict) throw new Refusal(verdict.status, verdict.code, verdict.message);
    }

    const headers = new Headers(request.headers);
    for (const h of DROP_REQUEST_HEADERS) headers.delete(h);
    headers.set("cf-access-client-id", env.ACCESS_CLIENT_ID);
    headers.set("cf-access-client-secret", env.ACCESS_CLIENT_SECRET);

    let res: Response;
    try {
      res = await deps.fetch(env.ORIGIN_URL.replace(/\/+$/, "") + url.pathname + url.search, { method: request.method, headers, body });
    } catch (e) {
      throw new Refusal(502, "origin_unreachable", `origin unreachable: ${(e as Error).name}`);
    }
    const out = new Headers(res.headers);
    out.delete("set-cookie");
    return new Response(res.body, { status: res.status, headers: out });
  } catch (e) {
    if (e instanceof Refusal) return err(e.status, e.code, e.message);
    return err(500, "internal", "gateway failure");
  }
}

export default {
  async fetch(request: Request, env: GatewayEnv): Promise<Response> {
    return handleGateway(request, env, { fetch: (...a) => fetch(...a) });
  },
};
