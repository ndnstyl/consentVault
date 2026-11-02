// Multi-tenant capture Worker: site key -> origin binding -> Turnstile (hostname match) -> rate limit
// -> signed forward to the vault. Every refusal is a named error with a non-2xx status.

import { Refusal, validateInput, sha256Hex, hmacSha256Hex } from "./worker.ts";

export interface SiteKeyRecord {
  active: boolean;
  source_id: string;
  allowed_origins: string[];
  rate_limit_per_minute?: number;
}

export interface CaptureEnv {
  SITE_KEYS: string; // JSON object: { "cv_site_...": SiteKeyRecord }
  VAULT_URL: string;
  SIGNING_SECRET: string;
  TURNSTILE_SECRET: string;
  ACCESS_CLIENT_ID: string;
  ACCESS_CLIENT_SECRET: string;
  DEFAULT_RATE_LIMIT_PER_MINUTE?: string;
}

export interface RateLimiter {
  hit(key: string, limit: number, windowSeconds: number): Promise<boolean>; // true = allowed
}

export interface CaptureDeps {
  fetch: typeof fetch;
  now: () => Date;
  rateLimiter: RateLimiter;
}

const MAX_BODY_BYTES = 16 * 1024;
const SITE_KEY_RE = /^cv_site_[A-Za-z0-9_-]{8,128}$/;
const enc = new TextEncoder();

export class MemoryRateLimiter implements RateLimiter {
  private hits = new Map<string, { start: number; n: number }>();
  async hit(key: string, limit: number, windowSeconds: number): Promise<boolean> {
    const now = Date.now();
    const cur = this.hits.get(key);
    if (!cur || now - cur.start >= windowSeconds * 1000) {
      this.hits.set(key, { start: now, n: 1 });
      return limit >= 1;
    }
    cur.n += 1;
    return cur.n <= limit;
  }
}

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...extra } });
}

export function parseSiteKeys(env: CaptureEnv): Record<string, SiteKeyRecord> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(env.SITE_KEYS);
  } catch {
    throw new Refusal(500, "misconfigured", "SITE_KEYS is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Refusal(500, "misconfigured", "SITE_KEYS must be a JSON object");
  }
  return parsed as Record<string, SiteKeyRecord>;
}

function requireEnv(env: CaptureEnv): void {
  for (const k of ["SITE_KEYS", "VAULT_URL", "SIGNING_SECRET", "TURNSTILE_SECRET", "ACCESS_CLIENT_ID", "ACCESS_CLIENT_SECRET"] as const) {
    if (!env[k]) throw new Refusal(500, "misconfigured", `capture setting ${k} is not set`);
  }
}

function hostOf(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return "";
  }
}

export async function verifyTurnstile(
  env: CaptureEnv,
  token: string | undefined,
  ip: string,
  allowedHosts: string[],
  deps: CaptureDeps,
): Promise<string> {
  if (!token) throw new Refusal(403, "bot_check_missing", "a bot-check token is required");
  const form = new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token });
  if (ip) form.set("remoteip", ip);
  let res: Response;
  try {
    res = await deps.fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
  } catch (e) {
    throw new Refusal(502, "bot_check_unreachable", `bot-check service unreachable: ${(e as Error).message}`);
  }
  if (!res.ok) throw new Refusal(502, "bot_check_unreachable", `bot-check service answered ${res.status}`);
  let data: { success?: boolean; hostname?: string };
  try {
    data = (await res.json()) as { success?: boolean; hostname?: string };
  } catch {
    throw new Refusal(502, "bot_check_unreachable", "bot-check service answered with non-JSON");
  }
  if (data.success !== true) throw new Refusal(403, "bot_check_failed", "bot check failed");
  const host = (data.hostname || "").toLowerCase();
  if (!host) throw new Refusal(403, "bot_check_hostname_missing", "bot check returned no hostname");
  if (!allowedHosts.includes(host)) {
    throw new Refusal(403, "bot_check_hostname_mismatch", "bot check was solved on a host that is not an allowed origin for this site key");
  }
  return "turnstile:pass";
}

function cors(origin: string | null, ok: boolean): Record<string, string> {
  if (origin && ok) {
    return {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "content-type, x-consentvault-site-key",
      vary: "origin",
    };
  }
  return { vary: "origin" };
}

export async function handleCapture(request: Request, env: CaptureEnv, deps: CaptureDeps): Promise<Response> {
  const origin = request.headers.get("origin");
  let corsHeaders: Record<string, string> = { vary: "origin" };
  try {
    requireEnv(env);
    const keys = parseSiteKeys(env);
    const url = new URL(request.url);
    if (url.pathname !== "/capture") throw new Refusal(404, "not_found", "no such route");

    if (request.method === "OPTIONS") {
      const any = origin && Object.values(keys).some((k) => k && k.active === true && Array.isArray(k.allowed_origins) && k.allowed_origins.includes(origin));
      if (!any) throw new Refusal(403, "origin_refused", "origin not allowed");
      return new Response(null, { status: 204, headers: cors(origin, true) });
    }
    if (request.method !== "POST") throw new Refusal(405, "method_not_allowed", "use POST");

    const siteKey = request.headers.get("x-consentvault-site-key") || "";
    if (!SITE_KEY_RE.test(siteKey)) throw new Refusal(401, "site_key_missing", "a well-formed site key is required in X-ConsentVault-Site-Key");
    const rec = Object.prototype.hasOwnProperty.call(keys, siteKey) ? keys[siteKey] : undefined;
    if (!rec) throw new Refusal(403, "site_key_unknown", "site key is not known");
    if (rec.active !== true) throw new Refusal(403, "site_key_inactive", "site key is not active");
    if (!Array.isArray(rec.allowed_origins) || rec.allowed_origins.length === 0 || !rec.source_id) {
      throw new Refusal(500, "misconfigured", "site key record has no allowed origins or source");
    }
    if (!origin || !rec.allowed_origins.includes(origin)) throw new Refusal(403, "origin_refused", "origin is not allowed for this site key");
    corsHeaders = cors(origin, true);

    const limit = rec.rate_limit_per_minute ?? Number(env.DEFAULT_RATE_LIMIT_PER_MINUTE || 60);
    if (!(await deps.rateLimiter.hit(`site:${siteKey}`, limit, 60))) {
      throw new Refusal(429, "rate_limited", "too many submissions for this site key; try again shortly");
    }

    const declared = Number(request.headers.get("content-length") || 0);
    if (declared > MAX_BODY_BYTES) throw new Refusal(413, "too_large", "body too large");
    const text = await request.text();
    if (enc.encode(text).length > MAX_BODY_BYTES) throw new Refusal(413, "too_large", "body too large");
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Refusal(400, "bad_json", "body is not valid JSON");
    }
    const input = validateInput(parsed);

    const ip = request.headers.get("cf-connecting-ip") || "";
    if (!ip) throw new Refusal(400, "no_client_ip", "CF-Connecting-IP header is missing");
    const hosts = rec.allowed_origins.map(hostOf).filter(Boolean);
    const bot = await verifyTurnstile(env, input.turnstile_token, ip, hosts, deps);
    const receivedAt = deps.now().toISOString();

    const event: Record<string, unknown> = {
      contact: input.contact,
      event_type: "grant",
      checked: true,
      method: "checkbox",
      origin: "consumer",
      contact_verification: "none",
      channels: input.channels,
      purposes: input.purposes,
      disclosure_sha256: input.disclosure_sha256,
      page_url: input.page_url,
      session_ref: input.session,
      edge_received_at: receivedAt,
      client_ip: ip,
      user_agent: request.headers.get("user-agent") || "",
      bot_check: bot,
      payload_sha256: await sha256Hex(text),
      site_key: siteKey,
      source_id: rec.source_id,
      source: "site_key",
    };
    const body = JSON.stringify(event);
    const timestamp = String(Math.floor(deps.now().getTime() / 1000));
    const signature = await hmacSha256Hex(env.SIGNING_SECRET, `${timestamp}.${body}`);

    let res: Response;
    try {
      res = await deps.fetch(env.VAULT_URL.replace(/\/+$/, "") + "/v1/events", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-consentvault-timestamp": timestamp,
          "x-consentvault-signature": signature,
          "cf-access-client-id": env.ACCESS_CLIENT_ID,
          "cf-access-client-secret": env.ACCESS_CLIENT_SECRET,
        },
        body,
      });
    } catch (e) {
      throw new Refusal(502, "vault_unreachable", `vault unreachable: ${(e as Error).message}`);
    }
    if (!res.ok) throw new Refusal(502, "vault_refused", `vault answered ${res.status}; nothing was recorded`);
    return json(200, { recorded: true, payload_sha256: event.payload_sha256 }, corsHeaders);
  } catch (e) {
    if (e instanceof Refusal) return json(e.status, { recorded: false, error: e.code, message: e.message }, corsHeaders);
    return json(500, { recorded: false, error: "internal", message: (e as Error).message }, corsHeaders);
  }
}

const limiter = new MemoryRateLimiter();
export default {
  async fetch(request: Request, env: CaptureEnv): Promise<Response> {
    return handleCapture(request, env, { fetch: (...a) => fetch(...a), now: () => new Date(), rateLimiter: limiter });
  },
};
