// Multi-tenant capture Worker: every request on the capture hostname, any path, any method, any body, any origin, is
// forwarded whole to the vault in one signed envelope (envelope.ts) and answered with the vault's receipt. The site key,
// the origin, the bot check, the rate and the client address are facts in the envelope; none of them is a reason to refuse
// or drop the request. A request that arrives while the vault is down waits in the edge's durable store and is told so.

import {
  deliverBatch, durableFrom, storeAndAnswer, type CaptureDeps as EnvelopeDeps, type Durable, type QueueLike, type QueueMessage, type R2Like,
} from "./envelope.ts";

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
  BODY_STORE?: R2Like; // optional: where a request waits while the vault is down (with CAPTURE_QUEUE)
  CAPTURE_QUEUE?: QueueLike;
}

export interface RateLimiter {
  hit(key: string, limit: number, windowSeconds: number): Promise<boolean>; // true = within the limit
}

export interface CaptureDeps {
  fetch: typeof fetch;
  now: () => Date;
  rateLimiter: RateLimiter;
  durable?: Durable;
  alarm?: EnvelopeDeps["alarm"];
}

const SITE_KEY_RE = /^cv_site_[A-Za-z0-9_-]{8,128}$/;

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

export function parseSiteKeys(env: CaptureEnv): Record<string, SiteKeyRecord> | null {
  try {
    const parsed: unknown = JSON.parse(env.SITE_KEYS);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, SiteKeyRecord>) : null;
  } catch {
    return null;
  }
}

function hostOf(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/** The bot check's answer exactly as the provider gave it, or the reason there is none. Never throws, never decides. */
export async function botCheckAnswer(env: CaptureEnv, token: string | undefined, ip: string, deps: CaptureDeps): Promise<unknown> {
  if (!token) return { error: "no_token_sent" };
  if (!env.TURNSTILE_SECRET) return { error: "no_secret_configured" };
  const form = new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token });
  if (ip) form.set("remoteip", ip);
  try {
    const res = await deps.fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch {
      return { error: "answer_not_json", status: res.status, text };
    }
  } catch (e) {
    return { error: "unreachable", detail: (e as Error).name };
  }
}

/** The turnstile token a browser body carries, read without parsing the body for anything else (a body that is not JSON has none). */
function tokenOf(text: string): string | undefined {
  try {
    const v = (JSON.parse(text) as { turnstile_token?: unknown } | null)?.turnstile_token;
    return typeof v === "string" ? v : undefined;
  } catch {
    return undefined;
  }
}

export async function handleCapture(request: Request, env: CaptureEnv, deps: CaptureDeps): Promise<Response> {
  const facts: Record<string, unknown> = { intake: "edge_site_key" };
  const origin = request.headers.get("origin");
  const siteKey = request.headers.get("x-consentvault-site-key") || "";
  const keys = parseSiteKeys(env);
  facts.site_key_present = siteKey !== "";
  let rec: SiteKeyRecord | undefined;
  if (keys === null) facts.site_key_state = "settings_unreadable";
  else if (!SITE_KEY_RE.test(siteKey)) facts.site_key_state = siteKey ? "malformed" : "missing";
  else {
    rec = Object.prototype.hasOwnProperty.call(keys, siteKey) ? keys[siteKey] : undefined;
    facts.site_key_state = !rec ? "unknown" : rec.active === true ? "active" : "inactive";
  }
  const allowed = rec && Array.isArray(rec.allowed_origins) ? rec.allowed_origins : [];
  facts.origin_on_list = !!origin && allowed.includes(origin);

  if (rec && facts.site_key_state === "active" && request.method !== "OPTIONS") {
    const limit = rec.rate_limit_per_minute ?? Number(env.DEFAULT_RATE_LIMIT_PER_MINUTE || 60);
    facts.rate_count_window = { limit, within: await deps.rateLimiter.hit(`site:${siteKey}`, limit, 60) };
  }
  if (request.method === "POST") {
    const text = await request.clone().text().catch(() => "");
    const ip = request.headers.get("cf-connecting-ip") || "";
    facts.bot_check_answer = await botCheckAnswer(env, tokenOf(text), ip, deps);
    const hosts = allowed.map(hostOf).filter(Boolean);
    const answer = facts.bot_check_answer as { hostname?: unknown } | null;
    facts.bot_check_hostname_on_list = typeof answer?.hostname === "string" && hosts.includes(answer.hostname.toLowerCase());
  }
  return storeAndAnswer(request, env, deps, facts);
}

const limiter = new MemoryRateLimiter();
export default {
  async fetch(request: Request, env: CaptureEnv): Promise<Response> {
    return handleCapture(request, env, { fetch: (...a) => fetch(...a), now: () => new Date(), rateLimiter: limiter, durable: durableFrom(env) });
  },
  // The queue consumer: delivers waiting requests to the vault in arrival order.
  async queue(batch: { messages: QueueMessage[] }, env: CaptureEnv): Promise<void> {
    await deliverBatch(batch.messages, env, { fetch: (...a) => fetch(...a), now: () => new Date() });
  },
};

