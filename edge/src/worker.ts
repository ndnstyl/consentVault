// consentvault capture edge (single site): a dependency-free Cloudflare Worker. Every request on the edge's hostname, any
// path, any method, any body, any origin, is forwarded whole to the vault in one signed envelope (envelope.ts) and answered
// with the vault's receipt. The origin list and the bot check are facts in the envelope; neither is a reason to refuse.

import {
  alarmDeadLetters, deliverBatch, durableFrom, hmacSha256Hex, sha256Hex, storeAndAnswer, type CaptureDeps as EnvelopeDeps, type Durable, type QueueLike,
  type QueueMessage, type R2Like,
} from "./envelope.ts";

export { sha256Hex, hmacSha256Hex };

export interface Env {
  ALLOWED_ORIGINS: string;
  VAULT_URL: string;
  SIGNING_SECRET: string;
  SOURCE_ID?: string;
  TURNSTILE_SECRET?: string;
  BODY_STORE?: R2Like; // optional: where a request waits while the vault is down (with CAPTURE_QUEUE)
  CAPTURE_QUEUE?: QueueLike;
  DEAD_LETTER_QUEUE?: string; // the name of the dead-letter queue: a message there raises an alarm
}

export interface Deps {
  fetch: typeof fetch;
  now: () => Date;
  durable?: Durable;
  alarm?: EnvelopeDeps["alarm"];
}

/** A named refusal. The capture Workers never raise one; the gateway and the portal Workers still do, for routes that are not captures. */
export class Refusal extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function allowedOrigins(env: Env): string[] {
  return (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
}

/** The bot check's answer exactly as the provider gave it, or the reason there is none. Never throws, never decides. */
export async function botCheckAnswer(env: Env, token: string | undefined, ip: string, deps: Deps): Promise<unknown> {
  if (!env.TURNSTILE_SECRET) return { error: "no_secret_configured" };
  if (!token) return { error: "no_token_sent" };
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

function tokenOf(text: string): string | undefined {
  try {
    const v = (JSON.parse(text) as { turnstile_token?: unknown } | null)?.turnstile_token;
    return typeof v === "string" ? v : undefined;
  } catch {
    return undefined;
  }
}

export async function handleConsent(request: Request, env: Env, deps: Deps): Promise<Response> {
  const origin = request.headers.get("origin");
  const facts: Record<string, unknown> = { intake: "edge_single", source_label: env.SOURCE_ID || "edge" };
  facts.origin_on_list = !!origin && allowedOrigins(env).includes(origin);
  if (request.method === "POST") {
    const text = await request.clone().text().catch(() => "");
    facts.bot_check_answer = await botCheckAnswer(env, tokenOf(text), request.headers.get("cf-connecting-ip") || "", deps);
  }
  return storeAndAnswer(request, env, deps, facts);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleConsent(request, env, { fetch: (...a) => fetch(...a), now: () => new Date(), durable: durableFrom(env) });
  },
  async queue(batch: { queue?: string; messages: QueueMessage[] }, env: Env): Promise<void> {
    const deps = { fetch: (...a: Parameters<typeof fetch>) => fetch(...a), now: () => new Date() };
    if (env.DEAD_LETTER_QUEUE && batch.queue === env.DEAD_LETTER_QUEUE) return alarmDeadLetters(batch.messages, deps);
    await deliverBatch(batch.messages, env, deps);
  },
};
