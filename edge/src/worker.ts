// consentvault capture edge: a dependency-free Cloudflare Worker.
// Accepts POST /consent from the widget, validates it, adds what only the server can know,
// signs the body and forwards it to the vault's POST /v1/events.

export interface Env {
  ALLOWED_ORIGINS: string;
  VAULT_URL: string;
  SIGNING_SECRET: string;
  SOURCE_ID?: string;
  TURNSTILE_SECRET?: string;
}

export interface Deps {
  fetch: typeof fetch;
  now: () => Date;
}

const CHANNELS = ["voice", "artificial_voice", "sms", "email"];
const SHA256_HEX = /^[0-9a-f]{64}$/;
const MAX_BODY_BYTES = 16 * 1024;

export class Refusal extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const enc = new TextEncoder();

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(text: string): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

export async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
}

export function allowedOrigins(env: Env): string[] {
  return (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
}

function requireEnv(env: Env): void {
  for (const k of ["ALLOWED_ORIGINS", "VAULT_URL", "SIGNING_SECRET"] as const) {
    if (!env[k]) throw new Refusal(500, "misconfigured", `edge setting ${k} is not set`);
  }
  if (allowedOrigins(env).length === 0) throw new Refusal(500, "misconfigured", "ALLOWED_ORIGINS is empty");
}

function corsHeaders(origin: string | null, env: Env): Record<string, string> {
  if (origin && allowedOrigins(env).includes(origin)) {
    return {
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "content-type",
      vary: "origin",
    };
  }
  return { vary: "origin" };
}

function json(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...extra },
  });
}

export interface ConsentInput {
  contact: string;
  checked: boolean;
  disclosure_sha256: string;
  channels: string[];
  purposes: string[];
  page_url: string;
  session: string;
  turnstile_token?: string;
}

export function validateInput(raw: unknown): ConsentInput {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Refusal(400, "bad_shape", "body must be a JSON object");
  }
  const r = raw as Record<string, unknown>;
  const str = (k: string, max = 2048): string => {
    const v = r[k];
    if (typeof v !== "string" || v.trim() === "" || v.length > max) {
      throw new Refusal(400, "bad_shape", `field '${k}' must be a non-empty string`);
    }
    return v.trim();
  };
  const list = (k: string): string[] => {
    const v = r[k];
    if (!Array.isArray(v) || v.length === 0 || v.some((x) => typeof x !== "string" || x.trim() === "")) {
      throw new Refusal(400, "bad_shape", `field '${k}' must be a non-empty list of strings`);
    }
    return Array.from(new Set((v as string[]).map((x) => x.trim()))).sort();
  };
  if (r.checked !== true) {
    throw new Refusal(422, "unchecked", "the consent box was not checked; no grant is recorded");
  }
  if (r.disclosure_text !== undefined) {
    throw new Refusal(
      400,
      "disclosure_text_refused",
      "wording is not accepted here: the operator registers it with the vault first and the request carries only its sha256",
    );
  }
  const disclosure_sha256 = str("disclosure_sha256", 64).toLowerCase();
  if (!SHA256_HEX.test(disclosure_sha256)) {
    throw new Refusal(400, "bad_shape", "field 'disclosure_sha256' must be 64 hex characters");
  }
  const channels = list("channels");
  const badChannel = channels.filter((c) => !CHANNELS.includes(c));
  if (badChannel.length) {
    throw new Refusal(400, "bad_shape", `unknown channel: ${badChannel.join(",")}; allowed: ${CHANNELS.join(",")}`);
  }
  const out: ConsentInput = {
    contact: str("contact", 320),
    checked: true,
    disclosure_sha256,
    channels,
    purposes: list("purposes"),
    page_url: str("page_url"),
    session: str("session", 128),
  };
  if (r.turnstile_token !== undefined) {
    if (typeof r.turnstile_token !== "string") throw new Refusal(400, "bad_shape", "field 'turnstile_token' must be a string");
    out.turnstile_token = r.turnstile_token;
  }
  return out;
}

export async function botCheck(env: Env, token: string | undefined, ip: string, deps: Deps): Promise<string> {
  if (!env.TURNSTILE_SECRET) return "none";
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
  const data = (await res.json()) as { success?: boolean };
  if (data.success !== true) throw new Refusal(403, "bot_check_failed", "bot check failed");
  return "turnstile:pass";
}

export async function handleConsent(request: Request, env: Env, deps: Deps): Promise<Response> {
  const origin = request.headers.get("origin");
  const cors = corsHeaders(origin, env);
  try {
    requireEnv(env);
    const url = new URL(request.url);
    if (url.pathname !== "/consent") throw new Refusal(404, "not_found", "no such route");
    if (request.method === "OPTIONS") {
      if (!origin || !allowedOrigins(env).includes(origin)) throw new Refusal(403, "origin_refused", "origin not allowed");
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== "POST") throw new Refusal(405, "method_not_allowed", "use POST");
    if (!origin || !allowedOrigins(env).includes(origin)) throw new Refusal(403, "origin_refused", "origin not allowed");

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
    const bot = await botCheck(env, input.turnstile_token, ip, deps);
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
      source: env.SOURCE_ID || "edge",
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
        },
        body,
      });
    } catch (e) {
      throw new Refusal(502, "vault_unreachable", `vault unreachable: ${(e as Error).message}`);
    }
    if (!res.ok) throw new Refusal(502, "vault_refused", `vault answered ${res.status}; nothing was recorded`);
    return json(200, { recorded: true, payload_sha256: event.payload_sha256 }, cors);
  } catch (e) {
    if (e instanceof Refusal) return json(e.status, { recorded: false, error: e.code, message: e.message }, cors);
    return json(500, { recorded: false, error: "internal", message: (e as Error).message }, cors);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleConsent(request, env, { fetch: (...a) => fetch(...a), now: () => new Date() });
  },
};
