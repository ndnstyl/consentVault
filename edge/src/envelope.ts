// What the capture Workers share: forward the browser's own request to the vault in one signed envelope, and answer the
// browser with the vault's receipt. The edge judges nothing: every check it makes (site key, origin, rate, bot check,
// size) is a fact in the envelope, never a reason to refuse or drop the request (contracts/capture-api.md).
//
// The vault is the only thing that stores. When it cannot be reached, the request waits in a durable store the edge holds
// (a body store and a queue, when bound) and the browser is told it is queued with the fingerprint of what it sent; when
// neither can be written the browser is told, in so many words, that nothing was stored.

const enc = new TextEncoder();

export interface VaultTarget {
  VAULT_URL: string;
  SIGNING_SECRET: string;
  ACCESS_CLIENT_ID?: string;
  ACCESS_CLIENT_SECRET?: string;
}

/** Where a request waits while the vault is down: the whole body first, then one small message naming it. */
export interface Durable {
  putBody(key: string, body: Uint8Array): Promise<void>;
  enqueue(message: string): Promise<string>; // the queue id
}

export interface CaptureDeps {
  fetch: typeof fetch;
  now: () => Date;
  durable?: Durable;
  alarm?: (name: string, detail: string) => void;
}

export interface QueuedMessage {
  queue_id?: string;
  body_key: string;
  envelope: Record<string, unknown>; // the envelope as built, without body_b64
  queued_at: string;
}

export const ADDRESS_HEADERS: [string, string][] = [
  ["cf-connecting-ip", "cloudflare"],
  ["cf-connecting-ipv6", "cloudflare"],
  ["cf-pseudo-ipv4", "cloudflare"],
  ["x-forwarded-for", "any proxy or the sender"],
  ["forwarded", "any proxy or the sender"],
  ["x-real-ip", "any proxy or the sender"],
  ["true-client-ip", "cloudflare enterprise or the sender"],
];

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256HexOf(bytes: Uint8Array): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}

export async function sha256Hex(text: string): Promise<string> {
  return sha256HexOf(enc.encode(text));
}

export async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
}

export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

/** Every header as the runtime presents it. The runtime lower-cases names and joins repeated values; the vault records that. */
export function collectHeaders(request: Request): [string, string][] {
  return Array.from(request.headers.entries());
}

export function addressFacts(request: Request): Record<string, unknown> {
  const facts: Record<string, unknown> = {};
  for (const [name, setBy] of ADDRESS_HEADERS) {
    const v = request.headers.get(name);
    if (v !== null) facts[name === "cf-connecting-ip" ? "client_ip" : name.replace(/-/g, "_")] = name === "cf-connecting-ip" ? v : { value: v, set_by: setBy };
  }
  const ray = request.headers.get("cf-ray");
  if (ray !== null) facts.cf_ray = ray;
  const cf = (request as unknown as { cf?: unknown }).cf;
  if (cf !== undefined) facts.request_cf = cf;
  return facts;
}

/** The permission headers every capture answer carries: the request's origin echoed (or any), the methods and headers it asked for. */
export function permissionHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("origin");
  const asked = request.headers.get("access-control-request-headers");
  return {
    "access-control-allow-origin": origin || "*",
    "access-control-allow-methods": request.headers.get("access-control-request-method") || "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "access-control-allow-headers": asked || "*",
    "access-control-expose-headers": "x-request-id",
    vary: "origin",
  };
}

export function isPreflight(request: Request): boolean {
  return request.method === "OPTIONS" && request.headers.has("access-control-request-method");
}

function json(status: number, body: unknown, extra: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...extra } });
}

export function unavailable(extra: Record<string, string>): Response {
  return json(503, { stored: false, error: "store_unavailable", detail: "the record store could not be written; nothing was stored; send again" }, extra);
}

export interface Built {
  envelope: Record<string, unknown>;
  bodySha256: string;
  bodyBytes: number;
}

/** The envelope for one browser request. ``body_b64`` is present only when the body is carried inline. */
export async function buildEnvelope(request: Request, body: Uint8Array, facts: Record<string, unknown>, inline: boolean): Promise<Built> {
  const url = new URL(request.url);
  const bodySha256 = await sha256HexOf(body);
  const envelope: Record<string, unknown> = {
    method: request.method,
    path: url.pathname,
    query: url.search.replace(/^\?/, ""),
    headers: collectHeaders(request),
    body_sha256: bodySha256,
    body_bytes: body.byteLength,
    edge_facts: facts,
  };
  if (inline) envelope.body_b64 = toBase64(body);
  return { envelope, bodySha256, bodyBytes: body.byteLength };
}

async function post(target: VaultTarget, deps: CaptureDeps, envelope: Record<string, unknown>): Promise<Response> {
  const text = JSON.stringify(envelope);
  const timestamp = String(Math.floor(deps.now().getTime() / 1000));
  const signature = await hmacSha256Hex(target.SIGNING_SECRET, `${timestamp}.${text}`);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-consentvault-timestamp": timestamp,
    "x-consentvault-signature": signature,
  };
  if (target.ACCESS_CLIENT_ID) headers["cf-access-client-id"] = target.ACCESS_CLIENT_ID;
  if (target.ACCESS_CLIENT_SECRET) headers["cf-access-client-secret"] = target.ACCESS_CLIENT_SECRET;
  return deps.fetch(target.VAULT_URL.replace(/\/+$/, "") + "/v1/events", { method: "POST", headers, body: text });
}

function alarm(deps: CaptureDeps, name: string, detail: string): void {
  (deps.alarm ?? ((n, d) => console.error(`consentvault edge alarm ${n}: ${d}`)))(name, detail);
}

/**
 * Store-and-answer for one browser request: forward it whole, relay the vault's receipt; when the vault cannot be reached
 * or answers anything but a receipt, queue it durably; when that cannot be done either, say nothing was stored.
 */
export async function storeAndAnswer(request: Request, target: Partial<VaultTarget>, deps: CaptureDeps, facts: Record<string, unknown>): Promise<Response> {
  const cors = permissionHeaders(request);
  let body: Uint8Array;
  try {
    body = new Uint8Array(await request.arrayBuffer());
  } catch (e) {
    body = new Uint8Array(0);
    facts = { ...facts, body_read_failed: (e as Error).name };
  }
  const preflight = isPreflight(request);
  const edgeReceivedAt = deps.now().toISOString();
  facts = { edge_received_at: edgeReceivedAt, origin_header: request.headers.get("origin"), ...addressFacts(request), ...facts };
  const have = !!(target.VAULT_URL && target.SIGNING_SECRET);
  if (!have) {
    alarm(deps, "capture.store_unavailable", "the edge has no vault address or signing secret; nothing was stored");
    return preflight ? new Response(null, { status: 204, headers: cors }) : unavailable(cors);
  }
  const built = await buildEnvelope(request, body, facts, true);
  let reply: Response | null = null;
  try {
    const res = await post(target as VaultTarget, deps, built.envelope);
    if (res.status === 201) reply = res;
  } catch {
    reply = null; // the vault could not be reached; the request is queued below
  }
  if (reply !== null) {
    if (preflight) return new Response(null, { status: 204, headers: cors });
    const text = await reply.text();
    return new Response(text, { status: 201, headers: { "content-type": "application/json", "cache-control": "no-store", ...cors } });
  }
  // The vault did not answer with a receipt. Queue the request durably, or say nothing was stored.
  if (deps.durable) {
    try {
      const key = `bodies/${crypto.randomUUID()}`;
      await deps.durable.putBody(key, body);
      const { body_b64: _drop, ...rest } = built.envelope as Record<string, unknown> & { body_b64?: string };
      const message: QueuedMessage = { body_key: key, envelope: rest, queued_at: edgeReceivedAt };
      const queueId = await deps.durable.enqueue(JSON.stringify(message));
      if (preflight) return new Response(null, { status: 204, headers: cors });
      return json(202, { stored: false, queued: true, queue_id: queueId, body_sha256: built.bodySha256, body_bytes: built.bodyBytes, edge_received_at: edgeReceivedAt }, cors);
    } catch (e) {
      alarm(deps, "capture.store_unavailable", `the vault and the edge's durable store both failed (${(e as Error).name}); nothing was stored`);
    }
  } else {
    alarm(deps, "capture.store_unavailable", "the vault did not answer and the edge has no durable store; nothing was stored");
  }
  return preflight ? new Response(null, { status: 204, headers: cors }) : unavailable(cors);
}

/**
 * Deliver one queued request to the vault: rebuild the envelope with the body read back from the durable store, add the facts
 * ``queued_at_edge`` and ``delivered_from_queue_at``, sign it with a fresh timestamp. The body fingerprint is the one that was
 * answered to the browser. Throws when the vault does not answer with a receipt (the queue retries; past its deadline an alarm).
 */
export async function deliverQueued(message: QueuedMessage, body: Uint8Array, target: VaultTarget, deps: CaptureDeps): Promise<void> {
  const envelope = { ...message.envelope, body_b64: toBase64(body) } as Record<string, unknown>;
  const facts = { ...(envelope.edge_facts as Record<string, unknown>), queued_at_edge: message.queued_at, delivered_from_queue_at: deps.now().toISOString() };
  envelope.edge_facts = facts;
  if ((await sha256HexOf(body)) !== envelope.body_sha256) throw new Error("the queued body no longer matches its fingerprint");
  const res = await post(target, deps, envelope);
  if (res.status !== 201) throw new Error(`the vault answered ${res.status}`);
}

// Cloudflare bindings: the durable store is an R2 bucket (``BODY_STORE``) for the body and a Queue (``CAPTURE_QUEUE``) for the
// one small message that names it. Neither is a dependency of the vault; without both the edge has no durable store and says so.
export interface R2Like {
  put(key: string, value: Uint8Array): Promise<unknown>;
  get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer> } | null>;
}
export interface QueueLike {
  send(message: string): Promise<void>;
}

export function durableFrom(env: { BODY_STORE?: R2Like; CAPTURE_QUEUE?: QueueLike }): Durable | undefined {
  const { BODY_STORE, CAPTURE_QUEUE } = env;
  if (!BODY_STORE || !CAPTURE_QUEUE) return undefined;
  return {
    putBody: async (key, body) => { await BODY_STORE.put(key, body); },
    enqueue: async (message) => {
      const queueId = crypto.randomUUID();
      await CAPTURE_QUEUE.send(JSON.stringify({ ...(JSON.parse(message) as QueuedMessage), queue_id: queueId }));
      return queueId;
    },
  };
}

export interface QueueMessage {
  body: string;
  ack(): void;
  retry(): void;
}
export const QUEUE_DEADLINE_MS = 60 * 60 * 1000;

/**
 * Deliver a batch of queued requests in arrival order. The first one the vault does not take stops the batch: it and every
 * one after it are retried, so a later request never lands before an earlier one. A request still undelivered an hour after
 * the edge accepted it raises the past-deadline alarm every time it is retried.
 */
export async function deliverBatch(messages: QueueMessage[], env: { BODY_STORE?: R2Like } & Partial<VaultTarget>, deps: CaptureDeps): Promise<void> {
  let failed = false;
  for (const m of messages) {
    if (failed) { m.retry(); continue; }
    let message: QueuedMessage;
    try {
      message = JSON.parse(m.body) as QueuedMessage;
    } catch {
      alarm(deps, "capture.queue_unreadable", "a queued message could not be read; it is kept and retried");
      failed = true;
      m.retry();
      continue;
    }
    try {
      if (!env.BODY_STORE || !env.VAULT_URL || !env.SIGNING_SECRET) throw new Error("the edge's store or vault settings are missing");
      const object = await env.BODY_STORE.get(message.body_key);
      if (!object) throw new Error("the queued body is missing from the store");
      await deliverQueued(message, new Uint8Array(await object.arrayBuffer()), env as VaultTarget, deps);
      m.ack();
    } catch (e) {
      failed = true;
      m.retry();
      if (deps.now().getTime() - Date.parse(message.queued_at) > QUEUE_DEADLINE_MS) {
        alarm(deps, "capture.queue_past_deadline", `a queued request is still undelivered an hour after it was accepted (${(e as Error).name})`);
      }
    }
  }
}
