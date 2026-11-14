// Gateway Worker. Two callers, one door to the vault:
//  - machine clients send a bearer token; the gateway passes it through (it does not mint or read it; the vault verifies).
//  - the portal's browser sends only the opaque session cookie; the gateway turns it into the vault call per
//    contracts/session.md: the identity token for the sign-in endpoints, the short tenant token for everything else.
//    The browser never holds either token.
// Adds the Access service token toward the origin, enforces size limits and a WAF hook, and logs nothing.

import { Refusal } from "./worker.ts";
import { ASSERTION_HEADER, MisconfiguredError, assertionConfigError, signAssertion } from "./assertion.ts";
import { StoreUnavailable, sessionStoreFor, type GateNamespace, type SessionStore } from "./session-store.ts";
import {
  SESSION_COOKIE, TENANT_TOKEN_HEADER, clearCookie, cookieValue, tokenClaims,
  type KV, type SessionRecord,
} from "./session.ts";

export interface GatewayEnv {
  ORIGIN_URL: string;
  ACCESS_CLIENT_ID: string;
  ACCESS_CLIENT_SECRET: string;
  MAX_BODY_BYTES?: string;
  // Portal sessions (absent on a machine-only gateway):
  SESSIONS?: KV;
  AUTH_BASE_URL?: string;
  AUTH_CLIENT_ID?: string;
  AUTH_CLIENT_SECRET?: string;
  PUBLIC_URL?: string;
  ASSERTION_KEY_JWK?: string;
  PROVIDER_MFA_REQUIRED?: string;
  // One Durable Object per session owns the session record and is its only writer (see session-gate.ts); optional.
  SESSION_GATE?: GateNamespace;
  // Workers rate-limit bindings for the confirmation doors (wrangler [[ratelimits]]); see confirmationDoor below.
  INBOUND_LIMITER?: RateLimiter;
  PAGE_LIMITER?: RateLimiter;
  // D1 database the fallback door stores each post in until the vault has answered it with a 2xx (drainInboundSpool, on the cron).
  INBOUND_SPOOL?: D1Like;
  // The operator's bearer for POST /ops/inbound-spool/replay (a Worker secret). Unset: the route does not exist (404).
  OPS_REPLAY_SECRET?: string;
}

/** The few D1 calls the inbound store makes (prepare, bind, run or all). */
export interface D1Like {
  prepare(sql: string): { bind(...values: unknown[]): { run(): Promise<unknown>; all(): Promise<{ results?: Record<string, unknown>[] }> } };
}

/** The Workers rate-limit binding's shape: one call per request, { success: false } over the limit. */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface GatewayDeps {
  fetch: typeof fetch;
  now?: () => number; // milliseconds
  // WAF hook: returns its verdict. On a capture route the verdict is a fact beside the post, never a block; on every other
  // route a verdict blocks. Undefined allows.
  waf?: (request: Request) => Promise<{ status: number; code: string; message: string } | undefined>;
  alarm?: (name: string, detail: string) => void;
}

const DEFAULT_MAX_BODY = 256 * 1024;
// A capture route: every request, any method, any body, is forwarded whole and stored by the vault (contracts/capture-api.md).
const CAPTURE_PREFIXES = ["/v1/events", "/v1/capture"];
export const GATEWAY_FACTS_HEADER = "x-consentvault-gateway-facts";
const isCapturePath = (p: string) => CAPTURE_PREFIXES.some((x) => p === x || p.startsWith(x + "/"));
const BEARER_RE = /^Bearer [A-Za-z0-9._~+\/-]+=*$/;
// The link host of a confirmation page, set only by this Worker from the request's own host name (confirm/wiring.py reads it).
export const LINK_HOST_HEADER = "x-consentvault-link-host";
const DROP_REQUEST_HEADERS = ["cf-access-client-id", "cf-access-client-secret", "cf-access-jwt-assertion", "host", "connection", "x-forwarded-for", "cookie", LINK_HOST_HEADER];
const ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const DOWNLOAD_RE = /^\/v1\/exports\/[0-9a-fA-F-]{36}\/download$/; // the signed one-time link is the credential
const INVITE_VIEW_RE = /^\/v1\/invites\/[^/:]+$/; // the public view of an invitation, read before the person has joined
const ACCEPT_RE = /^\/v1\/invites\/[^/]+:accept$/;
// The Twenty receiver (twenty.md 3.1): the signature over the raw body is the credential, so no bearer; 256 KB at most.
const TWENTY_WEBHOOK_RE = /^\/v1\/connectors\/twenty\/[A-Za-z0-9_-]{1,128}\/webhook$/;
// Stripe's live webhook: the Stripe-Signature over the raw body is the credential, so no bearer; this one exact path and method.
const STRIPE_WEBHOOK_PATH = "/v1/billing/webhook";
const TWENTY_WEBHOOK_MAX_BODY = 256 * 1024;
// The text provider's inbound posts (confirmations.md section 9): Twilio sends no bearer; the X-Twilio-Signature over the address
// the vault stored is the credential, checked by the vault. The key is the random per-account part of that address.
const INBOUND_RE = /^\/v1\/confirmations\/inbound\/([A-Za-z0-9_-]{20,128})$/;
// The number's fallback address: Twilio calls it once when the primary fails. Every post here is kept in INBOUND_SPOOL before
// the vault is asked, and answered 200 once kept, so a STOP sent while the vault is down is delivered when it is back.
const FALLBACK_RE = /^\/v1\/confirmations\/inbound-fallback\/([A-Za-z0-9_-]{20,128})$/;
// The edge cannot check Twilio's signature (the auth token lives only in the vault), so what it stores is capped: open posts per
// number (inbound key) and in all; past a cap a post is only forwarded.
export const SPOOL_PER_KEY = 200;
export const SPOOL_TOTAL = 1000;
// A stored post older than this is an alarm: it should have reached the vault within a few runs.
const STALE_AFTER_MS = 10 * 60_000;
// Drained rows are kept a week for reading back, then removed.
const KEEP_DRAINED_MS = 7 * 24 * 3600_000;
// The store (edge/migrations/0001_inbound_spool.sql). D1 is strongly consistent through its primary: the drain reads the open
// rows every minute; there is no flag and no listing.
export const SPOOL_SQL = {
  countKey: "SELECT count(*) AS n FROM inbound_spool WHERE number_key = ? AND drained_at IS NULL AND refused_at IS NULL",
  countAll: "SELECT count(*) AS n FROM inbound_spool WHERE drained_at IS NULL AND refused_at IS NULL",
  insert: "INSERT INTO inbound_spool (id, number_key, received_at, path, body_b64, headers_json) VALUES (?, ?, ?, ?, ?, ?)",
  pending: "SELECT id, number_key, received_at, path, body_b64, headers_json FROM inbound_spool WHERE drained_at IS NULL AND refused_at IS NULL ORDER BY received_at LIMIT 1000",
  // A post the vault refuses BY NAME (VAULT_REFUSALS) is closed as refused after its alarm, kept for the record with the status,
  // and no longer counts toward the cap; any other answer keeps it open.
  markRefused: "UPDATE inbound_spool SET refused_at = ?, attempts = attempts + 1, last_status = ? WHERE id = ?",
  markDrained: "UPDATE inbound_spool SET drained_at = ?, attempts = attempts + 1, last_status = ? WHERE id = ?",
  markAttempt: "UPDATE inbound_spool SET attempts = attempts + 1, last_status = ? WHERE id = ?",
  // Refused rows received in a window, for the replay after a Twilio auth-token change (the vault then refused real posts).
  refusedInWindow: "SELECT id, number_key, received_at, path, body_b64, headers_json FROM inbound_spool WHERE refused_at IS NOT NULL AND drained_at IS NULL AND received_at >= ? AND received_at <= ? ORDER BY received_at LIMIT 1000",
  purge: "DELETE FROM inbound_spool WHERE drained_at IS NOT NULL AND drained_at < ?",
} as const;
const FALLBACK_MAX_BODY = 16 * 1024; // the vault refuses more (confirm/inbound.py MAX_BODY_BYTES), so the edge keeps no more
// The provider headers a kept post carries back to the vault (the signature over the address and the body is the credential).
const SPOOL_HEADERS = ["content-type", "x-twilio-signature", "i-twilio-idempotency-token", "user-agent"];
const INBOUND_MAX_BODY = 64 * 1024; // the vault itself answers 413 over 16 KB and counts it with the signature failures
// The person's pages on an organisation's own link host (confirmations.md sections 6 and 7; the product's own token pattern).
const PAGE_RE = /^\/c\/(r|stop)\/([A-Za-z0-9_-]{8,128})$/;
const PROBE_PATH = "/c/ping"; // the vault's link-host probe answer (confirm/egress.py)
const PAGE_MAX_BODY = 8 * 1024;
const TENANT_LEAD_SECONDS = 20;
const REFRESH_LEAD_SECONDS = 30;

function err(status: number, code: string, message: string, cookies: string[] = []): Response {
  const h = new Headers({ "content-type": "application/json", "cache-control": "no-store" });
  for (const c of cookies) h.append("set-cookie", c);
  return new Response(JSON.stringify({ error: code, message }), { status, headers: h });
}

const clean = (u: string) => u.replace(/\/+$/, "");

type Portal = { bearer: string | null; sid: string; rec: SessionRecord; mintedFor?: string };

// What the vault is asked, as the Worker: always through the Access service token, never with the browser's cookie.
function originCall(env: GatewayEnv, deps: GatewayDeps, method: string, pathAndQuery: string, headers: Headers, body?: ArrayBuffer | string): Promise<Response> {
  const h = new Headers(headers);
  for (const x of DROP_REQUEST_HEADERS) h.delete(x);
  h.set("cf-access-client-id", env.ACCESS_CLIENT_ID);
  h.set("cf-access-client-secret", env.ACCESS_CLIENT_SECRET);
  return deps.fetch(clean(env.ORIGIN_URL) + pathAndQuery, { method, headers: h, body });
}

export function vaultCaller(env: GatewayEnv, deps: GatewayDeps): (path: string, token: string | null, extra?: Record<string, string>) => Promise<Response> {
  return (path, token, extra) => originCall(env, deps, "GET", path, new Headers({ ...(token ? { authorization: `Bearer ${token}` } : {}), ...(extra ?? {}) }));
}

// The edge's signed statement of how this person signed in, for calls that carry the identity token.
async function assertionFor(env: GatewayEnv, deps: GatewayDeps, rec: SessionRecord): Promise<string> {
  const sub = tokenClaims(rec.token)?.sub ?? "";
  return signAssertion(env, rec.token, sub, rec.amr ?? [], rec.method ?? "", (deps.now ?? Date.now)(), { email: rec.email ?? null, email_verified: rec.email_verified === true }, rec.sso_connection_id && rec.sso_organization_id ? { connection: rec.sso_connection_id, organization: rec.sso_organization_id } : null);
}

async function endSession(store: SessionStore, sid: string, nowMs: number): Promise<Response> {
  await store.revoke(sid, nowMs);
  return err(401, "unauthenticated", "the session ended; sign in again", [clearCookie(SESSION_COOKIE)]);
}

function tenantFrom(res: Response, body: { org_id?: string; expires_at?: string } | null): { orgId: string; tenant: { token: string; exp: number } } | null {
  const token = res.headers.get(TENANT_TOKEN_HEADER);
  const exp = body?.expires_at ? Math.floor(Date.parse(body.expires_at) / 1000) : NaN;
  return token && body?.org_id && Number.isFinite(exp) ? { orgId: body.org_id, tenant: { token, exp } } : null;
}

// Asks the vault for a tenant token for the organization the session chose. The token is saved through the session's store,
// which accepts it only while the session still names that organization: another tab may have chosen a different one while
// the vault answered, and the stale result is neither saved over it nor used (409, the write never reaches the vault).
async function mintTenant(env: GatewayEnv, deps: GatewayDeps, store: SessionStore, p: Portal, orgId: string): Promise<Response | null> {
  const headers = new Headers({ authorization: `Bearer ${p.rec.token}`, "content-type": "application/json" });
  const assertion = await assertionFor(env, deps, p.rec);
  headers.set(ASSERTION_HEADER, assertion);
  let res: Response;
  try {
    res = await originCall(env, deps, "POST", "/v1/session/org", headers, JSON.stringify({ org_id: orgId }));
  } catch {
    return err(502, "origin_unreachable", "origin unreachable");
  }
  if (!res.ok) return new Response(res.body, { status: res.status, headers: scrub(res.headers) });
  const got = tenantFrom(res, (await res.clone().json().catch(() => null)) as { org_id?: string; expires_at?: string } | null);
  if (!got || got.orgId !== orgId) return err(502, "origin_unreachable", "the vault answered without a usable session token");
  const now = (deps.now ?? Date.now)();
  const saved = await store.adoptTenant(p.sid, orgId, got.tenant, now);
  if (saved === "gone") return err(401, "unauthenticated", "the session ended; sign in again", [clearCookie(SESSION_COOKIE)]);
  if (saved === "mismatch") return err(409, "org_mismatch", "the session's organization changed in another tab");
  const fresh = await store.load(p.sid, now);
  if (!fresh) return err(401, "unauthenticated", "the session ended; sign in again", [clearCookie(SESSION_COOKIE)]);
  p.rec = fresh;
  return null;
}

function scrub(h: Headers): Headers {
  const out = new Headers(h);
  out.delete("set-cookie");
  out.delete(TENANT_TOKEN_HEADER);
  return out;
}

// A capture through the gateway: everything is forwarded unchanged, whatever the method, bearer, size or origin; what the
// gateway noticed (the bearer's shape, the declared size, the WAF's verdict, the origin) travels as one fact header and is
// stored with the post. Only a vault that cannot be reached is answered, and then it says nothing was stored.
async function forwardCapture(request: Request, env: GatewayEnv, deps: GatewayDeps): Promise<Response> {
  const url = new URL(request.url);
  const auth = request.headers.get("authorization");
  let verdict: { status: number; code: string; message: string } | undefined;
  try {
    verdict = deps.waf ? await deps.waf(request) : undefined;
  } catch (e) {
    verdict = { status: 0, code: "waf_failed", message: (e as Error).name };
  }
  const facts = {
    bearer: !auth ? "absent" : !BEARER_RE.test(auth) ? "malformed" : auth.slice(7).startsWith("cv_site_") ? "site_key" : "well_formed",
    declared_length: request.headers.get("content-length"),
    waf: verdict ?? null,
    origin_header: request.headers.get("origin"),
    path_prefix_ok: url.pathname.startsWith("/v1/"),
    method: request.method,
    cookie_removed: request.headers.has("cookie"), // the one header not forwarded: the gateway's own portal session cookie
  };
  let body: ArrayBuffer | undefined;
  if (request.method !== "GET" && request.method !== "HEAD") body = await request.arrayBuffer();
  const headers = new Headers(request.headers);
  for (const h of ["cf-access-client-id", "cf-access-client-secret", "cf-access-jwt-assertion", "host", "connection", "cookie"]) headers.delete(h);
  headers.set("cf-access-client-id", env.ACCESS_CLIENT_ID);
  headers.set("cf-access-client-secret", env.ACCESS_CLIENT_SECRET);
  headers.set(GATEWAY_FACTS_HEADER, JSON.stringify(facts));
  // the request's own identity: the sender's, else minted here; the vault records a request once whatever number of times it arrives
  const requestId = request.headers.get("x-consentvault-request-id") || crypto.randomUUID();
  headers.set("x-consentvault-request-id", requestId);
  try {
    const res = await deps.fetch(clean(env.ORIGIN_URL) + url.pathname + url.search, { method: request.method, headers, body });
    return new Response(res.body, { status: res.status, headers: scrub(res.headers) });
  } catch (e) {
    // The vault did not answer, so it is not known whether it stored the request: the answer says so and gives the
    // fingerprint of what was sent and the request id to resend it under.
    const digest = await crypto.subtle.digest("SHA-256", body ?? new ArrayBuffer(0));
    const fingerprint = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    (deps.alarm ?? ((n, d) => console.error(`consentvault gateway alarm ${n}: ${d}`)))("capture.store_unknown", `the vault did not answer a capture (${(e as Error).name}); it is not known whether it was stored`);
    return new Response(JSON.stringify({ stored: "unknown", error: "store_unknown", body_sha256: fingerprint, request_id: requestId,
      detail: "the vault did not answer; whether it was stored is unknown; resending the same request (with x-consentvault-request-id set to this request_id, or the same signed request) is safe because a request is recorded once" }), {
      status: 503, headers: { "content-type": "application/json", "cache-control": "no-store", "access-control-allow-origin": request.headers.get("origin") || "*", vary: "origin" },
    });
  }
}

const TOKEN_ENDPOINT_PATH = "/v1/oauth/token";

function tooMany(): Response {
  return new Response(JSON.stringify({ error: "rate_limited", message: "too many requests; try again shortly" }), {
    status: 429, headers: { "content-type": "application/json", "cache-control": "no-store", "retry-after": "10" },
  });
}

function alarmOf(deps: GatewayDeps) {
  return deps.alarm ?? ((n: string, d: string) => console.error(`consentvault gateway alarm ${n}: ${d}`));
}

// The provider headers and body as the vault must see them: the edge's own credentials added, the browser's removed.
function towardVault(source: Headers, env: GatewayEnv): Headers {
  const headers = new Headers(source);
  for (const h of DROP_REQUEST_HEADERS) headers.delete(h);
  headers.delete("authorization");
  headers.delete("x-cv-org");
  headers.delete(ASSERTION_HEADER);
  headers.set("cf-access-client-id", env.ACCESS_CLIENT_ID);
  headers.set("cf-access-client-secret", env.ACCESS_CLIENT_SECRET);
  return headers;
}

async function readCapped(request: Request, max: number): Promise<ArrayBuffer | undefined> {
  const declared = request.headers.get("content-length");
  if (declared !== null && Number(declared) > max) throw new Refusal(413, "too_large", `body exceeds ${max} bytes`);
  if (request.method !== "POST") return undefined;
  const body = await request.arrayBuffer();
  if (body.byteLength > max) throw new Refusal(413, "too_large", `body exceeds ${max} bytes`);
  return body;
}

// A delivery report carries MessageStatus; a person's reply does not. Counted apart, a burst of reports never uses up the
// replies' allowance. Read from the form without changing a byte of what is forwarded.
function inboundKind(body: ArrayBuffer | undefined): "report" | "reply" {
  try {
    return new URLSearchParams(new TextDecoder().decode(body ?? new ArrayBuffer(0))).has("MessageStatus") ? "report" : "reply";
  } catch {
    return "reply";
  }
}

// The confirmation doors. Nothing here judges the request: the vault checks the provider's signature and finds a page token
// only on its organisation's verified host. No cookie, no Authorization and no session store are ever involved.
// The inbound door is NEVER refused: over its limit (or with no limiter) it forwards and raises a named alarm, because a STOP
// Twilio is told was refused is not sent again.
async function inboundDoor(request: Request, url: URL, env: GatewayEnv, deps: GatewayDeps, key: string): Promise<Response> {
  const alarm = alarmOf(deps);
  const body = await readCapped(request, INBOUND_MAX_BODY);
  const kind = inboundKind(body);
  if (!env.INBOUND_LIMITER) {
    alarm("confirmations.inbound_rate_limit_unbound", "the INBOUND_LIMITER binding is not set; the inbound door is not rate limited");
  } else if (!(await env.INBOUND_LIMITER.limit({ key: `inbound:${key}:${kind}` })).success) {
    alarm("confirmations.inbound_rate_limited", `an inbound ${kind} went over its limit and was forwarded anyway`);
  }
  let res: Response;
  try {
    res = await deps.fetch(clean(env.ORIGIN_URL) + url.pathname + url.search, { method: "POST", headers: towardVault(request.headers, env), body });
  } catch (e) {
    throw new Refusal(502, "origin_unreachable", `origin unreachable: ${(e as Error).name}`);
  }
  return new Response(res.body, { status: res.status, headers: scrub(res.headers) });
}

function b64(buf: ArrayBuffer): string {
  let bin = "";
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin);
}

function unb64(text: string): ArrayBuffer {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

// Only the vault's 2xx ends a stored post (taken, or a replay it already holds). Anything else (a refusal, 404, a redirect, 5xx
// or no answer) keeps the post, which may be a STOP, and raises an alarm: a person decides, nothing is dropped by the edge.
const taken = (status: number) => status >= 200 && status < 300;

// The vault's own named refusals at the inbound door (product confirm/inbound.py): an unsigned or wrongly signed post, a number
// that is not the account's, a body over 16 KB. Only these close a stored post as refused. Any other non-2xx (Access refusing
// the edge, 429, a 404 during a rollout or with confirmations off or when the auth token cannot be opened, a redirect, 5xx) is
// a fault: the post stays open and alarms.
const VAULT_REFUSALS: Record<number, string> = { 401: "unauthenticated", 403: "inbound_number_mismatch", 413: "inbound_too_large" };

async function vaultRefused(res: Response): Promise<boolean> {
  const want = VAULT_REFUSALS[res.status];
  const text = await res.text().catch(() => "");
  if (!want) return false;
  try {
    const body = JSON.parse(text) as { error?: unknown } | null;
    return !!body && typeof body === "object" && body.error === want;
  } catch {
    return false;
  }
}

async function count(db: D1Like, sql: string, ...args: unknown[]): Promise<number> {
  const out = await db.prepare(sql).bind(...args).all();
  return Number(out.results?.[0]?.n ?? 0);
}

async function fallbackDoor(request: Request, url: URL, env: GatewayEnv, deps: GatewayDeps, inboundKey: string): Promise<Response> {
  const alarm = alarmOf(deps);
  const body = (await readCapped(request, FALLBACK_MAX_BODY)) ?? new ArrayBuffer(0);
  const keptHeaders: Record<string, string> = {};
  for (const h of SPOOL_HEADERS) {
    const v = request.headers.get(h);
    if (v !== null) keptHeaders[h] = v;
  }
  const now = new Date((deps.now ?? Date.now)()).toISOString();
  const id = crypto.randomUUID();
  const db = env.INBOUND_SPOOL;
  let kept = false;
  if (!db) {
    alarm("confirmations.inbound_spool_unbound", "the INBOUND_SPOOL binding is not set; a fallback post is only forwarded, never stored");
  } else {
    let room = true;
    try {
      room = (await count(db, SPOOL_SQL.countKey, inboundKey)) < SPOOL_PER_KEY && (await count(db, SPOOL_SQL.countAll)) < SPOOL_TOTAL;
    } catch (e) {
      // the cap could not be read: the post is stored anyway (a STOP is kept rather than refused)
      alarm("confirmations.inbound_spool_unreadable", `the inbound store's open count could not be read (${(e as Error).message.slice(0, 80)})`);
    }
    if (!room) {
      alarm("confirmations.inbound_spool_full", `the inbound store is at its cap (${SPOOL_PER_KEY} per number, ${SPOOL_TOTAL} in all); this post is only forwarded`);
    } else {
      try {
        await db.prepare(SPOOL_SQL.insert).bind(id, inboundKey, now, url.pathname, b64(body), JSON.stringify(keptHeaders)).run();
        kept = true;
      } catch (e) {
        alarm("confirmations.inbound_spool_unwritable", `a fallback post could not be stored (${(e as Error).message.slice(0, 80)})`);
      }
    }
  }
  let res: Response | null = null;
  try {
    res = await deps.fetch(clean(env.ORIGIN_URL) + url.pathname, { method: "POST", headers: towardVault(new Headers(keptHeaders), env), body });
  } catch {
    res = null;
  }
  if (res && taken(res.status)) {
    if (kept) {
      try {
        await db!.prepare(SPOOL_SQL.markDrained).bind(now, res.status, id).run();
      } catch (e) {
        alarm("confirmations.inbound_spool_unwritable", `a delivered post could not be marked drained; the drain sends it again (${(e as Error).message.slice(0, 80)})`);
      }
    }
    return new Response(res.body, { status: res.status, headers: scrub(res.headers) });
  }
  if (kept) {
    if (res && (await vaultRefused(res))) {
      alarm("confirmations.inbound_spool_refused", `the vault refused a fallback post with ${res.status}; it is closed as refused and kept for the record`);
      try {
        await db!.prepare(SPOOL_SQL.markRefused).bind(now, res.status, id).run();
      } catch (e) {
        alarm("confirmations.inbound_spool_unwritable", `a refused post could not be closed; it stays open (${(e as Error).message.slice(0, 80)})`);
      }
    } else if (res && res.status < 500) {
      alarm("confirmations.inbound_spool_vault_fault", `the vault's door answered a fallback post ${res.status} without a named refusal; it stays stored`);
    } else alarm("confirmations.inbound_spooled", "the vault did not take a fallback post; it is stored at the edge and delivered by the drain");
    return new Response(JSON.stringify({ received: true, kept: true }), { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } });
  }
  if (res) return new Response(res.body, { status: res.status, headers: scrub(res.headers) });
  return err(503, "store_unavailable", "the post could be neither stored nor delivered; nothing was recorded");
}

/** The cron's drain, every minute: each open row goes to the vault's fallback door again, oldest first; only a 2xx marks it
 * drained. Every store error is a named alarm; nothing here throws. */
export async function drainInboundSpool(env: GatewayEnv, deps: GatewayDeps): Promise<{ delivered: number; kept: number }> {
  const alarm = alarmOf(deps);
  const db = env.INBOUND_SPOOL;
  if (!db) {
    alarm("confirmations.inbound_spool_unbound", "the INBOUND_SPOOL binding is not set; nothing to drain");
    return { delivered: 0, kept: 0 };
  }
  const nowMs = (deps.now ?? Date.now)();
  const nowIso = new Date(nowMs).toISOString();
  let rows: Record<string, unknown>[];
  try {
    rows = (await db.prepare(SPOOL_SQL.pending).bind().all()).results ?? [];
  } catch (e) {
    alarm("confirmations.inbound_spool_unreadable", `the drain could not read the inbound store (${(e as Error).message.slice(0, 80)})`);
    return { delivered: 0, kept: 0 };
  }
  let delivered = 0;
  let kept = 0;
  let refused = 0;
  let faults = 0;
  let stale = 0;
  for (const row of rows) {
    if (nowMs - Date.parse(String(row.received_at)) > STALE_AFTER_MS) stale++;
    let headers: Record<string, string>;
    let body: ArrayBuffer;
    try {
      headers = JSON.parse(String(row.headers_json)) as Record<string, string>;
      body = unb64(String(row.body_b64));
    } catch {
      alarm("confirmations.inbound_spool_unreadable", `stored post ${String(row.id)} is not readable; it is left for a person`);
      kept++;
      continue;
    }
    let status = 0;
    let refusedByName = false;
    try {
      const res = await deps.fetch(clean(env.ORIGIN_URL) + String(row.path), { method: "POST", headers: towardVault(new Headers(headers), env), body });
      status = res.status;
      if (taken(status)) await res.body?.cancel();
      else refusedByName = await vaultRefused(res);
    } catch {
      status = 0; // no answer: kept, and no write spent on the attempt
    }
    try {
      if (taken(status)) {
        await db.prepare(SPOOL_SQL.markDrained).bind(nowIso, status, String(row.id)).run();
        delivered++;
        continue;
      }
      if (refusedByName) {
        refused++;
        await db.prepare(SPOOL_SQL.markRefused).bind(nowIso, status, String(row.id)).run();
        continue;
      }
      if (status > 0 && status < 500) faults++;
      if (status > 0) await db.prepare(SPOOL_SQL.markAttempt).bind(status, String(row.id)).run();
    } catch (e) {
      alarm("confirmations.inbound_spool_unwritable", `stored post ${String(row.id)} could not be marked (${(e as Error).message.slice(0, 80)}); it is sent again next run`);
    }
    kept++;
  }
  if (stale) alarm("confirmations.inbound_spool_stale", `${stale} stored inbound post(s) are older than 10 minutes`);
  if (refused) alarm("confirmations.inbound_spool_refused", `${refused} stored inbound post(s) were refused by the vault; closed as refused and kept for the record`);
  if (faults) alarm("confirmations.inbound_spool_vault_fault", `${faults} stored inbound post(s) were answered without a named refusal (Access, a rate limit, a missing route); they stay open`);
  if (kept) alarm("confirmations.inbound_spool_waiting", `${kept} stored inbound post(s) still wait for the vault`);
  try {
    await db.prepare(SPOOL_SQL.purge).bind(new Date(nowMs - KEEP_DRAINED_MS).toISOString()).run();
  } catch (e) {
    alarm("confirmations.inbound_spool_unwritable", `drained rows could not be purged (${(e as Error).message.slice(0, 80)})`);
  }
  return { delivered, kept };
}

const REPLAY_PATH = "/ops/inbound-spool/replay";
const REPLAY_MAX_WINDOW_MS = 7 * 24 * 3600_000;

async function sameSecret(given: string, want: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(given)), crypto.subtle.digest("SHA-256", enc.encode(want))]);
  const x = new Uint8Array(a), y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// The operator's replay, after the Twilio auth token was changed: rows the vault refused (with the old token's signatures read
// against the new one, or the reverse) inside the window are posted to the vault again; each is marked by the answer: 2xx
// drained, the named refusal again refused (attempts counted), anything else left refused and counted as a fault.
async function replayRefused(request: Request, env: GatewayEnv, deps: GatewayDeps): Promise<Response> {
  const alarm = alarmOf(deps);
  if (!env.OPS_REPLAY_SECRET) throw new Refusal(404, "not_found", "no such route");
  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ") || !(await sameSecret(auth.slice(7), env.OPS_REPLAY_SECRET))) throw new Refusal(401, "unauthenticated", "the operator bearer is required");
  const db = env.INBOUND_SPOOL;
  if (!db) throw new Refusal(503, "store_unavailable", "the INBOUND_SPOOL binding is not set");
  const raw = await readCapped(request, 1024);
  let from = NaN, to = NaN;
  try {
    const b = JSON.parse(new TextDecoder().decode(raw ?? new ArrayBuffer(0))) as { from?: string; to?: string };
    from = Date.parse(String(b.from)); to = Date.parse(String(b.to));
  } catch {
    // named below
  }
  if (!Number.isFinite(from) || !Number.isFinite(to) || to < from || to - from > REPLAY_MAX_WINDOW_MS) {
    throw new Refusal(400, "invalid_window", "send {from, to} as ISO times, to after from, at most 7 days apart");
  }
  let rows: Record<string, unknown>[];
  try {
    rows = (await db.prepare(SPOOL_SQL.refusedInWindow).bind(new Date(from).toISOString(), new Date(to).toISOString()).all()).results ?? [];
  } catch (e) {
    alarm("confirmations.inbound_spool_unreadable", `the replay could not read the inbound store (${(e as Error).message.slice(0, 80)})`);
    throw new Refusal(503, "store_unavailable", "the inbound store could not be read; nothing was replayed");
  }
  const nowIso = new Date((deps.now ?? Date.now)()).toISOString();
  let delivered = 0, refused = 0, faults = 0;
  for (const row of rows) {
    let status = 0, named = false;
    try {
      const res = await deps.fetch(clean(env.ORIGIN_URL) + String(row.path), { method: "POST", headers: towardVault(new Headers(JSON.parse(String(row.headers_json)) as Record<string, string>), env), body: unb64(String(row.body_b64)) });
      status = res.status;
      if (taken(status)) await res.body?.cancel();
      else named = await vaultRefused(res);
    } catch {
      status = 0;
    }
    try {
      if (taken(status)) { await db.prepare(SPOOL_SQL.markDrained).bind(nowIso, status, String(row.id)).run(); delivered++; continue; }
      if (named) { await db.prepare(SPOOL_SQL.markRefused).bind(nowIso, status, String(row.id)).run(); refused++; continue; }
      if (status > 0) await db.prepare(SPOOL_SQL.markAttempt).bind(status, String(row.id)).run();
    } catch (e) {
      alarm("confirmations.inbound_spool_unwritable", `replayed post ${String(row.id)} could not be marked (${(e as Error).message.slice(0, 80)})`);
    }
    faults++;
  }
  if (refused) alarm("confirmations.inbound_spool_refused", `${refused} replayed post(s) were refused again; check the stored auth token`);
  if (faults) alarm("confirmations.inbound_spool_vault_fault", `${faults} replayed post(s) got no answer or a fault; they stay refused for another replay`);
  return new Response(JSON.stringify({ replayed: rows.length, delivered, refused, faults }), { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

async function pageDoor(request: Request, url: URL, env: GatewayEnv, deps: GatewayDeps, key: string): Promise<Response> {
  if (!env.PAGE_LIMITER) {
    alarmOf(deps)("confirmations.page_rate_limit_unbound", "the PAGE_LIMITER binding is not set; the pages are not rate limited");
  } else if (!(await env.PAGE_LIMITER.limit({ key })).success) {
    return tooMany();
  }
  const body = await readCapped(request, PAGE_MAX_BODY);
  const headers = towardVault(request.headers, env);
  headers.set(LINK_HOST_HEADER, url.hostname.toLowerCase());
  let res: Response;
  try {
    res = await deps.fetch(clean(env.ORIGIN_URL) + url.pathname + url.search, { method: request.method, headers, body });
  } catch (e) {
    throw new Refusal(502, "origin_unreachable", `origin unreachable: ${(e as Error).name}`);
  }
  return new Response(res.body, { status: res.status, headers: scrub(res.headers) });
}

export async function handleGateway(request: Request, env: GatewayEnv, deps: GatewayDeps): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (isCapturePath(url.pathname)) {
      if (!env.ORIGIN_URL || !env.ACCESS_CLIENT_ID || !env.ACCESS_CLIENT_SECRET) {
        (deps.alarm ?? ((n, d) => console.error(`consentvault gateway alarm ${n}: ${d}`)))("capture.store_unavailable", "the gateway has no origin address or Access token; nothing was stored");
        return new Response(JSON.stringify({ stored: false, error: "store_unavailable", detail: "the record store could not be written; nothing was stored; send again" }), {
          status: 503, headers: { "content-type": "application/json", "cache-control": "no-store", "access-control-allow-origin": request.headers.get("origin") || "*", vary: "origin" },
        });
      }
      return await forwardCapture(request, env, deps);
    }
    for (const k of ["ORIGIN_URL", "ACCESS_CLIENT_ID", "ACCESS_CLIENT_SECRET"] as const) {
      if (!env[k]) throw new Refusal(500, "misconfigured", `gateway setting ${k} is not set`);
    }
    const inbound = INBOUND_RE.exec(url.pathname);
    if (inbound && request.method === "POST") return await inboundDoor(request, url, env, deps, inbound[1]);
    if (url.pathname === REPLAY_PATH && request.method === "POST") return await replayRefused(request, env, deps);
    const fallback = FALLBACK_RE.exec(url.pathname);
    if (fallback && request.method === "POST") return await fallbackDoor(request, url, env, deps, fallback[1]);
    const page = PAGE_RE.exec(url.pathname);
    if (page || url.pathname === PROBE_PATH) {
      const allowed = request.method === "GET" || (request.method === "POST" && page?.[1] === "stop");
      if (!allowed) throw new Refusal(405, "method_not_allowed", "method not allowed");
      // A stop posted to the stop page (the email's one-click unsubscribe, sent by the mail provider's servers) is counted per
      // token, never per client address: many people's stops can come from one address.
      const key = request.method === "POST" ? `stop:${page![2]}` : `page:${request.headers.get("cf-connecting-ip") || "unknown"}`;
      return await pageDoor(request, url, env, deps, key);
    }
    if (!url.pathname.startsWith("/v1/")) throw new Refusal(404, "not_found", "no such route");
    if (!ALLOWED_METHODS.includes(request.method)) throw new Refusal(405, "method_not_allowed", "method not allowed");

    const auth = request.headers.get("authorization");
    const cookieHeader = request.headers.get("cookie");
    const downloadLink = request.method === "GET" && (DOWNLOAD_RE.test(url.pathname) || INVITE_VIEW_RE.test(url.pathname));
    const twentyWebhook = request.method === "POST" && (TWENTY_WEBHOOK_RE.test(url.pathname) || url.pathname === STRIPE_WEBHOOK_PATH);
    const tokenEndpoint = request.method === "POST" && url.pathname === TOKEN_ENDPOINT_PATH; // the client proves itself with a signed assertion in the form, not a bearer
    const portalMode = !auth && !downloadLink && !twentyWebhook && !tokenEndpoint && !!env.SESSIONS && !!cookieValue(cookieHeader, SESSION_COOKIE);
    if (!auth && !portalMode && !downloadLink && !twentyWebhook && !tokenEndpoint) throw new Refusal(401, "bearer_missing", "an Authorization: Bearer token is required");
    if (auth && !twentyWebhook && !tokenEndpoint) {
      if (!BEARER_RE.test(auth)) throw new Refusal(401, "bearer_malformed", "Authorization header is not a well-formed bearer token");
      if (auth.slice(7).startsWith("cv_site_")) throw new Refusal(401, "site_key_not_accepted", "site keys are accepted only at the capture endpoint");
    }

    const max = twentyWebhook ? Math.min(TWENTY_WEBHOOK_MAX_BODY, Number(env.MAX_BODY_BYTES || DEFAULT_MAX_BODY)) : Number(env.MAX_BODY_BYTES || DEFAULT_MAX_BODY);
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
    headers.delete("x-cv-org");
    headers.delete(ASSERTION_HEADER); // only the edge's own signature may speak for how someone signed in
    if (downloadLink || twentyWebhook || tokenEndpoint) headers.delete("authorization");

    let portal: Portal | null = null;
    let store: SessionStore | null = null;
    if (portalMode) {
      for (const k of ["AUTH_BASE_URL", "AUTH_CLIENT_ID", "PUBLIC_URL"] as const) {
        if (!env[k]) throw new Refusal(500, "misconfigured", `gateway setting ${k} is not set`);
      }
      if (request.method !== "GET" && request.headers.get("origin") !== clean(env.PUBLIC_URL!)) {
        throw new Refusal(403, "origin_refused", "a request that changes data must come from the portal's own origin");
      }
      const bad = assertionConfigError(env);
      if (bad) throw new Refusal(500, "misconfigured", bad);
      store = sessionStoreFor({ SESSIONS: env.SESSIONS!, SESSION_GATE: env.SESSION_GATE, AUTH_BASE_URL: env.AUTH_BASE_URL!, AUTH_CLIENT_ID: env.AUTH_CLIENT_ID!, AUTH_CLIENT_SECRET: env.AUTH_CLIENT_SECRET }, deps.fetch);
      const sid = cookieValue(cookieHeader, SESSION_COOKIE)!;
      const now = (deps.now ?? Date.now)();
      const rec = await store.load(sid, now);
      if (!rec) return err(401, "unauthenticated", "no sign-in for this browser", [clearCookie(SESSION_COOKIE)]);
      portal = { bearer: null, sid, rec };
      if (portal.rec.token_exp - now / 1000 < REFRESH_LEAD_SECONDS) {
        const next = await store.refresh(sid, now, REFRESH_LEAD_SECONDS);
        if (!next) return endSession(store, sid, now);
        portal.rec = next;
      }
      const identityRoute = (request.method === "GET" && url.pathname === "/v1/session") ||
        (request.method === "POST" && url.pathname === "/v1/session/org") ||
        (request.method === "POST" && ACCEPT_RE.test(url.pathname)) ||
        (request.method === "GET" && url.pathname === "/v1/session/current-org" && !portal.rec.org_id);
      if (identityRoute) {
        portal.bearer = portal.rec.token;
      } else {
        if (!portal.rec.org_id) return err(409, "no_org_selected", "no organization is chosen for this session; choose one with POST /v1/session/org");
        // The session holds one chosen organization shared by every tab, so each request names the one its tab shows.
        // A read from a tab that has not learned its organization yet (a fresh page load) may omit it and learns it from the
        // answer; a write must always name it, and a named organization that differs is refused.
        const named = request.headers.get("x-cv-org");
        if (named ? named !== portal.rec.org_id : request.method !== "GET") return err(409, "org_mismatch", "this tab shows a different organization than the session's; reload to continue");
        if (!portal.rec.tenant || portal.rec.tenant.exp - now / 1000 < TENANT_LEAD_SECONDS) {
          const refused = await mintTenant(env, deps, store!, portal, portal.rec.org_id);
          if (refused) return refused;
        }
        portal.bearer = portal.rec.tenant!.token;
      }
      headers.set("authorization", `Bearer ${portal.bearer}`);
      if (identityRoute) headers.set(ASSERTION_HEADER, await assertionFor(env, deps, portal.rec));
    }

    let res: Response;
    try {
      res = await deps.fetch(clean(env.ORIGIN_URL) + url.pathname + url.search, { method: request.method, headers, body });
    } catch (e) {
      throw new Refusal(502, "origin_unreachable", `origin unreachable: ${(e as Error).name}`);
    }
    if (portal && store && request.method === "POST" && url.pathname === "/v1/session/org" && res.ok) {
      const got = tenantFrom(res, (await res.clone().json().catch(() => null)) as { org_id?: string; expires_at?: string } | null);
      if (!got || !(await store.chooseOrg(portal.sid, got.orgId, got.tenant, (deps.now ?? Date.now)()))) {
        return err(502, "origin_unreachable", "the vault answered without a usable session token");
      }
    }
    return new Response(res.body, { status: res.status, headers: scrub(res.headers) });
  } catch (e) {
    if (e instanceof Refusal) return err(e.status, e.code, e.message);
    if (e instanceof MisconfiguredError) return err(500, "misconfigured", e.message);
    if (e instanceof StoreUnavailable) return err(503, "session_unavailable", "the session store did not answer; nothing was changed");
    return err(500, "internal", "gateway failure");
  }
}

export default {
  async fetch(request: Request, env: GatewayEnv): Promise<Response> {
    return handleGateway(request, env, { fetch: (...a) => fetch(...a) });
  },
  // Every minute (wrangler [triggers] crons): deliver what the fallback door stored while the vault was away.
  async scheduled(_event: unknown, env: GatewayEnv): Promise<void> {
    await drainInboundSpool(env, { fetch: (...a) => fetch(...a) });
  },
};
