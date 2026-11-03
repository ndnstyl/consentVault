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
  // One Durable Object per session owns the session record and is its only writer (see session-gate.ts); optional.
  SESSION_GATE?: GateNamespace;
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
const DROP_REQUEST_HEADERS = ["cf-access-client-id", "cf-access-client-secret", "cf-access-jwt-assertion", "host", "connection", "x-forwarded-for", "cookie"];
const ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const DOWNLOAD_RE = /^\/v1\/exports\/[0-9a-fA-F-]{36}\/download$/; // the signed one-time link is the credential
const INVITE_VIEW_RE = /^\/v1\/invites\/[^/:]+$/; // the public view of an invitation, read before the person has joined
const ACCEPT_RE = /^\/v1\/invites\/[^/]+:accept$/;
// The Twenty receiver (twenty.md 3.1): the signature over the raw body is the credential, so no bearer; 256 KB at most.
const TWENTY_WEBHOOK_RE = /^\/v1\/connectors\/twenty\/[A-Za-z0-9_-]{1,128}\/webhook$/;
// Stripe's live webhook: the Stripe-Signature over the raw body is the credential, so no bearer; this one exact path and method.
const STRIPE_WEBHOOK_PATH = "/v1/billing/webhook";
const TWENTY_WEBHOOK_MAX_BODY = 256 * 1024;
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
  try {
    const res = await deps.fetch(clean(env.ORIGIN_URL) + url.pathname + url.search, { method: request.method, headers, body });
    return new Response(res.body, { status: res.status, headers: scrub(res.headers) });
  } catch (e) {
    (deps.alarm ?? ((n, d) => console.error(`consentvault gateway alarm ${n}: ${d}`)))("capture.store_unavailable", `the vault did not answer a capture (${(e as Error).name}); nothing was stored`);
    return new Response(JSON.stringify({ stored: false, error: "store_unavailable", detail: "the record store could not be written; nothing was stored; send again" }), {
      status: 503, headers: { "content-type": "application/json", "cache-control": "no-store", "access-control-allow-origin": request.headers.get("origin") || "*", vary: "origin" },
    });
  }
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
    if (!url.pathname.startsWith("/v1/")) throw new Refusal(404, "not_found", "no such route");
    if (!ALLOWED_METHODS.includes(request.method)) throw new Refusal(405, "method_not_allowed", "method not allowed");

    const auth = request.headers.get("authorization");
    const cookieHeader = request.headers.get("cookie");
    const downloadLink = request.method === "GET" && (DOWNLOAD_RE.test(url.pathname) || INVITE_VIEW_RE.test(url.pathname));
    const twentyWebhook = request.method === "POST" && (TWENTY_WEBHOOK_RE.test(url.pathname) || url.pathname === STRIPE_WEBHOOK_PATH);
    const portalMode = !auth && !downloadLink && !twentyWebhook && !!env.SESSIONS && !!cookieValue(cookieHeader, SESSION_COOKIE);
    if (!auth && !portalMode && !downloadLink && !twentyWebhook) throw new Refusal(401, "bearer_missing", "an Authorization: Bearer token is required");
    if (auth && !twentyWebhook) {
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
    if (downloadLink || twentyWebhook) headers.delete("authorization");

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
};
