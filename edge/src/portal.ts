// Portal Worker: the dashboard's one public door. /auth/* is sign-in (auth.ts), /v1/* is the gateway with session
// cookies (gateway.ts), everything else is the dashboard's static export.

import { handleAuth } from "./auth.ts";
import { handleGateway, vaultCaller, type GatewayDeps, type GatewayEnv } from "./gateway.ts";
import { cookieValue, SESSION_COOKIE, type KV } from "./session.ts";
import { sessionStoreFor } from "./session-store.ts";
import { callWake, type WakeEnv } from "./wake.ts";

export { SessionGate } from "./session-gate.ts";

export interface PortalEnv extends GatewayEnv, WakeEnv {
  AUTH_BASE_URL: string;
  AUTH_CLIENT_ID: string;
  PUBLIC_URL: string;
  SESSIONS: KV;
  ASSETS: { fetch(request: Request): Promise<Response> };
}

// The vault is parked when nobody has asked for it: the tunnel has no connector (Cloudflare answers 530, or 521 to 524, or 502
// and 504) or the call never connects. The vault's own 503 (a gate that fails closed) is an answer, not a parked vault.
const PARKED_STATUSES = new Set([502, 504, 520, 521, 522, 523, 524, 525, 526, 527, 530]);
export const WAKE_MARKER = "cv:wake:requested";
export const WAKE_MARKER_SECONDS = 120; // Workers KV accepts no expiry under 60 seconds
export const UP_CACHE_MS = 60_000;
export const WAKE_DAILY_CAP = 20;
const WAKE_DAY_KEY = "cv:wake:day:";
const lastUp = new WeakMap<object, number>();
const clean = (u: string) => u.replace(/\/+$/, "");

async function vaultParked(env: PortalEnv, deps: GatewayDeps, nowMs: number): Promise<boolean> {
  if (!env.ORIGIN_URL || !env.ACCESS_CLIENT_ID || !env.ACCESS_CLIENT_SECRET) return false; // a misconfiguration is the gateway's named error
  const seen = lastUp.get(env);
  if (seen !== undefined && nowMs - seen < UP_CACHE_MS) return false;
  try {
    const res = await deps.fetch(clean(env.ORIGIN_URL) + "/v1/health", {
      method: "GET",
      headers: { "cf-access-client-id": env.ACCESS_CLIENT_ID, "cf-access-client-secret": env.ACCESS_CLIENT_SECRET },
      signal: AbortSignal.timeout(5000),
    });
    await res.body?.cancel();
    if (PARKED_STATUSES.has(res.status)) return true;
    lastUp.set(env, nowMs);
    return false;
  } catch {
    return true;
  }
}

const esc = (t: string) => t.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

function startingResponse(wantsHtml: boolean, started: boolean, detail: string): Response {
  const message = started
    ? "ConsentVault is starting, about two minutes. This page refreshes itself."
    : "ConsentVault could not be started. The team has been alerted. Try again in a few minutes.";
  if (!wantsHtml) {
    return new Response(JSON.stringify({ error: started ? "vault_starting" : "vault_wake_failed", message, detail }), {
      status: 503, headers: { "content-type": "application/json", "cache-control": "no-store", ...(started ? { "retry-after": "15" } : {}) },
    });
  }
  const refresh = started ? '<meta http-equiv="refresh" content="15">' : "";
  const title = started ? "ConsentVault is starting" : "ConsentVault could not be started";
  const body = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">${refresh}<title>${esc(title)}</title>` +
    `<main style="font-family:system-ui,sans-serif;max-width:32rem;margin:20vh auto;padding:0 1.5rem"><h1>${esc(title)}</h1><p>${esc(message)}</p></main>`;
  return new Response(body, { status: 503, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...(started ? { "retry-after": "15" } : {}) } });
}

async function signedInPerson(request: Request, env: PortalEnv, deps: GatewayDeps, nowMs: number): Promise<boolean> {
  try {
    const sid = cookieValue(request.headers.get("cookie"), SESSION_COOKIE);
    if (!sid) return false;
    // The record lives wherever the session store keeps it (the session's Durable Object in production), never assumed to be the key-value copy.
    const rec = await sessionStoreFor({ SESSIONS: env.SESSIONS, SESSION_GATE: env.SESSION_GATE, AUTH_BASE_URL: env.AUTH_BASE_URL!, AUTH_CLIENT_ID: env.AUTH_CLIENT_ID!, AUTH_CLIENT_SECRET: env.AUTH_CLIENT_SECRET }, deps.fetch).load(sid, nowMs);
    return !!rec && rec.until * 1000 > nowMs;
  } catch (e) {
    console.error(`consentvault portal SESSION_UNREADABLE: ${(e as Error).name}; treated as not signed in, no wake asked`);
    return false;
  }
}

// The vault is parked: ask for it once per cold period (a marker in the session store, which expires), say so, and never
// pretend a failed wake is a start. A failed wake is logged by name and leaves no marker, so the next request tries again.
async function whileParked(request: Request, env: PortalEnv, deps: GatewayDeps, nowMs: number): Promise<Response> {
  const url = new URL(request.url);
  const wantsHtml = (request.headers.get("accept") ?? "").includes("text/html") && !url.pathname.startsWith("/v1/");
  lastUp.delete(env);
  // Only a person with a live sign-in may start the servers. A visitor without one, and a crawler, trigger nothing and are
  // never told the vault is starting (nothing would start it): a page goes to sign-in, a JSON call is told to sign in.
  if (!(await signedInPerson(request, env, deps, nowMs))) {
    if (!wantsHtml) return new Response(JSON.stringify({ error: "signin_required" }), { status: 401, headers: { "content-type": "application/json", "cache-control": "no-store" } });
    return new Response(null, { status: 302, headers: { location: "/auth/login?return=" + encodeURIComponent(url.pathname + url.search), "cache-control": "no-store" } });
  }
  return wakeOnce(env, deps, nowMs, wantsHtml);
}

// Ask for the vault once per cold period through the counted path (marker, daily cap), and say what happened.
async function wakeOnce(env: PortalEnv, deps: GatewayDeps, nowMs: number, wantsHtml: boolean): Promise<Response> {
  let marked: string | null = null;
  try { marked = await env.SESSIONS.get(WAKE_MARKER); } catch (e) { console.error(`consentvault portal WAKE_MARKER_UNREADABLE: ${(e as Error).name}; asking for a wake anyway`); }
  if (!marked) {
    const day = WAKE_DAY_KEY + new Date(nowMs).toISOString().slice(0, 10);
    let used = 0;
    try { used = Number(await env.SESSIONS.get(day)) || 0; } catch (e) { console.error(`consentvault portal WAKE_COUNTER_UNREADABLE: ${(e as Error).name}; the daily cap cannot be checked, no wake was asked`); return startingResponse(wantsHtml, false, "the daily wake counter could not be read"); }
    if (used >= WAKE_DAILY_CAP) {
      console.error(`consentvault portal WAKE_CAP_REACHED: ${used} wakes already asked today (cap ${WAKE_DAILY_CAP}); no further wake until tomorrow`);
      return startingResponse(wantsHtml, false, `the daily cap of ${WAKE_DAILY_CAP} wakes was reached`);
    }
    try { await env.SESSIONS.put(day, String(used + 1), { expirationTtl: 2 * 86400 }); } catch (e) { console.error(`consentvault portal WAKE_COUNTER_UNWRITABLE: ${(e as Error).name}; no wake was asked`); return startingResponse(wantsHtml, false, "the daily wake counter could not be written"); }
    const woke = await callWake(env, deps.fetch, nowMs);
    if (!woke.ok) {
      console.error(`consentvault portal WAKE_FAILED: ${woke.reason}`);
      return startingResponse(wantsHtml, false, woke.reason);
    }
    try { await env.SESSIONS.put(WAKE_MARKER, new Date(nowMs).toISOString(), { expirationTtl: WAKE_MARKER_SECONDS }); } catch (e) { console.error(`consentvault portal WAKE_MARKER_UNWRITABLE: ${(e as Error).name}; the next request will ask again`); }
  }
  return startingResponse(wantsHtml, true, "");
}

// A sign-in that just finished: if the vault is parked, ask for it so the person lands on "starting" that actually starts.
// A sign-in the parked vault kept from finishing (the edge cannot check it with the vault) is told so by name, with the
// wake asked, instead of the generic failure.
async function afterCallback(res: Response, env: PortalEnv, deps: GatewayDeps, now: () => number): Promise<Response> {
  const created = res.status === 302 && res.headers.getSetCookie().some((c) => c.startsWith(SESSION_COOKIE + "="));
  const unfinished = res.status === 502;
  if (!created && !unfinished) return res;
  if (!(await vaultParked(env, deps, now()))) return res;
  lastUp.delete(env);
  const woke = await wakeOnce(env, deps, now(), true);
  if (created) return res;
  const started = woke.status === 503 && !(await woke.clone().text()).includes("could not be started");
  const message = started
    ? "Your sign-in could not be finished because ConsentVault was asleep. It is starting now, about two minutes. Then sign in again."
    : "Your sign-in could not be finished and ConsentVault could not be started. The team has been alerted. Try again in a few minutes.";
  const title = started ? "ConsentVault is starting" : "ConsentVault could not be started";
  return new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>` +
    `<main style="font-family:system-ui,sans-serif;max-width:32rem;margin:20vh auto;padding:0 1.5rem"><h1>${esc(title)}</h1><p>${esc(message)}</p><p><a href="/auth/login">Sign in again</a></p></main>`,
    { status: 503, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

export async function handlePortal(request: Request, env: PortalEnv, deps: GatewayDeps): Promise<Response> {
  const path = new URL(request.url).pathname;
  const now = deps.now ?? Date.now;
  const accept = request.headers.get("accept") ?? "";
  const navigation = request.method === "GET" && accept.includes("text/html");
  const asksJson = path.startsWith("/v1/") && accept.includes("application/json");
  if (path.startsWith("/auth/")) {
    // Sign-in is never behind the parked check: it is how a signed-out person gets the right to wake the vault.
    const res = await handleAuth(request, env, { fetch: deps.fetch, now, vault: vaultCaller(env, deps) });
    if (res) return path === "/auth/callback" ? afterCallback(res, env, deps, now) : res;
  }
  if ((navigation || asksJson) && (await vaultParked(env, deps, now()))) return whileParked(request, env, deps, now());
  if (path.startsWith("/v1/")) {
    const res = await handleGateway(request, env, deps);
    // A call that did not ask for JSON still finds out the vault is parked when the gateway cannot reach it.
    if (res.status === 502 && (await res.clone().json().catch(() => null) as { error?: string } | null)?.error === "origin_unreachable") return whileParked(request, env, deps, now());
    return res;
  }
  if (!env.ASSETS) return new Response(JSON.stringify({ error: "misconfigured", message: "the dashboard static host is not bound" }), { status: 500, headers: { "content-type": "application/json" } });
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request: Request, env: PortalEnv): Promise<Response> {
    return handlePortal(request, env, { fetch: (...a) => fetch(...a) });
  },
};
