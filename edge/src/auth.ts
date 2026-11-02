// Portal sign-in routes for the edge Worker: /auth/login, /auth/callback, /auth/logout.
// The browser never sees the identity provider's tokens: the Worker runs the authorization code flow (PKCE and state),
// exchanges the code server to server, checks the token with the vault, and gives the browser one opaque session
// cookie. Contract: contracts/session.md, "Sign-in, sign-out and callback are edge routes".

import { ASSERTION_HEADER, MisconfiguredError, amrFromExchange, assertionConfigError, signAssertion, ssoFromExchange, whoFromExchange, type ExchangeAnswer } from "./assertion.ts";
import { StoreUnavailable, sessionStoreFor, type GateNamespace } from "./session-store.ts";
import {
  LOGIN_COOKIE, LOGIN_SECONDS, SESSION_COOKIE, SESSION_SECONDS, b64url, clearCookie, cookieValue, loginKey,
  randomToken, setCookie, sha256Hex, tokenClaims, type KV, type SessionRecord,
} from "./session.ts";

export interface AuthEnv {
  AUTH_BASE_URL: string;        // the provider's user-management base, e.g. https://api.workos.com/user_management
  AUTH_CLIENT_ID: string;
  AUTH_CLIENT_SECRET?: string;
  PUBLIC_URL: string;           // the portal's own origin; the redirect address is built from it, never from a header
  SESSIONS: KV;
  SESSION_GATE?: GateNamespace; // one Durable Object per session owns the session record (session-gate.ts)
  ASSERTION_KEY_JWK?: string;   // the edge's private ES256 key (a secret); the vault holds only the public half
}

export interface AuthDeps {
  fetch: typeof fetch;
  now: () => number;            // milliseconds
  // A call to the vault with the identity token as bearer (the Worker adds the origin and the Access service token).
  vault: (path: string, token: string | null, headers?: Record<string, string>) => Promise<Response>;
}

// Passkey, and "your company" (the hosted page sends a company address to its SSO connection). No personal Google or Microsoft.
const PROVIDERS: Record<string, string> = { passkey: "authkit", sso: "authkit" };

export function safeReturn(raw: string | null): string {
  if (!raw || !raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\") || /[\u0000-\u001f]/.test(raw)) return "/";
  return raw;
}

function page(status: number, title: string, detail: string, extra: string[] = []): Response {
  const h = new Headers({ "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  for (const c of extra) h.append("set-cookie", c);
  const esc = (t: string) => t.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
  return new Response(`<!doctype html><meta charset="utf-8"><title>${esc(title)}</title><h1>${esc(title)}</h1><p>${esc(detail)}</p><p><a href="/auth/login">Sign in again</a></p>`, { status, headers: h });
}

// A page that asked for JSON (the dashboard's own sign-out call) gets the address in the body instead of a redirect: the
// dashboard's form-action policy would block a form post that is redirected to the identity provider's address.
function redirect(location: string, cookies: string[] = [], asked?: Request): Response {
  const h = new Headers({ "cache-control": "no-store" });
  for (const c of cookies) h.append("set-cookie", c);
  if (asked?.headers.get("accept")?.includes("application/json")) {
    h.set("content-type", "application/json");
    return new Response(JSON.stringify({ redirect: location }), { status: 200, headers: h });
  }
  h.set("location", location);
  return new Response(null, { status: 302, headers: h });
}

const clean = (u: string) => u.replace(/\/+$/, "");

async function login(request: Request, env: AuthEnv, deps: AuthDeps): Promise<Response> {
  const q = new URL(request.url).searchParams;
  const state = randomToken(32);
  const verifier = randomToken(48);
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  await env.SESSIONS.put(await loginKey(state), JSON.stringify({ verifier, ret: safeReturn(q.get("return")) }), { expirationTtl: LOGIN_SECONDS });
  const to = new URL(clean(env.AUTH_BASE_URL) + "/authorize");
  to.searchParams.set("client_id", env.AUTH_CLIENT_ID);
  to.searchParams.set("redirect_uri", clean(env.PUBLIC_URL) + "/auth/callback");
  to.searchParams.set("response_type", "code");
  to.searchParams.set("provider", PROVIDERS[q.get("method") ?? ""] ?? "authkit");
  to.searchParams.set("state", state);
  to.searchParams.set("code_challenge", challenge);
  to.searchParams.set("code_challenge_method", "S256");
  return redirect(to.toString(), [setCookie(LOGIN_COOKIE, state, LOGIN_SECONDS)]);
}

async function callback(request: Request, env: AuthEnv, deps: AuthDeps): Promise<Response | null> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  if (!code && !url.searchParams.get("error")) return null; // the portal's own callback page
  const spent = clearCookie(LOGIN_COOKIE);
  if (!code) return redirect("/sign-in", [spent]);

  const state = url.searchParams.get("state") ?? "";
  const bound = cookieValue(request.headers.get("cookie"), LOGIN_COOKIE);
  const key = await loginKey(state);
  const raw = state && bound === state ? await env.SESSIONS.get(key) : null;
  if (!raw) return page(400, "Sign-in could not be completed", "The sign-in attempt was not started in this browser, or it was already used.", [spent]);
  await env.SESSIONS.delete(key); // single use
  const { verifier, ret } = JSON.parse(raw) as { verifier: string; ret: string };

  let tokens: { id_token?: string; access_token?: string; refresh_token?: string } & ExchangeAnswer;
  try {
    const res = await deps.fetch(clean(env.AUTH_BASE_URL) + "/authenticate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_id: env.AUTH_CLIENT_ID, ...(env.AUTH_CLIENT_SECRET ? { client_secret: env.AUTH_CLIENT_SECRET } : {}), grant_type: "authorization_code", code, code_verifier: verifier }),
    });
    if (!res.ok) return page(401, "Sign-in was refused", "The identity provider did not accept the sign-in.", [spent]);
    tokens = (await res.json()) as typeof tokens;
  } catch {
    return page(502, "Sign-in is unavailable", "The identity provider could not be reached.", [spent]);
  }
  const token = tokens.id_token ?? tokens.access_token;
  const claims = token ? tokenClaims(token) : null;
  if (!token || !claims) return page(502, "Sign-in is unavailable", "The identity provider answered without a usable token.", [spent]);

  const amr = amrFromExchange(tokens);
  const who = whoFromExchange(tokens);
  const sso = ssoFromExchange(tokens);
  const method = typeof tokens.authentication_method === "string" ? tokens.authentication_method : "";
  let check: Response;
  try {
    const assertion = claims.sub ? await signAssertion(env, token, claims.sub, amr, method, deps.now(), who, sso) : null;
    check = await deps.vault("/v1/session?limit=1", token, assertion ? { [ASSERTION_HEADER]: assertion } : undefined);
  } catch (e) {
    if (e instanceof MisconfiguredError) return page(500, "Sign-in is not configured", e.message, [spent]);
    return page(502, "Sign-in is unavailable", "The service could not be reached.", [spent]);
  }
  // A missing second factor still gets a session: the portal's callback page explains it and offers a way forward.
  if (!check.ok && !(check.status === 403 && (await check.clone().text()).includes("second_factor_required"))) {
    return page(check.status === 401 ? 401 : 502, "Sign-in was not accepted", "The service did not accept this sign-in.", [spent]);
  }

  const sid = randomToken(32);
  const rec: SessionRecord = {
    token, token_exp: claims.exp, refresh: tokens.refresh_token ?? null, provider_sid: claims.sid, org_id: null, tenant: null, amr, method, sso_connection_id: sso?.connection ?? null, sso_organization_id: sso?.organization ?? null, email: who.email, email_verified: who.email_verified,
    until: Math.floor(deps.now() / 1000) + SESSION_SECONDS, iat: Math.floor(deps.now() / 1000),
  };
  try {
    await sessionStoreFor(env, deps.fetch).create(sid, rec, deps.now());
  } catch (e) {
    if (e instanceof StoreUnavailable) return unavailable(request, [spent]);
    throw e;
  }
  return redirect(`/auth/callback?return=${encodeURIComponent(ret)}`, [setCookie(SESSION_COOKIE, sid, SESSION_SECONDS), spent]);
}

// The session store failed: say so (503) and still clear the browser's cookie, so nothing is left half signed in.
function unavailable(request: Request, cookies: string[]): Response {
  const detail = "The session store did not answer. Nothing was changed on your account.";
  if (request.headers.get("accept")?.includes("application/json")) {
    const h = new Headers({ "content-type": "application/json", "cache-control": "no-store" });
    for (const c of cookies) h.append("set-cookie", c);
    return new Response(JSON.stringify({ error: "session_unavailable", message: detail }), { status: 503, headers: h });
  }
  return page(503, "Sign-in is unavailable", detail, cookies);
}

async function logout(request: Request, env: AuthEnv, deps: AuthDeps): Promise<Response> {
  const cookies = [clearCookie(SESSION_COOKIE)];
  try {
    return await logoutInner(request, env, deps, cookies);
  } catch (e) {
    if (e instanceof StoreUnavailable) return unavailable(request, cookies);
    throw e;
  }
}

async function logoutInner(request: Request, env: AuthEnv, deps: AuthDeps, cookies: string[]): Promise<Response> {
  const sid = cookieValue(request.headers.get("cookie"), SESSION_COOKIE);
  const store = sessionStoreFor(env, deps.fetch);
  const rec = sid ? await store.load(sid, deps.now()) : null;
  if (!sid || !rec) return redirect("/sign-in", cookies, request);
  await store.revoke(sid, deps.now());
  const providerSid = rec.provider_sid ?? tokenClaims(rec.token)?.sid ?? null;
  if (!providerSid) return redirect("/sign-in", cookies, request);
  const to = new URL(clean(env.AUTH_BASE_URL) + "/sessions/logout");
  to.searchParams.set("session_id", providerSid);
  to.searchParams.set("return_to", clean(env.PUBLIC_URL) + "/sign-in");
  return redirect(to.toString(), cookies, request);
}

// Trades the stored refresh token for a new identity token. Returns the updated record, or null when the provider
// refuses (the session is then over).
export async function refreshIdentity(env: Pick<AuthEnv, "AUTH_BASE_URL" | "AUTH_CLIENT_ID" | "AUTH_CLIENT_SECRET">, f: typeof fetch, rec: SessionRecord): Promise<SessionRecord | null> {
  if (!rec.refresh) return null;
  try {
    const res = await f(clean(env.AUTH_BASE_URL) + "/authenticate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_id: env.AUTH_CLIENT_ID, ...(env.AUTH_CLIENT_SECRET ? { client_secret: env.AUTH_CLIENT_SECRET } : {}), grant_type: "refresh_token", refresh_token: rec.refresh }),
    });
    if (!res.ok) return null;
    const t = (await res.json()) as { id_token?: string; access_token?: string; refresh_token?: string };
    const token = t.id_token ?? t.access_token;
    const claims = token ? tokenClaims(token) : null;
    if (!token || !claims) return null;
    return { ...rec, token, token_exp: claims.exp, refresh: t.refresh_token ?? rec.refresh, provider_sid: claims.sid ?? rec.provider_sid };
  } catch {
    return null;
  }
}

// Returns null for a path that is not an auth route (or the portal's own callback page), so the caller serves assets.
export async function handleAuth(request: Request, env: AuthEnv, deps: AuthDeps): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  if (!path.startsWith("/auth/")) return null;
  for (const k of ["AUTH_BASE_URL", "AUTH_CLIENT_ID", "PUBLIC_URL"] as const) {
    if (!env[k]) return page(500, "Sign-in is not configured", `the portal setting ${k} is not set`);
  }
  if (!env.SESSIONS) return page(500, "Sign-in is not configured", "the portal setting SESSIONS is not set");
  const bad = assertionConfigError(env);
  if (bad) return page(500, "Sign-in is not configured", bad);
  const refuse = (status: number, error: string, message: string, allow?: string) => new Response(JSON.stringify({ error, message }), { status, headers: { "content-type": "application/json", ...(allow ? { allow } : {}) } });
  if (path === "/auth/logout") {
    // Signing out changes state: a POST from the portal's own origin, never a followed link or another site's form.
    if (request.method !== "POST") return refuse(405, "method_not_allowed", "sign-out is a POST", "POST");
    if (request.headers.get("origin") !== clean(env.PUBLIC_URL)) return refuse(403, "origin_refused", "sign-out must come from the portal's own origin");
    return logout(request, env, deps);
  }
  if (request.method !== "GET") return refuse(405, "method_not_allowed", "method not allowed", "GET");
  if (path === "/auth/login") return login(request, env, deps);
  if (path === "/auth/callback") return callback(request, env, deps);
  return null;
}

export { sha256Hex };
