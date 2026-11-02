// Portal session store for the edge Worker. The browser holds one opaque, random id in a __Host- cookie; everything
// else (the identity token, the refresh token, the chosen organization, the short tenant token) stays in the Worker's
// key-value store under a hash of that id. The cookie carries no token and no tenant data.

export const SESSION_COOKIE = "__Host-cv_session";
export const LOGIN_COOKIE = "__Host-cv_login";
export const TENANT_TOKEN_HEADER = "x-consentvault-tenant-token";
export const SESSION_SECONDS = 8 * 3600;
export const LOGIN_SECONDS = 600;

export interface KV {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface SessionRecord {
  token: string;                       // the identity provider's token the vault verifies
  token_exp: number;                   // seconds since the epoch, read from the token for timing only
  refresh: string | null;
  provider_sid: string | null;         // the identity provider's own session id, for sign-out
  org_id: string | null;               // the organization this session chose
  tenant: { token: string; exp: number } | null;
  until: number;                       // when the sign-in itself ends (seconds); never extended
  amr: string[];                       // how the person signed in (RFC 8176 values), from the provider's answer to the code exchange
  method: string;                      // the provider's own name for it, for diagnostics
  sso_organization_id?: string | null;
  sso_connection_id?: string | null;   // set for a company single sign-on: the connection the provider reported
  email: string | null;                // the address the provider verified, from its server-to-server answer (tokens carry none)
  email_verified: boolean;
  iat: number;                         // when this sign-in was made (seconds); a revocation at or after it refuses the record
}

export function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomToken(bytes = 32): string {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256Hex(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function cookieValue(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

export function setCookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

export function clearCookie(name: string): string {
  return setCookie(name, "", 0);
}

// Reads the timing and session id out of a JWT without trusting it: the vault does the verifying.
export function tokenClaims(token: string): { exp: number; sid: string | null; sub: string | null } | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const json = new TextDecoder().decode(Uint8Array.from(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));
    const c = JSON.parse(json) as Record<string, unknown>;
    if (typeof c.exp !== "number") return null;
    return { exp: c.exp, sid: typeof c.sid === "string" ? c.sid : null, sub: typeof c.sub === "string" ? c.sub : null };
  } catch {
    return null;
  }
}

export const sessionKey = async (sid: string) => `sess:${await sha256Hex(sid)}`;
export const loginKey = async (state: string) => `login:${await sha256Hex(state)}`;

const revokedKey = async (sid: string) => `revoked:${await sha256Hex(sid)}`;

// A stored record is usable only if no revocation marker at or after its issue time exists. Key-value deletes can take up
// to a minute to reach every location, so sign-out writes the marker as well as deleting: a stale copy of the record is
// refused for as long as the marker is visible, and the marker outlives any sign-in.
export async function loadBySid(kv: KV, sid: string): Promise<SessionRecord | null> {
  const raw = await kv.get(await sessionKey(sid));
  if (!raw) return null;
  let rec: SessionRecord;
  try {
    rec = JSON.parse(raw) as SessionRecord;
  } catch {
    await kv.delete(await sessionKey(sid));
    return null;
  }
  const mark = await kv.get(await revokedKey(sid));
  if (mark !== null && Number(mark) >= rec.iat) return null;
  return rec;
}

export async function loadSession(kv: KV, cookieHeader: string | null): Promise<{ sid: string; rec: SessionRecord } | null> {
  const sid = cookieValue(cookieHeader, SESSION_COOKIE);
  if (!sid) return null;
  const rec = await loadBySid(kv, sid);
  return rec ? { sid, rec } : null;
}

export async function revokeSession(kv: KV, sid: string, nowMs: number): Promise<void> {
  await kv.put(await revokedKey(sid), String(Math.floor(nowMs / 1000) + 1), { expirationTtl: SESSION_SECONDS + 3600 });
  await kv.delete(await sessionKey(sid));
}

// The stored record lives only as long as the sign-in itself (eight hours from creation, never extended by a save).
export async function saveSession(kv: KV, sid: string, rec: SessionRecord, nowMs: number): Promise<void> {
  await kv.put(await sessionKey(sid), JSON.stringify(rec), { expirationTtl: Math.max(60, Math.floor(rec.until - nowMs / 1000)) });
}
