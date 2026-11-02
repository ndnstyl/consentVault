// The one place a stored sign-in record is changed. Every change (create, refresh, choose organization, save a tenant token,
// revoke) runs one at a time per session, so two overlapping requests can never write an older copy over a newer one.
//
// In production the store runs inside the session's Durable Object (session-gate.ts), over that object's own storage, and
// every Worker request reaches it through GateSessionStore. Without the binding (tests, a single-isolate deployment) the same
// logic runs over the key-value namespace with an in-isolate queue per session.

import { refreshIdentity } from "./auth.ts";
import {
  loadBySid, revokeSession, saveSession, type KV, type SessionRecord,
} from "./session.ts";

export type AdoptResult = "ok" | "mismatch" | "gone";
export interface Tenant { token: string; exp: number }
export interface ProviderEnv { AUTH_BASE_URL: string; AUTH_CLIENT_ID: string; AUTH_CLIENT_SECRET?: string }

export interface SessionStore {
  create(sid: string, rec: SessionRecord, nowMs: number): Promise<void>;
  load(sid: string, nowMs: number): Promise<SessionRecord | null>;
  // Refreshes the identity token if it is within leadSeconds of expiry. A refused refresh ends the session (null).
  refresh(sid: string, nowMs: number, leadSeconds: number): Promise<SessionRecord | null>;
  // The person's explicit choice (the vault just confirmed it): sets the organization and its tenant token.
  chooseOrg(sid: string, orgId: string, tenant: Tenant, nowMs: number): Promise<SessionRecord | null>;
  // A re-minted tenant token: saved only while the session still names that organization.
  adoptTenant(sid: string, orgId: string, tenant: Tenant, nowMs: number): Promise<AdoptResult>;
  revoke(sid: string, nowMs: number): Promise<void>;
}

const queues = new Map<string, Promise<unknown>>();

export class LocalSessionStore implements SessionStore {
  private kv: KV; private provider: ProviderEnv; private f: typeof fetch;
  constructor(kv: KV, provider: ProviderEnv, f: typeof fetch) { this.kv = kv; this.provider = provider; this.f = f; }

  private serial<T>(sid: string, fn: () => Promise<T>): Promise<T> {
    const prev = queues.get(sid) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.catch(() => undefined);
    queues.set(sid, tail);
    void tail.then(() => { if (queues.get(sid) === tail) queues.delete(sid); });
    return run;
  }

  async create(sid: string, rec: SessionRecord, nowMs: number): Promise<void> {
    await this.serial(sid, () => saveSession(this.kv, sid, rec, nowMs));
  }

  async load(sid: string, nowMs: number): Promise<SessionRecord | null> {
    const rec = await loadBySid(this.kv, sid);
    return rec && rec.until * 1000 > nowMs ? rec : null;
  }

  refresh(sid: string, nowMs: number, leadSeconds: number): Promise<SessionRecord | null> {
    return this.serial(sid, async () => {
      const rec = await this.load(sid, nowMs);
      if (!rec) return null;
      if (rec.token_exp - nowMs / 1000 >= leadSeconds) return rec; // another request refreshed it while this one waited
      const next = await refreshIdentity(this.provider, this.f, rec);
      if (!next) { await revokeSession(this.kv, sid, nowMs); return null; }
      await saveSession(this.kv, sid, next, nowMs);
      return next;
    });
  }

  chooseOrg(sid: string, orgId: string, tenant: Tenant, nowMs: number): Promise<SessionRecord | null> {
    return this.serial(sid, async () => {
      const rec = await this.load(sid, nowMs);
      if (!rec) return null;
      const next = { ...rec, org_id: orgId, tenant };
      await saveSession(this.kv, sid, next, nowMs);
      return next;
    });
  }

  adoptTenant(sid: string, orgId: string, tenant: Tenant, nowMs: number): Promise<AdoptResult> {
    return this.serial(sid, async () => {
      const rec = await this.load(sid, nowMs);
      if (!rec) return "gone";
      if (rec.org_id !== orgId) return "mismatch";
      await saveSession(this.kv, sid, { ...rec, tenant }, nowMs);
      return "ok";
    });
  }

  revoke(sid: string, nowMs: number): Promise<void> {
    return this.serial(sid, () => revokeSession(this.kv, sid, nowMs));
  }
}

// The Worker's view of the session's Durable Object: each operation is one request to the object, which runs it one at a time.
export interface GateNamespace { idFromName(name: string): unknown; get(id: unknown): { fetch(request: Request): Promise<Response> } }

export class GateSessionStore implements SessionStore {
  private ns: GateNamespace;
  constructor(ns: GateNamespace) { this.ns = ns; }

  private async call<T>(sid: string, op: string, args: Record<string, unknown>): Promise<T> {
    const stub = this.ns.get(this.ns.idFromName(sid));
    const res = await stub.fetch(new Request("https://session-gate/op", { method: "POST", body: JSON.stringify({ op, sid, ...args }) }));
    if (!res.ok) throw new Error(`the session store answered ${res.status} to ${op}`);
    return (await res.json()) as T;
  }
  create(sid: string, rec: SessionRecord, nowMs: number) { return this.call<void>(sid, "create", { rec, nowMs }); }
  load(sid: string, nowMs: number) { return this.call<SessionRecord | null>(sid, "load", { nowMs }); }
  refresh(sid: string, nowMs: number, leadSeconds: number) { return this.call<SessionRecord | null>(sid, "refresh", { nowMs, leadSeconds }); }
  chooseOrg(sid: string, orgId: string, tenant: Tenant, nowMs: number) { return this.call<SessionRecord | null>(sid, "chooseOrg", { orgId, tenant, nowMs }); }
  adoptTenant(sid: string, orgId: string, tenant: Tenant, nowMs: number) { return this.call<AdoptResult>(sid, "adoptTenant", { orgId, tenant, nowMs }); }
  revoke(sid: string, nowMs: number) { return this.call<void>(sid, "revoke", { nowMs }); }
}

// Any failure of the storage under a session operation, named: callers answer 503 and say so, never a quiet pass.
export class StoreUnavailable extends Error {}

class GuardedStore implements SessionStore {
  private inner: SessionStore;
  constructor(inner: SessionStore) { this.inner = inner; }
  private async guard<T>(fn: () => Promise<T>): Promise<T> {
    try { return await fn(); } catch (e) { throw new StoreUnavailable(`the session store failed: ${(e as Error).message}`); }
  }
  create(sid: string, rec: SessionRecord, nowMs: number) { return this.guard(() => this.inner.create(sid, rec, nowMs)); }
  load(sid: string, nowMs: number) { return this.guard(() => this.inner.load(sid, nowMs)); }
  refresh(sid: string, nowMs: number, lead: number) { return this.guard(() => this.inner.refresh(sid, nowMs, lead)); }
  chooseOrg(sid: string, orgId: string, tenant: Tenant, nowMs: number) { return this.guard(() => this.inner.chooseOrg(sid, orgId, tenant, nowMs)); }
  adoptTenant(sid: string, orgId: string, tenant: Tenant, nowMs: number) { return this.guard(() => this.inner.adoptTenant(sid, orgId, tenant, nowMs)); }
  revoke(sid: string, nowMs: number) { return this.guard(() => this.inner.revoke(sid, nowMs)); }
}

export interface StoreEnv extends ProviderEnv { SESSIONS: KV; SESSION_GATE?: GateNamespace }

export function sessionStoreFor(env: StoreEnv, f: typeof fetch): SessionStore {
  return new GuardedStore(env.SESSION_GATE ? new GateSessionStore(env.SESSION_GATE) : new LocalSessionStore(env.SESSIONS, env, f));
}
