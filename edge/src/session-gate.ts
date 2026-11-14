// Durable Object, one instance per session. It owns the session record in its own storage and is the only writer: every
// operation (create, refresh, choose organization, save a tenant token, revoke) arrives here and runs one at a time, so a
// request holding an older copy can never overwrite a newer one, and the provider's single-use refresh token is spent once.

import { LocalSessionStore, type ProviderEnv } from "./session-store.ts";
import type { KV } from "./session.ts";

type Storage = { get(key: string): Promise<unknown>; put(key: string, value: string): Promise<void>; delete(key: string): Promise<boolean | void>; setAlarm(at: number): Promise<void>; deleteAll(): Promise<void> };

// The object's storage has no per-key expiry; LocalSessionStore refuses a record past its end on every load.
function asKV(s: Storage): KV {
  return { get: async (k) => ((await s.get(k)) as string | undefined) ?? null, put: async (k, v) => s.put(k, v), delete: async (k) => { await s.delete(k); } };
}

export class SessionGate {
  private store: LocalSessionStore;
  private storage: Storage;
  constructor(state: { storage: Storage }, env: ProviderEnv) {
    this.storage = state.storage;
    this.store = new LocalSessionStore(asKV(state.storage), env, (...a) => fetch(...a));
  }

  // At the sign-in's end the object forgets everything: the identity token, the refresh token and the address.
  async alarm(): Promise<void> {
    await this.storage.deleteAll();
  }

  async fetch(request: Request): Promise<Response> {
    const a = (await request.json()) as Record<string, any>;
    const s = this.store;
    let out: unknown;
    switch (a.op) {
      case "create": await s.create(a.sid, a.rec, a.nowMs); await this.storage.setAlarm(a.rec.until * 1000); out = null; break;
      case "load": out = await s.load(a.sid, a.nowMs); break;
      case "refresh": out = await s.refresh(a.sid, a.nowMs, a.leadSeconds); break;
      case "chooseOrg": out = await s.chooseOrg(a.sid, a.orgId, a.tenant, a.nowMs); break;
      case "adoptTenant": out = await s.adoptTenant(a.sid, a.orgId, a.tenant, a.nowMs); break;
      case "revoke": await s.revoke(a.sid, a.nowMs); out = null; break;
      default: return new Response(JSON.stringify({ error: "unknown_op" }), { status: 400 });
    }
    return new Response(JSON.stringify(out), { headers: { "content-type": "application/json" } });
  }
}
