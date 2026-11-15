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

// The assistant's capabilities live here, beside the session they belong to (portal assistant, contracts/portal-reader.md section 1).
// One key holds every live capability of this session, keyed by the SHA-256 of its random part; expired ones are dropped on every use.
const CAPS_KEY = "assist:caps";
export const CAP_SECONDS = 60;
export const CAP_READS = 4;
export const CAP_MAX_LIVE = 20;
export type CapReason = "expired" | "spent" | "unknown" | "wrong_session" | "wrong_question" | "too_many";
interface CapRecord { sid: string; org: string; question_id: string; expires_at: number; uses_left: number }

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

  private async caps(nowMs: number): Promise<Record<string, CapRecord>> {
    const raw = (await this.storage.get(CAPS_KEY)) as string | undefined;
    const all = raw ? (JSON.parse(raw) as Record<string, CapRecord>) : {};
    for (const [k, r] of Object.entries(all)) if (r.expires_at <= nowMs) delete all[k];
    return all;
  }

  // The Worker has checked the cookie; the object checks again that the session is live before it holds a capability for it.
  private async mintCap(a: Record<string, any>): Promise<{ ok: boolean; reason?: CapReason }> {
    const live = await this.store.load(a.sid, a.nowMs);
    if (!live || !live.org_id || live.org_id !== a.org) return { ok: false, reason: "wrong_session" };
    const all = await this.caps(a.nowMs);
    if (Object.keys(all).length >= CAP_MAX_LIVE) return { ok: false, reason: "too_many" };
    all[a.capHash] = { sid: a.sid, org: a.org, question_id: a.questionId, expires_at: a.nowMs + CAP_SECONDS * 1000, uses_left: CAP_READS };
    await this.storage.put(CAPS_KEY, JSON.stringify(all));
    return { ok: true };
  }

  // One read: checks the capability against this object's own record, spends a use, and hands back the session and organization
  // the record names. Nothing in the caller's request supplies either.
  private async spendCap(a: Record<string, any>): Promise<{ ok: true; sid: string; org: string } | { ok: false; reason: CapReason }> {
    const all = await this.caps(a.nowMs);
    const rec = all[a.capHash];
    if (!rec) {
      const raw = (await this.storage.get(CAPS_KEY)) as string | undefined;
      const had = raw ? (JSON.parse(raw) as Record<string, CapRecord>)[a.capHash] : undefined;
      if (had) await this.storage.put(CAPS_KEY, JSON.stringify(all));
      return { ok: false, reason: had ? "expired" : "unknown" };
    }
    if (rec.question_id !== a.questionId) return { ok: false, reason: "wrong_question" };
    if (rec.uses_left <= 0) return { ok: false, reason: "spent" };
    const live = await this.store.load(rec.sid, a.nowMs);
    if (!live || live.org_id !== rec.org) return { ok: false, reason: "wrong_session" };
    rec.uses_left -= 1;
    await this.storage.put(CAPS_KEY, JSON.stringify(all));
    return { ok: true, sid: rec.sid, org: rec.org };
  }

  async fetch(request: Request): Promise<Response> {
    const a = (await request.json()) as Record<string, any>;
    const s = this.store;
    let out: unknown;
    switch (a.op) {
      case "mintCap": out = await this.mintCap(a); break;
      case "spendCap": out = await this.spendCap(a); break;
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
