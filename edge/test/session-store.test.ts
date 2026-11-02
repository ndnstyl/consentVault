import test from "node:test";
import assert from "node:assert/strict";
import { LocalSessionStore } from "../src/session-store.ts";
import { sessionKey, saveSession, type KV, type SessionRecord } from "../src/session.ts";
import { AUTH_ENV_BASE, NOW_MS, jwt, memKV, nowSec } from "./support/portal.ts";

const SID = "sid-store-0123456789012345678901234567";
const base = (over: Partial<SessionRecord> = {}): SessionRecord => ({
  token: jwt({ sub: "u", sid: "ps", exp: nowSec() + 3 }), token_exp: nowSec() + 3, refresh: "rt_1", provider_sid: "ps", org_id: "ORG-A",
  tenant: { token: "t-old", exp: nowSec() + 5 }, amr: ["hwk", "user"], method: "Passkey", email: "a@b.example", email_verified: true,
  until: nowSec() + 1000, iat: nowSec(), ...over,
});

// A store whose every read and write takes real time, so unserialized read-modify-write cycles interleave.
function slow(inner: ReturnType<typeof memKV>): KV {
  const wait = () => new Promise((ok) => setTimeout(ok, 15));
  return { get: async (k) => { await wait(); return inner.get(k); }, put: async (k, v, o) => { await wait(); return inner.put(k, v, o); }, delete: async (k) => { await wait(); return inner.delete(k); } };
}
const refreshFetch = (async () => new Response(JSON.stringify({ access_token: jwt({ sub: "u", sid: "ps", exp: nowSec() + 300, jti: "n" }), refresh_token: "rt_2" }), { status: 200 })) as unknown as typeof fetch;

test("a refresh and a tenant-token save that overlap both survive: the record changes one operation at a time", async () => {
  const inner = memKV();
  const kv = slow(inner);
  await saveSession(inner, SID, base(), NOW_MS);
  const store = new LocalSessionStore(kv, AUTH_ENV_BASE, refreshFetch);
  const [fresh, adopted] = await Promise.all([store.refresh(SID, NOW_MS, 30), store.adoptTenant(SID, "ORG-A", { token: "t-new", exp: nowSec() + 290 }, NOW_MS)]);
  assert.ok(fresh);
  assert.equal(adopted, "ok");
  const rec = JSON.parse(inner.data.get(await sessionKey(SID))!) as SessionRecord;
  assert.equal(rec.refresh, "rt_2", "the refreshed refresh token was not overwritten by the tenant save");
  assert.equal(rec.tenant?.token, "t-new", "and the tenant token was not lost to the refresh");
});

test("control: the same two changes made as unserialized read-modify-write lose one of them (so the test above has teeth)", async () => {
  const inner = memKV();
  const kv = slow(inner);
  await saveSession(inner, SID, base(), NOW_MS);
  const key = await sessionKey(SID);
  const change = (f: (r: SessionRecord) => SessionRecord) => async () => { const r = JSON.parse((await kv.get(key))!) as SessionRecord; await kv.put(key, JSON.stringify(f(r))); };
  await Promise.all([change((r) => ({ ...r, refresh: "rt_2" }))(), change((r) => ({ ...r, tenant: { token: "t-new", exp: 1 } }))()]);
  const rec = JSON.parse(inner.data.get(key)!) as SessionRecord;
  assert.ok(rec.refresh !== "rt_2" || rec.tenant?.token !== "t-new");
});

test("a tenant token for an organization the session no longer names is refused, never saved over the newer choice", async () => {
  const inner = memKV();
  await saveSession(inner, SID, base({ org_id: "ORG-B", tenant: { token: "t-b", exp: nowSec() + 200 } }), NOW_MS);
  const store = new LocalSessionStore(inner, AUTH_ENV_BASE, refreshFetch);
  assert.equal(await store.adoptTenant(SID, "ORG-A", { token: "t-a", exp: nowSec() + 200 }, NOW_MS), "mismatch");
  assert.equal((await store.load(SID, NOW_MS))!.tenant!.token, "t-b");
  assert.equal(await store.adoptTenant("nope", "ORG-A", { token: "t", exp: 1 }, NOW_MS), "gone");
});

test("a save after sign-out cannot bring the session back", async () => {
  const inner = memKV();
  await saveSession(inner, SID, base(), NOW_MS);
  const store = new LocalSessionStore(slow(inner), AUTH_ENV_BASE, refreshFetch);
  const [, adopted] = await Promise.all([store.revoke(SID, NOW_MS), store.adoptTenant(SID, "ORG-A", { token: "t", exp: nowSec() + 100 }, NOW_MS)]);
  assert.ok(adopted === "gone" || adopted === "ok");
  assert.equal(await store.load(SID, NOW_MS + 5000), null);
});

test("a session past its end is gone even where the store has no expiry of its own", async () => {
  const inner = memKV();
  await saveSession(inner, SID, base({ until: nowSec() - 1 }), NOW_MS);
  assert.equal(await new LocalSessionStore(inner, AUTH_ENV_BASE, refreshFetch).load(SID, NOW_MS), null);
});

test("through the session's Durable Object, the same operations hold: one writer, the same answers", async () => {
  const { SessionGate } = await import("../src/session-gate.ts");
  const { GateSessionStore } = await import("../src/session-store.ts");
  const mem = new Map<string, string>();
  const storage = { get: async (k: string) => mem.get(k), put: async (k: string, v: string) => { mem.set(k, v); }, delete: async (k: string) => mem.delete(k), setAlarm: async () => undefined, deleteAll: async () => mem.clear() };
  const gate = new SessionGate({ storage }, AUTH_ENV_BASE);
  const ns = { idFromName: (n: string) => n, get: () => ({ fetch: (r: Request) => gate.fetch(r) }) };
  const store = new GateSessionStore(ns);
  await store.create(SID, base(), NOW_MS);
  assert.equal(await store.adoptTenant(SID, "ORG-A", { token: "t-new", exp: nowSec() + 200 }, NOW_MS), "ok");
  assert.equal(await store.adoptTenant(SID, "ORG-Z", { token: "x", exp: 1 }, NOW_MS), "mismatch");
  assert.equal((await store.load(SID, NOW_MS))!.tenant!.token, "t-new");
  await store.revoke(SID, NOW_MS);
  assert.equal(await store.load(SID, NOW_MS + 5000), null);
});

test("a store that fails says so: no operation reports success when the storage under it threw", async () => {
  const { sessionStoreFor, StoreUnavailable } = await import("../src/session-store.ts");
  const down = async () => { throw new Error("storage down"); };
  const boom: KV = { get: down, put: down, delete: down };
  const raw = new LocalSessionStore(boom, AUTH_ENV_BASE, refreshFetch);
  await assert.rejects(() => raw.create(SID, base(), NOW_MS));
  await assert.rejects(() => raw.load(SID, NOW_MS));
  await assert.rejects(() => raw.refresh(SID, NOW_MS, 30));
  await assert.rejects(() => raw.adoptTenant(SID, "ORG-A", { token: "t", exp: 1 }, NOW_MS));
  await assert.rejects(() => raw.revoke(SID, NOW_MS));
  const guarded = sessionStoreFor({ ...AUTH_ENV_BASE, SESSIONS: boom }, refreshFetch);
  for (const call of [() => guarded.create(SID, base(), NOW_MS), () => guarded.load(SID, NOW_MS), () => guarded.revoke(SID, NOW_MS)]) {
    await assert.rejects(call, StoreUnavailable);
  }
});

test("when a Durable Object namespace is bound, every session operation goes through it and none touches the key-value store", async () => {
  const { sessionStoreFor } = await import("../src/session-store.ts");
  const kv = memKV();
  const ops: string[] = [];
  const ns = { idFromName: (n: string) => n, get: () => ({ fetch: async (r: Request) => { const b = (await r.clone().json()) as { op: string }; ops.push(b.op); return new Response("null"); } }) };
  const store = sessionStoreFor({ ...AUTH_ENV_BASE, SESSIONS: kv, SESSION_GATE: ns }, refreshFetch);
  await store.create(SID, base(), NOW_MS); await store.load(SID, NOW_MS); await store.refresh(SID, NOW_MS, 30);
  await store.chooseOrg(SID, "A", { token: "t", exp: 1 }, NOW_MS); await store.adoptTenant(SID, "A", { token: "t", exp: 1 }, NOW_MS); await store.revoke(SID, NOW_MS);
  assert.deepEqual(ops, ["create", "load", "refresh", "chooseOrg", "adoptTenant", "revoke"]);
  assert.equal(kv.data.size, 0, "nothing was written to the key-value store");
});

test("a session's Durable Object deletes everything it holds (identity token, refresh token, address) when the sign-in ends", async () => {
  const { SessionGate } = await import("../src/session-gate.ts");
  const mem = new Map<string, string>();
  let alarm: number | null = null;
  const storage = { get: async (k: string) => mem.get(k), put: async (k: string, v: string) => { mem.set(k, v); }, delete: async (k: string) => mem.delete(k), setAlarm: async (t: number) => { alarm = t; }, deleteAll: async () => { mem.clear(); alarm = null; } };
  const gate = new SessionGate({ storage }, AUTH_ENV_BASE);
  const rec = base();
  await gate.fetch(new Request("https://g/op", { method: "POST", body: JSON.stringify({ op: "create", sid: SID, rec, nowMs: NOW_MS }) }));
  assert.equal(alarm, rec.until * 1000, "an alarm is set at the session end");
  assert.ok([...mem.values()].some((v) => v.includes("a@b.example")));
  await gate.alarm();
  assert.equal(mem.size, 0, "the alarm clears the whole storage");
});
