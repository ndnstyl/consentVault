// The portal's in-app assistant door (marketing repo specs/support-agents, contracts/portal-reader.md). Two routes on the portal Worker:
//   POST /assist/ask          the signed-in member's question; mints a one-question capability and forwards to the answer core.
//   GET  /assist/read/<tool>  the reader: the answer core, over the service binding, asks for one fixed vault GET with that capability.
// This file holds no prompt, no corpus and no answer text. The reader's tools are a closed list of GETs the portal's own screens already
// make; the vault decides tenant and role from the session exactly as for any portal call. Nothing here can read a record, a contact
// point, evidence, an export, the audit log, members or invitations: see FORBIDDEN_PREFIXES and the test that walks the vault's route table.

import { handleGateway, type GatewayDeps, type GatewayEnv } from "./gateway.ts";
import { SESSION_COOKIE, cookieValue, randomToken, sha256Hex, tokenClaims, clearCookie } from "./session.ts";
import { sessionStoreFor, type GateNamespace } from "./session-store.ts";
import { CAP_READS, CAP_SECONDS, type CapReason } from "./session-gate.ts";

export interface AssistGate extends GateNamespace { idFromString(id: string): unknown }
export interface ServiceBinding { fetch(request: Request): Promise<Response> }
export interface AssistEnv extends GatewayEnv {
  SESSION_GATE?: AssistGate;
  /** Service binding to the private answer core (consentvault-support). */
  SUPPORT?: ServiceBinding;
  /** Shared secret that marks a call as coming over the service binding; the same value is the core's PORTAL_MARKER. A Worker secret. */
  ASSIST_MARKER?: string;
}

export const MARKER_HEADER = "x-cv-assist-marker";
export const CAPABILITY_HEADER = "x-cv-capability";
export const QUESTION_HEADER = "x-cv-question";
export const ASK_MAX_QUESTION = 4000;
export const ASK_MAX_BODY = 16 * 1024;
const CORE_TIMEOUT_MS = 20_000;

/** Never a reader tool, at any depth (contracts/portal-reader.md section 3). The route-table test proves no tool path touches one. */
export const FORBIDDEN_PREFIXES = [
  "/v1/records", "/v1/evidence", "/v1/proof", "/v1/exports", "/v1/audit", "/v1/members", "/v1/invites", "/v1/erasures", "/v1/offboarding",
  "/v1/events", "/v1/capture", "/v1/confirmations", "/v1/oauth", "/v1/wording", "/v1/checklists", "/v1/retention", "/v1/holds",
];
export const FORBIDDEN_SUFFIXES = ["/deliveries"];

type J = Record<string, any>;

/** An expected field is missing: a named error, never a silent empty object. */
export class FieldMissing extends Error {
  tool: string;
  field: string;
  constructor(tool: string, field: string) { super(`the vault's answer for ${tool} lacks the field ${field}`); this.tool = tool; this.field = field; }
}

const need = (tool: string, o: J | null | undefined, k: string): any => {
  if (!o || typeof o !== "object" || !(k in o)) throw new FieldMissing(tool, k);
  return o[k];
};
const cap80 = (v: unknown) => (typeof v === "string" ? v.slice(0, 80) : v);
const items = (tool: string, j: J): J[] => {
  const it = need(tool, j, "items");
  if (!Array.isArray(it)) throw new FieldMissing(tool, "items");
  return it;
};

export interface ToolDef {
  path: string;
  /** The portal screen that shows this fact; the answer names and links it. */
  screen: string;
  shape(json: J, ctx: { org: string }): J;
}

const passed = (t: J | null | undefined): "passed" | "failed" | null => {
  if (!t || typeof t !== "object") return null;
  const code = Number(t.http_status);
  return Number.isFinite(code) ? (code >= 200 && code < 300 ? "passed" : "failed") : "failed";
};

// Field names are as the vault returns them today (read from src/consentvault in the product repo, 2026-11-15); a deviation from the cloud
// contracts is listed in the spec's tasks file under B3.
export const TOOLS: Record<string, ToolDef> = {
  setup_status: {
    path: "/v1/setup", screen: "/setup",
    shape: (j) => ({
      steps: need("setup_status", j, "steps").map((s: J) => ({ step: need("setup_status", s, "step"), status: need("setup_status", s, "status"), required: need("setup_status", s, "required"), blocked_reason: need("setup_status", s, "blocked_reason"), skipped_at: need("setup_status", s, "skipped_at") })),
      current_step: need("setup_status", j, "current_step"), complete: need("setup_status", j, "complete"),
      partial: Array.isArray(j.partial) ? j.partial.filter((x: unknown) => typeof x === "string").slice(0, 10) : j.partial === true,
    }),
  },
  plan_and_usage: {
    path: "/v1/billing", screen: "/billing",
    shape: (j) => {
      const plan = need("plan_and_usage", j, "plan");
      const period = need("plan_and_usage", j, "period");
      const included = need("plan_and_usage", j, "included");
      const used = need("plan_and_usage", j, "used");
      return {
        status: need("plan_and_usage", j, "status"), past_due_since: need("plan_and_usage", j, "past_due_since"),
        plan: plan ? { name: need("plan_and_usage", plan, "name") } : null,
        period: period ? { start: need("plan_and_usage", period, "start"), end: need("plan_and_usage", period, "end") } : null,
        included: included ? { events: need("plan_and_usage", included, "events"), gate_checks: need("plan_and_usage", included, "gate_checks") } : null,
        used: used ? { events: need("plan_and_usage", used, "events"), gate_checks: need("plan_and_usage", used, "gate_checks") } : null,
        last_reported_at: need("plan_and_usage", j, "last_reported_at"),
      };
    },
  },
  plans_on_sale: {
    path: "/v1/billing/plans", screen: "/start/plan",
    shape: (j) => ({ items: items("plans_on_sale", j).map((p) => Object.fromEntries(["name", "interval", "unit_amount", "currency", "included_events", "included_gate_checks", "systems", "legal_holds"].map((k) => [k, need("plans_on_sale", p, k)]))) }),
  },
  org_status: {
    path: "/v1/org", screen: "/settings",
    shape: (j) => ({ name: cap80(need("org_status", j, "name")), status: need("org_status", j, "status"), ...(typeof j.role === "string" ? { role: j.role } : {}) }),
  },
  sources_summary: {
    path: "/v1/sources", screen: "/sources",
    shape: (j) => ({
      items: items("sources_summary", j).map((s) => ({ name: cap80(need("sources_summary", s, "name")), kind: need("sources_summary", s, "kind"), status: need("sources_summary", s, "status"), last_event_at: need("sources_summary", s, "last_event_at") })),
      first_page_only: !!j.next_cursor,
    }),
  },
  systems_summary: {
    path: "/v1/systems", screen: "/systems",
    shape: (j) => ({
      items: items("systems_summary", j).map((s) => ({ name: cap80(need("systems_summary", s, "name")), kind: need("systems_summary", s, "kind"), status: need("systems_summary", s, "status"), last_test: s.last_test ? { result: passed(s.last_test), at: s.last_test.at ?? null } : null, counts: null })),
      first_page_only: !!j.next_cursor,
    }),
  },
  credentials_summary: {
    path: "/v1/credentials", screen: "/credentials",
    shape: (j) => {
      const by_scope: Record<string, { active: number; revoked: number }> = {};
      let newest: string | null = null;
      for (const c of items("credentials_summary", j)) {
        const scope = String(need("credentials_summary", c, "scope")).slice(0, 40);
        const b = (by_scope[scope] ??= { active: 0, revoked: 0 });
        if (need("credentials_summary", c, "revoked_at")) b.revoked += 1; else b.active += 1;
        const used = need("credentials_summary", c, "last_used_at");
        if (typeof used === "string" && (!newest || used > newest)) newest = used;
      }
      return { by_scope, newest_last_used_at: newest, first_page_only: !!j.next_cursor };
    },
  },
  session_role: {
    path: "/v1/session", screen: "",
    // The vault lists every organization this person belongs to; only the one this capability names is kept.
    shape: (j, ctx) => {
      const mine = items("session_role", j).find((o) => o.org_id === ctx.org);
      if (!mine) throw new FieldMissing("session_role", "the capability's organization in items");
      return { role: need("session_role", mine, "role"), name: cap80(need("session_role", mine, "name")) };
    },
  },
};

const json = (status: number, body: unknown, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...extra } });

function sameSecret(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function configured(env: AssistEnv): Response | null {
  const missing = (["SUPPORT", "ASSIST_MARKER", "SESSION_GATE", "SESSIONS"] as const).filter((k) => !env[k]);
  if (missing.length === 0) return null;
  console.error(`consentvault assist ASSIST_NOT_CONFIGURED: ${missing.join(", ")} not set on the portal Worker; the assistant answers 503`);
  return json(503, { error: "assist_not_configured", message: "the assistant is not set up on this Worker" });
}

const alarm = (deps: GatewayDeps, name: string, detail: string) => (deps.alarm ?? ((n: string, d: string) => console.error(`consentvault assist alarm ${n}: ${d}`)))(name, detail);

async function viaGateway(env: AssistEnv, deps: GatewayDeps, sid: string, org: string, path: string): Promise<Response> {
  const req = new Request((env.PUBLIC_URL ?? "https://portal.invalid").replace(/\/+$/, "") + path, {
    method: "GET", headers: { cookie: `${SESSION_COOKIE}=${sid}`, "x-cv-org": org, accept: "application/json" },
  });
  return handleGateway(req, env, deps);
}

// POST /assist/ask ----------------------------------------------------------------------------------------------------------------------
async function ask(request: Request, env: AssistEnv, deps: GatewayDeps): Promise<Response> {
  if (request.method !== "POST") return json(405, { error: "method_not_allowed" });
  const bad = configured(env);
  if (bad) return bad;
  if (request.headers.get("origin") !== (env.PUBLIC_URL ?? "").replace(/\/+$/, "")) return json(403, { error: "origin_refused", message: "a question must come from the portal's own origin" });
  const now = (deps.now ?? Date.now)();
  const sid = cookieValue(request.headers.get("cookie"), SESSION_COOKIE);
  if (!sid) return json(401, { error: "no_session", message: "sign in to ask" });
  const store = sessionStoreFor({ SESSIONS: env.SESSIONS!, SESSION_GATE: env.SESSION_GATE, AUTH_BASE_URL: env.AUTH_BASE_URL!, AUTH_CLIENT_ID: env.AUTH_CLIENT_ID!, AUTH_CLIENT_SECRET: env.AUTH_CLIENT_SECRET }, deps.fetch);
  const rec = await store.load(sid, now);
  if (!rec) return json(401, { error: "no_session", message: "sign in to ask" }, { "set-cookie": clearCookie(SESSION_COOKIE) });
  if (!rec.org_id) return json(409, { error: "no_org_selected", message: "choose an organization first" });
  const named = request.headers.get("x-cv-org");
  if (!named || named !== rec.org_id) return json(409, { error: "org_mismatch", message: "this tab shows a different organization than the session's; reload to continue" });

  const declared = request.headers.get("content-length");
  if (declared !== null && Number(declared) > ASK_MAX_BODY) return json(413, { error: "too_large" });
  const raw = await request.text();
  if (raw.length > ASK_MAX_BODY) return json(413, { error: "too_large" });
  let b: J;
  try { b = JSON.parse(raw); } catch { return json(400, { kind: "error", error: "bad_json" }); }
  if (!b || typeof b !== "object" || typeof b.question !== "string" || typeof b.conversation_id !== "string") return json(400, { kind: "error", error: "bad_request" });
  const question = b.question.trim();
  if (!question) return json(400, { kind: "error", error: "empty_question" });
  if (question.length > ASK_MAX_QUESTION) return json(413, { kind: "error", error: "question_too_long" });

  // The role is the vault's answer for this person in this organization, never anything the browser said.
  const who = await viaGateway(env, deps, sid, rec.org_id, "/v1/session");
  if (!who.ok) return new Response(who.body, { status: who.status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
  const me = ((await who.json().catch(() => null)) as J | null)?.items?.find?.((o: J) => o.org_id === rec.org_id);
  if (!me || typeof me.role !== "string") return json(409, { error: "org_mismatch", message: "this sign-in does not belong to the organization this tab shows" });

  const secret = randomToken(32);
  const objectId = String(env.SESSION_GATE!.idFromName(sid));
  const questionId = "q_" + randomToken(12);
  const gate = env.SESSION_GATE!.get(env.SESSION_GATE!.idFromString(objectId));
  const minted = await gate.fetch(new Request("https://session-gate/op", { method: "POST", body: JSON.stringify({ op: "mintCap", sid, capHash: await sha256Hex(secret), org: rec.org_id, questionId, nowMs: now }) }));
  const mint = (await minted.json().catch(() => null)) as { ok?: boolean; reason?: CapReason } | null;
  if (!minted.ok || !mint?.ok) return json(mint?.reason === "too_many" ? 429 : 401, { error: mint?.reason ?? "no_session", message: "the assistant could not start for this sign-in" });

  const sub = tokenClaims(rec.token)?.sub ?? "";
  const toCore = {
    surface: "portal", conversation_id: b.conversation_id, question,
    role: me.role, capability: `${objectId}.${secret}`, question_id: questionId,
    member_key: await sha256Hex(`portal-member:${sub}:${rec.org_id}`),
    contact: { org_id: rec.org_id, email: rec.email ?? null },
  };
  let res: Response;
  try {
    res = await env.SUPPORT!.fetch(new Request("https://support/v1/ask", {
      method: "POST", headers: { "content-type": "application/json", "x-cv-support-binding": "1", [MARKER_HEADER]: env.ASSIST_MARKER! }, body: JSON.stringify(toCore), signal: AbortSignal.timeout(CORE_TIMEOUT_MS),
    }));
  } catch (e) {
    alarm(deps, "assist.core_unreachable", `the answer core did not answer (${(e as Error).name})`);
    return json(503, { kind: "unavailable", error: "support_core_unreachable", text: "Questions are not available right now." });
  }
  const text = await res.text();
  return new Response(text, { status: res.status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

// GET /assist/read/<tool> ---------------------------------------------------------------------------------------------------------------
async function read(request: Request, url: URL, env: AssistEnv, deps: GatewayDeps): Promise<Response> {
  if (request.method !== "GET") return json(405, { error: "method_not_allowed" });
  const bad = configured(env);
  if (bad) return bad;
  // Only the service binding carries the marker. A public request without it learns nothing, not even that the route exists.
  const marker = request.headers.get(MARKER_HEADER) ?? "";
  if (!sameSecret(marker, env.ASSIST_MARKER!)) return json(404, { error: "not_found" });
  const toolName = url.pathname.slice("/assist/read/".length);
  const tool = Object.prototype.hasOwnProperty.call(TOOLS, toolName) ? TOOLS[toolName] : null;
  if (!tool || url.search !== "") return json(404, { error: "unknown_tool", message: "no such tool" });

  const refused = (reason: CapReason, status = 403) => { alarm(deps, "support.reader_refused", `capability refused: ${reason}`); return json(status, { error: "capability_refused", reason }); };
  const cap = request.headers.get(CAPABILITY_HEADER) ?? "";
  const dot = cap.indexOf(".");
  const questionId = request.headers.get(QUESTION_HEADER) ?? "";
  if (dot < 1 || dot === cap.length - 1 || cap.length > 200 || !questionId) return refused("unknown");
  let gate: { fetch(r: Request): Promise<Response> };
  try { gate = env.SESSION_GATE!.get(env.SESSION_GATE!.idFromString(cap.slice(0, dot))); } catch { return refused("unknown"); }
  const now = (deps.now ?? Date.now)();
  const spent = await gate.fetch(new Request("https://session-gate/op", { method: "POST", body: JSON.stringify({ op: "spendCap", capHash: await sha256Hex(cap.slice(dot + 1)), questionId, nowMs: now }) }));
  const got = (await spent.json().catch(() => null)) as { ok: true; sid: string; org: string } | { ok: false; reason: CapReason } | null;
  if (!spent.ok || !got) return json(502, { error: "session_unavailable" });
  if (!got.ok) return refused(got.reason);

  const res = await viaGateway(env, deps, got.sid, got.org, tool.path);
  const body = (await res.json().catch(() => null)) as J | null;
  if (res.ok && body) {
    try {
      return json(200, { tool: toolName, fact_id: `f_${toolName}`, screen: tool.screen, data: tool.shape(body, { org: got.org }) });
    } catch (e) {
      if (e instanceof FieldMissing) {
        alarm(deps, "assist.field_missing", e.message);
        return json(502, { tool: toolName, error: "field_missing", field: e.field });
      }
      throw e;
    }
  }
  const code = typeof body?.error === "string" && /^[a-z_]{1,40}$/.test(body.error) ? body.error : "vault_error";
  if (res.status === 401) return refused("wrong_session");
  if (res.status === 409 && code === "org_mismatch") return refused("wrong_session");
  if (res.status >= 500) return json(502, { tool: toolName, error: code, status: res.status });
  // The vault's own refusal (a role that cannot read the screen, an acknowledgement not given) is the answer; no figure comes with it.
  return json(200, { tool: toolName, fact_id: null, screen: tool.screen, refused: code, status: res.status });
}

export const isAssistPath = (path: string): boolean => path.startsWith("/assist/");

export async function handleAssist(request: Request, env: AssistEnv, deps: GatewayDeps): Promise<Response> {
  const url = new URL(request.url);
  try {
    if (url.pathname === "/assist/ask") return await ask(request, env, deps);
    if (url.pathname.startsWith("/assist/read/")) return await read(request, url, env, deps);
    return json(404, { error: "not_found" });
  } catch (e) {
    console.error(`consentvault assist ERROR: ${(e as Error).name}: ${(e as Error).message}`);
    return json(500, { error: "assist_failure", message: "the assistant could not complete that request" });
  }
}

export const READER_LIMITS = { seconds: CAP_SECONDS, reads: CAP_READS };
