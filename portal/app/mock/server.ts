// Mock ConsentVault Cloud API + static host for the portal export. Node stdlib only.
//   node mock/server.ts --port 4010 [--static out]
// Control surface (tests only): POST /__mock/scenario {reset?, ...Scenario}, GET /__mock/log, GET /__mock/state.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type * as T from '../src/lib/api/types.ts';
import { ATTESTATION, CHANNELS, DEFAULT_SCENARIO, newStore, nid, ORG_ID, ORG_NAME, PLANS, PURPOSES, REFERENCES } from './data.ts';
import { isEd25519, isHmac } from '../src/lib/signature.ts';
import { registerRecords } from './records.ts';
import { registerConfirmations } from './confirmations.ts';
import type { FailRule, Scenario, Store } from './data.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
type Res = { status: number; body?: unknown; headers?: Record<string, string> };
type Ctx = { method: string; path: string; query: URLSearchParams; body: any; m: RegExpMatchArray; st: Store };

const E = (status: number, error: string, detail = '', fields?: Record<string, unknown>): Res => ({ status, body: { error, detail: detail || error.replace(/_/g, ' '), request_id: 'req_mock', ...(fields ? { fields } : {}) } });
const OK = (body: unknown, status = 200): Res => ({ status, body });
const nowIso = () => new Date().toISOString();

function page<X>(items: X[], q: URLSearchParams): T.Page<X> {
  const limit = Math.min(200, Math.max(1, Number(q.get('limit') ?? 50)));
  const start = q.get('cursor') ? Number(Buffer.from(q.get('cursor')!, 'base64url').toString()) : 0;
  const slice = items.slice(start, start + limit);
  const next = start + limit < items.length ? Buffer.from(String(start + limit)).toString('base64url') : null;
  return { items: slice, next_cursor: next };
}

const isAdmin = (c: Ctx) => c.st.role === 'admin';
const refuse = (c: Ctx) => E(403, 'role_not_allowed', `The ${c.st.role} role may not call this endpoint.`, { role: c.st.role });
const allow = (c: Ctx, ...roles: T.Role[]) => (roles.includes(c.st.role) ? null : refuse(c));
const suspendedBlock = (c: Ctx) => (c.st.status === 'suspended' ? E(403, 'org_suspended', 'Paused while the organization is suspended.') : c.st.status === 'closed' || c.st.status === 'offboarding' ? E(403, 'org_not_active', 'Organization is not active.') : null);

function membership(st: Store): T.Membership { return { org_id: ORG_ID, name: ORG_NAME, role: st.role, status: st.status }; }
function otherMembership(): T.Membership { return { org_id: 'org_solar', name: 'Acme Solar', role: 'compliance_viewer', status: 'past_due' }; }

function brandCounts(st: Store): void {
  for (const b of st.brands) { b.source_count = st.sources.filter((s) => s.brand_ids.includes(b.brand_id)).length; }
}

function sealStr(st: Store): { sealed: boolean } { return { sealed: st.scenario.firstEvent !== 'unsealed' }; }

function proofFor(st: Store, contactKey: string): Res {
  const sc = st.scenario;
  const digits = contactKey.replace(/\D/g, '');
  if (digits.endsWith('0503')) return E(503, 'key_unavailable', 'The organization key did not answer.');
  if (!(digits.endsWith('0100') || digits.endsWith('0101') || digits.endsWith('0102') || digits.endsWith('0103') || contactKey === 'dana.test@example.com')) {
    return OK({ found: false, evaluated_at: nowIso(), notice: 'Evidence status and the outcome of your organization\'s approved policy. Not a legal determination.', permissions: [], timeline: null, disclosures: null, gate_decisions: null, contact_log: null, reviews: null, doc_check_results: null, chain: null });
  }
  const unsealed = digits.endsWith('0101');
  const review = digits.endsWith('0102');
  const partial = digits.endsWith('0103') || sc.nulls.includes('proof_gate');
  const inForce = st.policies.find((p) => p.status === 'approved');
  const pv = inForce ? inForce.version : null;
  const act = (a: 'proceed' | 'hold') => (inForce ? a : null);
  return OK({
    found: true, evaluated_at: nowIso(), notice: "Evidence status and the outcome of your organization's approved policy. Not a legal determination.",
    permissions: [
      { channel: 'sms', purpose: 'marketing', evidence_status: 'stop_on_record', policy_action: act('hold'), policy_version: pv, basis_event_ids: ['evt_9'] },
      { channel: 'voice', purpose: 'marketing', evidence_status: 'stop_on_record', policy_action: act('hold'), policy_version: pv, basis_event_ids: ['evt_9'] },
      { channel: 'email', purpose: 'marketing', evidence_status: 'no_record', policy_action: act('proceed'), policy_version: pv, basis_event_ids: [] },
      { channel: 'artificial_voice', purpose: 'marketing', evidence_status: 'record_incomplete:not_a_condition_of_purchase', policy_action: act('hold'), policy_version: pv, basis_event_ids: ['evt_1'] },
    ],
    timeline: { items: [
      { event_id: 'evt_1', seq: 1, event_type: 'grant', at: '2026-10-31T14:42:07Z', channels: ['sms', 'voice'], purposes: ['marketing'], source_id: 'src_web', brand_ids: ['brd_acme'], disclosure_sha256: '9f2c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6ee1', sealed: !unsealed, sealed_at: unsealed ? null : '2026-10-31T14:58:00Z', recorded_during_trial: sc.orgStatus === 'trial' },
      { event_id: 'evt_9', seq: 9, event_type: 'revoke', at: '2026-11-02T20:10:00Z', channels: ['sms', 'voice'], purposes: ['marketing'], source_id: 'src_sms', brand_ids: ['brd_acme'], disclosure_sha256: null, sealed: true, sealed_at: '2026-11-02T20:31:00Z', recorded_during_trial: false },
    ], next_cursor: null },
    disclosures: [{ sha256: '9f2c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6ee1', label: '2026-10', version_label: '2026-10' }],
    gate_decisions: partial ? null : { items: [
      { decision_id: 'gd_2', at: '2026-11-02T21:00:00Z', channel: 'sms', purpose: 'marketing', evidence_status: 'stop_on_record', policy_action: act('hold'), policy_version: pv },
      { decision_id: 'gd_1', at: '2026-11-01T14:00:00Z', channel: 'sms', purpose: 'marketing', evidence_status: 'consent_record_found', policy_action: act('proceed'), policy_version: pv },
    ], next_cursor: null },
    contact_log: { items: [], next_cursor: null },
    reviews: review ? { items: [{ review_id: 'rv_1', at: '2026-11-03T15:00:00Z', kind: 'contact_control_unverified', event_id: 'evt_12' }], next_cursor: null } : { items: [], next_cursor: null },
    doc_check_results: [{ event_id: 'evt_1', checklist_version: 2, present: ['el_seller', 'el_channels', 'el_auto', 'el_agree'], missing: ['el_cond'] }],
    chain: { head: 'c81e44aa', events: 2, path: 'chain', anchors: [{ at: '2026-11-02T09:00:00Z', ok: true }] },
    ...(partial ? { partial: ['gate_decisions'] } : {}),
  });
}

type Handler = (c: Ctx) => Res | Promise<Res>;
const routes: { method: string; re: RegExp; h: Handler }[] = [];
const route = (method: string, pattern: string, h: Handler) => {
  const re = new RegExp('^' + pattern.replace(/(?<!\\):([a-z_]+)/g, '(?<$1>[^/:]+)').replace(/\//g, '\\/') + '$');
  routes.push({ method, re, h });
};

// ---- session ----
route('GET', '/v1/session', (c) => {
  if (c.st.scenario.noSecondFactor) return E(403, 'second_factor_required', 'No passkey or second factor in the sign-in.');
  const items = c.st.scenario.orgs === 'none' ? [] : c.st.scenario.orgs === 'two' ? [membership(c.st), otherMembership()] : [membership(c.st)];
  if (c.st.scenario.nulls.includes('org2_status') && items[1]) (items[1] as any).status = null;
  return OK({ user: { display_name: 'Dana Ruiz', email: 'dana@acme.com' }, items, next_cursor: null });
});
route('POST', '/v1/session/org', (c) => {
  if (c.body?.org_id === 'org_solar') { c.st.currentOrg = 'org_solar'; return OK(otherMembership()); }
  if (c.body?.org_id !== ORG_ID) return E(404, 'not_found');
  c.st.currentOrg = ORG_ID; return OK(membership(c.st));
});
route('GET', '/v1/org', (c) => {
  if (!c.st.currentOrg) return E(403, 'not_a_member', 'No organization chosen for this session.');
  const st = c.st;
  if (st.currentOrg === 'org_solar') return OK({ org_id: 'org_solar', name: 'Acme Solar', status: 'past_due', region: 'us', role: 'compliance_viewer' });
  if (st.role !== 'admin') return OK({ org_id: ORG_ID, name: ORG_NAME, status: st.status, region: 'us', role: st.role });
  const steps: T.OffboardingStep[] = [
    { step: 'final_export', status: 'done', at: '2026-11-04T14:00:00Z' }, { step: 'credentials_revoked', status: 'done', at: '2026-11-04T15:00:00Z' },
    { step: 'key_destruction_scheduled', status: 'pending', at: null }, { step: 'destruction_record', status: 'pending', at: null },
  ];
  const off = st.scenario.offboarding || st.status === 'offboarding' || st.status === 'closed';
  const nul = st.scenario.nulls.includes('key');
  return OK({
    org_id: ORG_ID, name: ORG_NAME, status: st.status, region: 'us', created_at: '2026-10-29T14:00:00Z', plan: st.status === 'trial' ? null : { plan_id: 'plan_growth', name: 'Growth' },
    sso: (c.st as any).sso ?? { connected: c.st.scenario.sso !== 'none', connection_id: c.st.scenario.sso === 'verified' ? 'conn_01E4ZCR3C56J083X43JQXF3JK5' : null, required: false, verified: c.st.scenario.sso === 'verified' },
    key: nul ? null : { status: 'active', version: 1, destroy_after: off ? '2026-12-04T14:00:00Z' : null },
    offboarding: off ? { requested_at: '2026-11-03T14:00:00Z', requested_by: 'Dana Ruiz', state: 'in_progress', steps, destroy_after: '2026-12-04T14:00:00Z', held: { legal_hold_active: false, since: null } }
      : st.offboardingRequested ? { requested_at: nowIso(), requested_by: 'Dana Ruiz', state: 'requested', steps: [], destroy_after: null, held: { legal_hold_active: false, since: null } } : null,
    trial: st.status === 'trial' ? { started_at: '2026-10-29T14:00:00Z' } : null, ...(nul ? { partial: ['key'] } : {}),
  });
});
route('GET', '/v1/health', (c) => {
  const sc = c.st.scenario;
  if (sc.nulls.includes('health')) return OK({ evaluated_at: nowIso(), unsealed_events_over_1h: null, dead_deliveries: null, last_chain_verification: null, first_event: null });
  const dead = c.st.systems.reduce((n, s) => n + (c.st.deliveries[s.system_id] ?? []).filter((d) => d.status === 'dead').length, 0);
  const first = sc.firstEvent === 'none' ? null : { at: '2026-10-31T14:42:07Z', sealed: sc.firstEvent === 'sealed' };
  const counts: Record<string, number> = { 'restore.stops_unconfirmed': 2, reveal_volume: 5200 };
  const alarms = sc.alarms.map((name, i) => ({ name, since: new Date(Date.now() - (i + 1) * 3600e3).toISOString(), count: counts[name] ?? null, next_action: `Next step for ${name}.` }))
    .filter((a) => c.st.role === 'admin' || (c.st.role === 'compliance_viewer' && a.name !== 'billing.second_live_subscription'));
  return OK({ evaluated_at: nowIso(), unsealed_events_over_1h: 0, dead_deliveries: dead, last_chain_verification: { at: nowIso(), result: 'ok' }, first_event: first, alarms: sc.nulls.includes('alarms') ? null : alarms });
});
route('POST', '/v1/offboarding-requests', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  if (c.body?.org_name !== ORG_NAME) return E(422, 'org_name_mismatch');
  if (!c.body?.reason) return E(422, 'validation_failed', '', { reason: 'required' });
  if (c.st.offboardingRequested) return E(409, 'offboarding_already_requested');
  c.st.offboardingRequested = true; return OK({ request_id: nid('ofr'), status: 'requested', requested_at: nowIso() }, 202);
});

// ---- invites and members ----
route('GET', '/v1/invites/:token', (c) => {
  const mode = c.st.scenario.inviteMode; const tok = c.m.groups!.token;
  if (tok === 'missing') return E(404, 'invite_not_found');
  if (mode === 'expired') return E(410, 'invite_expired', 'Invitations last 7 days.', { expired_on: '2026-11-05' });
  if (mode === 'used') return E(410, 'invite_used', '', { used_on: '2026-10-30' });
  if (mode === 'withdrawn') return E(410, 'invite_withdrawn');
  return OK({ org_name: ORG_NAME, role: 'admin', invited_by_name: 'The Innovative Native (operator)', invited_email_hint: 'd***@acme.com', expires_at: '2026-11-05T15:42:00Z' });
});
route('POST', '/v1/invites/:token\\:accept', (c) => {
  if (c.st.scenario.inviteMode === 'wrong_account') return E(403, 'invite_wrong_account', 'The invitation was sent to d***@acme.com.');
  c.st.currentOrg = ORG_ID; return OK(membership(c.st));
});
route('GET', '/v1/members', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  let items = c.st.members;
  if (c.query.get('include') !== 'invites') items = items.filter((m) => m.kind === 'member');
  return OK(page(items, c.query));
});
route('POST', '/v1/members', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const email = String(c.body?.email ?? '').toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !c.body?.role) return E(422, 'validation_failed', '', { email: 'invalid' });
  if (c.st.members.some((m) => m.email === email)) return E(409, 'already_member');
  const id = nid('inv'); const exp = new Date(Date.now() + 7 * 864e5).toISOString();
  c.st.members.push({ kind: 'invite', id, display_name: null, email, role: c.body.role, status: 'invited', created_at: nowIso(), last_sign_in_at: null, expires_at: exp, invited_by_name: 'Dana Ruiz' });
  return OK({ invite_id: id, email, role: c.body.role, expires_at: exp }, 201);
});
route('PATCH', '/v1/members/:id', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const m = c.st.members.find((y) => y.id === c.m.groups!.id); if (!m) return E(404, 'not_found');
  if (m.role === 'admin' && c.body.role !== 'admin' && c.st.members.filter((y) => y.role === 'admin' && y.kind === 'member').length <= 1) return E(409, 'last_admin');
  m.role = c.body.role; return OK({ member_id: m.id, role: m.role });
});
route('DELETE', '/v1/members/:id', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const m = c.st.members.find((y) => y.id === c.m.groups!.id); if (!m) return E(404, 'not_found');
  if (m.role === 'admin' && c.st.members.filter((y) => y.role === 'admin' && y.kind === 'member').length <= 1) return E(409, 'last_admin');
  c.st.members = c.st.members.filter((y) => y !== m); return { status: 204 };
});
route('DELETE', '/v1/invites/:id', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const before = c.st.members.length; c.st.members = c.st.members.filter((y) => y.id !== c.m.groups!.id);
  return before === c.st.members.length ? E(404, 'not_found') : { status: 204 };
});
route('GET', '/v1/audit', (c) => {
  const x = allow(c, 'admin', 'compliance_viewer'); if (x) return x;
  let items = c.st.audit.slice();
  const a = c.query.get('action'); if (a) items = items.filter((r) => r.action === a);
  const w = c.query.get('actor'); if (w) items = items.filter((r) => r.actor.id === w);
  const f = c.query.get('from'); if (f) items = items.filter((r) => r.at >= f);
  const t = c.query.get('to'); if (t) items = items.filter((r) => r.at <= t);
  if (c.st.scenario.nulls.includes('audit_names')) items = items.map((r) => ({ ...r, actor: { ...r.actor, display_name: null } }));
  return OK(page(items, c.query));
});
route('GET', '/v1/audit/actions', (c) => {
  const x = allow(c, 'admin', 'compliance_viewer'); if (x) return x;
  const names = [...new Set(c.st.audit.map((r) => r.action))].sort();
  return OK(page(names.map((n) => ({ action: n, label: n })), c.query));
});

// ---- brands, sources, credentials ----
route('GET', '/v1/brands', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  brandCounts(c.st);
  const nul = c.st.scenario.nulls.includes('source_counts');
  return OK(page(c.st.brands.map((b) => (nul ? { ...b, source_count: null, disclosure_count: null } : b)), c.query));
});
route('POST', '/v1/brands', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const name = String(c.body?.display_name ?? '').trim();
  if (!name) return E(422, 'validation_failed', '', { display_name: 'required' });
  if (c.st.brands.some((b) => b.display_name.toLowerCase() === name.toLowerCase())) return E(409, 'brand_exists');
  const b = { brand_id: nid('brd'), display_name: name, created_at: nowIso(), source_count: 0, disclosure_count: 0 };
  c.st.brands.push(b); return OK({ brand_id: b.brand_id, display_name: b.display_name, created_at: b.created_at }, 201);
});
// admin.md (ruled 2026-10-31): the one brand and source read a compliance viewer has: ids and names, nothing else
route('GET', '/v1/brand-names', (c) => {
  const x = allow(c, 'admin', 'developer', 'compliance_viewer'); if (x) return x;
  return OK(page(c.st.brands.slice().sort((a, b) => a.display_name.localeCompare(b.display_name)).map((b) => ({ brand_id: b.brand_id, display_name: b.display_name })), c.query));
});
route('GET', '/v1/source-names', (c) => {
  const x = allow(c, 'admin', 'developer', 'compliance_viewer'); if (x) return x;
  return OK(page(c.st.sources.slice().sort((a, b) => a.name.localeCompare(b.name)).map((s) => ({ source_id: s.source_id, name: s.name })), c.query));
});
route('GET', '/v1/sources', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const nul = c.st.scenario.nulls.includes('last_event');
  const items = c.st.sources.map((s) => (nul ? { ...s, last_event_at: null, last_event_seq: null, last_event_sealed: null, partial: ['last_event'] } : s));
  return OK(page(items, c.query));
});
route('GET', '/v1/sources/:id', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const s = c.st.sources.find((y) => y.source_id === c.m.groups!.id); return s ? OK(s) : E(404, 'not_found');
});
const originOk = (o: string) => /^https?:\/\/[^/\s]+$/.test(o);
route('POST', '/v1/sources', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const b = c.body ?? {};
  if (!b.name || !Array.isArray(b.brand_ids) || b.brand_ids.length < 1) return E(422, 'validation_failed', '', { brand_ids: 'at least one' });
  if (b.kind === 'site_key') {
    const bad = (b.allowed_origins ?? []).find((o: string) => !originOk(o));
    if (!(b.allowed_origins ?? []).length) return E(422, 'validation_failed', '', { allowed_origins: 'at least one' });
    if (bad) return E(422, 'invalid_origin', `${bad} is not an origin.`, { origin: bad });
  }
  if (c.st.sources.some((s) => s.name.toLowerCase() === String(b.name).toLowerCase())) return E(409, 'source_exists');
  const s: T.Source = { source_id: nid('src'), name: b.name, kind: b.kind, brand_ids: b.brand_ids, allowed_origins: b.kind === 'server' ? [] : b.allowed_origins, status: 'active', created_at: nowIso(), last_event_at: null, last_event_seq: null, last_event_sealed: null };
  c.st.sources.unshift(s); return OK(s, 201);
});
route('PATCH', '/v1/sources/:id', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const s = c.st.sources.find((y) => y.source_id === c.m.groups!.id); if (!s) return E(404, 'not_found');
  Object.assign(s, c.body); return OK(s);
});
const WIDGET_MAP: T.FieldMapBuiltIn = {
  label: 'built_in:widget', body_format: 'json', consent_paths: ['/checked'], consent_ticked_value: null, seller_paths: null,
  contact_paths: [{ path: '/contact', kind: 'detect' }], decision_time_path: '/decided_at', wording_path: '/disclosure_text', wording_hash_path: '/disclosure_sha256',
  form_version_path: null, checkbox_default_path: null, submit_context_path: null, third_party_cert_path: null, jurisdiction_path: null, channel_scope_path: null,
};
route('GET', '/v1/sources/:id/field-maps', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const id = c.m.groups!.id;
  if (!c.st.sources.some((y) => y.source_id === id)) return E(404, 'not_found');
  return OK({ items: (c.st.fieldMaps[id] ?? []).slice().sort((a, b) => b.map_version - a.map_version), built_in: WIDGET_MAP });
});
route('POST', '/v1/sources/:id/field-maps', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const id = c.m.groups!.id;
  const src = c.st.sources.find((y) => y.source_id === id);
  if (!src) return E(404, 'not_found');
  if (src.status !== 'active') return E(422, 'validation_failed', '', { source_id: 'that source is retired' });
  const b = c.body ?? {};
  if (!['json', 'form_urlencoded', 'multipart', 'text'].includes(b.body_format)) return E(422, 'validation_failed', '', { body_format: 'one of the four formats' });
  if (!Array.isArray(b.consent_paths) || b.consent_paths.length < 1) return E(422, 'validation_failed', '', { consent_paths: 'at least one' });
  const list = (c.st.fieldMaps[id] ??= []);
  const v: T.FieldMapVersion = {
    source_id: id, map_version: list.length + 1, body_format: b.body_format, consent_paths: b.consent_paths, consent_ticked_value: b.consent_ticked_value ?? null,
    seller_paths: b.seller_paths ?? null, contact_paths: b.contact_paths ?? [], decision_time_path: b.decision_time_path ?? null, wording_path: b.wording_path ?? null,
    wording_hash_path: b.wording_hash_path ?? null, form_version_path: b.form_version_path ?? null, checkbox_default_path: b.checkbox_default_path ?? null,
    submit_context_path: b.submit_context_path ?? null, third_party_cert_path: b.third_party_cert_path ?? null, jurisdiction_path: b.jurisdiction_path ?? null,
    channel_scope_path: b.channel_scope_path ?? null, set_by: 'Dana Ruiz', set_at: nowIso(),
  };
  list.push(v); return OK(v, 201);
});
route('GET', '/v1/credentials', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  let items = c.st.credentials; if (c.st.role === 'developer') items = items.filter((y) => y.scope === 'capture');
  return OK(page(items, c.query));
});
route('POST', '/v1/credentials', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const b = c.body ?? {};
  if (c.st.role === 'developer' && b.scope !== 'capture') return refuse(c);
  const sus = suspendedBlock(c); if (sus) return sus;
  if (typeof b.public_key === 'string' && /PRIVATE KEY/.test(b.public_key)) return E(422, 'private_key_refused', 'The pasted material contains a private key.');
  if (b.scope === 'gate_read' && !c.st.policies.some((p) => p.status === 'approved')) return E(409, 'policy_required');
  if (!b.name || !b.kind || !b.scope) return E(422, 'validation_failed');
  const id = nid('crd');
  c.st.credentials.unshift({ credential_id: id, name: b.name, kind: b.kind, scope: b.scope, source_id: b.source_id ?? null, algorithm: b.algorithm ?? null, created_by: 'Dana Ruiz', created_at: nowIso(), revoked_at: null, last_used_at: null });
  const out: any = { credential_id: id, name: b.name, kind: b.kind, scope: b.scope, source_id: b.source_id ?? null, algorithm: b.algorithm ?? null, created_at: nowIso(), shown_once: b.kind === 'hmac_fallback' };
  if (b.kind === 'edge_site_key') out.site_key_id = 'cv_site_8Hq2';
  if (b.kind === 'jwt_public_key') out.client_id = `cv_client_${id.slice(-5)}`;
  if (b.kind === 'hmac_fallback') { out.client_id = `cv_client_${id.slice(-5)}`; out.secret = 'whsec_mock_7f3a9c1e5b2d4a6f8c0e1b3d5f7a9c2e'; }
  return OK(out, 201);
});
route('POST', '/v1/credentials/:id\\:revoke', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const cr = c.st.credentials.find((y) => y.credential_id === c.m.groups!.id); if (!cr) return E(404, 'not_found');
  if (cr.revoked_at) return E(409, 'already_revoked');
  if (!c.body?.reason) return E(422, 'validation_failed', '', { reason: 'required' });
  cr.revoked_at = nowIso(); return OK({ credential_id: cr.credential_id, revoked_at: cr.revoked_at });
});
route('GET', '/v1/retention', (c) => {
  const x = allow(c, 'admin', 'compliance_viewer'); if (x) return x;
  const items = c.st.retention;
  if (c.st.scenario.nulls.includes('retention_history')) return OK({ current: items[0] ?? null, platform_minimum_years: 5, items: [], next_cursor: null, partial: ['history'] });
  return OK({ current: items[0] ?? null, platform_minimum_years: 5, items: page(items, c.query).items, next_cursor: null });
});
route('PUT', '/v1/org/sso', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const keys = Object.keys(c.body ?? {}); const req = c.body?.require_sso;
  if (keys.some((k) => k !== 'require_sso') || typeof req !== 'boolean') return E(422, 'validation_failed', 'Not accepted: the connection is bound by your operator.');
  const before = (c.st as any).sso ?? { connected: c.st.scenario.sso !== 'none', connection_id: c.st.scenario.sso === 'verified' ? 'conn_01E4ZCR3C56J083X43JQXF3JK5' : null, required: false, verified: c.st.scenario.sso === 'verified' };
  if (req && !before.verified) return E(422, 'validation_failed', 'Sign in through your company account as an admin first.');
  (c.st as any).sso = { ...before, required: req };
  return OK({ version: 1, connection_id: before.connection_id, required: req, verified: before.verified, applies_from: nowIso() });
});
route('PUT', '/v1/retention', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const y = Number(c.body?.evidence_years);
  if (!Number.isFinite(y)) return E(422, 'validation_failed');
  if (y < 5) return E(422, 'below_platform_minimum', `${y} years is below the platform minimum of 5 years.`, { minimum: 5 });
  const v = { version: (c.st.retention[0]?.version ?? 0) + 1, evidence_years: y, applies_from: nowIso(), set_by: 'Dana Ruiz' };
  c.st.retention.unshift(v); return OK({ version: v.version, evidence_years: y, applies_from: v.applies_from });
});
route('POST', '/v1/contacts\\:erase', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const d = String(c.body?.contact ?? '').replace(/\D/g, '');
  if (d.endsWith('0666')) return E(409, 'legal_hold_active', 'A legal hold covers this contact.');
  if (!c.body?.reason) return E(422, 'validation_failed', '', { reason: 'required' });
  return OK({ erasure_id: nid('ers'), status: 'pending_operator_confirmation' }, 202);
});

// ---- policy ----
route('GET', '/v1/channels', (c) => OK(page(CHANNELS, c.query)));
route('GET', '/v1/purposes', (c) => OK(page(PURPOSES, c.query)));
route('GET', '/v1/disclosures', (c) => OK(page(c.st.disclosures.map(({ body: _b, ...r }) => r), c.query)));
route('GET', '/v1/disclosures/:sha', (c) => { const d = c.st.disclosures.find((y) => y.sha256 === c.m.groups!.sha); return d ? OK(d) : E(404, 'not_found'); });
route('POST', '/v1/disclosures', async (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const b = c.body ?? {};
  if (typeof b.body !== 'string' || !b.body || !b.label || !(b.channels ?? []).length || !(b.purposes ?? []).length || !(b.brand_ids ?? []).length) return E(422, 'validation_failed');
  const { createHash } = await import('node:crypto');
  const sha = createHash('sha256').update(b.body, 'utf8').digest('hex');
  const ex = c.st.disclosures.find((d) => d.sha256 === sha); if (ex) return E(409, 'disclosure_exists', 'Already registered.', { sha256: sha });
  const d: T.Disclosure = { sha256: sha, label: b.label, version_label: b.label, channels: b.channels, purposes: b.purposes, brand_ids: b.brand_ids, supersedes_sha256: b.supersedes_sha256 ?? null, superseded_by_sha256: null, effective_from: b.effective_from, registered_by: 'Dana Ruiz', registered_at: nowIso(), body: b.body };
  if (d.supersedes_sha256) { const o = c.st.disclosures.find((y) => y.sha256 === d.supersedes_sha256); if (o) o.superseded_by_sha256 = sha; }
  c.st.disclosures.unshift(d); return OK(d, 201);
});
route('GET', '/v1/policies', (c) => {
  let items = c.st.policies.map(({ rules: _r, attestation: _a, ...r }) => r) as T.PolicyItem[];
  const s = c.query.get('status'); if (s) items = items.filter((p) => p.status === s);
  if (c.st.scenario.nulls.includes('approver')) items = items.map((p) => ({ ...p, approved_by: null }));
  return OK(page(items, c.query));
});
route('GET', '/v1/policies/:v', (c) => { const p = c.st.policies.find((y) => String(y.version) === c.m.groups!.v); return p ? OK(p) : E(404, 'not_found'); });
route('POST', '/v1/policies', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const v = Math.max(0, ...c.st.policies.map((p) => p.version)) + 1;
  c.st.policies.unshift({ version: v, status: 'draft', template_ref: c.body.template_ref ?? null, based_on_version: c.body.based_on_version ?? null, created_by: 'Dana Ruiz', created_at: nowIso(), approved_by: null, approved_at: null, retired_at: null, retired_by_version: null, rules: c.body.rules });
  return OK({ version: v, status: 'draft' }, 201);
});
route('PUT', '/v1/policies/:v', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const p = c.st.policies.find((y) => String(y.version) === c.m.groups!.v); if (!p) return E(404, 'not_found');
  if (p.status !== 'draft') return E(409, 'version_not_draft'); p.rules = c.body.rules; return OK(p);
});
route('POST', '/v1/policies/:v\\:approve', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const p = c.st.policies.find((y) => String(y.version) === c.m.groups!.v); if (!p) return E(404, 'not_found');
  if (c.body?.accepted !== true) return E(422, 'acknowledgement_required');
  if (c.body.attestation_version !== ATTESTATION.version) return E(409, 'attestation_mismatch');
  if (p.status !== 'draft') return E(409, 'version_not_draft');
  const cur = c.st.policies.find((y) => y.status === 'approved');
  if (p.based_on_version && cur && cur.version !== p.based_on_version) return E(409, 'policy_superseded', 'A newer version is in force.', { newer_version: cur.version });
  let retired = null as null | { version: number; retired_at: string };
  if (cur) { cur.status = 'retired'; cur.retired_at = nowIso(); cur.retired_by_version = p.version; retired = { version: cur.version, retired_at: cur.retired_at }; }
  p.status = 'approved'; p.approved_by = 'Dana Ruiz'; p.approved_at = nowIso(); p.attestation = { version: 1, sha256: ATTESTATION.sha256 };
  return OK({ version: p.version, status: 'approved', approved_by: 'Dana Ruiz', approved_at: p.approved_at, retired });
});
route('GET', '/v1/policy-templates', (c) => {
  const p = (hold: boolean): T.PolicyRules => ({ schema_version: 1, purposes: { marketing: { checklist_version: null, cells: (['consent_record_found', 'stop_on_record', 'no_record', 'record_incomplete', 'unavailable'] as const).flatMap((st) => ['sms', 'voice', 'artificial_voice', 'email'].map((ch) => ({ evidence_status: st, channel: ch, action: (st === 'consent_record_found' ? 'proceed' : hold ? 'hold' : st === 'stop_on_record' ? 'hold' : 'proceed') as 'proceed' | 'hold' }))) } } });
  return OK(page([{ template_ref: 'hold_unless_found', label: 'Template: hold unless a consent record is found', description: 'Hold everything except a found record.', rules: p(true) }], c.query));
});
route('GET', '/v1/attestations/current', () => OK(ATTESTATION));
route('GET', '/v1/checklists', (c) => OK(page(c.st.checklists.map(({ elements: _e, ...r }) => r), c.query)));
route('GET', '/v1/checklists/:v', (c) => { const p = c.st.checklists.find((y) => String(y.version) === c.m.groups!.v); return p ? OK(p) : E(404, 'not_found'); });
route('GET', '/v1/checklist-templates', (c) => OK(page([{ template_ref: 'pewc_example', kind: 'pewc', label: 'PEWC example', elements: [
  { element_id: 'tpl_1', name: 'Seller named', description: 'the brand name', required: true, rule_reference_id: 'ref_fed' },
  { element_id: 'tpl_2', name: 'Channels named', description: 'texts and calls', required: true, rule_reference_id: 'ref_fed' },
  { element_id: 'tpl_3', name: 'Agreement captured', description: 'checkbox ticked', required: true, rule_reference_id: 'ref_fed' },
] }], c.query)));
route('POST', '/v1/checklists', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const v = Math.max(0, ...c.st.checklists.map((p) => p.version)) + 1;
  const els = (c.body.elements ?? []).map((e: any) => ({ ...e, element_id: nid('el') }));
  const cl: T.ChecklistDetail = { version: v, kind: c.body.kind, label: c.body.label, status: 'draft', element_count: els.length, created_at: nowIso(), approved_by: null, approved_at: null, elements: els };
  c.st.checklists.unshift(cl); return OK(cl, 201);
});
route('PUT', '/v1/checklists/:v', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const p = c.st.checklists.find((y) => String(y.version) === c.m.groups!.v); if (!p) return E(404, 'not_found');
  if (p.status !== 'draft') return E(409, 'version_not_draft');
  p.elements = (c.body.elements ?? []).map((e: any) => ({ ...e, element_id: e.element_id ?? nid('el') })); p.element_count = p.elements.length; if (c.body.label) p.label = c.body.label; return OK(p);
});
route('POST', '/v1/checklists/:v\\:approve', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const p = c.st.checklists.find((y) => String(y.version) === c.m.groups!.v); if (!p) return E(404, 'not_found');
  if (c.body?.acknowledged_documentation_only !== true) return E(422, 'acknowledgement_required');
  if (p.status !== 'draft') return E(409, 'version_not_draft');
  p.status = 'approved'; p.approved_by = 'Dana Ruiz'; p.approved_at = nowIso(); return OK({ version: p.version, status: 'approved', approved_by: 'Dana Ruiz', approved_at: p.approved_at });
});
route('GET', '/v1/rule-references', (c) => {
  if (c.st.scenario.empty.includes('references')) return OK({ items: [], next_cursor: null });
  const j = c.query.get('jurisdiction'); let items = REFERENCES.slice();
  if (j) items = items.filter((r) => r.jurisdiction === j);
  if (c.st.scenario.nulls.includes('review_dates')) items = items.map((r) => ({ ...r, last_reviewed_on: null }));
  return OK(page(items, c.query));
});

// ---- systems ----
const countsFor = (st: Store, id: string) => { const d = st.deliveries[id] ?? []; return { pending: d.filter((x) => x.status === 'pending').length, dead: d.filter((x) => x.status === 'dead').length, acknowledged_24h: d.filter((x) => x.status === 'acknowledged').length }; };
route('GET', '/v1/systems', (c) => OK(page(c.st.systems.map((s) => ({ ...s, counts: c.st.scenario.nulls.includes('system_counts') ? null : countsFor(c.st, s.system_id) })), c.query)));
route('GET', '/v1/systems/:id', (c) => { const s = c.st.systems.find((y) => y.system_id === c.m.groups!.id); return s ? OK({ ...s, counts: c.st.scenario.nulls.includes('system_counts') ? null : countsFor(c.st, s.system_id) }) : E(404, 'not_found'); });
route('POST', '/v1/systems', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const sus = suspendedBlock(c); if (sus) return sus;
  const b = c.body ?? {};
  if (!b.name || !b.kind || !b.endpoint) return E(422, 'validation_failed');
  if (!/^https:\/\//.test(b.endpoint)) return E(422, 'endpoint_not_https');
  if (c.st.systems.some((s) => s.name.toLowerCase() === String(b.name).toLowerCase())) return E(409, 'system_exists');
  const s: T.System = { system_id: nid('sys'), name: b.name, kind: b.kind, connector: 'generic_webhook', endpoint: b.endpoint, signature: b.signature, contact_form: b.contact_form, retry_window_hours: b.retry_window_hours ?? 24, status: 'active', public_key: isEd25519(b.signature) ? 'MCowBQYDK2VwAyEAmock0PublicKey0Value0Here000000000000000' : null, created_at: nowIso(), last_delivery_at: null, counts: { pending: 0, dead: 0, acknowledged_24h: 0 }, last_test: null };
  c.st.systems.push(s); c.st.deliveries[s.system_id] = [];
  return OK({ ...s, ...(isHmac(b.signature) ? { hmac_secret: 'hmac_mock_2b4d6f8a0c1e3a5b7d9f1c3e5a7b9d1f' } : {}) }, 201);
});
route('PATCH', '/v1/systems/:id', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const s = c.st.systems.find((y) => y.system_id === c.m.groups!.id); if (!s) return E(404, 'not_found');
  if (c.body.endpoint && !/^https:\/\//.test(c.body.endpoint)) return E(422, 'endpoint_not_https');
  Object.assign(s, c.body); return OK(s);
});
route('POST', '/v1/systems/:id\\:test', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const s = c.st.systems.find((y) => y.system_id === c.m.groups!.id); if (!s) return E(404, 'not_found');
  c.st.testPushes[s.system_id] = (c.st.testPushes[s.system_id] ?? 0) + 1;
  const bad = s.name.toLowerCase().includes('dialer') && c.st.scenario.nulls.includes('test_push_401');
  const r: T.TestPush = bad ? { result: 'rejected', http_status: 401, latency_ms: 120, at: nowIso() } : { result: 'accepted', http_status: 200, latency_ms: 140, at: nowIso() };
  s.last_test = { at: r.at, result: r.result, http_status: r.http_status, latency_ms: r.latency_ms }; return OK(r);
});
route('GET', '/v1/systems/:id/deliveries', (c) => {
  const x = allow(c, 'admin', 'developer', 'compliance_viewer'); if (x) return x;
  let items = c.st.deliveries[c.m.groups!.id] ?? []; const s = c.query.get('status'); if (s) items = items.filter((d) => d.status === s);
  return OK(page(items, c.query));
});
route('POST', '/v1/deliveries\\:redrive', (c) => {
  const x = allow(c, 'admin', 'developer'); if (x) return x;
  const sus = suspendedBlock(c); if (sus) return sus;
  const id = c.body?.system_id; if (!c.st.systems.find((s) => s.system_id === id)) return E(404, 'not_found');
  if (!c.body?.reason) return E(422, 'validation_failed', '', { reason: 'required' });
  const dead = (c.st.deliveries[id] ?? []).filter((d) => d.status === 'dead'); const rid = nid('rdr');
  c.st.redrives[rid] = { polls: 0, total: dead.length, sys: id }; dead.forEach((d) => { d.status = 'pending'; d.attempts += 1; });
  return OK({ redrive_id: rid, requeued: dead.length }, 202);
});
route('GET', '/v1/redrives/:id', (c) => {
  const r = c.st.redrives[c.m.groups!.id]; if (!r) return E(404, 'not_found');
  r.polls += 1; const done = r.polls >= 2;
  if (done) (c.st.deliveries[r.sys] ?? []).filter((d) => d.status === 'pending').forEach((d) => { d.status = 'acknowledged'; d.last_http_status = 200; });
  return OK({ redrive_id: c.m.groups!.id, system_id: r.sys, status: done ? 'done' : 'running', requeued: r.total, acknowledged: done ? r.total : 0, dead_again: 0, remaining: done ? 0 : r.total, started_at: nowIso(), finished_at: done ? nowIso() : null });
});
route('POST', '/v1/deliveries\\:query', (c) => {
  const x = allow(c, 'admin', 'compliance_viewer'); if (x) return x;
  const sys = c.st.systems.find((s) => s.system_id === c.body?.system_id); if (!sys) return E(404, 'not_found');
  const dead = (c.st.deliveries[sys.system_id] ?? []).some((d) => d.status === 'dead');
  return OK({ items: [{ system_id: sys.system_id, system_name: sys.name, sent_at: '2026-11-02T20:10:00Z', state: 'denied', status: dead ? 'dead' : 'acknowledged', acknowledged_at: dead ? null : '2026-11-02T20:10:03Z' }], next_cursor: null });
});

// ---- proof and exports ----
route('POST', '/v1/proof', (c) => {
  const x = allow(c, 'admin', 'compliance_viewer'); if (x) return x;
  const contact = String(c.body?.contact ?? ''); const d = contact.replace(/\D/g, '');
  if (!contact.includes('@') && d.length < 10) return E(422, 'invalid_contact', 'That is not a complete phone number.', { kind: 'phone' });
  return proofFor(c.st, contact);
});
route('GET', '/v1/exports', (c) => { const x = allow(c, 'admin', 'compliance_viewer'); if (x) return x; return OK(page(c.st.exports.map((e) => e.item), c.query)); });
route('POST', '/v1/exports', (c) => {
  const x = allow(c, 'admin', 'compliance_viewer'); if (x) return x;
  const sus = suspendedBlock(c); if (sus) return sus;
  const contact = String(c.body?.contact ?? ''); const d = contact.replace(/\D/g, '');
  if (!contact.includes('@') && d.length < 10) return E(422, 'invalid_contact');
  if (!(d.endsWith('0100') || d.endsWith('0101') || d.endsWith('0102') || d.endsWith('0103') || d.endsWith('0500'))) return E(404, 'no_records');
  const id = nid('exp'); const mode = d.endsWith('0500') ? 'fail' : c.st.scenario.exportMode;
  c.st.exports.unshift({ item: { export_id: id, status: 'building', requested_by: 'Dana Ruiz', created_at: nowIso(), completed_at: null, progress: mode === 'large' ? { done: 18000, total: 42000 } : null, contact_fp_hint: `fp_${d.slice(-4)}a1`, downloaded_at: null, expires_at: null, sha256: null }, polls: 0, mode, contact, downloaded: false });
  return OK({ export_id: id, status: 'building', created_at: nowIso() }, 202);
});
function expState(e: Store['exports'][number]): T.ExportDetail {
  e.polls += 1;
  const slow = e.mode === 'large' ? 3 : 2;
  if (e.item.status === 'building' && e.polls >= slow) {
    if (e.mode === 'fail') { e.item.status = 'failed'; }
    else { e.item.status = 'ready'; e.item.completed_at = nowIso(); e.item.expires_at = new Date(Date.now() + 15 * 60000).toISOString(); e.item.sha256 = 'c81e0000000000000000000000000000000000000000000000000000000044aa'; e.item.progress = null; }
  }
  const it = e.item;
  return { export_id: it.export_id, status: it.status, progress: it.status === 'building' ? (e.mode === 'large' ? { done: 18000, total: 42000 } : null) : null, failed_cause: it.status === 'failed' ? 'seal_store_unreachable' : null,
    download_url: it.status === 'ready' && !e.downloaded ? `/__mock/download/${it.export_id}` : null, sha256: it.sha256, signature: it.status === 'ready' ? 'sig_platform_key_v2' : null, expires_at: it.expires_at, downloaded_at: it.downloaded_at };
}
route('GET', '/v1/exports/:id', (c) => { const x = allow(c, 'admin', 'compliance_viewer'); if (x) return x; const e = c.st.exports.find((y) => y.item.export_id === c.m.groups!.id); return e ? OK(expState(e)) : E(404, 'not_found'); });
route('POST', '/v1/exports/:id\\:link', (c) => {
  const x = allow(c, 'admin', 'compliance_viewer'); if (x) return x;
  const sus = suspendedBlock(c); if (sus) return sus;
  const e = c.st.exports.find((y) => y.item.export_id === c.m.groups!.id); if (!e) return E(404, 'not_found');
  if (e.item.status !== 'ready') return E(409, 'export_not_ready');
  e.downloaded = false; e.item.expires_at = new Date(Date.now() + 15 * 60000).toISOString(); return OK({ download_url: `/__mock/download/${e.item.export_id}`, expires_at: e.item.expires_at });
});
route('POST', '/v1/exports/:id\\:resume', (c) => {
  const x = allow(c, 'admin', 'compliance_viewer'); if (x) return x;
  const e = c.st.exports.find((y) => y.item.export_id === c.m.groups!.id); if (!e) return E(404, 'not_found');
  if (e.item.status !== 'failed') return E(409, 'export_not_resumable');
  e.item.status = 'building'; e.mode = 'normal'; e.polls = 0; return OK({ export_id: e.item.export_id, status: 'building' }, 202);
});

// ---- billing ----
route('GET', '/v1/billing/plans', (c) => { const x = allow(c, 'admin'); if (x) return x; return OK(c.st.scenario.empty.includes('plans') ? { items: [], next_cursor: null } : page(PLANS, c.query)); });
route('GET', '/v1/billing', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  const st = c.st; const trial = st.status === 'trial';
  return OK({ status: st.status, plan: trial ? null : { plan_id: 'plan_growth', name: 'Growth' }, period: trial ? null : { start: '2026-11-01T00:00:00Z', end: '2026-12-01T00:00:00Z' },
    included: trial ? null : { events: 10000, gate_checks: 50000 }, used: trial || st.scenario.nulls.includes('usage') ? null : { events: 4812, gate_checks: 22340 }, last_reported_at: trial ? null : '2026-11-03T06:00:00Z' });
});
route('POST', '/v1/billing/checkout', (c) => {
  const x = allow(c, 'admin'); if (x) return x;
  if (!PLANS.some((p) => p.plan_id === c.body?.plan_id)) return E(404, 'not_found');
  if (c.st.scenario.nulls.includes('checkout_paid')) c.st.status = 'active';
  return OK({ checkout_url: '/__mock/stripe/checkout' }, 201);
});
route('POST', '/v1/billing/portal', (c) => { const x = allow(c, 'admin'); if (x) return x; return OK({ portal_url: '/__mock/stripe/portal' }, 201); });

// ---- dispatch ----
registerRecords({ route, E, OK, page, allow, suspendedBlock, nowIso });
registerConfirmations({ route, E, OK, page, allow, suspendedBlock, nowIso });

function matchFail(st: Store, key: string): FailRule | null {
  for (const [k, rule] of Object.entries(st.scenario.fail)) {
    const ok = k.endsWith('*') ? key.startsWith(k.slice(0, -1)) : k === key;
    if (!ok) continue;
    if (rule.once) { st.failCount[k] = (st.failCount[k] ?? 0) + 1; if (st.failCount[k] > 1) continue; }
    return rule;
  }
  return null;
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function createMock() {
  let st = newStore({ ...DEFAULT_SCENARIO });
  const csp = (() => { try { const t = fs.readFileSync(path.join(here, '..', fs.existsSync(path.join(here, '..', 'out', '_headers')) ? 'out' : 'public', '_headers'), 'utf8') /* the shipped policy, with the boot hashes */; const m = /Content-Security-Policy:\s*(.+)/.exec(t); return m ? m[1].trim() : ''; } catch { return ''; } })();
  // Every other header the edge applies to every path (out/_headers, block "/*"), so the run exercises the shipped isolation headers.
  const shipped: Record<string, string> = (() => {
    const t = fs.readFileSync(path.join(here, '..', fs.existsSync(path.join(here, '..', 'out', '_headers')) ? 'out' : 'public', '_headers'), 'utf8');
    const h: Record<string, string> = {}; let all = false;
    for (const line of t.split('\n')) {
      if (!line.trim()) continue;
      if (!/^\s/.test(line)) { all = line.trim() === '/*'; continue; }
      const k = line.slice(0, line.indexOf(':')).trim();
      if (all && !['content-security-policy', 'cache-control'].includes(k.toLowerCase())) h[k.toLowerCase()] = line.slice(line.indexOf(':') + 1).trim();
    }
    return h;
  })();

  async function api(req: http.IncomingMessage, url: URL, raw: string): Promise<Res | null> {
    const method = req.method ?? 'GET';
    if (url.pathname.startsWith('/__mock/')) {
      if (url.pathname === '/__mock/scenario' && method === 'POST') {
        const b = JSON.parse(raw || '{}');
        const base: Scenario = b.reset === false ? { ...st.scenario } : { ...DEFAULT_SCENARIO };
        delete b.reset;
        st = newStore({ ...base, ...b });
        return OK({ ok: true, scenario: st.scenario });
      }
      if (url.pathname === '/__mock/log') return OK(st.log);
      if (url.pathname === '/__mock/state') return OK({ currentOrg: st.currentOrg, status: st.status, brands: st.brands, sources: st.sources, disclosures: st.disclosures, credentials: st.credentials, members: st.members, policies: st.policies.map((p) => ({ version: p.version, status: p.status })), exports: st.exports.length, scenario: st.scenario });
      if (url.pathname.startsWith('/__mock/download/')) { const e = st.exports.find((y) => url.pathname.endsWith(y.item.export_id)); if (e) { e.downloaded = true; e.item.downloaded_at = nowIso(); } return { status: 200, body: { package: 'mock' } }; }
      if (url.pathname.startsWith('/__mock/stripe/')) return { status: 200, body: { stripe: 'mock' } };
      return E(404, 'not_found');
    }
    if (!url.pathname.startsWith('/v1/')) return null;
    let body: any; try { body = raw ? JSON.parse(raw) : undefined; } catch { return E(400, 'invalid_request'); }
    st.log.push({ method, url: url.pathname + url.search, body });
    const key = `${method} ${url.pathname}`;
    const rule = matchFail(st, key);
    if (st.scenario.delayMs) await sleep(st.scenario.delayMs);
    if (rule?.delayMs) await sleep(rule.delayMs);
    if (rule && rule.status > 0) return { ...E(rule.status, rule.error, rule.detail ?? '', rule.fields), headers: rule.headers };
    const open = /^\/v1\/invites\/[^/]+$/.test(url.pathname) && method === 'GET';
    if (st.scenario.signedOut && !open) return E(401, 'unauthenticated', 'Your session ended.');
    for (const r of routes) {
      if (r.method !== method) continue;
      const m = url.pathname.match(r.re); if (!m) continue;
      return r.h({ method, path: url.pathname, query: url.searchParams, body, m, st });
    }
    return E(404, 'not_found', 'No such endpoint.');
  }

  const MIME: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.json': 'application/json', '.ico': 'image/x-icon', '.txt': 'text/plain' };
  const DYNAMIC = ['/sources/', '/wording/', '/policies/', '/checklists/', '/exports/', '/systems/', '/confirmations/'];

  function serveStatic(root: string, pathname: string, res: http.ServerResponse): void {
    const clean = path.posix.normalize(decodeURIComponent(pathname)).replace(/^(\.\.\/)+/, '');
    const cands = [clean, `${clean}.html`, path.join(clean, 'index.html')];
    let file = cands.map((x) => path.join(root, x)).find((f) => f.startsWith(root) && fs.existsSync(f) && fs.statSync(f).isFile());
    if (!file) {
      const dyn = DYNAMIC.find((d) => clean.startsWith(d));
      if (dyn) {
        const first = `${dyn.slice(0, -1)}.html`;
        const f2 = path.join(root, first);
        if (fs.existsSync(f2)) file = f2;
      }
    }
    if (!file) { const nf = path.join(root, '404.html'); res.writeHead(404, { 'content-type': MIME['.html'] }); res.end(fs.existsSync(nf) ? fs.readFileSync(nf) : 'Not found'); return; }
    const ext = path.extname(file);
    const headers: Record<string, string> = { 'content-type': MIME[ext] ?? 'application/octet-stream', 'cache-control': 'no-store' };
    if (ext === '.html' && csp) headers['content-security-policy'] = csp;
    Object.assign(headers, shipped);
    res.writeHead(200, headers); res.end(fs.readFileSync(file));
  }

  function server(staticRoot: string | null, corsOrigin: string | null) {
    return http.createServer(async (req, res) => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const chunks: Uint8Array[] = []; for await (const ch of req) chunks.push(ch as Uint8Array);
      const raw = Buffer.concat(chunks).toString('utf8');
      const cors: Record<string, string> = corsOrigin ? { 'access-control-allow-origin': corsOrigin, 'access-control-allow-credentials': 'true', 'access-control-allow-headers': 'content-type,x-request-id,accept', 'access-control-allow-methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS' } : {};
      if (req.method === 'OPTIONS') { res.writeHead(204, cors); res.end(); return; }
      if (url.pathname === '/auth/login') { res.writeHead(200, { 'content-type': MIME['.html'] }); res.end('<!doctype html><title>WorkOS sign-in (mock)</title><h1>WorkOS hosted sign-in (mock)</h1>'); return; }
      if (url.pathname === '/auth/logout') { st.scenario.signedOut = true; res.writeHead(302, { location: '/sign-in' }); res.end(); return; }
      try {
        const out = await api(req, url, raw);
        if (out) {
          const h: Record<string, string> = { 'content-type': 'application/json', 'cache-control': 'no-store', ...cors, ...(out.headers ?? {}) };
          res.writeHead(out.status, h); res.end(out.body === undefined ? undefined : JSON.stringify(out.body)); return;
        }
      } catch (e) {
        res.writeHead(500, { 'content-type': 'application/json', ...cors }); res.end(JSON.stringify({ error: 'mock_failure', detail: String(e) })); return;
      }
      if (staticRoot) { serveStatic(staticRoot, url.pathname, res); return; }
      res.writeHead(404, cors); res.end();
    });
  }
  return { server, state: () => st };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const args = process.argv.slice(2);
  const arg = (n: string, d: string) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  const port = Number(arg('--port', '4010'));
  const root = args.includes('--no-static') ? null : path.resolve(here, '..', arg('--static', 'out'));
  const srv = createMock().server(root, arg('--cors', 'http://localhost:3000'));
  srv.listen(port, '127.0.0.1', () => console.log(`mock api on http://127.0.0.1:${port}${root ? ` serving ${root}` : ''}`));
  void ORG_ID; void ORG_NAME;
}
