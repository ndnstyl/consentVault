// Mock API state for the portal: one in-memory organization, scenario switches for every screen state.
// Shapes follow the cloud contracts. Test data only.
import type * as T from '../src/lib/api/types.ts';

export interface FailRule { status: number; error: string; detail?: string; once?: boolean; delayMs?: number; fields?: Record<string, unknown>; headers?: Record<string, string> }

export interface Scenario {
  role: T.Role;
  orgStatus: T.OrgStatus;
  orgs: 'one' | 'two' | 'none';
  preselected: boolean;
  signedOut: boolean;
  noSecondFactor: boolean;
  setup: 'full' | 'new' | 'blank' | 'almost';
  firstEvent: 'none' | 'unsealed' | 'sealed';
  empty: string[];
  nulls: string[];
  alarms: string[];
  sso: 'none' | 'pending' | 'verified';
  fail: Record<string, FailRule>;
  delayMs: number;
  offboarding: boolean;
  exportMode: 'normal' | 'large' | 'fail';
  inviteMode: 'ok' | 'expired' | 'used' | 'withdrawn' | 'wrong_account';
  records: 'full' | 'none';
  confirmations: 'full' | 'empty' | 'texts_off' | 'awaiting' | 'link_unset' | 'failing';
}

export const DEFAULT_SCENARIO: Scenario = {
  role: 'admin', orgStatus: 'active', orgs: 'one', preselected: true, signedOut: false, noSecondFactor: false, setup: 'full',
  firstEvent: 'sealed', empty: [], nulls: [], alarms: [], sso: 'none', fail: {}, delayMs: 0, offboarding: false, exportMode: 'normal', inviteMode: 'ok', records: 'full', confirmations: 'full',
};

const iso = (d: string) => new Date(d).toISOString();
const now = () => new Date().toISOString();
let counter = 100;
export const nid = (p: string) => `${p}_${(counter++).toString(36)}${Math.random().toString(36).slice(2, 6)}`;

export const ORG_ID = 'org_acme';
export const ORG_NAME = 'Acme Lending';

export interface Store {
  scenario: Scenario;
  currentOrg: string | null;
  status: T.OrgStatus;
  role: T.Role;
  brands: T.Brand[];
  sources: T.Source[];
  fieldMaps: Record<string, T.FieldMapVersion[]>;
  credentials: T.Credential[];
  disclosures: T.Disclosure[];
  checklists: T.ChecklistDetail[];
  systems: T.System[];
  deliveries: Record<string, T.Delivery[]>;
  redrives: Record<string, { polls: number; total: number; sys: string }>;
  members: T.MemberRow[];
  audit: T.AuditRow[];
  retention: T.RetentionVersion[];
  exports: { item: T.ExportItem; polls: number; mode: string; contact: string; downloaded: boolean }[];
  invites: Record<string, true>;
  log: { method: string; url: string; body: unknown }[];
  failCount: Record<string, number>;
  offboardingRequested: boolean;
  firstEventPolls: number;
  testPushes: Record<string, number>;
  ext: Record<string, any>;
}

export function newStore(s: Scenario): Store {
  const role = s.role;
  const brands: T.Brand[] = s.setup === 'blank' ? [] : [
    { brand_id: 'brd_acme', display_name: 'Acme Lending', created_at: iso('2026-10-29T14:00:00Z'), source_count: 2, disclosure_count: 2 },
    { brand_id: 'brd_ahl', display_name: 'Acme Home Loans', created_at: iso('2026-10-30T14:00:00Z'), source_count: 1, disclosure_count: 0 },
  ];
  const withSources = s.setup !== 'blank';
  const sources: T.Source[] = withSources ? [
    { source_id: 'src_web', name: 'Website form', kind: 'site_key', brand_ids: ['brd_acme'], allowed_origins: ['https://acme.com'], status: 'active', created_at: iso('2026-10-29T15:00:00Z'),
      last_event_at: s.firstEvent === 'none' ? null : iso('2026-10-31T14:42:07Z'), last_event_seq: s.firstEvent === 'none' ? null : 1, last_event_sealed: s.firstEvent === 'none' ? null : s.firstEvent === 'sealed' },
    { source_id: 'src_sf', name: 'Salesforce', kind: 'server', brand_ids: ['brd_acme', 'brd_ahl'], allowed_origins: [], status: 'active', created_at: iso('2026-10-30T15:00:00Z'), last_event_at: null, last_event_seq: null, last_event_sealed: null },
  ] : [];
  const full = s.setup === 'full' || s.setup === 'almost';
  const credentials: T.Credential[] = s.setup === 'blank' ? [] : [
    ...(full ? [{ credential_id: 'crd_web', name: 'Website form key', kind: 'edge_site_key' as const, scope: 'capture' as const, source_id: 'src_web', algorithm: null, created_by: 'Dana Ruiz', created_at: iso('2026-10-31T14:30:00Z'), revoked_at: null, last_used_at: iso('2026-11-03T13:00:00Z') },
    { credential_id: 'crd_sf', name: 'Salesforce server', kind: 'jwt_public_key' as const, scope: 'capture' as const, source_id: 'src_sf', algorithm: 'ES256', created_by: 'Dana Ruiz', created_at: iso('2026-10-31T14:35:00Z'), revoked_at: null, last_used_at: null }] : []),
    { credential_id: 'crd_old', name: 'Old dialer check', kind: 'jwt_public_key', scope: 'gate_read', source_id: null, algorithm: 'ES256', created_by: 'Dana Ruiz', created_at: iso('2026-09-02T14:00:00Z'), revoked_at: iso('2026-10-01T14:00:00Z'), last_used_at: null },
  ];
  const body = 'By checking this box, I agree that Acme Lending may contact me by text message, calls and artificial or prerecorded voice at the number I gave, including with automated technology, about marketing. Consent is not a condition of purchase.';
  const disclosures: T.Disclosure[] = full ? [
    { sha256: '9f2c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6ee1', label: '2026-10', version_label: '2026-10', channels: ['sms', 'voice', 'artificial_voice'], purposes: ['marketing'], brand_ids: ['brd_acme'],
      supersedes_sha256: '41ab0000000000000000000000000000000000000000000000000000000000c7', superseded_by_sha256: null, effective_from: iso('2026-10-01T00:00:00Z'), registered_by: 'Dana Ruiz', registered_at: iso('2026-10-01T13:00:00Z'), body },
    { sha256: '41ab0000000000000000000000000000000000000000000000000000000000c7', label: '2026-07', version_label: '2026-07', channels: ['sms', 'voice'], purposes: ['marketing'], brand_ids: ['brd_acme'],
      supersedes_sha256: null, superseded_by_sha256: '9f2c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6ee1', effective_from: iso('2026-07-01T00:00:00Z'), registered_by: 'Dana Ruiz', registered_at: iso('2026-07-01T13:00:00Z'), body: 'By checking this box, I agree that Acme Lending may contact me by text message and calls about marketing.' },
  ] : [];
  const els = (): T.ChecklistElement[] => [
    { element_id: 'el_seller', name: 'Seller named', description: 'Acme Lending', required: true, rule_reference_id: 'ref_fed' },
    { element_id: 'el_channels', name: 'Channels named', description: 'texts and calls', required: true, rule_reference_id: 'ref_fed' },
    { element_id: 'el_auto', name: 'Automated or artificial voice named', description: 'automated technology', required: true, rule_reference_id: 'ref_fed' },
    { element_id: 'el_agree', name: 'Agreement captured', description: 'checkbox ticked', required: true, rule_reference_id: 'ref_fed' },
    { element_id: 'el_cond', name: 'Not a condition of purchase', description: 'not a condition of purchase', required: true, rule_reference_id: 'ref_fed' },
  ];
  const checklists: T.ChecklistDetail[] = full ? [
    { version: 2, kind: 'pewc', label: 'PEWC elements', status: 'approved', element_count: 5, created_at: iso('2026-10-20T14:00:00Z'), approved_by: 'Dana Ruiz', approved_at: iso('2026-10-30T14:00:00Z'), elements: els() },
    { version: 3, kind: 'pewc', label: 'PEWC elements', status: 'draft', element_count: 5, created_at: iso('2026-11-01T14:00:00Z'), approved_by: null, approved_at: null, elements: els() },
  ] : [];
  const systems: T.System[] = s.setup === 'full' ? [
    { system_id: 'sys_crm', name: 'CRM', kind: 'crm', connector: 'generic_webhook', endpoint: 'https://crm.acme.com/consentvault', signature: 'hmac', contact_form: 'fingerprint', retry_window_hours: 24, status: 'active', public_key: null, created_at: iso('2026-10-30T14:00:00Z'), last_delivery_at: iso('2026-11-03T14:01:00Z'), counts: { pending: 0, dead: 0, acknowledged_24h: 12 }, last_test: { at: iso('2026-10-30T14:05:00Z'), result: 'accepted', http_status: 200, latency_ms: 120 } },
    { system_id: 'sys_dialer', name: 'Dialer', kind: 'dialer', connector: 'generic_webhook', endpoint: 'https://dialer.acme.com/consentvault', signature: 'ed25519', contact_form: 'plaintext', retry_window_hours: 24, status: 'active', public_key: 'MCowBQYDK2VwAyEA9f2c4d5e6a7b8c9d0e1f2a3b4c5d6e7f809', created_at: iso('2026-10-30T14:10:00Z'), last_delivery_at: iso('2026-11-02T19:58:00Z'), counts: { pending: 0, dead: 2, acknowledged_24h: 3 }, last_test: { at: iso('2026-11-03T13:55:00Z'), result: 'accepted', http_status: 200, latency_ms: 340 } },
  ] : [];
  const deliveries: Record<string, T.Delivery[]> = s.setup === 'full' ? {
    sys_dialer: [
      { outbox_id: 'obx_1', created_at: iso('2026-11-02T20:10:00Z'), contact_fp_hint: 'fp_7a1c9e2b', channel: 'sms', purpose: 'marketing', version: 9, status: 'dead', attempts: 14, last_attempt_at: iso('2026-11-03T20:10:00Z'), last_http_status: 503, last_error_class: 'http_5xx' },
      { outbox_id: 'obx_2', created_at: iso('2026-11-02T20:12:00Z'), contact_fp_hint: 'fp_c02d41aa', channel: 'voice', purpose: 'marketing', version: 10, status: 'dead', attempts: 14, last_attempt_at: iso('2026-11-03T20:12:00Z'), last_http_status: null, last_error_class: 'timeout' },
      { outbox_id: 'obx_3', created_at: iso('2026-11-01T20:12:00Z'), contact_fp_hint: 'fp_91b0e3cc', channel: 'sms', purpose: 'marketing', version: 8, status: 'acknowledged', attempts: 1, last_attempt_at: iso('2026-11-01T20:12:05Z'), last_http_status: 200, last_error_class: null },
    ],
    sys_crm: [{ outbox_id: 'obx_4', created_at: iso('2026-11-03T14:00:00Z'), contact_fp_hint: 'fp_7a1c9e2b', channel: 'sms', purpose: 'marketing', version: 9, status: 'acknowledged', attempts: 1, last_attempt_at: iso('2026-11-03T14:01:00Z'), last_http_status: 200, last_error_class: null }],
  } : {};
  const members: T.MemberRow[] = [
    { kind: 'member', id: 'mem_dana', display_name: 'Dana Ruiz', email: 'dana@acme.com', role: 'admin', status: 'active', created_at: iso('2026-10-29T14:00:00Z'), last_sign_in_at: iso('2026-11-03T12:00:00Z'), expires_at: null, invited_by_name: null },
    ...(s.empty.includes('members') ? [] : [
      { kind: 'member' as const, id: 'mem_lee', display_name: 'Lee Park', email: 'lee@acme.com', role: 'compliance_viewer' as const, status: 'active' as const, created_at: iso('2026-10-30T14:00:00Z'), last_sign_in_at: null, expires_at: null, invited_by_name: null },
      { kind: 'invite' as const, id: 'inv_sam', display_name: null, email: 'sam@acme.com', role: 'developer' as const, status: 'invited' as const, created_at: iso('2026-11-01T14:00:00Z'), last_sign_in_at: null, expires_at: iso('2026-11-07T14:00:00Z'), invited_by_name: 'Dana Ruiz' },
    ]),
  ];
  const aud = (i: number, at: string, who: string | null, action: string, tk: string, tid: string | null, reason: string | null): T.AuditRow => ({
    audit_id: `aud_${i}`, at: iso(at), action, actor: { kind: 'member', id: who ? `mem_${who.split(' ')[0].toLowerCase()}` : 'user_01J8K2', display_name: who }, target: { kind: tk, id: tid }, reason, request_id: `req_${i}9f2a1b`,
  });
  const audit: T.AuditRow[] = [
    aud(1, '2026-11-03T14:40:00Z', 'Dana Ruiz', 'deliveries.redrive', 'system', 'Dialer', 'Dialer endpoint restored'),
    aud(2, '2026-11-03T14:12:00Z', 'Lee Park', 'export.create', 'export', 'exp_31a8', 'Demand letter received'),
    aud(3, '2026-10-31T15:40:00Z', 'Dana Ruiz', 'credential.create', 'credential', 'Website form key', null),
  ];
  const retention: T.RetentionVersion[] = [
    { version: 2, evidence_years: 7, applies_from: iso('2026-10-30T14:00:00Z'), set_by: 'Dana Ruiz' },
    { version: 1, evidence_years: 5, applies_from: iso('2026-10-29T14:00:00Z'), set_by: 'Operator' },
  ];
  void role;
  return {
    scenario: s, currentOrg: s.preselected && s.orgs !== 'none' ? ORG_ID : null, status: s.orgStatus, role: s.role,
    brands: s.empty.includes('brands') ? [] : brands, sources: s.empty.includes('sources') ? [] : sources, credentials: s.empty.includes('credentials') ? [] : credentials,
    disclosures: s.empty.includes('disclosures') ? [] : disclosures,
    checklists: s.empty.includes('checklists') ? [] : checklists, systems: s.empty.includes('systems') ? [] : systems, deliveries,
    fieldMaps: {}, redrives: {}, members, audit: s.empty.includes('audit') ? [] : audit, retention: s.empty.includes('retention') ? retention.slice(1).slice(0, 0) : retention,
    exports: [], invites: {}, log: [], failCount: {}, offboardingRequested: false, firstEventPolls: 0, testPushes: {}, ext: {},
  };
}

export const REFERENCES: T.RuleReference[] = [
  { ref_id: 'ref_fed', version: 1, jurisdiction: 'Federal', citation: '47 CFR 64.1200', source_url: 'https://www.ecfr.gov/current/title-47/chapter-I/subchapter-B/part-64/subpart-L/section-64.1200', last_reviewed_on: '2026-10-29' },
  { ref_id: 'ref_fl', version: 1, jurisdiction: 'Florida', citation: 'Fla. Stat. 501.059', source_url: 'http://www.leg.state.fl.us/statutes/index.cfm?App_mode=Display_Statute&URL=0500-0599/0501/Sections/0501.059.html', last_reviewed_on: '2026-10-29' },
];

export const PLANS: T.Plan[] = [
  { plan_id: 'plan_starter', name: 'Starter', interval: 'month', unit_amount: 49900, currency: 'usd', included_events: 2000, included_gate_checks: 10000, orgs_brands: 1 },
  { plan_id: 'plan_growth', name: 'Growth', interval: 'month', unit_amount: 149900, currency: 'usd', included_events: 10000, included_gate_checks: 50000, orgs_brands: 5 },
  { plan_id: 'plan_enterprise', name: 'Enterprise', interval: 'month', unit_amount: 499900, currency: 'usd', included_events: 100000, included_gate_checks: 500000, orgs_brands: 25 },
];

export const CHANNELS: T.Channel[] = [
  { channel: 'artificial_voice', label: 'Artificial or prerecorded voice' }, { channel: 'email', label: 'Email' }, { channel: 'sms', label: 'SMS' }, { channel: 'voice', label: 'Voice' },
];
export const PURPOSES: T.Purpose[] = [{ purpose: 'marketing', label: 'Marketing', description: 'Marketing messages from the brand' }];

export function nowIso(): string { return now(); }
