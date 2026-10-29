// Hand-written from /Users/oxfloors/brain/specs/268-consentvault-cloud/contracts/*.md (2026-10-29).
// Every `T | null` below is a value the API sends as null when it could not be read: the portal renders
// "Not available" for it and never substitutes 0.

export type Role = 'admin' | 'developer' | 'compliance_viewer';
export type OrgStatus = 'trial' | 'active' | 'past_due' | 'suspended' | 'offboarding' | 'closed';

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface ErrorBody {
  error: string;
  detail?: string;
  request_id?: string;
  fields?: Record<string, unknown>;
}

// session.md
export interface Membership { org_id: string; name: string; role: Role; status: OrgStatus | null }
export interface SessionAnswer { user: { display_name: string; email: string }; items: Membership[]; next_cursor: string | null }
export interface OffboardingStep { step: 'final_export' | 'credentials_revoked' | 'key_destruction_scheduled' | 'destruction_record'; status: 'pending' | 'done' | 'delayed'; at: string | null }
export interface OrgAdmin {
  org_id: string; name: string; status: OrgStatus; region: string; created_at: string;
  plan: { plan_id: string; name: string } | null;
  key: { status: 'active' | 'retired' | 'scheduled_destroy' | 'destroyed'; version: number; destroy_after: string | null } | null;
  offboarding: null | {
    requested_at: string; requested_by: string; state: 'requested' | 'in_progress' | 'complete';
    steps: OffboardingStep[]; destroy_after: string | null; held: { legal_hold_active: boolean; since: string | null };
  };
  trial: null | { started_at: string };
  role?: Role;
  partial?: string[];
}
export interface OrgBasic { org_id: string; name: string; status: OrgStatus; region: string; role: Role }
export type Org = OrgAdmin | OrgBasic;
export interface Health {
  evaluated_at: string;
  unsealed_events_over_1h: number | null;
  dead_deliveries: number | null;
  last_chain_verification: { at: string; result: 'ok' | 'failed' | 'not_run' } | null;
  first_event: { at: string; sealed: boolean } | null;
}

// admin.md
export interface Brand { brand_id: string; display_name: string; created_at: string; source_count: number | null; disclosure_count: number | null }
export interface Source {
  source_id: string; name: string; kind: 'site_key' | 'server'; brand_ids: string[]; allowed_origins: string[];
  status: 'active' | 'retired'; created_at: string;
  last_event_at: string | null; last_event_seq: number | null; last_event_sealed: boolean | null;
  partial?: string[];
}
export type CredentialKind = 'edge_site_key' | 'jwt_public_key' | 'hmac_fallback';
export type CredentialScope = 'capture' | 'gate_read' | 'proof_read';
export interface Credential {
  credential_id: string; name: string; kind: CredentialKind; scope: CredentialScope; source_id: string | null;
  algorithm: string | null; created_by: string; created_at: string; revoked_at: string | null; last_used_at: string | null;
}
export interface CredentialIssued {
  credential_id: string; name: string; kind: CredentialKind; scope: CredentialScope; source_id: string | null;
  algorithm: string | null; created_at: string; client_id?: string; site_key_id?: string; secret?: string; shown_once: boolean;
}
export interface RetentionVersion { version: number; evidence_years: number; applies_from: string; set_by: string }
export interface Retention { current: RetentionVersion | null; platform_minimum_years: number; items: RetentionVersion[]; next_cursor: string | null; partial?: string[] }
export interface ErasureAccepted { erasure_id: string; status: 'pending_operator_confirmation' }

// members.md
export interface InviteLookup { org_name: string; role: Role; invited_by_name: string; invited_email_hint: string; expires_at: string }
export interface MemberRow {
  kind: 'member' | 'invite'; id: string; display_name: string | null; email: string; role: Role;
  status: 'active' | 'invited'; created_at: string; last_sign_in_at: string | null; expires_at: string | null; invited_by_name: string | null;
}
export interface AuditRow {
  audit_id: string; at: string; action: string;
  actor: { kind: 'member' | 'credential' | 'operator' | 'system'; id: string; display_name: string | null };
  target: { kind: string; id: string | null }; reason: string | null; request_id: string;
}

// policy.md
export interface Channel { channel: string; label: string }
export interface Purpose { purpose: string; label: string; description: string }
export interface Disclosure {
  sha256: string; label: string; version_label: string; channels: string[]; purposes: string[]; brand_ids: string[];
  supersedes_sha256: string | null; superseded_by_sha256: string | null; effective_from: string; registered_by: string; registered_at: string;
  body?: string;
}
export type EvidenceStatusKey = 'consent_record_found' | 'stop_on_record' | 'no_record' | 'record_incomplete' | 'unavailable';
export interface PolicyCell { evidence_status: EvidenceStatusKey; channel: string; action: 'proceed' | 'hold' }
export interface PolicyRules { schema_version: 1; purposes: Record<string, { cells: PolicyCell[]; checklist_version: number | null }> }
export interface PolicyItem {
  version: number; status: 'draft' | 'approved' | 'retired'; template_ref: string | null; based_on_version: number | null;
  created_by: string; created_at: string; approved_by: string | null; approved_at: string | null; retired_at: string | null; retired_by_version: number | null;
}
export interface PolicyDetail extends PolicyItem { rules: PolicyRules; attestation?: { version: number; sha256: string } }
export interface PolicyTemplate { template_ref: string; label: string; description: string; rules: PolicyRules }
export interface Attestation { version: number; text: string; sha256: string; published_at: string }
export interface ChecklistItem { version: number; kind: 'pewc' | 'custom'; label: string; status: 'draft' | 'approved'; element_count: number; created_at: string; approved_by: string | null; approved_at: string | null }
export interface ChecklistElement { element_id: string; name: string; description: string; required: boolean; rule_reference_id: string | null }
export interface ChecklistDetail extends ChecklistItem { elements: ChecklistElement[] }
export interface ChecklistTemplate { template_ref: string; kind: 'pewc' | 'custom'; label: string; elements: ChecklistElement[] }
export interface RuleReference { ref_id: string; version: number; jurisdiction: string; citation: string; source_url: string; last_reviewed_on: string | null }

// systems.md
export interface System {
  system_id: string; name: string; kind: 'crm' | 'dialer' | 'sms' | 'email' | 'ai_agent' | 'webhook'; connector: 'generic_webhook';
  endpoint: string; signature: 'ed25519' | 'hmac'; contact_form: 'plaintext' | 'fingerprint'; retry_window_hours: number;
  status: 'active' | 'paused'; public_key: string | null; created_at: string; last_delivery_at: string | null;
  counts: { pending: number; dead: number; acknowledged_24h: number } | null;
  last_test: { at: string; result: string; http_status: number | null; latency_ms: number | null } | null;
}
export interface SystemCreated extends System { hmac_secret?: string }
export interface TestPush { result: 'accepted' | 'rejected' | 'server_error' | 'timeout' | 'unreachable'; http_status: number | null; latency_ms: number | null; at: string }
export interface Delivery {
  outbox_id: string; created_at: string; contact_fp_hint: string; channel: string; purpose: string; version: number;
  status: 'pending' | 'acknowledged' | 'dead' | 'superseded'; attempts: number; last_attempt_at: string | null;
  last_http_status: number | null; last_error_class: 'timeout' | 'http_4xx' | 'http_5xx' | 'signature_rejected' | 'unreachable' | null;
}
export interface Redrive { redrive_id: string; system_id: string; status: 'running' | 'done'; requeued: number; acknowledged: number; dead_again: number; remaining: number; started_at: string; finished_at: string | null }
export interface ContactDelivery { system_id: string; system_name: string; sent_at: string; state: 'denied' | 'permitted'; status: 'sent' | 'acknowledged' | 'failed' | 'dead' | 'superseded'; acknowledged_at: string | null }

// proof-export.md
export interface ProofPermission { channel: string; purpose: string; evidence_status: string; policy_action: 'proceed' | 'hold' | null; policy_version: number | null; basis_event_ids: string[] }
export interface TimelineEvent {
  event_id: string; seq: number; event_type: 'grant' | 'revoke' | 'suppress' | 'release'; at: string; channels: string[]; purposes: string[];
  source_id: string; brand_ids: string[]; disclosure_sha256: string | null; sealed: boolean; sealed_at: string | null; recorded_during_trial: boolean;
}
export interface GateDecision { decision_id: string; at: string; channel: string; purpose: string; evidence_status: string; policy_action: 'proceed' | 'hold' | null; policy_version: number | null }
export interface Proof {
  found: boolean; evaluated_at: string; notice: string;
  permissions: ProofPermission[];
  timeline: Page<TimelineEvent> | null;
  disclosures: { sha256: string; label: string; version_label: string }[] | null;
  gate_decisions: Page<GateDecision> | null;
  contact_log: Page<Record<string, unknown>> | null;
  reviews: Page<{ review_id: string; at: string; kind: string; event_id: string | null }> | null;
  doc_check_results: { event_id: string; checklist_version: number; present: string[]; missing: string[] }[] | null;
  chain: { head: string; events: number; path: string; anchors: { at: string; ok: boolean }[] } | null;
  partial?: string[];
}
export interface ExportItem {
  export_id: string; status: 'building' | 'ready' | 'failed'; requested_by: string; created_at: string; completed_at: string | null;
  progress: { done: number; total: number } | null; contact_fp_hint: string; downloaded_at: string | null; expires_at: string | null; sha256: string | null;
}
export interface ExportDetail {
  export_id: string; status: 'building' | 'ready' | 'failed'; progress: { done: number; total: number } | null; failed_cause: string | null;
  download_url: string | null; sha256: string | null; signature: string | null; expires_at: string | null; downloaded_at: string | null;
}

// billing.md
export interface Plan { plan_id: string; name: string; interval: string; unit_amount: number; currency: string; included_events: number; included_gate_checks: number; orgs_brands: number }
export interface Billing {
  status: OrgStatus; plan: { plan_id: string; name: string } | null; period: { start: string; end: string } | null;
  included: { events: number; gate_checks: number } | null; used: { events: number; gate_checks: number } | null; last_reported_at: string | null;
}
