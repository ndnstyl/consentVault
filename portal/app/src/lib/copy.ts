import type { OrgStatus, Role } from './api/types.ts';

// Copy of record: /Users/oxfloors/debwe/portal/design/copy-rules.md and the wireframe text.
// No em dashes or en dashes. Never a legal conclusion.

export const GATE_NOTICE = "Evidence status and the outcome of your organization's approved policy. Not a legal determination.";
export const PACKAGE_COVER = 'Its cover page states that the records are evidence for an investigation or dispute, and that storing a record does not by itself establish valid consent.';
export const ATTESTATION_TEMPLATE = "I am an admin of [Organization]. [Organization] is responsible for whether this policy is legally sufficient for its marketing. ConsentVault recommends that [Organization]'s counsel review it before approval. ConsentVault applies this policy as written and does not decide whether any communication is permitted by law.";
export const NOT_LEGAL_ADVICE = 'Not legal advice';
export const NOT_A_LEGAL_TEST = 'not a legal test';

export function fillOrg(text: string, org: string): string { return text.replace(/\[Organization\]/g, org); }

export const NA = 'Not available';

// ---- Label dictionary (copy-rules.md section 3) ----
export type EvidenceKind = 'found' | 'stop' | 'none' | 'incomplete' | 'na';
export interface Label { text: string; kind: EvidenceKind; icon: string }

export function evidenceLabel(status: string): Label {
  if (status === 'consent_record_found') return { text: 'Consent record found', kind: 'found', icon: 'i-found' };
  if (status === 'stop_on_record') return { text: 'Stop on record', kind: 'stop', icon: 'i-stop' };
  if (status === 'no_record') return { text: 'No record', kind: 'none', icon: 'i-none' };
  if (status.startsWith('record_incomplete')) {
    const els = status.split(':')[1];
    const names = els ? els.split(',').map((s) => s.replace(/_/g, ' ')).join(', ') : '';
    return { text: names ? `Record incomplete: missing ${names}` : 'Record incomplete', kind: 'incomplete', icon: 'i-incomplete' };
  }
  if (status.startsWith('unavailable')) {
    const cause = status.split(':')[1];
    return { text: `Not available${cause ? `: ${causeFor(cause)}` : ''}`, kind: 'na', icon: 'i-warn' };
  }
  return { text: `Not available: the service answered ${status}`, kind: 'na', icon: 'i-warn' };
}

export function policyLabel(action: 'proceed' | 'hold' | null, version: number | null): { text: string; cls: string; icon: string } {
  if (action === 'proceed') return { text: 'Your policy: proceed', cls: 'pol-proceed', icon: 'i-arrow' };
  if (action === 'hold') return { text: 'Your policy: hold', cls: 'pol-hold', icon: 'i-pause' };
  return { text: version === null ? 'No policy in force' : 'No action in policy', cls: 'pol-none', icon: 'i-dash' };
}

export const ORG_STATUS_LABEL: Record<OrgStatus, string> = { trial: 'Trial', active: 'Active', past_due: 'Past due', suspended: 'Suspended', offboarding: 'Offboarding', closed: 'Closed' };
export const ORG_STATUS_TONE: Record<OrgStatus, string> = { trial: 'st-info', active: 'st-success', past_due: 'st-warning', suspended: 'st-danger', offboarding: 'st-warning', closed: 'st-neutral' };
export const ORG_STATUS_ICON: Record<OrgStatus, string> = { trial: 'i-info', active: 'i-ok', past_due: 'i-warn', suspended: 'i-err', offboarding: 'i-warn', closed: 'i-dash' };

export const DELIVERY_LABEL: Record<string, string> = {
  pending: 'Sending', sent: 'Sending', acknowledged: 'Acknowledged', failed: 'Retrying', dead: 'Undelivered (dead)', superseded: 'Replaced by a newer change',
};
export const DELIVERY_TONE: Record<string, string> = { pending: 'st-info', sent: 'st-info', acknowledged: 'st-success', failed: 'st-warning', dead: 'st-danger', superseded: 'st-neutral' };
export const PUSH_STATE_LABEL: Record<string, string> = { denied: 'Suppress', permitted: 'Release suppression' };
export const EVENT_LABEL: Record<string, string> = { grant: 'Grant', revoke: 'Stop (revoke)', suppress: 'Stop (suppress)', release: 'Stop lifted' };

export const KIND_LABEL: Record<string, string> = { crm: 'CRM', dialer: 'Dialer', sms: 'Texting', email: 'Email', ai_agent: 'AI agent', webhook: 'Other webhook' };
export const SOURCE_KIND_LABEL: Record<string, string> = { site_key: 'Website (site key)', server: 'Server (public key)' };
export const CRED_KIND_LABEL: Record<string, string> = { edge_site_key: 'Site key', jwt_public_key: 'Public key', hmac_fallback: 'Signed webhook secret' };
export const CRED_SCOPE_LABEL: Record<string, string> = { capture: 'Capture', gate_read: 'Gate check', proof_read: 'Evidence read' };
export const CHANNEL_FALLBACK: Record<string, string> = { sms: 'SMS', voice: 'Voice', artificial_voice: 'Artificial or prerecorded voice', email: 'Email' };

export const ROLE_DESCRIPTION: Record<Role, string> = {
  admin: 'Admin: everything, including policies, members and billing',
  developer: 'Developer: sources, credentials, connected systems, test events. No personal records.',
  compliance_viewer: 'Compliance viewer: look up records and build evidence packages. Changes nothing.',
};

// ---- Plain causes (copy-rules.md section 5, plus the contract errors the screens meet) ----
const CAUSES: Record<string, string> = {
  key_unavailable: "your organization's encryption key did not answer",
  service_unavailable: 'the service did not answer',
  stripe_unavailable: 'Stripe did not answer',
  email_send_failed: 'the email service did not accept the message',
  org_not_active: 'your organization is not active',
  org_suspended: 'this action is paused while your organization is suspended',
  'invalid_contact:phone': 'that is not a complete phone number',
  'invalid_contact:email': 'that is not a complete email address',
  invalid_contact: 'that is not a complete phone number or email address',
  timeout: 'the service did not answer in time',
  unreachable: 'the service could not be reached',
  role_not_allowed: 'your role may not do this',
  not_found: 'that item does not exist in this organization',
  rate_limited: 'too many requests were sent in a short time',
  brand_exists: 'a brand with this name already exists in your organization',
  source_exists: 'a source with this name already exists',
  system_exists: 'a connected system with this name already exists',
  invalid_origin: 'an origin has no path',
  private_key_refused: 'that text is a private key and only a public key may be added',
  policy_required: 'a gate check credential needs a policy in force first',
  disclosure_exists: 'this exact text is already registered',
  policy_superseded: 'another admin approved a newer version first',
  below_platform_minimum: 'that value is below the platform minimum',
  last_admin: 'that would leave the organization with no admin',
  already_member: 'that person is already a member or has an open invitation',
  already_revoked: 'that credential is already revoked',
  already_subscribed: 'your organization already has a subscription',
  endpoint_not_https: 'the endpoint address must start with https',
  org_name_mismatch: 'the typed name does not match the organization name',
  offboarding_already_requested: 'an offboarding request is already open',
  legal_hold_active: 'a legal hold covers this contact point',
  redrive_in_progress: 'a redrive for this system is still running',
  export_expired: 'the package is past its retention and can no longer be linked',
  export_not_ready: 'the package is still building or did not finish',
  no_records: 'there are no records for that contact point in this organization',
  validation_failed: 'a field is missing or not in the expected form',
  invalid_cursor: 'the page link expired',
  version_not_draft: 'that version is no longer a draft',
  attestation_mismatch: 'the attestation was updated while you were reading it',
  acknowledgement_required: 'the acknowledgement was not accepted',
  unknown_brand: 'a brand does not belong to this organization',
  UnknownPurposeError: 'a purpose is not on your purpose list',
  UnknownDisclosureError: 'that wording is not registered for your organization',
  invalid_channel: 'a channel is not one your organization has',
  stop_cannot_proceed: 'a stop on record cannot be set to proceed',
  policy_incomplete: 'the policy lacks a cell for an evidence status, channel and purpose',
  invite_wrong_account: 'you are signed in with a different address than the one invited',
  second_factor_required: 'your sign-in shows no passkey or second factor',
  not_a_member: 'you are not a member of that organization',
  unauthenticated: 'your session ended',
};

export function causeFor(code: string): string {
  return CAUSES[code] ?? `the service answered ${code}`;
}

/** "<plain cause> (<status> <name>)" for the Cause line of the error formula (copy-rules.md section 4). */
export function causeLine(status: number, code: string, override?: string): string {
  const known = override !== undefined || CAUSES[code] !== undefined;
  if (!known) return `The service answered ${status > 0 ? `${status} ` : ''}${code}`;
  const plain = override ?? CAUSES[code];
  const cap = plain.charAt(0).toUpperCase() + plain.slice(1);
  return status > 0 ? `${cap} (${status} ${code})` : `${cap} (${code})`;
}

// What a capture request prints when it is refused (wireframe 06, contracts/capture.md).
export const CAPTURE_REFUSALS: { answer: string; means: string; todo: string }[] = [
  { answer: '422 UnknownDisclosureError', means: 'That wording is not registered for {org}.', todo: 'Register the exact text in Wording, then send its fingerprint.' },
  { answer: '403 source_not_allowed', means: 'The source in the body is not the one this credential belongs to.', todo: 'Use the source id shown on the credential.' },
  { answer: '403 brand_not_allowed', means: 'The brand is not on this source.', todo: "Add the brand to the source, or send the source's brand." },
  { answer: '403 org_not_active', means: 'Your organization is not active.', todo: 'Check Billing, or ask the operator.' },
  { answer: '401 invalid_client', means: 'The token or signature was not accepted.', todo: 'Get a fresh token. Check the key and algorithm.' },
  { answer: '422 UncheckedConsentError', means: 'The grant did not carry checked: true.', todo: 'Send checked: true only when the person ticked the box.' },
  { answer: '422 UnknownPurposeError', means: 'A purpose is not on your purpose list.', todo: 'Use a purpose your wording names.' },
  { answer: '422 GrantScopeError', means: 'The grant names a channel or purpose the wording does not.', todo: 'Match the channels and purposes to the registered wording.' },
  { answer: '429 rate_limited', means: 'Too many requests.', todo: 'Wait and send again.' },
  { answer: '503 key_unavailable', means: 'Nothing was written. Your encryption key could not be reached.', todo: 'Send again in a minute. Report it if it repeats.' },
];
