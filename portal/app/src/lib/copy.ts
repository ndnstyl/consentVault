import type { OrgStatus, Role } from './api/types.ts';

// Copy of record: portal/design/copy-rules.md and the wireframe text.
// No em dashes or en dashes. Never a legal conclusion.

export const GATE_NOTICE = "Evidence status as recorded. Not a legal determination.";
export const PACKAGE_COVER = 'Its cover page states that the records are evidence for an investigation or dispute, and that storing a record does not by itself establish valid consent.';
export const NOT_LEGAL_ADVICE = 'Not legal advice';
export const NOT_A_LEGAL_TEST = 'not a legal test';

export function fillOrg(text: string, org: string): string { return text.replace(/\[Organization\]/g, org); }

export const NA = 'Not available';

// ---- Label dictionary (copy-rules.md section 3) ----
export type EvidenceKind = 'found' | 'stop' | 'none' | 'incomplete' | 'na';
export interface Label { text: string; kind: EvidenceKind; icon: string }

export function evidenceLabel(status: string): Label {
  if (status === 'consent_record_found') return { text: 'Consent record found', kind: 'found', icon: 'i-found' };
  if (status === 'records_found') return { text: 'Records found', kind: 'found', icon: 'i-found' };
  if (status === 'no_record_found') return { text: 'No record found', kind: 'none', icon: 'i-none' };
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
export const CRED_SCOPE_LABEL: Record<string, string> = { capture: 'Capture', gate_read: 'Contact check', proof_read: 'Evidence read' };
export const CHANNEL_FALLBACK: Record<string, string> = { sms: 'SMS', voice: 'Voice', artificial_voice: 'Artificial or prerecorded voice', email: 'Email' };

export const ROLE_DESCRIPTION: Record<Role, string> = {
  admin: 'Admin: everything, including members and billing',
  developer: 'Developer: sources, credentials, connected systems, test events. No personal records.',
  compliance_viewer: 'Compliance viewer: look up records and build evidence packages. Changes nothing.',
};

// ---- Plain causes (copy-rules.md section 5, plus the contract errors the screens meet) ----
const CAUSES: Record<string, string> = {
  sso_required: 'your organization requires you to sign in with your company account, and this sign-in did not come through it',
  sso_not_connected: "this organization has not connected that company sign-in, or its admin has not proved it yet",
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
  disclosure_exists: 'this exact text is already registered',
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
  acknowledgement_required: 'the acknowledgement was not accepted',
  unknown_brand: 'a brand does not belong to this organization',
  UnknownPurposeError: 'a purpose is not on your purpose list',
  UnknownDisclosureError: 'that wording is not registered for your organization',
  invalid_channel: 'a channel is not one your organization has',
  invite_wrong_account: 'you are signed in with a different address than the one invited',
  second_factor_required: 'your sign-in shows no passkey or second factor',
  not_a_member: 'you are not a member of that organization',
  unauthenticated: 'your session ended',
  audit_unavailable: 'the audit log could not record this view',
  export_too_large: 'the list is over the number of records one file can hold',
  export_in_progress: 'another file for your organization is still being built',
  export_link_expired: 'the download link expired',
  link_host_dns_missing: 'the DNS record for the link host was not found',
  link_host_not_verified: 'the wording link host is not verified',
  texting_not_registered: 'texting registration is not marked complete',
  inbound_not_verified: 'no test reply has reached ConsentVault',
  no_sending_account: 'no sending account is connected for that channel',
  sender_details_missing: 'the organization name, postal address or help contact is missing',
  sender_not_verified: 'the sending domain is not verified at the provider',
  provider_not_supported: 'that provider is not supported for this channel',
  provider_unreachable: 'the sending provider did not answer',
  provider_refused: 'the sending provider refused the request',
  inbound_still_pointed_here: 'your number still sends its replies to ConsentVault',
  step_not_skippable: 'only the optional steps can be skipped',
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

// What a capture request can still be answered with. Every post that reaches the vault is stored; nothing about the post is
// checked or refused (contracts/capture-api.md), so the only answers left are a token the service did not accept and a
// store that could not be written.
export const CAPTURE_REFUSALS: { answer: string; means: string; todo: string }[] = [
  { answer: '401 invalid_client', means: 'The token or signature was not accepted.', todo: 'Get a fresh token. Check the key and algorithm.' },
  { answer: '503 store_unavailable', means: 'Nothing was stored. The record store could not be written.', todo: 'Send again in a minute. Report it if it repeats.' },
];

// ---- Records, setup and confirmation messages (copy-rules.md section 8) ----
export const RECORDS_NOTICE = 'Evidence status describes the records held. Each contact\'s evidence lookup page shows the recorded facts and history.';
export const RECORDS_SEARCH_HINT = 'Whole number or address only. Each contact is stored encrypted, so partial search is not possible.';
export const REVEAL_DIALOG = 'Each page you open this way writes one audit row with your name and the records shown.';
export const REGISTRATION_DIALOG = 'ConsentVault records who marked it and when. It does not check your registration with carriers or your provider.';

/** Confirmation status words for a record's latest send (records.md section 2). */
export function confirmationWord(c: { last_status: string; channel: string } | null): string {
  if (!c) return 'None';
  const ch = c.channel === 'sms' ? 'Text' : c.channel === 'email' ? 'Email' : c.channel;
  const w: Record<string, string> = { sent: 'sent', delivered: 'delivered', failed: 'failed', dead: 'undelivered after 2 hours', skipped: 'not sent' };
  return `${ch} ${w[c.last_status] ?? c.last_status}`;
}

/** Why a send did not go out (copy-rules.md section 8, skip names from confirmations.md section 5). */
export function skipWord(reason: string | null, ctx: { brand?: string; delay?: number; hours?: number } = {}): string {
  const b = ctx.brand ?? 'that brand';
  const m: Record<string, string> = {
    quiet_hours: "Not sent: outside texting hours (in the person's time zone)",
    time_zone_unknown: "Not sent: the person's time zone could not be told from the number",
    brand_not_in_grant: `Not sent: the consent does not name ${b}`,
    inbound_not_verified: 'Not sent: no test reply has reached ConsentVault',
    link_host_failing: 'Not sent: your wording link host is not answering',
    no_sending_account: 'Not sent: no sending account connected',
    sending_account_failing: 'Not sent: your provider refused the account 5 times in a row; check the account',
    channel_not_in_grant: 'Not sent: the consent does not name this channel',
    contact_kind: 'Not sent: no address for this channel',
    late: `Not sent: the consent arrived more than ${ctx.delay ?? 10} minutes after it was captured`,
    stop_on_record: 'Not sent: stop on record',
    recent_confirmation: `Not sent: one was sent in the last ${ctx.hours ?? 24} hours`,
    texting_not_registered: 'Not sent: texting registration not marked',
    org_not_active: 'Not sent: organization not active',
    test_event: 'Not sent: test events are off for this rule',
    contact_erased: 'Not sent: the contact was erased',
    org_hourly_cap: 'Not sent: the hourly sending limit was reached',
  };
  return reason ? m[reason] ?? `Not sent: ${reason.replace(/_/g, ' ')}` : 'Not sent';
}

export function deadCauseWord(cause: string | null): string {
  if (!cause) return NA;
  if (cause === 'provider_unreachable') return 'Provider did not answer (502 provider_unreachable)';
  if (cause === 'key_unavailable') return "Your organization's encryption key did not answer (503 key_unavailable)";
  const m = /^retry:(\d+)$/.exec(cause);
  return m ? `Provider answered ${m[1]}` : `The service answered ${cause}`;
}

// The field map screen (T065). A map only says where a form puts its fields; nothing here judges a form or a value.
export const FIELD_MAP_COPY: Record<string, string> = {
  title: 'Field map',
  lede: 'Where this capture source puts each field in what it sends. A change is a new version. An earlier version is never edited and stays on record.',
  empty: 'No version added yet. Until you add one, a post from the ConsentVault widget is read with the built-in widget map shown below, and any other post is stored whole and read as unmapped.',
  built_in: 'Built-in widget map. It applies to posts from the ConsentVault widget when this source has no version of its own.',
  add: 'Add a version',
  paths_hint: 'Write each path exactly as the form sends it: a JSON pointer such as /checked, or a form field name such as tcpa_box.',
  ticked_hint: 'The exact text your box sends when it is ticked, for example true or on. It is only used to link a stop that a form lifts. Leave it empty if you are unsure.',
  contact_hint: 'One per line, written as path: phone or path: email.',
  saved: 'Version added. Recorded in the audit log. The earlier versions are unchanged.',
  retired: 'This source is retired. Its versions can be read; a new one cannot be added.',
};
