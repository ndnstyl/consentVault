import type { FieldMapBodyFormat, FieldMapNew } from './api/types.ts';

// A field map says where a form puts its fields. The portal only adds a new version; a version is never edited.
// Paths are sent exactly as typed (a JSON pointer such as /checked, or a form field name such as tcpa_box).

export interface FieldMapForm {
  body_format: FieldMapBodyFormat;
  consent_paths: string;
  consent_ticked_value: string;
  contact_paths: string;
  seller_paths: string;
  decision_time_path: string;
  wording_path: string;
  wording_hash_path: string;
  form_version_path: string;
  checkbox_default_path: string;
  submit_context_path: string;
  third_party_cert_path: string;
  jurisdiction_path: string;
  channel_scope_path: string;
}

export const EMPTY_FORM: FieldMapForm = {
  body_format: 'json', consent_paths: '', consent_ticked_value: '', contact_paths: '', seller_paths: '', decision_time_path: '', wording_path: '',
  wording_hash_path: '', form_version_path: '', checkbox_default_path: '', submit_context_path: '', third_party_cert_path: '', jurisdiction_path: '', channel_scope_path: '',
};

export const SINGLE_PATHS = ['decision_time_path', 'wording_path', 'wording_hash_path', 'form_version_path', 'checkbox_default_path', 'submit_context_path', 'third_party_cert_path', 'jurisdiction_path', 'channel_scope_path'] as const;

export function splitLines(text: string): string[] {
  return text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
}

/** One contact line reads `path: phone` or `path: email`; the kind follows the last colon. */
export function parseContact(line: string): { path: string; kind: string } | null {
  const i = line.lastIndexOf(':');
  if (i <= 0) return null;
  const path = line.slice(0, i).trim();
  const kind = line.slice(i + 1).trim();
  return path ? { path, kind } : null;
}

export function fieldMapErrors(f: FieldMapForm): { id?: string; message: string }[] {
  const errs: { id?: string; message: string }[] = [];
  if (splitLines(f.consent_paths).length === 0) errs.push({ id: 'consent_paths', message: 'Enter where the consent box is found, one per line.' });
  for (const line of splitLines(f.contact_paths)) {
    const c = parseContact(line);
    if (!c) errs.push({ id: 'contact_paths', message: `${line} needs a kind: write it as path: phone or path: email.` });
    else if (c.kind !== 'phone' && c.kind !== 'email') errs.push({ id: 'contact_paths', message: `${line} has the kind ${c.kind}. The kind is phone or email.` });
  }
  return errs;
}

export function fieldMapBody(f: FieldMapForm): FieldMapNew {
  const body: FieldMapNew = { body_format: f.body_format, consent_paths: splitLines(f.consent_paths) };
  if (f.consent_ticked_value !== '') body.consent_ticked_value = f.consent_ticked_value;
  const contacts = splitLines(f.contact_paths).map(parseContact).filter((c): c is { path: string; kind: string } => c !== null);
  if (contacts.length) body.contact_paths = contacts as { path: string; kind: 'phone' | 'email' }[];
  const sellers = splitLines(f.seller_paths);
  if (sellers.length) body.seller_paths = sellers;
  for (const k of SINGLE_PATHS) { const v = f[k].trim(); if (v) body[k] = v; }
  return body;
}
