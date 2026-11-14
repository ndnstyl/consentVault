import { ATTESTATION_TEMPLATE, GATE_NOTICE, NOT_A_LEGAL_TEST, NOT_LEGAL_ADVICE, PACKAGE_COVER } from './copy.ts';

// G-3 (design/handoff.md): rendered strings may not match any of these. The three fixed strings in
// copy-rules.md section 2, "Not legal advice" and "not a legal test" are allowlisted by exact match.

export const BANNED: RegExp[] = [
  /\bcompliant\b/i, /non-compliant/i, /in compliance/i, /compliance status/i, /valid consent/i, /consent is valid/i,
  /\bprov(e|es|en)\b/i, /\bproof\b/i, /\blawful\b/i, /legally sufficient/i, /permitted to/i,
  /allowed to (contact|call|text|email|dial)/i, /safe to/i, /cleared to/i, /OK to contact/i, /guarantee/i,
  /hold(s)? up in court/i, /court-ready/i, /qualifies/i, /satisfied/i, /meets (the )?TCPA/i, /something went wrong/i,
  /—/, /–/,
  // copy-rules.md section 8 (2026-10-30)
  /consent confirmed/i, /confirmed consent/i, /verified consent/i, /\bopted in\b/i, /\b(has|with|without) consent\b/i,
];

function esc(s: string): string { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

const ATTEST_RE = new RegExp(esc(ATTESTATION_TEMPLATE).replace(/\\\[Organization\\\]/g, '[^.]{1,80}?'), 'g');

export function stripAllowlisted(text: string): string {
  return text
    .split(GATE_NOTICE).join('')
    .split(PACKAGE_COVER).join('')
    .replace(ATTEST_RE, '')
    .split(NOT_LEGAL_ADVICE).join('')
    .split(NOT_LEGAL_ADVICE.toLowerCase()).join('')
    .split(NOT_A_LEGAL_TEST).join('');
}

/** Returns each banned pattern that matches, with the surrounding text. */
export function scanCopy(text: string): string[] {
  const t = stripAllowlisted(text.replace(/\s+/g, ' '));
  const hits: string[] = [];
  for (const re of BANNED) {
    const m = re.exec(t);
    if (m) hits.push(`${re} matched "${t.slice(Math.max(0, m.index - 30), m.index + m[0].length + 30)}"`);
  }
  return hits;
}
