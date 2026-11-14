// Dates show in the viewer's zone with the zone named (G-10); the machine time rides in <time datetime>.

export function zoneName(): string {
  try { return new Intl.DateTimeFormat('en-US', { timeZoneName: 'short' }).formatToParts(new Date()).find((p) => p.type === 'timeZoneName')?.value ?? ''; } catch { return ''; }
}

export function fmtDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' }).format(d);
}
export function fmtDate(iso: string): string {
  // A date the service stores as midnight UTC is a calendar day, not a moment: it is read in UTC so it never slips to the day before.
  const day = iso.length === 10 || /T00:00:00(\.0+)?Z$/.test(iso);
  const d = new Date(iso.length === 10 ? `${iso}T12:00:00Z` : iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeZone: day ? 'UTC' : undefined }).format(d);
}
export function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit', timeZoneName: 'short' }).format(d);
}
export function fmtNum(n: number): string { return new Intl.NumberFormat('en-US').format(n); }
export function orgsBrandsLine(n: number | null | undefined): string | null { return typeof n === 'number' && Number.isFinite(n) ? `Up to ${fmtNum(n)} organizations and brands` : null; }
export function fmtMoney(cents: number, currency: string): string {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: currency.toUpperCase(), maximumFractionDigits: 0 }).format(cents / 100);
}

export const NOT_RECORDED = 'Not recorded';

/** A field the record may not hold, as text: the value, or "Not recorded". Never "undefined", "null" or an empty cell. */
export function rec(v: unknown, fallback: string = NOT_RECORDED): string {
  if (v === null || v === undefined) return fallback;
  const t = typeof v === 'string' ? v.trim() : String(v);
  return t === '' || t === 'null' || t === 'undefined' || t === 'NaN' ? fallback : t;
}

// A phone is recognised only by its whole shape (an optional +1, then exactly ten digits, with only phone punctuation between),
// never by finding digits inside some other value: an export id or a fingerprint carries digit runs too.
const PHONE_SHAPE = /^(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}$/;
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const tenDigits = (c: string): string | null => (PHONE_SHAPE.test(c.trim()) ? c.replace(/\D/g, '').slice(-10) : null);

/** "(555) ***-0100" for a contact point we may only show masked. Anything that is not a whole email or phone shows as "***". */
export function maskContact(c: string): string {
  if (EMAIL_SHAPE.test(c)) { const [u, d] = c.split('@'); return `${u.slice(0, 1)}***@${d}`; }
  const ten = tenDigits(c);
  return ten ? `(${ten.slice(0, 3)}) ***-${ten.slice(6)}` : '***';
}
/** A phone in its usual form when it is a whole phone; every other value is shown exactly as it is. */
export function prettyContact(c: string): string {
  if (c.includes('@')) return c;
  const ten = tenDigits(c);
  return ten ? `(${ten.slice(0, 3)}) ${ten.slice(3, 6)}-${ten.slice(6)}` : c;
}

/** The Target cell of the audit log: what the record holds. Only a contact target whose value is itself a whole email or phone is masked. */
export function targetLine(t: { kind: string; id: string | null } | null | undefined): string {
  if (!t) return NOT_RECORDED;
  if (t.kind === 'org') return 'This organization';
  const label = rec(t.kind, 'record').replace(/_/g, ' ');
  const id = typeof t.id === 'string' ? t.id.trim() : '';
  if (!id) return label;
  const isContactPoint = t.kind === 'contact' && (EMAIL_SHAPE.test(id) || PHONE_SHAPE.test(id));
  return `${label} ${isContactPoint ? maskContact(id) : id}`;
}

/** Classify a typed contact as phone or email and say why it is incomplete (invalid_contact:phone|email). */
export function checkContact(raw: string): { ok: true; value: string; kind: 'phone' | 'email' } | { ok: false; kind: 'phone' | 'email'; shown: string } {
  const v = raw.trim();
  if (v.includes('@')) {
    const ok = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v);
    return ok ? { ok: true, value: v, kind: 'email' } : { ok: false, kind: 'email', shown: v };
  }
  const digits = v.replace(/\D/g, '');
  if (digits.length === 10) return { ok: true, value: `+1${digits}`, kind: 'phone' };
  if (digits.length === 11 && digits.startsWith('1')) return { ok: true, value: `+${digits}`, kind: 'phone' };
  return { ok: false, kind: 'phone', shown: v };
}

export function shortId(sha: string): string { return sha.length > 10 ? `${sha.slice(0, 4)}...${sha.slice(-2)}` : sha; }
