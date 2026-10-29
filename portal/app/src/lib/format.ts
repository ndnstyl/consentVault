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
  const d = new Date(iso.length === 10 ? `${iso}T12:00:00Z` : iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeZone: iso.length === 10 ? 'UTC' : undefined }).format(d);
}
export function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit', timeZoneName: 'short' }).format(d);
}
export function fmtNum(n: number): string { return new Intl.NumberFormat('en-US').format(n); }
export function fmtMoney(cents: number, currency: string): string {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: currency.toUpperCase(), maximumFractionDigits: 0 }).format(cents / 100);
}

/** "(555) ***-0100" for a contact point we may only show masked. */
export function maskContact(c: string): string {
  if (c.includes('@')) { const [u, d] = c.split('@'); return `${u.slice(0, 1)}***@${d}`; }
  const digits = c.replace(/\D/g, '');
  const ten = digits.slice(-10);
  return ten.length === 10 ? `(${ten.slice(0, 3)}) ***-${ten.slice(6)}` : '***';
}
export function prettyContact(c: string): string {
  if (c.includes('@')) return c;
  const ten = c.replace(/\D/g, '').slice(-10);
  return ten.length === 10 ? `(${ten.slice(0, 3)}) ${ten.slice(3, 6)}-${ten.slice(6)}` : c;
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
