// Mock for contracts/records.md: 312 active records and 8 erased ones, built the same way on every run so tests can count.
import type * as T from '../src/lib/api/types.ts';
import type { Store } from './data.ts';
import { nid } from './data.ts';

type Res = { status: number; body?: unknown; headers?: Record<string, string> };
type Ctx = { method: string; path: string; query: URLSearchParams; body: any; m: RegExpMatchArray; st: Store };
export interface Deps {
  route: (method: string, pattern: string, h: (c: Ctx) => Res | Promise<Res>) => void;
  E: (status: number, error: string, detail?: string, fields?: Record<string, unknown>) => Res;
  OK: (body: unknown, status?: number) => Res;
  page: <X>(items: X[], q: URLSearchParams) => T.Page<X>;
  allow: (c: Ctx, ...roles: T.Role[]) => Res | null;
  suspendedBlock: (c: Ctx) => Res | null;
  nowIso: () => string;
}

interface Full extends T.ContactRecord { _full: string | null }
const END = Date.parse('2026-10-30T20:00:00Z');
const NAMES: [string, string | null][] = [['Kim Osei', 'Northwind Supply'], ['Priya Nair', 'Helio Roofing'], ['Marcus Webb', null], ['Lena Fischer', 'Helio Roofing'], ['Tomas Rivera', 'Northwind Supply'], ['Aisha Khan', null]];
const CHANNEL_KEYS = ['email', 'sms', 'voice', 'artificial_voice'];
const hex8 = (n: number) => ((Math.imul(n + 1, 0x9e3779b1) >>> 0).toString(16)).padStart(8, '0');
const CONF: (null | T.ConfirmationLatest['last_status'])[] = ['sent', 'delivered', 'skipped', 'failed', 'dead', null];

function build(): Full[] {
  const out: Full[] = [];
  const mk = (i: number, erased: boolean): Full => {
    const email = i % 3 === 2;
    const src = i % 7 === 0 && i > 0 ? { source_id: 'src_sf', name: 'Salesforce' } : { source_id: 'src_web', name: 'Website form' };
    const stop = erased ? true : src.source_id === 'src_web' && i % 11 === 5;
    const first = END - i * 2.3 * 3600e3;
    const last = Math.min(END, first + (i % 5) * 3600e3);
    const num = String(100 + i).padStart(4, '0');
    const status = (on: boolean): T.RecordStatus => (!on ? 'no_record' : stop ? 'stop_on_record' : 'consent_record_found');
    const channels: Record<string, T.RecordChannel> = {};
    for (const ch of CHANNEL_KEYS) {
      const st = ch === 'artificial_voice' && !email && i % 4 === 1 ? 'no_record' : status(ch === 'email' ? email : !email && ch !== 'email');
      channels[ch] = { counts: { consent_record_found: st === 'consent_record_found' ? 1 : 0, stop_on_record: st === 'stop_on_record' ? 1 : 0, no_record: st === 'no_record' ? 1 : 0 }, purposes: [{ purpose: 'marketing', evidence_status: st }] };
    }
    const person = erased || i % 7 === 3 ? (erased ? null : { name: null, company: null }) : { name: NAMES[i % 6][0], company: NAMES[i % 6][1] };
    const cs = CONF[i % 6];
    return {
      record_id: erased ? `rec_e${i}` : `rec_${i.toString(36).padStart(3, '0')}`,
      contact_kind: email ? 'email' : 'phone',
      contact: { masked: erased ? null : email ? 'l***@example.com' : `(555) ***-${num}`, fp_hint: hex8(erased ? 900 + i : i) },
      person, state: erased ? 'erased' : 'active',
      first_recorded_at: new Date(first).toISOString(), last_event_at: new Date(last).toISOString(),
      first_source: src, source_ids: [src.source_id], source_count: 1, brand_ids: ['brd_acme'], channels,
      has_stop: stop, last_stop_at: stop ? new Date(last + 1800e3).toISOString() : null,
      confirmation: erased || !cs ? null : { last_status: cs, channel: email ? 'email' : 'sms', at: new Date(first + 60e3).toISOString() },
      recorded_during_trial: i % 9 === 0, linked_record_count: i % 10 === 4 ? 1 : 0,
      _full: erased ? null : email ? `lead${i}@example.com` : `+1555555${num}`,
    };
  };
  for (let i = 0; i < 312; i++) out.push(mk(i, false));
  for (let i = 0; i < 8; i++) out.push(mk(150 + i * 20, true));
  return out;
}

function store(st: Store): { recs: Full[]; exports: { item: T.RecordsExportItem; polls: number; mode: string; total: number }[] } {
  if (!st.ext.records) st.ext.records = { recs: st.scenario.records === 'none' ? [] : build(), exports: [] };
  return st.ext.records;
}

const CALL = ['voice', 'artificial_voice'];
function cells(r: T.ContactRecord, channel: string | null, purpose: string | null): T.RecordStatus[] {
  const keys = channel === 'call' ? CALL : channel ? [channel] : Object.keys(r.channels);
  return keys.flatMap((k) => (r.channels[k]?.purposes ?? []).filter((p) => !purpose || p.purpose === purpose).map((p) => p.evidence_status));
}
function matches(r: Full, q: URLSearchParams): boolean {
  const state = q.get('state') ?? 'active';
  if (state !== 'all' && r.state !== state) return false;
  const ch = q.get('channel'), status = q.get('status'), purpose = q.get('purpose');
  if (status && !cells(r, ch, purpose).includes(status as T.RecordStatus)) return false;
  if (!status && ch && cells(r, ch, purpose).length === 0) return false;
  const hs = q.get('has_stop'); if (hs && String(r.has_stop) !== hs) return false;
  const srcs = q.getAll('source_id'); if (srcs.length && !r.source_ids.some((s) => srcs.includes(s))) return false;
  const field = q.get('date_field') === 'last_event' ? r.last_event_at : r.first_recorded_at;
  const from = q.get('from'), to = q.get('to');
  if (from && field < from) return false; if (to && field >= to) return false;
  const kind = q.get('contact_kind'); if (kind && r.contact_kind !== kind) return false;
  const cf = q.get('confirmation'); if (cf && (cf === 'none' ? r.confirmation !== null : r.confirmation?.last_status !== cf)) return false;
  const tr = q.get('trial') ?? 'include'; if (tr === 'exclude' && r.recorded_during_trial) return false; if (tr === 'only' && !r.recorded_during_trial) return false;
  return true;
}
function sorted(rs: Full[], q: URLSearchParams): Full[] {
  const s = q.get('sort') ?? 'last_event_desc';
  const key = (r: Full) => (s === 'last_event_desc' ? r.last_event_at : r.first_recorded_at);
  const dir = s === 'first_recorded_asc' ? 1 : -1;
  return rs.slice().sort((a, b) => (key(a) < key(b) ? -dir : key(a) > key(b) ? dir : a.record_id < b.record_id ? -1 : 1));
}
function shape(r: Full, role: T.Role, nulls: string[]): T.ContactRecord {
  const { _full: _f, ...rest } = r;
  const out: T.ContactRecord = { ...rest, contact: { ...r.contact }, person: r.person ? { ...r.person } : null };
  if (role === 'developer') { out.contact.masked = null; out.person = null; }
  else {
    if (nulls.includes('rec_mask')) out.contact.masked = null;
    if (nulls.includes('rec_person')) out.person = null;
  }
  return out;
}
const digitsOf = (s: string) => s.replace(/\D/g, '');
function normalize(raw: string): string | null {
  const v = String(raw ?? '').trim();
  if (v.includes('@')) return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v) ? v.toLowerCase() : null;
  const d = digitsOf(v);
  if (v.startsWith('+') && d.length >= 11 && d.length <= 15) return `+${d}`;
  if (d.length === 10) return `+1${d}`;
  if (d.length === 11 && d.startsWith('1')) return `+${d}`;
  return null;
}

export function registerRecords(x: Deps): void {
  const { route, E, OK, allow, suspendedBlock, nowIso } = x;
  route('GET', '/v1/records', (c) => {
    const r0 = allow(c, 'admin', 'developer', 'compliance_viewer'); if (r0) return r0;
    const bad = c.query.get('status'); if (bad === 'record_incomplete') return E(422, 'validation_failed', '', { status: 'record_incomplete is not on the list' });
    if (c.query.get('from') && c.query.get('to') && c.query.get('from')! > c.query.get('to')!) return E(422, 'validation_failed', '', { from: 'later than to' });
    const all = sorted(store(c.st).recs.filter((r) => matches(r, c.query)), c.query);
    const limit = Math.min(200, Math.max(1, Number(c.query.get('limit') ?? 50)));
    const start = c.query.get('cursor') ? Number(Buffer.from(c.query.get('cursor')!, 'base64url').toString()) : 0;
    const nulls = c.st.scenario.nulls;
    const slice = all.slice(start, start + limit).map((r) => shape(r, c.st.role, nulls));
    const partial = c.st.role === 'developer' ? [] : [...(nulls.includes('rec_mask') ? ['contact_mask'] : []), ...(nulls.includes('rec_person') ? ['person'] : [])];
    const enc = (n: number) => Buffer.from(String(n)).toString('base64url');
    return OK({ as_of: nowIso(), items: slice, next_cursor: start + limit < all.length ? enc(start + limit) : null, prev_cursor: start > 0 ? enc(Math.max(0, start - limit)) : null, total: nulls.includes('rec_total') ? null : all.length, ...(partial.length ? { partial } : {}) });
  });
  route('GET', '/v1/records/summary', (c) => {
    const r0 = allow(c, 'admin', 'developer', 'compliance_viewer'); if (r0) return r0;
    const all = store(c.st).recs.filter((r) => matches(r, c.query));
    // default window (records.md section 4): with no from, the last 30 local days ending on the day holding `to` (default: the mock's now)
    const endDay = (c.query.get('to') ?? new Date(END).toISOString()).slice(0, 10);
    const startDay = c.query.get('from') ? c.query.get('from')!.slice(0, 10) : new Date(Date.parse(`${endDay}T00:00:00Z`) - 29 * 86400e3).toISOString().slice(0, 10);
    if (Date.parse(`${endDay}T00:00:00Z`) - Date.parse(`${startDay}T00:00:00Z`) > 399 * 86400e3) return E(422, 'validation_failed', '', { from: 'at most 400 days' });
    const days: { date: string; count: number }[] = [];
    for (let t = Date.parse(`${startDay}T00:00:00Z`); t <= Date.parse(`${endDay}T00:00:00Z`); t += 86400e3) days.push({ date: new Date(t).toISOString().slice(0, 10), count: 0 });
    for (const r of all) { const day = r.first_recorded_at.slice(0, 10); const e = days.find((y) => y.date === day); if (e) e.count++; }
    const chart = c.st.scenario.nulls.includes('rec_chart');
    const by = ['email', 'sms', 'voice', 'artificial_voice'].map((ch) => {
      const o = { channel: ch, consent_record_found: 0, stop_on_record: 0, no_record: 0 };
      for (const r of all) { const s = cells(r, ch, null); o[s.includes('stop_on_record') ? 'stop_on_record' : s.includes('consent_record_found') ? 'consent_record_found' : 'no_record']++; }
      return o;
    });
    // the call total counts each record once, under its most protective status across voice and artificial_voice
    const callNull = c.st.scenario.nulls.includes('rec_call');
    const call = { consent_record_found: 0, stop_on_record: 0, no_record: 0 };
    for (const r of all) { const s2 = cells(r, 'call', null); call[s2.includes('stop_on_record') ? 'stop_on_record' : s2.includes('consent_record_found') ? 'consent_record_found' : 'no_record']++; }
    const partial = [...(chart ? ['new_per_day'] : []), ...(callNull ? ['call'] : [])];
    return OK({ as_of: nowIso(), tz: c.query.get('tz') ?? 'UTC', total: all.length, with_stop: all.filter((r) => r.has_stop).length, new_in_range: days.reduce((n, d) => n + d.count, 0),
      new_per_day: chart ? null : days, by_channel: by, call: callNull ? null : call, ...(partial.length ? { partial } : {}) });
  });
  route('POST', '/v1/records\\:search', (c) => {
    const r0 = allow(c, 'admin', 'compliance_viewer'); if (r0) return r0;
    const n = normalize(c.body?.contact); if (!n) return E(422, 'invalid_contact', 'That is not a complete phone number or email address.');
    const hit = store(c.st).recs.filter((r) => r._full === n && r.state === 'active');
    return OK({ items: hit.map((r) => shape(r, c.st.role, c.st.scenario.nulls)) });
  });
  route('POST', '/v1/records\\:reveal', (c) => {
    const r0 = allow(c, 'admin', 'compliance_viewer'); if (r0) return r0;
    const ids: string[] = c.body?.record_ids;
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 200) return E(422, 'validation_failed', '', { record_ids: '1 to 200' });
    const recs = store(c.st).recs;
    const items: T.RevealItem[] = [];
    for (const id of ids) {
      const r = recs.find((y) => y.record_id === id); if (!r) return E(422, 'validation_failed', '', { record_ids: `unknown id` });
      items.push(r.state === 'erased' ? { record_id: id, contact: null, cause: 'erased' } : { record_id: id, contact: r._full, cause: null });
    }
    return OK({ reveal_id: nid('rvl'), revealed_at: '2026-10-30T15:04:05Z', items });
  });
  route('POST', '/v1/records/exports', (c) => {
    const r0 = allow(c, 'admin', 'compliance_viewer'); if (r0) return r0;
    const sus = suspendedBlock(c); if (sus) return sus;
    const b = c.body ?? {};
    if (!['masked', 'full', 'fingerprint'].includes(b.contact_form)) return E(422, 'validation_failed', '', { contact_form: 'masked, full or fingerprint' });
    if (b.contact_form === 'full' && !String(b.reason ?? '').trim()) return E(422, 'validation_failed', '', { reason: 'required for a full file' });
    if (b.contact_form === 'fingerprint' && b.include_person === true) return E(422, 'validation_failed', '', { include_person: 'not with fingerprints' });
    if (c.st.scenario.exportMode === 'large') return E(422, 'export_too_large', 'Over the ceiling.', { count: 301220, max: 250000 });
    const s = store(c.st);
    if (s.exports.some((e) => e.item.status === 'building')) return E(409, 'export_in_progress', '', { export_id: s.exports.find((e) => e.item.status === 'building')!.item.export_id });
    const total = sorted(s.recs.filter((r) => matches(r, new URLSearchParams(b.filters ?? {}))), new URLSearchParams()).length;
    const item: T.RecordsExportItem = { export_id: nid('rex'), status: 'building', contact_form: b.contact_form, row_count: null, requested_by: 'Dana Ruiz', created_at: nowIso(), completed_at: null, expires_at: null, downloaded_at: null, sha256: null, failed_cause: null };
    s.exports.unshift({ item, polls: 0, mode: c.st.scenario.exportMode, total });
    return OK({ export_id: item.export_id, status: 'building', row_estimate: total }, 202);
  });
  route('GET', '/v1/records/exports', (c) => {
    const r0 = allow(c, 'admin', 'compliance_viewer'); if (r0) return r0;
    return OK(x.page(store(c.st).exports.map((e) => e.item), c.query));
  });
  route('GET', '/v1/records/exports/:id', (c) => {
    const r0 = allow(c, 'admin', 'compliance_viewer'); if (r0) return r0;
    const e = store(c.st).exports.find((y) => y.item.export_id === c.m.groups!.id); if (!e) return E(404, 'not_found');
    if (e.item.status === 'building') {
      e.polls++;
      if (e.polls >= 2) {
        if (e.mode === 'fail') { e.item.status = 'failed'; e.item.failed_cause = 'service_unavailable'; }
        else { e.item.status = 'ready'; e.item.row_count = e.total; e.item.completed_at = nowIso(); e.item.expires_at = new Date(Date.now() + 24 * 3600e3).toISOString(); e.item.sha256 = '9c41e0b7a1d2c3e4f5061728394a5b6c7d8e9f001122334455667788aa99a77f'; }
      }
    }
    const url = e.item.status === 'ready' ? `/__mock/download/records-${e.item.export_id}` : null;
    return OK({ ...e.item, progress: e.item.status === 'ready' ? { done: e.total, total: e.total } : { done: Math.min(150, e.total), total: e.total }, download_url: url });
  });
  route('POST', '/v1/records/exports/:id\\:link', (c) => {
    const r0 = allow(c, 'admin', 'compliance_viewer'); if (r0) return r0;
    const e = store(c.st).exports.find((y) => y.item.export_id === c.m.groups!.id); if (!e) return E(404, 'not_found');
    if (e.item.status !== 'ready') return E(409, 'export_not_ready');
    return OK({ download_url: `/__mock/download/records-${e.item.export_id}`, expires_at: new Date(Date.now() + 15 * 60e3).toISOString() });
  });
}
