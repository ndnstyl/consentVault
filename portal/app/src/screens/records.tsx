import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, allPages } from '../lib/api/client.ts';
import type { ContactRecord, RecordFilters, RecordsExportDetail, RecordsExportItem, RecordsSummary, SourceName } from '../lib/api/types.ts';
import { NA, RECORDS_NOTICE, RECORDS_SEARCH_HINT, REVEAL_DIALOG, causeLine, confirmationWord, evidenceLabel } from '../lib/copy.ts';
import { checkContact, fmtDate, fmtDateTime, fmtNum, fmtTime, prettyContact } from '../lib/format.ts';
import { useAction, usePoll, useResource } from '../lib/hooks.ts';
import { useRouter } from '../lib/router.tsx';
import { canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { ConfirmDialog } from '../components/Dialog.tsx';
import { Banner, Btn, Chip, CopyButton, DataTable, ErrorBlock, Icon, KV, LinkBtn, NotAvailable, PageHead, Pager, Radio, SelectField, Skeleton, StateBlock, SuccessBanner, TextField, Tile, Time, cx } from '../components/ui.tsx';

const PAGE = 50;
// The first time a person turns full contact points on in this visit they are asked; a reload starts a new visit.
let revealAcked = false;

const FILTER_KEYS = ['channel', 'status', 'purpose', 'has_stop', 'source_id', 'date_field', 'from', 'to', 'trial', 'state', 'sort'] as const;
const ENUMS: Record<string, string[]> = {
  channel: ['email', 'sms', 'call'], status: ['consent_record_found', 'stop_on_record', 'no_record'], has_stop: ['true', 'false'], date_field: ['first_recorded', 'last_event'],
  trial: ['include', 'exclude', 'only'], state: ['active', 'erased', 'all'], sort: ['last_event_desc', 'first_recorded_desc', 'first_recorded_asc'],
};
const CHANNEL_WORD: Record<string, string> = { email: 'Email', sms: 'Text', call: 'Call' };
const STATUS_WORD: Record<string, string> = { consent_record_found: 'Consent record found', stop_on_record: 'Stop on record', no_record: 'No record' };

/** Only known keys with known values survive: the address is never a way to carry a contact point. */
function filtersFrom(search: URLSearchParams): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of FILTER_KEYS) {
    const v = search.get(k);
    if (!v) continue;
    if (ENUMS[k] ? ENUMS[k].includes(v) : /^[A-Za-z0-9_:.\-]{1,64}$/.test(v)) out[k] = v;
  }
  return out;
}
const nextDay = (d: string) => new Date(Date.parse(`${d}T00:00:00Z`) + 86400e3).toISOString().slice(0, 10);
function toApi(f: Record<string, string>): RecordFilters {
  const o: Record<string, string> = { ...f };
  if (f.from && /^\d{4}-\d{2}-\d{2}$/.test(f.from)) o.from = `${f.from}T00:00:00Z`;
  if (f.to && /^\d{4}-\d{2}-\d{2}$/.test(f.to)) o.to = `${nextDay(f.to)}T00:00:00Z`;
  return o as RecordFilters;
}

// ---------- chips per channel group ----------
const GROUPS: { key: string; label: string; channels: string[] }[] = [
  { key: 'email', label: 'Email', channels: ['email'] },
  { key: 'sms', label: 'Text', channels: ['sms'] },
  { key: 'call', label: 'Call', channels: ['voice', 'artificial_voice'] },
];
const RANK: Record<string, number> = { stop_on_record: 2, consent_record_found: 1, no_record: 0 };

function groupStatuses(r: ContactRecord, channels: string[], purpose: string | undefined): string[] {
  const byPurpose = new Map<string, string>();
  for (const ch of channels) for (const p of r.channels[ch]?.purposes ?? []) {
    if (purpose && p.purpose !== purpose) continue;
    const cur = byPurpose.get(p.purpose);
    if (cur === undefined || RANK[p.evidence_status] > RANK[cur]) byPurpose.set(p.purpose, p.evidence_status);
  }
  return [...byPurpose.values()];
}
function StatusChip({ status, n, erased }: { status: string; n?: number; erased?: boolean }) {
  const l = evidenceLabel(status);
  const text = erased && status === 'stop_on_record' ? 'Stop written by the erasure request' : l.text;
  return <Chip tone={`ev-${l.kind}`} icon={l.icon}>{text}{n && n > 1 ? ` (${n})` : ''}</Chip>;
}
function ChannelCell({ r, channels, purpose }: { r: ContactRecord; channels: string[]; purpose: string | undefined }) {
  const st = groupStatuses(r, channels, purpose);
  const stop = st.filter((s) => s === 'stop_on_record').length;
  const found = st.filter((s) => s === 'consent_record_found').length;
  return (
    <span className="chips">
      {stop > 0 && <StatusChip status="stop_on_record" n={stop} erased={r.state === 'erased'} />}
      {found > 0 && <StatusChip status="consent_record_found" n={found} />}
      {stop === 0 && found === 0 && <StatusChip status="no_record" />}
    </span>
  );
}

// ---------- chart and share bars ----------
function BarChart({ series }: { series: { date: string; count: number }[] }) {
  const max = Math.max(1, ...series.map((s) => s.count));
  const peak = series.reduce((a, b) => (b.count > a.count ? b : a), series[0]);
  const w = 300 / series.length;
  const label = `New records per day, ${fmtDate(series[0].date)} to ${fmtDate(series[series.length - 1].date)}. Most in one day: ${peak.count} on ${fmtDate(peak.date)}.`;
  return (
    <>
      <svg className="chart" viewBox="0 0 300 100" preserveAspectRatio="none" role="img" aria-label={label}>
        <line className="base" x1="0" y1="99.5" x2="300" y2="99.5" />
        {series.map((s, i) => <rect key={s.date} x={i * w + 0.6} y={99 - (s.count / max) * 96} width={Math.max(1, w - 1.2)} height={(s.count / max) * 96} />)}
      </svg>
      <div className="axis" aria-hidden="true"><span>{fmtDate(series[0].date)}</span><span>{fmtDate(series[Math.floor(series.length / 2)].date)}</span><span>{fmtDate(series[series.length - 1].date)}</span></div>
      <details className="tbl">
        <summary>Show the chart as a table</summary>
        <table><caption>New records per day</caption><thead><tr><th scope="col">Day</th><th scope="col" className="r">New records</th></tr></thead>
          <tbody>{series.map((s) => <tr key={s.date}><td>{fmtDate(s.date)}</td><td className="r">{s.count}</td></tr>)}</tbody></table>
      </details>
    </>
  );
}

function ShareBars({ by, call }: { by: NonNullable<RecordsSummary['by_channel']>; call: RecordsSummary['call'] }) {
  return (
    <div className="sharebars">
      {GROUPS.map((g) => {
        if (g.key === 'call' && call == null) return <div className="sharebar" key={g.key}><div className="lab"><b>{g.label}</b><span className="na">{NA}</span></div></div>;
        // the Call total is the service's: a record holding both voice and AI-voice counts once, so it is never the sum of the two rows
        const rows = g.key === 'call' ? [{ channel: 'call', ...call! }] : by.filter((b) => g.channels.includes(b.channel));
        const f = rows.reduce((n, b) => n + b.consent_record_found, 0), s = rows.reduce((n, b) => n + b.stop_on_record, 0), z = rows.reduce((n, b) => n + b.no_record, 0);
        const tot = f + s + z;
        const pct = (n: number) => (tot ? Math.round((n / tot) * 100) : 0);
        const text = `Consent record found ${pct(f)}% · Stop on record ${pct(s)}% · No record ${pct(z)}%`;
        const aria = `${g.label}: Consent record found ${pct(f)}%, Stop on record ${pct(s)}%, No record ${pct(z)}%`;
        return (
          <div className="sharebar" key={g.key}>
            <div className="lab"><b>{g.label}</b><span>{text}</span></div>
            <div className="bar" role="img" aria-label={aria}><i className="f" style={{ width: `${pct(f)}%` }} /><i className="s" style={{ width: `${pct(s)}%` }} /><i className="n" style={{ width: `${pct(z)}%` }} /></div>
          </div>
        );
      })}
    </div>
  );
}

// ---------- the export ----------
function ExportDialog({ total, filterText, filters, onClose, onStarted, onError }: { total: number | null; filterText: string; filters: RecordFilters; onClose: () => void; onStarted: (id: string, form: string) => void; onError: (e: ApiError) => void }) {
  const { api } = useSession();
  const [form, setForm] = useState<'masked' | 'full' | 'fingerprint'>('masked');
  const [person, setPerson] = useState(true);
  return (
    <ConfirmDialog title="Export this list" confirmLabel="Build the file" busyLabel="Building" onClose={onClose} reasonLabel="Reason" reasonRequired={form === 'full'}
      failTitle="The file was not built" failNext="Try again. Nothing was built." onConfirm={async (reason) => {
        try {
          const r = await api.records.exportCreate({ filters, contact_form: form, include_person: form === 'fingerprint' ? false : person, ...(reason ? { reason } : {}) });
          onStarted(r.export_id, form);
        } catch (e) { onError(e as ApiError); }
        return null;
      }}
      body={<>
        <p>{total !== null ? `${fmtNum(total)} records match your filters (${filterText}).` : `The records that match your filters (${filterText}) will be exported.`} The file is a zip with a spreadsheet file, the filters used and a fingerprint of the file. It is kept 24 hours.</p>
        <fieldset className="mt4"><legend>Contact points in the file</legend>
          <Radio name="contact_form" label="Masked, for example (555) ***-0142" checked={form === 'masked'} onChange={() => { setForm('masked'); setPerson(true); }} />
          <Radio name="contact_form" label="Full phone numbers and email addresses" hint=" (reason required, recorded in the audit log)" checked={form === 'full'} onChange={() => { setForm('full'); setPerson(true); }} />
          <Radio name="contact_form" label="Fingerprints only" checked={form === 'fingerprint'} onChange={() => { setForm('fingerprint'); setPerson(false); }} />
        </fieldset>
        <div className="check mb4"><input id="inc-person" type="checkbox" checked={form === 'fingerprint' ? false : person} disabled={form === 'fingerprint'} onChange={(e) => setPerson(e.target.checked)} />
          <label htmlFor="inc-person">Include name and company <span className="hint">(masked or full files only; off and unavailable for fingerprints)</span></label></div>
        <p className="hint">A full or masked file with names records every record in it in the audit log.</p>
      </>} />
  );
}

const FORM_WORD: Record<string, string> = { masked: 'masked contact points', full: 'full contact points', fingerprint: 'fingerprints only' };
/** The download link works once. After it is used the link is gone and the way forward is a new one, never a dead link that looks live. */
function OneTimeDownload({ exportId, first, size }: { exportId: string; first: string | null; size?: 'sm' }) {
  const { api } = useSession();
  const [url, setUrl] = useState<string | null>(first);
  const link = useAction(() => api.records.exportLink(exportId));
  if (url) return <a className={`btn ${size === 'sm' ? 'btn-secondary btn-sm' : 'btn-primary'}`} href={url} download onClick={() => { window.setTimeout(() => setUrl(null), 150); }}>Download</a>;
  return (
    <>
      <Btn size={size ?? 'sm'} busy={link.busy} busyLabel="Getting link" onClick={async () => { const r = await link.run(); if (r.ok) setUrl(r.value.download_url); }}>Get a new download link</Btn>
      {link.error && <ErrorBlock title="A new link was not made" err={link.error} next="Try again. The file is kept 24 hours." headingLevel={3} />}
    </>
  );
}

function ExportStatus({ id, form, onAgain, onChangeFilters }: { id: string; form: string; onAgain: () => void; onChangeFilters: () => void }) {
  const { api } = useSession();
  const poll = usePoll<RecordsExportDetail>(() => api.records.exportGet(id), { intervalMs: 3000, deadlineMs: 20 * 60 * 1000, until: (e) => e.status !== 'building' });
  const e = poll.value;
  if (!e && poll.error) return <ErrorBlock title="The file status did not load" err={poll.error} next="Try again in a minute. The file, if built, is under Exports for 24 hours." actions={<Btn onClick={poll.restart}>Try again</Btn>} />;
  if (!e) return <div className="mb5"><Skeleton what="the file status" rows={1} /></div>;
  if (e.status === 'building') {
    return <div role="status" aria-live="polite"><Banner kind="info" title={`Building your file: ${fmtNum(e.progress?.done ?? 0)} of ${e.progress ? fmtNum(e.progress.total) : NA} records.`}>You can leave this page; the file will be under Exports on this page for 24 hours.</Banner></div>;
  }
  if (e.status === 'failed') {
    return <ErrorBlock title="The file was not built" err={new ApiError(503, e.failed_cause ?? 'service_unavailable', '', null)} override={`the records database stopped answering${e.progress ? ` at ${fmtNum(e.progress.done)} of ${fmtNum(e.progress.total)}` : ''} (${e.failed_cause ?? 'service_unavailable'})`}
      next="Start the export again. Nothing was downloaded." actions={<Btn variant="primary" onClick={onAgain}>Export again</Btn>} />;
  }
  if (e.status === 'expired') return <Banner kind="warning" title="That file has expired">Files are kept 24 hours. Export the list again to get a new one.</Banner>;
  void onChangeFilters;
  return (
    <SuccessBanner title="Your file is ready."
      action={<div className="btn-row mt4"><OneTimeDownload exportId={e.export_id} first={e.download_url} />{e.sha256 && <CopyButton text={e.sha256} label="Copy fingerprint" ariaLabel="Copy file fingerprint" />}</div>}>
      {`${fmtNum(e.row_count ?? 0)} records, ${FORM_WORD[e.contact_form] ?? FORM_WORD[form]}. The download link works once, for 15 minutes. File fingerprint (SHA-256) ${e.sha256 ? `${e.sha256.slice(0, 6)}...${e.sha256.slice(-4)}` : NA}`}
    </SuccessBanner>
  );
}

function PastExports() {
  const { api } = useSession();
  const res = useResource(() => api.records.exportList(), [api]);
  if (res.status !== 'ok' || res.data.items.length === 0) return null;
  return (
    <div className="mt6">
      <DataTable caption="Exports kept for 24 hours" rows={res.data.items} rowKey={(x: RecordsExportItem) => x.export_id}
        columns={[
          { key: 'at', header: 'Asked for', primary: true, render: (x) => <Time iso={x.created_at} /> },
          { key: 'f', header: 'Contact points', render: (x) => FORM_WORD[x.contact_form] ?? x.contact_form },
          { key: 'n', header: 'Records', render: (x) => (x.row_count === null ? <NotAvailable /> : fmtNum(x.row_count)) },
          { key: 's', header: 'Status', render: (x) => ({ building: 'Building', ready: 'Ready', failed: 'Failed', expired: 'Expired' } as Record<string, string>)[x.status] ?? x.status },
        ]}
        actions={(x) => (x.status === 'ready' ? <OneTimeDownload exportId={x.export_id} first={null} size="sm" /> : null)} />
    </div>
  );
}

// ---------- the screen ----------
export function Records() {
  const { api, role, orgName, status } = useSession();
  const { search, navigate } = useRouter();
  const canSearch = canDo(role, 'records.search');
  const canReveal = canDo(role, 'records.reveal');
  const canExport = canDo(role, 'records.export');
  const showPerson = canDo(role, 'records.person');
  const isDev = role === 'developer';
  const suspended = status === 'suspended';
  const filters = filtersFrom(search);
  const filterKey = JSON.stringify(filters);
  const tz = useMemo(() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch { return 'UTC'; } }, []);

  const [pageIdx, setPageIdx] = useState(0);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  useEffect(() => { setPageIdx(0); setCursors([null]); }, [filterKey]);
  const cursor = cursors[pageIdx] ?? null;

  const list = useResource(() => api.records.list({ ...toApi(filters), limit: PAGE, cursor }), [api, filterKey, cursor]);
  const summary = useResource(() => api.records.summary({ ...toApi(filters), tz }), [api, filterKey]);
  const purposes = useResource(() => api.purposes().then((p) => p.items), [api]);
  const sources = useResource<SourceName[]>(() => allPages((c) => api.sourceNames({ cursor: c })), [api]);

  // exact search keeps its answer in memory only
  const [found, setFound] = useState<{ shown: string; items: ContactRecord[] } | null>(null);
  const [searchErr, setSearchErr] = useState<ApiError | null>(null);
  const [badEntry, setBadEntry] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const search_ = useAction((c: string) => api.records.search(c));

  // reveal: in memory only, cleared on off, on a new page, and when the page is left
  const [revealOn, setRevealOn] = useState(false);
  const [revealMap, setRevealMap] = useState<Record<string, string | null>>({});
  const [revealAt, setRevealAt] = useState<string | null>(null);
  const [revealCount, setRevealCount] = useState(0);
  const [revealErr, setRevealErr] = useState<ApiError | null>(null);
  const [askReveal, setAskReveal] = useState(false);
  const revealedKey = useRef<string | null>(null);
  const reasonRef = useRef<string | undefined>(undefined);

  const rows: ContactRecord[] = found ? found.items : list.status === 'ok' ? list.data.items : [];
  const activeIds = rows.filter((r) => r.state === 'active').map((r) => r.record_id);
  const idsKey = activeIds.join(',');

  const doReveal = async (ids: string[], reason?: string): Promise<boolean> => {
    try {
      const r = await api.records.reveal(ids, reason);
      const m: Record<string, string | null> = {};
      for (const it of r.items) m[it.record_id] = it.contact;
      setRevealMap(m); setRevealAt(r.revealed_at); setRevealCount(ids.length); setRevealErr(null);
      return true;
    } catch (e) {
      setRevealMap({}); setRevealOn(false); setRevealErr(e as ApiError); revealedKey.current = null;
      return false;
    }
  };
  useEffect(() => {
    if (!revealOn || activeIds.length === 0 || revealedKey.current === idsKey) return;
    revealedKey.current = idsKey;
    setRevealMap({});
    void doReveal(activeIds, undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revealOn, idsKey]);
  const turnOff = () => { setRevealOn(false); setRevealMap({}); setRevealAt(null); revealedKey.current = null; };
  // leaving the page, or the browser putting it into its back-forward cache, must not keep full contact points in memory
  useEffect(() => {
    const clear = () => { setRevealOn(false); setRevealMap({}); setRevealAt(null); revealedKey.current = null; };
    window.addEventListener('pagehide', clear);
    return () => window.removeEventListener('pagehide', clear);
  }, []);
  const toggleReveal = () => {
    if (revealOn) { turnOff(); return; }
    setRevealErr(null);
    if (!revealAcked) { setAskReveal(true); return; }
    setRevealOn(true);
  };

  const [exporting, setExporting] = useState(false);
  const [started, setStarted] = useState<{ id: string; form: string } | null>(null);
  const [exportErr, setExportErr] = useState<ApiError | null>(null);
  const filterBar = useRef<HTMLFormElement>(null);
  const foundBanner = useRef<HTMLDivElement>(null);
  useEffect(() => { if (found) foundBanner.current?.focus(); }, [found]);

  const setFilter = (k: string, v: string) => {
    const next = new URLSearchParams();
    for (const [kk, vv] of Object.entries(filters)) if (kk !== k) next.set(kk, vv);
    if (v) next.set(k, v);
    setFound(null);
    navigate(`/records${next.toString() ? `?${next.toString()}` : ''}`, { replace: true });
  };
  const clearFilters = () => { setFound(null); navigate('/records', { replace: true }); };
  const hasFilters = Object.keys(filters).length > 0;

  const sourceOptions = useMemo(() => {
    const m = new Map<string, string>();
    if (sources.status === 'ok') for (const s of sources.data) m.set(s.source_id, s.name);
    else for (const r of rows) m.set(r.first_source.source_id, r.first_source.name);
    if (filters.source_id && !m.has(filters.source_id)) m.set(filters.source_id, filters.source_id);
    return [...m.entries()].map(([value, label]) => ({ value, label }));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sources.status, sources.data, idsKey, filters.source_id]);
  const sourceName = (id: string) => sourceOptions.find((o) => o.value === id)?.label ?? id;

  const filterText = () => {
    const parts: string[] = [];
    if (filters.channel) parts.push(`Channel: ${CHANNEL_WORD[filters.channel]}`);
    if (filters.status) parts.push(`Evidence status: ${STATUS_WORD[filters.status]}`);
    if (filters.purpose) parts.push(`Purpose: ${filters.purpose}`);
    if (filters.has_stop) parts.push(`Has a stop: ${filters.has_stop === 'true' ? 'Yes' : 'No'}`);
    if (filters.source_id) parts.push(`Source: ${sourceName(filters.source_id)}`);
    if (filters.from || filters.to) parts.push(`${filters.from ? fmtDate(filters.from) : 'Start'} to ${filters.to ? fmtDate(filters.to) : 'now'}`);
    if (filters.state && filters.state !== 'active') parts.push(`Showing: ${filters.state === 'erased' ? 'Erased' : 'All'}`);
    if (filters.trial && filters.trial !== 'include') parts.push(`Test events: ${filters.trial === 'only' ? 'Only' : 'Exclude'}`);
    return parts.length ? parts.join(' · ') : 'all records';
  };

  // total held when a filter matches nothing
  const [heldTotal, setHeldTotal] = useState<number | null | undefined>(undefined);
  const noMatch = list.status === 'ok' && list.data.items.length === 0 && hasFilters && !found;
  useEffect(() => {
    if (!noMatch) { setHeldTotal(undefined); return; }
    let live = true;
    api.records.summary({}).then((s) => { if (live) setHeldTotal(s.total); }, () => { if (live) setHeldTotal(null); });
    return () => { live = false; };
  }, [api, noMatch, filterKey]);

  const submitSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    const c = checkContact(query);
    setSearchErr(null); setBadEntry(null);
    if (!c.ok) { setBadEntry(c.shown); return; }
    const r = await search_.run(c.value);
    if (r.ok) { turnOff(); setFound({ shown: prettyContact(c.value), items: r.value.items }); setQuery(''); }
    else setSearchErr(r.error);
  };
  useEffect(() => () => { setQuery(''); setFound(null); }, []);

  const total = list.status === 'ok' ? list.data.total : null;
  const sum = summary.status === 'ok' ? summary.data : null;
  const partial = list.status === 'ok' ? list.data.partial ?? [] : [];
  const maskLost = partial.includes('contact_mask');
  const personLost = partial.includes('person');
  const retryAfterMin = revealErr?.retryAfter ? Math.max(1, Math.ceil(revealErr.retryAfter / 60)) : null;

  const contactCell = (r: ContactRecord) => {
    const f = r.contact.fp_hint;
    if (r.state === 'erased') return <><b>Erased</b><span className="cellsub">fingerprint {f}</span></>;
    if (isDev) return <><span className="mono">fingerprint {f}</span></>;
    const shown = revealMap[r.record_id];
    const text = shown ? prettyContact(shown) : r.contact.masked;
    const inner = text ?? <><NotAvailable /><span className="cellsub">encryption key did not answer</span></>;
    return (
      <>
        <a href={`/evidence?record=${encodeURIComponent(r.record_id)}`} onClick={(e) => { if (e.button === 0 && !e.metaKey && !e.ctrlKey) { e.preventDefault(); navigate(`/evidence?record=${encodeURIComponent(r.record_id)}`); } }}>{inner}</a>
        {r.linked_record_count > 0 && <span className="cellsub">{`${r.linked_record_count} other contact point from the same person`}</span>}
      </>
    );
  };
  const personCell = (r: ContactRecord, which: 'name' | 'company') => {
    if (r.state === 'erased') return 'Erased';
    if (personLost || !r.person) return <NotAvailable />;
    return r.person[which] ?? 'Not captured';
  };

  const columns = [
    { key: 'c', header: 'Contact', primary: true, render: contactCell },
    ...(showPerson ? [{ key: 'n', header: 'Name', render: (r: ContactRecord) => personCell(r, 'name') }, { key: 'co', header: 'Company', render: (r: ContactRecord) => personCell(r, 'company') }] : []),
    { key: 'f', header: 'First recorded', render: (r: ContactRecord) => <Time iso={r.first_recorded_at} /> },
    { key: 's', header: 'Source', render: (r: ContactRecord) => r.first_source.name },
    ...GROUPS.map((g) => ({ key: g.key, header: g.label, render: (r: ContactRecord) => <ChannelCell r={r} channels={g.channels} purpose={filters.purpose} /> })),
    { key: 'st', header: 'Stop', render: (r: ContactRecord) => (r.has_stop ? <>Yes{r.last_stop_at ? `, ${fmtDate(r.last_stop_at)}` : ''}</> : 'No') },
    { key: 'cf', header: 'Confirmation', render: (r: ContactRecord) => confirmationWord(r.confirmation) },
  ];

  const selOpts = (pairs: [string, string][]) => pairs.map(([value, label]) => ({ value, label }));
  const noRecordsYet = list.status === 'ok' && list.data.items.length === 0 && !hasFilters && !found && (total === 0 || total === null);

  return (
    <>
      <PageHead title="Records" lede={`Every phone number and email address ${orgName} holds, with the name and company when the form captured them, and what the records show for each channel. Open a row for its full timeline.`} />
      {isDev && <Banner kind="info" title="Your role sees fingerprints, not contact points, names or companies.">Counts, charts and statuses are the same as an admin sees. Rows do not open, because the evidence lookup shows personal data.</Banner>}
      <p className="sr-live" role="status" aria-live="polite">{list.status === 'ok' && total !== null ? `${fmtNum(total)} records` : ''}</p>

      {list.status === 'error' && list.error.code === 'audit_unavailable' && (
        <ErrorBlock title="The list was not shown" err={list.error} override="the audit log could not record this view" next="Try again. Records are never shown without an audit row. If this repeats, the service status page names the outage." actions={<Btn onClick={list.reload}>Try again</Btn>} />
      )}
      {list.status === 'error' && list.error.code !== 'audit_unavailable' && (
        <ErrorBlock title="The records list did not load" err={list.error} override={list.error.code === 'service_unavailable' ? 'the records database did not answer' : undefined} next="Try again. Capture keeps recording while this page is down." actions={<Btn onClick={list.reload}>Try again</Btn>} />
      )}
      {list.status === 'loading' && <Skeleton what="records" rows={4} variant="tiles" />}

      {noRecordsYet && (
        <StateBlock kind="empty" title={`No records yet in ${orgName}`} actions={canDo(role, 'source.write') ? <><LinkBtn href="/setup/first-event" variant="primary">Send a test event</LinkBtn><LinkBtn href="/sources">Open capture sources</LinkBtn></> : undefined}>
          {`Records appear here when a capture source sends its first event.${sources.status === 'ok' && sources.data && sources.data.length ? ` Your sources: ${sources.data.map((s) => s.name).join(', ')}.` : ''}`}
        </StateBlock>
      )}

      {list.status === 'ok' && !noRecordsYet && (
        <>
          {maskLost && <Banner kind="warning" title="Contact points are not available right now." action={<Btn size="sm" onClick={list.reload}>Try again</Btn>}>
            {`Cause: your organization's encryption key did not answer (503 key_unavailable). Names, companies and contact points need the key. Evidence status and stops are shown, because they do not. Next: try again in a minute.`}</Banner>}
          {!maskLost && personLost && <Banner kind="warning" title="Names and companies are not available right now." action={<Btn size="sm" onClick={list.reload}>Try again</Btn>}>
            {`Cause: your organization's encryption key did not answer (503 key_unavailable). Contact points and statuses are shown.`}</Banner>}

          <div className="grid g4">
            <Tile label="Records held" value={summary.status === 'loading' ? '...' : sum && sum.total !== null ? <span className="num">{fmtNum(sum.total)}</span> : null} sub={sum && sum.total !== null ? 'One per phone number or email address' : summary.status === 'loading' ? 'Loading' : 'The count did not load'} />
            <Tile label="New in the last 30 days" value={summary.status === 'loading' ? '...' : sum && sum.new_in_range !== null ? <span className="num">{fmtNum(sum.new_in_range)}</span> : null}
              sub={sum && sum.new_per_day && sum.new_per_day.length ? `First recorded ${fmtDate(sum.new_per_day[0].date)} to ${fmtDate(sum.new_per_day[sum.new_per_day.length - 1].date)}` : sum ? 'The count did not load' : undefined} />
            <Tile label="With a stop on record" value={summary.status === 'loading' ? '...' : sum && sum.with_stop !== null ? <span className="num">{fmtNum(sum.with_stop)}</span> : null} sub={sum && sum.with_stop === null ? 'The count did not load' : undefined}
              href={sum && sum.with_stop ? '/records?has_stop=true' : undefined} action={sum && sum.with_stop ? 'Show only these' : undefined} />
          </div>
          {sum && <p className="hint mt4">As of <Time iso={sum.as_of} />.</p>}

          <div className="grid g2 mt5">
            <div className="card">
              <h2>New records per day, last 30 days</h2>
              {summary.status === 'loading' && <Skeleton what="the chart" rows={1} />}
              {(summary.status === 'error' || (sum && sum.new_per_day === null)) && (
                <Banner kind="warning" title="The chart did not load." action={<Btn size="sm" onClick={summary.reload}>Try the chart again</Btn>}>
                  {`Cause: the daily counts did not answer (${summary.status === 'error' ? `${summary.error.status} ${summary.error.code}` : '503 service_unavailable'}). The list below is current.`}</Banner>
              )}
              {sum && sum.new_per_day && sum.new_per_day.length > 0 && <BarChart series={sum.new_per_day} />}
            </div>
            <div className="card">
              <h2>Evidence status by channel, all records</h2>
              {summary.status === 'loading' && <Skeleton what="the channel shares" rows={1} />}
              {(summary.status === 'error' || (sum && sum.by_channel === null)) && <p className="na">{NA}</p>}
              {sum && sum.by_channel && <><ShareBars by={sum.by_channel} call={sum.call} />
                {filters.state === 'erased' && <p className="hint mt4">These records are erased. Each stop shown was written by the erasure request, on the channels it was recorded on.</p>}
                <p className="hint mt4">Each record counts once per channel, as the records show it. Where a stop and a consent are both recorded for a channel, the count shows the stop, as read under the rule-set in use. Whether a record is complete against your documentation checklist depends on the checklist, and shows on each contact's evidence lookup page, not here. A record is one phone number or one email address, so an email record reads No record for Text and Call, and a phone record reads No record for Email. A stop is recorded on the channel it arrived on. How far a stop reaches is set by the rule-set in use, which your counsel may replace. This portal does not name the rule-set yet; each contact's evidence lookup page lists the stop with the channel it arrived on.</p></>}
            </div>
          </div>

          <form className="card mt5" ref={filterBar} aria-label="Filters" onSubmit={(e) => e.preventDefault()}>
            <div className="filters">
              <SelectField label="Channel" name="channel" value={filters.channel ?? ''} onChange={(e) => setFilter('channel', e.target.value)} options={selOpts([['', 'Any'], ['email', 'Email'], ['sms', 'Text'], ['call', 'Call']])} />
              <SelectField label="Evidence status" name="status" value={filters.status ?? ''} onChange={(e) => setFilter('status', e.target.value)} options={selOpts([['', 'Any'], ['consent_record_found', 'Consent record found'], ['stop_on_record', 'Stop on record'], ['no_record', 'No record']])} />
              <SelectField label="Purpose" name="purpose" value={filters.purpose ?? ''} onChange={(e) => setFilter('purpose', e.target.value)} options={[{ value: '', label: 'Any' }, ...(purposes.status === 'ok' ? purposes.data.map((p) => ({ value: p.purpose, label: p.label })) : [])]} />
              <SelectField label="Source" name="source_id" value={filters.source_id ?? ''} onChange={(e) => setFilter('source_id', e.target.value)} options={[{ value: '', label: 'All sources' }, ...sourceOptions]} />
              <SelectField label="Has a stop" name="has_stop" value={filters.has_stop ?? ''} onChange={(e) => setFilter('has_stop', e.target.value)} options={selOpts([['', 'Either'], ['true', 'Yes'], ['false', 'No']])} />
              <SelectField label="Date" name="date_field" value={filters.date_field ?? ''} onChange={(e) => setFilter('date_field', e.target.value)} options={selOpts([['', 'First recorded'], ['last_event', 'Last event']])} />
              <TextField label="From" name="from" type="date" value={filters.from ?? ''} onChange={(e) => setFilter('from', e.target.value)} />
              <TextField label="To" name="to" type="date" value={filters.to ?? ''} onChange={(e) => setFilter('to', e.target.value)} />
              <SelectField label="Test events" name="trial" value={filters.trial ?? ''} onChange={(e) => setFilter('trial', e.target.value)} options={selOpts([['', 'Include'], ['exclude', 'Exclude'], ['only', 'Only']])} />
              <SelectField label="Showing" name="state" value={filters.state ?? ''} onChange={(e) => setFilter('state', e.target.value)} options={selOpts([['', 'Active records'], ['erased', 'Erased records'], ['all', 'All records']])} />
            </div>
            <div className="btn-row mt4"><Btn onClick={clearFilters} disabled={!hasFilters}>Clear filters</Btn></div>
          </form>

          <div className="tools">
            {canSearch && (
              <form className="inline-form" onSubmit={submitSearch} noValidate>
                <TextField label="Find one exact phone number or email" hint={RECORDS_SEARCH_HINT} name="contact-point" value={query} onChange={(e) => { setQuery(e.target.value); setBadEntry(null); }} autoComplete="off" spellCheck={false} autoCapitalize="off" autoCorrect="off" inputMode={/^[a-z@]/i.test(query.trim()) ? 'email' : 'tel'} />
                <Btn type="submit" variant="primary" busy={search_.busy} busyLabel="Finding">Find</Btn>
              </form>
            )}
            <div className="stack">
              {canReveal && (
                <div className="switch-row">
                  <button type="button" role="switch" aria-checked={revealOn} className="switch" aria-describedby="reveal-hint" onClick={toggleReveal}><i /><span className="lbl">Show full contact points</span></button>
                  <span className="hint" id="reveal-hint">Masked by default. Turning this on is recorded in the audit log with your name.</span>
                </div>
              )}
              {canExport && <Btn onClick={() => { setExportErr(null); setExporting(true); }} disabled={suspended}>Export this list</Btn>}
              {canExport && suspended && <p className="hint">{`Exports are paused until billing is resolved. You can read and search records.`}{role === 'admin' && <> <LinkBtn href="/billing" size="sm">Open billing</LinkBtn></>}</p>}
            </div>
          </div>

          {badEntry !== null && <ErrorBlock title="Not searched." err={new ApiError(422, 'invalid_contact', '', null)} override={`${badEntry ? `"${badEntry}" is` : 'That is'} not a complete phone number or email address`} next="Enter the whole number with area code, or the whole address. Nothing was looked up." />}
          {searchErr && <ErrorBlock title={searchErr.code === 'rate_limited' ? 'Search was not run.' : 'Not searched.'} err={searchErr} next={searchErr.code === 'rate_limited' ? `Try again in ${searchErr.retryAfter ? Math.max(1, Math.ceil(searchErr.retryAfter / 60)) : 'a few'} minutes.` : 'Check the entry and try again. Nothing was looked up.'} />}
          {revealErr && <ErrorBlock title="Full contact points were not shown." err={revealErr} override={revealErr.code === 'rate_limited' ? 'you reached 30 searches and reveals in 10 minutes' : undefined}
            next={`${revealErr.code === 'rate_limited' ? `Try again in ${retryAfterMin ?? 'a few'} minutes. ` : 'Try again. '}Masked contact points stay on this page; nothing was revealed or recorded as revealed.`} />}
          {revealOn && revealAt && (
            <Banner kind="success" title="Full contact points are showing." action={<Btn size="sm" onClick={turnOff}>Hide contact points</Btn>}>{`This page was recorded in the audit log at ${fmtTime(revealAt)} (${fmtNum(revealCount)} records).`}</Banner>
          )}
          {exportErr && (exportErr.code === 'export_too_large'
            ? <ErrorBlock title="The file was not built" err={exportErr} override={`the list has ${fmtNum(Number(exportErr.fields.count ?? 0))} records, over the ${fmtNum(Number(exportErr.fields.max ?? 0))} a single file can hold`} next="Narrow the date range or source, then export again. Nothing was built." actions={<Btn onClick={() => { setExportErr(null); document.querySelector<HTMLElement>('form[aria-label="Filters"] select')?.focus(); }}>Change filters</Btn>} />
            : <ErrorBlock title="The file was not built" err={exportErr} next="Try again. Nothing was built." actions={<Btn onClick={() => { setExportErr(null); setExporting(true); }}>Export again</Btn>} />)}
          {started && <ExportStatus key={started.id} id={started.id} form={started.form} onAgain={() => { setStarted(null); setExporting(true); }} onChangeFilters={() => setStarted(null)} />}

          {found && (
            <div ref={foundBanner} tabIndex={-1} aria-label="Search result"><Banner kind="info" title={found.items.length > 0 ? `${found.items.length} record${found.items.length === 1 ? '' : 's'} for ${found.shown}.` : `No record for ${found.shown} in ${orgName}`}
              action={<Btn size="sm" onClick={() => { setFound(null); turnOff(); }}>Back to the full list</Btn>}>
              {found.items.length > 0 ? 'Exact match on the whole phone number or email address.' : 'Search matches the whole phone number or email address only. Check the number, or open the full list.'}
            </Banner></div>
          )}

          {rows.length === 0 && noMatch && (
            <StateBlock kind="empty" title="No records match these filters" actions={<Btn onClick={clearFilters}>Clear filters</Btn>}>
              {`${filterText()}. Total records held: ${heldTotal === undefined ? '' : heldTotal === null ? NA : fmtNum(heldTotal)}.`}
            </StateBlock>
          )}
          {rows.length > 0 && (
            <>
              <DataTable caption="Records, newest event first. Status chips show the evidence status as recorded." rows={rows} rowKey={(r) => r.record_id} columns={columns} />
              {!found && (
                <div className="between mt4">
                  <p className="hint">{total === null ? `Showing ${pageIdx * PAGE + 1} to ${pageIdx * PAGE + rows.length}. Total not available.` : `Showing ${pageIdx * PAGE + 1} to ${pageIdx * PAGE + rows.length} of ${fmtNum(total)}`}</p>
                  <Pager prev={pageIdx > 0} next={!!(list.status === 'ok' && list.data.next_cursor)} onPrev={() => setPageIdx((i) => Math.max(0, i - 1))}
                    onNext={() => { if (list.status !== 'ok' || !list.data.next_cursor) return; const nc = list.data.next_cursor; setCursors((c) => [...c.slice(0, pageIdx + 1), nc]); setPageIdx((i) => i + 1); }} />
                </div>
              )}
              {rows.some((r) => r.state === 'erased') && <p className="hint mt4">Erased (stop kept): the contact point, name and company can no longer be read. The stop was written by the erasure request and is kept, with the channels it was recorded on. How far it reaches is set by the rule-set in use. Shown only with the filter Erased or All.</p>}
              <p className="notice mt4">{RECORDS_NOTICE}</p>
            </>
          )}
          {canExport && <PastExports key={started ? started.id : 'none'} />}
        </>
      )}

      {askReveal && (
        <ConfirmDialog title="Show full contact points?" confirmLabel="Show full contact points" busyLabel="Showing" reasonLabel="Reason (optional, never a contact point)"
          body={<p>{`Full phone numbers and email addresses will show for the rows on each page you open until you turn this off or sign out. ${REVEAL_DIALOG}`}</p>}
          failTitle="Full contact points were not shown." failNext="Try again."
          onClose={() => setAskReveal(false)}
          onConfirm={async (reason) => {
            revealAcked = true; reasonRef.current = reason || undefined;
            revealedKey.current = idsKey;
            const ok = await doReveal(activeIds, reason || undefined);
            if (ok) setRevealOn(true);
            return null;
          }} />
      )}
      {exporting && <ExportDialog total={total} filterText={filterText()} filters={toApi(filters)} onClose={() => setExporting(false)} onStarted={(id, form) => { setExporting(false); setStarted({ id, form }); }} onError={(e) => { setExporting(false); setExportErr(e); }} />}
    </>
  );
}

void Icon; void KV; void cx; void causeLine;
