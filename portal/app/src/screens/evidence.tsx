import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, allPages } from '../lib/api/client.ts';
import type { ContactDelivery, ContactRecord, ExportDetail, ExportItem, Proof, ProofAnchor, ProofPermission, System } from '../lib/api/types.ts';
import { CHANNEL_FALLBACK, EVENT_LABEL, GATE_NOTICE, NA, PACKAGE_COVER, PUSH_STATE_LABEL, causeLine } from '../lib/copy.ts';
import { useAction, usePoll, useResource } from '../lib/hooks.ts';
import { Link, useRouter } from '../lib/router.tsx';
import { canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { checkContact, fmtDateTime, maskContact, prettyContact } from '../lib/format.ts';
import { eventOrigin, purposeWords } from '../lib/labels.ts';
import { useToast } from '../lib/toast.tsx';
import { ConfirmDialog } from '../components/Dialog.tsx';
import type { Col } from '../components/ui.tsx';
import { Banner, Btn, Chip, CopyButton, DataTable, DeliveryChip, ErrorBlock, EvidenceChip, Icon, KV, LinkBtn, NotAvailable, PageHead, SealChip, Skeleton, StateBlock, SuccessBanner, TextField, Time } from '../components/ui.tsx';

function ContactInput({ onSubmit, busy, label = 'Look up records', busyLabel = 'Looking up', error, hint }: { onSubmit: (contact: string) => void; busy: boolean; label?: string; busyLabel?: string; error?: React.ReactNode; hint?: string }) {
  const [v, setV] = useState('');
  const [bad, setBad] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const mode = /^[a-z@]/i.test(v.trim()) ? 'email' : 'tel';
  useEffect(() => () => setV(''), []);
  return (
    <form onSubmit={(e) => { e.preventDefault(); const c = checkContact(v); if (!c.ok) { setBad(c.shown); return; } setBad(null); onSubmit(c.value); }} noValidate className="inline-form">
      <TextField ref={input} label="Phone number or email" hint={hint ?? 'Sent in the request body, never in the page address. Cleared when you leave this page.'} name="contact-point" value={v} onChange={(e) => { setV(e.target.value); setBad(null); }} autoComplete="off" inputMode={mode} spellCheck={false} autoCapitalize="off" autoCorrect="off" error={bad !== null ? 'Enter 10 digits, or a full email address.' : null} />
      <Btn type="submit" variant="primary" busy={busy} busyLabel={busyLabel}>{label}</Btn>
      {error}
    </form>
  );
}

export interface WordingPairs { channels: string[]; purposes: string[] }
const CHANNELS_FOR: Record<'phone' | 'email', string[]> = { email: ['email'], phone: ['sms', 'voice', 'artificial_voice'] };
const NO_RECORD = new Set(['', 'no_record', 'no_record_found']);
/**
 * Only the rows that can mean something: pairs with any record first, then pairs a registered current wording offers
 * on a channel that fits the contact point. `hidden` counts the rest. With no wording list, nothing is hidden.
 */
export function relevantPermissions(all: ProofPermission[], kind: 'phone' | 'email' | undefined, wordings: WordingPairs[] | null | undefined): { shown: ProofPermission[]; hidden: number } {
  if (!wordings) return { shown: all, hidden: 0 };
  const fits = (c: string) => !kind || CHANNELS_FOR[kind].includes(c);
  const offered = (p: ProofPermission) => fits(p.channel) && wordings.some((w) => w.channels.includes(p.channel) && w.purposes.includes(p.purpose));
  const recorded = all.filter((p) => !NO_RECORD.has(statusOf(p)));
  const rest = all.filter((p) => NO_RECORD.has(statusOf(p)) && offered(p));
  const shown = [...recorded, ...rest];
  return { shown, hidden: all.length - shown.length };
}
export function PermissionsTable({ permissions, contactKind, wordings }: { permissions: ProofPermission[]; contactKind?: 'phone' | 'email'; wordings?: WordingPairs[] | null }) {
  const [all, setAll] = useState(false);
  const { shown, hidden } = useMemo(() => relevantPermissions(permissions, contactKind, wordings), [permissions, contactKind, wordings]);
  const rows = all ? permissions : shown;
  return (
    <>
      <DataTable caption="Evidence status by channel and purpose" rows={rows} rowKey={(p) => `${p.channel}:${p.purpose}`}
        columns={[
          { key: 'c', header: 'Channel', render: (p) => CHANNEL_FALLBACK[p.channel] ?? p.channel, primary: true },
          { key: 'p', header: 'Purpose', render: (p) => purposeWords(p.purpose) },
          { key: 'e', header: 'Evidence status', render: (p) => <EvidenceChip status={statusOf(p)} /> },
        ]} />
      {hidden > 0 && (
        <p className="hint">
          {all
            ? 'Showing every channel and purpose, including combinations with no wording and no record. '
            : `Showing the channels and purposes your wording covers. ${hidden} other combination${hidden === 1 ? ' has' : 's have'} no wording and no record. `}
          <Btn variant="quiet" size="sm" aria-pressed={all} onClick={() => setAll((v) => !v)}>{all ? 'Show fewer' : 'Show all'}</Btn>
        </p>
      )}
    </>
  );
}
/** The same per-channel statuses the Records page shows, as lookup rows. */
export function permissionsFromRecord(rec: Pick<ContactRecord, 'channels'>): ProofPermission[] {
  const order = ['sms', 'voice', 'artificial_voice', 'email'];
  const keys = [...order.filter((k) => rec.channels?.[k]), ...Object.keys(rec.channels ?? {}).filter((k) => !order.includes(k))];
  return keys.flatMap((k) => (rec.channels[k].purposes ?? []).map((p) => ({ channel: k, purpose: p.purpose, status: p.evidence_status, basis_event_ids: [] })));
}
export const statusOf = (p: ProofPermission): string => p.status || p.evidence_status || '';
export function chainLine(chain: NonNullable<Proof['chain']>): React.ReactNode {
  const last: ProofAnchor | undefined = chain.anchors[chain.anchors.length - 1];
  if (!last) return 'No outside anchor yet';
  const when = last.anchored_at ?? last.at;
  if (last.ok === false) return 'An anchor check failed. The operator has been told.';
  return <>{last.ok === true ? 'Verified to anchor ' : 'Last outside anchor '}{when ? <Time iso={when} /> : NA}</>;
}

function invalidContactText(c: string): string {
  const r = checkContact(c);
  return r.ok ? '' : `${r.shown || 'That entry'} is not a complete ${r.kind === 'phone' ? 'phone number' : 'email address'} (invalid_contact:${r.kind})`;
}

// ---------- 13 Evidence lookup ----------
interface Lists { systems: System[] | null; names: Map<string, string>; checklists: Map<number, Map<string, string>> }

export function EvidenceLookup() {
  const { api, role, orgName, status } = useSession();
  const { navigate, search } = useRouter();
  const toast = useToast();
  const recordId = search.get('record');
  const revealRecord = useAction((id: string) => api.records.reveal([id]));
  const [unreadable, setUnreadable] = useState<string | null>(null);
  const [contact, setContact] = useState<string | null>(null);
  const [proof, setProof] = useState<Proof | null>(null);
  const [lists, setLists] = useState<Lists>({ systems: null, names: new Map(), checklists: new Map() });
  const [erase, setErase] = useState(false);
  const [eraseDone, setEraseDone] = useState(false);
  const [more, setMore] = useState<string | null>(null);
  const [invalid, setInvalid] = useState<string | null>(null);
  const [recordRows, setRecordRows] = useState<ProofPermission[] | null>(null);
  const [wordings, setWordings] = useState<WordingPairs[] | null>(null);
  const [masked, setMasked] = useState<string | null>(null);
  const openedFor = useRef<string | null>(null);
  const lookup = useAction((c: string) => api.evidence.lookup(c));
  const build = useAction((c: string) => api.exports.create(c));
  const heading = useRef<HTMLHeadingElement>(null);
  const suspended = status === 'suspended';
  const run = async (c: string) => {
    setContact(c); setProof(null); setEraseDone(false); setInvalid(null); setRecordRows(null); setWordings(null);
    const r = await lookup.run(c);
    if (r.ok) {
      setProof(r.value);
      const names = new Map<string, string>();
      const checklists = new Map<number, Map<string, string>>();
      let systems: System[] | null = null;
      await Promise.all([
        api.records.search(c).then((x) => { const rec = x.items[0]; setRecordRows(rec ? permissionsFromRecord(rec) : null); }).catch(() => setRecordRows(null)),
        allPages((x) => api.disclosures.list({ cursor: x, state: 'current' })).then((w) => setWordings(w.map((d) => ({ channels: d.channels, purposes: d.purposes })))).catch(() => setWordings(null)),
        allPages((x) => api.brandNames({ cursor: x })).then((b) => b.forEach((y) => names.set(y.brand_id, y.display_name))).catch(() => undefined),
        allPages((x) => api.sourceNames({ cursor: x })).then((s) => s.forEach((y) => names.set(y.source_id, y.name))).catch(() => undefined),
        allPages((x) => api.systems.list({ cursor: x })).then((s) => { systems = s; }).catch(() => { systems = null; }),
        ...[...new Set((r.value.doc_check_results ?? []).map((d) => d.checklist_version))].map((v) => api.checklists.get(v).then((cl) => checklists.set(v, new Map(cl.elements.map((e) => [e.element_id, e.name])))).catch(() => undefined)),
      ]);
      setLists({ systems, names, checklists });
    }
  };
  useEffect(() => { if (proof) heading.current?.focus(); }, [proof]);
  const openRecord = async (id: string) => {
    const r = await revealRecord.run(id);
    const it = r.ok ? r.value.items[0] : null;
    if (it && it.contact) { setMasked(maskContact(it.contact)); await run(it.contact); }
    else if (it) setUnreadable(it.cause === 'erased' ? 'This record is erased. Its contact point can no longer be read, so there is nothing to look up. The stop written by the erasure request is kept.' : "Your organization's encryption key did not answer. Try again in a minute.");
  };
  useEffect(() => { if (recordId && openedFor.current !== recordId) { openedFor.current = recordId; void openRecord(recordId); } }, [recordId]);
  const loadMore = async (section: 'timeline' | 'gate_decisions', cursor: string | null) => {
    if (!contact || !cursor) return;
    setMore(section);
    try {
      const r = await api.evidence.lookup(contact, { section, cursor });
      setProof((p) => (p ? { ...p, [section]: { items: [...((p[section] as { items: unknown[] } | null)?.items ?? []), ...((r[section] as { items: unknown[] } | null)?.items ?? [])], next_cursor: (r[section] as { next_cursor: string | null } | null)?.next_cursor ?? null } } as Proof : p));
    } catch { /* the Load more button stays; the page keeps what it has */ }
    setMore(null);
  };
  const timeline = proof?.timeline?.items ?? [];
  const unsealed = timeline.filter((e) => !e.sealed);
  const review = proof?.reviews?.items.filter((r) => r.kind === 'contact_control_unverified') ?? [];
  const name = (id: string) => lists.names.get(id) ?? id;
  const wording = (sha: string | null) => (sha ? proof?.disclosures?.find((d) => d.sha256 === sha) : undefined);
  const chLabel = (c: string) => CHANNEL_FALLBACK[c] ?? c;
  const lookupErr = lookup.error;
  const shown = masked ?? (contact ? prettyContact(contact) : '');
  return (
    <>
      <PageHead title="Evidence lookup" lede={`Everything ${orgName}'s records hold for one phone number or email address.`} />
      {recordId && !proof && (
        <Banner kind="info" title="Opened from Records"
          action={revealRecord.error ? <Btn variant="primary" onClick={() => void openRecord(recordId)}>Try again</Btn> : undefined}>
          {revealRecord.busy || lookup.busy ? 'Loading this record.' : revealRecord.error || unreadable ? 'This record did not load.' : 'The contact point was read once to load this record and is shown masked. That read is recorded in the audit log with your name.'}
        </Banner>
      )}
      {unreadable && <Banner kind="warning" title="The contact point was not shown">{unreadable}</Banner>}
      {revealRecord.error && <ErrorBlock title="The contact point was not shown" err={revealRecord.error} next="Try again in a minute. Nothing was changed." />}
      <div className="card"><ContactInput onSubmit={run} busy={lookup.busy} /></div>
      {lookup.busy && <div className="mt5"><Skeleton what="records" rows={4} /></div>}
      {lookupErr && !lookup.busy && (
        <div className="mt5">{lookupErr.code === 'invalid_contact'
          ? <ErrorBlock title="Enter a phone number or email" err={lookupErr} override={contact ? invalidContactText(contact) || 'that is not a complete phone number or email address' : undefined} next="Enter 10 digits, or a full email address." actions={<Btn onClick={() => document.querySelector<HTMLInputElement>('input[name="contact-point"]')?.focus()}>Fix entry</Btn>} />
          : <ErrorBlock title="Records could not be read" err={lookupErr} override={lookupErr.code === 'key_unavailable' ? `Not available: ${'your organization\'s encryption key did not answer'}` : undefined} next="Try again in a minute. Nothing was changed. If it repeats, the operator has already been alerted by name." actions={<Btn onClick={() => contact && run(contact)}>Try again</Btn>} />}</div>
      )}
      {invalid && <p>{invalid}</p>}
      {proof && !proof.found && (
        <div className="mt5">
          <h2 ref={heading} tabIndex={-1} className="sec">{`No records for ${shown} in ${orgName}`}</h2>
          <p>{`${orgName} has recorded no consent, stop or contact check for this contact point. Check the number, or try the email address the person used.`}</p>
          <p className="notice">{proof.notice || GATE_NOTICE}</p>
        </div>
      )}
      {proof && proof.found && (
        <div className="mt5">
          <div className="between"><h2 ref={heading} tabIndex={-1} className="sec">{`Records for ${shown} in ${orgName}`}</h2>
            <div className="btn-row">
              <Btn variant="primary" disabled={suspended} busy={build.busy} busyLabel="Building" onClick={async () => { const r = await build.run(contact!); if (r.ok) navigate(`/exports/${r.value.export_id}`); }}>Build evidence package</Btn>
              {canDo(role, 'evidence.erase') && <Btn variant="danger" onClick={() => setErase(true)}>Request erasure</Btn>}
            </div></div>
          {suspended && <p className="hint mb4">{`Evidence packages are paused while ${orgName} is suspended. Resolve billing to build packages.`}</p>}
          {build.error && <ErrorBlock title="The package was not built" err={build.error} next="Try again. Nothing was changed." />}
          {eraseDone && <SuccessBanner>Erasure request sent. The operator confirms every erasure before it runs, and your records stay readable until then.</SuccessBanner>}
          <p className="hint">Chain integrity: {proof.chain ? chainLine(proof.chain) : NA}</p>
          {(proof.partial?.length ?? 0) > 0 && <Banner kind="warning" title="Some sections did not load">{`${proof.partial!.map((p) => p.replace(/_/g, ' ')).join(', ')} did not load. The sections below are complete.`}</Banner>}
          {unsealed.length > 0 && <Banner kind="warning" title="Seal pending">{`${unsealed.length} event${unsealed.length === 1 ? ' is' : 's are'} not sealed yet. Outside timestamps are usually added within an hour. Packages built now mark ${unsealed.length === 1 ? 'it' : 'them'} as unsealed.`}</Banner>}
          {review.length > 0 && <Banner kind="info" title="A later grant is recorded after a stop">{`A later grant was recorded after a stop on ${proof.permissions.find((p) => statusOf(p) === 'stop_on_record') ? chLabel(proof.permissions.find((p) => statusOf(p) === 'stop_on_record')!.channel) : 'a channel'}. The person's control of the contact point was not verified (contact_control_unverified), It is listed for review. Whether the grant changes how far the stop reaches is set by the rule-set in use.`}</Banner>}

          <h3 className="sec mt5">Evidence status now</h3>
          <PermissionsTable permissions={recordRows ?? proof.permissions} contactKind={contact ? checkContact(contact).kind : undefined} wordings={wordings} />
          <p className="notice">{proof.notice || GATE_NOTICE}</p>

          <h3 className="sec mt5">Timeline (arrival order)</h3>
          {proof.timeline === null ? <Banner kind="warning" title="Timeline did not load">Shown as Not available.</Banner> : timeline.length === 0 ? <p className="hint">No events on record.</p> : (
            <ol className="tl">
              {timeline.map((e) => {
                const w = wording(e.disclosure_sha256);
                const dc = proof.doc_check_results?.find((d) => d.event_id === e.event_id);
                const names = lists.checklists.get(dc?.checklist_version ?? -1);
                return (
                  <li key={e.event_id}>
                    <Icon name={e.event_type === 'grant' ? 'i-found' : 'i-stop'} />
                    <div className="hd"><b>{EVENT_LABEL[e.event_type] ?? e.event_type}</b><span className="when"><Time iso={e.at} /> · seq {e.seq}</span></div>
                    <div className="body">{e.channels.map(chLabel).join(', ')} · {e.purposes.map(purposeWords).join(', ')} · Brand {eventOrigin(e, name).brand} · Source {eventOrigin(e, name).source}{w && <> · Wording <Link href={`/wording/${w.sha256}`}>{w.version_label ?? w.label}</Link></>}</div>
                    <div className="gap-row"><SealChip sealedAt={e.sealed ? e.sealed_at : null} />{e.recorded_during_trial && <Chip tone="st-info" icon="i-info">Recorded during trial</Chip>}</div>
                    {dc && <div className="body">{`Checklist v${dc.checklist_version}: ${dc.present.length} of ${dc.present.length + dc.missing.length} present${dc.missing.length ? `, missing ${dc.missing.map((m) => `"${names?.get(m) ?? m}"`).join(', ')}` : ''}. Documentation completeness, not a legal test.`}</div>}
                  </li>
                );
              })}
            </ol>
          )}
          {proof.timeline?.next_cursor && <Btn size="sm" busy={more === 'timeline'} busyLabel="Loading" onClick={() => loadMore('timeline', proof.timeline!.next_cursor)}>Load more events</Btn>}

          <h3 className="sec mt5">Contact checks for this contact</h3>
          {proof.gate_decisions === null ? <Banner kind="warning" title="Contact checks did not load">Shown as Not available. The rest of this page is complete.</Banner> : proof.gate_decisions.items.length === 0 ? <p className="hint">No contact checks on record.</p> : (
            <DataTable caption="Contact checks" rows={proof.gate_decisions.items} rowKey={(g) => g.decision_id}
              columns={[
                { key: 't', header: 'Checked', render: (g) => <Time iso={g.at} />, primary: true },
                { key: 'c', header: 'Channel', render: (g) => chLabel(g.channel) },
                { key: 'e', header: 'Evidence status', render: (g) => <EvidenceChip status={g.evidence_status || g.status || ''} /> },
              ]} />
          )}
          {proof.gate_decisions?.next_cursor && <Btn size="sm" busy={more === 'gate_decisions'} busyLabel="Loading" onClick={() => loadMore('gate_decisions', proof.gate_decisions!.next_cursor)}>Load more contact checks</Btn>}

          <h3 className="sec mt5">Stops sent to your connected systems</h3>
          {lists.systems === null ? <p>Not available. <Btn size="sm" onClick={() => contact && run(contact)}>Try again</Btn></p> : lists.systems.length === 0 ? <p className="hint">No systems are connected.</p> : <Deliveries contact={contact!} systems={lists.systems} />}
        </div>
      )}
      {erase && contact && (
        <ConfirmDialog title={`Request erasure for ${shown}?`} destructive confirmLabel="Send erasure request" busyLabel="Sending" reasonLabel="Reason (recorded in the audit log)" reasonRequired
          body={<><p>What happens: this person&apos;s contact details become unreadable. Their fingerprint and stop records are kept, with the channels each stop was recorded on. How far a stop reaches is set by the rule-set in use. Your chain still verifies. This cannot be undone.</p><p>The operator confirms every erasure before it runs. A legal hold on this contact blocks it.</p></>}
          failTitle="The erasure was not requested" failNext="Nothing was queued."
          onClose={() => setErase(false)}
          onConfirm={async (reason) => { try { await api.erasure.request(contact, reason); setEraseDone(true); toast('Erasure request sent. Recorded in the audit log.'); return null; } catch (e) { return e as ApiError; } }} />
      )}
    </>
  );
}

function Deliveries({ contact, systems }: { contact: string; systems: System[] }) {
  const { api } = useSession();
  const res = useResource(async () => {
    const out: { sys: System; rows: ContactDelivery[] | null }[] = [];
    for (const s of systems) {
      try { out.push({ sys: s, rows: (await api.evidence.deliveriesFor(contact, s.system_id)).items }); } catch { out.push({ sys: s, rows: null }); }
    }
    return out;
  }, [api, contact, systems]);
  if (res.status === 'loading') return <Skeleton what="deliveries" rows={2} />;
  if (res.status === 'error') return <p>Not available. <Btn size="sm" onClick={res.reload}>Try again</Btn></p>;
  const failed = res.data.filter((r) => r.rows === null);
  const rows = res.data.flatMap((r) => (r.rows ?? []).map((d) => ({ ...d, system_name: d.system_name || r.sys.name })));
  return (
    <>
      {failed.length > 0 && <Banner kind="warning" title="Stops sent to connected systems did not load">{`${failed.map((f) => f.sys.name).join(', ')}: not available. Status, timeline and contact checks on this page are complete.`}</Banner>}
      {rows.length > 0 && (
        <DataTable caption="Stops sent to connected systems" rows={rows} rowKey={(r) => `${r.system_id}:${r.sent_at}`}
          columns={[
            { key: 's', header: 'System', render: (r) => r.system_name, primary: true },
            { key: 't', header: 'Sent', render: (r) => <Time iso={r.sent_at} /> },
            { key: 'st', header: 'State sent', render: (r) => PUSH_STATE_LABEL[r.state] ?? r.state },
            { key: 'r', header: 'Result', render: (r) => <span className="gap-row"><DeliveryChip status={r.status} />{r.acknowledged_at && <Time iso={r.acknowledged_at} />}</span> },
          ]}
          actions={(r) => (r.status === 'dead' ? <LinkBtn href={`/systems/${r.system_id}`} size="sm" variant="secondary">Redrive</LinkBtn> : null)} />
      )}
    </>
  );
}

// ---------- 14 Evidence packages ----------
function ExportStatus({ e }: { e: Pick<ExportItem, 'status' | 'downloaded_at'> }) {
  return e.status === 'ready' ? <Chip tone="st-success" icon="i-ok">Ready</Chip> : e.status === 'building' ? <Chip tone="st-info" icon="i-info">Building</Chip> : <Chip tone="st-danger" icon="i-err">Failed</Chip>;
}

export function Exports() {
  const { api, role, orgName, status } = useSession();
  const { navigate } = useRouter();
  const res = useResource(() => allPages((c) => api.exports.list({ cursor: c })), [api]);
  const build = useAction((c: string) => api.exports.create(c));
  const suspended = status === 'suspended';
  const rows = res.status === 'ok' ? res.data : [];
  const doBuild = async (c: string) => { const r = await build.run(c); if (r.ok) navigate(`/exports/${r.value.export_id}`); };
  const buildErr = build.error;
  return (
    <>
      <PageHead title="Evidence packages" lede={<>{`A package holds one person's records in ${orgName}, signed and checkable offline. `}{PACKAGE_COVER}</>} />
      {suspended && <Banner kind="danger" role="status" action={canDo(role, 'billing.manage') ? <LinkBtn href="/billing" size="sm" variant="secondary">Open billing</LinkBtn> : undefined}>{`Evidence packages are paused while ${orgName} is suspended. Your records are kept and capture keeps recording. Resolve billing to build packages.`}</Banner>}
      {buildErr && <ErrorBlock title="The package was not built" err={buildErr} override={buildErr.code === 'invalid_contact' ? 'that is not a complete phone number or email address' : undefined} next={buildErr.code === 'no_records' ? 'Check the number or email address, or start from Evidence lookup.' : 'Try again. Nothing was changed.'} />}
      <div className="card">
        {suspended ? <><p className="hint">{`Evidence packages are paused while ${orgName} is suspended.`}</p><Btn variant="primary" disabled>Build evidence package</Btn></>
          : <ContactInput onSubmit={doBuild} busy={build.busy} label="Build evidence package" busyLabel="Building" hint="Sent in the request body, never in the page address. Cleared when you leave this page." />}
      </div>
      <h2 className="sec mt5">Packages</h2>
      {res.status === 'loading' && <Skeleton what="packages" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="Packages did not load" err={res.error} onRetry={res.reload} next="Try again. Nothing was changed." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {res.status === 'ok' && rows.length === 0 && <StateBlock kind="empty" title="No packages built yet">Enter a contact point above, or start from Evidence lookup.</StateBlock>}
      {rows.length > 0 && (
        <DataTable caption="Evidence packages" rows={rows} rowKey={(r) => r.export_id}
          columns={EXPORT_COLUMNS}
          actions={(r) => <LinkBtn href={`/exports/${r.export_id}`} size="sm" variant="secondary">{r.status === 'ready' ? 'Open package' : 'Open'}</LinkBtn>} />
      )}
    </>
  );
}

export const EXPORT_COLUMNS: Col<ExportItem>[] = [
            { key: 'c', header: 'Contact', render: (r) => <span className="mono">{r.contact_fp_hint}</span>, primary: true },
            { key: 's', header: 'Started', render: (r) => <Time iso={r.created_at} /> },
            { key: 't', header: 'Status', render: (r) => <><ExportStatus e={r} />{r.status === 'building' && r.progress && <span className="hint">{` ${r.progress.done.toLocaleString('en-US')} of ${r.progress.total.toLocaleString('en-US')}`}</span>}</> },
            { key: 'x', header: 'Kept until', render: (r) => <>{r.expires_at ? <Time iso={r.expires_at} /> : <span className="hint">Not applicable</span>}{r.downloaded_at && <span className="hint">{' Downloaded '}<Time iso={r.downloaded_at} /></span>}</> },
];

export function PackageFacts({ d }: { d: ExportDetail }) {
  return (
    <KV rows={[
            ['Package sha256', d.sha256 ? <span key="s" className="gap-row"><code className="mono">{d.sha256}</code><CopyButton text={d.sha256} ariaLabel="Copy package sha256" /></span> : <NotAvailable key="s" />],
            ['Signed by', d.signature ? <span key="g">Platform key <code className="mono">{d.signature}</code></span> : <NotAvailable key="g" />],
            ['Package kept until', <Time key="e" iso={d.expires_at} />],
            ['Download link', 'Works once, for 15 minutes'],
          ]} />
  );
}

/** What the download area says: nothing yet, "started" after the first click, "used" only on a second attempt or a link that was already spent when the page opened. */
export function downloadNotice(clicks: number, spent: boolean): 'none' | 'started' | 'used' {
  if (clicks >= 2) return 'used';
  if (clicks === 1) return 'started';
  return spent ? 'used' : 'none';
}

export function DownloadPanel({ d, spent, clicks, linkUntil, suspended, linkBusy, onDownloadClick, onNewLink }: { d: ExportDetail; spent: boolean; clicks: number; linkUntil: string | null; suspended: boolean; linkBusy: boolean; onDownloadClick: () => void; onNewLink: () => void }) {
  const notice = downloadNotice(clicks, spent);
  const newLink = <Btn variant="secondary" disabled={suspended} busy={linkBusy} busyLabel="Getting link" onClick={onNewLink}>Get a new link</Btn>;
  return (
    <>
      {d.status === 'ready' && !spent && (
        <SuccessBanner title="Package ready" action={<a className="btn btn-primary" href={d.download_url ?? '#'} download onClick={onDownloadClick}>Download package</a>}>
          {linkUntil ? `This download link works once, until ${fmtDateTime(linkUntil)}.` : 'The download link works once and lasts 15 minutes.'}
        </SuccessBanner>
      )}
      {d.status === 'ready' && notice === 'started' && (
        <Banner kind="info" title="Download started" action={newLink}>Check your downloads folder. The link has now been used. If the file did not arrive, get a new link; the package itself is unchanged.</Banner>
      )}
      {d.status === 'ready' && notice === 'used' && (
        <StateBlock kind="error" title="This download link was used or expired" cause="Each link works once, for 15 minutes." next="Get a new link. The package itself is unchanged." actions={newLink} />
      )}
    </>
  );
}

export function ExportDetailScreen({ id }: { id: string }) {
  const { api, orgName, status, role } = useSession();
  const [detail, setDetail] = useState<ExportDetail | null>(null);
  const [fail, setFail] = useState<ApiError | null>(null);
  const poll = usePoll(() => api.exports.get(id), { intervalMs: 3000, deadlineMs: 30 * 60 * 1000, until: (d) => d.status !== 'building' });
  useEffect(() => { if (poll.value) setDetail(poll.value); }, [poll.value]);
  useEffect(() => { if (poll.error && !detail) setFail(poll.error); }, [poll.error, detail]);
  const link = useAction(() => api.exports.link(id));
  const resume = useAction(() => api.exports.resume(id));
  const suspended = status === 'suspended';
  const heading = useRef<HTMLHeadingElement>(null);
  const [clicks, setClicks] = useState(0);
  const [linkUntil, setLinkUntil] = useState<string | null>(null);
  void role;
  if (!detail && fail) {
    return fail.status === 404
      ? <><PageHead title="Evidence package" /><StateBlock kind="error" title={`That page does not exist in ${orgName}`} cause="The address may be mistyped, or the item belongs to another organization you are not working in." next="Go back to evidence packages." actions={<LinkBtn href="/exports" variant="secondary">Evidence packages</LinkBtn>} /></>
      : <><PageHead title="Evidence package" /><ErrorBlock title="This package did not load" err={fail} onRetry={() => { setFail(null); poll.restart(); }} next="Try again." actions={<Btn onClick={() => { setFail(null); poll.restart(); }}>Try again</Btn>} /></>;
  }
  if (!detail) return <><PageHead title="Evidence package" /><Skeleton what="this package" /></>;
  const d = detail;
  const spent = d.status === 'ready' && !d.download_url;
  const newUrl = link.error === null && link.busy === false ? null : null;
  void newUrl;
  const cause = d.failed_cause ? causeLine(0, d.failed_cause).replace(/ \(.*\)$/, '') : '';
  return (
    <>
      <PageHead title="Evidence package" lede={PACKAGE_COVER} meta={<ExportStatus e={d} />} />
      {suspended && <Banner kind="danger" role="status">{`Evidence packages are paused while ${orgName} is suspended. Your records are kept and capture keeps recording. Resolve billing to build packages.`}</Banner>}
      {d.status === 'building' && (
        <div role="status" aria-busy="true"><Banner kind="info" title="Building the package">
          {d.progress ? `Still building: ${d.progress.done.toLocaleString('en-US')} of ${d.progress.total.toLocaleString('en-US')} records packed. Large histories take longer. If the build stops, it resumes from where it stopped. A package is never cut short.` : 'Most finish in under 2 minutes. You can leave this page; it stays in the list.'}
        </Banner></div>
      )}
      {d.status === 'failed' && (
        <StateBlock kind="error" title="The package was not built" cause={`The build stopped while reading sealed records (export failed: ${d.failed_cause ?? 'unknown'}). No partial package was made.${cause ? '' : ''}`} next="Start the build again. It resumes from where it stopped."
          actions={<Btn variant="secondary" disabled={suspended} busy={resume.busy} busyLabel="Starting" onClick={async () => { const r = await resume.run(); if (r.ok) { setDetail({ ...d, status: 'building', failed_cause: null }); poll.restart(); } }}>Start again</Btn>} />
      )}
      {resume.error && <ErrorBlock title="The build did not start" err={resume.error} next="Try again." />}
      <DownloadPanel d={d} spent={spent} clicks={clicks} linkUntil={linkUntil} suspended={suspended} linkBusy={link.busy}
        onDownloadClick={() => { setClicks((c) => c + 1); window.setTimeout(() => poll.restart(), 1500); }}
        onNewLink={async () => { const r = await link.run(); if (r.ok) { setClicks(0); setLinkUntil(r.value.expires_at); setDetail({ ...d, download_url: r.value.download_url, downloaded_at: null }); } }} />
      {link.error && <ErrorBlock title="A new link could not be made" err={link.error} next="Try again." />}
      {poll.deadlinePassed && d.status === 'building' && <ErrorBlock title="The package is still building" err={new ApiError(0, 'timeout', '', null)} override="the build has taken longer than 30 minutes" next="Open the list to see its status later, or start the build again." actions={<LinkBtn href="/exports" variant="secondary">Evidence packages</LinkBtn>} />}
      {d.status === 'ready' && (
        <div className="card mt5"><h2 ref={heading}>How anyone can check this package</h2>
          <ol className="step-list">
            <li>Download the public verifier from the open-source ConsentVault repository.</li>
            <li>Run it on the package, offline, with the timestamp authority&apos;s root certificate and the published anchors.</li>
            <li>It names anything that fails. Change one byte and it fails by name.</li>
          </ol>
          <PackageFacts d={d} />
        </div>
      )}
      <div className="btn-row mt5"><LinkBtn href="/exports" variant="quiet">Back to evidence packages</LinkBtn></div>
    </>
  );
}

void useMemo; void maskContact;
