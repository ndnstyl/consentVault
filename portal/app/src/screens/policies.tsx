import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, allPages } from '../lib/api/client.ts';
import type { Attestation, Channel, ChecklistDetail, ChecklistElement, ChecklistItem, EvidenceStatusKey, PolicyDetail, PolicyItem, PolicyRules, Purpose } from '../lib/api/types.ts';
import { ATTESTATION_TEMPLATE, CHANNEL_FALLBACK, NA, fillOrg } from '../lib/copy.ts';
import { useAction, useResource } from '../lib/hooks.ts';
import { Link, useRouter } from '../lib/router.tsx';
import { canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import type { Embedded } from '../components/ui.tsx';
import { Banner, Btn, Check, Chip, DataTable, ErrorBlock, Icon, KV, LinkBtn, NotAvailable, PageHead, PolicyChip, Skeleton, StateBlock, SuccessBanner, Tabs, TextField, Time } from '../components/ui.tsx';

const STATUSES: { key: EvidenceStatusKey; label: string }[] = [
  { key: 'consent_record_found', label: 'Consent record found' },
  { key: 'stop_on_record', label: 'Stop on record' },
  { key: 'no_record', label: 'No record' },
  { key: 'record_incomplete', label: 'Record incomplete' },
  { key: 'unavailable', label: 'Records not available' },
];

function PolicyStatus({ p }: { p: PolicyItem }) {
  if (p.status === 'approved') return <Chip tone="st-success" icon="i-ok">In force</Chip>;
  if (p.status === 'draft') return <Chip tone="st-info" icon="i-info">Draft</Chip>;
  return <Chip tone="st-neutral" icon="i-dash">Retired</Chip>;
}

function makeBlank(channels: string[], purposes: string[]): PolicyRules {
  return { schema_version: 1, purposes: Object.fromEntries(purposes.map((p) => [p, { checklist_version: null, cells: STATUSES.flatMap((s) => channels.map((ch) => ({ evidence_status: s.key, channel: ch, action: 'hold' as const }))) }])) };
}

/** The matrix: rows are evidence statuses, columns are channels, each cell proceed or hold. */
const CH_ORDER = ['sms', 'voice', 'artificial_voice', 'email'];
const orderChannels = (cs: Channel[]) => [...cs].sort((a, b) => (CH_ORDER.indexOf(a.channel) + 1 || 99) - (CH_ORDER.indexOf(b.channel) + 1 || 99));

function PolicyMatrix({ rules, channels: rawChannels, purposes, editable, onChange, checklistLabel }: { rules: PolicyRules; channels: Channel[]; purposes: Purpose[]; editable: boolean; onChange?: (r: PolicyRules) => void; checklistLabel: (v: number | null) => string }) {
  const channels = orderChannels(rawChannels);
  const keys = Object.keys(rules.purposes);
  const [tab, setTab] = useState(keys[0]);
  const cur = rules.purposes[tab] ?? rules.purposes[keys[0]];
  const purposeLabel = (k: string) => purposes.find((p) => p.purpose === k)?.label ?? k;
  const chLabel = (c: string) => channels.find((x) => x.channel === c)?.label ?? CHANNEL_FALLBACK[c] ?? c;
  const set = (st: EvidenceStatusKey, ch: string, action: 'proceed' | 'hold') => {
    const next: PolicyRules = JSON.parse(JSON.stringify(rules));
    const cell = next.purposes[tab].cells.find((c) => c.evidence_status === st && c.channel === ch);
    if (cell) cell.action = action; else next.purposes[tab].cells.push({ evidence_status: st, channel: ch, action });
    onChange?.(next);
  };
  const cell = (st: EvidenceStatusKey, ch: string) => cur.cells.find((c) => c.evidence_status === st && c.channel === ch)?.action ?? null;
  return (
    <div>
      {keys.length > 1 && <Tabs label="Purpose" current={tab} onSelect={setTab} tabs={keys.map((k) => ({ id: k, label: purposeLabel(k) }))} />}
      {keys.length === 1 && <p className="hint">{`Purpose: ${purposeLabel(keys[0])}`}</p>}
      <div className="tw matrix-scroll"><div className="tscroll" role="region" aria-label={`Policy matrix, ${purposeLabel(tab)}`} tabIndex={0}>
        <table className="matrix">
          <caption className="sr">When the records show</caption>
          <thead><tr><th scope="col">When the records show</th>{channels.map((c) => <th key={c.channel} scope="col">{c.label}</th>)}</tr></thead>
          <tbody>
            {STATUSES.map((s) => (
              <tr key={s.key}>
                <th scope="row">{s.key === 'record_incomplete' ? `Record incomplete (${checklistLabel(cur.checklist_version)})` : s.label}</th>
                {channels.map((c) => {
                  const v = cell(s.key, c.channel);
                  const locked = s.key === 'stop_on_record';
                  const name = `${s.label}, ${chLabel(c.channel)}`;
                  return (
                    <td key={c.channel} className={locked ? 'lock' : undefined}>
                      {editable && !locked
                        ? <select className="select sel-sm" aria-label={name} value={v ?? 'hold'} onChange={(e) => set(s.key, c.channel, e.target.value as 'proceed' | 'hold')}><option value="proceed">Proceed</option><option value="hold">Hold</option></select>
                        : <span><PolicyChip action={v} version={0} />{locked && <span className="sr">{` ${name}: a stop on record always holds`}</span>}</span>}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div></div>
    </div>
  );
}

function useRefs() {
  const { api } = useSession();
  return useResource(async () => {
    const [channels, purposes, checklists] = await Promise.all([
      allPages((c) => api.channels({ cursor: c })), allPages((c) => api.purposes({ cursor: c })), allPages((c) => api.checklists.list({ cursor: c, status: 'approved' })),
    ]);
    return { channels, purposes, checklists };
  }, [api]);
}

// ---------- 11 Policies list ----------
export function Policies() {
  const { api, role } = useSession();
  const res = useResource(() => allPages((c) => api.policies.list({ cursor: c })), [api]);
  const write = canDo(role, 'policy.write');
  const rows = res.status === 'ok' ? res.data : [];
  const inForce = rows.some((p) => p.status === 'approved');
  const partial = rows.some((p) => p.status !== 'draft' && p.approved_by === null);
  const draft = write ? <LinkBtn href="/policies/new" variant="primary">{rows.length ? 'Draft a new version' : 'Draft a policy'}</LinkBtn> : null;
  return (
    <>
      <PageHead title="Policies" lede="Gate checks return evidence status always, and your policy's action only when a policy is in force." actions={rows.length > 0 ? draft : null} />
      {res.status === 'loading' && <Skeleton what="policies" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="Policies did not load" err={res.error} next="Try again. The policy in force keeps applying while this page is down." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {res.status === 'ok' && rows.length === 0 && (
        <StateBlock kind="empty" title="No policy in force" actions={draft}>Without one, gate checks return evidence status only, with no action, and gate check credentials cannot be issued. {write ? 'Start from a template and change it to fit your rules.' : 'An admin drafts and approves the policy.'}</StateBlock>
      )}
      {rows.length > 0 && (
        <>
          {!inForce && <Banner kind="info" title="No policy in force">Gate checks return evidence status only until an admin approves a policy.</Banner>}
          {partial && <Banner kind="warning" title="Approver names did not load">Versions and statuses are current.</Banner>}
          <DataTable caption="Policy versions" rows={rows} rowKey={(p) => String(p.version)}
            columns={[
              { key: 'v', header: 'Version', render: (p) => <Link href={`/policies/${p.version}`}>{`Version ${p.version}`}</Link>, primary: true },
              { key: 's', header: 'Status', render: (p) => <PolicyStatus p={p} /> },
              { key: 'b', header: 'Approved by', render: (p) => (p.status === 'draft' ? <span className="hint">Not approved</span> : p.approved_by ?? <NotAvailable />) },
              { key: 'a', header: 'Approved', render: (p) => (p.approved_at ? <Time iso={p.approved_at} date /> : <span className="hint">Not approved</span>) },
            ]} />
        </>
      )}
    </>
  );
}

// ---------- 11 Policy: new draft, edit draft, read ----------
export function PolicyNew({ embedded }: { embedded?: Embedded } = {}) {
  const { api, role } = useSession();
  const { navigate } = useRouter();
  const refs = useRefs();
  const load = useResource(async () => {
    const [inForce, templates] = await Promise.all([
      api.policies.list({ status: 'approved' }).then(async (p) => (p.items[0] ? api.policies.get(p.items[0].version) : null)),
      allPages((c) => api.policies.templates({ cursor: c })),
    ]);
    return { inForce, templates };
  }, [api]);
  const [start, setStart] = useState('blank');
  const [rules, setRules] = useState<PolicyRules | null>(null);
  const save = useAction((r: PolicyRules, tpl?: string, based?: number) => api.policies.create({ rules: r, ...(tpl ? { template_ref: tpl } : {}), ...(based ? { based_on_version: based } : {}) }));
  const ready = refs.status === 'ok' && load.status === 'ok';
  useEffect(() => {
    if (!ready) return;
    const chs = refs.data.channels.map((c) => c.channel); const prs = refs.data.purposes.map((p) => p.purpose);
    if (start === 'blank') setRules(makeBlank(chs, prs));
    else if (start === 'inforce' && load.data.inForce) setRules(JSON.parse(JSON.stringify(load.data.inForce.rules)));
    else { const t = load.data.templates.find((x) => x.template_ref === start); if (t) setRules(JSON.parse(JSON.stringify(t.rules))); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, start]);
  useEffect(() => { if (ready && load.data.inForce && start === 'blank') setStart('inforce'); // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready]);
  if (!canDo(role, 'policy.write')) return null;
  const err = refs.status === 'error' ? refs.error : load.status === 'error' ? load.error : null;
  const submit = async (approveNext: boolean) => {
    if (!rules) return;
    const r = await save.run(rules, ['blank', 'inforce'].includes(start) ? undefined : start, start === 'inforce' ? load.status === 'ok' ? load.data.inForce?.version : undefined : undefined);
    if (r.ok) {
      if (embedded && !approveNext) embedded.onDone(`Draft saved as version ${r.value.version}. The step is done once a policy is approved.`, `/policies/${r.value.version}/approve`);
      else navigate(approveNext ? `/policies/${r.value.version}/approve` : `/policies/${r.value.version}?saved=1`);
    }
  };
  return (
    <>
      {!embedded && <PageHead title="Draft a policy" lede="Your policy tells your systems what to do with each evidence status. ConsentVault applies it exactly as written. It does not decide whether a message is allowed by law." />}
      {(refs.status === 'loading' || load.status === 'loading') && <Skeleton what="the policy editor" variant="table" />}
      {err && <ErrorBlock title="The policy editor did not load" err={err} next="Try again." actions={<Btn onClick={() => { refs.reload(); load.reload(); }}>Try again</Btn>} />}
      {ready && rules && (
        <div className="card">
          {save.error && <ErrorBlock title="The draft was not saved" err={save.error} next="Fix the cell named and try again. Nothing was changed." headingLevel={3} />}
          <div className="field"><label htmlFor="start">Start from</label>
            <select id="start" className="select" value={start} onChange={(e) => setStart(e.target.value)}>
              {load.data.inForce && <option value="inforce">{`Version ${load.data.inForce.version} (in force)`}</option>}
              {load.data.templates.map((t) => <option key={t.template_ref} value={t.template_ref}>{t.label}</option>)}
              <option value="blank">Blank</option>
            </select></div>
          <PolicyMatrix rules={rules} channels={refs.data.channels} purposes={refs.data.purposes} editable onChange={setRules} checklistLabel={(v) => (v ? `checklist v${v}` : 'no checklist')} />
          <ChecklistPick rules={rules} setRules={setRules} checklists={refs.data.checklists} />
          <div className="actions">{!embedded && <LinkBtn href="/policies" variant="secondary">Cancel</LinkBtn>}<Btn onClick={() => submit(false)} busy={save.busy} busyLabel="Saving">Save draft</Btn><Btn variant="primary" onClick={() => submit(true)} disabled={save.busy}>Review and approve</Btn></div>
        </div>
      )}
    </>
  );
}

function ChecklistPick({ rules, setRules, checklists }: { rules: PolicyRules; setRules: (r: PolicyRules) => void; checklists: ChecklistItem[] }) {
  const key = Object.keys(rules.purposes)[0];
  const cur = rules.purposes[key]?.checklist_version ?? null;
  return (
    <div className="field mt5"><label htmlFor="cl">Documentation checklist used for &quot;Record incomplete&quot;</label>
      <select id="cl" className="select" value={cur === null ? '' : String(cur)} onChange={(e) => { const n: PolicyRules = JSON.parse(JSON.stringify(rules)); for (const k of Object.keys(n.purposes)) n.purposes[k].checklist_version = e.target.value ? Number(e.target.value) : null; setRules(n); }}>
        <option value="">None</option>
        {checklists.map((c) => <option key={c.version} value={c.version}>{`${c.label} version ${c.version}`}</option>)}
      </select></div>
  );
}

export function PolicyDetail({ version }: { version: string }) {
  const { api, role, orgName } = useSession();
  const { search, navigate } = useRouter();
  const refs = useRefs();
  const res = useResource(() => api.policies.get(version), [api, version]);
  const save = useAction((r: PolicyRules) => api.policies.replace(Number(version), r));
  const [rules, setRules] = useState<PolicyRules | null>(null);
  useEffect(() => { if (res.status === 'ok') setRules(JSON.parse(JSON.stringify(res.data.rules))); }, [res.status, res.data]);
  const write = canDo(role, 'policy.write');
  if (res.status === 'loading' || refs.status === 'loading') return <><PageHead title={`Policy version ${version}`} /><Skeleton what="this policy" variant="table" /></>;
  if (res.status === 'error') {
    return res.error.status === 404
      ? <><PageHead title="Policy" /><StateBlock kind="error" title={`That page does not exist in ${orgName}`} cause="The address may be mistyped, or the item belongs to another organization you are not working in." next="Go back to the policy list." actions={<LinkBtn href="/policies" variant="secondary">Policies</LinkBtn>} /></>
      : <><PageHead title="Policy" /><ErrorBlock title="This policy did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} /></>;
  }
  if (refs.status === 'error') return <><PageHead title={`Policy version ${version}`} /><ErrorBlock title="The policy editor did not load" err={refs.error} next="Try again." actions={<Btn onClick={refs.reload}>Try again</Btn>} /></>;
  const p = res.data;
  const editable = write && p.status === 'draft';
  const clLabel = (v: number | null) => (v ? `checklist v${v}` : 'no checklist');
  const shown = editable ? rules ?? p.rules : p.rules;
  const lede = p.status === 'approved' ? <>In force since <Time iso={p.approved_at} date />. Approved by {p.approved_by ?? NA}.</> : p.status === 'retired' ? <>Retired <Time iso={p.retired_at} date />{p.retired_by_version ? `, replaced by version ${p.retired_by_version}` : ''}. It stays on record.</> : 'Draft. It does nothing until an admin approves it.';
  return (
    <>
      <PageHead title={`${p.status === 'draft' ? 'Draft policy' : 'Policy'} version ${p.version}`} lede={lede} meta={<PolicyStatus p={p} />} />
      {search.get('approved') && <SuccessBanner action={canDo(role, 'credential.issue.gate_read') ? <LinkBtn href="/credentials/new" size="sm" variant="secondary">Issue a gate check credential</LinkBtn> : undefined}>{`Policy version ${p.version} is in force. Approved by ${p.approved_by ?? NA}${p.approved_at ? ` at ${new Date(p.approved_at).toLocaleTimeString('en-US', { timeStyle: 'short' })}` : ''}. The approval and attestation are recorded and cannot be changed. Gate check credentials can now be issued.`}</SuccessBanner>}
      {search.get('saved') && <SuccessBanner>Draft saved. Recorded in the audit log.</SuccessBanner>}
      {save.error && <ErrorBlock title="The draft was not saved" err={save.error} next="Fix the cell named and try again. Nothing was changed." />}
      <div className="card">
        <PolicyMatrix rules={shown} channels={refs.data.channels} purposes={refs.data.purposes} editable={editable} onChange={setRules} checklistLabel={clLabel} />
        {editable && rules && <ChecklistPick rules={rules} setRules={setRules} checklists={refs.data.checklists} />}
        {editable && (
          <div className="actions"><Btn onClick={async () => { if (rules) { const r = await save.run(rules); if (r.ok) res.refresh(); } }} busy={save.busy} busyLabel="Saving">Save draft</Btn>
            <Btn variant="primary" disabled={save.busy} onClick={async () => { if (rules) { const r = await save.run(rules); if (r.ok) navigate(`/policies/${p.version}/approve`); } }}>Review and approve</Btn></div>
        )}
      </div>
      {!write && <p className="hint mt4">Only an admin can draft or approve.</p>}
      <div className="btn-row mt5"><LinkBtn href="/policies" variant="quiet">Back to policies</LinkBtn></div>
    </>
  );
}

// ---------- 11 Approve ----------
export function PolicyApprove({ version }: { version: string }) {
  const { api, user, orgName } = useSession();
  const { navigate } = useRouter();
  const refs = useRefs();
  const res = useResource(async () => {
    const [policy, att, inForce] = await Promise.all([api.policies.get(version), api.policies.attestation(), api.policies.list({ status: 'approved' }).then((p) => p.items[0] ?? null)]);
    return { policy, att, inForce };
  }, [api, version]);
  const [ticked, setTicked] = useState(false);
  const approve = useAction((a: Attestation) => api.policies.approve(Number(version), a.version, a.sha256));
  if (res.status === 'loading' || refs.status === 'loading') return <><PageHead title={`Approve policy version ${version}`} /><Skeleton what="the approval page" /></>;
  if (res.status === 'error') return <><PageHead title={`Approve policy version ${version}`} /><ErrorBlock title="The approval page did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} /></>;
  if (refs.status === 'error') return <><PageHead title={`Approve policy version ${version}`} /><ErrorBlock title="The approval page did not load" err={refs.error} next="Try again." actions={<Btn onClick={refs.reload}>Try again</Btn>} /></>;
  const { policy, att, inForce } = res.data;
  const notDraft = policy.status !== 'draft';
  const err = approve.error;
  const newer = err?.code === 'policy_superseded' ? Number((err.fields as { newer_version?: number }).newer_version) : null;
  const go = async () => {
    const r = await approve.run(att);
    if (r.ok) navigate(`/policies/${policy.version}?approved=1`);
  };
  return (
    <>
      <PageHead title={`Approve policy version ${policy.version}`} />
      {notDraft && <Banner kind="warning" title={`Version ${policy.version} is ${policy.status === 'approved' ? 'already in force' : 'retired'}`}>Only a draft can be approved. <Link href={`/policies/${policy.version}`}>Open version {policy.version}</Link></Banner>}
      {err && err.code === 'policy_superseded' && <ErrorBlock title={`Version ${policy.version} was not approved`} err={err} override={`another admin approved version ${newer} while you were reviewing`} next={`Open version ${newer} and review it.`} actions={<LinkBtn href={`/policies/${newer}`} variant="secondary">{`Open version ${newer}`}</LinkBtn>} />}
      {err && err.code !== 'policy_superseded' && <ErrorBlock title={`Version ${policy.version} was not approved`} err={err} next={err.code === 'attestation_mismatch' ? 'Reload this page to read the current attestation, then approve again.' : 'Try again. Nothing was changed.'} />}
      <div className="card">
        <PolicyMatrix rules={policy.rules} channels={refs.data.channels} purposes={refs.data.purposes} editable={false} checklistLabel={(v) => (v ? `checklist v${v}` : 'no checklist')} />
        <h2 className="sec mt5">{`Attestation (version ${att.version})`}</h2>
        <div className="attest"><span className="ver">{`Attestation version ${att.version}`}</span><p>{fillOrg(att.text || ATTESTATION_TEMPLATE, orgName)}</p></div>
        <Check name="accept" label={`I accept this attestation for ${orgName}.`} checked={ticked} onChange={(e) => setTicked(e.target.checked)} disabled={notDraft} />
        <div className="mt4"><KV rows={[['Approving as', user ? `${user.display_name}, ${user.email} (from your sign-in)` : NA], ['On approval', inForce && inForce.version !== policy.version ? `Version ${policy.version} goes into force. Version ${inForce.version} is retired. Both stay on record.` : `Version ${policy.version} goes into force.`]]} /></div>
        <div className="actions"><LinkBtn href={`/policies/${policy.version}`} variant="secondary">Back to draft</LinkBtn><Btn variant="primary" disabled={!ticked || notDraft} busy={approve.busy} busyLabel="Approving" onClick={go}>{`Approve version ${policy.version}`}</Btn></div>
        {!ticked && !notDraft && <p className="hint" id="approve-reason">Approve turns on after the box is ticked.</p>}
      </div>
    </>
  );
}

// ---------- 12 Checklists ----------
export function Checklists() {
  const { api, role, orgName } = useSession();
  const { navigate } = useRouter();
  const res = useResource(async () => {
    const [items, inForce] = await Promise.all([
      allPages((c) => api.checklists.list({ cursor: c })),
      api.policies.list({ status: 'approved' }).then(async (p) => (p.items[0] ? api.policies.get(p.items[0].version) : null)).then((x) => ({ ok: true as const, v: x }), () => ({ ok: false as const, v: null })),
    ]);
    return { items, inForce };
  }, [api]);
  const write = canDo(role, 'checklist.write');
  const tpl = useAction(async () => {
    const t = (await api.checklists.templates()).items.find((x) => x.template_ref === 'pewc_example') ?? (await api.checklists.templates()).items[0];
    if (!t) throw new ApiError(404, 'not_found', '', null);
    return api.checklists.create({ kind: t.kind, label: t.label, elements: t.elements.map(({ element_id: _e, ...r }) => r) });
  });
  const again = useAction(async () => {
    const last = res.status === 'ok' ? res.data.items[0] : null;
    if (!last) throw new ApiError(404, 'not_found', '', null);
    const d = await api.checklists.get(last.version);
    return api.checklists.create({ kind: d.kind, label: d.label, elements: d.elements.map(({ element_id: _e, ...r }) => r) });
  });
  const d = res.status === 'ok' ? res.data : null;
  const usedBy = (v: number): number | null => { const p = d?.inForce.v; if (!p) return null; return Object.values(p.rules.purposes).some((x) => x.checklist_version === v) ? p.version : null; };
  const start = async (fn: typeof tpl) => { const r = await fn.run(); if (r.ok) navigate(`/checklists/${(r.value as ChecklistDetail).version}`); };
  void orgName;
  return (
    <>
      <PageHead title="Documentation checklists" lede="A checklist reports which elements a record documents. It measures documentation completeness only, never legal sufficiency." actions={d && d.items.length > 0 && write ? <Btn variant="primary" busy={again.busy} busyLabel="Creating" onClick={() => start(again as never)}>New checklist version</Btn> : null} />
      {(tpl.error || again.error) && <ErrorBlock title="The checklist was not created" err={(tpl.error ?? again.error)!} next="Try again. Nothing was changed." />}
      {res.status === 'loading' && <Skeleton what="checklists" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="Checklists did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {d && d.items.length === 0 && (
        <StateBlock kind="empty" title="No checklists yet" actions={write ? <Btn variant="primary" busy={tpl.busy} busyLabel="Creating" onClick={() => start(tpl)}>Start from the PEWC example</Btn> : null}>
          {write ? 'Start from the PEWC example, which names the regulation, and change each element to match your forms.' : 'An admin defines the checklists.'}
        </StateBlock>
      )}
      {d && d.items.length > 0 && (
        <>
          {!d.inForce.ok && <Banner kind="warning" title="Which policy uses each checklist did not load">Checklists are listed in full.</Banner>}
          <DataTable caption="Checklist versions" rows={d.items} rowKey={(c) => String(c.version)}
            columns={[
              { key: 'l', header: 'Checklist', render: (c) => <Link href={`/checklists/${c.version}`}>{c.label}</Link>, primary: true },
              { key: 'v', header: 'Version', render: (c) => <span className="num">{c.version}</span> },
              { key: 'e', header: 'Elements', render: (c) => <span className="num">{c.element_count}</span> },
              { key: 'b', header: 'Approved by', render: (c) => (c.status === 'draft' ? <span className="hint">Not approved</span> : <>{c.approved_by ?? NA}{c.approved_at && <>, <Time iso={c.approved_at} date /></>}</>) },
              { key: 's', header: 'Status', render: (c) => { const u = usedBy(c.version); return c.status === 'draft' ? <Chip tone="st-info" icon="i-info">Draft</Chip> : u ? <Chip tone="st-success" icon="i-ok">{`In use by policy ${u}`}</Chip> : !d.inForce.ok ? <NotAvailable /> : <Chip tone="st-neutral" icon="i-dash">Approved</Chip>; } },
            ]} />
        </>
      )}
    </>
  );
}

export function ChecklistDetail({ version }: { version: string }) {
  const { api, role, orgName } = useSession();
  const { search } = useRouter();
  const res = useResource(async () => {
    const [c, refsList] = await Promise.all([api.checklists.get(version), api.ruleReferences().then((p) => p.items).catch(() => null)]);
    return { c, refsList };
  }, [api, version]);
  const [els, setEls] = useState<ChecklistElement[] | null>(null);
  const [ack, setAck] = useState(false);
  const [approved, setApproved] = useState(false);
  const save = useAction((e: ChecklistElement[]) => api.checklists.replace(Number(version), { elements: e.map(({ element_id: _i, ...r }) => r) }));
  const approve = useAction(() => api.checklists.approve(Number(version)));
  useEffect(() => { if (res.status === 'ok') setEls(res.data.c.elements.map((e) => ({ ...e }))); }, [res.status, res.data]);
  const lastAdded = useRef<HTMLInputElement>(null);
  if (res.status === 'loading') return <><PageHead title={`Documentation checklist version ${version}`} /><Skeleton what="this checklist" variant="table" /></>;
  if (res.status === 'error') {
    return res.error.status === 404
      ? <><PageHead title="Documentation checklist" /><StateBlock kind="error" title={`That page does not exist in ${orgName}`} cause="The address may be mistyped, or the item belongs to another organization you are not working in." next="Go back to the checklists." actions={<LinkBtn href="/checklists" variant="secondary">Documentation checklists</LinkBtn>} /></>
      : <><PageHead title="Documentation checklist" /><ErrorBlock title="This checklist did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} /></>;
  }
  const { c, refsList } = res.data;
  const editable = canDo(role, 'checklist.write') && c.status === 'draft' && !approved;
  const list = els ?? c.elements;
  const upd = (i: number, patch: Partial<ChecklistElement>) => setEls(list.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  const cite = (id: string | null) => (id === null ? null : refsList?.find((r) => r.ref_id === id)?.citation ?? id);
  return (
    <>
      <PageHead title={`${c.label}, version ${c.version}${c.status === 'draft' && !approved ? ' (draft)' : ''}`} lede="Documentation completeness only. It is not a legal test." />
      {(approved || search.get('approved')) && <SuccessBanner>{`Checklist version ${c.version} approved. New records are checked against it. To use it for holds, select it in your next policy version.`}</SuccessBanner>}
      {save.error && <ErrorBlock title="The checklist was not saved" err={save.error} next="Fix the field and try again. Nothing was changed." />}
      {approve.error && <ErrorBlock title="The checklist was not approved" err={approve.error} next="Try again. Nothing was changed." />}
      <div className="card">
        {!editable && (
          <DataTable caption="Checklist elements" rows={list} rowKey={(e) => e.element_id}
            columns={[{ key: 'n', header: 'Element', render: (e) => e.name, primary: true }, { key: 'd', header: 'Text to check for (your wording)', render: (e) => e.description }, { key: 'r', header: 'Regulation citation', render: (e) => cite(e.rule_reference_id) ?? <span className="hint">None</span> }, { key: 'q', header: 'Required', render: (e) => (e.required ? 'Yes' : 'No') }]} />
        )}
        {editable && (
          <>
            <ul className="elements">
              {list.map((e, i) => (
                <li key={e.element_id} className="el-row">
                  <TextField ref={i === list.length - 1 ? lastAdded : undefined} label="Element" name={`el-name-${i}`} value={e.name} onChange={(x) => upd(i, { name: x.target.value })} autoComplete="off" />
                  <TextField label="Text to check for (your wording)" name={`el-desc-${i}`} value={e.description} onChange={(x) => upd(i, { description: x.target.value })} autoComplete="off" />
                  <div className="field"><label htmlFor={`el-ref-${i}`}>Regulation citation</label>
                    <select id={`el-ref-${i}`} className="select" value={e.rule_reference_id ?? ''} onChange={(x) => upd(i, { rule_reference_id: x.target.value || null })}>
                      <option value="">None</option>
                      {(refsList ?? []).map((r) => <option key={r.ref_id} value={r.ref_id}>{`${r.jurisdiction}: ${r.citation}`}</option>)}
                    </select>
                    {refsList === null && <p className="hint">Citations did not load. Shown as {NA}.</p>}</div>
                  <Btn size="sm" variant="danger" aria-label={`Remove element ${e.name || i + 1}`} onClick={() => setEls(list.filter((_, j) => j !== i))}>Remove</Btn>
                </li>
              ))}
            </ul>
            <div className="btn-row"><Btn onClick={() => { setEls([...list, { element_id: `new_${list.length}_${Date.now()}`, name: '', description: '', required: true, rule_reference_id: null }]); window.setTimeout(() => lastAdded.current?.focus(), 30); }}>Add element</Btn></div>
            <div className="mt5"><Check name="ack" label={`I approve this checklist for ${orgName}. It reports documentation completeness and is not a legal test.`} checked={ack} onChange={(e) => setAck(e.target.checked)} /></div>
            <div className="actions"><Btn onClick={async () => { await save.run(list); }} busy={save.busy} busyLabel="Saving">Save draft</Btn>
              <Btn variant="primary" disabled={!ack || list.length === 0} busy={approve.busy} busyLabel="Approving" onClick={async () => { const s = await save.run(list); if (!s.ok) return; const r = await approve.run(); if (r.ok) { setApproved(true); res.refresh(); } }}>{`Approve version ${c.version}`}</Btn></div>
            {!ack && <p className="hint">Approve turns on after the box is ticked.</p>}
          </>
        )}
      </div>
      <div className="btn-row mt5"><LinkBtn href="/checklists" variant="quiet">Back to checklists</LinkBtn></div>
    </>
  );
}

void Icon; void useMemo;
