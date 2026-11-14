import React, { useEffect, useRef, useState } from 'react';
import { ApiError, allPages } from '../lib/api/client.ts';
import type { ChecklistDetail, ChecklistElement } from '../lib/api/types.ts';
import { NA } from '../lib/copy.ts';
import { useAction, useResource } from '../lib/hooks.ts';
import { Link, useRouter } from '../lib/router.tsx';
import { canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { Banner, Btn, Check, Chip, DataTable, ErrorBlock, LinkBtn, NotAvailable, PageHead, Skeleton, StateBlock, SuccessBanner, TextField, Time } from '../components/ui.tsx';

// ---------- 12 Checklists ----------
export function Checklists() {
  const { api, role, orgName } = useSession();
  const { navigate } = useRouter();
  const res = useResource(async () => ({ items: await allPages((c) => api.checklists.list({ cursor: c })) }), [api]);
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
  const start = async (fn: typeof tpl) => { const r = await fn.run(); if (r.ok) navigate(`/checklists/${(r.value as ChecklistDetail).version}`); };
  void orgName;
  return (
    <>
      <PageHead title="Documentation checklists" lede="A checklist reports which elements a record documents. It measures documentation completeness only, never legal sufficiency." actions={d && d.items.length > 0 && write ? <Btn variant="primary" busy={again.busy} busyLabel="Creating" onClick={() => start(again as never)}>New checklist version</Btn> : null} />
      {(tpl.error || again.error) && <ErrorBlock title="The checklist was not created" err={(tpl.error ?? again.error)!} next="Try again. Nothing was changed." />}
      {res.status === 'loading' && <Skeleton what="checklists" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="Checklists did not load" err={res.error} onRetry={res.reload} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {d && d.items.length === 0 && (
        <StateBlock kind="empty" title="No checklists yet" actions={write ? <Btn variant="primary" busy={tpl.busy} busyLabel="Creating" onClick={() => start(tpl)}>Start from the PEWC example</Btn> : null}>
          {write ? 'Start from the PEWC example, which names the regulation, and change each element to match your forms.' : 'An admin defines the checklists.'}
        </StateBlock>
      )}
      {d && d.items.length > 0 && (
        <>
          <DataTable caption="Checklist versions" rows={d.items} rowKey={(c) => String(c.version)}
            columns={[
              { key: 'l', header: 'Checklist', render: (c) => <Link href={`/checklists/${c.version}`}>{c.label}</Link>, primary: true },
              { key: 'v', header: 'Version', render: (c) => <span className="num">{c.version}</span> },
              { key: 'e', header: 'Elements', render: (c) => <span className="num">{c.element_count}</span> },
              { key: 'b', header: 'Approved by', render: (c) => (c.status === 'draft' ? <span className="hint">Not approved</span> : <>{c.approved_by ?? NA}{c.approved_at && <>, <Time iso={c.approved_at} date /></>}</>) },
              { key: 's', header: 'Status', render: (c) => (c.status === 'draft' ? <Chip tone="st-info" icon="i-info">Draft</Chip> : c.status === 'retired' ? <Chip tone="st-neutral" icon="i-dash">Retired</Chip> : <Chip tone="st-success" icon="i-ok">Approved</Chip>) },
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
      : <><PageHead title="Documentation checklist" /><ErrorBlock title="This checklist did not load" err={res.error} onRetry={res.reload} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} /></>;
  }
  const { c, refsList } = res.data;
  const editable = canDo(role, 'checklist.write') && c.status === 'draft' && !approved;
  const list = els ?? c.elements;
  const upd = (i: number, patch: Partial<ChecklistElement>) => setEls(list.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  const cite = (id: string | null) => (id === null ? null : refsList?.find((r) => r.ref_id === id)?.citation ?? id);
  return (
    <>
      <PageHead title={`${c.label}, version ${c.version}${c.status === 'draft' && !approved ? ' (draft)' : ''}`} lede="Documentation completeness only. It is not a legal test." />
      {(approved || search.get('approved')) && <SuccessBanner>{`Checklist version ${c.version} approved. New records are checked against it.`}</SuccessBanner>}
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

