import React, { useRef, useState } from 'react';
import type { FieldMapSettings, FieldMapVersion } from '../lib/api/types.ts';
import { rec } from '../lib/format.ts';
import { FIELD_MAP_COPY as C } from '../lib/copy.ts';
import { EMPTY_FORM, SINGLE_PATHS, fieldMapBody, fieldMapErrors } from '../lib/fieldmap.ts';
import type { FieldMapForm } from '../lib/fieldmap.ts';
import { useAction, useResource } from '../lib/hooks.ts';
import { canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { useToast } from '../lib/toast.tsx';
import { Dialog } from '../components/Dialog.tsx';
import { Btn, DataTable, ErrorBlock, ErrorSummary, KV, LinkBtn, PageHead, SelectField, Skeleton, StateBlock, SuccessBanner, TextArea, TextField, Time } from '../components/ui.tsx';

const FORMATS = [{ value: 'json', label: 'JSON' }, { value: 'form_urlencoded', label: 'Web form fields' }, { value: 'multipart', label: 'Multipart form' }, { value: 'text', label: 'Plain text' }];
const FORMAT_LABEL: Record<string, string> = Object.fromEntries(FORMATS.map((f) => [f.value, f.label]));
const SINGLE_LABEL: Record<(typeof SINGLE_PATHS)[number], string> = {
  decision_time_path: 'Decision time', wording_path: 'Wording', wording_hash_path: 'Wording hash', form_version_path: 'Form version', checkbox_default_path: 'Box default',
  submit_context_path: 'Submit context', third_party_cert_path: 'Third party certification', jurisdiction_path: 'Jurisdiction', channel_scope_path: 'Channel scope',
};
const none = <span className="hint">Not set</span>;

function Paths({ list }: { list: string[] | null }) {
  return list && list.length ? <>{list.map((p) => <div key={p}><code className="mono">{p}</code></div>)}</> : none;
}

function settingsRows(m: FieldMapSettings): [string, React.ReactNode][] {
  return [
    ['Form sends', FORMAT_LABEL[m.body_format] ?? m.body_format],
    ['Consent box', <Paths key="c" list={m.consent_paths} />],
    ['Ticked value', m.consent_ticked_value === null ? none : <code key="t" className="mono">{m.consent_ticked_value}</code>],
    ['Contact points', m.contact_paths.length ? <>{m.contact_paths.map((c) => <div key={c.path}><code className="mono">{c.path}</code> <span className="hint">{c.kind}</span></div>)}</> : none],
    ['Seller', <Paths key="s" list={m.seller_paths} />],
    ...SINGLE_PATHS.map((k): [string, React.ReactNode] => [SINGLE_LABEL[k], m[k] ? <code key={k} className="mono">{m[k]}</code> : none]),
  ];
}

function VersionForm({ onSubmit, busy, apiError, onCancel }: { onSubmit: (f: FieldMapForm) => void; busy: boolean; apiError: Parameters<typeof ErrorBlock>[0]['err'] | null; onCancel: () => void }) {
  const [f, setF] = useState<FieldMapForm>(EMPTY_FORM);
  const [touched, setTouched] = useState(false);
  const summary = useRef<HTMLDivElement>(null);
  const errs = fieldMapErrors(f);
  const set = (k: keyof FieldMapForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (errs.length) { setTouched(true); window.setTimeout(() => summary.current?.focus(), 0); return; }
    onSubmit(f);
  };
  const consentErr = touched ? errs.find((x) => x.id === 'consent_paths')?.message ?? null : null;
  const contactErr = touched ? errs.find((x) => x.id === 'contact_paths')?.message ?? null : null;
  return (
    <form onSubmit={submit} noValidate>
      {touched && <ErrorSummary errors={errs} headingRef={summary} />}
      {apiError && <ErrorBlock title="The version was not added" err={apiError} next="Fix the field and try again. Nothing was changed." headingLevel={3} />}
      <SelectField label="What the form sends" name="body_format" value={f.body_format} onChange={set('body_format')} options={FORMATS} />
      <TextArea label="Consent box" name="consent_paths" rows={2} hint={C.paths_hint} value={f.consent_paths} onChange={set('consent_paths')} autoComplete="off" spellCheck={false} error={consentErr} />
      <TextField label="Ticked value" name="consent_ticked_value" hint={C.ticked_hint} value={f.consent_ticked_value} onChange={set('consent_ticked_value')} autoComplete="off" spellCheck={false} />
      <TextArea label="Contact points" name="contact_paths" rows={2} hint={C.contact_hint} value={f.contact_paths} onChange={set('contact_paths')} autoComplete="off" spellCheck={false} error={contactErr} />
      <TextArea label="Seller" name="seller_paths" rows={2} hint="One path per line. Optional." value={f.seller_paths} onChange={set('seller_paths')} autoComplete="off" spellCheck={false} />
      {SINGLE_PATHS.map((k) => (
        <TextField key={k} label={SINGLE_LABEL[k]} name={k} hint="One path. Optional." value={f[k]} onChange={set(k)} autoComplete="off" spellCheck={false} />
      ))}
      <div className="actions"><Btn onClick={onCancel}>Cancel</Btn><Btn type="submit" variant="primary" busy={busy} busyLabel="Saving">{C.add}</Btn></div>
    </form>
  );
}

export function SourceFieldMaps({ id }: { id: string }) {
  const { api, role } = useSession();
  const toast = useToast();
  const res = useResource(async () => {
    const [source, maps] = await Promise.all([api.sources.get(id), api.sources.fieldMaps.list(id)]);
    return { source, maps };
  }, [api, id]);
  const write = canDo(role, 'fieldmap.add');
  const [dialog, setDialog] = useState(false);
  const [added, setAdded] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const add = useAction((f: FieldMapForm) => api.sources.fieldMaps.add(id, fieldMapBody(f)));
  if (res.status === 'loading') return <><PageHead title={C.title} /><Skeleton what="this field map" variant="table" /></>;
  if (res.status === 'error') return <><PageHead title={C.title} /><ErrorBlock title="The field map did not load" err={res.error} onRetry={res.reload} next="Go back to the capture source, or try again." actions={<><Btn onClick={res.reload}>Try again</Btn><LinkBtn href={`/sources/${id}`} variant="secondary">Capture source</LinkBtn></>} /></>;
  const { source, maps } = res.data;
  const canAdd = write && source.status === 'active';
  const addBtn = canAdd ? <Btn variant="primary" onClick={() => { add.clear(); setDialog(true); }}>{C.add}</Btn> : null;
  const shown: FieldMapVersion | undefined = maps.items.find((v) => v.map_version === open);
  return (
    <>
      <PageHead title={`${C.title}: ${source.name}`} lede={C.lede} actions={addBtn} />
      {added && <SuccessBanner>{C.saved}</SuccessBanner>}
      {source.status !== 'active' && <StateBlock kind="empty" title="This source is retired">{C.retired}</StateBlock>}
      {maps.items.length === 0 ? (
        <StateBlock kind="empty" title="No version added yet" actions={addBtn}>{C.empty}</StateBlock>
      ) : (
        <DataTable caption="Field map versions" rows={maps.items} rowKey={(v) => String(v.map_version)}
          columns={[
            { key: 'v', header: 'Version', render: (v) => <b className="num">{v.map_version}</b>, primary: true },
            { key: 'f', header: 'Form sends', render: (v) => FORMAT_LABEL[v.body_format] ?? v.body_format },
            { key: 'c', header: 'Consent box', render: (v) => <Paths list={v.consent_paths} /> },
            { key: 'w', header: 'Set by', render: (v) => rec(v.set_by) },
            { key: 'a', header: 'Set at', render: (v) => <Time iso={v.set_at} /> },
          ]}
          actions={(v) => <Btn size="sm" variant="quiet" onClick={() => setOpen(open === v.map_version ? null : v.map_version)}>{open === v.map_version ? 'Close' : 'Show all settings'}</Btn>} />
      )}
      {shown && <div className="card mt5"><h2>{`Version ${shown.map_version}`}</h2><KV rows={settingsRows(shown)} /></div>}
      <div className="card mt5"><h2>Built-in widget map</h2><p className="hint">{C.built_in}</p><KV rows={settingsRows(maps.built_in)} /></div>
      <div className="btn-row mt5"><LinkBtn href={`/sources/${id}`} variant="quiet">Back to the capture source</LinkBtn></div>
      {dialog && (
        <Dialog title={C.add} onClose={() => setDialog(false)} wide>
          <VersionForm busy={add.busy} apiError={add.error} onCancel={() => setDialog(false)}
            onSubmit={async (f) => { const r = await add.run(f); if (r.ok) { setDialog(false); setAdded(true); res.refresh(); toast(`Version ${r.value.map_version} added. Recorded in the audit log.`); } }} />
        </Dialog>
      )}
    </>
  );
}
