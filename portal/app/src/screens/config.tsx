import React, { useEffect, useRef, useState } from 'react';
import { ApiError, allPages } from '../lib/api/client.ts';
import type { Brand, Credential, CredentialIssued, CredentialKind, CredentialScope, Source } from '../lib/api/types.ts';
import { CRED_KIND_LABEL, CRED_SCOPE_LABEL, NA, SOURCE_KIND_LABEL, causeLine } from '../lib/copy.ts';
import { useAction, useDraft, useResource } from '../lib/hooks.ts';
import { Link, useRouter } from '../lib/router.tsx';
import { canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { useToast } from '../lib/toast.tsx';
import { Dialog, ConfirmDialog } from '../components/Dialog.tsx';
import type { Embedded } from '../components/ui.tsx';
import { Banner, Btn, Check, Chip, CopyButton, DataTable, ErrorBlock, ErrorSummary, Icon, KV, LinkBtn, NotAvailable, PageHead, Radio, SelectField, Skeleton, StateBlock, SuccessBanner, TextArea, TextField, Time } from '../components/ui.tsx';

// ---------- 07 Brands ----------
export function Brands() {
  const { api, role, orgName } = useSession();
  const res = useResource(() => allPages((c) => api.brands.list({ cursor: c })), [api]);
  const write = canDo(role, 'brand.create');
  const [dialog, setDialog] = useState(false);
  const [added, setAdded] = useState<string | null>(null);
  const create = useAction((name: string) => api.brands.create(name));
  const [draftName, setDraftName, clearDraftName] = useDraft('brand-new', { name: '' });
  const name = draftName.name;
  const setName = (v: string) => setDraftName({ name: v });
  const [touched, setTouched] = useState(false);
  const field = useRef<HTMLInputElement>(null);
  const addBtn = write ? <Btn variant="primary" onClick={() => { setDialog(true); setTouched(false); create.clear(); }}>Add a brand</Btn> : null;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) { setTouched(true); return; }
    const r = await create.run(name.trim());
    if (r.ok) { setDialog(false); clearDraftName(); setAdded(r.value.display_name); res.refresh(); }
    else field.current?.focus();
  };
  const rows = res.status === 'ok' ? res.data : [];
  const countsFailed = rows.some((b) => b.source_count === null);
  return (
    <>
      <PageHead title="Brands" lede="A brand is a business name your wording names as the seller." actions={rows.length > 0 ? addBtn : null} />
      {added && <SuccessBanner>{`${added} added. Add it to a capture source so events can name it.`}</SuccessBanner>}
      {res.status === 'loading' && <Skeleton what="brands" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="Brands did not load" err={res.error} onRetry={res.reload} next="Try again. Nothing was changed." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {res.status === 'ok' && rows.length === 0 && (
        <StateBlock kind="empty" title="No brands yet" actions={addBtn}>
          {write ? 'Add the business name your consent wording names as the seller. You need one before you add a capture source.' : 'An admin adds the business name your consent wording names as the seller.'}
        </StateBlock>
      )}
      {rows.length > 0 && (
        <>
          {countsFailed && <Banner kind="warning" title="Capture source counts did not load">Brand names below are current.</Banner>}
          <DataTable caption="Brands" rows={rows} rowKey={(b) => b.brand_id}
            columns={[
              { key: 'n', header: 'Brand', render: (b) => <b>{b.display_name}</b>, primary: true },
              { key: 'i', header: 'Id', render: (b) => <code className="mono">{b.brand_id}</code> },
              { key: 's', header: 'Capture sources', render: (b) => (b.source_count === null ? <NotAvailable /> : <span className="num">{b.source_count}</span>) },
              { key: 'a', header: 'Added', render: (b) => <Time iso={b.created_at} date /> },
            ]} />
        </>
      )}
      {dialog && (
        <Dialog title="Add a brand" onClose={() => setDialog(false)}>
          <form onSubmit={submit} noValidate>
            {create.error && <ErrorBlock title="The brand was not added" err={create.error}
              override={create.error.code === 'brand_exists' ? `a brand with this name already exists in ${orgName}` : undefined}
              next={create.error.code === 'brand_exists' ? 'Use the existing brand, or choose a different name.' : 'Try again. Nothing was changed.'}
              actions={<Btn size="sm" onClick={() => field.current?.focus()}>Edit name</Btn>} headingLevel={3} />}
            <TextField ref={field} label="Brand name" hint="The business name your wording names as the seller. Write it exactly as it appears on your forms." name="brand" value={name} onChange={(e) => setName(e.target.value)} required autoComplete="off" error={touched && !name.trim() ? 'Enter the brand name.' : null} />
            <div className="actions"><Btn onClick={() => setDialog(false)}>Cancel</Btn><Btn type="submit" variant="primary" busy={create.busy} busyLabel="Saving">Add brand</Btn></div>
          </form>
        </Dialog>
      )}
    </>
  );
}

// ---------- 08 Sources ----------
const ORIGIN_RE = /^https?:\/\/[^/\s?#]+$/;
export function originError(o: string): string | null {
  const t = o.trim();
  if (!t) return null;
  return ORIGIN_RE.test(t) ? null : `${t} is not an origin. An origin has no path.`;
}

interface SourceValues { name: string; kind: 'site_key' | 'server'; brand_ids: string[]; origins: string }
function SourceForm({ brands, initial, onSubmit, busy, submitLabel, busyLabel, apiError, onCancel, lockKind }: { brands: Brand[]; initial: SourceValues; onSubmit: (v: SourceValues) => void; busy: boolean; submitLabel: string; busyLabel: string; apiError: ApiError | null; onCancel: () => void; lockKind?: boolean }) {
  const [v, setV] = useState(initial);
  const [touched, setTouched] = useState(false);
  const summary = useRef<HTMLDivElement>(null);
  const lines = v.origins.split('\n').map((x) => x.trim()).filter(Boolean);
  const originErrs = v.kind === 'site_key' ? lines.map(originError).filter((x): x is string => !!x) : [];
  const errs: { id?: string; message: string }[] = [];
  if (!v.name.trim()) errs.push({ message: 'Enter a name.' });
  if (v.brand_ids.length === 0) errs.push({ message: 'Choose at least one brand.' });
  if (v.kind === 'site_key' && lines.length === 0) errs.push({ message: 'Enter at least one website origin.' });
  originErrs.forEach((m) => errs.push({ message: m }));
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (errs.length) { setTouched(true); window.setTimeout(() => summary.current?.focus(), 0); return; }
    onSubmit(v);
  };
  return (
    <form onSubmit={submit} noValidate>
      {touched && <ErrorSummary errors={errs} headingRef={summary} />}
      {apiError && <ErrorBlock title="The source was not added" err={apiError}
        override={apiError.code === 'invalid_origin' ? `${String((apiError.fields as { origin?: string }).origin ?? 'that address')} is not an origin. An origin has no path` : undefined}
        next={apiError.code === 'invalid_origin' ? 'Enter https://acme.com.' : 'Fix the field and try again. Nothing was changed.'} headingLevel={3} />}
      <TextField label="Name" name="source-name" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} required autoComplete="off" error={touched && !v.name.trim() ? 'Enter a name.' : null} />
      <fieldset>
        <legend>How it sends</legend>
        <Radio name="kind" label="Website form in a browser (site key)" checked={v.kind === 'site_key'} disabled={lockKind} onChange={() => setV({ ...v, kind: 'site_key' })} />
        <Radio name="kind" label="A server, CRM or integration (public key)" checked={v.kind === 'server'} disabled={lockKind} onChange={() => setV({ ...v, kind: 'server' })} />
      </fieldset>
      <fieldset>
        <legend>Brands it may name</legend>
        {brands.map((b) => (
          <Check key={b.brand_id} name={`brand-${b.brand_id}`} label={b.display_name} checked={v.brand_ids.includes(b.brand_id)}
            onChange={(e) => setV({ ...v, brand_ids: e.target.checked ? [...v.brand_ids, b.brand_id] : v.brand_ids.filter((x) => x !== b.brand_id) })} />
        ))}
      </fieldset>
      {v.kind === 'site_key' && (
        <TextArea label="Allowed website origins" name="origins" rows={3} hint="One per line, for example https://acme.com. Requests from other sites are refused." value={v.origins} onChange={(e) => setV({ ...v, origins: e.target.value })} placeholder="https://acme.com" autoComplete="off" spellCheck={false}
          error={originErrs.length ? `${originErrs[0]} Enter ${(lines.find((l) => originError(l)) ?? '').replace(/^(https?:\/\/[^/\s?#]+).*$/, '$1') || 'https://acme.com'}.` : null} />
      )}
      <div className="actions"><Btn onClick={onCancel}>Cancel</Btn><Btn type="submit" variant="primary" busy={busy} busyLabel={busyLabel}>{submitLabel}</Btn></div>
    </form>
  );
}

export function Sources() {
  const { api, role } = useSession();
  const toast = useToast();
  const res = useResource(async () => {
    const [sources, brands] = await Promise.all([allPages((c) => api.sources.list({ cursor: c })), allPages((c) => api.brands.list({ cursor: c }))]);
    return { sources, brands };
  }, [api]);
  const write = canDo(role, 'source.write');
  const [dialog, setDialog] = useState(false);
  const [added, setAdded] = useState<Source | null>(null);
  const create = useAction((b: Parameters<typeof api.sources.create>[0]) => api.sources.create(b));
  const d = res.status === 'ok' ? res.data : null;
  const brandName = (id: string) => d?.brands.find((b) => b.brand_id === id)?.display_name ?? id;
  const addBtn = write ? <Btn variant="primary" onClick={() => { create.clear(); setDialog(true); }}>Add a capture source</Btn> : null;
  const noBrand = !!d && d.brands.length === 0;
  const partial = !!d && d.sources.some((s) => s.partial?.includes('last_event'));
  return (
    <>
      <PageHead title="Capture sources" lede="Each website form, CRM or integration that sends consents, with the brands it may name." actions={d && d.sources.length > 0 && !noBrand ? addBtn : null} />
      {added && <SuccessBanner action={write ? <LinkBtn href={`/credentials/new?source=${added.source_id}`} size="sm" variant="secondary">{`Issue a credential for ${added.name}`}</LinkBtn> : undefined}>{`${added.name} added. Next: issue its credential.`}</SuccessBanner>}
      {res.status === 'loading' && <Skeleton what="capture sources" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="Capture sources did not load" err={res.error} onRetry={res.reload} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {d && noBrand && <StateBlock kind="empty" title="Add a brand first" actions={write ? <LinkBtn href="/brands" variant="primary">Add a brand</LinkBtn> : null}>Every capture source names at least one brand. Your organization has none yet.</StateBlock>}
      {d && !noBrand && d.sources.length === 0 && (
        <StateBlock kind="empty" title="No capture sources yet" actions={addBtn}>A capture source is a website form, CRM or integration that sends consents. Each one gets its own credential.</StateBlock>
      )}
      {d && d.sources.length > 0 && (
        <>
          {partial && <Banner kind="warning" title="Last event times did not load">Shown as Not available. Sources are listed in full.</Banner>}
          <DataTable caption="Capture sources" rows={d.sources} rowKey={(s) => s.source_id}
            columns={[
              { key: 'n', header: 'Source', render: (s) => <Link href={`/sources/${s.source_id}`}>{s.name}</Link>, primary: true },
              { key: 'k', header: 'Sends as', render: (s) => SOURCE_KIND_LABEL[s.kind] },
              { key: 'b', header: 'Brands', render: (s) => s.brand_ids.map(brandName).join(', ') },
              { key: 'o', header: 'Allowed origins', render: (s) => (s.allowed_origins.length ? s.allowed_origins.join(', ') : <span className="hint">None</span>) },
              { key: 'l', header: 'Last event', render: (s) => (s.partial?.includes('last_event') ? <NotAvailable /> : s.last_event_at ? <Time iso={s.last_event_at} /> : <span className="hint">No event yet</span>) },
            ]} />
        </>
      )}
      {dialog && d && (
        <Dialog title="Add a capture source" onClose={() => setDialog(false)} wide>
          <SourceForm brands={d.brands} initial={{ name: '', kind: 'site_key', brand_ids: [], origins: '' }} busy={create.busy} busyLabel="Saving" submitLabel="Add source" apiError={create.error} onCancel={() => setDialog(false)}
            onSubmit={async (v) => {
              const r = await create.run({ name: v.name.trim(), kind: v.kind, brand_ids: v.brand_ids, allowed_origins: v.kind === 'site_key' ? v.origins.split('\n').map((x) => x.trim()).filter(Boolean) : [] });
              if (r.ok) { setDialog(false); setAdded(r.value); res.refresh(); toast(`${r.value.name} added. Recorded in the audit log.`); }
            }} />
        </Dialog>
      )}
    </>
  );
}

export function SourceDetail({ id }: { id: string }) {
  const { api, role } = useSession();
  const toast = useToast();
  const res = useResource(async () => {
    const [source, brands] = await Promise.all([api.sources.get(id), allPages((c) => api.brands.list({ cursor: c }))]);
    return { source, brands };
  }, [api, id]);
  const write = canDo(role, 'source.write');
  const [edit, setEdit] = useState(false);
  const [retire, setRetire] = useState(false);
  const update = useAction((b: Parameters<typeof api.sources.update>[1]) => api.sources.update(id, b));
  const [saved, setSaved] = useState(false);
  if (res.status === 'loading') return <><PageHead title="Capture source" /><Skeleton what="this source" /></>;
  if (res.status === 'error') return <><PageHead title="Capture source" /><ErrorBlock title="This source did not load" err={res.error} onRetry={res.reload} next="Go back to capture sources, or try again." actions={<><Btn onClick={res.reload}>Try again</Btn><LinkBtn href="/sources" variant="secondary">Capture sources</LinkBtn></>} /></>;
  const { source, brands } = res.data;
  const brandName = (b: string) => brands.find((x) => x.brand_id === b)?.display_name ?? b;
  return (
    <>
      <PageHead title={source.name} lede={`${SOURCE_KIND_LABEL[source.kind]}`} actions={write && source.status === 'active' ? <><Btn onClick={() => { update.clear(); setEdit(!edit); }}>{edit ? 'Close editor' : 'Edit source'}</Btn><Btn variant="danger" onClick={() => setRetire(true)}>Retire source</Btn></> : null} />
      {saved && <SuccessBanner>Source saved. Recorded in the audit log.</SuccessBanner>}
      <div className="card">
        <KV rows={[
          ['Status', <Chip key="s" tone={source.status === 'active' ? 'st-success' : 'st-neutral'} icon={source.status === 'active' ? 'i-ok' : 'i-dash'}>{source.status === 'active' ? 'Active' : 'Retired'}</Chip>],
          ['Source id', <code key="i" className="mono">{source.source_id}</code>],
          ['Brands', source.brand_ids.map(brandName).join(', ')],
          ['Allowed origins', source.allowed_origins.length ? source.allowed_origins.join(', ') : 'None'],
          ['Last event', source.partial?.includes('last_event') ? <NotAvailable key="l" /> : source.last_event_at ? <Time key="l" iso={source.last_event_at} /> : 'No event yet'],
        ]} />
      </div>
      {edit && (
        <div className="card mt5"><h2>Edit source</h2>
          <SourceForm brands={brands} lockKind initial={{ name: source.name, kind: source.kind, brand_ids: source.brand_ids, origins: source.allowed_origins.join('\n') }} busy={update.busy} busyLabel="Saving" submitLabel="Save source" apiError={update.error} onCancel={() => setEdit(false)}
            onSubmit={async (v) => { const r = await update.run({ name: v.name.trim(), brand_ids: v.brand_ids, allowed_origins: v.kind === 'site_key' ? v.origins.split('\n').map((x) => x.trim()).filter(Boolean) : [] }); if (r.ok) { setEdit(false); setSaved(true); res.refresh(); } }} />
        </div>
      )}
      <div className="btn-row mt5"><LinkBtn href={`/sources/${source.source_id}/field-maps`} variant="secondary">Field map</LinkBtn><LinkBtn href="/sources" variant="quiet">Back to capture sources</LinkBtn></div>
      {retire && (
        <ConfirmDialog title={`Retire ${source.name}?`} destructive confirmLabel="Retire source" busyLabel="Retiring" failTitle="The source was not retired" failNext="Try again. Nothing was changed."
          body="A retired source refuses new events. Records already captured stay on record."
          onClose={() => setRetire(false)} onConfirm={async () => { const r = await update.run({ status: 'retired' }); if (r.ok) { res.refresh(); toast(`${source.name} retired. Recorded in the audit log.`); return null; } return r.error; }} />
      )}
    </>
  );
}

// ---------- 09 Credentials ----------
const ALGOS = [{ value: 'ES256', label: 'ES256' }, { value: 'EdDSA', label: 'EdDSA' }];
function statusOf(c: Credential) {
  return c.revoked_at ? <Chip tone="st-neutral" icon="i-dash">Revoked <Time iso={c.revoked_at} date /></Chip> : <Chip tone="st-success" icon="i-ok">Active</Chip>;
}

export function Credentials() {
  const { api, role, orgName, status } = useSession();
  const toast = useToast();
  const { search } = useRouter();
  const issuedName = search.get('issued');
  const issuedId = search.get('id');
  const res = useResource(async () => {
    const [credentials, sources] = await Promise.all([
      allPages((c) => api.credentials.list({ cursor: c })),
      api.sources.list().then((p) => p.items).catch(() => null),
    ]);
    return { credentials, sources };
  }, [api]);
  const write = canDo(role, 'credential.issue');
  const suspended = status === 'suspended';
  const [revoke, setRevoke] = useState<Credential | null>(null);
  const revokeA = useAction((id: string, reason: string) => api.credentials.revoke(id, reason));
  const d = res.status === 'ok' ? res.data : null;
  const srcName = (id: string | null) => (id === null ? <span className="hint">None</span> : d?.sources ? d.sources.find((s) => s.source_id === id)?.name ?? id : <NotAvailable />);
  const issue = write ? <LinkBtn href="/credentials/new" variant="primary" disabled={suspended} onClick={(e) => { if (suspended) e.preventDefault(); }}>Issue a credential</LinkBtn> : null;
  return (
    <>
      <PageHead title="Credentials" lede="To rotate: issue a new credential, switch your system to it, then revoke the old one." actions={issue} />
      {issuedName && <SuccessBanner action={<LinkBtn href="/setup/first-event" size="sm" variant="secondary">Send a test event</LinkBtn>}>{`${issuedName} issued.${issuedId ? ` Client id ${issuedId}.` : ''} Next: send your first test event.`}</SuccessBanner>}
      {suspended && <Banner kind="warning" title="New credentials are paused">{`New credentials are paused while ${orgName} is suspended. Existing capture credentials keep working. Resolve billing to issue new ones.`}</Banner>}
      {res.status === 'loading' && <Skeleton what="credentials" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="Credentials did not load" err={res.error} onRetry={res.reload} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {d && d.credentials.length === 0 && <StateBlock kind="empty" title="No credentials yet" actions={issue}>Your systems need a credential to send consents. Start with a capture credential for your first source.</StateBlock>}
      {d && d.credentials.length > 0 && (
        <>
          {d.sources === null && <Banner kind="warning" title="Capture source names did not load">Credentials are listed in full; their source shows as Not available.</Banner>}
          <DataTable caption="Credentials" rows={d.credentials} rowKey={(c) => c.credential_id}
            columns={[
              { key: 'n', header: 'Name', render: (c) => <b>{c.name}</b>, primary: true },
              { key: 'k', header: 'Kind', render: (c) => `${CRED_KIND_LABEL[c.kind]}${c.algorithm ? ` (${c.algorithm})` : ''}` },
              { key: 's', header: 'Scope', render: (c) => CRED_SCOPE_LABEL[c.scope] },
              { key: 'r', header: 'Source', render: (c) => srcName(c.source_id) },
              { key: 'c', header: 'Created', render: (c) => <Time iso={c.created_at} date /> },
              { key: 't', header: 'Status', render: statusOf },
            ]}
            actions={(c) => (!c.revoked_at && canDo(role, 'credential.revoke') ? <Btn size="sm" variant="danger" aria-label={`Revoke ${c.name}`} onClick={() => { revokeA.clear(); setRevoke(c); }}>Revoke</Btn> : null)} />
        </>
      )}
      {revoke && (
        <ConfirmDialog title={`Revoke ${revoke.name}?`} destructive confirmLabel="Revoke now" busyLabel="Revoking" reasonLabel="Reason (recorded in the audit log)" reasonRequired
          failTitle="The credential was not revoked" failNext="Try again. Nothing was changed."
          body="It stops working the moment you confirm. Any form or system still using it will have its requests refused until it uses a new credential."
          onClose={() => setRevoke(null)}
          onConfirm={async (reason) => { const r = await revokeA.run(revoke.credential_id, reason); if (r.ok) { res.refresh(); toast(`${revoke.name} revoked. Recorded in the audit log.`); return null; } return r.error; }} />
      )}
    </>
  );
}

function SecretReveal({ issued, onDone }: { issued: CredentialIssued; onDone: () => void }) {
  const [stored, setStored] = useState(false);
  const [confirmClose, setConfirmClose] = useState(false);
  if (confirmClose) {
    return (
      <Dialog title="Close without storing?" alert onClose={() => setConfirmClose(false)}>
        <p>This secret will not be shown again.</p>
        <div className="actions"><Btn data-safe="" onClick={() => setConfirmClose(false)}>Go back</Btn><Btn variant="danger" onClick={onDone}>Close anyway</Btn></div>
      </Dialog>
    );
  }
  return (
    <Dialog title="Copy your signed webhook secret now" onClose={() => setConfirmClose(true)} confirmEsc={() => setConfirmClose(true)} initialFocus="[data-copy] button">
      <p>This is the only time it is shown. ConsentVault stores it encrypted and cannot show it again.</p>
      <div className="field"><span className="lbl">Secret</span>
        <div className="secret" data-copy=""><code>{issued.secret}</code><CopyButton text={issued.secret ?? ''} label="Copy secret" copiedLabel="Secret copied" /></div></div>
      {issued.client_id && <KV rows={[['Client id', <code key="c" className="mono">{issued.client_id}</code>]]} />}
      <div className="mt4"><Check name="stored" label="I stored this secret somewhere safe" checked={stored} onChange={(e) => setStored(e.target.checked)} /></div>
      <div className="actions"><Btn onClick={() => setConfirmClose(true)}>Close</Btn><Btn variant="primary" disabled={!stored} onClick={onDone}>Done</Btn></div>
      <p className="hint mt4">Done turns on after the box is ticked. Closing without ticking asks once to confirm.</p>
    </Dialog>
  );
}

/** The credential kind a source sends with: a website form uses a site key, a server uses its public key. Anything else: no default. */
export function defaultKindFor(source: Pick<Source, 'kind'> | undefined): CredentialKind | '' {
  return source?.kind === 'site_key' ? 'edge_site_key' : source?.kind === 'server' ? 'jwt_public_key' : '';
}

export function CredentialNew({ embedded }: { embedded?: Embedded } = {}) {
  const { api } = useSession();
  const res = useResource(async () => {
    const sources = await allPages((c) => api.sources.list({ cursor: c }));
    return { sources };
  }, [api]);
  return <CredentialNewView res={res} embedded={embedded} />;
}

export function CredentialNewView({ res, embedded }: { res: ReturnType<typeof useResource<{ sources: Source[] }>>; embedded?: Embedded }) {
  const { api, role, orgName, status } = useSession();
  const { search, navigate } = useRouter();
  const [draft, setDraft] = useDraft('credential-new', { scope: 'capture', kind: '', source: search.get('source') ?? '', name: '', algorithm: 'ES256' });
  const [step, setStep] = useState(1);
  const [key, setKey] = useState('');
  const [touched, setTouched] = useState(false);
  const [refused, setRefused] = useState(false);
  const [issued, setIssued] = useState<CredentialIssued | null>(null);
  const issue = useAction((b: Parameters<typeof api.credentials.issue>[0]) => api.credentials.issue(b));
  const heading = useRef<HTMLHeadingElement>(null);
  const toast = useToast();
  useEffect(() => { heading.current?.focus(); }, [step]);
  const suspended = status === 'suspended';
  const d = res.status === 'ok' ? res.data : null;
  const scope = draft.scope as CredentialScope;
  const sources = (d?.sources ?? []).filter((s) => s.status === 'active');
  const needsSource = scope === 'capture';
  // the kind follows the source that is selected (or the one the form will pre-select) until the person picks one; with no source, or a kind it does not know, nothing is chosen
  const chosenSource = needsSource ? sources.find((s) => s.source_id === draft.source) ?? (draft.source ? undefined : sources[0]) : undefined;
  const kind = (draft.kind || defaultKindFor(chosenSource)) as CredentialKind | '';
  const websiteSource = scope === 'capture' && chosenSource?.kind === 'site_key';
  useEffect(() => {
    if (d && needsSource && !draft.source && sources[0]) setDraft({ source: sources[0].source_id });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [d]);
  const kindsFor = scope === 'capture' ? (['edge_site_key', 'jwt_public_key', 'hmac_fallback'] as CredentialKind[]) : (['jwt_public_key', 'hmac_fallback'] as CredentialKind[]);
  useEffect(() => { if (draft.kind && !kindsFor.includes(draft.kind as CredentialKind)) setDraft({ kind: '' }); // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope]);
  const nameErr = touched && !draft.name.trim() ? 'Enter a name.' : null;
  const finish = async () => {
    const body: Parameters<typeof api.credentials.issue>[0] = { name: draft.name.trim(), kind: kind as CredentialKind, scope, ...(needsSource ? { source_id: draft.source } : {}), ...(kind === 'jwt_public_key' ? { public_key: key, algorithm: draft.algorithm } : {}) };
    const r = await issue.run(body);
    if (!r.ok) return;
    setKey('');
    setIssued(r.value);
    if (!r.value.secret) done(r.value);
  };
  const done = (c: CredentialIssued) => {
    setIssued(null);
    try { sessionStorage.removeItem('cv.draft.credential-new'); } catch { /* nothing to clear */ }
    const idLine = c.site_key_id ? `Client id ${c.site_key_id}.` : c.client_id ? `Client id ${c.client_id}.` : '';
    toast(`${c.name} issued. Recorded in the audit log.`);
    if (embedded) embedded.onDone(`${c.name} issued.${idLine ? ` ${idLine}` : ''} Recorded in the audit log.`);
    else navigate(`/credentials?issued=${encodeURIComponent(c.name)}&id=${encodeURIComponent(c.site_key_id ?? c.client_id ?? '')}`);
    void idLine;
  };
  const next1 = () => {
    setTouched(true);
    if (!draft.name.trim() || !kind || (needsSource && !draft.source) || (websiteSource && kind === 'jwt_public_key')) return;
    if (kind === 'jwt_public_key') setStep(2); else void finish();
  };
  const next2 = () => {
    if (/PRIVATE KEY/i.test(key)) { setRefused(true); return; }
    setRefused(false);
    if (!key.trim()) { setTouched(true); return; }
    void finish();
  };
  if (!role || !canDo(role, 'credential.issue')) return null;
  return (
    <>
      {!embedded && <PageHead title="Issue a credential" lede={`Step ${step === 1 ? 1 : 2} of ${kind === 'jwt_public_key' ? 3 : 2}`} />}
      {res.status === 'loading' && <Skeleton what="your sources" />}
      {res.status === 'error' && <ErrorBlock title="Your sources did not load" err={res.error} onRetry={res.reload} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {suspended && <Banner kind="warning" title="New credentials are paused">{`New credentials are paused while ${orgName} is suspended. Existing capture credentials keep working. Resolve billing to issue new ones.`}</Banner>}
      {d && step === 1 && (
        <form className="card" onSubmit={(e) => { e.preventDefault(); next1(); }} noValidate>
          <h2 ref={heading} tabIndex={-1}>What it does</h2>
          {issue.error && <ErrorBlock title="The credential was not issued" err={issue.error} next="Fix the field and try again. Nothing was changed." headingLevel={3} />}
          <fieldset>
            <legend>Scope</legend>
            <Radio name="scope" label="Capture: send consents and stops. Cannot read anything." checked={scope === 'capture'} onChange={() => setDraft({ scope: 'capture' })} />
            {canDo(role, 'credential.issue.gate_read') && (
              <>
                <Radio name="scope" label="Contact check: read what the records show for a contact, before you contact them." checked={scope === 'gate_read'} onChange={() => setDraft({ scope: 'gate_read' })} />
              </>
            )}
            {canDo(role, 'credential.issue.proof_read') && <Radio name="scope" label="Evidence read: look up records and build evidence packages." checked={scope === 'proof_read'} onChange={() => setDraft({ scope: 'proof_read' })} />}
          </fieldset>
          <fieldset>
            <legend>Kind</legend>
            {kindsFor.includes('edge_site_key') && <Radio name="kind" label="Site key for a website form" checked={kind === 'edge_site_key'} onChange={() => setDraft({ kind: 'edge_site_key' })} />}
            <Radio name="kind" label="Public key for a server (you keep the private key)" checked={kind === 'jwt_public_key'} onChange={() => setDraft({ kind: 'jwt_public_key' })}
              disabled={websiteSource} hint={websiteSource ? 'Not for a website form source: a server would be vouching for the visitor details only the ConsentVault edge may record. Use a site key, or pick a server source.' : undefined} />
            <Radio name="kind" label="Signed webhook secret, for systems that cannot use keys" checked={kind === 'hmac_fallback'} onChange={() => setDraft({ kind: 'hmac_fallback' })} />
            {touched && !kind && <p className="field-error" role="alert"><Icon name="i-err" /><span>Choose a kind.</span></p>}
            {touched && websiteSource && kind === 'jwt_public_key' && <p className="field-error" role="alert"><Icon name="i-err" /><span>A public key is not available for a website form source. Choose a site key, or pick a server source.</span></p>}
          </fieldset>
          {needsSource && (sources.length === 0
            ? <Banner kind="warning" title="Add a capture source first">A capture credential belongs to one source. <Link href="/sources">Open capture sources</Link></Banner>
            : <SelectField label="Capture source" name="source" value={draft.source} onChange={(e) => setDraft({ source: e.target.value })} options={sources.map((s) => ({ value: s.source_id, label: s.name }))} />)}
          <TextField label="Name" name="cred-name" value={draft.name} onChange={(e) => setDraft({ name: e.target.value })} required autoComplete="off" error={nameErr} />
          <div className="actions"><LinkBtn href="/credentials" variant="secondary">Cancel</LinkBtn><Btn type="submit" variant="primary" disabled={suspended || (needsSource && sources.length === 0)} busy={issue.busy} busyLabel="Issuing">{kind === 'jwt_public_key' ? 'Next' : 'Issue credential'}</Btn></div>
          {suspended && <p className="hint">Issuing is paused while {orgName} is suspended. Resolve billing to continue.</p>}
        </form>
      )}
      {d && step === 2 && (
        <form className="card" onSubmit={(e) => { e.preventDefault(); next2(); }} noValidate>
          <h2 ref={heading} tabIndex={-1}>Add your public key</h2>
          <p className="hint">Step 2 of 3 (server credentials only)</p>
          {refused && <ErrorBlock title="The credential was not issued" err={new ApiError(0, 'private_key_refused', '', null)} override="that text is a private key. Only a public key may be added" next="Paste the public half. Treat the private key you pasted as exposed and replace it." headingLevel={3} />}
          {issue.error && issue.error.code === 'private_key_refused' && <ErrorBlock title="The credential was not issued" err={issue.error} override="that text is a private key. Only a public key may be added" next="Paste the public half. Treat the private key you pasted as exposed and replace it." headingLevel={3} />}
          {issue.error && issue.error.code !== 'private_key_refused' && <ErrorBlock title="The credential was not issued" err={issue.error} next="Fix the field and try again. Nothing was changed." headingLevel={3} />}
          <TextArea label="Public key (PEM)" name="public-key" hint="Paste the public half only. Never paste a private key." rows={6} className="mono" value={key} onChange={(e) => { setKey(e.target.value); setRefused(false); }} placeholder="-----BEGIN PUBLIC KEY-----" autoComplete="off" spellCheck={false} error={touched && !key.trim() && !refused ? 'Paste your public key.' : null} />
          <SelectField label="Signing algorithm" name="algorithm" hint="Pinned for this credential. Tokens signed any other way are refused." value={draft.algorithm} onChange={(e) => setDraft({ algorithm: e.target.value })} options={ALGOS} />
          <div className="actions"><Btn onClick={() => setStep(1)}>Back</Btn><Btn type="submit" variant="primary" busy={issue.busy} busyLabel="Issuing" disabled={suspended}>Issue credential</Btn></div>
        </form>
      )}
      {issued && issued.secret && <SecretReveal issued={issued} onDone={() => done(issued)} />}
    </>
  );
}

void NA; void causeLine;
