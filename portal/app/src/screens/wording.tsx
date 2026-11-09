import React, { useEffect, useRef, useState } from 'react';
import { allPages } from '../lib/api/client.ts';
import type { Brand, Channel, Disclosure, Purpose } from '../lib/api/types.ts';
import { CHANNEL_FALLBACK, NA } from '../lib/copy.ts';
import { useAction, useDraft, useResource } from '../lib/hooks.ts';
import { Link, useRouter } from '../lib/router.tsx';
import { canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { fmtDate, shortId } from '../lib/format.ts';
import { memberName, wordingName, type NamedMember } from '../lib/labels.ts';
import type { Embedded } from '../components/ui.tsx';
import { Banner, Btn, Check, CopyButton, DataTable, ErrorBlock, ErrorSummary, KV, LinkBtn, NotAvailable, PageHead, Radio, Skeleton, StateBlock, SuccessBanner, TextArea, TextField, Time } from '../components/ui.tsx';


function useLabels() {
  const { api, role } = useSession();
  const brandsOk = role === 'admin' || role === 'developer';
  return useResource(async () => {
    const settle = async <T,>(p: Promise<T>): Promise<T | null> => { try { return await p; } catch { return null; } };
    const [brands, channels, purposes] = await Promise.all([
      brandsOk ? settle(allPages((c) => api.brands.list({ cursor: c }))) : Promise.resolve([] as Brand[]), settle(allPages((c) => api.channels({ cursor: c }))), settle(allPages((c) => api.purposes({ cursor: c }))),
    ]);
    return { brands, channels, purposes };
  }, [api, brandsOk]);
}
type Labels = { brands: Brand[] | null; channels: Channel[] | null; purposes: Purpose[] | null };
const chLabel = (l: Labels | null, c: string) => l?.channels?.find((x) => x.channel === c)?.label ?? CHANNEL_FALLBACK[c] ?? c;
const prLabel = (l: Labels | null, p: string) => l?.purposes?.find((x) => x.purpose === p)?.label ?? p;
const brLabel = (l: Labels | null, b: string) => l?.brands?.find((x) => x.brand_id === b)?.display_name ?? null;

// ---------- 10 Wording list ----------
export function Wording() {
  const { api, role } = useSession();
  const res = useResource(() => allPages((c) => api.disclosures.list({ cursor: c })), [api]);
  const labels = useLabels();
  const write = canDo(role, 'wording.register');
  const rows = res.status === 'ok' ? res.data : [];
  const l = labels.status === 'ok' ? labels.data : null;
  const reg = write ? <LinkBtn href="/wording/new" variant="primary">Register wording</LinkBtn> : null;
  const byHash = (h: string | null) => (h ? rows.find((r) => r.sha256 === h) : undefined);
  const labelsFailed = !!l && (l.brands === null || l.channels === null || l.purposes === null);
  return (
    <>
      <PageHead title="Wording" lede="The exact consent text each form shows, with its version history. Registered wording can never be edited." actions={rows.length > 0 ? reg : null} />
      {res.status === 'loading' && <Skeleton what="wording" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="Wording did not load" err={res.error} next="Try again. Nothing was changed." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {res.status === 'ok' && rows.length === 0 && (
        <StateBlock kind="empty" title="No wording registered yet" actions={reg}>A consent can only be recorded against wording you registered first. {write ? 'Paste the exact text your form shows.' : 'An admin registers the exact text your form shows.'}</StateBlock>
      )}
      {rows.length > 0 && (
        <>
          {labelsFailed && <Banner kind="warning" title="Some names did not load">Brand, channel or purpose names that did not load show as Not available. Versions and fingerprints are current.</Banner>}
          <DataTable caption="Registered wording versions" rows={rows} rowKey={(r) => r.sha256}
            columns={[
              { key: 'v', header: 'Version', render: (r) => <Link href={`/wording/${r.sha256}`}>{wordingName(r)}</Link>, primary: true },
              { key: 'b', header: 'Brands', render: (r) => (l?.brands ? r.brand_ids.map((b) => brLabel(l, b) ?? b).join(', ') : <NotAvailable />) },
              { key: 'c', header: 'Channels', render: (r) => (l?.channels ? r.channels.map((c) => chLabel(l, c)).join(', ') : <NotAvailable />) },
              { key: 'p', header: 'Purposes', render: (r) => (l?.purposes ? r.purposes.map((p) => prLabel(l, p)).join(', ') : <NotAvailable />) },
              { key: 'f', header: 'Shown from', render: (r) => <Time iso={r.effective_from} date /> },
              { key: 'h', header: 'Fingerprint', render: (r) => <code className="mono">{shortId(r.sha256)}</code> },
              { key: 'r', header: 'Replaces', render: (r) => (r.supersedes_sha256 ? (byHash(r.supersedes_sha256) ? wordingName(byHash(r.supersedes_sha256)!) : null) ?? <code className="mono">{shortId(r.supersedes_sha256)}</code> : <span className="hint">None recorded</span>) },
            ]} />
        </>
      )}
    </>
  );
}

// ---------- 10 Register wording ----------
export function WordingNew({ embedded }: { embedded?: Embedded } = {}) {
  const { api, role } = useSession();
  const { search, navigate } = useRouter();
  const res = useResource(async () => {
    const [brands, channels, purposes, existing] = await Promise.all([
      allPages((c) => api.brands.list({ cursor: c })), allPages((c) => api.channels({ cursor: c })), allPages((c) => api.purposes({ cursor: c })), allPages((c) => api.disclosures.list({ cursor: c, state: 'current' })),
    ]);
    return { brands, channels, purposes, existing };
  }, [api]);
  const [d, setD] = useDraft('wording-new', { body: '', label: '', channels: [] as string[], purposes: [] as string[], brands: [] as string[], replaces: search.get('replaces') ?? '', from: new Date().toISOString().slice(0, 10) });
  const [touched, setTouched] = useState(false);
  const register = useAction((b: Parameters<typeof api.disclosures.register>[0]) => api.disclosures.register(b));
  const summary = useRef<HTMLDivElement>(null);
  const data = res.status === 'ok' ? res.data : null;
  const toggle = (k: 'channels' | 'purposes' | 'brands', v: string, on: boolean) => setD({ [k]: on ? [...d[k], v] : d[k].filter((x) => x !== v) } as never);
  const errs: { message: string }[] = [];
  if (!d.body.trim()) errs.push({ message: 'Paste the exact wording.' });
  if (!d.label.trim()) errs.push({ message: 'Enter a version label.' });
  if (!d.channels.length) errs.push({ message: 'Choose at least one channel.' });
  if (!d.purposes.length) errs.push({ message: 'Choose at least one purpose.' });
  if (!d.brands.length) errs.push({ message: 'Choose at least one brand.' });
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (errs.length) { setTouched(true); window.setTimeout(() => summary.current?.focus(), 0); return; }
    // The wording is sent byte for byte: no trimming, no quote conversion.
    const r = await register.run({ body: d.body, label: d.label.trim(), channels: d.channels, purposes: d.purposes, brand_ids: d.brands, ...(d.replaces ? { supersedes_sha256: d.replaces } : {}), effective_from: `${d.from}T00:00:00Z` });
    if (r.ok) {
      try { sessionStorage.removeItem('cv.draft.wording-new'); } catch { /* nothing to clear */ }
      if (embedded) embedded.onDone(`Wording registered as version ${d.label.trim()}. It can never be edited; a change is a new version.`);
      else navigate(`/wording/${r.value.sha256}?registered=1`);
    } else summary.current?.focus();
  };
  useEffect(() => { if (register.error) summary.current?.focus(); }, [register.error]);
  if (!canDo(role, 'wording.register')) return null;
  const exists = register.error?.code === 'disclosure_exists';
  const existingSha = String((register.error?.fields as { sha256?: string } | undefined)?.sha256 ?? '');
  const existingLabel = data?.existing.find((x) => x.sha256 === existingSha) ? wordingName(data!.existing.find((x) => x.sha256 === existingSha)!) : undefined;
  return (
    <>
      {!embedded && <PageHead title="Register wording" lede="Paste the exact text people see next to the checkbox. It is stored character for character, including spaces and punctuation. Registered wording can never be edited." />}
      {res.status === 'loading' && <Skeleton what="the form" />}
      {res.status === 'error' && <ErrorBlock title="The form did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {data && (
        <form className="card" onSubmit={submit} noValidate>
          <div ref={summary} tabIndex={-1}>
            {register.error && <ErrorBlock title="The wording was not registered" err={register.error}
              override={exists ? `this exact text is already registered${existingLabel ? ` as version ${existingLabel}` : ''}` : undefined}
              next={exists ? 'Use the existing version. If the text changed, check that what you pasted matches your form exactly.' : 'Fix the field and try again. Nothing was changed.'}
              actions={exists ? <LinkBtn href={`/wording/${existingSha}`} variant="secondary">{existingLabel ? `Open version ${existingLabel}` : 'Open the existing version'}</LinkBtn> : undefined} headingLevel={3} />}
            {touched && <ErrorSummary errors={errs} />}
          </div>
          <TextArea label="Exact wording" name="body" rows={6} value={d.body} onChange={(e) => setD({ body: e.target.value })} placeholder="By checking this box, I agree that Acme Lending may contact me..." spellCheck autoCorrect="off" autoCapitalize="off" autoComplete="off" required error={touched && !d.body.trim() ? 'Paste the exact wording.' : null} />
          <TextField label="Version label" name="label" value={d.label} onChange={(e) => setD({ label: e.target.value })} autoComplete="off" required error={touched && !d.label.trim() ? 'Enter a version label.' : null} />
          <fieldset><legend>Channels it names</legend>{data.channels.map((c) => <Check key={c.channel} name={`ch-${c.channel}`} label={c.label} checked={d.channels.includes(c.channel)} onChange={(e) => toggle('channels', c.channel, e.target.checked)} />)}</fieldset>
          <fieldset><legend>Purposes it names</legend>{data.purposes.map((p) => <Check key={p.purpose} name={`pu-${p.purpose}`} label={p.label} hint={p.description} checked={d.purposes.includes(p.purpose)} onChange={(e) => toggle('purposes', p.purpose, e.target.checked)} />)}</fieldset>
          <fieldset><legend>Brands named as seller</legend>{data.brands.map((b) => <Check key={b.brand_id} name={`br-${b.brand_id}`} label={b.display_name} checked={d.brands.includes(b.brand_id)} onChange={(e) => toggle('brands', b.brand_id, e.target.checked)} />)}</fieldset>
          <fieldset><legend>Replaces</legend>
            <Radio name="replaces" label="Nothing (first version)" checked={d.replaces === ''} onChange={() => setD({ replaces: '' })} />
            {data.existing.map((x) => <Radio key={x.sha256} name="replaces" label={wordingName(x)} checked={d.replaces === x.sha256} onChange={() => setD({ replaces: x.sha256 })} />)}
          </fieldset>
          <TextField label="Shown on your forms from" name="from" type="date" value={d.from} onChange={(e) => setD({ from: e.target.value })} required />
          <div className="actions">{!embedded && <LinkBtn href="/wording" variant="secondary">Cancel</LinkBtn>}<Btn type="submit" variant="primary" busy={register.busy} busyLabel="Registering">Register wording</Btn></div>
        </form>
      )}
    </>
  );
}

// ---------- 10 Wording detail ----------
export function WordingDetail({ sha }: { sha: string }) {
  const { api, role, orgName } = useSession();
  const { search } = useRouter();
  const res = useResource(() => api.disclosures.get(sha), [api, sha]);
  const labels = useLabels();
  const l = labels.status === 'ok' ? labels.data : null;
  const list = useResource(() => allPages((c) => api.disclosures.list({ cursor: c })), [api]);
  const all: Disclosure[] = list.status === 'ok' ? list.data : [];
  const members = useResource(() => (role === 'admin' ? allPages((c) => api.members.list({ cursor: c })).catch(() => null) : Promise.resolve(null)), [api, role]);
  if (res.status === 'loading') return <><PageHead title="Wording" /><Skeleton what="this wording" /></>;
  if (res.status === 'error') {
    return res.error.status === 404
      ? <><PageHead title="Wording" /><StateBlock kind="error" title={`That page does not exist in ${orgName}`} cause="The address may be mistyped, or the item belongs to another organization you are not working in." next="Go back to the wording list." actions={<LinkBtn href="/wording" variant="secondary">Wording</LinkBtn>} /></>
      : <><PageHead title="Wording" /><ErrorBlock title="This wording did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} /></>;
  }
  const d = res.data;
  const link = (h: string | null) => { const x = h ? all.find((y) => y.sha256 === h) : undefined; return h ? <Link href={`/wording/${h}`}>{x ? wordingName(x) : shortId(h)}</Link> : null; };
  const by = members.status === 'ok' && members.data ? memberName(members.data.find((m: NamedMember) => m.id === d.registered_by)) : null;
  return (
    <>
      <PageHead title={`Wording ${wordingName(d)}`} />
      {search.get('registered') && <SuccessBanner>{`Version ${wordingName(d)} registered. Send this fingerprint with each grant: ${shortId(d.sha256)}.`}</SuccessBanner>}
      <div className="card">
        <KV rows={[
          ['Fingerprint (sha256)', <span key="f" className="gap-row"><code className="mono">{d.sha256}</code><CopyButton text={d.sha256} ariaLabel="Copy fingerprint" /></span>],
          ['Registered', <span key="r"><Time iso={d.registered_at} date /> by {by ?? <NotAvailable />}</span>],
          ['Shown from', <Time key="s" iso={d.effective_from} date />],
          ['Replaces', link(d.supersedes_sha256) ?? 'None recorded'],
          ['Replaced by', link(d.superseded_by_sha256) ?? 'Nothing yet'],
          ['Brands', l?.brands ? d.brand_ids.map((b) => brLabel(l, b) ?? b).join(', ') : NA],
          ['Channels', l?.channels ? d.channels.map((c) => chLabel(l, c)).join(', ') : NA],
          ['Purposes', l?.purposes ? d.purposes.map((p) => prLabel(l, p)).join(', ') : NA],
        ]} />
      </div>
      <h2 className="sec mt5">Exact text</h2>
      <pre className="code wrap-pre" data-copy-exempt="" tabIndex={0} role="region" aria-label="Exact registered text">{d.body ?? ''}</pre>
      <div className="btn-row mt5">
        {canDo(role, 'wording.register') && <LinkBtn href={`/wording/new?replaces=${d.sha256}`} variant="secondary">Register a new version that replaces this one</LinkBtn>}
        <LinkBtn href="/wording" variant="quiet">Back to wording</LinkBtn>
      </div>
    </>
  );
}
