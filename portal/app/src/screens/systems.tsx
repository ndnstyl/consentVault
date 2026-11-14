import React, { useEffect, useRef, useState } from 'react';
import { ApiError, allPages } from '../lib/api/client.ts';
import type { Delivery, System, SystemCreated, TestPush } from '../lib/api/types.ts';
import { CHANNEL_FALLBACK, KIND_LABEL, NA } from '../lib/copy.ts';
import { useAction, usePoll, useResource } from '../lib/hooks.ts';
import { Link, useRouter } from '../lib/router.tsx';
import { canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { useToast } from '../lib/toast.tsx';
import { isEd25519, isHmac } from '../lib/signature.ts';
import type { SignatureKind } from '../lib/signature.ts';
import { ConfirmDialog } from '../components/Dialog.tsx';
import type { Embedded } from '../components/ui.tsx';
import { Banner, Btn, Check, Chip, CopyButton, DataTable, DeliveryChip, ErrorBlock, ErrorSummary, KV, LinkBtn, NotAvailable, PageHead, Radio, SelectField, Skeleton, StateBlock, SuccessBanner, TextField, Time } from '../components/ui.tsx';

function stateChip(s: System) {
  if (s.status === 'paused') return <Chip tone="st-neutral" icon="i-pause">Paused</Chip>;
  if (!s.counts) return <NotAvailable />;
  if (s.counts.dead > 0) return <Chip tone="st-danger" icon="i-err">{`${s.counts.dead} undelivered`}</Chip>;
  return <Chip tone="st-success" icon="i-ok">Delivering</Chip>;
}

// ---------- 15 Connected systems ----------
export function Systems() {
  const { api, role } = useSession();
  const res = useResource(() => allPages((c) => api.systems.list({ cursor: c })), [api]);
  const write = canDo(role, 'system.write');
  const rows = res.status === 'ok' ? res.data : [];
  const connect = write ? <LinkBtn href="/systems/new" variant="primary">Connect a system</LinkBtn> : null;
  return (
    <>
      <PageHead title="Connected systems" lede="Every stop is pushed to each system below, retried for 24 hours, then marked undelivered and alerted." actions={rows.length > 0 ? connect : null} />
      {res.status === 'loading' && <Skeleton what="connected systems" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="Connected systems did not load" err={res.error} onRetry={res.reload} next="Try again. Pushes keep running while this page is down." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {res.status === 'ok' && rows.length === 0 && <StateBlock kind="empty" title="No systems connected" actions={connect}>Stops are recorded and contact checks show them, but nothing is pushed to your CRM, dialer or texting platform until you connect them.</StateBlock>}
      {rows.length > 0 && (
        <>
          {rows.some((s) => s.counts === null) && <Banner kind="warning" title="Undelivered counts did not load">Shown as Not available, never as zero.</Banner>}
          <DataTable caption="Connected systems" rows={rows} rowKey={(s) => s.system_id}
            columns={[
              { key: 'n', header: 'System', render: (s) => <Link href={`/systems/${s.system_id}`}>{s.name}</Link>, primary: true },
              { key: 'k', header: 'Kind', render: (s) => KIND_LABEL[s.kind] ?? s.kind },
              { key: 'c', header: 'Connector', render: () => 'Signed webhook' },
              { key: 's', header: 'State', render: stateChip },
              { key: 'l', header: 'Last delivery', render: (s) => (s.last_delivery_at ? <Time iso={s.last_delivery_at} /> : <span className="hint">None yet</span>) },
              { key: 'd', header: 'Undelivered (dead)', right: true, render: (s) => (s.counts ? <span className="num">{s.counts.dead}</span> : <NotAvailable />) },
            ]} />
        </>
      )}
    </>
  );
}

const KINDS = [['crm', 'CRM'], ['dialer', 'Dialer'], ['sms', 'Texting'], ['email', 'Email'], ['ai_agent', 'AI agent'], ['webhook', 'Other webhook']].map(([value, label]) => ({ value, label }));

function pushAnswer(name: string, t: TestPush): { ok: boolean; text: string; next?: string } {
  if (t.result === 'accepted') return { ok: true, text: `Test push accepted: ${t.http_status} in ${t.latency_ms} ms` };
  if (t.result === 'rejected') {
    const c = t.http_status ?? 0;
    const next = c === 401 || c === 403 ? `Load the public key shown below into ${name}, then send another test push.` : c === 404 ? `Check the endpoint address in ${name}, then send another test push.` : c === 410 ? `${name} says this address is gone. Edit the address, then send another test push.` : `Check ${name}'s log for the reason, then send another test push.`;
    return { ok: false, text: `${name} answered ${c}${t.latency_ms !== null ? ` after ${t.latency_ms} ms` : ''}. It did not accept the push.`, next };
  }
  if (t.result === 'server_error') return { ok: false, text: `${name} answered ${t.http_status}. It had an error.`, next: `Fix ${name}, then send another test push.` };
  if (t.result === 'timeout') return { ok: false, text: `${name} did not answer within 10 seconds.`, next: 'Check that the address is reachable, then send another test push.' };
  return { ok: false, text: `${name} could not be reached.`, next: 'Check the endpoint address, then send another test push.' };
}

function TestResult({ name, t, publicKey, onAgain, busy }: { name: string; t: TestPush; publicKey: string | null; onAgain: () => void; busy: boolean }) {
  const a = pushAnswer(name, t);
  const [showKey, setShowKey] = useState(false);
  return a.ok
    ? <Banner kind="success" title="Test push">{a.text}</Banner>
    : (
      <StateBlock kind="error" title="Test push failed" cause={a.text} next={a.next}
        actions={<><Btn busy={busy} busyLabel="Sending" onClick={onAgain}>Send another test push</Btn>{publicKey && <Btn onClick={() => setShowKey(!showKey)}>{showKey ? 'Hide public key' : 'Show public key'}</Btn>}{showKey && publicKey && <code className="mono wrap-pre">{publicKey}</code>}</>} />
    );
}

export function SystemNew({ embedded }: { embedded?: Embedded } = {}) {
  const { api, role, orgName, status } = useSession();
  const { navigate } = useRouter();
  const toast = useToast();
  const [v, setV] = useState({ name: '', kind: 'crm', endpoint: '', signature: 'ed25519', contact_form: 'fingerprint', hours: '24' });
  const [touched, setTouched] = useState(false);
  const [made, setMade] = useState<SystemCreated | null>(null);
  const [test, setTest] = useState<TestPush | null>(null);
  const [stored, setStored] = useState(false);
  const create = useAction((b: Parameters<typeof api.systems.create>[0]) => api.systems.create(b));
  const tester = useAction((id: string) => api.systems.test(id));
  const summary = useRef<HTMLDivElement>(null);
  const errs: string[] = [];
  if (!v.name.trim()) errs.push('Enter a name.');
  if (!/^https:\/\/[^\s/]+/.test(v.endpoint.trim())) errs.push('The endpoint address must start with https://.');
  const hours = Number(v.hours);
  if (!Number.isFinite(hours) || hours < 1 || hours > 168) errs.push('Enter a retry window between 1 and 168 hours.');
  const suspended = status === 'suspended';
  if (!canDo(role, 'system.write')) return null;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (errs.length) { setTouched(true); window.setTimeout(() => summary.current?.focus(), 0); return; }
    const r = await create.run({ name: v.name.trim(), kind: v.kind as System['kind'], endpoint: v.endpoint.trim(), signature: v.signature as 'ed25519' | 'hmac', contact_form: v.contact_form as 'plaintext' | 'fingerprint', retry_window_hours: hours });
    if (r.ok) { setMade(r.value); const t = await tester.run(r.value.system_id); if (t.ok) setTest(t.value); toast(`${r.value.name} connected. Recorded in the audit log.`); }
  };
  if (made) {
    return (
      <>
        {!embedded && <PageHead title={`${made.name} connected`} lede="Load the key below into the receiving system, then check the test push." />}
        {tester.error && <ErrorBlock title="The test push did not run" err={tester.error} next="Send another test push from the system page." />}
        {test && <TestResult name={made.name} t={test} publicKey={made.public_key} busy={tester.busy} onAgain={async () => { const t = await tester.run(made.system_id); if (t.ok) setTest(t.value); }} />}
        <div className="card mt4">
          {made.public_key && <KV rows={[['Public key', <span key="k" className="gap-row"><code className="mono wrap-pre">{made.public_key}</code><CopyButton text={made.public_key} ariaLabel="Copy public key" /></span>]]} />}
          {made.hmac_secret && (
            <>
              <p>This secret is shown once. ConsentVault stores it encrypted and cannot show it again.</p>
              <div className="secret"><code>{made.hmac_secret}</code><CopyButton text={made.hmac_secret} label="Copy secret" copiedLabel="Secret copied" /></div>
              <div className="mt4"><Check name="stored" label="I stored this secret somewhere safe" checked={stored} onChange={(e) => setStored(e.target.checked)} /></div>
            </>
          )}
        </div>
        <div className="btn-row mt5"><Btn variant="primary" disabled={!!made.hmac_secret && !stored} onClick={() => (embedded ? embedded.onDone(`${made.name} connected. Recorded in the audit log.`) : navigate(`/systems/${made.system_id}`))}>{embedded ? 'Done' : 'Open system'}</Btn>{made.hmac_secret && !stored && <span className="hint">Open system turns on after the box is ticked.</span>}</div>
      </>
    );
  }
  return (
    <>
      {!embedded && <PageHead title="Connect a system" lede="Stops are pushed to this system as signed webhooks." />}
      {suspended && <Banner kind="warning" title="New connections are paused">{`Connecting a system is paused while ${orgName} is suspended. Resolve billing to continue.`}</Banner>}
      <form className="card" onSubmit={submit} noValidate>
        <div ref={summary} tabIndex={-1}>
          {touched && <ErrorSummary errors={errs.map((m) => ({ message: m }))} />}
          {create.error && <ErrorBlock title="The system was not connected" err={create.error} next="Fix the field and try again. Nothing was changed." headingLevel={3} />}
        </div>
        <TextField label="Name" name="sys-name" value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} autoComplete="off" error={touched && !v.name.trim() ? 'Enter a name.' : null} />
        <SelectField label="Kind" name="kind" value={v.kind} onChange={(e) => setV({ ...v, kind: e.target.value })} options={KINDS} />
        <TextField label="Endpoint address (https only)" name="endpoint" type="url" value={v.endpoint} onChange={(e) => setV({ ...v, endpoint: e.target.value })} placeholder="https://dialer.acme.com/consentvault" autoComplete="off" spellCheck={false} error={v.endpoint && !/^https:\/\//.test(v.endpoint.trim()) ? 'The endpoint address must start with https://.' : touched && !v.endpoint ? 'Enter the endpoint address.' : null} />
        <fieldset><legend>Signature</legend>
          <Radio name="sig" label="Ed25519 (recommended)" hint="You load a public key into the receiver." checked={isEd25519(v.signature as SignatureKind)} onChange={() => setV({ ...v, signature: 'ed25519' })} />
          <Radio name="sig" label="HMAC shared secret" hint="A secret is shown once after you connect." checked={isHmac(v.signature as SignatureKind)} onChange={() => setV({ ...v, signature: 'hmac' })} />
        </fieldset>
        <fieldset><legend>Contact sent as</legend>
          <Radio name="form" label="Plain contact point" hint="Sends the person's number or email to this system. The choice is recorded in the audit log." checked={v.contact_form === 'plaintext'} onChange={() => setV({ ...v, contact_form: 'plaintext' })} />
          <Radio name="form" label="Fingerprint only" checked={v.contact_form === 'fingerprint'} onChange={() => setV({ ...v, contact_form: 'fingerprint' })} />
        </fieldset>
        <TextField label="Keep retrying for (hours)" name="hours" type="number" min={1} max={168} value={v.hours} onChange={(e) => setV({ ...v, hours: e.target.value })} hint="24 hours is the default." />
        <div className="actions">{!embedded && <LinkBtn href="/systems" variant="secondary">Cancel</LinkBtn>}<Btn type="submit" variant="primary" disabled={suspended} busy={create.busy || tester.busy} busyLabel="Connecting">Connect and send a test push</Btn></div>
      </form>
    </>
  );
}

function lastAnswer(d: Delivery): string {
  switch (d.last_error_class) {
    case 'timeout': return 'Timed out (10 s)';
    case 'http_5xx': return `${d.last_http_status ?? 5} error after 10 s`.replace(' after 10 s', '');
    case 'http_4xx': return `${d.last_http_status ?? 4} refused`;
    case 'signature_rejected': return 'Signature rejected';
    case 'unreachable': return 'Could not be reached';
    default: return d.last_http_status ? String(d.last_http_status) : NA;
  }
}

export function SystemDetail({ id }: { id: string }) {
  const { api, role, orgName } = useSession();
  const toast = useToast();
  const res = useResource(async () => {
    const [system, dead] = await Promise.all([api.systems.get(id), api.systems.deliveries(id, { status: 'dead' }).then((p) => p.items).catch(() => null)]);
    return { system, dead };
  }, [api, id]);
  const tester = useAction(() => api.systems.test(id));
  const patch = useAction((b: Parameters<typeof api.systems.update>[1]) => api.systems.update(id, b));
  const [test, setTest] = useState<TestPush | null>(null);
  const [dialog, setDialog] = useState(false);
  const [redrive, setRedrive] = useState<{ id: string; n: number } | null>(null);
  const poll = usePoll(() => api.systems.redriveStatus(redrive!.id), { intervalMs: 5000, deadlineMs: 5 * 60 * 1000, enabled: !!redrive, until: (r) => r.status === 'done' });
  useEffect(() => { if (poll.done) res.refresh(); // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [poll.done]);
  const write = canDo(role, 'system.write');
  if (res.status === 'loading') return <><PageHead title="Connected system" /><Skeleton what="this system" /></>;
  if (res.status === 'error') {
    return res.error.status === 404
      ? <><PageHead title="Connected system" /><StateBlock kind="error" title={`That page does not exist in ${orgName}`} cause="The address may be mistyped, or the item belongs to another organization you are not working in." next="Go back to connected systems." actions={<LinkBtn href="/systems" variant="secondary">Connected systems</LinkBtn>} /></>
      : <><PageHead title="Connected system" /><ErrorBlock title="This system did not load" err={res.error} onRetry={res.reload} next="Try again. Pushes keep running while this page is down." actions={<Btn onClick={res.reload}>Try again</Btn>} /></>;
  }
  const { system: s, dead } = res.data;
  const lt = test ?? (s.last_test ? { result: s.last_test.result as TestPush['result'], http_status: s.last_test.http_status, latency_ms: s.last_test.latency_ms, at: s.last_test.at } : null);
  const deadN = s.counts?.dead ?? dead?.length ?? null;
  return (
    <>
      <PageHead title={s.name} meta={<>{KIND_LABEL[s.kind]} {stateChip(s)}</>}
        actions={write ? <><Btn busy={tester.busy} busyLabel="Sending" onClick={async () => { const r = await tester.run(); if (r.ok) { setTest(r.value); res.refresh(); } }}>Send a test push</Btn>
          {canDo(role, 'system.redrive') && <Btn variant="primary" disabled={!deadN} onClick={() => setDialog(true)}>Redrive undelivered</Btn>}</> : null} />
      {tester.error && <ErrorBlock title="The test push did not run" err={tester.error} next="Try again." />}
      {test && !tester.busy && <TestResult name={s.name} t={test} publicKey={s.public_key} busy={tester.busy} onAgain={async () => { const r = await tester.run(); if (r.ok) setTest(r.value); }} />}
      <div className="card">
        <KV rows={[
          ['Endpoint', <code key="e" className="mono wrap-pre">{s.endpoint}</code>],
          ['Signature', isEd25519(s.signature) ? 'Ed25519, key version 1' : 'HMAC shared secret'],
          ['Contact sent as', s.contact_form === 'plaintext' ? 'Plain contact point' : 'Fingerprint only'],
          ['Retry window', `${s.retry_window_hours} hours`],
          ['Last test push', lt ? <span key="t"><Time iso={lt.at} />: {lt.http_status ?? lt.result}{lt.latency_ms !== null ? ` in ${lt.latency_ms} ms` : ''}</span> : 'None yet'],
          ...(s.public_key ? [['Public key', <span key="k" className="gap-row"><code className="mono wrap-pre">{s.public_key}</code><CopyButton text={s.public_key} ariaLabel="Copy public key" /></span>] as [string, React.ReactNode]] : []),
        ]} />
        {write && <div className="btn-row mt4"><Btn size="sm" busy={patch.busy} busyLabel="Saving" onClick={async () => { const r = await patch.run({ status: s.status === 'active' ? 'paused' : 'active' }); if (r.ok) { res.refresh(); toast(`${s.name} ${s.status === 'active' ? 'paused' : 'resumed'}. Recorded in the audit log.`); } }}>{s.status === 'active' ? 'Pause pushes' : 'Resume pushes'}</Btn></div>}
        {patch.error && <ErrorBlock title="The change was not saved" err={patch.error} next="Try again. Nothing was changed." />}
      </div>
      {redrive && (
        <div className="mt5" role="status" aria-live="polite">
          <Banner kind={poll.done ? 'success' : 'info'}>{poll.done
            ? `${redrive.n} stop${redrive.n === 1 ? '' : 's'} re-sent to ${s.name}. ${poll.value?.acknowledged ?? 0} acknowledged, ${poll.value?.dead_again ?? 0} undelivered again.`
            : `${redrive.n} stop${redrive.n === 1 ? '' : 's'} re-queued for ${s.name}. They send in order. This page updates as each is acknowledged.`}</Banner>
          {poll.deadlinePassed && !poll.done && <ErrorBlock title="The redrive is still running" err={new ApiError(0, 'timeout', '', null)} override="no final answer in 5 minutes" next="Open this page again later to see the result. Nothing was lost." />}
        </div>
      )}
      <h2 className="sec mt6">Undelivered stops (dead)</h2>
      {dead === null && <Banner kind="warning" title="Undelivered stops did not load">Shown as Not available, never as zero.</Banner>}
      {dead && dead.length === 0 && <p className="hint">Nothing is undelivered.</p>}
      {dead && dead.length > 0 && (
        <DataTable caption="Undelivered stops" rows={dead} rowKey={(d) => d.outbox_id}
          columns={[
            { key: 't', header: 'Stop recorded', render: (d) => <Time iso={d.created_at} />, primary: true },
            { key: 'f', header: 'Contact (fingerprint)', render: (d) => <code className="mono">{d.contact_fp_hint}</code> },
            { key: 'c', header: 'Channel', render: (d) => CHANNEL_FALLBACK[d.channel] ?? d.channel },
            { key: 'a', header: 'Last answer', render: lastAnswer },
            { key: 'n', header: 'Attempts', right: true, render: (d) => <span className="num">{d.attempts}</span> },
            { key: 's', header: 'Result', render: (d) => <DeliveryChip status={d.status} /> },
          ]} />
      )}
      <div className="btn-row mt5"><LinkBtn href="/systems" variant="quiet">Back to connected systems</LinkBtn></div>
      {dialog && (
        <ConfirmDialog title={`Redrive ${deadN} undelivered stop${deadN === 1 ? '' : 's'} to ${s.name}?`} confirmLabel="Redrive now" busyLabel="Redriving" reasonLabel="Reason (recorded in the audit log)" reasonRequired destructive
          body={`Do this after ${s.name} is fixed. Each stop is sent again in order. Contact checks have answered "Stop on record" for these people the whole time.`}
          failTitle="The redrive did not start" failNext="Try again. Nothing was changed."
          onClose={() => setDialog(false)}
          onConfirm={async (reason) => { try { const r = await api.systems.redrive(s.system_id, reason); setRedrive({ id: r.redrive_id, n: r.requeued }); res.refresh(); return null; } catch (e) { return e as ApiError; } }} />
      )}
    </>
  );
}

void SuccessBanner; void Chip;
