import React, { useEffect, useMemo, useState } from 'react';
import type { ApiError } from '../lib/api/client.ts';
import { allPages } from '../lib/api/client.ts';
import type { Billing, Health, SetupAnswer, SetupStepName, System } from '../lib/api/types.ts';
import { alarmCopy } from '../lib/alarms.ts';
import { CAPTURE_REFUSALS, NA } from '../lib/copy.ts';
import { FLAGS } from '../lib/flags.ts';
import { usePoll, useResource } from '../lib/hooks.ts';
import { canDo } from '../lib/roles.ts';
import { ORDER, RAIL_LABEL, chipFor } from './setup.tsx';
import { useSession } from '../lib/session.tsx';
import { fmtDateTime, fmtTime } from '../lib/format.ts';
import { Banner, Btn, CodeBlock, CopyButton, DataTable, ErrorBlock, KV, LinkBtn, NotAvailable, OrgChip, PageHead, Chip, SetupChecklist, type ChecklistItem, Skeleton, StateBlock, SuccessBanner, Tabs, Tile, Time, Meter } from '../components/ui.tsx';

type Got<T> = { ok: true; v: T } | { ok: false; e: ApiError };
async function got<T>(p: Promise<T>): Promise<Got<T>> {
  try { return { ok: true, v: await p }; } catch (e) { return { ok: false, e: e as ApiError }; }
}

const STEP_HREF: Record<SetupStepName, string> = {
  brand: '/brands', source: '/sources', wording: '/wording/new', credential: '/credentials/new', first_event: '/setup/first-event', system: '/systems/new', confirmations: '/confirmations',
};

interface Setup {
  health: Got<Health>;
  setup: Got<SetupAnswer>;
  billing: Got<Billing> | null;
  systems: Got<System[]> | null;
}

// ---- 05 Overview ----
export function Overview() {
  const { api, role, org, orgName, orgId } = useSession();
  const setupRole = canDo(role, 'first-event.send');
  const res = useResource<Setup>(async () => {
    const [health, setup, billing, systems] = await Promise.all([
      got(api.session.health()),
      got(api.setup.get()),
      role === 'admin' ? got(api.billing.get()) : null,
      got(allPages((c) => api.systems.list({ cursor: c }))),
    ]);
    return { health, setup, billing, systems } as Setup;
  }, [api, role]);
  const flagKey = `cv.setup.done.${orgId}`;
  const [celebrate, setCelebrate] = useState(false);

  const view = useMemo(() => {
    if (res.status !== 'ok') return null;
    const d = res.data;
    // the checklist is the eight steps GET /v1/setup reports: the service decides what is done, this page only draws it
    const answer = d.setup.ok ? d.setup.v : null;
    const firstEventAt = (d.health.ok ? d.health.v.first_event?.at : null) ?? answer?.steps.find((s) => s.step === 'first_event')?.evidence?.at ?? null;
    const items = answer ? ORDER.map((name) => {
      const st = answer.steps.find((x) => x.step === name);
      if (!st) return { label: RAIL_LABEL(name), done: null, href: STEP_HREF[name] };
      const mine = st.roles.includes(role as 'admin' | 'developer');
      return { label: RAIL_LABEL(name), done: st.status === null ? null : st.status === 'done' || st.status === 'skipped', href: STEP_HREF[name], chip: chipFor(st, role), primary: setupRole && mine && name === answer.current_step };
    }) : null;
    return { d, items, answer, firstEventAt };
  }, [res.status, res.data, setupRole, role]);

  const complete = !!view?.answer && view.answer.complete;
  useEffect(() => {
    if (!complete || !orgId) return;
    try { if (!localStorage.getItem(flagKey)) { setCelebrate(true); localStorage.setItem(flagKey, '1'); } } catch { /* storage unavailable: no first-time banner */ }
  }, [complete, flagKey, orgId]);

  const plan = org && 'plan' in org && org.plan ? org.plan.name : null;
  return (
    <>
      <PageHead title={complete || !view?.items ? 'Overview' : 'Welcome to ConsentVault'}
        lede={view?.items && !complete ? (role === 'compliance_viewer' ? 'Setup is still in progress. An admin finishes these steps.' : 'Finish these steps to record your first test event. About 15 minutes.') : 'Where your organization stands: policy, sealing, deliveries and usage.'}
        meta={<>{orgName} · <OrgChip status={org?.status ?? null} />{plan && <> · {plan} plan</>}</>} />
      {res.status === 'loading' && <Skeleton what="overview" rows={4} variant="tiles" />}
      {res.status === 'error' && <ErrorBlock title="The overview did not load" err={res.error} onRetry={res.reload} override="your organization's status could not be read" next="Try again. Capture from your website and systems is not affected by this page." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {view && <OverviewBody v={view} celebrate={celebrate} role={role} />}
    </>
  );
}

interface OverviewView { d: Setup; items: ChecklistItem[] | null; answer: SetupAnswer | null; firstEventAt: string | null }
function OverviewBody({ v, celebrate, role }: { v: OverviewView; celebrate: boolean; role: ReturnType<typeof useSession>['role'] }) {
  const { d, items } = v;
  const failed: string[] = [];
  const note = (name: string, g: Got<unknown> | null) => { if (g && !g.ok) failed.push(name); };
  note('Health counts', d.health); note('Setup progress', d.setup); note('Usage', d.billing); note('Systems', d.systems);
  const h = d.health.ok ? d.health.v : null;
  const noSystems = !!d.systems && d.systems.ok && d.systems.v.length === 0;
  const dead = h ? (h.dead_deliveries ?? (noSystems ? 0 : null)) : null;
  const deadSystem = d.systems && d.systems.ok ? [...d.systems.v].sort((a, b) => (b.counts?.dead ?? 0) - (a.counts?.dead ?? 0))[0] : null;
  const showUsage = role === 'admin';
  const billing = d.billing && d.billing.ok ? d.billing.v : null;
  const usageNA = !billing || !billing.used || !billing.included;
  const usageFailed = !!d.billing && (!d.billing.ok || (billing !== null && billing.plan !== null && usageNA));
  const incomplete = !!v.answer && !v.answer.complete;
  const nullTiles = (h && (h.unsealed_events_over_1h === null || dead === null)) || !d.health.ok || (showUsage && usageFailed);
  return (
    <>
      {celebrate && v.firstEventAt && <SuccessBanner>{`Setup is complete. Your first test event was recorded on ${fmtDateTime(v.firstEventAt)}.`}</SuccessBanner>}
      {h && h.alarms === null && <Banner kind="warning" title="Open alarms did not load">Not available right now, never read as none. Reload to try again.</Banner>}
      {h?.alarms && h.alarms.length > 0 && (
        <div className="mb5" role="region" aria-label="Open alarms">
          {h.alarms.map((a) => {
            const c = alarmCopy(a);
            return (
              <Banner key={`${a.name}:${a.since}`} kind="danger" title={c.title} action={c.href ? <LinkBtn href={c.href} size="sm">Open</LinkBtn> : undefined}>
                <p>{c.what}</p>
                <p className="hint">Since <Time iso={a.since} />.</p>
                <p><b>Next:</b> {c.next}</p>
              </Banner>
            );
          })}
        </div>
      )}
      {nullTiles && <Banner kind="warning" title="Some figures did not load">{`${showUsage && usageFailed ? 'Usage is not available right now. ' : ''}Figures that did not load read Not available, never zero. Everything else on this page is current.`}</Banner>}
      {items && (incomplete || celebrate) && <div className="mb5"><SetupChecklist items={items} readOnly={role === 'compliance_viewer'} /></div>}
      {items && !incomplete && !celebrate && null}
      <div className="grid g4">
        <Tile label="Events not yet sealed after 1 hour" value={h && h.unsealed_events_over_1h !== null ? <span className="num">{h.unsealed_events_over_1h}</span> : null} sub={h && h.unsealed_events_over_1h !== null ? <>Checked <Time iso={h.evaluated_at} /></> : 'Count did not load'} />
        <Tile label="Undelivered stops (dead)" alert={!!dead && dead > 0} value={dead !== null ? <span className="num">{dead}</span> : null}
          sub={dead === null ? 'Count did not load' : h && h.dead_deliveries === null ? 'No systems are connected, so no stops are waiting' : dead > 0 && deadSystem ? `${deadSystem.name}: review and redrive` : dead > 0 ? 'Review in Connected systems' : 'Nothing waiting'}
          href={dead && dead > 0 ? (deadSystem ? `/systems/${deadSystem.system_id}` : '/systems') : undefined} action={dead && dead > 0 ? 'Review in Connected systems' : undefined} />
        {showUsage && <Tile label="Events this period" value={!usageNA ? <span className="num">{billing!.used!.events.toLocaleString('en-US')}</span> : billing && billing.plan === null ? 'No plan yet' : null} of={!usageNA ? `of ${billing!.included!.events.toLocaleString('en-US')}` : undefined}
          sub={!usageNA ? `Contact checks: ${billing!.used!.gate_checks.toLocaleString('en-US')} of ${billing!.included!.gate_checks.toLocaleString('en-US')}` : billing && billing.plan === null ? 'Usage counts once you choose a plan' : 'Usage count did not load'} />}
      </div>
      {showUsage && !usageNA && (
        <div className="card mt5"><h2>Usage this period</h2>
          <Meter label="Events this period" used={billing!.used!.events} included={billing!.included!.events} />
          <Meter label="Contact checks this period" used={billing!.used!.gate_checks} included={billing!.included!.gate_checks} />
        </div>
      )}
      {failed.length > 0 && <p className="hint mt4">{`Not loaded: ${failed.join(', ')}.`}</p>}
    </>
  );
}

// ---- 06 First test event ----
function waitingFor(prereq: { label: string; done: boolean | null; href: string; button: string }[]) {
  return prereq.filter((p) => p.done !== true);
}

export function FirstEvent() {
  const { api, orgName } = useSession();
  const load = useResource(async () => {
    const [brands, sources, wording, credentials] = await Promise.all([
      allPages((c) => api.brands.list({ cursor: c })), allPages((c) => api.sources.list({ cursor: c })),
      allPages((c) => api.disclosures.list({ cursor: c })), allPages((c) => api.credentials.list({ cursor: c })),
    ]);
    return { brands, sources, wording, credentials };
  }, [api]);
  const [tab, setTab] = useState('server');
  const d = load.status === 'ok' ? load.data : null;
  const source = d ? d.sources.find((s) => s.status === 'active' && s.last_event_at === null) ?? d.sources.find((s) => s.status === 'active') ?? null : null;
  const brand = d && source ? d.brands.find((b) => source.brand_ids.includes(b.brand_id)) ?? d.brands[0] : d?.brands[0] ?? null;
  const wording = d ? d.wording.find((w) => !w.superseded_by_sha256) ?? null : null;
  const cred = d ? d.credentials.find((c) => c.scope === 'capture' && !c.revoked_at && (!source || c.source_id === source.source_id)) ?? d.credentials.find((c) => c.scope === 'capture' && !c.revoked_at) ?? null : null;
  const prereq = d ? [
    { label: 'Brand', done: d.brands.length > 0, href: '/brands', button: 'Add a brand', value: brand?.display_name ?? null },
    { label: 'Capture source', done: !!source, href: '/sources', button: 'Add a capture source', value: source?.name ?? null },
    { label: 'Wording', done: !!wording, href: '/wording/new', button: 'Register your consent wording', value: wording ? `Version ${wording.version_label}` : null },
    { label: 'Credential', done: !!cred, href: '/credentials/new', button: 'Issue a capture credential', value: cred?.name ?? null },
  ] : [];
  const missing = waitingFor(prereq);
  const ready = d && missing.length === 0;
  const poll = usePoll(() => api.sources.list(), { intervalMs: 5000, deadlineMs: 15 * 60 * 1000, enabled: !!ready, until: (p) => p.items.some((s) => s.last_event_at && s.last_event_sealed === true) });
  const seen = poll.value ? poll.value.items.find((s) => s.last_event_at) ?? null : null;
  const channels = wording?.channels ?? ['sms'];
  const purposes = wording?.purposes ?? ['marketing'];
  const snippet = ready ? [
    'curl -X POST https://capture.consentvault.ai/v1/events \\',
    '  -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \\',
    `  -d '${JSON.stringify({ contact: '+15555550100', event_type: 'grant', channels: [channels[0]], purposes: [purposes[0]], checked: true, brand_ids: [brand!.brand_id], disclosure_sha256: wording!.sha256, source_id: source!.source_id })}'`,
  ].join('\n') : '';
  const words = ['Zero', 'One', 'Two', 'Three', 'Four'];
  return (
    <>
      <PageHead title="Send your first test event" lede="Use a test phone number you control. The event is real evidence in your ledger and cannot be deleted, so do not use a customer's number." />
      {load.status === 'loading' && <Skeleton what="your setup" rows={3} />}
      {load.status === 'error' && <ErrorBlock title="Your setup did not load" err={load.error} next="Try again. Nothing was changed." actions={<Btn onClick={load.reload}>Try again</Btn>} />}
      {d && missing.length > 0 && (
        <StateBlock kind="empty" title={`${words[missing.length]} ${missing.length === 1 ? 'step comes' : 'steps come'} first`} icon="i-vault"
          actions={<LinkBtn href={missing[0].href} variant="primary">{missing[0].button}</LinkBtn>}>
          {missing.length === 2 && missing[0].label === 'Wording' && missing[1].label === 'Credential' ? 'A grant needs registered wording, and sending needs a credential. You have neither yet.' : `Before you can send a test event, finish: ${missing.map((m) => m.label.toLowerCase()).join(', ')}.`}
        </StateBlock>
      )}
      {d && prereq.length > 0 && (
        <ul className="prereq card">{prereq.map((p) => (
          <li key={p.label}><span>{p.label}{p.value ? `: ${p.value}` : ''}</span> <Chip tone={p.done ? 'st-success' : 'st-neutral'} icon={p.done ? 'i-ok' : 'i-dash'}>{p.done ? 'Done' : 'To do'}</Chip></li>
        ))}</ul>
      )}
      {ready && (
        <>
          <h2 className="sec mt5">Send it</h2>
          <p>Server credential (get a token first) or site key (from your web form).</p>
          <Tabs label="How you send" current={tab} onSelect={setTab} tabs={[{ id: 'server', label: 'Server token' }, { id: 'site', label: 'Site key' }]} />
          {tab === 'server' || FLAGS.gap_site_key_header
            ? <><CodeBlock code={snippet} label="Command to send a test event" /><div className="btn-row mt4"><CopyButton text={snippet} label="Copy command" size="sm" /></div></>
            : <Banner kind="info" title="Site key command: Not available">The header that carries a site key is not part of the capture contract yet. A website form sends through the capture script on your site, with the site key issued under Credentials.</Banner>}
          <div className="mt5" role="status" aria-live="polite">
            {!seen && !poll.deadlinePassed && <Banner kind="info" role="status">{`Waiting for your first event from ${source!.name}. This box updates every 5 seconds for 15 minutes.`}</Banner>}
            {seen && seen.last_event_sealed !== true && (
              <><Banner kind="warning" title={`Event received at ${seen.last_event_at ? fmtTime(seen.last_event_at) : NA} from ${seen.name}.`}>Sealing is pending: the outside timestamp is usually added within an hour. Nothing else is needed from you.</Banner>
                <KV rows={[['Sequence', String(seen.last_event_seq ?? NA)], ['Seal', 'Pending']]} /></>
            )}
            {seen && seen.last_event_sealed === true && (
              <SuccessBanner title="Your first test event is recorded.">{`Received ${seen.last_event_at ? fmtDateTime(seen.last_event_at) : NA}. Sequence ${seen.last_event_seq ?? NA}, sealed.`}</SuccessBanner>
            )}
          </div>
          {seen && seen.last_event_sealed === true && <div className="btn-row mt4"><LinkBtn href="/evidence" variant="secondary">Look up this test contact</LinkBtn><LinkBtn href="/" variant="primary">Back to overview</LinkBtn></div>}
          {!seen && poll.deadlinePassed && (
            <div className="mt5"><StateBlock kind="error" title="No event arrived in 15 minutes" cause={`Nothing from ${source!.name} reached your ledger in that window.`} next="Check the answer your command printed against the table below, then send again."
              actions={<><Btn onClick={poll.restart}>Keep waiting another 15 minutes</Btn><LinkBtn href="/credentials" variant="secondary">Open credentials</LinkBtn></>} /></div>
          )}
          <h2 className="sec mt6">If your command was refused</h2>
          <DataTable caption="Refusals and what to do" rows={CAPTURE_REFUSALS} rowKey={(r) => r.answer}
            columns={[{ key: 'a', header: 'Answer', render: (r) => <code className="mono">{r.answer}</code>, primary: true }, { key: 'm', header: 'What it means', render: (r) => r.means.replace('{org}', orgName) }, { key: 't', header: 'What to do', render: (r) => r.todo }]} />
        </>
      )}
      {d && missing.length > 0 && (
        <>
          <h2 className="sec mt6">If your command was refused</h2>
          <DataTable caption="Refusals and what to do" rows={CAPTURE_REFUSALS} rowKey={(r) => r.answer}
            columns={[{ key: 'a', header: 'Answer', render: (r) => <code className="mono">{r.answer}</code>, primary: true }, { key: 'm', header: 'What it means', render: (r) => r.means.replace('{org}', orgName) }, { key: 't', header: 'What to do', render: (r) => r.todo }]} />
        </>
      )}
    </>
  );
}

void NotAvailable;
