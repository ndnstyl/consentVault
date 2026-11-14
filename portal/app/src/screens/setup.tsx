import React, { useEffect, useRef, useState } from 'react';
import { ApiError, allPages } from '../lib/api/client.ts';
import type { SetupAnswer, SetupStep, SetupStepName } from '../lib/api/types.ts';
import { NA } from '../lib/copy.ts';
import { fmtDateTime, fmtDate } from '../lib/format.ts';
import { useAction, usePoll, useResource } from '../lib/hooks.ts';
import { useRouter } from '../lib/router.tsx';
import { canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { ConfirmDialog } from '../components/Dialog.tsx';
import type { Embedded } from '../components/ui.tsx';
import { WordingNew } from './wording.tsx';
import { CredentialNew } from './config.tsx';
import { PolicyNew } from './policies.tsx';
import { SystemNew } from './systems.tsx';
import { Banner, Btn, Chip, ErrorBlock, LinkBtn, PageHead, Skeleton, StateBlock, SuccessBanner, TextField } from '../components/ui.tsx';

export const ORDER: SetupStepName[] = ['brand', 'source', 'wording', 'credential', 'first_event', 'policy', 'system', 'confirmations'];
const LABEL: Record<SetupStepName, string> = {
  brand: 'Add a brand', source: 'Add a capture source', wording: 'Register your consent wording', credential: 'Issue a capture credential',
  first_event: 'Send a test event', policy: 'Approve a policy', system: 'Connect a system that receives stops', confirmations: 'Turn on confirmation messages',
};
export const RAIL_LABEL = (s: SetupStepName) => (s === 'system' || s === 'confirmations' ? `${LABEL[s]} (optional)` : LABEL[s]);
const PARTIAL_CAUSE: Record<SetupStepName, string> = {
  brand: 'the brand list', source: 'the source list', wording: 'the wording list', credential: 'the credential list', first_event: 'the first event check', policy: 'the policy list', system: 'the connected systems list', confirmations: 'the confirmation rules',
};
const num = (s: SetupStepName) => ORDER.indexOf(s) + 1;
const done = (s: SetupStep) => s.status === 'done' || s.status === 'skipped';

function list(nums: number[]): string {
  if (nums.length === 1) return String(nums[0]);
  return `${nums.slice(0, -1).join(', ')} and ${nums[nums.length - 1]}`;
}
function prefixDone(steps: SetupStep[]): number {
  let k = 0;
  for (const s of steps) { if (done(s)) k++; else break; }
  return k;
}

// ---------- 24 Setup walkthrough ----------
export function Setup() {
  const { api, role, orgName, user, status } = useSession();
  const { search, navigate } = useRouter();
  const res = useResource(() => api.setup.get(), [api]);
  const paramStep = ORDER.find((s) => s === search.get('step')) ?? null;
  const [selected, setSelected] = useState<SetupStepName | null>(paramStep);
  const [began, setBegan] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  const moved = useRef(false);
  useEffect(() => { setSelected(paramStep); }, [paramStep]);
  useEffect(() => { if (moved.current) heading.current?.focus(); }, [selected]);

  const go = (s: SetupStepName) => {
    moved.current = true;
    setSelected(s); setBegan(true);
    navigate(`/setup?step=${s}`, { replace: true });
  };

  const first = user?.display_name.split(' ')[0] ?? '';
  const a: SetupAnswer | null = res.status === 'ok' ? res.data : null;
  const steps = a?.steps ?? [];
  const byName = (n: SetupStepName) => steps.find((s) => s.step === n);
  const current = a?.current_step ?? null;
  const untouched = !!a && a.steps.every((s) => s.status === 'to_do' || s.status === 'blocked');
  const showWelcome = !!a && untouched && !began && paramStep === null;
  const showComplete = !!a && current === null && selected === null && !began;
  const active: SetupStepName = selected ?? current ?? 'brand';

  const title = showWelcome ? `Welcome to ConsentVault, ${first}` : showComplete ? 'Setup is complete' : `Set up ${orgName}`;
  const lede = showWelcome ? undefined : showComplete ? undefined : 'Progress saves as you go. Leave any time and come back here or to the overview.';

  return (
    <>
      <PageHead title={title} lede={lede} />
      {res.status === 'loading' && <Skeleton what="setup progress" rows={4} />}
      {res.status === 'error' && <ErrorBlock title="Setup progress did not load" err={res.error} next="Try again. Nothing you finished is lost; every step saves when you do it." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {a && showWelcome && (
        <div className="card">
          <p>{`You joined ${orgName} as ${role === 'admin' ? 'an admin' : 'a developer'}. Eight steps take you from here to your first recorded event and your first stop delivered. Most people finish the first five in about 25 minutes.`}</p>
          <ol className="step-list">{ORDER.map((s) => <li key={s}>{RAIL_LABEL(s)}</li>)}</ol>
          {status === 'trial' && <p className="hint">Your organization is in trial. Test events are recorded and labelled as trial records.</p>}
          <div className="btn-row mt4"><Btn variant="primary" onClick={() => go(current ?? 'brand')}>Start with step 1</Btn><LinkBtn href="/">Go to the overview instead</LinkBtn></div>
        </div>
      )}
      {a && showComplete && <Complete a={a} />}
      {a && !showWelcome && !showComplete && (
        <>
          {role === 'developer' && <DeveloperNote steps={steps} role={role} />}
          <Rail steps={steps} active={active} role={role} onSelect={go} />
          <Panel key={active} step={byName(active)!} steps={steps} a={a} reload={res.reload} setAnswer={res.setData} refresh={res.refresh} go={go} welcomeBack={selected === null && paramStep === null && prefixDone(steps) > 0 && active === current} heading={heading} />
        </>
      )}
    </>
  );
}

export function chipFor(s: SetupStep, role: string | null): { text: string; tone: string; icon: string } {
  if (s.status === null) return { text: NA, tone: 'ev-na', icon: 'i-warn' };
  if (s.status === 'done') return { text: 'Done', tone: 'st-success', icon: 'i-ok' };
  if (s.status === 'skipped') return { text: 'Skipped', tone: 'st-neutral', icon: 'i-dash' };
  if (role && !s.roles.includes(role as 'admin' | 'developer')) return { text: 'Waiting on an admin', tone: 'st-warning', icon: 'i-warn' };
  if (s.status === 'blocked') return s.blocked_reason === 'org_suspended' ? { text: 'Paused', tone: 'st-warning', icon: 'i-pause' } : { text: s.blocked_reason?.startsWith('needs:') ? `Needs step ${num(s.blocked_reason.slice(6) as SetupStepName)}` : 'Paused', tone: 'st-warning', icon: 'i-pause' };
  return { text: 'To do', tone: 'st-neutral', icon: 'i-dash' };
}

function Rail({ steps, active, role, onSelect }: { steps: SetupStep[]; active: SetupStepName; role: string | null; onSelect: (s: SetupStepName) => void }) {
  return (
    <>
      <div className="stepsel">
        <label htmlFor="step-select" className="hint">Step</label>
        <select id="step-select" className="select" value={active} onChange={(e) => onSelect(e.target.value as SetupStepName)}>
          {steps.map((s) => <option key={s.step} value={s.step}>{`${num(s.step)}. ${RAIL_LABEL(s.step)}`}</option>)}
        </select>
      </div>
      <ol className="rail" aria-label="Setup steps">
        {steps.map((s) => {
          const c = chipFor(s, role);
          return (
            <li key={s.step} data-current={s.step === active}>
              <button type="button" className="step" aria-current={s.step === active ? 'step' : undefined} onClick={() => onSelect(s.step)}>{`${num(s.step)}. ${RAIL_LABEL(s.step)}`}</button>
              <Chip tone={c.tone} icon={c.icon}>{c.text}</Chip>
            </li>
          );
        })}
      </ol>
    </>
  );
}

function DeveloperNote({ steps, role }: { steps: SetupStep[]; role: string }) {
  const open = steps.filter((s) => !done(s) && s.status !== null);
  const admin = open.filter((s) => !s.roles.includes(role as 'developer')).map((s) => num(s.step));
  const mine = open.filter((s) => s.roles.includes(role as 'developer')).map((s) => num(s.step));
  if (admin.length === 0) return null;
  const fe = steps.find((s) => s.step === 'first_event');
  const needsWording = fe?.blocked_reason === 'needs:wording';
  return (
    <Banner kind="info" title={`Step${admin.length === 1 ? '' : 's'} ${list(admin)} need${admin.length === 1 ? 's' : ''} an admin.`}>
      {mine.length ? `You can do step${mine.length === 1 ? '' : 's'} ${list(mine)}.` : 'Nothing is waiting on you right now.'}{needsWording && mine.includes(5) ? ' Step 5 needs step 3 first, because a test event names the wording it showed.' : ''}
    </Banner>
  );
}

function Complete({ a }: { a: SetupAnswer }) {
  const fe = a.steps.find((s) => s.step === 'first_event');
  const pol = a.steps.find((s) => s.step === 'policy');
  const conf = a.steps.find((s) => s.step === 'confirmations');
  return (
    <>
      <p>{fe?.evidence ? `Your first event was recorded and sealed on ${fmtDateTime(fe.evidence.at)}.` : ''}{pol?.evidence ? ` Policy version ${pol.evidence.id} is in force.` : ''}</p>
      <ul className="stack card" style={{ listStyle: 'none' }}>
        {a.steps.map((s) => <li key={s.step}><Chip tone={s.status === 'done' ? 'st-success' : 'st-neutral'} icon={s.status === 'done' ? 'i-ok' : 'i-dash'}>{s.status === 'done' ? 'Done' : 'Skipped'}</Chip> {LABEL[s.step]}</li>)}
      </ul>
      <div className="btn-row mt4"><LinkBtn href="/records" variant="primary">Open records</LinkBtn>{conf && conf.status !== 'done' && <LinkBtn href="/confirmations">Turn on confirmation messages</LinkBtn>}</div>
    </>
  );
}

// ---------- one step ----------
interface PanelProps {
  step: SetupStep; steps: SetupStep[]; a: SetupAnswer; reload: () => void; refresh: () => void; setAnswer: (v: SetupAnswer) => void;
  go: (s: SetupStepName) => void; welcomeBack: boolean; heading: React.RefObject<HTMLHeadingElement>;
}
function Panel({ step, steps, a, refresh, setAnswer, go, welcomeBack, heading }: PanelProps) {
  const { api, role, orgName, status } = useSession();
  const n = num(step.step);
  const next = ORDER[n] as SetupStepName | undefined;
  const prev = n > 1 ? ORDER[n - 2] : null;
  const mine = !!role && step.roles.includes(role as 'admin' | 'developer');
  const skippable = (step.step === 'system' && canDo(role, 'setup.skip')) || (step.step === 'confirmations' && role === 'admin');
  const [skipping, setSkipping] = useState(false);
  const unskip = useAction(() => api.setup.unskip(step.step));
  const [notice, setNotice] = useState<string | null>(null);
  const [nextLink, setNextLink] = useState<string | null>(null);
  const k = prefixDone(steps);
  const doneBefore = k === 0 ? '' : k === 1 ? 'Step 1 stays done.' : `Steps 1 to ${k} stay done.`;

  return (
    <div className="card stepbox">
      {welcomeBack && <Banner kind="info" title="Welcome back.">{`${k === 1 ? 'Step 1 is done' : k === 2 ? 'Steps 1 and 2 are done' : `Steps 1 to ${k} are done`}. You are on step ${n}.`}</Banner>}
      <p className="hint">{`Step ${n} of 8`}</p>
      <h2 ref={heading} tabIndex={-1}>{`${n}. ${LABEL[step.step]}`}</h2>

      {step.status === null && (
        <>
          <Banner kind="warning" title={`Step ${n} could not be checked.`} action={<Btn size="sm" onClick={refresh}>Check again</Btn>}>{`Cause: ${PARTIAL_CAUSE[step.step]} did not answer (503 service_unavailable). It may already be done. Next: try again; other steps still work.`}</Banner>
          <p className="na">Status not available until the check answers.</p>
        </>
      )}
      {step.status === 'done' && <SuccessLine step={step} />}
      {step.status === 'skipped' && (
        <Banner kind="info" title="Skipped" action={skippable ? <Btn size="sm" busy={unskip.busy} busyLabel="Working" onClick={async () => { const r = await unskip.run(); if (r.ok) refresh(); }}>Turn it back on</Btn> : undefined}>
          {`${step.skipped_by ? `Skipped by ${step.skipped_by}${step.skipped_at ? ` on ${fmtDate(step.skipped_at)}` : ''}. ` : ''}${step.skip_reason ? `Reason: ${step.skip_reason}. ` : ''}You can do this later.`}
        </Banner>
      )}
      {unskip.error && <ErrorBlock title="The step was not turned back on" err={unskip.error} next="Ask an admin to turn it back on. Nothing was changed." />}
      {step.status === 'blocked' && step.blocked_reason === 'org_suspended' && (
        <Banner kind="warning" title={`${step.step === 'credential' ? 'New credentials are' : 'Connecting a system is'} paused while ${orgName} is suspended.`} action={role === 'admin' ? <LinkBtn href="/billing" size="sm">Open billing</LinkBtn> : undefined}>{`${doneBefore} Resolve billing to continue with step ${n}.`.trim()}</Banner>
      )}
      {step.status === 'blocked' && step.blocked_reason?.startsWith('needs:') && (
        <Banner kind="info" title={`This step needs step ${num(step.blocked_reason.slice(6) as SetupStepName)} first.`} action={<Btn size="sm" onClick={() => go(step.blocked_reason!.slice(6) as SetupStepName)}>{`Go to step ${num(step.blocked_reason.slice(6) as SetupStepName)}`}</Btn>}>A test event names the wording it showed, so register your wording first.</Banner>
      )}
      {(step.status === 'to_do' || step.status === 'blocked') && !mine && (
        <Banner kind="info" title="Waiting on an admin">{`This step needs an admin of ${orgName}. Nothing here changes until they do it.`}</Banner>
      )}
      {notice && <SuccessBanner>{notice}</SuccessBanner>}
      {nextLink && <div className="btn-row mb4"><LinkBtn href={nextLink} variant="primary">Review and approve this draft</LinkBtn></div>}
      {step.status === 'to_do' && mine && <StepBody step={step.step} a={a} refresh={refresh} setAnswer={setAnswer} go={go} suspended={status === 'suspended'} onNotice={setNotice} embedded={{ onDone: (t, href) => { setNotice(t); setNextLink(href ?? null); refresh(); } }} />}

      <div className="btn-row mt5">
        {prev && <Btn onClick={() => go(prev)}>Back</Btn>}
        {skippable && step.status === 'to_do' && <Btn onClick={() => setSkipping(true)}>Skip for now</Btn>}
        {next && done(step) && <Btn variant="primary" onClick={() => go(next)}>{`Continue to step ${n + 1}: ${LABEL[next]}`}</Btn>}
        {next && step.status === null && <Btn onClick={() => go(next)}>{`Go to step ${n + 1}`}</Btn>}
        <LinkBtn href="/" variant="quiet">Leave setup</LinkBtn>
      </div>
      {skipping && (
        <ConfirmDialog title={step.step === 'system' ? 'Skip connecting a system for now?' : 'Skip turning on confirmation messages for now?'} confirmLabel="Skip for now" busyLabel="Skipping" reasonLabel="Reason (optional)"
          body={<p>{step.step === 'system' ? 'Stops are still recorded and shown in Records. No other system will hear about them until you connect one. You can do this later from the overview or Connected systems.' : 'Consents are still recorded and nothing is sent to the person. You can turn confirmation messages on later from Confirmation messages.'}</p>}
          failTitle="The step was not skipped" failNext="Try again. Nothing was changed."
          onClose={() => setSkipping(false)}
          onConfirm={async (reason) => { try { await api.setup.skip(step.step, reason || undefined); refresh(); return null; } catch (e) { return e as ApiError; } }} />
      )}
    </div>
  );
}

function SuccessLine({ step }: { step: SetupStep }) {
  const e = step.evidence;
  const word: Record<SetupStepName, string> = {
    brand: 'A brand is set up.', source: 'A capture source is set up.', wording: 'Your consent wording is registered.', credential: 'A capture credential is active.',
    first_event: 'Your first event was recorded.', policy: 'A policy is in force.', system: 'A connected system answered its test push.', confirmations: 'A confirmation message rule is on.',
  };
  return <p><Chip tone="st-success" icon="i-ok">Done</Chip> {word[step.step]}{e ? ` ${fmtDateTime(e.at)}.` : ''}</p>;
}

function StepBody({ step, a, refresh, setAnswer, go, suspended, onNotice, embedded }: { embedded: Embedded; step: SetupStepName; a: SetupAnswer; refresh: () => void; setAnswer: (v: SetupAnswer) => void; go: (s: SetupStepName) => void; suspended: boolean; onNotice: (t: string) => void }) {
  void go; void a;
  switch (step) {
    case 'brand': return <BrandForm refresh={refresh} onNotice={onNotice} />;
    case 'source': return <><p>A source is where consents come from: a website form or a server. Add one for each place that sends you consents.</p><LinkBtn href="/sources" variant="primary">Add a capture source</LinkBtn></>;
    case 'wording': return <><p>Paste the exact words shown beside your consent checkbox. Register every version your forms have shown, oldest first, so older records point at the words those people saw. Wording is stored byte for byte; a change is a new version.</p><WordingNew embedded={embedded} /></>;
    case 'credential': return suspended ? null : <><p>A credential lets one source send events. A site key goes in your web form; a public key is for a server.</p><CredentialNew embedded={embedded} /></>;
    case 'first_event': return <FirstEvent setAnswer={setAnswer} refresh={refresh} />;
    case 'policy': return <><p>Your policy says what your systems do with each evidence status: proceed or hold. Until one is approved, gate checks return evidence status only. ConsentVault applies the policy as written and does not decide what the law allows.</p><PolicyNew embedded={embedded} /></>;
    case 'system': return suspended ? null : <><p>A connected system hears about stops so it stops contacting the person. Connect your dialer, CRM or texting platform.</p><SystemNew embedded={embedded} /></>;
    case 'confirmations': return <><p>When a new consent arrives, send the person one message from your own email domain or texting number that repeats what they agreed to, when, and how to stop.</p><LinkBtn href="/confirmations" variant="primary">Turn on confirmation messages</LinkBtn></>;
  }
}

function BrandForm({ refresh, onNotice }: { refresh: () => void; onNotice: (t: string) => void }) {
  const { api } = useSession();
  const [name, setName] = useState('');
  const create = useAction((n: string) => api.brands.create(n));
  const err = create.error;
  return (
    <form onSubmit={async (e) => { e.preventDefault(); if (!name.trim()) return; const r = await create.run(name.trim()); if (r.ok) { onNotice(`Brand added. ${r.value.display_name} is ready for your capture sources.`); setName(''); refresh(); } }} noValidate>
      <p>A brand is the name your customers know you by. Each consent names the brand it was given to.</p>
      {err && <ErrorBlock title="Your brand was not added" err={err} next="Use a different name, or continue with the existing brand." />}
      <TextField label="Brand name" name="brand-name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />
      <Btn type="submit" variant="primary" busy={create.busy} busyLabel="Adding">Add brand</Btn>
    </form>
  );
}

function FirstEvent({ setAnswer, refresh }: { setAnswer: (v: SetupAnswer) => void; refresh: () => void }) {
  const { api } = useSession();
  const src = useResource(() => allPages((c) => api.sources.list({ cursor: c })).catch(() => []), [api]);
  const poll = usePoll<SetupAnswer>(async () => { const x = await api.setup.get(); setAnswer(x); return x; }, { intervalMs: 5000, deadlineMs: 15 * 60 * 1000, until: (x) => x.steps.find((s) => s.step === 'first_event')?.status === 'done' });
  const name = src.status === 'ok' && src.data[0] ? src.data[0].name : 'your capture source';
  const checkNow = useAction(async () => { const x = await api.setup.get(); setAnswer(x); });
  return (
    <>
      <p>Submit your own form with a phone number and email you control, or run the command. Test events are permanent evidence and are labelled as trial records.</p>
      <LinkBtn href="/setup/first-event">Open the command and refusal table</LinkBtn>
      <div className="mt4" role="status" aria-live="polite">
        {!poll.deadlinePassed && <Banner kind="info" title={`Waiting for your first event from ${name}.`}>Checking every 5 seconds for 15 minutes. You can leave and come back; the step finishes on its own when the event arrives.</Banner>}
        {poll.deadlinePassed && <StateBlock kind="error" title="No event arrived in 15 minutes" cause={`Nothing from ${name} reached your ledger in that window.`} next="Check the answer your command printed, then send again." actions={<Btn onClick={poll.restart}>Keep waiting another 15 minutes</Btn>} />}
      </div>
      <div className="btn-row mt4"><Btn busy={checkNow.busy} busyLabel="Checking" onClick={async () => { await checkNow.run(); refresh(); }}>Check now</Btn></div>
    </>
  );
}
