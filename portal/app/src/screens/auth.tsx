import React, { useEffect, useRef, useState } from 'react';
import { ApiError } from '../lib/api/client.ts';
import type { InviteLookup, Membership, Plan, SessionAnswer } from '../lib/api/types.ts';
import { causeLine, ORG_STATUS_LABEL } from '../lib/copy.ts';
import { useAction, usePoll, useResource } from '../lib/hooks.ts';
import { Link, useRouter } from '../lib/router.tsx';
import { ROLE_LABEL } from '../lib/roles.ts';
import { safeReturn, useSession } from '../lib/session.tsx';
import { fmtDate, fmtMoney, fmtNum } from '../lib/format.ts';
import { Banner, Btn, Chip, ErrorBlock, KV, LinkBtn, NotAvailable, OrgChip, Skeleton, StateBlock, Time } from '../components/ui.tsx';

function CenteredCard({ children, wide }: { children: React.ReactNode; wide?: boolean }) {
  return (
    <div className="centered">
      <Link className="brand" href="/"><i aria-hidden="true" />CONSENTVAULT</Link>
      <div className={wide ? 'cc wide' : 'cc'}><div className="card">{children}</div></div>
    </div>
  );
}

function useHeadingFocus(dep: unknown) {
  const ref = useRef<HTMLHeadingElement>(null);
  useEffect(() => { ref.current?.focus(); }, [dep]);
  return ref;
}

const FOOTER = (
  <p className="hint mt4">
    <a href="https://consentvault.ai/terms" target="_blank" rel="noopener noreferrer">Terms of Service (opens in a new tab)</a>
    {' · '}
    <a href="https://consentvault.ai/privacy" target="_blank" rel="noopener noreferrer">Privacy Policy (opens in a new tab)</a>
  </p>
);

// ---- 01 Sign in ----
export function SignIn() {
  const { search } = useRouter();
  const ret = safeReturn(search.get('return'));
  const expired = search.get('reason') === 'expired';
  const h = useHeadingFocus(expired);
  const q = (m: string) => `/auth/login?method=${m}&return=${encodeURIComponent(ret)}`;
  return (
    <CenteredCard>
      {expired && <Banner kind="warning" title="Your session ended">Your session ended after 8 hours. Sign in again to continue. Anything you had not saved is kept on this device until you return.</Banner>}
      <h1 ref={h} tabIndex={-1}>Sign in to ConsentVault</h1>
      <p>Use a passkey, or sign in with your company account if your organization has connected one.</p>
      <div className="btn-col">
        <a className="btn btn-primary" href={q('passkey')}>{expired ? 'Sign in again with a passkey' : 'Sign in with a passkey'}</a>
        <a className="btn btn-secondary" href={q('sso')}>Sign in with your company</a>
      </div>
      <p className="hint mt4">Hosted by WorkOS under the ConsentVault brand. No password is ever asked for or stored.</p>
      {FOOTER}
    </CenteredCard>
  );
}

// ---- 01 Sign-in callback ----
type CbState =
  | { k: 'loading' } | { k: 'success'; org: string }
  | { k: 'noorg'; email: string } | { k: 'factor' } | { k: 'error'; err: ApiError };

export function Callback() {
  const { api, selectOrg, signOut } = useSession();
  const { navigate, search } = useRouter();
  const [s, setS] = useState<CbState>({ k: 'loading' });
  const [nonce, setNonce] = useState(0);
  const h = useHeadingFocus(s.k);
  useEffect(() => {
    let live = true;
    setS({ k: 'loading' });
    (async () => {
      let ans: SessionAnswer;
      try { ans = await api.session.get(); }
      catch (e) {
        if (!live) return;
        const err = e as ApiError;
        setS(err.code === 'second_factor_required' ? { k: 'factor' } : { k: 'error', err });
        return;
      }
      if (!live) return;
      if (ans.items.length === 0) { setS({ k: 'noorg', email: ans.user.email }); return; }
      try { sessionStorage.setItem('cv.session.started', String(Date.now())); } catch { /* storage unavailable: the session clock starts at first load */ }
      if (ans.items.length > 1) { setS({ k: 'success', org: '' }); navigate('/choose-org', { replace: true }); return; }
      const err = await selectOrg(ans.items[0].org_id);
      if (!live) return;
      if (err) { setS({ k: 'error', err }); return; }
      setS({ k: 'success', org: ans.items[0].name });
      navigate(safeReturn(search.get('return')), { replace: true });
    })();
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce]);
  const again = <a className="btn btn-primary" href={`/auth/login?return=${encodeURIComponent(safeReturn(search.get('return')))}`}>Sign in again</a>;
  return (
    <CenteredCard>
      {s.k === 'loading' && <div role="status" aria-busy="true"><h1 ref={h} tabIndex={-1}>Signing you in</h1><p>Checking your sign-in with WorkOS.</p></div>}
      {s.k === 'success' && <div role="status"><h1 ref={h} tabIndex={-1}>Signed in</h1><p>{s.org ? `Opening ${s.org}.` : 'Opening your organizations.'}</p></div>}
      {s.k === 'noorg' && (
        <div role="alert"><h1 ref={h} tabIndex={-1}>Your account is not a member of any organization</h1>
          <p><b>Cause:</b> {`You signed in as ${s.email}, and no organization on ConsentVault lists that address as a member.`}</p>
          <p><b>Next:</b> Ask your organization&apos;s admin to invite this address, or sign in with the address your invitation was sent to.</p>
          <div className="btn-row">{again}<button type="button" className="btn btn-secondary" onClick={signOut}>Sign out</button></div></div>
      )}
      {s.k === 'factor' && (
        <div role="alert"><h1 ref={h} tabIndex={-1}>Your sign-in needs a second factor</h1>
          <p><b>Cause:</b> Your sign-in shows no passkey or second factor. ConsentVault requires a passkey or two-step verification on every sign-in.</p>
          <p><b>Next:</b> Turn on two-step verification with your sign-in provider, or use a passkey, then sign in again.</p>
          <div className="btn-row"><a className="btn btn-primary" href="/auth/login?method=passkey">Sign in with a passkey</a>{again}</div></div>
      )}
      {s.k === 'error' && (
        <div role="alert"><h1 ref={h} tabIndex={-1}>Sign-in did not finish</h1>
          <p><b>Cause:</b> {s.err.code === 'timeout' || s.err.code === 'unreachable' ? 'The sign-in service did not answer within 15 seconds (WorkOS unreachable).' : causeLine(s.err.status, s.err.code)}</p>
          <p><b>Next:</b> Wait a minute and sign in again. Nothing was changed in your organization.</p>
          <div className="btn-row">{again}<Btn onClick={() => setNonce((n) => n + 1)}>Check again</Btn></div></div>
      )}
    </CenteredCard>
  );
}

// ---- 02 Invitation ----
type InvState =
  | { k: 'loading' } | { k: 'ok'; inv: InviteLookup } | { k: 'joined'; m: Membership } | { k: 'wrong'; hint: string; email: string | null; inv: InviteLookup | null } | { k: 'fail'; err: ApiError };

export function Invite() {
  const { api, signOut } = useSession();
  const { search, navigate } = useRouter();
  const token = search.get('token');
  const [s, setS] = useState<InvState>({ k: 'loading' });
  const h = useHeadingFocus(s.k);
  const accept = useAction(async () => api.invites.accept(token ?? ''));
  useEffect(() => {
    if (!token) return;
    let live = true;
    api.invites.lookup(token).then((inv) => { if (live) setS({ k: 'ok', inv }); }, (e) => { if (live) setS({ k: 'fail', err: e as ApiError }); });
    return () => { live = false; };
  }, [api, token]);
  if (!token) {
    return (
      <CenteredCard>
        <div role="alert"><h1 ref={h} tabIndex={-1}>This link has no invitation in it</h1>
          <p><b>Cause:</b> The address you opened is missing its invitation code. Links can break when copied from some email apps.</p>
          <p><b>Next:</b> Open the link straight from the invitation email, or ask the person who invited you to send a new one.</p>
          <LinkBtn href="/sign-in" variant="secondary">Go to sign in</LinkBtn></div>
      </CenteredCard>
    );
  }
  const doAccept = async () => {
    const inv = s.k === 'ok' ? s.inv : null;
    const r = await accept.run();
    if (r.ok) {
      await api.session.selectOrg(r.value.org_id).catch(() => undefined);
      setS({ k: 'joined', m: r.value });
      return;
    }
    if (r.error.code === 'invite_wrong_account') {
      let email: string | null = null;
      try { email = (await api.session.get()).user.email; } catch { /* the address is only a hint on the screen */ }
      setS({ k: 'wrong', hint: inv?.invited_email_hint ?? 'the invited address', email, inv });
    } else if (r.error.status !== 401) setS({ k: 'fail', err: r.error });
  };
  return (
    <CenteredCard>
      {s.k === 'loading' && <div role="status" aria-busy="true"><h1 ref={h} tabIndex={-1}>Checking your invitation</h1><p className="loading-msg">Loading your invitation</p></div>}
      {s.k === 'ok' && (
        <>
          <h1 ref={h} tabIndex={-1}>{`Join ${s.inv.org_name} on ConsentVault`}</h1>
          <KV rows={[['Role', ROLE_LABEL[s.inv.role]], ['Invited by', s.inv.invited_by_name], ['Sent to', s.inv.invited_email_hint], ['Link expires', <Time key="t" iso={s.inv.expires_at} />]]} />
          {accept.error && accept.error.status !== 401 && <div className="mt4"><ErrorBlock title="The invitation was not accepted" err={accept.error} next="Try again." /></div>}
          <div className="btn-row mt5"><Btn variant="primary" busy={accept.busy} busyLabel="Signing in" onClick={doAccept}>Sign in to accept</Btn></div>
          <p className="hint mt4">Signing in creates your membership. You choose a plan next.</p>
        </>
      )}
      {s.k === 'wrong' && (
        <div role="alert"><h1 ref={h} tabIndex={-1}>You are signed in with a different address</h1>
          <p><b>Cause:</b> {`The invitation was sent to ${s.hint}.${s.email ? ` You are signed in as ${s.email}.` : ''}`}</p>
          <p><b>Next:</b> {`Sign out, then sign in with ${s.hint}.`}</p>
          <button type="button" className="btn btn-secondary" onClick={signOut}>Sign out and switch account</button></div>
      )}
      {s.k === 'joined' && (
        <div role="status"><h1 ref={h} tabIndex={-1}>{`You joined ${s.m.name} as ${ROLE_LABEL[s.m.role]}.`}</h1>
          <p>{s.m.role === 'admin' ? 'Next: choose a plan so your organization can go live.' : 'Next: open the overview.'}</p>
          {s.m.role === 'admin' ? <Btn variant="primary" onClick={() => navigate('/start/plan')}>Choose a plan</Btn> : <Btn variant="primary" onClick={() => navigate('/')}>Go to overview</Btn>}</div>
      )}
      {s.k === 'fail' && <InviteFailure err={s.err} headingRef={h} />}
    </CenteredCard>
  );
}

function InviteFailure({ err, headingRef }: { err: ApiError; headingRef: React.Ref<HTMLHeadingElement> }) {
  const f = err.fields as { expired_on?: string; used_on?: string };
  const date = (d?: string) => (d ? fmtDate(d) : null);
  const map: Record<string, { t: string; cause: string; next: string; btn: string; href: string }> = {
    invite_expired: { t: 'This invitation expired', cause: `Invitations last 7 days.${date(f.expired_on) ? ` This one expired on ${date(f.expired_on)}.` : ''}`, next: 'Ask your admin, or the operator for a new organization, to send a new invitation.', btn: 'Go to sign in', href: '/sign-in' },
    invite_used: { t: 'This invitation was already used', cause: date(f.used_on) ? `Someone accepted it on ${date(f.used_on)}.` : 'Someone already accepted it.', next: 'If that was you, sign in. If not, tell your admin right away.', btn: 'Sign in', href: '/sign-in' },
    invite_withdrawn: { t: 'This invitation was withdrawn', cause: 'An admin cancelled it.', next: 'Ask your admin for a new invitation.', btn: 'Go to sign in', href: '/sign-in' },
    invite_not_found: { t: 'This link has no invitation in it', cause: 'No invitation matches this link. Links can break when copied from some email apps.', next: 'Open the link straight from the invitation email, or ask the person who invited you to send a new one.', btn: 'Go to sign in', href: '/sign-in' },
  };
  const m = map[err.code];
  if (!m) return <div role="alert"><h1 ref={headingRef} tabIndex={-1}>The invitation did not load</h1><p><b>Cause:</b> {causeLine(err.status, err.code)}</p><p><b>Next:</b> Try again in a minute.</p><LinkBtn href="/sign-in" variant="secondary">Go to sign in</LinkBtn></div>;
  return <div role="alert"><h1 ref={headingRef} tabIndex={-1}>{m.t}</h1><p><b>Cause:</b> {m.cause}</p><p><b>Next:</b> {m.next}</p><LinkBtn href={m.href} variant="secondary">{m.btn}</LinkBtn></div>;
}

// ---- 03 Choose an organization ----
export function ChooseOrg() {
  const { api, selectOrg, signOut } = useSession();
  const { navigate } = useRouter();
  const res = useResource(() => api.session.get(), [api]);
  const [opening, setOpening] = useState<string | null>(null);
  const [openErr, setOpenErr] = useState<ApiError | null>(null);
  const h = useHeadingFocus(res.status);
  const open = async (m: Membership) => {
    setOpening(m.name); setOpenErr(null);
    const e = await selectOrg(m.org_id);
    if (e) { setOpening(null); setOpenErr(e); return; }
    navigate('/', { replace: true });
  };
  useEffect(() => {
    if (res.status === 'ok' && res.data.items.length === 1 && !opening) { void open(res.data.items[0]); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [res.status]);
  return (
    <CenteredCard wide>
      {res.status === 'loading' && <><h1 ref={h} tabIndex={-1}>Choose an organization</h1><Skeleton what="your organizations" rows={2} variant="table" /></>}
      {res.status === 'error' && <><h1 ref={h} tabIndex={-1}>Choose an organization</h1><ErrorBlock title="Your organizations did not load" err={res.error} override="the membership service answered with an error" next="Try again. If it keeps failing, sign out and back in." actions={<><Btn onClick={res.reload}>Try again</Btn><Btn onClick={signOut}>Sign out</Btn></>} /></>}
      {res.status === 'ok' && opening && <div role="status"><h1 ref={h} tabIndex={-1}>{`Opening ${opening}.`}</h1></div>}
      {res.status === 'ok' && !opening && res.data.items.length === 0 && <><h1 ref={h} tabIndex={-1}>Choose an organization</h1>
        <StateBlock kind="error" title="You are not a member of any organization" cause="Your membership may have been removed, or the organization was closed." next="Ask your admin for an invitation, or sign in with another account." actions={<Btn onClick={signOut}>Sign out</Btn>} /></>}
      {res.status === 'ok' && !opening && res.data.items.length > 1 && (
        <>
          <h1 ref={h} tabIndex={-1}>Choose an organization</h1>
          <p>{`You are a member of ${res.data.items.length} organizations. Records never mix between them.`}</p>
          {res.data.items.some((m) => m.status === null) && <Banner kind="warning" title="One organization could not be loaded">{`${res.data.items.filter((m) => m.status === null).map((m) => m.name).join(', ')} did not answer. You can open another organization now and switch later.`}</Banner>}
          {openErr && <ErrorBlock title="The organization did not open" err={openErr} next="Try again." />}
          <ul className="org-list">
            {res.data.items.map((m) => (
              <li key={m.org_id} className="card org-row">
                <div><b>{m.name}</b><div className="hint">{ROLE_LABEL[m.role]}</div></div>
                <div>{m.status ? <OrgChip status={m.status} /> : <span><span className="sr">Status: </span><NotAvailable /></span>}</div>
                <Btn variant="primary" size="sm" disabled={m.status === null} onClick={() => open(m)} aria-label={`Open ${m.name}`}>Open</Btn>
              </li>
            ))}
          </ul>
        </>
      )}
    </CenteredCard>
  );
}

// ---- 04 Plan and checkout ----
export function Plan() {
  const { api, orgName, role } = useSession();
  const { navigate } = useRouter();
  const res = useResource(() => api.billing.plans(), [api]);
  const checkout = useAction((id: string) => api.billing.checkout(id));
  const [picked, setPicked] = useState<string | null>(null);
  const h = useHeadingFocus(res.status);
  void orgName; void role;
  const choose = async (p: Plan) => {
    setPicked(p.plan_id);
    const r = await checkout.run(p.plan_id);
    if (r.ok) window.location.assign(r.value.checkout_url);
  };
  return (
    <>
      <h1 ref={h} tabIndex={-1} className="page-h1">Choose a plan</h1>
      <p>Payment happens on Stripe&apos;s secure page. ConsentVault never sees or stores card or bank details.</p>
      {res.status === 'loading' && <Skeleton what="plans" rows={3} variant="tiles" />}
      {res.status === 'error' && <ErrorBlock title="Plans are not available right now" err={res.error} next="Try again in a few minutes. You can still set up your first test event while this is fixed." actions={<><Btn onClick={res.reload}>Try again</Btn><LinkBtn href="/setup/first-event" variant="secondary">Set up first test event</LinkBtn></>} />}
      {res.status === 'ok' && res.data.items.length === 0 && (
        <StateBlock kind="empty" title="Plans are not available right now" actions={<><Btn onClick={res.reload}>Try again</Btn><LinkBtn href="/setup/first-event" variant="secondary">Set up first test event</LinkBtn></>}>
          No plans were returned for your organization. Try again in a few minutes. You can still set up your first test event while this is fixed.
        </StateBlock>
      )}
      {checkout.busy && <div role="status" aria-busy="true"><p className="loading-msg">Opening secure checkout. You will be taken to Stripe.</p></div>}
      {checkout.error && <ErrorBlock title="Checkout could not start" err={checkout.error} next="Try again. Nothing was charged." actions={<Btn onClick={() => { const p = res.status === 'ok' ? res.data.items.find((x) => x.plan_id === picked) : undefined; if (p) void choose(p); }}>Try again</Btn>} />}
      {res.status === 'ok' && res.data.items.length > 0 && (
        <div className="plans">
          {res.data.items.map((p) => (
            <section key={p.plan_id} className="card plan" aria-labelledby={`plan-${p.plan_id}`}>
              <h2 id={`plan-${p.plan_id}`}>{p.name}</h2>
              <p className="hl">{fmtMoney(p.unit_amount, p.currency)} a {p.interval}</p>
              <ul>
                <li>{fmtNum(p.included_events)} events a month</li>
                <li>{fmtNum(p.included_gate_checks)} gate checks a month</li>
                <li>{`Up to ${fmtNum(p.orgs_brands)} organizations and brands`}</li>
              </ul>
              <p className="hint">Overage billed per event and per check. Capture is never refused for going over.</p>
              <Btn variant="primary" busy={checkout.busy && picked === p.plan_id} busyLabel="Opening checkout" disabled={checkout.busy} onClick={() => choose(p)}>{`Choose ${p.name}`}</Btn>
            </section>
          ))}
        </div>
      )}
      <p className="hint">Plan values come from Stripe.</p>
      <div className="btn-row mt4"><Btn variant="quiet" onClick={() => navigate('/')}>Back to overview</Btn></div>
    </>
  );
}

// ---- 04 Checkout return ----
export function BillingReturn() {
  const { api, orgName, role, refreshOrg } = useSession();
  const { search, navigate } = useRouter();
  const result = search.get('result');
  const h = useHeadingFocus(result);
  const poll = usePoll(() => api.session.org(), { intervalMs: 5000, deadlineMs: 2 * 60 * 1000, until: (o) => o.status !== 'trial', enabled: result === 'success' });
  useEffect(() => { if (poll.done) void refreshOrg(); // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [poll.done]);
  if (result === 'cancel') {
    return (
      <div role="alert"><h1 ref={h} tabIndex={-1}>Checkout was cancelled</h1>
        <p><b>Cause:</b> You left Stripe&apos;s page before paying.</p>
        <p><b>Next:</b> Nothing was charged. Choose a plan when you are ready.</p>
        <div className="btn-row"><LinkBtn href="/start/plan" variant="primary">Choose a plan</LinkBtn><LinkBtn href="/setup/first-event" variant="secondary">Set up first test event</LinkBtn></div></div>
    );
  }
  if (result !== 'success') {
    return <StateBlock kind="error" title="This checkout address is not complete" cause="The address is missing its result." next="Open Billing to see your plan." actions={<LinkBtn href="/billing" variant="secondary">Open billing</LinkBtn>} />;
  }
  const org = poll.value;
  if (poll.done && org) {
    const plan = 'plan' in org && org.plan ? org.plan.name : null;
    return (
      <div role="status"><h1 ref={h} tabIndex={-1}>{plan ? `Your ${plan} plan is active.` : 'Your plan is active.'}</h1>
        <p>Next: send your first test event. It takes about 15 minutes.</p>
        <LinkBtn href="/setup/first-event" variant="primary">Set up first test event</LinkBtn></div>
    );
  }
  if (poll.deadlinePassed) {
    return (
      <div role="alert"><h1 ref={h} tabIndex={-1}>Payment is not confirmed yet</h1>
        <p><b>Cause:</b> Stripe has not told ConsentVault about the payment yet.</p>
        <p><b>Next:</b> Your payment is safe on Stripe. Check Billing again in a few minutes, or start setup now.</p>
        <div className="btn-row"><LinkBtn href="/billing" variant="secondary">Open billing</LinkBtn><LinkBtn href="/setup/first-event" variant="primary">Start setup</LinkBtn></div></div>
    );
  }
  void orgName; void role; void navigate;
  return (
    <div role="status" aria-busy="true"><h1 ref={h} tabIndex={-1}>Checkout finished</h1>
      <p>Waiting for Stripe to confirm payment. This usually takes under a minute. This page updates on its own. You can start setup now.</p>
      <LinkBtn href="/setup/first-event" variant="primary">Start setup</LinkBtn></div>
  );
}

void Chip; void ORG_STATUS_LABEL;
