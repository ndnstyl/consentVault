import React, { useEffect, useRef, useState } from 'react';
import { useOnline, useTitle } from '../lib/hooks.ts';
import { Link, useRouter } from '../lib/router.tsx';
import { useSession } from '../lib/session.tsx';
import { NAV, ROLE_LABEL, canView, fallbackFor, navFor, refusalHeading } from '../lib/roles.ts';
import { ORG_STATUS_LABEL, causeLine } from '../lib/copy.ts';
import type { Org, OrgAdmin } from '../lib/api/types.ts';
import { fmtDate } from '../lib/format.ts';
import { Banner, Btn, ErrorBlock, Icon, LinkBtn, PageHead, Skeleton, Sprite, StateBlock } from './ui.tsx';
import { Dialog } from './Dialog.tsx';
import { Screen } from '../screens/index.tsx';

function Brand() {
  return <Link className="brand" href="/"><i aria-hidden="true" />CONSENTVAULT</Link>;
}

function useDisclosure() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const down = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    const key = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', down); document.addEventListener('keydown', key);
    return () => { document.removeEventListener('mousedown', down); document.removeEventListener('keydown', key); };
  }, [open]);
  return { open, setOpen, ref };
}

function OrgSwitcher() {
  const s = useSession();
  const d = useDisclosure();
  if (!s.orgName) return null;
  if (s.memberships.length < 2) return <span className="pill-btn org"><span>{s.orgName}</span></span>;
  return (
    <div className="menu-wrap" ref={d.ref}>
      <button type="button" className="pill-btn org" aria-expanded={d.open} aria-controls="org-menu" onClick={() => d.setOpen(!d.open)}>
        <span>{s.orgName}</span><Icon name="i-chev" />
      </button>
      {d.open && (
        <div className="menu-panel" id="org-menu" role="group" aria-label="Switch organization">
          {s.memberships.map((m) => (
            <button key={m.org_id} type="button" className="menu-item" aria-current={m.org_id === s.orgId ? 'true' : undefined} onClick={async () => { d.setOpen(false); if (m.org_id !== s.orgId) { await s.selectOrg(m.org_id); window.location.assign('/'); } }}>
              {m.name}<small>{ROLE_LABEL[m.role]}</small>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function PersonMenu() {
  const s = useSession();
  const d = useDisclosure();
  if (!s.user) return null;
  return (
    <div className="menu-wrap" ref={d.ref}>
      <button type="button" className="pill-btn who" aria-expanded={d.open} aria-controls="person-menu" onClick={() => d.setOpen(!d.open)}>
        <span>{s.user.display_name}{s.role && <small> ({ROLE_LABEL[s.role]})</small>}</span><Icon name="i-chev" />
      </button>
      {d.open && (
        <div className="menu-panel right" id="person-menu" role="group" aria-label="Your account">
          <p className="menu-note">{s.user.email}{s.role && <><br />{ROLE_LABEL[s.role]} in {s.orgName}</>}</p>
          <button type="button" className="menu-item" onClick={s.signOut}>Sign out</button>
        </div>
      )}
    </div>
  );
}

function offboardingSummary(org: Org | null): string {
  const o = org && 'offboarding' in org ? (org as OrgAdmin).offboarding : null;
  if (!o || !o.steps.length) return 'Offboarding in progress.';
  const at = (k: string) => o.steps.find((x) => x.step === k && x.status === 'done')?.at;
  const parts = ['Offboarding in progress.'];
  const fe = at('final_export'); if (fe) parts.push(`Final export delivered ${fmtDate(fe)}.`);
  const cr = at('credentials_revoked'); if (cr) parts.push(`Credentials revoked ${fmtDate(cr)}.`);
  if (o.destroy_after) parts.push(`Key destruction scheduled for ${fmtDate(o.destroy_after)}.`);
  return parts.join(' ');
}

function StatusBanner() {
  const s = useSession();
  if (!s.status || s.phase !== 'ready') return null;
  const admin = s.role === 'admin';
  const name = s.orgName;
  let node: React.ReactNode = null;
  if (s.status === 'trial') node = <Banner kind="info" action={admin ? <LinkBtn href="/start/plan" size="sm">Choose a plan</LinkBtn> : undefined}>{`${name} is in trial. Records are test data until you choose a plan.`}</Banner>;
  else if (s.status === 'past_due') node = <Banner kind="warning" action={admin ? <LinkBtn href="/billing" size="sm">Open billing</LinkBtn> : undefined}>{`Payment failed. Capture keeps recording and contact checks keep answering. ${admin ? 'Update your payment method to avoid suspension.' : 'Ask an admin to update the payment method to avoid suspension.'}`}</Banner>;
  else if (s.status === 'suspended') node = <Banner kind="danger" role="status" action={admin ? <LinkBtn href="/billing" size="sm">Open billing</LinkBtn> : undefined}>{`${name} is suspended. Capture keeps recording, because evidence is never refused for non-payment. Evidence packages and new credentials are paused until billing is resolved.`}</Banner>;
  else if (s.status === 'offboarding') node = <Banner kind="warning" action={<LinkBtn href="/settings" size="sm">Open settings</LinkBtn>}>{offboardingSummary(s.org)}</Banner>;
  if (!node) return null;
  return <div className="status-slot" role="region" aria-label="Organization status">{node}</div>;
}

function SideNav({ open, onNavigate }: { open: boolean; onNavigate: () => void }) {
  const s = useSession();
  const { path } = useRouter();
  const groups = navFor(s.role);
  return (
    <nav className={open ? 'side open' : 'side'} id="side" aria-label="Portal">
      {groups.map((g) => (
        <React.Fragment key={g.group}>
          <h2>{g.group}</h2>
          {g.items.map((i) => <Link key={i.id} href={i.href} aria-current={i.href === path ? 'page' : undefined} onClick={onNavigate}>{i.label}</Link>)}
        </React.Fragment>
      ))}
      {s.user && (
        <div className="side-account">
          <p className="menu-note">{s.user.display_name}{s.role && <> ({ROLE_LABEL[s.role]})</>}<br />{s.user.email}</p>
          <Btn size="sm" onClick={s.signOut}>Sign out</Btn>
        </div>
      )}
    </nav>
  );
}

function RoleRefusal({ id }: { id: Parameters<typeof refusalHeading>[0] }) {
  const s = useSession();
  const fb = fallbackFor(s.role);
  if (id === 'plan') {
    return <StateBlock kind="error" title="Only an admin can choose a plan" cause={`Your role is ${s.role ? ROLE_LABEL[s.role] : 'not known'}.`} next={`Ask an admin of ${s.orgName} to finish checkout.`} actions={<LinkBtn href={fb.href} variant="secondary">{`Go to ${fb.label}`}</LinkBtn>} />;
  }
  return (
    <StateBlock kind="error" title={refusalHeading(id)}
      cause={`Your role in ${s.orgName} is ${s.role ? ROLE_LABEL[s.role] : 'not known'}. This page is managed by ${refusalHeading(id).replace('This page is for ', '')}.`}
      next={`Ask an admin, or go back to ${fb.label}.`}
      actions={<LinkBtn href={fb.href} variant="secondary">{`Go to ${fb.label}`}</LinkBtn>} />
  );
}

function NotFound() {
  const s = useSession();
  return (
    <StateBlock kind="error" title={`That page does not exist in ${s.orgName || 'this organization'}`}
      cause="The address may be mistyped, or the item belongs to another organization you are not working in."
      next="Go back to the overview, or switch organization."
      actions={<><LinkBtn href="/" variant="secondary">Go to overview</LinkBtn>{s.memberships.length > 1 && <LinkBtn href="/choose-org" variant="secondary">Switch organization</LinkBtn>}</>} />
  );
}

function ClosedPage() {
  const s = useSession();
  const o = s.org && 'offboarding' in s.org ? (s.org as OrgAdmin).offboarding : null;
  const exp = o?.steps.find((x) => x.step === 'final_export')?.at;
  const key = o?.steps.find((x) => x.step === 'destruction_record')?.at ?? o?.destroy_after;
  return (
    <div className="centered"><Brand />
      <div className="cc"><div className="card">
        <h1 tabIndex={-1}>{`${s.orgName} is closed`}</h1>
        <p>{`${s.orgName} is closed. Its records were exported on ${exp ? fmtDate(exp) : 'a date that is not available'} and its key was destroyed on ${key ? fmtDate(key) : 'a date that is not available'}.`}</p>
        <div className="btn-row">{s.memberships.length > 1 && <LinkBtn href="/choose-org" variant="secondary">Switch organization</LinkBtn>}<Btn onClick={s.signOut}>Sign out</Btn></div>
      </div></div>
    </div>
  );
}

function Overlays() {
  const s = useSession();
  const online = useOnline();
  return (
    <>
      {!online && <div className="offline-bar" role="status"><Icon name="i-warn" /> You are offline. What is on screen may be out of date. Changes are not sent until you are back online.</div>}
      {s.signOutError && <div className="offline-bar" role="alert"><Icon name="i-warn" /> {s.signOutError} <Btn size="sm" onClick={s.dismissSignOutError}>Dismiss</Btn></div>}
      {s.sessionEnding && (
        <Dialog title="Your session ends in 2 minutes" onClose={s.dismissEnding} alert>
          <p>Sessions last 8 hours. Sign in again to keep working. Unsaved form entries are kept on this device.</p>
          <div className="actions"><Btn data-safe="" onClick={s.dismissEnding}>Dismiss</Btn><Btn variant="primary" onClick={s.signInAgain}>Sign in again</Btn></div>
        </Dialog>
      )}
    </>
  );
}

function ElsewhereBanner() {
  const s = useSession();
  if (!s.elsewhere) return null;
  return (
    <div className="status-slot" role="region" aria-label="Organization changed">
      <Banner kind="warning" title="Organization switched in another tab" action={<div className="btn-row"><Btn size="sm" variant="primary" onClick={() => window.location.reload()}>Reload</Btn><Btn size="sm" onClick={s.dismissElsewhere}>{`Stay on ${s.orgName}`}</Btn></div>}>
        {`You switched to ${s.elsewhere.orgName} in another tab. This tab still shows ${s.orgName}. Reload to continue in ${s.elsewhere.orgName}, or switch back. Changes from this tab are paused until you do.`}
      </Banner>
    </div>
  );
}

export function Shell() {
  const router = useRouter();
  const s = useSession();
  const [menuOpen, setMenuOpen] = useState(false);
  const m = router.matched;
  useEffect(() => { setMenuOpen(false); }, [router.path]);
  const title = m ? m.route.title : 'Page not found';
  useTitle(`${title} | ${s.orgName || 'ConsentVault'} | ConsentVault`);

  // Pages that do not need an organization (sign-in, callback, invite, choose organization).
  if (m && m.route.preOrg) {
    return <><Sprite /><a className="skip" href="#main">Skip to main content</a><div id="app-chrome"><main id="main"><Screen route={m.route} params={m.params} /></main></div><Overlays /></>;
  }
  if (s.phase === 'closed') return <><Sprite /><a className="skip" href="#main">Skip to main content</a><div id="app-chrome"><main id="main"><ClosedPage /></main></div></>;

  const ready = s.phase === 'ready';
  const allowed = m ? canView(s.role, m.route.id) : true;
  const card = m?.route.chrome === 'card';

  let body: React.ReactNode;
  const titled = (node: React.ReactNode, t = title) => <><PageHead title={t} />{node}</>;
  if (s.phase === 'idle' || s.phase === 'loading' || s.phase === 'choose') body = titled(<Skeleton what="your organization" rows={3} variant="tiles" />);
  else if (s.phase === 'noorg') body = titled(<StateBlock kind="error" title="Your account is not a member of any organization" cause="Your membership may have been removed, or the organization was closed." next="Ask your admin for an invitation, or sign in with another account." actions={<Btn variant="secondary" onClick={s.signOut}>Sign out</Btn>} />, 'Your organizations');
  else if (s.phase === 'error' && s.error) body = titled(<ErrorBlock title={`The ${title.toLowerCase()} did not load`} err={s.error} override="your organization's status could not be read" next="Try again. Capture from your website and systems is not affected by this page." actions={<Btn variant="secondary" onClick={s.reload}>Try again</Btn>} />);
  else if (!m) body = titled(<NotFound />);
  else if (!allowed) body = titled(<RoleRefusal id={m.route.id} />);
  else body = <Screen key={`${s.orgId}:${m.route.id}:${router.path}`} route={m.route} params={m.params} />;

  if (card && ready && allowed) {
    return <><Sprite /><a className="skip" href="#main">Skip to main content</a><div id="app-chrome"><div className="centered"><Brand /><main id="main" className="cc wide">{body}</main></div></div><Overlays /></>;
  }

  return (
    <>
      <Sprite />
      <a className="skip" href="#main">Skip to main content</a>
      <div id="app-chrome">
        <header className="topbar">
          <button type="button" className="pill-btn menu-btn" aria-expanded={menuOpen} aria-controls="side" onClick={() => setMenuOpen(!menuOpen)}><Icon name="i-menu" />Menu</button>
          <Brand />
          <span className="spacer" />
          <OrgSwitcher />
          <PersonMenu />
        </header>
        <div className="shell">
          {ready ? <SideNav open={menuOpen} onNavigate={() => setMenuOpen(false)} /> : <nav className="side" id="side" aria-label="Portal" />}
          <main className="main" id="main">
            <div className="wrap">
              <StatusBanner />
              <ElsewhereBanner />
              <fieldset className="contents" disabled={!!s.elsewhere}>{body}</fieldset>
            </div>
          </main>
        </div>
      </div>
      <Overlays />
    </>
  );
}

export { NAV };
