import { safeReturn } from './safe-return.ts';
import { postLogout } from './logout.ts';
import { BOOT_DEADLINE_MS } from './boot-watch.ts';
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, createClient } from './api/client.ts';
import type { Api } from './api/client.ts';
import type { Membership, Org, OrgStatus, Role } from './api/types.ts';
import { normalizeRole } from './roles.ts';
import { useRouter } from './router.tsx';

// Session and organization state. The role is read from the server on every boot, never kept in client storage (roles.md rule 2).

export type Phase = 'idle' | 'loading' | 'error' | 'noorg' | 'choose' | 'ready' | 'closed';
export const SESSION_MS = 8 * 60 * 60 * 1000;
export const WARN_BEFORE_MS = 2 * 60 * 1000;
const ORG_KEY = 'cv.org';
const STARTED_KEY = 'cv.session.started';

export interface SessionCtx {
  api: Api;
  phase: Phase;
  error: ApiError | null;
  user: { display_name: string; email: string } | null;
  memberships: Membership[];
  org: Org | null;
  orgId: string | null;
  orgName: string;
  role: Role | null;
  status: OrgStatus | null;
  elsewhere: { orgName: string } | null;
  sessionEnding: boolean;
  reload: () => void;
  refreshOrg: () => Promise<void>;
  selectOrg: (orgId: string) => Promise<ApiError | null>;
  signOut: () => void;
  signOutError: string | null;
  dismissSignOutError: () => void;
  signInAgain: () => void;
  dismissEnding: () => void;
  dismissElsewhere: () => void;
}
const Ctx = createContext<SessionCtx | null>(null);

export { safeReturn };

export { postLogout } from './logout.ts';

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const routerRef = useRef(router); routerRef.current = router;
  const orgRef = useRef<string | null>(null);
  const [elsewhere, setElsewhere] = useState<{ orgName: string } | null>(null);
  const api = useMemo(() => createClient({
    baseUrl: process.env.NEXT_PUBLIC_API_BASE ?? '',
    orgId: () => orgRef.current,
    onOrgMismatch: () => setElsewhere((e) => e ?? { orgName: 'another organization' }),
    onUnauthenticated: () => {
      const r = routerRef.current;
      const id = r.matched?.route.id;
      if (id === 'sign-in' || id === 'callback') return;
      const back = r.path + (r.search.toString() ? `?${r.search.toString()}` : '');
      r.navigate(`/sign-in?return=${encodeURIComponent(back)}`, { replace: true });
    },
  }), []);

  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<ApiError | null>(null);
  const [user, setUser] = useState<SessionCtx['user']>(null);
  const [memberships, setMemberships] = useState<Membership[]>([]);
  const [org, setOrg] = useState<Org | null>(null);
  const [nonce, setNonce] = useState(0);
  const [sessionEnding, setSessionEnding] = useState(false);
  const memRef = useRef<Membership[]>([]);

  const preOrg = router.matched?.route.preOrg ?? false;
  const routeKnown = router.matched !== null;

  const boot = useCallback(async (alive: () => boolean) => {
    setPhase((p) => (p === 'ready' ? p : 'loading')); setError(null);
    let items: Membership[];
    try {
      const s = await api.session.get();
      if (!alive()) return;
      items = s.items; setUser(s.user); setMemberships(items); memRef.current = items;
    } catch (e) {
      if (!alive()) return;
      const err = e as ApiError;
      if (err.status === 401) return;
      if (err.code === 'second_factor_required') { routerRef.current.navigate('/auth/callback', { replace: true }); return; }
      setError(err); setPhase('error'); return;
    }
    if (items.length === 0) { setPhase('noorg'); return; }
    let o: Org | null = null;
    try {
      o = await api.session.org();
    } catch (e) {
      if (!alive()) return;
      const err = e as ApiError;
      if (err.status === 401) return;
      if (err.status === 403 || err.status === 404) {
        if (items.length === 1) {
          try { await api.session.selectOrg(items[0].org_id); o = await api.session.org(); }
          catch (e2) { if (!alive()) return; if ((e2 as ApiError).status === 401) return; setError(e2 as ApiError); setPhase('error'); return; }
        } else { setPhase('choose'); routerRef.current.navigate('/choose-org', { replace: true }); return; }
      } else { setError(err); setPhase('error'); return; }
    }
    if (!alive() || !o) return;
    setOrg(o); orgRef.current = o.org_id;
    try { localStorage.setItem(ORG_KEY, JSON.stringify({ org_id: o.org_id, at: Date.now() })); } catch { /* storage unavailable: other tabs just are not told */ }
    setPhase(o.status === 'closed' ? 'closed' : 'ready');
  }, [api]);

  useEffect(() => {
    if (!routeKnown && phase === 'idle') { /* unknown route still needs the org name for the not-found state */ }
    if (preOrg) return;
    let live = true;
    void boot(() => live);
    return () => { live = false; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preOrg, nonce, boot]);

  // Every initial load has a deadline: a service that never answers becomes a styled error with Try again, never a skeleton
  // that waits for ever.
  useEffect(() => {
    if (preOrg || (phase !== 'idle' && phase !== 'loading')) return;
    const t = window.setTimeout(() => {
      setError(new ApiError(0, 'timeout', 'The service did not answer in time.', null));
      setPhase('error');
    }, BOOT_DEADLINE_MS);
    return () => window.clearTimeout(t);
  }, [phase, preOrg, nonce]);

  const refreshOrg = useCallback(async () => { try { setOrg(await api.session.org()); } catch { /* the page that asked shows its own error */ } }, [api]);
  const reload = useCallback(() => setNonce((n) => n + 1), []);

  const selectOrg = useCallback(async (orgId: string) => {
    try {
      await api.session.selectOrg(orgId);
      try { localStorage.setItem(ORG_KEY, JSON.stringify({ org_id: orgId, at: Date.now() })); } catch { /* see above */ }
      orgRef.current = orgId; setOrg(null); setElsewhere(null); setNonce((n) => n + 1);
      return null;
    } catch (e) { return e as ApiError; }
  }, [api]);

  // G-2: another tab changed the organization.
  useEffect(() => {
    const f = (e: StorageEvent) => {
      if (e.key !== ORG_KEY || !e.newValue || !orgRef.current) return;
      try {
        const v = JSON.parse(e.newValue) as { org_id: string };
        if (v.org_id !== orgRef.current) setElsewhere({ orgName: memRef.current.find((m) => m.org_id === v.org_id)?.name ?? 'another organization' });
        else setElsewhere(null);
      } catch { /* an unreadable signal is ignored; the next request still carries the server's truth */ }
    };
    window.addEventListener('storage', f);
    return () => window.removeEventListener('storage', f);
  }, []);

  // 8-hour session: warn two minutes before the end, then end it.
  useEffect(() => {
    if (phase !== 'ready') return;
    let started = Date.now();
    try { const s = sessionStorage.getItem(STARTED_KEY); if (s) started = Number(s); else sessionStorage.setItem(STARTED_KEY, String(started)); } catch { /* storage unavailable: count from now */ }
    const toWarn = Math.max(0, started + SESSION_MS - WARN_BEFORE_MS - Date.now());
    const toEnd = Math.max(0, started + SESSION_MS - Date.now());
    const a = window.setTimeout(() => setSessionEnding(true), toWarn);
    const b = window.setTimeout(() => { routerRef.current.navigate('/sign-in?reason=expired', { replace: true }); }, toEnd);
    return () => { window.clearTimeout(a); window.clearTimeout(b); };
  }, [phase]);

  const [signOutError, setSignOutError] = useState<string | null>(null);
  const signOut = useCallback(() => {
    setSignOutError(null);
    try { sessionStorage.removeItem(STARTED_KEY); localStorage.removeItem(ORG_KEY); } catch { /* nothing to clear */ }
    void postLogout().then((e) => setSignOutError(e));
  }, []);
  const dismissSignOutError = useCallback(() => setSignOutError(null), []);
  const signInAgain = useCallback(() => {
    const r = routerRef.current;
    const back = r.path + (r.search.toString() ? `?${r.search.toString()}` : '');
    try { sessionStorage.removeItem(STARTED_KEY); } catch { /* nothing to clear */ }
    window.location.assign(`/auth/login?return=${encodeURIComponent(back)}`);
  }, []);

  const role: Role | null = useMemo(() => {
    if (!org) return null;
    const direct = 'role' in org ? normalizeRole(org.role) : null;
    return direct ?? normalizeRole(memberships.find((m) => m.org_id === org.org_id)?.role);
  }, [org, memberships]);

  const value: SessionCtx = {
    api, phase, error, user, memberships, org, orgId: org?.org_id ?? null, orgName: org?.name ?? '', role, status: org?.status ?? null,
    elsewhere, sessionEnding, reload, refreshOrg, selectOrg, signOut, signOutError, dismissSignOutError, signInAgain,
    dismissEnding: () => setSessionEnding(false), dismissElsewhere: () => setElsewhere(null),
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): SessionCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useSession outside SessionProvider');
  return c;
}
