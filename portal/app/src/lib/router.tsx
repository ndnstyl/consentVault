import { sameOriginTarget } from './safe-return.ts';
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { matchRoute } from './routes.ts';
import type { Matched } from './routes.ts';

// A small History API router. The export has one HTML file per static route; dynamic routes
// (/sources/<id> and the like) are served the list page by the host rewrite and resolved here.

interface RouterCtx {
  path: string;
  search: URLSearchParams;
  matched: Matched | null;
  navigations: number;
  navigate: (to: string, o?: { replace?: boolean }) => void;
}
const Ctx = createContext<RouterCtx | null>(null);
export const RouterContext = Ctx;

export function RouterProvider({ children, initial }: { children: React.ReactNode; initial: string }) {
  const [loc, setLoc] = useState<{ path: string; search: string }>({ path: initial, search: '' });
  const navs = useRef(0);
  useEffect(() => {
    setLoc({ path: window.location.pathname, search: window.location.search });
    const pop = () => { navs.current += 1; setLoc({ path: window.location.pathname, search: window.location.search }); };
    window.addEventListener('popstate', pop);
    return () => window.removeEventListener('popstate', pop);
  }, []);
  const navigate = useCallback((to: string, o?: { replace?: boolean }) => {
    const target = sameOriginTarget(to, window.location.origin);
    if (target === null) { console.error('navigation refused: not a path on this site'); return; }
    const u = new URL(target, window.location.origin);
    if (o?.replace) window.history.replaceState(null, '', u.pathname + u.search + u.hash);
    else window.history.pushState(null, '', u.pathname + u.search + u.hash);
    navs.current += 1;
    window.scrollTo(0, 0);
    setLoc({ path: u.pathname, search: u.search });
  }, []);
  const value = useMemo<RouterCtx>(() => ({
    path: loc.path, search: new URLSearchParams(loc.search), matched: matchRoute(loc.path), navigations: navs.current, navigate,
  }), [loc, navigate]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useRouter(): RouterCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useRouter outside RouterProvider');
  return c;
}

export function Link({ href, children, className, onClick, ...rest }: React.AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) {
  const { navigate } = useRouter();
  const external = /^https?:\/\//.test(href) || rest.target === '_blank';
  return (
    <a
      href={href}
      className={className}
      {...rest}
      onClick={(e) => {
        onClick?.(e);
        if (e.defaultPrevented || external || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        e.preventDefault();
        navigate(href);
      }}
    >
      {children}
    </a>
  );
}
