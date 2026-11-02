import React, { useEffect, useState } from 'react';
import { RouterProvider } from '../lib/router.tsx';
import { SessionProvider } from '../lib/session.tsx';
import { ToastProvider } from '../lib/toast.tsx';
import { Shell } from './Shell.tsx';

/** Renders nothing until mounted: the static HTML is an empty shell, the router reads the real address on the client. */
export function PortalApp({ initial }: { initial: string }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
    document.documentElement.dataset.ready = '1'; // tells the page's boot watch that the dashboard started
    document.getElementById('boot-fail')?.setAttribute('hidden', '');
  }, []);
  return (
    <RouterProvider initial={initial}>
      <SessionProvider>
        <ToastProvider>
          {mounted ? <Shell /> : <p className="sr" role="status">Loading ConsentVault</p>}
          <div id="dialog-root" />
        </ToastProvider>
      </SessionProvider>
    </RouterProvider>
  );
}
