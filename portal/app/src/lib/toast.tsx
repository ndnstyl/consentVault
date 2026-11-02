import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';

// Toasts stay at least 10 seconds and pause on hover and focus. The same information is always on the page too (a11y spec section 6).
const Ctx = createContext<(m: string) => void>(() => undefined);
export const useToast = () => useContext(Ctx);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [msg, setMsg] = useState<string | null>(null);
  const timer = useRef<number | undefined>(undefined);
  const arm = useCallback(() => { window.clearTimeout(timer.current); timer.current = window.setTimeout(() => setMsg(null), 10000); }, []);
  const notify = useCallback((m: string) => { setMsg(m); arm(); }, [arm]);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <Ctx.Provider value={notify}>
      {children}
      <div className="toast-slot" role="status" aria-live="polite">
        {msg && <div className="toast" tabIndex={0} onMouseEnter={() => window.clearTimeout(timer.current)} onMouseLeave={arm} onFocus={() => window.clearTimeout(timer.current)} onBlur={arm}>{msg}</div>}
      </div>
    </Ctx.Provider>
  );
}
