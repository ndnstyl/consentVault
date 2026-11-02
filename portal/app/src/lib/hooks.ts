import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError } from './api/client.ts';

export type Res<T> =
  | { status: 'loading'; data: null; error: null }
  | { status: 'ok'; data: T; error: null }
  | { status: 'error'; data: null; error: ApiError };

function asApiError(e: unknown): ApiError {
  if (e instanceof ApiError) return e;
  return new ApiError(0, 'unreachable', e instanceof Error ? e.message : 'The service could not be reached.', null);
}

/** Load once per `deps` change; `reload()` runs it again. Ignores answers that arrive after unmount. */
export function useResource<T>(load: () => Promise<T>, deps: unknown[]): Res<T> & { reload: () => void; refresh: () => void; setData: (v: T) => void } {
  const [state, setState] = useState<Res<T>>({ status: 'loading', data: null, error: null });
  const [nonce, setNonce] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    let live = true;
    setState((s) => (s.status === 'ok' ? s : { status: 'loading', data: null, error: null }));
    loadRef.current().then(
      (data) => { if (live) setState({ status: 'ok', data, error: null }); },
      (e) => { if (live) setState({ status: 'error', data: null, error: asApiError(e) }); },
    );
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);
  const reload = useCallback(() => { setState({ status: 'loading', data: null, error: null }); setNonce((n) => n + 1); }, []);
  const refresh = useCallback(() => setNonce((n) => n + 1), []);
  const setData = useCallback((v: T) => setState({ status: 'ok', data: v, error: null }), []);
  return { ...state, reload, refresh, setData } as Res<T> & { reload: () => void; refresh: () => void; setData: (v: T) => void };
}

/** A write: busy while in flight, double submits impossible, error kept for the form to show. */
export function useAction<A extends unknown[], R>(fn: (...a: A) => Promise<R>) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const inflight = useRef(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const run = useCallback(async (...a: A): Promise<{ ok: true; value: R } | { ok: false; error: ApiError }> => {
    if (inflight.current) return { ok: false, error: new ApiError(0, 'busy', 'Already sending.', null) };
    inflight.current = true;
    if (mounted.current) { setBusy(true); setError(null); }
    try {
      const value = await fn(...a);
      return { ok: true, value };
    } catch (e) {
      const err = asApiError(e);
      if (mounted.current) setError(err);
      return { ok: false, error: err };
    } finally {
      inflight.current = false;
      if (mounted.current) setBusy(false);
    }
  }, [fn]);
  const clear = useCallback(() => setError(null), []);
  return { run, busy, error, clear };
}

export function useVisible(): boolean {
  const [v, setV] = useState(true);
  useEffect(() => {
    const f = () => setV(document.visibilityState !== 'hidden');
    f(); document.addEventListener('visibilitychange', f);
    return () => document.removeEventListener('visibilitychange', f);
  }, []);
  return v;
}

export interface PollState<T> { value: T | null; error: ApiError | null; deadlinePassed: boolean; done: boolean }

/**
 * Poll `tick` every `intervalMs` until `until(value)` is true or `deadlineMs` passes. Pauses while the tab is hidden.
 * Setting `enabled` false stops it. `restart()` begins a fresh deadline window.
 */
export function usePoll<T>(tick: () => Promise<T>, o: { intervalMs: number; deadlineMs: number; until: (v: T) => boolean; enabled?: boolean }) {
  const [s, setS] = useState<PollState<T>>({ value: null, error: null, deadlinePassed: false, done: false });
  const [epoch, setEpoch] = useState(0);
  const visible = useVisible();
  const tickRef = useRef(tick); tickRef.current = tick;
  const untilRef = useRef(o.until); untilRef.current = o.until;
  const enabled = o.enabled ?? true;
  useEffect(() => {
    if (!enabled) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const started = Date.now();
    setS({ value: null, error: null, deadlinePassed: false, done: false });
    const step = async () => {
      if (!live) return;
      if (Date.now() - started >= o.deadlineMs) { setS((p) => ({ ...p, deadlinePassed: true })); return; }
      if (visible) {
        try {
          const v = await tickRef.current();
          if (!live) return;
          const done = untilRef.current(v);
          setS({ value: v, error: null, deadlinePassed: false, done });
          if (done) return;
        } catch (e) {
          if (!live) return;
          setS((p) => ({ ...p, error: asApiError(e) }));
        }
      }
      timer = setTimeout(step, o.intervalMs);
    };
    void step();
    return () => { live = false; if (timer) clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, visible, epoch, o.intervalMs, o.deadlineMs]);
  const restart = useCallback(() => setEpoch((n) => n + 1), []);
  return { ...s, restart };
}

/** Keep unsaved form fields across a sign-in round trip (G-1). Never holds a contact point or a secret. */
export function useDraft<T extends Record<string, unknown>>(key: string, initial: T): [T, (patch: Partial<T>) => void, () => void] {
  const full = `cv.draft.${key}`;
  const [v, setV] = useState<T>(initial);
  const loaded = useRef(false);
  useEffect(() => {
    try { const raw = sessionStorage.getItem(full); if (raw) setV({ ...initial, ...JSON.parse(raw) }); } catch { /* storage unavailable: start empty */ }
    loaded.current = true;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [full]);
  const set = useCallback((patch: Partial<T>) => {
    setV((p) => {
      const n = { ...p, ...patch };
      try { sessionStorage.setItem(full, JSON.stringify(n)); } catch { /* storage unavailable: the draft is simply not kept */ }
      return n;
    });
  }, [full]);
  const clear = useCallback(() => { try { sessionStorage.removeItem(full); } catch { /* nothing to clear */ } setV(initial); // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [full]);
  return [v, set, clear];
}

export function useTitle(t: string | null) {
  useEffect(() => { if (t) document.title = t; }, [t]);
}

export function useOnline(): boolean {
  const [on, setOn] = useState(true);
  useEffect(() => {
    setOn(navigator.onLine);
    const a = () => setOn(true); const b = () => setOn(false);
    window.addEventListener('online', a); window.addEventListener('offline', b);
    return () => { window.removeEventListener('online', a); window.removeEventListener('offline', b); };
  }, []);
  return on;
}
