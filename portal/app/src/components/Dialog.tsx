import React, { useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { ApiError } from '../lib/api/client.ts';
import { Btn, ErrorBlock, TextArea } from './ui.tsx';

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

/** Modal dialog: labelled by its heading, focus trapped, Esc closes (unless `confirmEsc`), focus returns to the opener. */
export function Dialog({ title, children, onClose, alert, wide, confirmEsc, initialFocus }: { title: string; children: React.ReactNode; onClose: () => void; alert?: boolean; wide?: boolean; confirmEsc?: () => void; initialFocus?: string }) {
  const titleId = useId();
  const box = useRef<HTMLDivElement>(null);
  const opener = useRef<Element | null>(null);
  useEffect(() => {
    opener.current = document.activeElement;
    const chrome = document.getElementById('app-chrome');
    chrome?.setAttribute('inert', '');
    const root = box.current!;
    const target = (initialFocus ? root.querySelector<HTMLElement>(initialFocus) : null) ?? root.querySelector<HTMLElement>(alert ? '[data-safe]' : 'input:not([disabled]),textarea,select,button:not([disabled])') ?? root;
    target.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.preventDefault(); (confirmEsc ?? onClose)(); return; }
      if (e.key !== 'Tab') return;
      const els = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((x) => x.offsetParent !== null);
      if (!els.length) { e.preventDefault(); return; }
      const first = els[0]; const last = els[els.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', key);
    return () => {
      document.removeEventListener('keydown', key);
      chrome?.removeAttribute('inert');
      if (opener.current instanceof HTMLElement && document.contains(opener.current)) opener.current.focus();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const root = typeof document !== 'undefined' ? document.getElementById('dialog-root') : null;
  const node = (
    <div className="overlay">
      <div ref={box} className={wide ? 'dialog wide' : 'dialog'} role={alert ? 'alertdialog' : 'dialog'} aria-modal="true" aria-labelledby={titleId} tabIndex={-1}>
        <h2 id={titleId}>{title}</h2>
        {children}
      </div>
    </div>
  );
  return root ? createPortal(node, root) : node;
}

export interface ConfirmProps {
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  busyLabel: string;
  destructive?: boolean;
  reasonLabel?: string;
  reasonRequired?: boolean;
  /** Return null on success or the ApiError to show inside the dialog. */
  onConfirm: (reason: string) => Promise<ApiError | null>;
  onClose: () => void;
  failTitle: string;
  failNext: React.ReactNode;
  extra?: React.ReactNode;
  confirmDisabled?: boolean;
  /** Keep the confirm button disabled until a reason is typed (the reason box must be shown). */
  disableUntilReason?: boolean;
  extraValid?: boolean;
}

export function ConfirmDialog(p: ConfirmProps) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<ApiError | null>(null);
  const [touched, setTouched] = useState(false);
  const missing = p.reasonRequired && reason.trim() === '';
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy) return;
    if (missing) { setTouched(true); return; }
    setBusy(true); setErr(null);
    const out = await p.onConfirm(reason.trim());
    setBusy(false);
    if (out) setErr(out); else p.onClose();
  };
  return (
    <Dialog title={p.title} onClose={p.onClose} alert={p.destructive}>
      <form onSubmit={submit} noValidate>
        <div className="mb4">{p.body}</div>
        {err && <ErrorBlock title={p.failTitle} err={err} next={p.failNext} headingLevel={3} />}
        {p.extra}
        {p.reasonLabel && (
          <TextArea label={p.reasonLabel} name="reason" value={reason} onChange={(e) => setReason(e.target.value)} required={p.reasonRequired} aria-required={p.reasonRequired} error={touched && missing ? 'Enter a reason. It is recorded in the audit log.' : null} autoComplete="off" />
        )}
        <div className="actions">
          <Btn data-safe="" onClick={p.onClose}>Cancel</Btn>
          <Btn type="submit" variant={p.destructive ? 'danger' : 'primary'} busy={busy} busyLabel={p.busyLabel} disabled={p.confirmDisabled || (p.disableUntilReason && reason.trim() === '')}>{p.confirmLabel}</Btn>
        </div>
      </form>
    </Dialog>
  );
}
