import React, { useEffect, useId, useRef, useState } from 'react';
import { ASK_COPY, ASK_MAX, ask, newConversationId, type AskReply, type AskTurn } from '../lib/assist.ts';
import { useSession } from '../lib/session.tsx';
import { Btn } from './ui.tsx';

/** The Ask button for the header; opens the panel. The panel is a labelled region, not a modal: the page behind it stays usable. */
export function AskButton({ open, onClick, buttonRef }: { open: boolean; onClick: () => void; buttonRef?: React.RefObject<HTMLButtonElement> }) {
  return <button type="button" ref={buttonRef} className="pill-btn ask-btn" aria-expanded={open} aria-controls="ask-panel" onClick={onClick}>{ASK_COPY.button}</button>;
}

export function AssistantPanel({ turns, busy, onSend, onClose, initialQuestion = '' }: { turns: AskTurn[]; busy: boolean; onSend: (q: string) => void; onClose: () => void; initialQuestion?: string }) {
  const [q, setQ] = useState(initialQuestion);
  const id = useId();
  const input = useRef<HTMLTextAreaElement>(null);
  useEffect(() => { input.current?.focus(); }, []);
  const tooLong = q.length > ASK_MAX;
  const submit = (e: React.FormEvent) => { e.preventDefault(); if (!busy && q.trim() && !tooLong) { onSend(q.trim()); setQ(''); } };
  const last = turns[turns.length - 1];
  return (
    <section id="ask-panel" className="ask-panel" role="region" aria-labelledby={`${id}-t`} onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); onClose(); } }}>
      <header className="ask-head"><h2 id={`${id}-t`}>{ASK_COPY.title}</h2><Btn size="sm" variant="quiet" onClick={onClose}>{ASK_COPY.close}</Btn></header>
      <p>{ASK_COPY.greeting}</p>
      <p className="muted">{ASK_COPY.scope}</p>
      <ol className="ask-turns">
        {turns.map((t) => (
          <li key={t.id}>
            <p className="ask-q"><span className="sr-only">You asked: </span>{t.question}</p>
            <div className={`ask-a ask-${t.reply.kind}`}>
              <p>{t.reply.text}</p>
              {t.reply.links.length > 0 && <p>{t.reply.links.map((l, i) => <React.Fragment key={l.path}>{i > 0 && ' '}<a href={l.path}>{l.label}</a></React.Fragment>)}</p>}
            </div>
          </li>
        ))}
      </ol>
      <div className="sr-only" role="status" aria-live="polite">{busy ? ASK_COPY.sending : last ? last.reply.text : ''}</div>
      <form onSubmit={submit}>
        <label htmlFor={`${id}-q`}>{ASK_COPY.label}</label>
        <textarea id={`${id}-q`} ref={input} rows={3} value={q} onChange={(e) => setQ(e.target.value)} aria-invalid={tooLong || undefined} aria-describedby={tooLong ? `${id}-e` : undefined} />
        {tooLong && <p id={`${id}-e`} role="alert">{ASK_COPY.tooLong}</p>}
        <Btn type="submit" variant="primary" busy={busy} busyLabel={ASK_COPY.sending} disabled={!q.trim() || tooLong}>{ASK_COPY.send}</Btn>
      </form>
    </section>
  );
}

/** Button plus panel, owned by the shell header. Escape closes the panel and returns focus to the button. */
export function Assistant() {
  const s = useSession();
  const [open, setOpen] = useState(false);
  const [turns, setTurns] = useState<AskTurn[]>([]);
  const [busy, setBusy] = useState(false);
  const conv = useRef(newConversationId());
  const btn = useRef<HTMLButtonElement>(null);
  const close = () => { setOpen(false); btn.current?.focus(); };
  const send = async (question: string) => {
    if (!s.orgId) return;
    setBusy(true);
    const reply: AskReply = await ask(question, conv.current, s.orgId);
    setTurns((t) => [...t, { id: t.length + 1, question, reply }]);
    if (reply.kind === 'limited' && /length limit/.test(reply.text)) conv.current = newConversationId();
    setBusy(false);
  };
  if (s.phase !== 'ready' || !s.orgId) return null;
  return (
    <>
      <AskButton open={open} onClick={() => (open ? close() : setOpen(true))} buttonRef={btn} />
      {open && <AssistantPanel turns={turns} busy={busy} onSend={send} onClose={close} />}
    </>
  );
}
