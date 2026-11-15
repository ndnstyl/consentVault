import React, { useEffect, useRef, useState } from 'react';
import { ApiError } from '../lib/api/client.ts';
import type { RecordLink, RecordLinkBody, RecordLinkScope } from '../lib/api/types.ts';
import { fmtDateTime, fmtNum } from '../lib/format.ts';
import { useAction, useResource } from '../lib/hooks.ts';
import { useSession } from '../lib/session.tsx';
import { useToast } from '../lib/toast.tsx';
import { canDo } from '../lib/roles.ts';
import { ConfirmDialog, Dialog } from '../components/Dialog.tsx';
import { Banner, Btn, Check, Chip, CopyButton, DataTable, ErrorBlock, Skeleton, StateBlock, TextArea, TextField, Time } from '../components/ui.tsx';

// Record links: one sealed record shared by a link, on a public page that shows only what the sender switches on.
// The customer-facing name is "record link". The page itself, its recomputed checks and its one-record file are served by the
// vault; this screen only chooses the scope, shows the exact page before the link exists, lists the links and withdraws them.

export const SCOPE_DEFAULTS: RecordLinkScope = { show_org_name: true, show_contact: false, allow_contact_match: true, show_page_url: false, show_bot_check: false };

export const ACK_PHRASE = 'show contact';
export const ACK_SENTENCE = 'Anyone who holds this link will see the phone number or email address.';

export const COPY = {
  title: 'Share this record',
  lede: 'A record link opens a page with no sign-in. It shows this one sealed record and the integrity checks recomputed from it. Choose what the page shows. You can withdraw the link at any time.',
  always: 'The page always shows the consent box value as sent, the wording as sent with its fingerprint, the decision time and the arrival time, and the sealed row. It never shows the IP address, the device, other events or the contact\'s history.',
  org: 'Show the organization name',
  contact: 'Show the phone number or email address',
  contactHint: 'Off by default.',
  match: 'Let a visitor test a contact point against this record',
  matchHint: 'The visitor learns only whether it matches, yes or no. Ten attempts a day, then the box locks until you reset it.',
  pageUrl: 'Show the page address the form was on',
  pageUrlHint: 'The address can carry click ids and other identifiers.',
  bot: 'Show the bot check result',
  noteLabel: 'Label for this link (only you see it)',
  ackLabel: `Type "${ACK_PHRASE}" to confirm`,
  previewTitle: 'Exactly what the page will show',
  previewNote: 'This is the page as the vault will serve it, built from your choices. Nothing is public until you create the link.',
  previewSource: 'Show the page text',
  create: 'Create record link',
  creating: 'Creating',
  createdTitle: 'Your record link',
  createdNote: 'This is the only time the link is shown. Copy it now. If you lose it, withdraw this one and create another.',
  emptyList: 'No record links yet',
  emptyNote: 'Open a contact in Evidence lookup and choose Share this record on an event.',
  listCaption: 'Record links, newest first',
  withdraw: 'Withdraw',
  withdrawTitle: 'Withdraw this record link?',
  withdrawBody: 'Anyone who opens the link afterward sees that the sender withdrew it. The record itself is not changed. This is recorded in the audit log.',
  reset: 'Reset match lock',
  panelTitle: 'Record links',
  panelLede: 'Links you have shared, with how often each was opened. The link itself is shown only when it is created.',
} as const;

export type BodyResult = { ok: true; body: RecordLinkBody } | { ok: false; reason: string };

export function buildBody(i: { eventId: string; scope: RecordLinkScope; ack: string; note: string }): BodyResult {
  const body: RecordLinkBody = { event_id: i.eventId, ...i.scope };
  if (i.scope.show_contact) {
    if (i.ack.trim().toLowerCase() !== ACK_PHRASE) return { ok: false, reason: `Type "${ACK_PHRASE}" to confirm.` };
    body.contact_ack = ACK_SENTENCE;
  }
  const note = i.note.trim();
  if (note) body.note = note;
  return { ok: true, body };
}

type Api = ReturnType<typeof useSession>['api'];

export const previewLink = (api: Api, body: RecordLinkBody): Promise<string> => api.recordLinks.preview(body);

export async function createLink(api: Api, body: RecordLinkBody): Promise<{ share_id: string; link: string }> {
  const r = await api.recordLinks.create(body);
  const link = r.link ?? r.url;
  if (!link) throw new ApiError(502, 'link_missing', 'The vault created the link but did not return it.', null);
  return { share_id: r.share_id, link };
}

export type PreviewState = { status: 'idle' } | { status: 'loading' } | { status: 'ok'; html: string } | { status: 'error'; error: ApiError };

/** The page text is in a frame that runs no script and has no access to this page, and the same text is shown beside it. */
export function PreviewFrame({ html }: { html: string }) {
  return (
    <>
      <iframe title={COPY.previewTitle} sandbox="" srcDoc={html} className="preview-frame" style={{ width: '100%', minHeight: 360, border: '1px solid var(--line, #ccc)' }} />
      <details className="mt4">
        <summary>{COPY.previewSource}</summary>
        <pre className="mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{html}</pre>
      </details>
    </>
  );
}

export function ShareForm({ scope, ack, note, preview, onScope, onAck, onNote }: {
  scope: RecordLinkScope; ack: string; note: string; preview: PreviewState;
  onScope: (k: keyof RecordLinkScope, v: boolean) => void; onAck: (v: string) => void; onNote: (v: string) => void;
}) {
  const box = (k: keyof RecordLinkScope, label: string, hint?: string) => (
    <Check label={label} hint={hint} name={k} checked={scope[k]} onChange={(e) => onScope(k, e.target.checked)} />
  );
  return (
    <>
      <p>{COPY.lede}</p>
      <p className="hint">{COPY.always}</p>
      <fieldset className="mt4">
        <legend>What the page shows</legend>
        {box('show_org_name', COPY.org)}
        {box('show_contact', COPY.contact, COPY.contactHint)}
        {scope.show_contact && (
          <div className="mb4">
            <Banner kind="warning" title="This puts the contact point on a public page.">{ACK_SENTENCE}</Banner>
            <TextField label={COPY.ackLabel} name="contact_ack" value={ack} onChange={(e) => onAck(e.target.value)} autoComplete="off" spellCheck={false} />
          </div>
        )}
        {box('allow_contact_match', COPY.match, COPY.matchHint)}
        {box('show_page_url', COPY.pageUrl, COPY.pageUrlHint)}
        {box('show_bot_check', COPY.bot)}
      </fieldset>
      <TextField label={COPY.noteLabel} name="note" value={note} onChange={(e) => onNote(e.target.value)} autoComplete="off" />
      <h3 className="sec mt5">{COPY.previewTitle}</h3>
      <p className="hint">{COPY.previewNote}</p>
      {preview.status === 'loading' && <Skeleton what="the preview" rows={2} />}
      {preview.status === 'error' && (
        <ErrorBlock title="The preview did not load" err={preview.error} next="Change a choice or try again. Nothing was created." headingLevel={3} />
      )}
      {preview.status === 'ok' && <PreviewFrame html={preview.html} />}
    </>
  );
}

/** The scope dialog for one event: choices, the exact preview, then Create. The link is shown once, after it is created. */
export function ShareDialog({ eventId, onClose, onCreated }: { eventId: string; onClose: () => void; onCreated?: () => void }) {
  const { api } = useSession();
  const toast = useToast();
  const [scope, setScope] = useState<RecordLinkScope>(SCOPE_DEFAULTS);
  const [ack, setAck] = useState('');
  const [note, setNote] = useState('');
  const [preview, setPreview] = useState<PreviewState>({ status: 'idle' });
  const [made, setMade] = useState<{ share_id: string; link: string } | null>(null);
  const [touched, setTouched] = useState(false);
  const seq = useRef(0);
  const built = buildBody({ eventId, scope, ack, note });
  const create = useAction((b: RecordLinkBody) => createLink(api, b));
  const previewKey = JSON.stringify([scope, built.ok]);

  useEffect(() => {
    if (!built.ok) { setPreview({ status: 'idle' }); return; }
    const mine = ++seq.current;
    setPreview({ status: 'loading' });
    previewLink(api, built.body).then(
      (html) => { if (mine === seq.current) setPreview({ status: 'ok', html }); },
      (e) => { if (mine === seq.current) setPreview({ status: 'error', error: e instanceof ApiError ? e : new ApiError(0, 'unreachable', '', null) }); },
    );
    return () => { seq.current++; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [previewKey]);

  if (made) {
    return (
      <Dialog title={COPY.createdTitle} onClose={onClose}>
        <p>{COPY.createdNote}</p>
        <p className="mono" style={{ overflowWrap: 'anywhere' }}>{made.link}</p>
        <div className="actions"><CopyButton text={made.link} label="Copy link" ariaLabel="Copy the record link" /><Btn variant="primary" onClick={onClose}>Done</Btn></div>
      </Dialog>
    );
  }
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!built.ok) { setTouched(true); return; }
    const r = await create.run(built.body);
    if (r.ok) { setMade(r.value); toast('Record link created. Recorded in the audit log.'); onCreated?.(); }
  };
  return (
    <Dialog title={COPY.title} onClose={onClose} wide>
      <form onSubmit={submit} noValidate>
        <ShareForm scope={scope} ack={ack} note={note} preview={preview}
          onScope={(k, v) => { setScope((s) => ({ ...s, [k]: v })); if (k === 'show_contact' && !v) setAck(''); }} onAck={setAck} onNote={setNote} />
        {touched && !built.ok && <p className="field-err" role="alert">{built.reason}</p>}
        {create.error && <ErrorBlock title="The record link was not created" err={create.error} next="Try again. Nothing was shared." headingLevel={3} />}
        <div className="actions">
          <Btn onClick={onClose}>Cancel</Btn>
          <Btn type="submit" variant="primary" busy={create.busy} busyLabel={COPY.creating} disabled={preview.status !== 'ok'}>{COPY.create}</Btn>
        </div>
      </form>
    </Dialog>
  );
}

export function RecordLinksTable({ links, busy, onWithdraw, onReset }: { links: RecordLink[]; busy: string | null; onWithdraw: (l: RecordLink) => void; onReset: (l: RecordLink) => void }) {
  if (links.length === 0) return <StateBlock kind="empty" title={COPY.emptyList}>{COPY.emptyNote}</StateBlock>;
  return (
    <DataTable caption={COPY.listCaption} rows={links} rowKey={(l) => l.share_id}
      columns={[
        { key: 'c', header: 'Created', render: (l) => <Time iso={l.created_at} />, primary: true },
        { key: 'n', header: 'Label', render: (l) => l.note || 'No label' },
        { key: 'v', header: 'Opened', right: true, render: (l) => <span className="num">{fmtNum(l.view_count)}</span> },
        { key: 's', header: 'State', render: (l) => (l.withdrawn_at
          ? <Chip tone="st-info" icon="i-info" title={fmtDateTime(l.withdrawn_at)}>Withdrawn</Chip>
          : <Chip tone="st-success" icon="i-ok">Active</Chip>) },
        { key: 'm', header: 'Match box', render: (l) => (l.withdrawn_at ? 'Not applicable' : l.match_locked ? 'Locked' : l.allow_contact_match === false ? 'Off' : 'Open') },
      ]}
      actions={(l) => (l.withdrawn_at ? null : (
        <span className="gap-row">
          {l.match_locked && <Btn size="sm" busy={busy === `reset:${l.share_id}`} busyLabel="Resetting" onClick={() => onReset(l)}>{COPY.reset}</Btn>}
          <Btn size="sm" variant="danger" disabled={busy === `revoke:${l.share_id}`} onClick={() => onWithdraw(l)}>{COPY.withdraw}</Btn>
        </span>
      ))} />
  );
}

/** The list of record links with the withdraw action, for admins. */
export function RecordLinksPanel() {
  const { api, role } = useSession();
  const toast = useToast();
  const manage = canDo(role, 'recordlink.manage');
  const res = useResource(() => (manage ? api.recordLinks.list({ limit: 100 }) : Promise.resolve(null)), [api, manage]);
  const [withdrawing, setWithdrawing] = useState<RecordLink | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [resetErr, setResetErr] = useState<ApiError | null>(null);
  if (!manage) return null;
  const reset = async (l: RecordLink) => {
    setBusy(`reset:${l.share_id}`); setResetErr(null);
    try { await api.recordLinks.resetMatch(l.share_id); toast('Match lock reset. Recorded in the audit log.'); res.reload(); }
    catch (e) { setResetErr(e instanceof ApiError ? e : new ApiError(0, 'unreachable', '', null)); }
    setBusy(null);
  };
  return (
    <section className="card mt5" aria-label={COPY.panelTitle}>
      <h2>{COPY.panelTitle}</h2>
      <p className="hint">{COPY.panelLede}</p>
      {res.status === 'loading' && <Skeleton what="record links" rows={2} />}
      {res.status === 'error' && <ErrorBlock title="Record links did not load" err={res.error} next="Try again." onRetry={res.reload} actions={<Btn onClick={res.reload}>Try again</Btn>} headingLevel={3} />}
      {resetErr && <ErrorBlock title="The match lock was not reset" err={resetErr} next="Try again." headingLevel={3} />}
      {res.status === 'ok' && res.data && <RecordLinksTable links={res.data.items} busy={busy} onWithdraw={setWithdrawing} onReset={reset} />}
      {withdrawing && (
        <ConfirmDialog title={COPY.withdrawTitle} destructive confirmLabel={COPY.withdraw} busyLabel="Withdrawing"
          body={<p>{COPY.withdrawBody}</p>} failTitle="The link was not withdrawn" failNext="Try again. The link is still active."
          onClose={() => setWithdrawing(null)}
          onConfirm={async () => {
            try { await api.recordLinks.revoke(withdrawing.share_id); toast('Record link withdrawn. Recorded in the audit log.'); res.reload(); return null; }
            catch (e) { return e instanceof ApiError ? e : new ApiError(0, 'unreachable', '', null); }
          }} />
      )}
    </section>
  );
}
