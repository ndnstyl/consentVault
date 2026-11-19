import React, { useEffect, useReducer } from 'react';
import { useSession } from '../lib/session.tsx';
import { fmtDateTime } from '../lib/format.ts';
import { Btn, LinkBtn } from './ui.tsx';
import { Dialog } from './Dialog.tsx';
import { ApiError } from '../lib/api/client.ts';
import { channelWords, deliveryLines, initialPopup, popupReducer, stopNote } from '../lib/stop-notices.ts';

/** The stop-notice pop-up: shown on load to an admin while any stop is unacknowledged. There is no close button and Escape does nothing. */
export function StopNotices() {
  const s = useSession();
  const [st, dispatch] = useReducer(popupReducer, initialPopup);
  const admin = s.phase === 'ready' && s.role === 'admin';
  useEffect(() => {
    if (!admin) return;
    let live = true;
    s.api.stopNotices.list().then(
      (r) => { if (live) dispatch({ type: 'loaded', notices: r.notices, remaining: r.remaining }); },
      (e) => { if (live) dispatch({ type: 'load_failed', error: e instanceof ApiError ? e.detail || e.code : 'The stop notices could not be read.' }); },
    );
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [admin, s.orgId]);
  if (!admin) return null;
  if (st.phase === 'failed') {
    return <div className="offline-bar" role="alert">Stop notices could not be loaded: {st.error} <Btn size="sm" onClick={() => window.location.reload()}>Reload</Btn></div>;
  }
  if (st.phase !== 'open') return null;
  const ack = async () => {
    dispatch({ type: 'acknowledging' });
    const ids = st.notices.map((n) => n.notice_id);
    let done;
    try { done = await s.api.stopNotices.acknowledge(ids); }
    catch (e) { dispatch({ type: 'acknowledge_failed', error: e instanceof ApiError ? e.detail || e.code : 'The acknowledgement was not saved.' }); return; }
    if (done.remaining <= 0) { dispatch({ type: 'acknowledged', ids }); return; }
    try { const next = await s.api.stopNotices.list(); dispatch({ type: 'loaded', notices: next.notices, remaining: next.remaining }); }
    catch (e) { dispatch({ type: 'load_failed', error: `Your acknowledgement was saved, but the next stops could not be loaded (${e instanceof ApiError ? e.detail || e.code : 'try again'}).` }); }
  };
  const many = st.notices.length > 1;
  return (
    <Dialog title={many ? `${st.notices.length} stops were recorded` : 'A stop was recorded'} onClose={() => dispatch({ type: 'dismiss_attempt' })} alert wide dim initialFocus="[data-ack]">
      <ul>
        {st.notices.map((n) => (
          <li key={n.notice_id}>
            <strong>{n.contact}</strong>{`: ${channelWords(n.channels)} (${n.purposes.join(', ')}), ${fmtDateTime(n.stopped_at)}`}
            <div><small>Your connected systems</small></div>
            <ul>{deliveryLines(n).map((l) => <li key={l}><small>{l}</small></li>)}</ul>
          </li>
        ))}
      </ul>
      {st.remaining > st.notices.length && <p>{`${st.remaining - st.notices.length} more are waiting; they show after you acknowledge these.`}</p>}
      <p>{stopNote(st.notices.length)}</p>
      {st.error && <p role="alert">{`Your acknowledgement was not saved: ${st.error} Try again.`}</p>}
      <div className="actions">
        <LinkBtn href="/records?has_stop=true" variant="secondary">Open the records</LinkBtn>
        <Btn data-ack="" variant="primary" busy={st.busy} busyLabel="Saving" onClick={ack}>I have seen this</Btn>
      </div>
    </Dialog>
  );
}
