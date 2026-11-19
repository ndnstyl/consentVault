import type { StopNotice } from './api/types.ts';

// The pop-up an admin sees on sign-in for stops recorded since they last acknowledged. ConsentVault only notifies:
// the words never say it acted on a customer's system. The state below is the whole rule that the pop-up cannot be
// closed except by acknowledging: a dismiss attempt (Escape, a click outside, a second tab) changes nothing, and only a
// successful acknowledgement of the listed notices removes them.

export type PopupState =
  | { phase: 'loading' | 'failed'; notices: StopNotice[]; error: string | null }
  | { phase: 'open'; notices: StopNotice[]; busy: boolean; error: string | null }
  | { phase: 'clear'; notices: StopNotice[]; error: null };

export type PopupAction =
  | { type: 'loaded'; notices: StopNotice[] }
  | { type: 'load_failed'; error: string }
  | { type: 'dismiss_attempt' }
  | { type: 'acknowledging' }
  | { type: 'acknowledged'; ids: string[] }
  | { type: 'acknowledge_failed'; error: string };

export const initialPopup: PopupState = { phase: 'loading', notices: [], error: null };

export function popupReducer(s: PopupState, a: PopupAction): PopupState {
  switch (a.type) {
    case 'loaded': return a.notices.length ? { phase: 'open', notices: a.notices, busy: false, error: null } : { phase: 'clear', notices: [], error: null };
    case 'load_failed': return { phase: 'failed', notices: [], error: a.error };
    case 'dismiss_attempt': return s;
    case 'acknowledging': return s.phase === 'open' ? { ...s, busy: true, error: null } : s;
    case 'acknowledge_failed': return s.phase === 'open' ? { ...s, busy: false, error: a.error } : s;
    case 'acknowledged': {
      if (s.phase !== 'open') return s;
      const left = s.notices.filter((n) => !a.ids.includes(n.notice_id));
      return left.length ? { phase: 'open', notices: left, busy: false, error: null } : { phase: 'clear', notices: [], error: null };
    }
  }
}

export const DELIVERY_WORD: Record<string, string> = { delivered: 'delivered', waiting: 'waiting', refused: 'refused', none_connected: 'none connected' };

/** One line per connected system, with its status; a stop with none connected says so in one line. */
export function deliveryLines(n: StopNotice): string[] {
  return n.delivery.map((d) => (d.system ? `${d.system} (${DELIVERY_WORD[d.status]})` : DELIVERY_WORD[d.status]));
}

export const CHANNEL_WORD: Record<string, string> = { sms: 'Text message', voice: 'Phone call', artificial_voice: 'Automated phone call', email: 'Email' };
export const channelWords = (channels: string[]) => channels.map((c) => CHANNEL_WORD[c] ?? c).join(', ');

export const STOP_NOTE = 'ConsentVault has recorded this stop. Acting on it in your own systems is up to you.';
export const STOP_NOTE_MANY = 'ConsentVault has recorded these stops. Acting on them in your own systems is up to you.';
export const stopNote = (count: number) => (count > 1 ? STOP_NOTE_MANY : STOP_NOTE);
