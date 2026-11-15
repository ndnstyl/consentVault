// The Ask panel's logic, apart from the screen: the fixed strings, the request, and what each answer from /assist/ask becomes on screen.
// Every fixed string passes the portal copy check (test/assistant.test.ts). The panel never builds an address from the answer's text: a link is a path the
// portal itself serves, taken from a citation or a fact the answer carries, and anything else is shown as text.

export const ASK_COPY = {
  button: 'Ask',
  title: 'Ask a question',
  greeting: 'Ask about a portal screen, your setup, your plan and usage, or what an error message means.',
  scope: 'I cannot read your records, contact points or evidence, and I cannot give legal advice. If I cannot answer, I pass your question to the team.',
  label: 'Your question',
  send: 'Send',
  sending: 'Looking through the help',
  close: 'Close',
  signIn: 'Your sign-in has ended. Sign in again to ask.',
  failed: 'The assistant is not answering right now. Nothing you typed was lost; it is still in the box.',
  tooLong: 'That question is longer than 4000 characters. Shorten it and send it again.',
  switchedOff: 'Questions are not available right now.',
} as const;

export const ASK_MAX = 4000;

export type AskKind = 'answer' | 'refusal' | 'handoff' | 'limited' | 'unavailable' | 'signin' | 'failed';
export interface AskLink { label: string; path: string }
export interface AskReply { kind: AskKind; text: string; links: AskLink[] }
export interface AskTurn { id: number; question: string; reply: AskReply }

const SCREEN_LABEL: Record<string, string> = {
  '/setup': 'Setup', '/billing': 'Billing', '/start/plan': 'Choose a plan', '/settings': 'Organization settings',
  '/sources': 'Capture sources', '/systems': 'Connected systems', '/credentials': 'Credentials',
};

const pathOf = (url: unknown): string | null => {
  if (typeof url !== 'string') return null;
  try {
    const u = new URL(url, 'https://app.consentvault.ai');
    return u.hostname === 'app.consentvault.ai' && u.pathname.startsWith('/') && !u.pathname.startsWith('//') ? u.pathname : null;
  } catch { return null; }
};

export function newConversationId(): string {
  return 'c_' + [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function toReply(status: number, body: unknown): AskReply {
  const b = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>;
  if (status === 401) return { kind: 'signin', text: ASK_COPY.signIn, links: [{ label: 'Sign in', path: '/sign-in' }] };
  if (status === 413) return { kind: 'failed', text: ASK_COPY.tooLong, links: [] };
  if (status === 503 && b.error === 'switched_off') return { kind: 'unavailable', text: ASK_COPY.switchedOff, links: [] };
  const text = typeof b.text === 'string' && b.text ? b.text : '';
  if (status === 429) return { kind: 'limited', text: text || ASK_COPY.failed, links: [] };
  if (status >= 500 || status === 0 || !text) return { kind: 'failed', text: ASK_COPY.failed, links: [] };
  const kind: AskKind = b.kind === 'refusal' || b.kind === 'handoff' ? b.kind : 'answer';
  const links: AskLink[] = [];
  const seen = new Set<string>();
  const add = (label: string, url: unknown) => {
    const p = pathOf(url);
    if (p && !seen.has(p)) { seen.add(p); links.push({ label: label.slice(0, 60), path: p }); }
  };
  for (const f of Array.isArray(b.facts_used) ? b.facts_used : []) {
    const x = f as Record<string, unknown>;
    const p = pathOf(x?.url);
    if (p) add(`Open ${SCREEN_LABEL[p] ?? 'the screen'}`, x.url);
  }
  for (const c of Array.isArray(b.citations) ? b.citations : []) {
    const x = c as Record<string, unknown>;
    if (typeof x?.title === 'string') add(x.title, x.url);
  }
  return { kind, text, links };
}

export async function ask(question: string, conversationId: string, orgId: string, f: typeof fetch = fetch): Promise<AskReply> {
  let res: Response;
  try {
    res = await f('/assist/ask', {
      method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json', accept: 'application/json', 'x-cv-org': orgId },
      body: JSON.stringify({ conversation_id: conversationId, question, page: typeof location === 'undefined' ? undefined : location.pathname }),
    });
  } catch { return toReply(0, null); }
  return toReply(res.status, await res.json().catch(() => null));
}

/** The header button and the panel appear only when the build flag is on; the core's own switch is a second, separate gate. */
export const assistantEnabled = (): boolean => process.env.NEXT_PUBLIC_ASSISTANT === 'on';
