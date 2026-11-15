import './support/register-tsx.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ASK_COPY, ASK_MAX, ask, toReply } from '../src/lib/assist.ts';
import { scanCopy } from '../src/lib/copycheck.ts';
const { AssistantPanel, AskButton } = await import('../src/components/Assistant.tsx');

test('every fixed string in the Ask panel passes the portal copy check', () => {
  for (const [k, v] of Object.entries(ASK_COPY)) assert.deepEqual(scanCopy(v), [], k);
  const src = fs.readFileSync('src/components/Assistant.tsx', 'utf8') + fs.readFileSync('src/lib/assist.ts', 'utf8');
  assert.ok(!/[–—]/.test(src), 'no dash');
});

test('an answer becomes text with links only to portal screens; a link to anywhere else is dropped', () => {
  const r = toReply(200, {
    kind: 'answer', text: 'Your plan is Growth.',
    facts_used: [{ tool: 'plan_and_usage', screen: '/billing', url: 'https://app.consentvault.ai/billing' }, { tool: 'x', screen: '/x', url: 'https://evil.example/billing' }],
    citations: [{ title: 'Plans and billing', url: 'https://app.consentvault.ai/billing' }, { title: 'Elsewhere', url: 'https://evil.example/' }, { title: 'Scheme trick', url: 'javascript:alert(1)' }],
  });
  assert.equal(r.kind, 'answer');
  assert.deepEqual(r.links, [{ label: 'Open Billing', path: '/billing' }]);
});

test('each failure is a named state and nothing is shown as an answer', () => {
  assert.equal(toReply(401, {}).kind, 'signin');
  assert.equal(toReply(413, {}).text, ASK_COPY.tooLong);
  assert.equal(toReply(503, { error: 'switched_off' }).text, ASK_COPY.switchedOff);
  assert.equal(toReply(429, { kind: 'limited', text: 'That is the limit for questions for now.' }).kind, 'limited');
  for (const s of [0, 500, 502, 503]) assert.equal(toReply(s, null).kind, 'failed', String(s));
  assert.equal(toReply(200, { kind: 'answer' }).kind, 'failed', 'an answer with no text is a failure, not a blank answer');
  assert.equal(toReply(200, { kind: 'handoff', text: 'I passed your question to the team.' }).kind, 'handoff');
});

test("the request names the tab's organization, goes to the portal itself, and carries no role or capability", async () => {
  let seen: { url: string; init: RequestInit } | null = null;
  const f = (async (url: string, init: RequestInit) => { seen = { url, init }; return new Response(JSON.stringify({ kind: 'answer', text: 'ok' }), { status: 200 }); }) as unknown as typeof fetch;
  const r = await ask('How do I start?', 'c_' + 'a'.repeat(32), 'org-1', f);
  assert.equal(r.text, 'ok');
  assert.equal(seen!.url, '/assist/ask');
  assert.equal((seen!.init.headers as Record<string, string>)['x-cv-org'], 'org-1');
  assert.equal(seen!.init.credentials, 'same-origin');
  assert.ok(!/role|capability/.test(String(seen!.init.body)));
  const down = (async () => { throw new Error('offline'); }) as unknown as typeof fetch;
  assert.equal((await ask('q', 'c_x', 'o', down)).kind, 'failed');
});

test('the panel is a labelled region with a labelled box, a live region and real links, and a long question is refused in the box', () => {
  const html = renderToStaticMarkup(React.createElement(AssistantPanel, { turns: [{ id: 1, question: 'Where do I start?', reply: { kind: 'answer', text: 'Open Setup.', links: [{ label: 'Open Setup', path: '/setup' }] } }], busy: false, onSend: () => {}, onClose: () => {} }));
  assert.match(html, /<section id="ask-panel"[^>]*role="region"[^>]*aria-labelledby=/);
  assert.match(html, /<label for="[^"]+">Your question<\/label>/);
  assert.match(html, /role="status" aria-live="polite"/);
  assert.match(html, /<a href="\/setup">Open Setup<\/a>/);
  const long = renderToStaticMarkup(React.createElement(AssistantPanel, { turns: [], busy: false, onSend: () => {}, onClose: () => {}, initialQuestion: 'x'.repeat(ASK_MAX + 1) }));
  assert.match(long, /role="alert"/);
  assert.match(long, /disabled/);
  assert.match(renderToStaticMarkup(React.createElement(AskButton, { open: false, onClick: () => {} })), /aria-expanded="false" aria-controls="ask-panel"/);
});

test('the header shows the button only when the build flag is on', () => {
  const shell = fs.readFileSync('src/components/Shell.tsx', 'utf8');
  assert.match(shell, /\{assistantEnabled\(\) && <Assistant \/>\}/);
  assert.equal(process.env.NEXT_PUBLIC_ASSISTANT, undefined, 'the flag is off unless a build sets it');
});
