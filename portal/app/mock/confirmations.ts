// Mock for contracts/confirmations.md and contracts/setup.md. Test data only.
import type * as T from '../src/lib/api/types.ts';
import type { Store } from './data.ts';
import { nid } from './data.ts';
import type { Deps } from './records.ts';

interface ConfState {
  settings: Omit<T.ConfirmationSettings, 'counts' | 'alarms'>;
  rules: T.ConfirmationRule[];
  templates: T.ConfirmationTemplateDetail[];
  sends: T.ConfirmationSend[];
  replies: T.ConfirmationReply[];
  skips: Record<string, { by: string; at: string; reason: string | null }>;
}
const SOURCES = ['src_web', 'src_sf'];
const SOURCE_NAME: Record<string, string> = { src_web: 'Website form', src_sf: 'Salesforce' };
const BRAND_NAME = (st: Store, id: string | null) => (id ? st.brands.find((b) => b.brand_id === id)?.display_name ?? null : null);

/** The four fixed texts as the sender builds them (confirmations.md section 2): the places a message fills in stay as placeholders. */
function fixedTexts(helpEmail: string | null): { version: number; items: T.FixedText[] } {
  return { version: 1, items: [
    { kind: 'confirmation', text: '<Sending brand>: on <date and time> you agreed to texts and calls about <purposes>. Full wording: <link> Msg frequency varies. Msg & data rates may apply. Reply STOP to opt out, HELP for help.' },
    { kind: 'optout_reply', text: '<Sending brand>: You are unsubscribed and will get no more texts or calls from us. Email is not affected. Reply START to get texts again.' },
    { kind: 'help_reply', text: `<Sending brand>: Help: ${helpEmail ?? '<help email>'}. Reply STOP to opt out of texts and calls. Msg frequency varies. Msg & data rates may apply.` },
    { kind: 'start_reply', text: '<Sending brand>: You will get texts from us again. Msg frequency varies. Msg & data rates may apply. Reply STOP to opt out, HELP for help.' },
  ] };
}

function buildConf(st: Store): ConfState {
  const s = st.scenario;
  const mode = s.confirmations;
  const full = s.setup === 'full';
  const email: T.SendingAccount = { account_id: 'acc_email', channel: 'email', provider: 'ses', status: mode === 'failing' ? 'failing' : 'connected', from: { email_address: 'hello@acme.com', display_name: 'Acme Lending' }, inbound_url: null, provider_replies: null, inbound_verified_at: null,
    last_check: mode === 'failing' ? { at: '2026-10-30T14:20:00Z', result: '502 provider_refused', detail: 'code 403: sending domain not verified' } : { at: new Date(Date.now() - 4 * 60e3).toISOString(), result: 'ok', detail: null }, created_at: '2026-10-30T13:00:00Z' };
  const sms: T.SendingAccount = { account_id: 'acc_sms', channel: 'sms', provider: 'twilio', status: mode === 'awaiting' ? 'awaiting_test_reply' : 'connected', from: { sender_id: 'MG-early-access', number_hint: '***0123' },
    inbound_url: 'https://api.consentvault.ai/v1/confirmations/inbound/k7PqRt3xW9', provider_replies: { stop: true, help: true, start: true }, inbound_verified_at: mode === 'awaiting' ? null : '2026-10-30T14:31:00Z', last_check: null, created_at: '2026-10-30T13:10:00Z' };
  const accounts = mode === 'empty' ? [] : [email, sms];
  const marked = mode === 'full' || mode === 'failing' || mode === 'link_unset';
  const linkHost: T.ConfirmationSettings['link_host'] = mode === 'empty' || mode === 'link_unset' ? { host: null, status: 'unset', txt_record: null, cname_target: null, verified_at: null } : { host: 'consent.acme.com', status: 'verified', txt_record: 'cv=8f2c0b1d9e', cname_target: 'edge.consentvault.ai', verified_at: '2026-10-30T14:30:00Z' };
  const on = (src: string, ch: 'email' | 'sms') => (mode === 'full' || mode === 'failing') && full && !(src === 'src_sf' && ch === 'sms') || (mode === 'texts_off' && ch === 'email' && full);
  const rules: T.ConfirmationRule[] = SOURCES.flatMap((src) => (['email', 'sms'] as const).map((ch) => ({
    source_id: src, source_name: SOURCE_NAME[src], brand_name: BRAND_NAME(st, 'brd_acme'), channel: ch, enabled: on(src, ch), sending_brand_id: 'brd_acme', template_id: ch === 'email' ? 'tpl_1' : null, send_for_test_events: true, dedupe_hours: 24, max_delay_minutes: 10, updated_by: 'Dana Ruiz', updated_at: '2026-10-30T14:40:00Z',
  })));
  const mkSend = (i: number, at: string, ch: 'email' | 'sms', status: T.ConfirmationSend['status'], masked: string, extra: Partial<T.ConfirmationSend> = {}): T.ConfirmationSend => ({
    send_id: `snd_${i}`, record_id: `rec_${i.toString(36).padStart(3, '0')}`, contact: { masked, fp_hint: ((Math.imul(i + 3, 0x9e3779b1) >>> 0).toString(16)).padStart(8, '0') }, channel: ch, source_id: 'src_web', source_name: SOURCE_NAME.src_web, brand_id: 'brd_acme', brand_name: BRAND_NAME(st, 'brd_acme'), status, skip_reason: null, dead_cause: null, failed_code: null,
    provider_status: null, attempts: 1, first_attempt_at: at, last_attempt_at: at, at, ...extra });
  const sends: T.ConfirmationSend[] = [
    mkSend(1, '2026-10-30T14:42:00Z', 'email', 'delivered', 'd***@example.com'),
    mkSend(2, '2026-10-30T14:42:05Z', 'sms', 'sent', '(555) ***-0142'),
    mkSend(3, '2026-10-30T13:31:00Z', 'sms', 'skipped', '(555) ***-0166', { skip_reason: 'quiet_hours', attempts: 0, first_attempt_at: null, last_attempt_at: null }),
    mkSend(4, '2026-10-29T23:20:00Z', 'email', 'delivered', 'g***@example.com', { source_id: 'src_sf', source_name: SOURCE_NAME.src_sf }),
    mkSend(5, '2026-10-29T20:12:00Z', 'email', 'skipped', 'j***@example.net', { skip_reason: 'brand_not_in_grant', attempts: 0, first_attempt_at: null, last_attempt_at: null }),
    mkSend(6, '2026-10-30T13:15:00Z', 'email', 'dead', 'k***@example.org', { attempts: 8, dead_cause: 'provider_unreachable', first_attempt_at: '2026-10-30T13:15:00Z' }),
    mkSend(7, '2026-10-30T13:02:00Z', 'sms', 'dead', '(555) ***-0188', { attempts: 8, dead_cause: 'retry:429' }),
    mkSend(8, '2026-10-30T12:57:00Z', 'sms', 'dead', '(555) ***-0190', { attempts: 8, dead_cause: 'retry:503' }),
    mkSend(9, '2026-10-30T12:40:00Z', 'sms', 'failed', '(555) ***-0171', { failed_code: '21610', attempts: 1 }),
    mkSend(10, '2026-10-30T12:30:00Z', 'sms', 'sent', '(555) ***-0161', { source_id: null, source_name: null, brand_id: null, brand_name: null }),
  ];
  const old = s.nulls.includes('conf_old_reply');
  const mkReply = (i: number, masked: string, text: string, hours: number): T.ConfirmationReply => ({
    reply_id: `rpl_${i}`, received_at: new Date(Date.now() - hours * 3600e3).toISOString(), account_id: 'acc_sms', channel: 'sms', from: { masked, fp_hint: ((Math.imul(i + 11, 0x9e3779b1) >>> 0).toString(16)).padStart(8, '0') }, matched_record_id: `rec_00${i}`,
    text, verdict: 'needs_review', reason: 'No stop word', matched_words: [], state: 'to_read', event_id: null, our_reply: null, marked_by: null, marked_at: null, mark_reason: null, unread_hours: hours });
  const replies = mode === 'empty' ? [] : [mkReply(1, '(555) ***-0161', 'no more of these thanks', old ? 26 : 3), mkReply(2, '(555) ***-0142', 'thanks, when does it launch?', 1)];
  return {
    settings: {
      version: 1, sender: { organization_name: 'Acme Lending', postal_address: '100 Main St, Tampa FL 33602', help_contact: { email: 'hello@acme.com', phone: null } }, send_cap_per_hour: 500, link_host: linkHost,
      texting_registration: marked ? { status: 'marked', kind: '10dlc', reference: null, samples_statement_version: 1, marked_by: 'Dana Ruiz', marked_at: '2026-10-30T14:35:00Z' } : { status: 'not_marked', kind: null, reference: null, samples_statement_version: null, marked_by: null, marked_at: null },
      fixed_text_version: 1, fixed_texts: fixedTexts('hello@acme.com'), sending_accounts: accounts,
    },
    rules, templates: [{ template_id: 'tpl_1', channel: 'email', name: 'Thanks for asking: here is what you agreed to', body_version: 1, version: 1, status: 'current', updated_at: '2026-10-30T14:40:00Z', subject: 'Thanks for asking: here is what you agreed to', opening_line: 'Thanks for asking about early access.', created_by: 'Dana Ruiz', created_at: '2026-10-30T14:40:00Z' }], sends: mode === 'empty' ? [] : sends, replies, skips: Object.fromEntries((['system', 'confirmations'] as const).filter((k) => s.nulls.includes(`skipped.${k}`)).map((k) => [k, { by: 'Dana Ruiz', at: '2026-10-30T15:00:00Z', reason: null }])),
  };
}
export function conf(st: Store): ConfState {
  if (!st.ext.conf) st.ext.conf = buildConf(st);
  return st.ext.conf;
}

const STEPS: T.SetupStepName[] = ['brand', 'source', 'wording', 'credential', 'first_event', 'policy', 'system', 'confirmations'];
const DEV_STEPS: T.SetupStepName[] = ['source', 'credential', 'first_event', 'system'];
const ago = (m: number) => new Date(Date.now() - m * 60e3).toISOString();

export function setupAnswer(st: Store): T.SetupAnswer {
  const c = conf(st);
  const sc = st.scenario;
  const facts: Record<T.SetupStepName, { kind: string; id: string; at: string } | null> = {
    brand: st.brands[0] ? { kind: 'brand', id: st.brands[0].brand_id, at: st.brands[0].created_at } : null,
    source: st.sources[0] ? { kind: 'source', id: st.sources[0].source_id, at: st.sources[0].created_at } : null,
    wording: st.disclosures[0] ? { kind: 'disclosure', id: st.disclosures[0].sha256, at: st.disclosures[0].registered_at } : null,
    credential: st.credentials.find((x) => x.scope === 'capture' && !x.revoked_at) ? { kind: 'credential', id: st.credentials.find((x) => x.scope === 'capture' && !x.revoked_at)!.credential_id, at: ago(900) } : null,
    first_event: sc.firstEvent !== 'none' ? { kind: 'event', id: 'evt_1', at: '2026-10-31T14:42:07Z' } : null,
    policy: st.policies.find((p) => p.status === 'approved') ? { kind: 'policy', id: String(st.policies.find((p) => p.status === 'approved')!.version), at: ago(800) } : null,
    system: st.systems.find((y) => y.last_test && y.last_test.result === 'accepted') ? { kind: 'system', id: st.systems.find((y) => y.last_test && y.last_test.result === 'accepted')!.system_id, at: ago(700) } : null,
    confirmations: c.rules.some((r) => r.enabled) ? { kind: 'confirmation_rule', id: `${c.rules.find((r) => r.enabled)!.source_id}/${c.rules.find((r) => r.enabled)!.channel}`, at: ago(600) } : null,
  };
  const partialSteps = STEPS.filter((s) => sc.nulls.includes(`setup.${s}`));
  const steps: T.SetupStep[] = STEPS.map((step) => {
    const skip = c.skips[step] ?? null;
    const fact = facts[step];
    let status: T.SetupStep['status'] = fact ? 'done' : skip ? 'skipped' : 'to_do';
    let reason: string | null = null;
    if (!fact && !skip) {
      if (st.status === 'suspended' && (step === 'credential' || step === 'system')) { status = 'blocked'; reason = 'org_suspended'; }
      else if (step === 'first_event' && !facts.wording) { status = 'blocked'; reason = 'needs:wording'; }
    }
    if (partialSteps.includes(step)) status = null;
    return { step, status, required: step !== 'system' && step !== 'confirmations', evidence: partialSteps.includes(step) ? null : fact, blocked_reason: partialSteps.includes(step) ? null : reason,
      skipped_by: skip?.by ?? null, skipped_at: skip?.at ?? null, skip_reason: skip?.reason ?? null, roles: DEV_STEPS.includes(step) ? ['admin', 'developer'] : ['admin'] };
  });
  const cur = steps.find((s) => s.status !== 'done' && s.status !== 'skipped');
  return { steps, current_step: cur ? cur.step : null, complete: steps.filter((s) => s.required).every((s) => s.status === 'done'), partial: partialSteps };
}

const MARK_TEXT = (brand: string, purposes: string) => `${brand}: on Oct 30, 2026 at 10:42 AM ET you agreed to texts and calls about ${purposes}. Full wording: consent.acme.com/c/r/7Hq2... Msg frequency varies. Msg & data rates may apply. Reply STOP to opt out, HELP for help.`;

export function registerConfirmations(x: Deps): void {
  const { route, E, OK, allow, page, suspendedBlock, nowIso } = x;

  // ---- setup ----
  route('GET', '/v1/setup', (c) => OK(setupAnswer(c.st)));
  route('POST', '/v1/setup/steps/:step\\:skip', (c) => {
    const step = c.m.groups!.step as T.SetupStepName;
    const r0 = allow(c, 'admin', 'developer'); if (r0) return r0;
    if (step !== 'system' && step !== 'confirmations') return E(422, 'step_not_skippable', 'Only the optional steps can be skipped.');
    if (step === 'confirmations' && c.st.role !== 'admin') return E(403, 'role_not_allowed', 'Only an admin may skip this step.');
    const cur = setupAnswer(c.st).steps.find((s) => s.step === step)!;
    if (cur.status === 'done') return E(422, 'validation_failed', 'A done step cannot be skipped.');
    conf(c.st).skips[step] = { by: 'Dana Ruiz', at: nowIso(), reason: c.body?.reason ?? null };
    return OK(setupAnswer(c.st).steps.find((s) => s.step === step));
  });
  route('POST', '/v1/setup/steps/:step\\:unskip', (c) => {
    const step = c.m.groups!.step as T.SetupStepName;
    const r0 = allow(c, 'admin', 'developer'); if (r0) return r0;
    if (step !== 'system' && step !== 'confirmations') return E(422, 'step_not_skippable');
    if (step === 'confirmations' && c.st.role !== 'admin') return E(403, 'role_not_allowed', 'Only an admin may turn this step back on.');
    delete conf(c.st).skips[step];
    return OK(setupAnswer(c.st).steps.find((s) => s.step === step));
  });

  // ---- confirmations: settings, accounts, link host, registration ----
  route('GET', '/v1/confirmations/settings', (c) => {
    const k = conf(c.st); const n = c.st.scenario.nulls;
    const toRead = k.replies.filter((r) => r.state === 'to_read');
    const counts: T.ConfirmationSettings['counts'] = n.includes('conf_counts') ? null : {
      sent_24h: 14, failed_24h: 1, dead_24h: k.sends.filter((s) => s.status === 'dead').length, to_read: toRead.length, to_read_oldest_at: toRead.length ? toRead[0].received_at : null,
      provider_refusal_stops_24h: n.includes('conf_refusal') ? 2 : 0, inbound_signature_failures_1h: n.includes('conf_sigfail') ? 7 : 0,
      delivery_reports: { last_at: '2026-10-30T10:00:00Z', stale: n.includes('conf_stale') },
    };
    const alarms: T.ConfirmationAlarm[] = [
      ...(n.includes('conf_old_reply') ? [{ kind: 'replies_unread_24h', opened_at: ago(120), detail: { count: 1 } }] : []),
      ...(k.settings.sending_accounts.some((a) => a.status === 'failing') ? [{ kind: 'sending_account_failing', opened_at: ago(300), detail: { account_id: 'acc_email', channel: 'email', last_code: '403' } }] : []),
    ];
    const out: Record<string, unknown> = { ...k.settings, counts, alarms };
    if (n.includes('conf_fixed')) { delete out.fixed_texts; }
    return OK(out);
  });
  route('PUT', '/v1/confirmations/settings', (c) => {
    const r0 = allow(c, 'admin'); if (r0) return r0;
    const b = c.body ?? {};
    if (!b.organization_name || !b.postal_address || !b.help_contact?.email) return E(422, 'validation_failed', '', { help_contact: 'email required' });
    const k = conf(c.st);
    k.settings.sender = { organization_name: b.organization_name, postal_address: b.postal_address, help_contact: { email: b.help_contact.email, phone: b.help_contact.phone ?? null } }; k.settings.version++; k.settings.fixed_texts = fixedTexts(b.help_contact.email);
    return OK({ ...k.settings, counts: null });
  });
  route('POST', '/v1/confirmations/sending-accounts', (c) => {
    const r0 = allow(c, 'admin', 'developer'); if (r0) return r0;
    const sus = suspendedBlock(c); if (sus) return sus;
    const b = c.body ?? {}; const k = conf(c.st);
    if (b.channel === 'sms') {
      if (b.provider !== 'twilio') return E(422, 'provider_not_supported', 'Only Twilio is supported for text.');
      const cr = b.credentials ?? {};
      if (!/^AC[0-9a-f]{32}$/.test(String(cr.account_sid ?? ''))) return E(422, 'validation_failed', '', { 'credentials.account_sid': 'AC plus 32 hex' });
      if (!cr.api_key_sid || !cr.api_key_secret || !cr.auth_token) return E(422, 'validation_failed', '', { credentials: 'api key and auth token required' });
      if (typeof b.provider_replies_itself !== 'boolean') return E(422, 'validation_failed', '', { provider_replies_itself: 'required' });
      const a: T.SendingAccount = { account_id: nid('acc'), channel: 'sms', provider: 'twilio', status: 'awaiting_test_reply', from: { sender_id: b.sender?.messaging_service_sid ?? 'number', number_hint: `***${String(b.sender?.number ?? '0000').slice(-4)}` },
        inbound_url: `https://api.consentvault.ai/v1/confirmations/inbound/${nid('k')}`, provider_replies: { stop: b.provider_replies_itself, help: b.provider_replies_itself, start: b.provider_replies_itself }, inbound_verified_at: null, last_check: null, created_at: nowIso() };
      k.settings.sending_accounts = k.settings.sending_accounts.filter((y) => y.channel !== 'sms'); k.settings.sending_accounts.push(a);
      return OK(a, 201);
    }
    if (b.channel === 'email') {
      if (!['ses', 'postmark'].includes(b.provider)) return E(422, 'provider_not_supported');
      if (!b.from?.email_address) return E(422, 'validation_failed', '', { from: 'required' });
      const a: T.SendingAccount = { account_id: nid('acc'), channel: 'email', provider: b.provider, status: 'connected', from: { email_address: b.from.email_address, display_name: b.from.display_name }, inbound_url: null, provider_replies: null, inbound_verified_at: null, last_check: { at: nowIso(), result: 'ok', detail: null }, created_at: nowIso() };
      k.settings.sending_accounts = k.settings.sending_accounts.filter((y) => y.channel !== 'email'); k.settings.sending_accounts.push(a);
      return OK(a, 201);
    }
    return E(422, 'validation_failed', '', { channel: 'email or sms' });
  });
  route('POST', '/v1/confirmations/sending-accounts/:id\\:check', (c) => {
    const r0 = allow(c, 'admin', 'developer'); if (r0) return r0;
    const a = conf(c.st).settings.sending_accounts.find((y) => y.account_id === c.m.groups!.id); if (!a) return E(404, 'not_found');
    if (a.status === 'failing') return E(502, 'provider_refused', 'The provider refused.', { provider_code: '403' });
    a.last_check = { at: nowIso(), result: 'ok', detail: null }; return OK(a);
  });
  route('PATCH', '/v1/confirmations/sending-accounts/:id', (c) => {
    const r0 = allow(c, 'admin', 'developer'); if (r0) return r0;
    const a = conf(c.st).settings.sending_accounts.find((y) => y.account_id === c.m.groups!.id); if (!a) return E(404, 'not_found');
    const v = !!c.body?.provider_replies_itself; a.provider_replies = { stop: v, help: v, start: v }; return OK(a);
  });
  route('DELETE', '/v1/confirmations/sending-accounts/:id', (c) => {
    const r0 = allow(c, 'admin'); if (r0) return r0;
    const k = conf(c.st); const a = k.settings.sending_accounts.find((y) => y.account_id === c.m.groups!.id); if (!a) return E(404, 'not_found');
    if (!String(c.body?.reason ?? '').trim()) return E(422, 'validation_failed', '', { reason: 'required' });
    k.settings.sending_accounts = k.settings.sending_accounts.filter((y) => y !== a);
    for (const r of k.rules) if (r.channel === a.channel) r.enabled = false;
    return { status: 204 };
  });
  route('POST', '/v1/confirmations/link-host', (c) => {
    const r0 = allow(c, 'admin', 'developer'); if (r0) return r0;
    const host = String(c.body?.host ?? '').trim().toLowerCase();
    if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/.test(host)) return E(422, 'validation_failed', '', { host: 'not a host name' });
    const k = conf(c.st);
    k.settings.link_host = { host, status: 'pending_dns', txt_record: 'cv=8f2c0b1d9e', cname_target: 'edge.consentvault.ai', verified_at: null };
    return OK(k.settings.link_host);
  });
  route('POST', '/v1/confirmations/link-host\\:verify', (c) => {
    const r0 = allow(c, 'admin', 'developer'); if (r0) return r0;
    const k = conf(c.st); const h = k.settings.link_host;
    if (!h.host) return E(409, 'link_host_not_verified', 'No host is set.');
    if (h.host.includes('bad')) return E(422, 'link_host_dns_missing', 'The TXT record was not found.', { expected: `TXT _cv-verify.${h.host} cv=8f2c0b1d9e` });
    h.status = 'verified'; h.verified_at = '2026-10-30T16:20:00Z'; return OK(h);
  });
  route('POST', '/v1/confirmations/texting-registration', (c) => {
    const r0 = allow(c, 'admin'); if (r0) return r0;
    const b = c.body ?? {}; const k = conf(c.st);
    if (b.accepted !== true || b.samples_included !== true) return E(422, 'acknowledgement_required');
    if (!['10dlc', 'toll_free', 'short_code'].includes(b.kind)) return E(422, 'validation_failed', '', { kind: 'required' });
    const sms = k.settings.sending_accounts.find((a) => a.channel === 'sms');
    if (!sms) return E(409, 'no_sending_account'); if (sms.status === 'awaiting_test_reply') return E(409, 'inbound_not_verified');
    k.settings.texting_registration = { status: 'marked', kind: b.kind, reference: b.reference ?? null, samples_statement_version: k.settings.fixed_text_version ?? 1, marked_by: 'Dana Ruiz', marked_at: nowIso() };
    return OK(k.settings.texting_registration);
  });
  route('POST', '/v1/confirmations/texting-registration\\:withdraw', (c) => {
    const r0 = allow(c, 'admin'); if (r0) return r0;
    if (!String(c.body?.reason ?? '').trim()) return E(422, 'validation_failed', '', { reason: 'required' });
    const k = conf(c.st);
    k.settings.texting_registration = { status: 'not_marked', kind: null, reference: null, samples_statement_version: null, marked_by: null, marked_at: null };
    for (const r of k.rules) if (r.channel === 'sms') r.enabled = false;
    return OK(k.settings.texting_registration);
  });

  // ---- rules, templates, preview, test ----
  route('GET', '/v1/confirmations/rules', (c) => OK(page(conf(c.st).rules, c.query)));
  route('PUT', '/v1/confirmations/rules/:src/:ch', (c) => {
    const r0 = allow(c, 'admin'); if (r0) return r0;
    const k = conf(c.st); const b = c.body ?? {};
    const rule = k.rules.find((r) => r.source_id === c.m.groups!.src && r.channel === c.m.groups!.ch);
    const known = ['enabled', 'sending_brand_id', 'template_id', 'send_for_test_events', 'dedupe_hours', 'max_delay_minutes'];
    const bad = Object.keys(b).filter((x2) => !known.includes(x2));
    if (bad.length || typeof b.enabled !== 'boolean' || !b.sending_brand_id) return E(422, 'validation_failed', '', Object.fromEntries((bad.length ? bad : ['enabled']).map((x2) => [x2, 'invalid'])));
    if (b.dedupe_hours !== undefined && (b.dedupe_hours < 1 || b.dedupe_hours > 168)) return E(422, 'validation_failed', '', { dedupe_hours: '1 to 168' });
    if (!rule || !c.st.brands.some((y) => y.brand_id === b.sending_brand_id) || (b.template_id && !k.templates.some((t2) => t2.template_id === b.template_id))) return E(404, 'not_found');
    if (b.enabled) {
      const sus = suspendedBlock(c); if (sus) return sus;
      const acc = k.settings.sending_accounts.find((a) => a.channel === (c.m.groups!.ch === 'sms' ? 'sms' : 'email'));
      if (!acc) return E(409, 'no_sending_account', 'No sending account is connected for that channel.');
      if (c.m.groups!.ch === 'sms' && acc.status === 'awaiting_test_reply') return E(409, 'inbound_not_verified');
      if (c.m.groups!.ch === 'sms' && k.settings.texting_registration.status !== 'marked') return E(409, 'texting_not_registered');
      if (!k.settings.sender.organization_name || !k.settings.sender.postal_address || !k.settings.sender.help_contact?.email) return E(409, 'sender_details_missing');
      if (k.settings.link_host.status !== 'verified') return E(409, 'link_host_not_verified');
    }
    Object.assign(rule, { enabled: b.enabled, sending_brand_id: b.sending_brand_id, brand_name: BRAND_NAME(c.st, b.sending_brand_id), template_id: c.m.groups!.ch === 'email' ? b.template_id ?? rule.template_id : null, send_for_test_events: b.send_for_test_events ?? rule.send_for_test_events, dedupe_hours: b.dedupe_hours ?? rule.dedupe_hours, max_delay_minutes: b.max_delay_minutes ?? rule.max_delay_minutes, updated_by: 'Dana Ruiz', updated_at: nowIso() });
    return OK(rule);
  });
  const listShape = (t2: T.ConfirmationTemplateDetail, newest: number): T.ConfirmationTemplate => ({ template_id: t2.template_id, channel: 'email', name: t2.subject, body_version: t2.version, status: t2.version === newest ? 'current' : 'superseded', updated_at: t2.created_at });
  route('GET', '/v1/confirmations/templates', (c) => {
    const r0 = allow(c, 'admin', 'developer', 'compliance_viewer'); if (r0) return r0;
    const all = conf(c.st).templates; const newest = Math.max(0, ...all.map((t2) => t2.version));
    return OK({ items: all.slice().sort((a, b) => b.version - a.version).map((t2) => listShape(t2, newest)), next_cursor: null });
  });
  route('GET', '/v1/confirmations/templates/:id', (c) => {
    const r0 = allow(c, 'admin', 'developer', 'compliance_viewer'); if (r0) return r0;
    const all = conf(c.st).templates; const t2 = all.find((y) => y.template_id === c.m.groups!.id); if (!t2) return E(404, 'not_found');
    return OK({ ...listShape(t2, Math.max(...all.map((y) => y.version))), subject: t2.subject, opening_line: t2.opening_line, version: t2.version, created_by: t2.created_by, created_at: t2.created_at });
  });
  route('POST', '/v1/confirmations/templates', (c) => {
    const r0 = allow(c, 'admin'); if (r0) return r0;
    const b = c.body ?? {};
    if (typeof b.subject !== 'string' || b.subject.length < 1 || b.subject.length > 80 || (b.opening_line ?? '').length > 300 || Object.keys(b).some((y) => y !== 'subject' && y !== 'opening_line')) return E(422, 'validation_failed', '', { subject: '1 to 80 characters' });
    const k = conf(c.st); const v = k.templates.length + 1;
    const t2: T.ConfirmationTemplateDetail = { template_id: `tpl_${v}`, channel: 'email', name: b.subject, body_version: v, version: v, status: 'current', updated_at: nowIso(), subject: b.subject, opening_line: b.opening_line ?? null, created_by: 'Dana Ruiz', created_at: nowIso() };
    k.templates.push(t2); return OK({ template_id: t2.template_id, version: t2.version }, 201);
  });
  route('POST', '/v1/confirmations\\:preview', (c) => {
    const b = c.body ?? {}; const k = conf(c.st);
    if (!c.st.sources.some((s) => s.source_id === b.source_id)) return E(404, 'not_found');
    const host = k.settings.link_host.host ?? 'consent.example.com';
    const brand = c.st.brands[0]?.display_name ?? 'Acme Lending'; const s = k.settings.sender;
    if (b.channel === 'sms') {
      const body = MARK_TEXT(brand, 'marketing').replace('consent.acme.com', host);
      return OK({ subject: null, body, segments: Math.ceil(body.length / 153), characters: body.length });
    }
    const tpl = b.template ?? k.templates.find((y) => y.template_id === (b.template_id ?? 'tpl_1')) ?? k.templates[0];
    if (b.template && Object.keys(b.template).some((y) => y !== 'subject' && y !== 'opening_line')) return E(422, 'validation_failed', '', { template: 'only subject and opening_line' });
    const body = [tpl.opening_line ?? '', '', `On Oct 30, 2026 at 10:42 AM ET you agreed to the following from ${brand} at Website form:`, '"By checking this box, I agree that Acme Lending may contact me by text message, calls and artificial or prerecorded voice at the number I gave, about marketing. Consent is not a condition of purchase."',
      'Channels: call, text, email. Purposes: marketing.', '', `To stop email from ${brand}, use this link: https://${host}/c/stop/7Hq2Lm. The page also lets you stop texts and calls. Texts and calls are not affected unless you choose that.`, '', `${s.organization_name}, ${s.postal_address}. Help: ${s.help_contact?.email ?? ''}.`].join('\n').trim();
    return OK({ subject: tpl.subject, body, segments: null, characters: body.length });
  });
  route('POST', '/v1/confirmations\\:test', (c) => {
    const r0 = allow(c, 'admin'); if (r0) return r0;
    const b = c.body ?? {};
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(b.contact ?? '')) && b.channel === 'email') return E(422, 'invalid_contact');
    return OK({ send_id: nid('snd'), status: 'sent' });
  });

  // ---- sends and replies ----
  route('GET', '/v1/confirmations/sends', (c) => {
    const r0 = allow(c, 'admin', 'developer', 'compliance_viewer'); if (r0) return r0;
    let items = conf(c.st).sends.slice();
    const st = c.query.get('status'); if (st) items = items.filter((s) => s.status === st);
    const ch = c.query.get('channel'); if (ch) items = items.filter((s) => s.channel === ch);
    const src = c.query.get('source_id'); if (src) items = items.filter((s) => s.source_id === src);
    if (c.st.role === 'developer') items = items.map((s) => ({ ...s, contact: { masked: null, fp_hint: s.contact.fp_hint } }));
    return OK(page(items, c.query));
  });
  route('GET', '/v1/confirmations/replies', (c) => {
    const r0 = allow(c, 'admin', 'compliance_viewer'); if (r0) return r0;
    let items = conf(c.st).replies.slice(); const st = c.query.get('state'); if (st) items = items.filter((r) => r.state === st);
    return OK(page(items, c.query));
  });
  route('POST', '/v1/confirmations/replies/:id\\:mark', (c) => {
    const r0 = allow(c, 'admin'); if (r0) return r0;
    const r = conf(c.st).replies.find((y) => y.reply_id === c.m.groups!.id); if (!r) return E(404, 'not_found');
    if (!['stop', 'not_stop'].includes(c.body?.decision) || !String(c.body?.reason ?? '').trim()) return E(422, 'validation_failed', '', { reason: 'required' });
    r.state = c.body.decision; r.unread_hours = null; r.marked_by = { member_id: 'mem_dana', display_name: 'Dana Ruiz' }; r.marked_at = nowIso(); r.mark_reason = c.body.reason;
    return OK(r);
  });
}
