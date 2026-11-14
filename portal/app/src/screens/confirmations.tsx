import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { ApiError, allPages } from '../lib/api/client.ts';
import type { Brand, ConfirmationPreview, ConfirmationReply, ConfirmationRule, ConfirmationSend, ConfirmationSettings, SendingAccount, Source } from '../lib/api/types.ts';
import { NA, REGISTRATION_DIALOG, causeLine, deadCauseWord, skipWord } from '../lib/copy.ts';
import { checkContact, fmtDate, fmtDateTime, fmtNum, fmtTime } from '../lib/format.ts';
import { useAction, usePoll, useResource } from '../lib/hooks.ts';
import { Link, useRouter } from '../lib/router.tsx';
import { canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { ConfirmDialog } from '../components/Dialog.tsx';
import { Banner, Btn, Chip, CodeBlock, CopyButton, DataTable, ErrorBlock, LinkBtn, NotAvailable, PageHead, Radio, SelectField, Skeleton, StateBlock, SuccessBanner, TextArea, TextField, Tile, Time } from '../components/ui.tsx';

const LEDE = 'When a new consent arrives, send the person one message from your own email domain or texting number that repeats what they agreed to, when, and how to stop. Every message, reply and stop is recorded as evidence. Each message sent counts as one event on your plan; provider charges stay on your own accounts.';
const SENDING_RULE = "A message goes only on a channel the consent names, only when the consent names the brand it is sent as, only to the phone or email given, and never when a stop is on record. Texts go only between 9 AM and 8 PM Monday to Saturday or noon and 8 PM Sunday in the person's time zone, told from the number's area code; outside those hours, or when the zone cannot be told, the text is not sent at all. Email has no sending hours: an email-only sign-up always gets its email confirmation.";
const STOP_WORDS = "Any reply containing a stop word (STOP, END, CANCEL, UNSUBSCRIBE, QUIT, REVOKE, OPT OUT, REMOVE, \"do not text\", \"do not call\") stops texts, calls and AI-voice calls; email keeps its own consent. The opt-out reply goes within 5 minutes unless your provider already sends one. START asks the release rule to turn texts back on; calls stay stopped. A stop made by staff, a connected system or an import is not lifted. Matching uses whole words only, any letter case; 'bus stop' or 'don't stop' is not a stop (the second goes to Replies to read). When you answered Yes to 'Does Twilio reply to STOP, HELP and START itself', ConsentVault sends no second reply.";
const PROVIDER: Record<string, string> = { ses: 'Amazon SES', postmark: 'Postmark', twilio: 'Twilio' };
const pname = (a: SendingAccount | undefined) => (a ? PROVIDER[a.provider] ?? a.provider : '');
const chWord = (c: string) => (c === 'sms' ? 'Text' : 'Email');

function ago(iso: string | null | undefined): string {
  if (!iso) return NA;
  const m = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 60000));
  if (m < 1) return 'just now';
  if (m < 60) return `${m} minute${m === 1 ? '' : 's'} ago`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h} hour${h === 1 ? '' : 's'} ago` : fmtDate(iso);
}

/** Why the on switch cannot be pressed yet. Link host and sender details are left to the service so its named refusal shows. */
function blockReason(channel: 'email' | 'sms', s: ConfirmationSettings): string | null {
  const acc = s.sending_accounts.find((a) => a.channel === channel);
  if (!acc) return `Off until ${channel === 'sms' ? 'a text' : 'an email'} sending account is connected`;
  if (channel === 'sms' && acc.status === 'awaiting_test_reply') return 'Off until a test reply arrives: no test reply has reached ConsentVault';
  if (channel === 'sms' && s.texting_registration.status !== 'marked') return 'Off until texting registration is marked complete';
  return null;
}

function Switch({ checked, ariaLabel, onToggle, reason, busy, text }: { checked: boolean; ariaLabel: string; onToggle: (next: boolean) => void; reason?: string | null; busy?: boolean; text?: string }) {
  const rid = useId();
  const blocked = !!reason;
  return (
    <span className="switch-row">
      <button type="button" role="switch" aria-checked={checked} aria-label={ariaLabel} aria-disabled={blocked || busy ? true : undefined} aria-describedby={reason ? rid : undefined} className="switch" onClick={() => { if (!blocked && !busy) onToggle(!checked); }}>
        <i /><span className="lbl">{text ?? (checked ? 'On' : 'Off')}</span>
      </button>
      {reason && <span className="cellsub" id={rid}>{reason}</span>}
    </span>
  );
}

function Linkified({ text }: { text: string }) {
  const parts = text.split(/(https?:\/\/[^\s]+?)(?=[.,;]?(?:\s|$))/g);
  return <>{parts.map((p, i) => (/^https?:\/\//.test(p) ? <a key={i} href={p} target="_blank" rel="noopener noreferrer">{p.replace(/^https?:\/\//, '')}</a> : <React.Fragment key={i}>{p}</React.Fragment>))}</>;
}

// ---------- 25 Confirmation messages ----------
export function Confirmations() {
  const { api, role, orgName, status } = useSession();
  const isAdmin = role === 'admin';
  const canAcct = canDo(role, 'confirmations.account');
  const canReplies = canDo(role, 'confirmations.replies');
  const settings = useResource(() => api.confirmations.settings(), [api]);
  const rules = useResource(() => allPages((c) => api.confirmations.rules({ cursor: c })), [api]);
  const [filter, setFilter] = useState('');
  const activity = useResource(() => api.confirmations.sends({ limit: 50, ...(filter ? { status: filter } : {}) }), [api, filter]);
  const since = useMemo(() => new Date(Date.now() - 24 * 3600e3).toISOString(), []);
  const failures = useResource(() => api.confirmations.sends({ limit: 200, from: since }).then((p) => p.items.filter((s) => s.status === 'failed' || s.status === 'dead')), [api]);
  const sources = useResource<Source[] | null>(() => (role === 'admin' || role === 'developer' ? allPages((c) => api.sources.list({ cursor: c })) : Promise.resolve(null)), [api, role]);
  const brands = useResource<Brand[] | null>(() => (role === 'admin' || role === 'developer' ? allPages((c) => api.brands.list({ cursor: c })) : Promise.resolve(null)), [api, role]);
  const replies = useResource<ConfirmationReply[] | null>(() => (canReplies ? allPages((c) => api.confirmations.replies({ state: 'to_read', cursor: c })) : Promise.resolve(null)), [api, canReplies]);
  const [connect, setConnect] = useState<'email' | 'sms' | null>(null);
  const [arrivedAt, setArrivedAt] = useState<string | null>(null);
  const [ruleErr, setRuleErr] = useState<ApiError | null>(null);
  const [registration, setRegistration] = useState<'mark' | 'withdraw' | null>(null);
  const [disconnect, setDisconnect] = useState<SendingAccount | null>(null);
  const [decide, setDecide] = useState<{ reply: ConfirmationReply; decision: 'stop' | 'not_stop' } | null>(null);
  const [toggling, setToggling] = useState<string | null>(null);
  const textCard = useRef<HTMLDivElement>(null);

  const s = settings.status === 'ok' ? settings.data : null;
  const prevAwaiting = useRef(false);
  useEffect(() => {
    const sms = s?.sending_accounts.find((a) => a.channel === 'sms');
    if (prevAwaiting.current && sms && sms.status === 'connected') setArrivedAt(sms.inbound_verified_at);
    prevAwaiting.current = sms?.status === 'awaiting_test_reply';
  }, [s]);

  const reloadAll = () => { settings.refresh(); rules.refresh(); activity.refresh(); failures.refresh(); replies.refresh(); };
  const emailAcc = s?.sending_accounts.find((a) => a.channel === 'email');
  const smsAcc = s?.sending_accounts.find((a) => a.channel === 'sms');
  const ruleList = rules.status === 'ok' ? rules.data : [];
  const ruleFor = (src: string, ch: 'email' | 'sms') => ruleList.find((r) => r.source_id === src && r.channel === ch);
  const sourceRows: { id: string; name: string }[] = sources.status === 'ok' && sources.data ? sources.data.filter((x) => x.status === 'active').map((x) => ({ id: x.source_id, name: x.name })) : [...new Set(ruleList.map((r) => r.source_id))].map((id) => ({ id, name: ruleList.find((r) => r.source_id === id)?.source_name ?? NA }));
  const sendList = activity.status === 'ok' ? activity.data.items : [];
  const failList = failures.status === 'ok' ? failures.data : [];
  const lastSent = (src: string) => sendList.filter((x) => x.source_id === src && (x.status === 'sent' || x.status === 'delivered'))[0]?.at ?? null;
  const unreadOld = replies.status === 'ok' && replies.data ? replies.data.filter((r) => (r.unread_hours ?? 0) > 24).length : (s?.alarms ?? []).filter((a) => a.kind === 'replies_unread_24h').reduce((n, a) => n + Number((a.detail as { count?: number } | null)?.count ?? 1), 0);
  const counts = s?.counts ?? null;
  const dead = failList.filter((x) => x.status === 'dead');

  const toggle = async (src: string, ch: 'email' | 'sms', next: boolean) => {
    const rule = ruleFor(src, ch); if (!rule) return;
    const brand = rule.sending_brand_id ?? (brands.status === 'ok' && brands.data ? brands.data[0]?.brand_id : undefined);
    if (!brand) { setRuleErr(new ApiError(422, 'validation_failed', '', null)); return; }
    setToggling(`${src}:${ch}`); setRuleErr(null);
    try { await api.confirmations.saveRule(src, ch, { enabled: next, sending_brand_id: brand, ...(ch === 'email' && rule.template_id ? { template_id: rule.template_id } : {}) }); rules.refresh(); settings.refresh(); }
    catch (e) { setRuleErr(e as ApiError); }
    setToggling(null);
  };

  const refusals = counts?.provider_refusal_stops_24h ?? 0;
  const sigFails = counts?.inbound_signature_failures_1h ?? 0;
  const smsName = pname(smsAcc) || 'Your text provider';
  const countsNull = !!s && (counts === null || counts.to_read === null || counts.failed_24h === null || counts.sent_24h === null);
  const otherAlarms = (s?.alarms ?? []).filter((a) => !['replies_unread_24h', 'sending_account_failing', 'link_host_failing', 'delivery_reports_stale', 'provider_refusal_stop', 'inbound_signature_failures'].includes(a.kind));

  return (
    <>
      <PageHead title="Confirmation messages" lede={LEDE} />
      {settings.status === 'loading' && <Skeleton what="confirmation settings" rows={4} variant="tiles" />}
      {settings.status === 'error' && <ErrorBlock title="Confirmation settings did not load" err={settings.error} next="Try again. Messages already queued keep sending, and replies keep being recorded." actions={<Btn onClick={settings.reload}>Try again</Btn>} />}
      {s && (
        <>
          {status === 'suspended' && <Banner kind="danger" title={`${orgName} is suspended.`} action={isAdmin ? <LinkBtn href="/billing" size="sm">Open billing</LinkBtn> : undefined}>No confirmation messages are sent; each is recorded as not sent. Replies and stops are still recorded, and opt-out replies still go out.</Banner>}
          {role === 'developer' && <Banner kind="info" title="You can connect and check sending accounts and set the link host.">Turning messages on, marking texting registration and reading replies need an admin.</Banner>}
          {countsNull && <Banner kind="warning" title="Some figures did not load.">{`Failed counts and replies to read are not available (503 service_unavailable). Rules and settings below are current.`}</Banner>}
          {unreadOld > 0 && <Banner kind="danger" title={`${unreadOld} ${unreadOld === 1 ? 'reply has' : 'replies have'} been unread for more than 24 hours.`} action={canReplies ? <a className="btn btn-secondary btn-sm" href="#replies">Read it now</a> : undefined}>It may ask for something your team needs to act on.</Banner>}
          {refusals > 0 && (
            <Banner kind="danger" title={`${smsName} refused ${refusals} text${refusals === 1 ? '' : 's'} in the last 24 hours because ${refusals === 1 ? 'that number opted' : 'those numbers opted'} out at ${smsName} (error 21610).`} action={canReplies ? <LinkBtn href="/records?has_stop=true&channel=sms" size="sm">{`See the ${refusals} record${refusals === 1 ? '' : 's'}`}</LinkBtn> : undefined}>
              {`Stops for texts, calls and AI-voice calls were recorded for ${refusals === 2 ? 'both' : refusals === 1 ? 'it' : 'each'} and sent to your connected systems. This means a STOP reached ${smsName} but not ConsentVault; check that the webhook still points here.`}
            </Banner>
          )}
          {sigFails > 0 && (
            <Banner kind="danger" title={`${sigFails} messages to your reply address were refused in the last 10 minutes.`} action={<Btn size="sm" onClick={() => textCard.current?.scrollIntoView()}>Check the text account</Btn>}>
              {`Cause: the request signature did not match your ${smsName} account (401). Real replies may not be reaching ConsentVault, so a stop could be missed. Next: check that the webhook in ${smsName} is the address shown under your text account, and that the account credentials here are current. Your provider retries refused messages, and a provider refusal of the next send to an opted-out number records the stop.`}
            </Banner>
          )}
          {counts?.delivery_reports.stale && (
            <Banner kind="warning" title={`Delivery reports from ${smsName} stopped arriving${counts.delivery_reports.last_at ? ` at ${fmtTime(counts.delivery_reports.last_at)}` : ''}.`} action={<Btn size="sm" onClick={() => textCard.current?.scrollIntoView()}>Check the text account</Btn>}>
              {`Cause: the status callback has not answered for ${counts.delivery_reports.last_at ? Math.max(3, Math.round((Date.now() - Date.parse(counts.delivery_reports.last_at)) / 3600e3)) : 3} hours. Messages still send and replies still arrive; delivered or undelivered is not known for messages since then. Next: check the text account.`}
            </Banner>
          )}
          {emailAcc?.status === 'failing' && <FailingBanner acc={emailAcc} canCheck={canAcct} onDone={settings.refresh} />}
          {smsAcc?.status === 'failing' && <FailingBanner acc={smsAcc} canCheck={canAcct} onDone={settings.refresh} />}
          {s.link_host.status === 'failing' && <Banner kind="danger" title="Your wording link host is not answering.">Cause: the host no longer resolves. Next: check the records at your DNS provider. Messages with a dead link are not sent.</Banner>}
          {otherAlarms.map((a) => <Banner key={`${a.kind}:${a.opened_at}`} kind="warning" title={a.kind === 'optout_reply_dead' ? 'An opt-out reply was not sent within 5 minutes.' : a.kind === 'send_cap_reached' ? 'The hourly sending limit was reached.' : `An alert of a kind this page does not know (${a.kind}).`}>{`Opened ${fmtDateTime(a.opened_at)}.`}</Banner>)}
          {ruleErr && <ErrorBlock title="The rule was not changed" err={ruleErr} next="Fix what the cause names, then try again. Nothing was changed." />}

          {s.sending_accounts.length === 0 && connect === null && (
            <StateBlock kind="empty" title="Confirmation messages are off" actions={canAcct ? <><Btn variant="primary" onClick={() => setConnect('email')}>Connect an email provider</Btn><Btn variant="primary" onClick={() => setConnect('sms')}>Connect a text provider</Btn></> : undefined}>
              Messages go out from your own email domain and your own texting number, never from ConsentVault. To start: connect your email or text provider, set a wording link host on your domain, and add your sender details (organization name, postal address, help contact). Supported: email through Amazon SES or Postmark; text through Twilio.
            </StateBlock>
          )}
          {connect === 'email' && !emailAcc && canAcct && <ConnectEmail onDone={() => { setConnect(null); settings.refresh(); }} onCancel={() => setConnect(null)} />}
          {connect === 'sms' && !smsAcc && canAcct && <ConnectSms onDone={() => settings.refresh()} onCancel={() => setConnect(null)} />}
          {smsAcc && smsAcc.status === 'awaiting_test_reply' && canAcct && <SmsSteps acc={smsAcc} onSettings={settings.setData} onChanged={settings.refresh} />}
          {arrivedAt && smsAcc?.status === 'connected' && <SuccessBanner title={`Your test text arrived at ${fmtTime(arrivedAt)}.`}>Replies to your number now reach ConsentVault. Next: set your wording link host, then mark your texting registration complete.</SuccessBanner>}

          {(s.sending_accounts.length > 0 || connect !== null) && (
            <>
              <div className="grid g4">
                <div className="card acct">
                  <div className="k">Email sending account</div>
                  <AccountLine acc={emailAcc} />
                  <div className="btn-row">
                    {!emailAcc && canAcct && <Btn size="sm" onClick={() => setConnect('email')}>Connect an email provider</Btn>}
                    {emailAcc && canAcct && <CheckButton acc={emailAcc} onDone={settings.refresh} label={emailAcc.status === 'failing' ? 'Fix the account' : 'Check the account'} />}
                    {emailAcc && isAdmin && <Btn size="sm" variant="quiet" onClick={() => setDisconnect(emailAcc)}>{`Disconnect ${pname(emailAcc)}`}</Btn>}
                  </div>
                </div>
                <div className="card acct" ref={textCard}>
                  <div className="k">Text sending account</div>
                  <AccountLine acc={smsAcc} />
                  {smsAcc?.provider_replies && <p className="hint">{smsAcc.provider_replies.stop ? `Opt-out reply sent by ${pname(smsAcc)} (you answered that ${pname(smsAcc)} replies itself), not by ConsentVault.` : 'Opt-out reply sent by ConsentVault within 5 minutes of a stop.'}</p>}
                  <div className="btn-row">
                    {!smsAcc && canAcct && <Btn size="sm" onClick={() => setConnect('sms')}>Connect a text provider</Btn>}
                    {smsAcc && smsAcc.status !== 'awaiting_test_reply' && canAcct && <CheckButton acc={smsAcc} onDone={settings.refresh} label="Check the account" />}
                    {smsAcc && isAdmin && <Btn size="sm" variant="quiet" onClick={() => setDisconnect(smsAcc)}>{`Disconnect ${pname(smsAcc)}`}</Btn>}
                  </div>
                </div>
                <div className="card acct">
                  <div className="k">Wording link host</div>
                  <p><Chip tone={s.link_host.status === 'verified' ? 'st-success' : s.link_host.status === 'failing' ? 'st-danger' : 'st-neutral'} icon={s.link_host.status === 'verified' ? 'i-ok' : s.link_host.status === 'failing' ? 'i-err' : 'i-dash'}>{{ verified: 'Verified', failing: 'Failing', pending_dns: 'Waiting for DNS', unset: 'Not set' }[s.link_host.status]}</Chip></p>
                  {s.link_host.host && <p>{`${s.link_host.host} (your domain)`}</p>}
                  {s.link_host.status === 'verified' && s.link_host.verified_at && <p>{`Verified on ${fmtDateTime(s.link_host.verified_at)}.`}</p>}
                </div>
                <div className="card acct">
                  <div className="k">Texting registration</div>
                  <p><Chip tone={s.texting_registration.status === 'marked' ? 'st-success' : 'st-neutral'} icon={s.texting_registration.status === 'marked' ? 'i-ok' : 'i-dash'}>{s.texting_registration.status === 'marked' ? 'Marked complete' : 'Not marked'}</Chip></p>
                  {s.texting_registration.status === 'marked'
                    ? <p>{`Marked by ${s.texting_registration.marked_by ?? NA}, ${s.texting_registration.marked_at ? fmtDate(s.texting_registration.marked_at) : NA}. You mark this; ConsentVault does not check it with carriers.`}</p>
                    : <p>Texts stay off until you mark it.</p>}
                  {isAdmin && (s.texting_registration.status === 'marked'
                    ? <div className="btn-row"><Btn size="sm" onClick={() => setRegistration('withdraw')}>Withdraw</Btn></div>
                    : <div className="btn-row"><Btn size="sm" disabled={!smsAcc} onClick={() => setRegistration('mark')}>Mark texting registration complete</Btn></div>)}
                </div>
              </div>

              {s.link_host.status !== 'verified' && canAcct && <LinkHostCard s={s} onChanged={settings.refresh} />}
              <SenderCard s={s} canEdit={isAdmin} onSaved={settings.refresh} />

              <div className="grid g4 mt5">
                <Tile label="Sent, last 24 hours" value={counts && counts.sent_24h !== null ? <span className="num">{fmtNum(counts.sent_24h)}</span> : null} />
                <Tile label="Failed or undelivered, last 24 hours" value={counts && counts.failed_24h !== null && counts.dead_24h !== null ? <span className="num">{fmtNum(counts.failed_24h + counts.dead_24h)}</span> : null} />
                {canReplies
                  ? <Tile label="Replies to read" value={counts && counts.to_read !== null ? <span className="num">{fmtNum(counts.to_read)}</span> : null} action={<a className="btn btn-secondary btn-sm" href="#replies">Read replies</a>} />
                  : <Tile label="Replies to read" value="Not shown" sub="Replies are personal data" />}
              </div>

              <h2 className="sec mt6">By capture source</h2>
              {rules.status === 'error' && <ErrorBlock title="The rules did not load" err={rules.error} next="Try again." actions={<Btn onClick={rules.reload}>Try again</Btn>} />}
              {rules.status === 'ok' && (
                <DataTable caption="By capture source" rows={sourceRows} rowKey={(r) => r.id}
                  columns={[
                    { key: 's', header: 'Source', primary: true, render: (r) => r.name },
                    { key: 'b', header: 'Sends as', render: (r) => ruleFor(r.id, 'email')?.brand_name ?? ruleFor(r.id, 'sms')?.brand_name ?? NA },
                    ...(['email', 'sms'] as const).map((ch) => ({
                      key: ch, header: `${chWord(ch)} confirmation`,
                      render: (r: { id: string; name: string }) => {
                        const rule = ruleFor(r.id, ch);
                        if (!rule) return <NotAvailable />;
                        if (!isAdmin) return rule.enabled ? 'On' : 'Off';
                        return <Switch checked={rule.enabled} ariaLabel={`${chWord(ch)} confirmation for ${r.name}`} busy={toggling === `${r.id}:${ch}`} reason={rule.enabled ? null : blockReason(ch, s)} onToggle={(next) => toggle(r.id, ch, next)} />;
                      },
                    })),
                    { key: 'l', header: 'Last sent', render: (r) => (lastSent(r.id) ? <Time iso={lastSent(r.id)} /> : 'Not yet') },
                    { key: 'f', header: 'Failed or undelivered, last 24 hours', render: (r) => (failures.status === 'ok' ? String(failList.filter((x) => x.source_id === r.id).length) : <NotAvailable />) },
                  ]}
                  actions={(r) => <Link className="btn btn-secondary btn-sm" href={`/confirmations/${encodeURIComponent(r.id)}/email`}>{isAdmin ? 'Edit' : 'View'}</Link>} />
              )}
              <p className="hint mt4">{SENDING_RULE}</p>

              <h2 className="sec mt6">Recent activity</h2>
              <div className="inline-form mb4">
                <SelectField label="Show" name="activity-filter" value={filter} onChange={(e) => setFilter(e.target.value)} options={[{ value: '', label: 'Everything' }, { value: 'sent', label: 'Sent' }, { value: 'delivered', label: 'Sent, delivered' }, { value: 'failed', label: 'Failed' }, { value: 'dead', label: 'Undelivered after 2 hours' }, { value: 'skipped', label: 'Not sent' }]} />
              </div>
              {activity.status === 'loading' && <Skeleton what="recent activity" rows={3} variant="table" />}
              {activity.status === 'error' && <ErrorBlock title="Recent activity did not load" err={activity.error} next="Try again." actions={<Btn onClick={activity.reload}>Try again</Btn>} />}
              {activity.status === 'ok' && (activity.data.items.length === 0
                ? <p className="hint">Nothing matches yet.</p>
                : <DataTable caption="Recent activity" rows={activity.data.items} rowKey={(x) => x.send_id}
                    columns={[
                      { key: 'w', header: 'When', primary: true, render: (x) => <Time iso={x.at} /> },
                      { key: 'c', header: 'Contact', render: (x) => (x.contact.masked ?? <span className="mono">{`fingerprint ${x.contact.fp_hint}`}</span>) },
                      { key: 'ch', header: 'Channel', render: (x) => chWord(x.channel) },
                      { key: 's', header: 'Source', render: (x) => x.source_name ?? 'None' },
                      { key: 'b', header: 'Sent as', render: (x) => x.brand_name ?? 'None' },
                      { key: 'h', header: 'What happened', render: (x) => whatHappened(x, ruleList) },
                    ]} />)}

              {dead.length > 0 && (
                <>
                  <h2 className="sec mt6">{`Undelivered after 2 hours (${dead.length}, last 24 hours)`}</h2>
                  <DataTable caption="Undelivered sends" rows={dead} rowKey={(x) => x.send_id}
                    columns={[
                      { key: 'w', header: 'First tried', primary: true, render: (x) => <Time iso={x.first_attempt_at ?? x.at} /> },
                      { key: 'c', header: 'Contact', render: (x) => (x.contact.masked ?? <span className="mono">{`fingerprint ${x.contact.fp_hint}`}</span>) },
                      { key: 'ch', header: 'Channel', render: (x) => chWord(x.channel) },
                      { key: 'a', header: 'Attempts', render: (x) => String(x.attempts) },
                      { key: 'l', header: 'Last answer', render: (x) => deadCauseWord(x.dead_cause) },
                    ]} />
                  <p className="hint mt4">Undelivered messages are recorded and never sent again: a confirmation hours later would read as a new message. Nothing about the person's consent changed.</p>
                </>
              )}

              {canReplies && (
                <section id="replies" className="mt6">
                  <h2 className="sec">{`Replies to read (${replies.status === 'ok' && replies.data ? replies.data.length : counts?.to_read ?? NA})`}</h2>
                  <p className="hint">Replies with a stop word were already recorded as stops. These contain none. A person decides; nothing changes until you choose.</p>
                  {replies.status === 'error' && <ErrorBlock title="Replies did not load" err={replies.error} next="Try again." actions={<Btn onClick={replies.reload}>Try again</Btn>} />}
                  {replies.status === 'ok' && replies.data && (replies.data.length === 0
                    ? <p className="hint">No replies are waiting.</p>
                    : <DataTable caption="Replies to read" rows={replies.data} rowKey={(x) => x.reply_id}
                        columns={[
                          { key: 'r', header: 'Received', primary: true, render: (x) => <><Time iso={x.received_at} />{x.unread_hours !== null && x.unread_hours > 24 ? <span className="cellsub">{`${Math.round(x.unread_hours)} hours unread`}</span> : null}</> },
                          { key: 'f', header: 'From', render: (x) => x.from.masked ?? <NotAvailable /> },
                          { key: 't', header: 'Reply', render: (x) => (x.text === null ? <NotAvailable /> : `"${x.text}"`) },
                        ]}
                        actions={isAdmin ? (x) => <div className="btn-row"><Btn size="sm" aria-label={`Record a stop for ${x.from.masked ?? x.from.fp_hint}`} onClick={() => setDecide({ reply: x, decision: 'stop' })}>Record a stop</Btn><Btn size="sm" aria-label={`Not a stop for ${x.from.masked ?? x.from.fp_hint}`} onClick={() => setDecide({ reply: x, decision: 'not_stop' })}>Not a stop</Btn></div> : undefined} />)}
                </section>
              )}
            </>
          )}
        </>
      )}

      {registration === 'mark' && s && <MarkRegistration s={s} sources={sourceRows} onClose={() => setRegistration(null)} onDone={() => { settings.refresh(); rules.refresh(); }} />}
      {registration === 'withdraw' && (
        <ConfirmDialog title="Withdraw your texting registration mark?" confirmLabel="Withdraw and turn texts off" busyLabel="Withdrawing" reasonLabel="Reason (required)" reasonRequired destructive
          body={<p>Every text confirmation turns off now, for every source. Texts already queued are recorded as not sent. Email confirmations, replies and stops are not affected.</p>}
          failTitle="The mark was not withdrawn" failNext="Try again. Nothing was changed." onClose={() => setRegistration(null)}
          onConfirm={async (reason) => { try { await api.confirmations.withdrawRegistration(reason); settings.refresh(); rules.refresh(); return null; } catch (e) { return e as ApiError; } }} />
      )}
      {disconnect && (
        <ConfirmDialog title={`Disconnect ${pname(disconnect)}?`} confirmLabel="Disconnect" busyLabel="Disconnecting" reasonLabel="Reason (required)" reasonRequired destructive
          body={<p>{disconnect.channel === 'email'
            ? `Email confirmations turn off for ${sourceRows.map((r) => r.name).join(' and ') || 'every source'}. Emails already queued are recorded as not sent. Stop links in emails already sent keep working.`
            : 'Text confirmations turn off for every source. Texts already queued are recorded as not sent. After you disconnect, ConsentVault keeps recording replies that still arrive for 30 days.'}</p>}
          failTitle={`${pname(disconnect)} was not disconnected`} failNext={`In ${pname(disconnect)}, point the Messaging Service's incoming messages somewhere else, then disconnect. After you disconnect, ConsentVault keeps recording replies that still arrive for 30 days.`}
          onClose={() => setDisconnect(null)}
          onConfirm={async (reason) => { try { await api.confirmations.disconnectAccount(disconnect.account_id, reason); reloadAll(); return null; } catch (e) { return e as ApiError; } }} />
      )}
      {decide && (
        <ConfirmDialog title={decide.decision === 'stop' ? `Record a stop for ${decide.reply.from.masked ?? decide.reply.from.fp_hint}?` : `Mark the reply from ${decide.reply.from.masked ?? decide.reply.from.fp_hint} as not a stop?`}
          confirmLabel={decide.decision === 'stop' ? 'Record the stop' : 'Record not a stop'} busyLabel="Recording" reasonLabel="Reason (required)" reasonRequired disableUntilReason
          body={<p>{decide.decision === 'stop' ? 'This records a stop for texts, calls and AI-voice calls, all purposes, under your name, and sends it to your connected systems. Email is not affected.' : 'The reply is marked read and no stop is recorded. Your reason is kept in the audit log.'}</p>}
          failTitle="The decision was not recorded" failNext="Try again. Nothing was changed." onClose={() => setDecide(null)}
          onConfirm={async (reason) => { try { await api.confirmations.markReply(decide.reply.reply_id, decide.decision, reason); reloadAll(); return null; } catch (e) { return e as ApiError; } }} />
      )}
    </>
  );
}

function whatHappened(x: ConfirmationSend, rules: ConfirmationRule[]): React.ReactNode {
  const rule = rules.find((r) => r.source_id === x.source_id && r.channel === x.channel);
  switch (x.status) {
    case 'sent': return 'Sent';
    case 'delivered': return 'Sent, delivered';
    case 'sending': return 'Sending';
    case 'intent': return 'Queued';
    case 'failed': return `Failed: the provider refused the message${x.failed_code ? ` (code ${x.failed_code})` : ''}. It is not sent again.`;
    case 'dead': return deadCauseWord(x.dead_cause);
    case 'skipped': return skipWord(x.skip_reason, { brand: x.brand_name ?? rule?.brand_name ?? undefined, delay: rule?.max_delay_minutes, hours: rule?.dedupe_hours });
  }
}

function AccountLine({ acc }: { acc: SendingAccount | undefined }) {
  if (!acc) return <p><Chip tone="st-neutral" icon="i-dash">Not connected</Chip></p>;
  const tone = acc.status === 'connected' ? ['st-success', 'i-ok'] : acc.status === 'failing' ? ['st-danger', 'i-err'] : ['st-warning', 'i-warn'];
  const word = { connected: 'Connected', failing: 'Failing', awaiting_test_reply: 'Waiting for a test reply', disconnected: 'Disconnected' }[acc.status];
  return (
    <>
      <p><Chip tone={tone[0]} icon={tone[1]}>{word}</Chip></p>
      {acc.channel === 'email'
        ? <p>{`${pname(acc)}, from ${acc.from.email_address ?? NA}${acc.last_check ? ` · checked ${ago(acc.last_check.at)}` : ''}`}</p>
        : <p>{`${pname(acc)}, your number ending ${(acc.from.number_hint ?? '').replace(/\*/g, '') || NA}${acc.inbound_verified_at ? ' · replies reach us' : ' · waiting for a test reply'}`}</p>}
      {acc.status === 'failing' && acc.last_check && <p className="hint">{`The provider refused the last check (${acc.last_check.result}).`}</p>}
    </>
  );
}

function CheckButton({ acc, onDone, label }: { acc: SendingAccount; onDone: () => void; label: string }) {
  const { api } = useSession();
  const [err, setErr] = useState<ApiError | null>(null);
  const run = useAction(() => api.confirmations.checkAccount(acc.account_id));
  return (
    <>
      <Btn size="sm" busy={run.busy} busyLabel="Checking" onClick={async () => { setErr(null); const r = await run.run(); if (!r.ok) setErr(r.error); onDone(); }}>{label}</Btn>
      {err && <span className="field-error" role="alert">{causeLine(err.status, err.code)}</span>}
    </>
  );
}

function FailingBanner({ acc, canCheck, onDone }: { acc: SendingAccount; canCheck: boolean; onDone: () => void }) {
  const { api } = useSession();
  const run = useAction(() => api.confirmations.checkAccount(acc.account_id));
  const email = acc.channel === 'email';
  return (
    <Banner kind="danger" title={`${chWord(acc.channel)} confirmations are not going out.`} action={canCheck ? <Btn size="sm" busy={run.busy} busyLabel="Checking" onClick={async () => { await run.run(); onDone(); }}>Check the account</Btn> : undefined}>
      {`Cause: your ${email ? 'email' : 'text'} provider refused sending five times in a row (${acc.last_check?.result ?? 'provider refused'}${acc.last_check?.detail ? `, ${acc.last_check.detail}` : ''}). Messages are retried for 2 hours, then recorded as undelivered. Next: ${email ? 'verify the domain at your provider' : 'check the account at your provider'}, then check the account.`}
    </Banner>
  );
}

// ---------- connecting accounts ----------
function ConnectEmail({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const { api } = useSession();
  const [provider, setProvider] = useState<'ses' | 'postmark'>('ses');
  const [f, setF] = useState({ access_key: '', secret: '', server_token: '', email_address: '', display_name: '' });
  const connect = useAction((b: Record<string, unknown>) => api.confirmations.connectAccount(b));
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF((p) => ({ ...p, [k]: e.target.value }));
  const name = provider === 'ses' ? 'Amazon SES' : 'Postmark';
  return (
    <form className="card mb5" noValidate onSubmit={async (e) => {
      e.preventDefault();
      const body = { channel: 'email', provider, credentials: provider === 'ses' ? { access_key: f.access_key, secret: f.secret } : { server_token: f.server_token }, from: { email_address: f.email_address, display_name: f.display_name } };
      setF((p) => ({ ...p, secret: '', server_token: '', access_key: '' }));
      const r = await connect.run(body);
      if (r.ok) onDone();
    }}>
      <h2>Connect an email provider</h2>
      <p className="hint">Messages send from a domain you own and have verified at your provider. The credentials are sealed under your organization key and never shown again.</p>
      {connect.error && <ErrorBlock title="The account was not connected" err={connect.error} override={connect.error.code === 'provider_refused' && connect.error.fields.provider_code ? `the provider refused the credentials, code ${String(connect.error.fields.provider_code)}` : undefined} next="Check the credentials and the sending domain at your provider, then try again. Nothing was connected." />}
      <SelectField label="Provider" name="provider" value={provider} onChange={(e) => setProvider(e.target.value as 'ses' | 'postmark')} options={[{ value: 'ses', label: 'Amazon SES' }, { value: 'postmark', label: 'Postmark' }]} />
      {provider === 'ses'
        ? <><TextField label="Access key" name="access_key" type="text" className="secret" autoComplete="off" spellCheck={false} value={f.access_key} onChange={set('access_key')} /><TextField label="Secret key" name="secret" type="text" className="secret" autoComplete="off" spellCheck={false} value={f.secret} onChange={set('secret')} /></>
        : <TextField label="Server token" name="server_token" type="text" className="secret" autoComplete="off" spellCheck={false} value={f.server_token} onChange={set('server_token')} />}
      <TextField label="From address" name="email_address" type="text" autoComplete="off" value={f.email_address} onChange={set('email_address')} />
      <TextField label="From name" name="display_name" type="text" autoComplete="off" value={f.display_name} onChange={set('display_name')} />
      <div className="btn-row"><Btn type="submit" variant="primary" busy={connect.busy} busyLabel="Connecting">{`Connect ${name}`}</Btn><Btn onClick={onCancel}>Cancel</Btn></div>
    </form>
  );
}

function ConnectSms({ onDone, onCancel }: { onDone: () => void; onCancel: () => void }) {
  const { api } = useSession();
  const [f, setF] = useState({ account_sid: '', api_key_sid: '', api_key_secret: '', auth_token: '', number: '' });
  const [yes, setYes] = useState<boolean | null>(null);
  const [missing, setMissing] = useState(false);
  const connect = useAction((b: Record<string, unknown>) => api.confirmations.connectAccount(b));
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF((p) => ({ ...p, [k]: e.target.value }));
  return (
    <form className="card mb5" noValidate onSubmit={async (e) => {
      e.preventDefault();
      if (yes === null) { setMissing(true); return; }
      setMissing(false);
      const body = { channel: 'sms', provider: 'twilio', credentials: { account_sid: f.account_sid, api_key_sid: f.api_key_sid, api_key_secret: f.api_key_secret, auth_token: f.auth_token }, sender: { number: f.number }, provider_replies_itself: yes };
      setF((p) => ({ ...p, api_key_secret: '', auth_token: '' }));
      const r = await connect.run(body);
      if (r.ok) onDone();
    }}>
      <h2>Connect a text provider</h2>
      <p className="hint">Text goes through Twilio. Replies to your number must reach ConsentVault, so the number needs an incoming webhook set in step 2.</p>
      {connect.error && <ErrorBlock title="The account was not connected" err={connect.error} next="Check the credentials and the number, then try again. Nothing was connected." />}
      <TextField label="Twilio account SID" name="account_sid" type="text" autoComplete="off" spellCheck={false} value={f.account_sid} onChange={set('account_sid')} />
      <TextField label="API key SID" name="api_key_sid" type="text" autoComplete="off" spellCheck={false} value={f.api_key_sid} onChange={set('api_key_sid')} hint="A Twilio API key you created for ConsentVault. Sending uses it." />
      <TextField label="API key secret" name="api_key_secret" type="text" className="secret" autoComplete="off" spellCheck={false} value={f.api_key_secret} onChange={set('api_key_secret')} />
      <TextField label="Auth token" name="auth_token" type="text" className="secret" autoComplete="off" spellCheck={false} value={f.auth_token} onChange={set('auth_token')} hint="Used for signature checks only. It is kept to check the signature on every message Twilio posts, never to call Twilio, because it opens your whole Twilio account." />
      <TextField label="Texting number" name="number" type="text" autoComplete="off" value={f.number} onChange={set('number')} hint="Your Twilio number in full, for example +15555550123." />
      <fieldset><legend>Does Twilio reply to STOP, HELP and START itself on this number?</legend>
        <Radio name="provider_replies" label="Yes" hint="ConsentVault then sends none of those replies, so the person never gets two." checked={yes === true} onChange={() => setYes(true)} />
        <Radio name="provider_replies" label="No" hint="ConsentVault sends the opt-out, HELP and START replies." checked={yes === false} onChange={() => setYes(false)} />
      </fieldset>
      {missing && <p className="field-error" role="alert"><span>Answer whether Twilio replies to STOP, HELP and START itself on this number.</span></p>}
      <div className="btn-row"><Btn type="submit" variant="primary" busy={connect.busy} busyLabel="Connecting">Connect Twilio</Btn><Btn onClick={onCancel}>Cancel</Btn></div>
    </form>
  );
}

function SmsSteps({ acc, onSettings, onChanged }: { acc: SendingAccount; onSettings: (s: ConfirmationSettings) => void; onChanged: () => void }) {
  const { api } = useSession();
  const poll = usePoll<ConfirmationSettings>(async () => { const x = await api.confirmations.settings(); onSettings(x); return x; }, { intervalMs: 5000, deadlineMs: 15 * 60 * 1000, until: (x) => x.sending_accounts.find((a) => a.channel === 'sms')?.status !== 'awaiting_test_reply' });
  const check = useAction(async () => { onSettings(await api.confirmations.settings()); });
  const change = useAction((v: boolean) => api.confirmations.setProviderReplies(acc.account_id, v));
  const step2 = useRef<HTMLLIElement>(null);
  const yes = !!acc.provider_replies?.stop;
  const hint = (acc.from.number_hint ?? '').replace(/\*/g, '');
  return (
    <div className="card mb5" aria-label="Connect a text provider">
      <h2>Connect a text provider</h2>
      <ol className="msgs list-reset">
        <li><Chip tone="st-success" icon="i-ok">Done</Chip> <b>Provider and number.</b> {`${pname(acc)}, number ending ${hint}.`}</li>
        <li ref={step2}><Chip tone="st-success" icon="i-ok">Done</Chip> <b>Point replies at ConsentVault.</b> In Twilio, open Messaging, Services, your service, Integration. Under "Incoming messages" choose "Send a webhook" and paste:
          {acc.inbound_url && <><CodeBlock code={acc.inbound_url} label="Reply address to paste into Twilio" /><div className="mt4"><CopyButton text={acc.inbound_url} label="Copy" /></div></>}</li>
        <li><Chip tone="st-success" icon="i-ok">Done</Chip> <b>Does Twilio reply to STOP, HELP and START itself on this number?</b> {yes ? 'Yes' : 'No'}. {yes ? 'ConsentVault then sends none of those replies, so the person never gets two. ' : 'ConsentVault sends the opt-out, HELP and START replies. '}Stops are still recorded from every message Twilio posts. ConsentVault cannot read this from Twilio; change the answer here if you change it there.
          <div className="mt4"><Btn size="sm" busy={change.busy} busyLabel="Saving" onClick={async () => { const r = await change.run(!yes); if (r.ok) onChanged(); }}>{yes ? 'Change the answer to No' : 'Change the answer to Yes'}</Btn></div></li>
        <li><Chip tone="st-success" icon="i-ok">Done</Chip> <b>Credentials.</b> Sending uses a Twilio API key you created for ConsentVault (SID and secret). Your account auth token is kept for signature checks only, never to call Twilio, because it opens your whole Twilio account. Both are sealed under your organization key.</li>
        <li><Chip tone="st-neutral" icon="i-dash">To do</Chip> <b>Send a test reply.</b> {`From a phone you hold, text anything to your number ending ${hint}. Texts stay off until it arrives here. The test message is kept 30 days and creates no record.`}</li>
      </ol>
      <div role="status" aria-live="polite">
        {!poll.deadlinePassed && <Banner kind="info" title="Waiting for your test text.">Checking every 5 seconds. You can leave; this finishes on its own when the text arrives.</Banner>}
        {poll.deadlinePassed && (
          <StateBlock kind="error" title="No test text arrived in 15 minutes"
            cause={`ConsentVault has not received any message from your number ending ${hint}. The most common cause is the incoming webhook not set to the address in step 2.`}
            next={`Check the "Incoming messages" setting in ${pname(acc)}, then text your number again. Texts stay off until a test text arrives.`}
            actions={<Btn onClick={() => { poll.restart(); step2.current?.scrollIntoView(); }}>Show step 2 again</Btn>} />
        )}
      </div>
      <div className="btn-row"><Btn busy={check.busy} busyLabel="Checking" onClick={() => check.run()}>Check now</Btn></div>
    </div>
  );
}

// ---------- link host, sender details, registration ----------
function LinkHostCard({ s, onChanged }: { s: ConfirmationSettings; onChanged: () => void }) {
  const { api } = useSession();
  const [host, setHost] = useState(s.link_host.host ?? '');
  const set = useAction((h: string) => api.confirmations.setLinkHost(h));
  const verify = useAction(() => api.confirmations.verifyLinkHost());
  const lh = s.link_host;
  return (
    <div className="card mt5">
      <h2>Wording link host on your domain</h2>
      <p>Links in your messages open a page on your own domain that shows the full wording the person agreed to. Choose a name under a domain you own. Messages stay off until it is verified.</p>
      {lh.status !== 'unset' && lh.host && (
        <>
          <p><b>Add these records at your DNS provider</b></p>
          <div className="tw"><div className="tscroll"><table className="dns"><caption>DNS records for {lh.host}</caption><thead><tr><th scope="col">Type</th><th scope="col">Name</th><th scope="col">Value</th></tr></thead>
            <tbody>
              {lh.cname_target && <tr><td>CNAME</td><td className="mono">{lh.host}</td><td className="mono">{lh.cname_target}</td></tr>}
              {lh.txt_record && <tr><td>TXT</td><td className="mono">{`_cv-verify.${lh.host}`}</td><td className="mono">{lh.txt_record}</td></tr>}
            </tbody></table></div></div>
        </>
      )}
      {verify.error && <div className="mt4"><ErrorBlock title="The host is not verified yet" err={verify.error} override={verify.error.code === 'link_host_dns_missing' ? `the record was not found${verify.error.fields.expected ? ` (${String(verify.error.fields.expected)})` : ''}` : undefined} next="Add the record at your DNS provider, wait a few minutes, then check again. Messages stay off until it is verified." actions={<Btn onClick={async () => { const r = await verify.run(); if (r.ok) onChanged(); }}>Check again</Btn>} /></div>}
      {set.error && <div className="mt4"><ErrorBlock title="The host was not set" err={set.error} next="Enter a host name under a domain you own, such as consent.example.com." /></div>}
      <form className="inline-form mt4" noValidate onSubmit={async (e) => { e.preventDefault(); const r = await set.run(host.trim()); if (r.ok) onChanged(); }}>
        <TextField label="Host" name="link-host" type="text" value={host} onChange={(e) => setHost(e.target.value)} autoComplete="off" spellCheck={false} />
        <Btn type="submit" variant="primary" busy={set.busy} busyLabel="Setting">Set the host</Btn>
        {lh.status !== 'unset' && lh.host && <Btn busy={verify.busy} busyLabel="Checking" onClick={async () => { const r = await verify.run(); if (r.ok) onChanged(); }}>Check the records</Btn>}
      </form>
    </div>
  );
}

function SenderCard({ s, canEdit, onSaved }: { s: ConfirmationSettings; canEdit: boolean; onSaved: () => void }) {
  const { api } = useSession();
  const [f, setF] = useState({ organization_name: s.sender.organization_name ?? '', postal_address: s.sender.postal_address ?? '', email: s.sender.help_contact?.email ?? '', phone: s.sender.help_contact?.phone ?? '' });
  const [saved, setSaved] = useState(false);
  const save = useAction(() => api.confirmations.saveSender({ organization_name: f.organization_name, postal_address: f.postal_address, help_contact: { email: f.email, ...(f.phone ? { phone: f.phone } : {}) } }));
  const missing = !s.sender.organization_name || !s.sender.postal_address || !s.sender.help_contact?.email;
  if (!canEdit) return missing ? <p className="hint mt4">Sender details are not set yet. An admin adds them before any message can be turned on.</p> : null;
  return (
    <details className="card mt5" open={missing}>
      <summary><b>Sender details</b>{missing ? ' (needed before any message can be turned on)' : ''}</summary>
      <form className="mt4" noValidate onSubmit={async (e) => { e.preventDefault(); setSaved(false); const r = await save.run(); if (r.ok) { setSaved(true); onSaved(); } }}>
        <p className="hint">The organization name, postal address and help contact appear in every message. The help contact must be a real, answered contact of your organization; ConsentVault cannot check that.</p>
        {save.error && <ErrorBlock title="Sender details were not saved" err={save.error} next="Check each field and try again." />}
        {saved && <SuccessBanner>Sender details saved.</SuccessBanner>}
        <TextField label="Organization name" name="organization_name" type="text" value={f.organization_name} onChange={(e) => setF((p) => ({ ...p, organization_name: e.target.value }))} />
        <TextField label="Postal address" name="postal_address" type="text" value={f.postal_address} onChange={(e) => setF((p) => ({ ...p, postal_address: e.target.value }))} />
        <TextField label="Help email" name="help_email" type="text" value={f.email} onChange={(e) => setF((p) => ({ ...p, email: e.target.value }))} />
        <TextField label="Help phone (optional)" name="help_phone" type="text" value={f.phone} onChange={(e) => setF((p) => ({ ...p, phone: e.target.value }))} />
        <Btn type="submit" variant="primary" busy={save.busy} busyLabel="Saving">Save sender details</Btn>
      </form>
    </details>
  );
}

function MarkRegistration({ s, sources, onClose, onDone }: { s: ConfirmationSettings; sources: { id: string; name: string }[]; onClose: () => void; onDone: () => void }) {
  const { api } = useSession();
  const [kind, setKind] = useState('10dlc');
  const [ref, setRef] = useState('');
  const [a, setA] = useState(false);
  const [b, setB] = useState(false);
  const smsAcc = s.sending_accounts.find((x) => x.channel === 'sms');
  const hint = (smsAcc?.from.number_hint ?? '').replace(/\*/g, '');
  // the texts are the service's own (settings.fixed_texts), the same functions the sender uses, so what is shown here is what is sent
  const texts = s.fixed_texts && s.fixed_texts.items.length === 4 ? s.fixed_texts.items.map((i) => i.text) : null;
  return (
    <ConfirmDialog title="Mark texting registration complete" confirmLabel="Mark complete" busyLabel="Marking" confirmDisabled={!(a && b && texts)}
      failTitle="Registration was not marked" failNext="Try again. Nothing was changed." onClose={onClose}
      body={<><p>{REGISTRATION_DIALOG}</p><p className="mt4"><b>The texts ConsentVault will send from your number:</b></p>{texts ? <div className="msgs">{texts.map((t, i) => <div className="fixed" key={i}>{t}</div>)}</div> : <p className="na">{NA}: the fixed texts did not load. Close this and try again; nothing is marked until they show.</p>}</>}
      extra={<>
        <SelectField label="Registration type" name="kind" value={kind} onChange={(e) => setKind(e.target.value)} options={[{ value: '10dlc', label: '10DLC campaign' }, { value: 'toll_free', label: 'Toll-free verification' }, { value: 'short_code', label: 'Short code' }]} />
        <TextField label="Reference (optional)" name="reference" type="text" value={ref} onChange={(e) => setRef(e.target.value)} autoComplete="off" />
        <div className="check mb4"><input id="reg-a" type="checkbox" checked={a} onChange={(e) => setA(e.target.checked)} /><label htmlFor="reg-a">{`Our texting registration for the number ending ${hint} is approved.`}</label></div>
        <div className="check mb4"><input id="reg-b" type="checkbox" checked={b} onChange={(e) => setB(e.target.checked)} /><label htmlFor="reg-b">These texts are among the sample messages filed with the carrier for that registration.</label></div>
        <p className="hint">Mark complete stays disabled until both boxes are ticked. If this fixed text changes, texts turn off and you will be asked to mark again.</p>
      </>}
      onConfirm={async () => { try { await api.confirmations.markRegistration(kind, ref.trim() || undefined); onDone(); return null; } catch (e) { return e as ApiError; } }} />
  );
}

// ---------- 25 edit one rule ----------
export function ConfirmationEdit({ sourceId, channel }: { sourceId: string; channel: string }) {
  const { api, role, orgName } = useSession();
  const isAdmin = role === 'admin';
  const ch = channel === 'sms' ? 'sms' : channel === 'email' ? 'email' : null;
  const settings = useResource(() => api.confirmations.settings(), [api]);
  const rules = useResource(() => allPages((c) => api.confirmations.rules({ cursor: c })), [api]);
  const sources = useResource(() => allPages((c) => api.sources.list({ cursor: c })), [api]);
  const brands = useResource(() => allPages((c) => api.brands.list({ cursor: c })), [api]);
  const ruleNow = rules.status === 'ok' && (channel === 'sms' || channel === 'email') ? rules.data.find((r) => r.source_id === sourceId && r.channel === channel) : undefined;
  // the list carries name and version only; the subject and opening line of the rule's template come from the single-template read
  const templateId = ruleNow?.template_id ?? null;
  const template = useResource(() => (templateId ? api.confirmations.template(templateId) : Promise.resolve(null)), [api, templateId]);
  const templateReady = !ruleNow || !templateId || (template.status === 'ok' && template.data?.template_id === templateId);

  const src = sources.status === 'ok' ? sources.data.find((x) => x.source_id === sourceId) : undefined;
  const rule = rules.status === 'ok' && ch ? rules.data.find((r) => r.source_id === sourceId && r.channel === ch) : undefined;
  const tpl = template.status === 'ok' && template.data && templateReady ? template.data : undefined;
  const s = settings.status === 'ok' ? settings.data : null;

  const [subject, setSubject] = useState<string | null>(null);
  const [opening, setOpening] = useState<string | null>(null);
  const [opts, setOpts] = useState<{ test: boolean; dedupe: number; delay: number; brand: string } | null>(null);
  const [preview, setPreview] = useState<ConfirmationPreview | null>(null);
  const [previewErr, setPreviewErr] = useState<ApiError | null>(null);
  const [ruleErr, setRuleErr] = useState<ApiError | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [testedMsg, setTestedMsg] = useState(false);
  const [testTo, setTestTo] = useState('');
  const loading = [settings, rules, sources, brands, template].some((r) => r.status === 'loading') || (!templateReady && template.status !== 'error' && subject === null);
  const failed = [settings, rules, sources, brands, template].find((r) => r.status === 'error');

  useEffect(() => {
    if (rule && opts === null) setOpts({ test: rule.send_for_test_events, dedupe: rule.dedupe_hours, delay: rule.max_delay_minutes, brand: rule.sending_brand_id ?? '' });
    if (rule && subject === null && templateReady) { setSubject(tpl?.subject ?? ''); setOpening(tpl?.opening_line ?? ''); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rule, tpl, templateReady]);

  useEffect(() => {
    if (!ch || !src || !rule) return;
    if (ch === 'email' && (subject === null || subject.trim() === '')) return;
    const t = window.setTimeout(() => {
      api.confirmations.preview(ch === 'email' ? { source_id: sourceId, channel: 'email', template: { subject: subject!, ...(opening ? { opening_line: opening } : {}) } } : { source_id: sourceId, channel: 'sms' })
        .then((p) => { setPreview(p); setPreviewErr(null); }, (e) => setPreviewErr(e as ApiError));
    }, 400);
    return () => window.clearTimeout(t);
  }, [api, ch, sourceId, subject, opening, !!src, !!rule]); // eslint-disable-line react-hooks/exhaustive-deps

  const toggling = useAction(async (next: boolean) => {
    const brand = opts?.brand || rule!.sending_brand_id || (brands.status === 'ok' ? brands.data[0]?.brand_id : '') || '';
    return api.confirmations.saveRule(sourceId, ch!, { enabled: next, sending_brand_id: brand, ...(ch === 'email' && rule!.template_id ? { template_id: rule!.template_id } : {}) });
  });
  const saveAll = useAction(async () => {
    let template_id = rule!.template_id ?? undefined;
    if (ch === 'email' && (subject !== (tpl?.subject ?? '') || (opening ?? '') !== (tpl?.opening_line ?? ''))) {
      const t = await api.confirmations.createTemplate({ subject: subject!, ...(opening ? { opening_line: opening } : {}) });
      template_id = t.template_id;
    }
    return api.confirmations.saveRule(sourceId, ch!, { enabled: rule!.enabled, sending_brand_id: opts!.brand, ...(template_id ? { template_id } : {}), send_for_test_events: opts!.test, dedupe_hours: opts!.dedupe, max_delay_minutes: opts!.delay });
  });
  const sendTest = async (): Promise<ApiError | null> => {
    const c = checkContact(testTo);
    if (!c.ok) return new ApiError(422, 'invalid_contact', '', null);
    try { await api.confirmations.test({ source_id: sourceId, channel: ch!, contact: c.value }); setTestedMsg(true); setTestTo(''); return null; } catch (e) { return e as ApiError; }
  };

  if (!ch) return <><PageHead title="Confirmation message" /><StateBlock kind="error" title="That channel does not exist" cause="Confirmation messages go by email or by text." next="Open the list and choose a source." actions={<LinkBtn href="/confirmations">Back to confirmation messages</LinkBtn>} /></>;
  if (loading) return <><PageHead title="Confirmation message" /><Skeleton what="the rule" rows={4} /></>;
  if (failed && failed.status === 'error') return <><PageHead title="Confirmation message" /><ErrorBlock title="The rule did not load" err={failed.error} next="Try again. Nothing was changed." actions={<Btn onClick={() => { settings.reload(); rules.reload(); sources.reload(); brands.reload(); template.reload(); }}>Try again</Btn>} /></>;
  if (!src || !rule || !s) return <><PageHead title="Confirmation message" /><StateBlock kind="error" title={`That source does not exist in ${orgName}`} cause="The address may be mistyped, or the source was retired." next="Open the list and choose a source." actions={<LinkBtn href="/confirmations">Back to confirmation messages</LinkBtn>} /></>;

  const kindWord = ch === 'email' ? 'email' : 'text';
  const readOnly = !isAdmin;
  const reason = rule.enabled ? null : blockReason(ch, s);
  const chars = preview ? `${fmtNum(preview.characters)} characters${preview.segments ? `, ${preview.segments} text segment${preview.segments === 1 ? '' : 's'}` : ''}` : null;
  const replyTexts = s.fixed_texts && s.fixed_texts.items.length === 4 ? Object.fromEntries(s.fixed_texts.items.map((i) => [i.kind, i.text])) as Record<string, string> : null;
  const acc = s.sending_accounts.find((a) => a.channel === 'sms');

  return (
    <>
      <PageHead title={`${src.name}: ${kindWord} confirmation`} meta={<span className="gap-row"><Link href={`/confirmations/${encodeURIComponent(sourceId)}/email`}>Email</Link><Link href={`/confirmations/${encodeURIComponent(sourceId)}/sms`}>Text</Link></span>} />
      {readOnly && <Banner kind="info" title="This page is read only for your role.">Changing confirmation messages needs an admin.</Banner>}
      {ruleErr && <ErrorBlock title="The rule was not changed" err={ruleErr} next="Fix what the cause names, then try again. Nothing was changed." />}
      {saved && <SuccessBanner>{saved}</SuccessBanner>}
      {testedMsg && <SuccessBanner>The test message was sent. It is recorded as a test send and creates no record.</SuccessBanner>}
      <div className="card mb5">
        {readOnly
          ? <p>{rule.enabled ? 'On' : 'Off'}: {kindWord} confirmations for {src.name}.</p>
          : <Switch checked={rule.enabled} ariaLabel={`Send ${kindWord} confirmations for ${src.name}`} busy={toggling.busy} reason={reason}
              onToggle={async (next) => { setRuleErr(null); setSaved(null); const r = await toggling.run(next); if (!r.ok) setRuleErr(r.error); else { rules.refresh(); if (next) setSaved(`${chWord(ch)} confirmations are on for ${src.name}. The next new consent from that source gets one. Consents recorded before now do not.`); } }} />}
        <div className="mt4"><SelectField label="Sends as" name="brand" value={opts?.brand ?? ''} disabled={readOnly} onChange={(e) => setOpts((o) => (o ? { ...o, brand: e.target.value } : o))} options={brands.status === 'ok' ? brands.data.map((b) => ({ value: b.brand_id, label: b.display_name })) : []} /></div>
        {ch === 'email' && (
          <>
            <TextField label="Subject" name="subject" type="text" maxLength={80} value={subject ?? ''} disabled={readOnly} onChange={(e) => setSubject(e.target.value.slice(0, 80))} hint={`${(subject ?? '').length} of 80 characters`} autoComplete="off" />
            <TextArea label="Opening line (optional)" name="opening_line" maxLength={300} value={opening ?? ''} disabled={readOnly} onChange={(e) => setOpening(e.target.value.slice(0, 300))} autoComplete="off" />
          </>
        )}
      </div>

      <div className="card mb5" aria-label="Preview">
        <h2>{ch === 'email' ? 'Preview' : 'Text messages (fixed text, not editable)'}</h2>
        {ch === 'sms' && <p className="hint">The text carries a link to the full wording on your own domain, never the wording itself.</p>}
        {previewErr && <ErrorBlock title="The preview did not load" err={previewErr} next="Change a field to try again." />}
        {ch === 'email' && preview && <p data-preview-subject><b>Subject:</b> {preview.subject}</p>}
        {ch === 'email' && <p className="hint">Every email also carries these parts, which cannot be removed:</p>}
        {preview && <div className="fixed" data-fixed><Linkified text={preview.body} /></div>}
        {chars && <p className="hint">{ch === 'sms' ? `Confirmation: ${chars}.` : `${chars}.`}</p>}
        {ch === 'sms' && (
          <div className="msgs mt4">
            {replyTexts
              ? <>
                <div><div className="reply">please stop texting</div><div className="fixed">{replyTexts.optout_reply}</div></div>
                <div><div className="reply">HELP</div><div className="fixed">{replyTexts.help_reply}</div></div>
                <div><div className="reply">START</div><div className="fixed">{replyTexts.start_reply}</div></div>
              </>
              : <p className="na">{NA}: the fixed reply texts did not load.</p>}
            <p className="hint">{STOP_WORDS}</p>
            {acc?.provider_replies?.stop && <p className="hint">Opt-out reply sent by Twilio (you answered that Twilio replies itself), not by ConsentVault.</p>}
          </div>
        )}
      </div>

      <div className="card mb5">
        <h2>Options</h2>
        <div className="check mb4"><input id="opt-test" type="checkbox" checked={opts?.test ?? false} disabled={readOnly} onChange={(e) => setOpts((o) => (o ? { ...o, test: e.target.checked } : o))} /><label htmlFor="opt-test">Send for test events</label></div>
        <SelectField label="Send at most one confirmation per contact every" name="dedupe" value={String(opts?.dedupe ?? 24)} disabled={readOnly} onChange={(e) => setOpts((o) => (o ? { ...o, dedupe: Number(e.target.value) } : o))} options={[{ value: '24', label: '24 hours' }, { value: '168', label: '7 days' }]} />
        <SelectField label="Do not send when the consent arrives more than" name="delay" value={String(opts?.delay ?? 10)} disabled={readOnly} onChange={(e) => setOpts((o) => (o ? { ...o, delay: Number(e.target.value) } : o))} hint="after it was captured" options={[{ value: '10', label: '10 minutes' }, { value: '60', label: '60 minutes' }]} />
      </div>
      <div className="btn-row">
        {isAdmin && <Btn variant="primary" busy={saveAll.busy} busyLabel="Saving" onClick={async () => { setRuleErr(null); setSaved(null); const r = await saveAll.run(); if (!r.ok) setRuleErr(r.error); else { rules.refresh(); template.refresh(); setSaved(rule.enabled ? `${chWord(ch)} confirmations are on for ${src.name}. The next new consent from that source gets one. Consents recorded before now do not.` : `Saved. ${chWord(ch)} confirmations for ${src.name} are still off.`); } }}>Save</Btn>}
        {isAdmin && <Btn onClick={() => { setTestedMsg(false); setTesting(true); }}>{ch === 'email' ? 'Send a test to my own address' : 'Send a test to my own number'}</Btn>}
        <LinkBtn href="/confirmations">{readOnly ? 'Back to confirmation messages' : 'Cancel'}</LinkBtn>
      </div>
      {testing && (
        <ConfirmDialog title={ch === 'email' ? 'Send a test to my own address' : 'Send a test to my own number'} confirmLabel="Send the test" busyLabel="Sending" failTitle="The test was not sent" failNext="Check the entry and try again. Nothing was sent." onClose={() => setTesting(false)}
          body={<p>The test goes only to a contact point you control, is recorded as a test send, and creates no record. A stop on record and texting hours still apply.</p>}
          extra={<TextField label={ch === 'email' ? 'Your own address' : 'Your own number'} name="test-contact" type="text" value={testTo} onChange={(e) => setTestTo(e.target.value)} autoComplete="off" spellCheck={false} />}
          onConfirm={sendTest} />
      )}
    </>
  );
}
