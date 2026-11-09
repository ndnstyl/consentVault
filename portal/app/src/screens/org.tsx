import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ApiError, allPages } from '../lib/api/client.ts';
import type { AuditRow, MemberRow, OrgAdmin, Role } from '../lib/api/types.ts';
import { ROLE_DESCRIPTION } from '../lib/copy.ts';
import { NA, ORG_STATUS_LABEL } from '../lib/copy.ts';
import { useAction, useResource } from '../lib/hooks.ts';
import { useRouter } from '../lib/router.tsx';
import { ROLE_LABEL, canDo } from '../lib/roles.ts';
import { useSession } from '../lib/session.tsx';
import { fmtDate, fmtDateTime, fmtNum, maskContact } from '../lib/format.ts';
import { actionLabel, actorName, type NamedMember } from '../lib/labels.ts';
import { useToast } from '../lib/toast.tsx';
import { ConfirmDialog, Dialog } from '../components/Dialog.tsx';
import { Banner, Btn, Chip, DataTable, ErrorBlock, KV, LinkBtn, Meter, NotAvailable, OrgChip, PageHead, Radio, SelectField, Skeleton, StateBlock, SuccessBanner, TextArea, TextField, Time } from '../components/ui.tsx';

// ---------- 16 Retention ----------
export function Retention() {
  const { api, role } = useSession();
  const res = useResource(() => api.retention.get(), [api]);
  const [years, setYears] = useState('');
  const [reason, setReason] = useState('');
  const [touched, setTouched] = useState(false);
  const [saved, setSaved] = useState<{ years: number; from: string } | null>(null);
  const set = useAction((y: number, r: string) => api.retention.set(y, r));
  const write = canDo(role, 'retention.set');
  if (res.status === 'loading') return <><PageHead title="Retention" /><Skeleton what="retention" /></>;
  if (res.status === 'error') return <><PageHead title="Retention" /><ErrorBlock title="Retention did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} /></>;
  const d = res.data;
  const min = d.platform_minimum_years;
  const n = Number(years);
  const belowMin = years !== '' && Number.isFinite(n) && n < min;
  const yearsErr = belowMin ? `${n} years is below the platform minimum of ${min} years. Enter ${min} years or more.` : touched && (years === '' || !Number.isFinite(n)) ? 'Enter a number of years.' : null;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (yearsErr || years === '' || !reason.trim()) return;
    const r = await set.run(n, reason.trim());
    if (r.ok) { setSaved({ years: r.value.evidence_years, from: r.value.applies_from }); setYears(''); setReason(''); setTouched(false); res.refresh(); }
  };
  const serverBelow = set.error?.code === 'below_platform_minimum';
  const inForce = saved ? saved.years : d.current?.evidence_years ?? min;
  return (
    <>
      <PageHead title="Retention" lede="How long evidence is kept, and how to set a longer period for evidence written from now on." />
      {saved && <SuccessBanner>{`Retention set to ${saved.years} years. Applies to every record written from ${fmtDateTime(saved.from)}.`}</SuccessBanner>}
      {!d.current && <StateBlock kind="empty" title="Platform minimum in force">{`Your organization has not set its own retention, so records are kept for the platform minimum of ${min} years.`}</StateBlock>}
      <div className="card mt4">
        <KV rows={[
          ['In force', d.current ? `${inForce} years (version ${d.current.version}, set ${fmtDate(d.current.applies_from)} by ${d.current.set_by})` : `${min} years (platform minimum)`],
          ['Platform minimum', `${min} years`],
        ]} />
        <p className="mt4">Each record&apos;s keep-until date is locked when it is written. A change applies to records written after it. Nobody, including ConsentVault, can delete a record before its date.</p>
        {write && (
          <form onSubmit={submit} noValidate className="mt4">
            {set.error && <ErrorBlock title="Retention was not saved" err={set.error} override={serverBelow ? `${years || 'That'} years is below the platform minimum of ${min} years` : undefined} next={serverBelow ? `Enter ${min} years or more.` : 'Try again. Nothing was changed.'} headingLevel={3} />}
            <TextField label="New retention in years" name="years" type="number" min={min} step={1} value={years} onChange={(e) => setYears(e.target.value)} error={yearsErr} hint={`At least ${min} years. Applies to records written from now on.`} />
            <TextArea label="Reason (recorded in the audit log)" name="reason" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} error={touched && !reason.trim() ? 'Enter a reason.' : null} />
            <Btn type="submit" variant="primary" busy={set.busy} busyLabel="Saving">Save new version</Btn>
          </form>
        )}
      </div>
      <h2 className="sec mt6">History</h2>
      {d.partial?.includes('history') ? <Banner kind="warning" title="Version history did not load">{`The value in force is current: ${inForce} years.`}</Banner>
        : d.items.length === 0 ? <p className="hint">No versions yet.</p>
          : <DataTable caption="Retention versions" rows={d.items} rowKey={(r) => String(r.version)} columns={[
            { key: 'v', header: 'Version', render: (r) => <span className="num">{r.version}</span>, primary: true },
            { key: 'y', header: 'Years', render: (r) => <span className="num">{r.evidence_years}</span> },
            { key: 's', header: 'Set by', render: (r) => r.set_by },
            { key: 'f', header: 'From', render: (r) => <Time iso={r.applies_from} date /> },
          ]} />}
    </>
  );
}

// ---------- 17 Members ----------
const ROLES: Role[] = ['admin', 'developer', 'compliance_viewer'];
export function Members() {
  const { api } = useSession();
  const toast = useToast();
  const res = useResource(async () => {
    try { return { rows: await allPages((c) => api.members.list({ include: 'invites', cursor: c })), invitesFailed: false }; }
    catch (e) {
      if ((e as ApiError).status === 401 || (e as ApiError).status === 403) throw e;
      return { rows: await allPages((c) => api.members.list({ cursor: c })), invitesFailed: true };
    }
  }, [api]);
  const [invite, setInvite] = useState(false);
  const [sent, setSent] = useState<{ email: string; expires: string } | null>(null);
  const [roleFor, setRoleFor] = useState<MemberRow | null>(null);
  const [removeFor, setRemoveFor] = useState<MemberRow | null>(null);
  const [withdrawFor, setWithdrawFor] = useState<MemberRow | null>(null);
  const [lastAdminErr, setLastAdminErr] = useState<ApiError | null>(null);
  const rows = res.status === 'ok' ? res.data.rows : [];
  const adminMembers = rows.filter((r) => r.kind === 'member' && r.role === 'admin').length;
  const onlyYou = rows.length === 1 && rows[0].kind === 'member';
  const inviteBtn = <Btn variant="primary" onClick={() => setInvite(true)}>Invite a member</Btn>;
  return (
    <>
      <PageHead title="Members" lede="The people in this organization, and what each may do." actions={rows.length > 0 && !onlyYou ? inviteBtn : null} />
      {sent && <SuccessBanner>{`Invitation sent to ${sent.email}. It expires ${fmtDate(sent.expires)}.`}</SuccessBanner>}
      {lastAdminErr && <ErrorBlock title="You cannot remove the last admin" err={lastAdminErr} override="that would leave the organization with no admin" next="Make another member an admin first." />}
      {res.status === 'loading' && <Skeleton what="members" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="Members did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {res.status === 'ok' && res.data.invitesFailed && <Banner kind="warning" title="Pending invitations did not load">Active members are listed in full.</Banner>}
      {res.status === 'ok' && onlyYou && <StateBlock kind="empty" title="You are the only member" actions={inviteBtn}>Invite a second admin so your organization is never locked out, and a compliance viewer for record lookups.</StateBlock>}
      {rows.length > 0 && (
        <div className={onlyYou ? 'mt5' : undefined}>
          <DataTable caption="Members and invitations" rows={rows} rowKey={(r) => `${r.kind}:${r.id}`}
            columns={[
              { key: 'n', header: 'Name', render: (r) => (r.display_name ?? <span className="hint">{r.last_sign_in_at ? 'No name given' : 'Not signed in yet'}</span>), primary: true },
              { key: 'e', header: 'Email', render: (r) => r.email },
              { key: 'r', header: 'Role', render: (r) => ROLE_LABEL[r.role] },
              { key: 'l', header: 'Last sign-in', render: (r) => (r.kind === 'invite' ? <span className="hint">Not signed in yet</span> : r.last_sign_in_at ? <Time iso={r.last_sign_in_at} /> : <span className="hint">Never</span>) },
              { key: 's', header: 'Status', render: (r) => (r.kind === 'invite' ? <Chip tone="st-info" icon="i-info">{`Invited, expires ${r.expires_at ? fmtDate(r.expires_at) : NA}`}</Chip> : <Chip tone="st-success" icon="i-ok">Active</Chip>) },
            ]}
            actions={(r) => {
              if (r.kind === 'invite') return <Btn size="sm" variant="danger" aria-label={`Withdraw invitation for ${r.email}`} onClick={() => setWithdrawFor(r)}>Withdraw</Btn>;
              const sole = r.role === 'admin' && adminMembers <= 1;
              if (sole) return <span className="hint">Only admin</span>;
              return <><Btn size="sm" aria-label={`Change role for ${r.display_name ?? r.email}`} onClick={() => setRoleFor(r)}>Change role</Btn><Btn size="sm" variant="danger" aria-label={`Remove ${r.display_name ?? r.email}`} onClick={() => setRemoveFor(r)}>Remove</Btn></>;
            }} />
        </div>
      )}
      {invite && <InviteDialog onClose={() => setInvite(false)} onSent={(email, expires) => { setInvite(false); setSent({ email, expires }); res.refresh(); toast(`Invitation sent to ${email}. Recorded in the audit log.`); }} />}
      {roleFor && <RoleDialog row={roleFor} onClose={() => setRoleFor(null)} onDone={(e) => { setRoleFor(null); if (e) setLastAdminErr(e); else { setLastAdminErr(null); res.refresh(); toast('Role changed. Recorded in the audit log.'); } }} />}
      {removeFor && (
        <ConfirmDialog title={`Remove ${removeFor.display_name ?? removeFor.email}?`} destructive confirmLabel="Remove member" busyLabel="Removing" failTitle="The member was not removed" failNext="Try again. Nothing was changed."
          body="They lose access on their next request. Records they created stay on record."
          onClose={() => setRemoveFor(null)} onConfirm={async () => { try { await api.members.remove(removeFor.id); res.refresh(); toast('Member removed. Recorded in the audit log.'); return null; } catch (e) { const err = e as ApiError; if (err.code === 'last_admin') { setLastAdminErr(err); return null; } return err; } }} />
      )}
      {withdrawFor && (
        <ConfirmDialog title={`Withdraw the invitation for ${withdrawFor.email}?`} destructive confirmLabel="Withdraw invitation" busyLabel="Withdrawing" failTitle="The invitation was not withdrawn" failNext="Try again. Nothing was changed."
          body="The link stops working. You can invite them again later."
          onClose={() => setWithdrawFor(null)} onConfirm={async () => { try { await api.invites.withdraw(withdrawFor.id); res.refresh(); toast('Invitation withdrawn. Recorded in the audit log.'); return null; } catch (e) { return e as ApiError; } }} />
      )}
    </>
  );
}

function InviteDialog({ onClose, onSent }: { onClose: () => void; onSent: (email: string, expires: string) => void }) {
  const { api } = useSession();
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Role>('compliance_viewer');
  const [touched, setTouched] = useState(false);
  const send = useAction(() => api.members.invite(email.trim(), role));
  const bad = !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim());
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (bad) { setTouched(true); return; }
    const r = await send.run();
    if (r.ok) onSent(r.value.email, r.value.expires_at);
  };
  const err = send.error;
  return (
    <Dialog title="Invite a member" onClose={onClose}>
      <form onSubmit={submit} noValidate>
        {err && <ErrorBlock title={err.code === 'email_send_failed' ? 'The invitation was not sent' : err.code === 'already_member' ? 'That person is already here' : 'The invitation was not sent'} err={err}
          next={err.code === 'email_send_failed' ? 'Try again in a minute.' : err.code === 'already_member' ? 'Check the members list for that address.' : 'Fix the field and try again. Nothing was changed.'} headingLevel={3} />}
        <TextField label="Work email" name="invite-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" required error={touched && bad ? 'Enter a full work email address.' : null} />
        <fieldset><legend>Role</legend>
          {ROLES.map((r) => <Radio key={r} name="role" label={ROLE_DESCRIPTION[r].split(':')[0]} hint={ROLE_DESCRIPTION[r].split(': ').slice(1).join(': ')} checked={role === r} onChange={() => setRole(r)} />)}
        </fieldset>
        <p className="hint">The invitation link works once and expires in 7 days.</p>
        <div className="actions"><Btn onClick={onClose}>Cancel</Btn><Btn type="submit" variant="primary" busy={send.busy} busyLabel="Sending">Send invitation</Btn></div>
      </form>
    </Dialog>
  );
}

function RoleDialog({ row, onClose, onDone }: { row: MemberRow; onClose: () => void; onDone: (e: ApiError | null) => void }) {
  const { api } = useSession();
  const [role, setRole] = useState<Role>(row.role);
  const save = useAction(() => api.members.setRole(row.id, role));
  return (
    <Dialog title={`Change role for ${row.display_name ?? row.email}`} onClose={onClose}>
      <form onSubmit={async (e) => { e.preventDefault(); const r = await save.run(); if (r.ok) onDone(null); else if (r.error.code === 'last_admin') onDone(r.error); }} noValidate>
        {save.error && save.error.code !== 'last_admin' && <ErrorBlock title="The role was not changed" err={save.error} next="Try again. Nothing was changed." headingLevel={3} />}
        <fieldset><legend>Role</legend>
          {ROLES.map((r) => <Radio key={r} name="role" label={ROLE_DESCRIPTION[r].split(':')[0]} hint={ROLE_DESCRIPTION[r].split(': ').slice(1).join(': ')} checked={role === r} onChange={() => setRole(r)} />)}
        </fieldset>
        <div className="actions"><Btn onClick={onClose}>Cancel</Btn><Btn type="submit" variant="primary" busy={save.busy} busyLabel="Saving" disabled={role === row.role}>Save role</Btn></div>
      </form>
    </Dialog>
  );
}

// ---------- 18 Audit log ----------
const PERSONAL = /(\+?\d[\d\s().-]{8,}\d)|([^\s@]+@[^\s@]+\.[^\s@]+)/;
function safeTarget(t: AuditRow['target']): string {
  if (t.kind === 'org') return 'This organization';
  const id = t.id ?? '';
  const shown = PERSONAL.test(id) ? maskContact(id) : id;
  return `${t.kind.replace(/_/g, ' ')}${shown ? ` ${shown}` : ''}`;
}

export function Audit() {
  const { api, role } = useSession();
  const { search, navigate } = useRouter();
  const action = search.get('action') ?? '';
  const actor = search.get('actor') ?? '';
  const from = search.get('from') ?? '';
  const to = search.get('to') ?? '';
  const [stack, setStack] = useState<string[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const q = { action: action || undefined, actor: actor || undefined, from: from ? `${from}T00:00:00Z` : undefined, to: to ? `${to}T23:59:59Z` : undefined };
  const dateErr = from && to && from > to ? 'The From date is later than the To date.' : null;
  const res = useResource(() => (dateErr ? Promise.resolve(null) : api.audit.list({ ...q, cursor, limit: 25 })), [api, action, actor, from, to, cursor]);
  const actions = useResource(() => api.audit.actions({ limit: 200 }).then((p) => p.items).catch(() => null), [api]);
  const memberRes = useResource(() => (role === 'admin' ? allPages((c) => api.members.list({ cursor: c })).catch(() => null) : Promise.resolve(null)), [api, role]);
  const members = useMemo(() => new Map<string, NamedMember>((memberRes.status === 'ok' && memberRes.data ? memberRes.data : []).map((m) => [m.id, m])), [memberRes.status, memberRes.data]);
  const labelOf = useMemo(() => new Map<string, string>((actions.status === 'ok' && actions.data ? actions.data : []).map((a) => [a.action, a.label])), [actions.status, actions.data]);
  const actors = useMemo(() => { const m = new Map<string, string>(); if (res.status === 'ok' && res.data) for (const r of res.data.items) { const n = actorName(r.actor, members); if (n) m.set(r.actor.id, n); } return [...m.entries()]; }, [res.status, res.data, members]);
  const setFilter = (k: string, v: string) => {
    const p = new URLSearchParams(search.toString()); if (v) p.set(k, v); else p.delete(k);
    setStack([]); setCursor(null);
    navigate(`/audit${p.toString() ? `?${p}` : ''}`, { replace: true });
  };
  const filtered = !!(action || actor || from || to);
  const rows = res.status === 'ok' && res.data ? res.data.items : [];
  const namesMissing = rows.length > 0 && memberRes.status !== 'loading' && rows.some((r) => actorName(r.actor, members) === null);
  return (
    <>
      <PageHead title="Audit log" lede="Append-only and anchored outside ConsentVault. Nobody can change or remove an entry." />
      <form className="card inline-form" onSubmit={(e) => e.preventDefault()} aria-label="Audit filters">
        <SelectField label="Action" name="action" value={action} onChange={(e) => setFilter('action', e.target.value)} options={[{ value: '', label: 'All actions' }, ...((actions.status === 'ok' && actions.data ? actions.data : []).map((a) => ({ value: a.action, label: a.label })))]} />
        <SelectField label="Who" name="actor" value={actor} onChange={(e) => setFilter('actor', e.target.value)} options={[{ value: '', label: 'Everyone' }, ...actors.map(([id, n]) => ({ value: id, label: n })), ...(actor && !actors.some(([id]) => id === actor) ? [{ value: actor, label: actor }] : [])]} />
        <TextField label="From" name="from" type="date" value={from} onChange={(e) => setFilter('from', e.target.value)} />
        <TextField label="To" name="to" type="date" value={to} onChange={(e) => setFilter('to', e.target.value)} error={dateErr} />
      </form>
      {actions.status === 'ok' && actions.data === null && <p className="hint">The action list did not load. Filtering by action is Not available.</p>}
      <div className="mt5">
        {res.status === 'loading' && <Skeleton what="the audit log" variant="table" />}
        {res.status === 'error' && <ErrorBlock title="The audit log did not load" err={res.error} next="Try again. Actions are still being recorded." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
        {res.status === 'ok' && rows.length === 0 && !dateErr && (
          <StateBlock kind="empty" title={filtered ? 'No entries match these filters' : 'No entries yet'} actions={filtered ? <Btn onClick={() => { setStack([]); setCursor(null); navigate('/audit', { replace: true }); }}>Clear filters</Btn> : null}>
            {filtered ? 'Nothing was recorded for this action and person between these dates. Widen the dates or clear the filters.' : 'Privileged actions appear here as they happen.'}
          </StateBlock>
        )}
        {rows.length > 0 && (
          <>
            {namesMissing && <Banner kind="warning" title="Some member names did not load">Entries from a member the list does not hold read Not available.</Banner>}
            <DataTable caption="Audit entries" rows={rows} rowKey={(r) => r.audit_id}
              columns={[
                { key: 'w', header: 'When', render: (r) => <Time iso={r.at} />, primary: true },
                { key: 'a', header: 'Who', render: (r) => actorName(r.actor, members) ?? <NotAvailable /> },
                { key: 'x', header: 'Action', render: (r) => actionLabel(r.action, labelOf) },
                { key: 't', header: 'Target', render: (r) => safeTarget(r.target) },
                { key: 'r', header: 'Reason', render: (r) => r.reason ?? <span className="hint">None given</span> },
                { key: 'q', header: 'Request', render: (r) => <code className="mono">{r.request_id}</code> },
              ]} />
            <nav className="btn-row mt4" aria-label="Pages">
              <Btn size="sm" disabled={stack.length === 0 && cursor === null} onClick={() => { const prev = stack[stack.length - 1] ?? null; setStack(stack.slice(0, -1)); setCursor(prev === '' ? null : prev); }}>Newer</Btn>
              <Btn size="sm" disabled={!res.data?.next_cursor} onClick={() => { setStack([...stack, cursor ?? '']); setCursor(res.data!.next_cursor); }}>Older</Btn>
            </nav>
          </>
        )}
      </div>
    </>
  );
}

// ---------- 19 Billing ----------
export function BillingScreen() {
  const { api, orgName, status } = useSession();
  const res = useResource(() => api.billing.get(), [api]);
  const portal = useAction(() => api.billing.portal());
  const [back] = useState(() => { try { const v = sessionStorage.getItem('cv.stripe.out'); if (v) sessionStorage.removeItem('cv.stripe.out'); return !!v; } catch { return false; } });
  const open = async () => {
    const r = await portal.run();
    if (r.ok) { try { sessionStorage.setItem('cv.stripe.out', '1'); } catch { /* the return banner is optional */ } window.location.assign(r.value.portal_url); }
  };
  if (res.status === 'loading') return <><PageHead title="Billing" /><Skeleton what="billing" /></>;
  if (res.status === 'error') return <><PageHead title="Billing" /><ErrorBlock title="Billing did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} /></>;
  const b = res.data;
  const pastDue = (b.status ?? status) === 'past_due';
  const usageNA = !b.used || !b.included;
  const btn = <Btn variant="primary" busy={portal.busy} busyLabel="Opening Stripe" onClick={open}>{pastDue ? 'Update payment method on Stripe' : 'Manage billing on Stripe'}</Btn>;
  return (
    <>
      <PageHead title="Billing" />
      {back && <SuccessBanner>Back from Stripe. Changes you made there can take a minute to show here.</SuccessBanner>}
      {pastDue && <Banner kind="warning" title="Payment failed">Capture keeps recording. Update your payment method on Stripe to avoid suspension.</Banner>}
      {portal.error && <ErrorBlock title="Stripe's billing page could not be opened" err={portal.error} next="Try again in a minute. Nothing was changed." actions={<Btn onClick={open}>Try again</Btn>} />}
      {b.plan === null && (
        <StateBlock kind="empty" title="No plan yet" actions={<LinkBtn href="/start/plan" variant="primary">Choose a plan</LinkBtn>}>{`${orgName} is in trial. Choose a plan to go live with real records.`}</StateBlock>
      )}
      {b.plan !== null && (
        <div className="card">
          {usageNA && <Banner kind="warning" title="Usage did not load">Plan and status are current.</Banner>}
          <KV rows={[
            ['Plan', b.plan.name], ['Status', <OrgChip key="s" status={b.status} />],
            ['Events this period', b.used && b.included ? `${fmtNum(b.used.events)} of ${fmtNum(b.included.events)} included` : <NotAvailable key="e" />],
            ['Gate checks this period', b.used && b.included ? `${fmtNum(b.used.gate_checks)} of ${fmtNum(b.included.gate_checks)} included` : <NotAvailable key="g" />],
            ['Usage last reported', b.last_reported_at ? <Time key="l" iso={b.last_reported_at} /> : <NotAvailable key="l" />],
          ]} />
          {b.used && b.included && <div className="mt5"><Meter label="Events this period" used={b.used.events} included={b.included.events} /><Meter label="Gate checks this period" used={b.used.gate_checks} included={b.included.gate_checks} /></div>}
          <p className="mt4">Invoices, payment method and cancellation are on Stripe&apos;s secure page.</p>
          <div className="btn-row">{btn}</div>
          <p className="hint mt4">Going over a plan limit bills overage. Capture is never refused.</p>
        </div>
      )}
    </>
  );
}

// ---------- 20 Settings ----------
const STEP_LABEL: Record<string, string> = { final_export: 'Final export delivered', credentials_revoked: 'Credentials revoked', key_destruction_scheduled: 'Key destruction', destruction_record: 'Destruction record' };

export function Settings() {
  const { api, role, orgName, user, refreshOrg } = useSession();
  const res = useResource(() => api.session.org(), [api]);
  const [dialog, setDialog] = useState(false);
  const [done, setDone] = useState(false);
  if (res.status === 'loading') return <><PageHead title="Organization settings" /><Skeleton what="settings" /></>;
  if (res.status === 'error') return <><PageHead title="Organization settings" /><ErrorBlock title="Settings did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} /></>;
  const o = res.data as OrgAdmin;
  const admin = role === 'admin' && 'offboarding' in o;
  const keyNA = admin && (o.key === null || o.partial?.includes('key'));
  const off = admin ? o.offboarding : null;
  const stepLine = (s: { step: string; status: string; at: string | null }) => {
    const label = STEP_LABEL[s.step] ?? s.step;
    if (s.status === 'done') return { label, chip: <Chip tone="st-success" icon="i-ok">{`Done ${s.at ? fmtDate(s.at) : ''}`.trim()}</Chip> };
    if (s.status === 'delayed') return { label, chip: <Chip tone="st-warning" icon="i-warn">Delayed by a legal hold</Chip> };
    const when = off?.destroy_after ? fmtDate(off.destroy_after) : null;
    return { label, chip: <Chip tone="st-neutral" icon="i-dash">{s.step === 'destruction_record' ? (when ? `After ${when}` : 'After key destruction') : when ? `Scheduled ${when}` : 'Pending'}</Chip> };
  };
  return (
    <>
      <PageHead title="Organization settings" />
      {keyNA && <Banner kind="warning" title="Encryption key status did not load">Shown as Not available.</Banner>}
      <div className="card">
        <KV rows={[
          ['Name', o.name], ['Organization id', <code key="i" className="mono">{o.org_id}</code>], ['Status', <OrgChip key="s" status={o.status} />],
          ['Data region', o.region === 'us' ? 'United States' : o.region],
          ...(admin ? [['Encryption key', keyNA ? <NotAvailable key="k" /> : `${o.key!.status === 'active' ? 'Active' : o.key!.status.replace(/_/g, ' ')}, version ${o.key!.version}`] as [string, React.ReactNode]] : []),
        ]} />
      </div>
      {role === 'admin' && (
        <div className="card mt5">
          <h2>Leave ConsentVault</h2>
          {!off && !done && (
            <>
              <p>When an organization leaves, in this order:</p>
              <ol className="step-list">
                <li>A final, complete evidence export is built and delivered to you.</li>
                <li>All credentials stop working.</li>
                <li>After the waiting period in your contract (at least 30 days), your encryption key is destroyed. Your records become unreadable everywhere, including backups.</li>
                <li>You receive a destruction record.</li>
              </ol>
              <p className="hint">An active legal hold delays key destruction for what it covers.</p>
              <Btn variant="danger" onClick={() => setDialog(true)}>Request offboarding</Btn>
            </>
          )}
          {done && <SuccessBanner>{`Offboarding request sent. The operator will contact ${user?.email ?? 'you'} to confirm dates. Your records stay readable until then.`}</SuccessBanner>}
          {off && (
            <>
              <Banner kind="warning" title="Offboarding in progress">{off.state === 'requested' ? 'The operator has your request and will confirm dates.' : 'The final export comes first. Nothing is destroyed until the waiting period ends.'}</Banner>
              {off.held.legal_hold_active && <Banner kind="info" title="A legal hold is active">Key destruction is delayed for what the hold covers.</Banner>}
              {off.steps.length > 0 && <ul className="steps">{off.steps.map((s) => { const l = stepLine(s); return <li key={s.step}><span className="t">{l.label}</span>{l.chip}</li>; })}</ul>}
              <p className="hint mt4">The final export comes first and the wait is at least 30 days.</p>
            </>
          )}
        </div>
      )}
      {!off && !done && !admin && role !== 'admin' && null}
      {dialog && <OffboardDialog name={orgName} onClose={() => setDialog(false)} onDone={() => { setDialog(false); setDone(true); void refreshOrg(); res.refresh(); }} />}
    </>
  );
}

function OffboardDialog({ name, onClose, onDone }: { name: string; onClose: () => void; onDone: () => void }) {
  const { api } = useSession();
  const [reason, setReason] = useState('');
  const [typed, setTyped] = useState('');
  const [touched, setTouched] = useState(false);
  const send = useAction(() => api.session.requestOffboarding(reason.trim(), typed));
  const match = typed === name;
  const err = send.error;
  return (
    <Dialog title={`Request offboarding for ${name}?`} alert onClose={onClose}>
      <form onSubmit={async (e) => { e.preventDefault(); if (!match || !reason.trim()) { setTouched(true); return; } const r = await send.run(); if (r.ok) onDone(); }} noValidate>
        <p>The operator starts the process and confirms dates with you. Your final export comes first. Nothing is destroyed until the waiting period ends.</p>
        {err && <ErrorBlock title="The offboarding request was not sent" err={err} next={err.code === 'offboarding_already_requested' ? 'A request is already open. The operator will contact you.' : 'Try again. Nothing has changed.'} headingLevel={3} />}
        <TextArea label="Reason (recorded in the audit log)" name="reason" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} error={touched && !reason.trim() ? 'Enter a reason.' : null} />
        <TextField label="Type the organization name to confirm" name="confirm-name" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} hint={`Type ${name} exactly.`} error={touched && !match ? 'The name does not match yet.' : null} />
        <div className="actions"><Btn data-safe="" onClick={onClose}>Cancel</Btn><Btn type="submit" variant="danger" disabled={!match} busy={send.busy} busyLabel="Sending">Send request</Btn></div>
      </form>
    </Dialog>
  );
}

// ---------- 21 Rule references ----------
export function References() {
  const { api } = useSession();
  const { search, navigate } = useRouter();
  const res = useResource(() => allPages((c) => api.ruleReferences({ cursor: c })), [api]);
  const j = search.get('jurisdiction') ?? '';
  const rows = res.status === 'ok' ? res.data : [];
  const options = useMemo(() => { const s = new Set(rows.map((r) => r.jurisdiction)); if (j) s.add(j); return [...s]; }, [rows, j]);
  const shown = j ? rows.filter((r) => r.jurisdiction === j) : rows;
  const dateNA = shown.some((r) => r.last_reviewed_on === null);
  const host = (u: string) => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return u; } };
  return (
    <>
      <PageHead title="Rule references" />
      <Banner kind="info">Citations and official links only. Not legal advice. A reference never changes a gate check unless your organization writes it into its approved policy.</Banner>
      {res.status === 'loading' && <Skeleton what="rule references" variant="table" />}
      {res.status === 'error' && <ErrorBlock title="References did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} />}
      {res.status === 'ok' && rows.length === 0 && <StateBlock kind="empty" title="No references yet">None are listed yet.</StateBlock>}
      {res.status === 'ok' && rows.length > 0 && (
        <>
          <div className="card"><SelectField label="Jurisdiction" name="jurisdiction" value={j} onChange={(e) => navigate(e.target.value ? `/references?jurisdiction=${encodeURIComponent(e.target.value)}` : '/references', { replace: true })} options={[{ value: '', label: 'All' }, ...options.map((o) => ({ value: o, label: o }))]} /></div>
          {dateNA && <Banner kind="warning" title="Review dates did not load">Shown as Not available.</Banner>}
          {shown.length === 0
            ? <div className="mt5"><StateBlock kind="empty" title="No references for this jurisdiction" actions={<Btn onClick={() => navigate('/references', { replace: true })}>Show all</Btn>}>{`None are listed for ${j} yet. Choose another jurisdiction or All.`}</StateBlock></div>
            : <div className="mt5"><DataTable caption="Rule references" rows={shown} rowKey={(r) => r.ref_id} columns={[
              { key: 'j', header: 'Jurisdiction', render: (r) => r.jurisdiction, primary: true },
              { key: 'c', header: 'Citation', render: (r) => r.citation },
              { key: 'o', header: 'Official source', render: (r) => <a href={r.source_url} target="_blank" rel="noopener noreferrer">{`${host(r.source_url)} (opens in a new tab)`}</a> },
              { key: 'l', header: 'Last reviewed', render: (r) => (r.last_reviewed_on ? <Time iso={r.last_reviewed_on} date /> : <NotAvailable />) },
            ]} /></div>}
        </>
      )}
    </>
  );
}

void ORG_STATUS_LABEL; void SuccessBanner; void useEffect; void useRef;

// ---- Company sign-in (admin) ----
export function CompanySignIn() {
  const { api, orgName } = useSession();
  const res = useResource(() => api.session.org(), [api]);
  const [saved, setSaved] = useState<string | null>(null);
  const save = useAction((req: boolean) => api.sso.set(req));
  if (res.status === 'loading') return <><PageHead title="Company sign-in" /><Skeleton what="company sign-in" /></>;
  if (res.status === 'error') return <><PageHead title="Company sign-in" /><ErrorBlock title="Company sign-in did not load" err={res.error} next="Try again." actions={<Btn onClick={res.reload}>Try again</Btn>} /></>;
  const sso = 'sso' in res.data ? res.data.sso : undefined;
  const run = async (req: boolean, done: string) => { const r = await save.run(req); if (r.ok) { setSaved(done); res.refresh(); } };
  return (
    <>
      <PageHead title="Company sign-in" lede={`Let ${orgName} sign in with its company account (Okta, Microsoft Entra or Google Workspace), and choose whether it is required.`} />
      {saved && <SuccessBanner>{saved}</SuccessBanner>}
      <div className="card">
        {save.error && <ErrorBlock title="That was not saved" err={save.error} next="Nothing was changed." headingLevel={3} />}
        {!sso?.connected && (
          <StateBlock kind="empty" title="No company account is connected">
            ConsentVault connects your company account for you. Ask your ConsentVault contact to connect it. Until then, everyone signs in with a passkey.
          </StateBlock>
        )}
        {sso?.connected && !sso.verified && (
          <>
            <p><b>Connected, waiting for an admin to confirm it.</b> Your ConsentVault contact connected your company account. To confirm it is yours, an admin signs in once with the company account.</p>
            <LinkBtn href="/sign-in" variant="primary">Sign in with your company</LinkBtn>
          </>
        )}
        {sso?.verified && !sso.required && (
          <>
            <p><b>Connected and confirmed.</b> Members may use a passkey or the company account.</p>
            <p>Requiring it signs out everyone who did not come through it, on their next click. You must be signed in through the company account yourself.</p>
            <Btn variant="danger" busy={save.busy} busyLabel="Saving" onClick={() => run(true, 'Company sign-in is now required for everyone.')}>Require company sign-in</Btn>
          </>
        )}
        {sso?.required && (
          <>
            <p><b>Required.</b> Every member must sign in with the company account.</p>
            <Btn variant="secondary" busy={save.busy} busyLabel="Saving" onClick={() => run(false, 'Company sign-in is no longer required. Passkeys work again.')}>Stop requiring it</Btn>
          </>
        )}
        <p className="hint mt4">Personal Google or Microsoft accounts are never accepted. If your company account is down and nobody can sign in, ask your ConsentVault contact: they can lift the requirement and your admins are told here.</p>
      </div>
    </>
  );
}
