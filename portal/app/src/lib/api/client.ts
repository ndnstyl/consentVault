import type * as T from './types.ts';

// Typed client for the ConsentVault Cloud API. Runs in the browser (cookie session, same origin) and under
// node:test (injected fetch). No token is ever held here: the edge holds the session cookie.

export class ApiError extends Error {
  status: number;
  code: string;
  detail: string;
  requestId: string | null;
  fields: Record<string, unknown>;
  retryAfter: number | null;
  constructor(status: number, code: string, detail: string, requestId: string | null, fields: Record<string, unknown> = {}, retryAfter: number | null = null) {
    super(`${status} ${code}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.requestId = requestId;
    this.fields = fields;
    this.retryAfter = retryAfter;
  }
}

export interface ClientOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  onUnauthenticated?: () => void;
  orgId?: () => string | null;       // the organization this tab shows; sent on every request so a write can never land in another
  onOrgMismatch?: () => void;        // the session's organization is no longer the one this tab shows
  requestId?: () => string;
}

export type Query = Record<string, string | number | boolean | null | undefined>;

function qs(q?: Query): string {
  if (!q) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : '';
}

export function createClient(opts: ClientOptions = {}) {
  const base = (opts.baseUrl ?? '').replace(/\/$/, '');
  const doFetch = opts.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
  const timeoutMs = opts.timeoutMs ?? 15000;
  const rid = opts.requestId ?? (() => (typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : String(Date.now())));

  async function request<R>(method: string, path: string, o: { query?: Query; body?: unknown } = {}): Promise<R> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    let res: Response;
    try {
      res = await doFetch(`${base}${path}${qs(o.query)}`, {
        method,
        credentials: 'include',
        cache: 'no-store',
        signal: ctl.signal,
        headers: {
          accept: 'application/json',
          'x-request-id': rid(),
          ...(opts.orgId?.() ? { 'x-cv-org': opts.orgId()! } : {}),
          ...(o.body !== undefined ? { 'content-type': 'application/json' } : {}),
        },
        body: o.body !== undefined ? JSON.stringify(o.body) : undefined,
      });
    } catch (e) {
      const aborted = e instanceof Error && e.name === 'AbortError';
      throw new ApiError(0, aborted ? 'timeout' : 'unreachable', aborted ? 'The service did not answer in time.' : 'The service could not be reached.', null);
    } finally {
      clearTimeout(timer);
    }
    if (res.status === 204) return undefined as R;
    let json: unknown = null;
    const text = await res.text();
    if (text) {
      try { json = JSON.parse(text); } catch { json = null; }
    }
    if (res.ok) return json as R;
    const b = (json && typeof json === 'object' ? json : {}) as Partial<T.ErrorBody>;
    const retry = res.headers.get('retry-after');
    const err = new ApiError(
      res.status,
      typeof b.error === 'string' ? b.error : `http_${res.status}`,
      typeof b.detail === 'string' ? b.detail : '',
      typeof b.request_id === 'string' ? b.request_id : null,
      b.fields ?? {},
      retry ? Number(retry) || null : null,
    );
    if (res.status === 401 && opts.onUnauthenticated) opts.onUnauthenticated();
    if (res.status === 409 && b.error === 'org_mismatch' && opts.onOrgMismatch) opts.onOrgMismatch();
    throw err;
  }

  const get = <R>(path: string, query?: Query) => request<R>('GET', path, { query });
  const post = <R>(path: string, body?: unknown) => request<R>('POST', path, { body: body ?? {} });
  const put = <R>(path: string, body: unknown) => request<R>('PUT', path, { body });
  const patch = <R>(path: string, body: unknown) => request<R>('PATCH', path, { body });
  const del = <R = void>(path: string) => request<R>('DELETE', path);
  const enc = encodeURIComponent;
  type Paged = { limit?: number; cursor?: string | null };

  return {
    request,
    // session.md
    session: {
      get: (q?: Paged) => get<T.SessionAnswer>('/v1/session', q),
      selectOrg: (org_id: string) => post<T.Membership>('/v1/session/org', { org_id }),
      org: () => get<T.Org>('/v1/org'),
      health: () => get<T.Health>('/v1/health'),
      requestOffboarding: (reason: string, org_name: string) => post<{ request_id: string; status: 'requested'; requested_at: string }>('/v1/offboarding-requests', { reason, org_name }),
      // admin.md, final export delivery: the admin posts the sha256 of the file they downloaded; delivery is recorded only on a match
      confirmFinalExport: (request_id: string, sha256: string) => post<T.FinalExportConfirmation>(`/v1/offboarding/${enc(request_id)}/final-export:confirm`, { sha256 }),
    },
    // members.md
    invites: {
      lookup: (token: string) => get<T.InviteLookup>(`/v1/invites/${enc(token)}`),
      accept: (token: string) => post<T.Membership>(`/v1/invites/${enc(token)}:accept`),
      withdraw: (invite_id: string) => del(`/v1/invites/${enc(invite_id)}`),
    },
    members: {
      list: (q?: Paged & { include?: 'invites'; role?: string; status?: string }) => get<T.Page<T.MemberRow>>('/v1/members', q),
      invite: (email: string, role: T.Role) => post<{ invite_id: string; email: string; role: T.Role; expires_at: string }>('/v1/members', { email, role }),
      setRole: (member_id: string, role: T.Role) => patch<{ member_id: string; role: T.Role }>(`/v1/members/${enc(member_id)}`, { role }),
      remove: (member_id: string) => del(`/v1/members/${enc(member_id)}`),
    },
    audit: {
      list: (q?: Paged & { action?: string; actor?: string; target_kind?: string; from?: string; to?: string }) => get<T.Page<T.AuditRow>>('/v1/audit', q),
      actions: (q?: Paged) => get<T.Page<{ action: string; label: string }>>('/v1/audit/actions', q),
    },
    // admin.md (names only: the one brand and source read a compliance viewer has)
    brandNames: (q?: Paged) => get<T.Page<T.BrandName>>('/v1/brand-names', q),
    sourceNames: (q?: Paged) => get<T.Page<T.SourceName>>('/v1/source-names', q),
    brands: {
      list: (q?: Paged) => get<T.Page<T.Brand>>('/v1/brands', q),
      create: (display_name: string) => post<{ brand_id: string; display_name: string; created_at: string }>('/v1/brands', { display_name }),
    },
    sources: {
      list: (q?: Paged & { brand_id?: string; status?: string; kind?: string }) => get<T.Page<T.Source>>('/v1/sources', q),
      get: (id: string) => get<T.Source>(`/v1/sources/${enc(id)}`),
      create: (b: { name: string; kind: 'site_key' | 'server'; brand_ids: string[]; allowed_origins: string[] }) => post<T.Source>('/v1/sources', b),
      update: (id: string, b: { name?: string; brand_ids?: string[]; allowed_origins?: string[]; status?: 'retired' }) => patch<T.Source>(`/v1/sources/${enc(id)}`, b),
      // a field map is read and added to, never edited: each add is a new version
      fieldMaps: {
        list: (id: string) => get<T.FieldMapList>(`/v1/sources/${enc(id)}/field-maps`),
        add: (id: string, b: T.FieldMapNew) => post<T.FieldMapVersion>(`/v1/sources/${enc(id)}/field-maps`, b),
      },
    },
    credentials: {
      list: (q?: Paged & { source_id?: string; kind?: string; scope?: string; status?: string }) => get<T.Page<T.Credential>>('/v1/credentials', q),
      issue: (b: { name: string; kind: T.CredentialKind; scope: T.CredentialScope; source_id?: string; public_key?: string; algorithm?: string }) => post<T.CredentialIssued>('/v1/credentials', b),
      revoke: (id: string, reason: string) => post<{ credential_id: string; revoked_at: string }>(`/v1/credentials/${enc(id)}:revoke`, { reason }),
    },
    sso: {
      set: (require_sso: boolean) => put<T.SsoSaved>('/v1/org/sso', { require_sso }),
    },
    retention: {
      get: (q?: Paged) => get<T.Retention>('/v1/retention', q),
      set: (evidence_years: number, reason: string) => put<T.RetentionVersion>('/v1/retention', { evidence_years, reason }),
    },
    erasure: {
      request: (contact: string, reason: string) => post<T.ErasureAccepted>('/v1/contacts:erase', { contact, reason }),
    },
    // reference lists
    channels: (q?: Paged) => get<T.Page<T.Channel>>('/v1/channels', q),
    purposes: (q?: Paged) => get<T.Page<T.Purpose>>('/v1/purposes', q),
    disclosures: {
      list: (q?: Paged & { brand_id?: string; channel?: string; purpose?: string; state?: 'current' | 'superseded' }) => get<T.Page<T.Disclosure>>('/v1/disclosures', q),
      get: (sha256: string) => get<T.Disclosure>(`/v1/disclosures/${enc(sha256)}`),
      register: (b: { body: string; label: string; channels: string[]; purposes: string[]; brand_ids: string[]; supersedes_sha256?: string; effective_from: string }) => post<T.Disclosure>('/v1/disclosures', b),
    },
    checklists: {
      list: (q?: Paged & { kind?: string; status?: string }) => get<T.Page<T.ChecklistItem>>('/v1/checklists', q),
      get: (version: number | string) => get<T.ChecklistDetail>(`/v1/checklists/${enc(String(version))}`),
      templates: (q?: Paged) => get<T.Page<T.ChecklistTemplate>>('/v1/checklist-templates', q),
      create: (b: { kind: 'pewc' | 'custom'; label: string; elements: Omit<T.ChecklistElement, 'element_id'>[] }) => post<T.ChecklistDetail>('/v1/checklists', b),
      replace: (version: number, b: { label?: string; elements: Omit<T.ChecklistElement, 'element_id'>[] }) => put<T.ChecklistDetail>(`/v1/checklists/${version}`, b),
      approve: (version: number) => post<{ version: number; status: 'approved'; approved_by: string; approved_at: string }>(`/v1/checklists/${version}:approve`, { acknowledged_documentation_only: true }),
    },
    ruleReferences: (q?: Paged & { jurisdiction?: string }) => get<T.Page<T.RuleReference>>('/v1/rule-references', q),
    // systems.md
    systems: {
      list: (q?: Paged & { kind?: string; status?: string }) => get<T.Page<T.System>>('/v1/systems', q),
      get: (id: string) => get<T.System>(`/v1/systems/${enc(id)}`),
      create: (b: { name: string; kind: T.System['kind']; endpoint: string; signature: 'ed25519' | 'hmac'; contact_form: 'plaintext' | 'fingerprint'; retry_window_hours?: number }) => post<T.SystemCreated>('/v1/systems', b),
      update: (id: string, b: Partial<Pick<T.System, 'name' | 'endpoint' | 'contact_form' | 'retry_window_hours' | 'status'>>) => patch<T.System>(`/v1/systems/${enc(id)}`, b),
      test: (id: string) => post<T.TestPush>(`/v1/systems/${enc(id)}:test`),
      deliveries: (id: string, q?: Paged & { status?: string; from?: string; to?: string }) => get<T.Page<T.Delivery>>(`/v1/systems/${enc(id)}/deliveries`, q),
      redrive: (system_id: string, reason: string) => post<{ redrive_id: string; requeued: number }>('/v1/deliveries:redrive', { system_id, reason }),
      redriveStatus: (id: string) => get<T.Redrive>(`/v1/redrives/${enc(id)}`),
    },
    // proof-export.md (the contact point is only ever in a POST body)
    evidence: {
      lookup: (contact: string, page?: { section: string; cursor: string | null; limit?: number }) => post<T.Proof>('/v1/proof', page ? { contact, page } : { contact }),
      deliveriesFor: (contact: string, system_id: string) => post<T.Page<T.ContactDelivery>>('/v1/deliveries:query', { contact, system_id }),
    },
    exports: {
      list: (q?: Paged & { status?: string; from?: string; to?: string }) => get<T.Page<T.ExportItem>>('/v1/exports', q),
      create: (contact: string) => post<{ export_id: string; status: 'building'; created_at: string }>('/v1/exports', { contact }),
      get: (id: string) => get<T.ExportDetail>(`/v1/exports/${enc(id)}`),
      link: (id: string) => post<{ download_url: string; expires_at: string }>(`/v1/exports/${enc(id)}:link`),
      resume: (id: string) => post<{ export_id: string; status: 'building' }>(`/v1/exports/${enc(id)}:resume`),
    },
    // records.md (a contact point is only ever in a POST body)
    records: {
      list: (q?: T.RecordFilters & Paged) => get<T.RecordsPage>('/v1/records', q as Query),
      summary: (q?: T.RecordFilters & { tz?: string }) => get<T.RecordsSummary>('/v1/records/summary', q as Query),
      search: (contact: string) => post<{ items: T.ContactRecord[] }>('/v1/records:search', { contact }),
      reveal: (record_ids: string[], reason?: string) => post<T.RevealAnswer>('/v1/records:reveal', reason ? { record_ids, reason } : { record_ids }),
      exportCreate: (b: { filters: T.RecordFilters; contact_form: 'masked' | 'full' | 'fingerprint'; include_person: boolean; reason?: string }) => post<{ export_id: string; status: 'building'; row_estimate: number | null }>('/v1/records/exports', b),
      exportList: (q?: Paged) => get<T.Page<T.RecordsExportItem>>('/v1/records/exports', q),
      exportGet: (id: string) => get<T.RecordsExportDetail>(`/v1/records/exports/${enc(id)}`),
      exportLink: (id: string) => post<{ download_url: string; expires_at: string }>(`/v1/records/exports/${enc(id)}:link`),
    },
    // setup.md
    setup: {
      get: () => get<T.SetupAnswer>('/v1/setup'),
      skip: (step: T.SetupStepName, reason?: string) => post<T.SetupStep>(`/v1/setup/steps/${enc(step)}:skip`, reason ? { reason } : {}),
      unskip: (step: T.SetupStepName) => post<T.SetupStep>(`/v1/setup/steps/${enc(step)}:unskip`),
    },
    // confirmations.md
    confirmations: {
      settings: () => get<T.ConfirmationSettings>('/v1/confirmations/settings'),
      saveSender: (b: { organization_name: string; postal_address: string; help_contact: { email: string; phone?: string } }) => put<T.ConfirmationSettings>('/v1/confirmations/settings', b),
      connectAccount: (b: Record<string, unknown>) => post<T.SendingAccount>('/v1/confirmations/sending-accounts', b),
      checkAccount: (id: string) => post<T.SendingAccount>(`/v1/confirmations/sending-accounts/${enc(id)}:check`),
      setProviderReplies: (id: string, provider_replies_itself: boolean) => patch<T.SendingAccount>(`/v1/confirmations/sending-accounts/${enc(id)}`, { provider_replies_itself }),
      disconnectAccount: (id: string, reason: string) => request<unknown>('DELETE', `/v1/confirmations/sending-accounts/${enc(id)}`, { body: { reason } }),
      setLinkHost: (host: string) => post<T.LinkHost>('/v1/confirmations/link-host', { host }),
      verifyLinkHost: () => post<T.LinkHost>('/v1/confirmations/link-host:verify'),
      markRegistration: (kind: string, reference?: string) => post<T.ConfirmationSettings['texting_registration']>('/v1/confirmations/texting-registration', { kind, ...(reference ? { reference } : {}), accepted: true, samples_included: true }),
      withdrawRegistration: (reason: string) => post<T.ConfirmationSettings['texting_registration']>('/v1/confirmations/texting-registration:withdraw', { reason }),
      rules: (q?: Paged) => get<T.Page<T.ConfirmationRule>>('/v1/confirmations/rules', q),
      saveRule: (source_id: string, channel: 'email' | 'sms', b: { enabled: boolean; sending_brand_id: string; template_id?: string; send_for_test_events?: boolean; dedupe_hours?: number; max_delay_minutes?: number }) =>
        put<T.ConfirmationRule>(`/v1/confirmations/rules/${enc(source_id)}/${enc(channel)}`, b),
      templates: (q?: Paged) => get<T.Page<T.ConfirmationTemplate>>('/v1/confirmations/templates', q),
      template: (id: string) => get<T.ConfirmationTemplateDetail>(`/v1/confirmations/templates/${enc(id)}`),
      createTemplate: (b: { subject: string; opening_line?: string }) => post<{ template_id: string; version: number }>('/v1/confirmations/templates', b),
      preview: (b: { source_id: string; channel: 'email' | 'sms'; template_id?: string; template?: { subject: string; opening_line?: string } }) => post<T.ConfirmationPreview>('/v1/confirmations:preview', b),
      test: (b: { source_id: string; channel: 'email' | 'sms'; contact: string }) => post<{ send_id: string; status: string }>('/v1/confirmations:test', b),
      sends: (q?: Paged & { status?: string; channel?: string; source_id?: string; from?: string; to?: string }) => get<T.Page<T.ConfirmationSend>>('/v1/confirmations/sends', q),
      replies: (q?: Paged & { state?: string }) => get<T.Page<T.ConfirmationReply>>('/v1/confirmations/replies', q),
      markReply: (reply_id: string, decision: 'stop' | 'not_stop', reason: string) => post<T.ConfirmationReply>(`/v1/confirmations/replies/${enc(reply_id)}:mark`, { decision, reason }),
    },
    // billing.md
    billing: {
      plans: (q?: Paged) => get<T.Page<T.Plan>>('/v1/billing/plans', q),
      get: () => get<T.Billing>('/v1/billing'),
      checkout: (plan_id: string) => post<{ checkout_url: string }>('/v1/billing/checkout', { plan_id }),
      portal: () => post<{ portal_url: string }>('/v1/billing/portal'),
    },
  };
}

export type Api = ReturnType<typeof createClient>;

/** Follow next_cursor until the list ends or `max` pages, for lists the portal shows whole. */
export async function allPages<X>(fetchPage: (cursor: string | null) => Promise<T.Page<X>>, max = 10): Promise<X[]> {
  const out: X[] = [];
  let cursor: string | null = null;
  for (let i = 0; i < max; i++) {
    const p: T.Page<X> = await fetchPage(cursor);
    out.push(...p.items);
    if (!p.next_cursor) return out;
    cursor = p.next_cursor;
  }
  return out;
}
