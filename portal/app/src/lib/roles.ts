import type { Role } from './api/types.ts';

// Role matrix from portal/design/roles.md, updated to the contracts of 2026-10-29
// (developer exists; compliance viewer reads audit, systems, wording, checklists).
// The server is the authority; this only decides what to show.

export const ROLE_LABEL: Record<Role, string> = { admin: 'Admin', developer: 'Developer', compliance_viewer: 'Compliance viewer' };
export const ROLE_PLURAL: Record<Role, string> = { admin: 'admins', developer: 'developers', compliance_viewer: 'compliance viewers' };
export const ROLES: Role[] = ['admin', 'developer', 'compliance_viewer'];

export function normalizeRole(r: unknown): Role | null {
  return r === 'admin' || r === 'developer' || r === 'compliance_viewer' ? r : null;
}

const A: Role[] = ['admin'];
const AD: Role[] = ['admin', 'developer'];
const AV: Role[] = ['admin', 'compliance_viewer'];
const ALL: Role[] = ['admin', 'developer', 'compliance_viewer'];

export type RouteId =
  | 'sign-in' | 'callback' | 'invite' | 'choose-org' | 'plan' | 'billing-return'
  | 'overview' | 'first-event' | 'brands' | 'sources' | 'source-detail' | 'source-field-maps' | 'credentials' | 'credential-new'
  | 'wording' | 'wording-new' | 'wording-detail'
  | 'checklists' | 'checklist-detail' | 'evidence' | 'exports' | 'export-detail'
  | 'systems' | 'system-new' | 'system-detail' | 'retention' | 'members' | 'sso' | 'audit' | 'billing' | 'settings' | 'references'
  | 'records' | 'setup' | 'confirmations' | 'confirmation-edit';

export const VIEW_ROLES: Record<RouteId, Role[]> = {
  'sign-in': ALL, callback: ALL, invite: ALL, 'choose-org': ALL, plan: A, 'billing-return': A,
  overview: ALL, 'first-event': AD, brands: AD, sources: AD, 'source-detail': AD, 'source-field-maps': AD, credentials: AD, 'credential-new': AD,
  wording: ALL, 'wording-new': A, 'wording-detail': ALL,
  checklists: ALL, 'checklist-detail': ALL, evidence: AV, exports: AV, 'export-detail': AV,
  systems: ALL, 'system-new': AD, 'system-detail': ALL, retention: AV, members: A, sso: A, audit: AV, billing: A, settings: ALL, references: ALL,
  records: ALL, setup: AD, confirmations: ALL, 'confirmation-edit': AD,
};

export type Action =
  | 'brand.create' | 'source.write' | 'fieldmap.add' | 'credential.issue' | 'credential.issue.gate_read' | 'credential.issue.proof_read' | 'credential.revoke'
  | 'wording.register' | 'checklist.write' | 'evidence.erase' | 'export.build'
  | 'system.write' | 'system.redrive' | 'retention.set' | 'member.manage' | 'billing.manage' | 'offboarding.request' | 'first-event.send'
  | 'records.search' | 'records.reveal' | 'records.export' | 'records.person' | 'setup.skip' | 'confirmations.account' | 'confirmations.manage' | 'confirmations.replies';

export const ACTION_ROLES: Record<Action, Role[]> = {
  'brand.create': A, 'source.write': AD, 'fieldmap.add': AD, 'credential.issue': AD, 'credential.issue.gate_read': A, 'credential.issue.proof_read': A,
  'credential.revoke': AD, 'wording.register': A, 'checklist.write': A, 'evidence.erase': A, 'export.build': AV,
  'system.write': AD, 'system.redrive': AD, 'retention.set': A, 'member.manage': A, 'billing.manage': A, 'offboarding.request': A, 'first-event.send': AD,
  'records.search': AV, 'records.reveal': AV, 'records.export': AV, 'records.person': AV, 'setup.skip': AD, 'confirmations.account': AD, 'confirmations.manage': A, 'confirmations.replies': AV,
};

export function canView(role: Role | null, id: RouteId): boolean {
  return role !== null && VIEW_ROLES[id].includes(role);
}
export function canDo(role: Role | null, action: Action): boolean {
  return role !== null && ACTION_ROLES[action].includes(role);
}

export interface NavItem { id: RouteId; label: string; href: string }
export interface NavGroup { group: string; items: NavItem[] }

export const NAV: NavGroup[] = [
  { group: 'Start', items: [
    { id: 'overview', label: 'Overview', href: '/' },
    { id: 'setup', label: 'Setup', href: '/setup' },
    { id: 'first-event', label: 'First test event', href: '/setup/first-event' },
  ] },
  { group: 'Evidence', items: [
    { id: 'records', label: 'Records', href: '/records' },
    { id: 'evidence', label: 'Evidence lookup', href: '/evidence' },
    { id: 'exports', label: 'Evidence packages', href: '/exports' },
  ] },
  { group: 'Configuration', items: [
    { id: 'brands', label: 'Brands', href: '/brands' },
    { id: 'sources', label: 'Capture sources', href: '/sources' },
    { id: 'credentials', label: 'Credentials', href: '/credentials' },
    { id: 'wording', label: 'Wording', href: '/wording' },
    { id: 'checklists', label: 'Documentation checklists', href: '/checklists' },
    { id: 'systems', label: 'Connected systems', href: '/systems' },
    { id: 'confirmations', label: 'Confirmation messages', href: '/confirmations' },
    { id: 'retention', label: 'Retention', href: '/retention' },
  ] },
  { group: 'Organization', items: [
    { id: 'members', label: 'Members', href: '/members' },
    { id: 'sso', label: 'Company sign-in', href: '/sso' },
    { id: 'audit', label: 'Audit log', href: '/audit' },
    { id: 'billing', label: 'Billing', href: '/billing' },
    { id: 'settings', label: 'Settings', href: '/settings' },
    { id: 'references', label: 'Rule references', href: '/references' },
  ] },
];

export function navFor(role: Role | null): NavGroup[] {
  return NAV.map((g) => ({ group: g.group, items: g.items.filter((i) => canView(role, i.id)) })).filter((g) => g.items.length > 0);
}

/** Heading for the role-refusal state: "This page is for admins" (or the role list that may open it). */
export function refusalHeading(id: RouteId): string {
  const roles = VIEW_ROLES[id];
  if (roles.length === 1) return `This page is for ${ROLE_PLURAL[roles[0]]}`;
  const names = roles.map((r) => ROLE_PLURAL[r]);
  return `This page is for ${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

/** The first page a role may open, for the refusal state's button. */
export function fallbackFor(role: Role | null): NavItem {
  const first = navFor(role)[0]?.items[0];
  return first ?? { id: 'overview', label: 'Overview', href: '/' };
}
