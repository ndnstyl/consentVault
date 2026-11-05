import type { RouteId } from './roles.ts';

export interface RouteDef { id: RouteId; pattern: string; title: string; chrome: 'app' | 'card'; preOrg?: boolean }

// One job per route (design/ia.md). Patterns use :param segments.
export const ROUTES: RouteDef[] = [
  { id: 'sign-in', pattern: '/sign-in', title: 'Sign in', chrome: 'card', preOrg: true },
  { id: 'callback', pattern: '/auth/callback', title: 'Signing you in', chrome: 'card', preOrg: true },
  { id: 'invite', pattern: '/invite', title: 'Accept an invitation', chrome: 'card', preOrg: true },
  { id: 'choose-org', pattern: '/choose-org', title: 'Choose an organization', chrome: 'card', preOrg: true },
  { id: 'plan', pattern: '/start/plan', title: 'Choose a plan', chrome: 'card' },
  { id: 'billing-return', pattern: '/billing/return', title: 'Checkout result', chrome: 'card' },
  { id: 'overview', pattern: '/', title: 'Overview', chrome: 'app' },
  { id: 'first-event', pattern: '/setup/first-event', title: 'First test event', chrome: 'app' },
  { id: 'brands', pattern: '/brands', title: 'Brands', chrome: 'app' },
  { id: 'sources', pattern: '/sources', title: 'Capture sources', chrome: 'app' },
  { id: 'source-detail', pattern: '/sources/:source_id', title: 'Capture source', chrome: 'app' },
  { id: 'source-field-maps', pattern: '/sources/:source_id/field-maps', title: 'Field map', chrome: 'app' },
  { id: 'credentials', pattern: '/credentials', title: 'Credentials', chrome: 'app' },
  { id: 'credential-new', pattern: '/credentials/new', title: 'Issue a credential', chrome: 'app' },
  { id: 'wording', pattern: '/wording', title: 'Wording', chrome: 'app' },
  { id: 'wording-new', pattern: '/wording/new', title: 'Register wording', chrome: 'app' },
  { id: 'wording-detail', pattern: '/wording/:sha256', title: 'Wording version', chrome: 'app' },
  { id: 'policies', pattern: '/policies', title: 'Policies', chrome: 'app' },
  { id: 'policy-new', pattern: '/policies/new', title: 'Draft a policy', chrome: 'app' },
  { id: 'policy-detail', pattern: '/policies/:version', title: 'Policy', chrome: 'app' },
  { id: 'policy-approve', pattern: '/policies/:version/approve', title: 'Approve a policy', chrome: 'app' },
  { id: 'checklists', pattern: '/checklists', title: 'Documentation checklists', chrome: 'app' },
  { id: 'checklist-detail', pattern: '/checklists/:version', title: 'Documentation checklist', chrome: 'app' },
  { id: 'evidence', pattern: '/evidence', title: 'Evidence lookup', chrome: 'app' },
  { id: 'exports', pattern: '/exports', title: 'Evidence packages', chrome: 'app' },
  { id: 'export-detail', pattern: '/exports/:export_id', title: 'Evidence package', chrome: 'app' },
  { id: 'systems', pattern: '/systems', title: 'Connected systems', chrome: 'app' },
  { id: 'system-new', pattern: '/systems/new', title: 'Connect a system', chrome: 'app' },
  { id: 'system-detail', pattern: '/systems/:system_id', title: 'Connected system', chrome: 'app' },
  { id: 'retention', pattern: '/retention', title: 'Retention', chrome: 'app' },
  { id: 'members', pattern: '/members', title: 'Members', chrome: 'app' },
  { id: 'sso', pattern: '/sso', title: 'Company sign-in', chrome: 'app' },
  { id: 'audit', pattern: '/audit', title: 'Audit log', chrome: 'app' },
  { id: 'billing', pattern: '/billing', title: 'Billing', chrome: 'app' },
  { id: 'settings', pattern: '/settings', title: 'Organization settings', chrome: 'app' },
  { id: 'references', pattern: '/references', title: 'Rule references', chrome: 'app' },
  { id: 'records', pattern: '/records', title: 'Records', chrome: 'app' },
  { id: 'setup', pattern: '/setup', title: 'Setup', chrome: 'app' },
  { id: 'confirmations', pattern: '/confirmations', title: 'Confirmation messages', chrome: 'app' },
  { id: 'confirmation-edit', pattern: '/confirmations/:source_id/:channel', title: 'Confirmation message', chrome: 'app' },
];

export interface Matched { route: RouteDef; params: Record<string, string> }

function segs(p: string): string[] { return p.split('/').filter(Boolean); }

/** Static segments beat :params, so /wording/new is never read as a sha256. */
export function matchRoute(pathname: string): Matched | null {
  const clean = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  const parts = segs(clean);
  let best: { m: Matched; score: number } | null = null;
  for (const route of ROUTES) {
    const pp = segs(route.pattern);
    if (pp.length !== parts.length) continue;
    const params: Record<string, string> = {};
    let score = 0;
    let ok = true;
    for (let i = 0; i < pp.length; i++) {
      if (pp[i].startsWith(':')) { params[pp[i].slice(1)] = decodeURIComponent(parts[i]); }
      else if (pp[i] === parts[i]) score += 1;
      else { ok = false; break; }
    }
    if (ok && (!best || score > best.score)) best = { m: { route, params }, score };
  }
  return best ? best.m : null;
}

/** Every path that gets its own static HTML file (dynamic ones are served by the host rewrite). */
export function staticPaths(): string[] {
  return ROUTES.filter((r) => !r.pattern.includes(':')).map((r) => r.pattern);
}
