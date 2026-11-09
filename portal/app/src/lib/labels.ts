// Plain names for what the service sends as codes and ids. Nothing here invents a name: a person is shown by the
// name or address the service holds, an action by the service's own label or its code read as words.

export interface NamedMember { id: string; display_name: string | null; email: string }
export interface NamedActor { kind: string; id: string; display_name: string | null }

export function memberName(m: NamedMember | undefined): string | null { return m ? (m.display_name ?? m.email) : null; }

export function actorName(a: NamedActor, members: Map<string, NamedMember>): string | null {
  if (a.display_name) return a.display_name;
  if (a.kind === 'member') return memberName(members.get(a.id));
  if (a.kind === 'operator') return 'The platform operator';
  if (a.kind === 'system') return 'ConsentVault';
  return 'A credential';
}

export function actionWords(action: string): string {
  const w = action.replace(/[._]/g, ' ').trim();
  return w ? w.charAt(0).toUpperCase() + w.slice(1) : action;
}
export function actionLabel(action: string, labels: Map<string, string>): string { return labels.get(action) ?? actionWords(action); }

/** The service's own label for a wording version, else the label the sender gave it. */
export function wordingName(d: { version_label: string | null; label: string }): string { return d.version_label ?? d.label; }

export const purposeWords = (p: string): string => (p === '*' ? 'All purposes' : p);

/** Brand and source of a recorded event. A stop with neither was written by an erasure request; a missing brand on any other event is not recorded. */
export function eventOrigin(e: { brand_ids: string[]; source_id: string | null }, name: (id: string) => string): { brand: string; source: string } {
  const source = e.source_id ? name(e.source_id) : 'erasure request';
  const brand = e.brand_ids.length ? e.brand_ids.map(name).join(', ') : e.source_id ? 'Not recorded' : 'erasure request';
  return { brand, source };
}
