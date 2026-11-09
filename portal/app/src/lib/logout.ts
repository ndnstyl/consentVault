// What the page does with the edge's answer to a sign-out. A failure is shown, never treated as signed out.
export type LogoutOutcome = { go: string } | { error: string };

export function interpretLogout(status: number, body: { redirect?: unknown; message?: unknown; error?: unknown } | null): LogoutOutcome {
  if (status === 200 || status === 302) {
    const r = body?.redirect;
    return { go: typeof r === 'string' && /^(\/(?!\/)|https?:\/\/)/.test(r) ? r : '/sign-in' };
  }
  const why = typeof body?.message === 'string' ? body.message : status === 0 ? 'The service could not be reached.' : `The service answered ${status}.`;
  return { error: `Sign-out did not finish, so you may still be signed in on the service. ${why} Try again.` };
}

// Sign-out changes state, so it is a POST (the edge checks the request's origin), never a followed link. It goes over fetch:
// the page's form-action policy would block a form post that the edge redirects to the identity provider. A failed sign-out
// is returned as text for the page to show; it is never treated as signed out.
export async function postLogout(next?: 'passkey' | 'sso' | 'login', ret?: string): Promise<string | null> {
  const qs = next ? `?next=${next}${ret ? `&return=${encodeURIComponent(ret)}` : ''}` : '';
  let outcome;
  try {
    const r = await fetch(`/auth/logout${qs}`, { method: 'POST', credentials: 'include', cache: 'no-store', headers: { accept: 'application/json' } });
    outcome = interpretLogout(r.status, (await r.json().catch(() => null)) as never);
  } catch (e) {
    console.error('sign-out call failed', e);
    outcome = interpretLogout(0, null);
  }
  if ('error' in outcome) return outcome.error;
  window.location.assign(outcome.go);
  return null;
}
