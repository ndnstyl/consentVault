// Return addresses and navigation targets: a path on this site, never another origin. The browser strips tabs and
// newlines before it parses an address, so "/\t/evil.com" would become "//evil.com"; every control character, space and
// backslash is refused outright, and a resolved target is accepted only if its origin is this one.

const BAD = /[\u0000- \u007f\\]/;

export function safeReturn(r: string | null | undefined): string {
  if (!r || !r.startsWith('/') || r.startsWith('//') || BAD.test(r)) return '/';
  return sameOriginTarget(r, 'https://origin.invalid') ?? '/';
}

// The path (with query and hash) a target resolves to on `origin`, or null when it points anywhere else.
export function sameOriginTarget(to: string, origin: string): string | null {
  if (BAD.test(to)) return null;
  let u: URL;
  try { u = new URL(to, origin); } catch { return null; }
  if (u.origin !== origin) return null;
  return u.pathname + u.search + u.hash;
}
