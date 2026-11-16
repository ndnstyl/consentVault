// The security contact file (RFC 9116) every public host answers at /.well-known/security.txt. Answered by the Worker itself,
// never by the vault. The expiry is renewed when this file is edited (a file past its Expires line is stale by the standard).

export const SECURITY_CONTACT = "mailto:info@consentvault.ai";
export const SECURITY_TXT_EXPIRES = "2027-11-15T00:00:00.000Z";
export const SECURITY_TXT_PATH = "/.well-known/security.txt";

/** The 200 answer for a GET of the security file on ``host``; null for any other path or method. */
export function securityTxt(request: Request): Response | null {
  const url = new URL(request.url);
  if (url.pathname !== SECURITY_TXT_PATH) return null;
  if (request.method !== "GET" && request.method !== "HEAD") return null;
  const text = [
    `Contact: ${SECURITY_CONTACT}`,
    `Expires: ${SECURITY_TXT_EXPIRES}`,
    "Preferred-Languages: en",
    `Canonical: https://${url.host}${SECURITY_TXT_PATH}`,
    "",
  ].join("\n");
  return new Response(request.method === "HEAD" ? null : text, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=86400", "x-content-type-options": "nosniff" },
  });
}
