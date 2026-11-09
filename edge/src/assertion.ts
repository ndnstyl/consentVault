// How the person signed in, told to the vault by the edge and by nobody else.
//
// Some issuers (WorkOS) put no authentication-method claim in their tokens. The edge receives the issuer's own answer to the
// code exchange server to server, turns it into RFC 8176 `amr` values, and signs a short assertion (ES256) for each vault call
// that carries the identity token. The vault trusts only the public key it is configured with; the browser never holds the
// private key, never sees the answer, and cannot add an `amr`. The assertion names the person (`sub`) and the exact token
// (`tok`, its SHA-256) and lives 60 seconds.
//
// Provider answer fields read (WorkOS User Management, "authenticate" response): `authentication_method` (a string such as
// "Passkey", "Password", "GoogleOAuth", "MagicAuth") and `authentication_factors` (the person's MFA factors, present when a
// factor was used). The mapping below is deliberately narrow; the staging smoke prints what the real answer carries.

import { b64url, sha256Hex } from "./session.ts";

export const ASSERTION_HEADER = "x-consentvault-edge-assertion";
const ISSUER = "consentvault-portal-edge";
const AUDIENCE = "consentvault-vault";
const LIFETIME_SECONDS = 60;

export interface ExchangeAnswer { authentication_method?: unknown; sso_connection_id?: unknown; organization_id?: unknown; user?: { email?: unknown; email_verified?: unknown } }

// The rule rests on `authentication_method` alone, the field the provider sends with every successful sign-in. A passkey
// counts on its own; a password, a magic link, an OAuth sign-in or anything unknown shows no second factor and the vault
// refuses it. (The provider's separate factor list is not read: it is absent from the live answer.)
// `passwordWithTotp` is true only when the operator declared that the provider environment requires multi-factor AND the
// provider's own factor list shows the person holds an authenticator-app factor; a password then counts as password plus code.
export function amrFromExchange(body: ExchangeAnswer, passwordWithTotp = false): string[] {
  if (body.authentication_method === "Passkey") return ["hwk", "user"];
  if (body.authentication_method === "Password" && passwordWithTotp) return ["pwd", "otp"];
  // Company single sign-on: the company's identity provider answers for the second factor, and only through a named
  // connection. The vault then lets it into an organization only if that organization connected the same one.
  if (ssoFromExchange(body)) return ["sso"];
  return [];
}

export interface SsoFacts { connection: string; organization: string }

// The connection and the sign-in-service organization the provider reports for a company single sign-on (WorkOS:
// `sso_connection_id` and `organization_id` in the authenticate answer; the live smoke prints what the real answer carries, since
// these field names are not yet confirmed against it). Both must be named. Whether that connection is one the operator bound to
// the ConsentVault organization being entered is the vault's decision, not the edge's.
export function ssoFromExchange(body: ExchangeAnswer): SsoFacts | null {
  const c = body.sso_connection_id, o = body.organization_id;
  return body.authentication_method === "SSO" && typeof c === "string" && /^conn_[A-Za-z0-9]{10,64}$/.test(c) &&
    typeof o === "string" && /^org_[A-Za-z0-9]{10,64}$/.test(o) ? { connection: c, organization: o } : null;
}

// The address the provider verified, from the same server-to-server answer. Tokens carry none.
export function whoFromExchange(body: ExchangeAnswer): { email: string | null; email_verified: boolean } {
  const email = body.user?.email;
  return typeof email === "string" && email ? { email, email_verified: body.user?.email_verified === true } : { email: null, email_verified: false };
}

export class MisconfiguredError extends Error {}

export interface AssertionEnv { ASSERTION_KEY_JWK?: string }

// A missing or unusable signing key is a deployment fault, never "no second factor": callers answer 500 "misconfigured".
export function assertionConfigError(env: AssertionEnv): string | null {
  if (!env.ASSERTION_KEY_JWK) return "the portal setting ASSERTION_KEY_JWK is not set";
  try {
    const k = JSON.parse(env.ASSERTION_KEY_JWK) as { kid?: unknown; d?: unknown };
    if (typeof k.kid !== "string" || !k.kid || typeof k.d !== "string") return "the portal setting ASSERTION_KEY_JWK must be a private P-256 JWK with a kid";
  } catch {
    return "the portal setting ASSERTION_KEY_JWK is not valid JSON";
  }
  return null;
}

export async function signAssertion(env: AssertionEnv, token: string, sub: string, amr: string[], method: string, nowMs: number,
  who: { email: string | null; email_verified: boolean } = { email: null, email_verified: false }, sso: SsoFacts | null = null): Promise<string> {
  const bad = assertionConfigError(env);
  if (bad) throw new MisconfiguredError(bad);
  const { kid, ...key } = JSON.parse(env.ASSERTION_KEY_JWK!) as JsonWebKey & { kid: string };
  const iat = Math.floor(nowMs / 1000);
  const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const head = enc({ alg: "ES256", typ: "JWT", kid });
  const body = enc({ iss: ISSUER, aud: AUDIENCE, sub, tok: await sha256Hex(token), amr, method, ...(who.email ? { email: who.email, email_verified: who.email_verified } : {}), ...(sso ? { sso_connection_id: sso.connection, sso_organization_id: sso.organization } : {}), iat, exp: iat + LIFETIME_SECONDS });
  let priv: CryptoKey;
  try {
    priv = await crypto.subtle.importKey("jwk", key, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  } catch {
    throw new MisconfiguredError("the portal setting ASSERTION_KEY_JWK is not a usable private P-256 key");
  }
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, new TextEncoder().encode(`${head}.${body}`)));
  return `${head}.${body}.${b64url(sig)}`;
}
