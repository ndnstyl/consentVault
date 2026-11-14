// A stub OIDC issuer for the portal tests, in the shape of the identity provider's user-management API:
//   GET  /user_management/authorize      authorization code with PKCE (S256) and state; no screen, it signs in the persona
//                                        the test chose and redirects back at once
//   POST /user_management/authenticate   authorization_code (checks the PKCE verifier) and refresh_token grants
//   GET  /user_management/sessions/logout
//   GET  /jwks                           the signing key the vault verifies tokens against
// The test controls it over HTTP: POST /__stub/persona (who the next sign-in is), POST /__stub/mint (a token for
// seeding), GET /__stub/log (what the edge asked of it). Tokens are signed ES256 with a key made at start.
// Run standalone:  node stub-oidc.ts --port 4400 --client-id client_stub --redirect http://localhost:8787/auth/callback

import http from "node:http";
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";

export interface Persona { sub: string; email: string; name?: string; amr?: string[]; ttl?: number; method?: string; connection?: string; workosOrg?: string }

export interface StubOptions { port?: number; clientId: string; clientSecret?: string; redirectUris: string[]; returnToPrefixes?: string[] }

export function createStubIssuer(opts: StubOptions) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const kid = "stub-" + crypto.randomBytes(4).toString("hex");
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
  let persona: Persona | null = null;
  const codes = new Map<string, { persona: Persona; challenge: string; redirect: string; used: boolean }>();
  const refreshTokens = new Map<string, { persona: Persona; sid: string }>();
  const ended = new Set<string>();
  const log: Record<string, unknown>[] = [];
  let issuer = "";

  const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
  function sign(claims: Record<string, unknown>): string {
    const head = b64u(JSON.stringify({ alg: "ES256", typ: "JWT", kid }));
    const body = b64u(JSON.stringify(claims));
    const sig = crypto.sign("sha256", Buffer.from(`${head}.${body}`), { key: privateKey, dsaEncoding: "ieee-p1363" });
    return `${head}.${body}.${b64u(sig)}`;
  }
  // The persona's amr says how it signs in; the answer to the code exchange reports it the way the provider does.
  function answerFields(p: Persona): Record<string, unknown> {
    const amr = p.amr ?? ["hwk", "user"];
    if (p.method === "SSO") return { authentication_method: "SSO", ...(p.connection ? { sso_connection_id: p.connection } : {}), ...(p.workosOrg ? { organization_id: p.workosOrg } : {}) };
    return { authentication_method: p.method ?? (amr.includes("hwk") ? "Passkey" : "Password") };
  }
  function token(p: Persona, sid: string): string {
    const now = Math.floor(Date.now() / 1000);
    return sign({
      // the shape of a real WorkOS access token (read on the staging run): client_id, no aud, no amr
      iss: issuer, client_id: opts.clientId, sub: p.sub, sid, iat: now, exp: now + (p.ttl ?? 300), auth_time: now, jti: crypto.randomUUID(),
    });
  }

  const json = (res: http.ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(body));
  };
  const readBody = (req: http.IncomingMessage) => new Promise<string>((ok) => { let s = ""; req.on("data", (c) => (s += c)); req.on("end", () => ok(s)); });

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://stub");
    const q = url.searchParams;
    if (req.method === "GET" && url.pathname === "/jwks") return json(res, 200, { keys: [jwk] });

    if (req.method === "POST" && url.pathname === "/__stub/persona") {
      persona = JSON.parse(await readBody(req)) as Persona;
      return json(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/__stub/mint") {
      const p = JSON.parse(await readBody(req)) as Persona;
      return json(res, 200, { token: token(p, "mint_" + crypto.randomBytes(4).toString("hex")) });
    }
    if (req.method === "GET" && url.pathname === "/__stub/log") return json(res, 200, log);

    if (req.method === "GET" && url.pathname === "/user_management/authorize") {
      const redirect = q.get("redirect_uri") ?? "";
      if (q.get("client_id") !== opts.clientId || !opts.redirectUris.includes(redirect)) {
        log.push({ route: "authorize", refused: "client_or_redirect" });
        return json(res, 400, { error: "invalid_request" });
      }
      if (q.get("response_type") !== "code" || q.get("code_challenge_method") !== "S256" || !q.get("code_challenge") || !q.get("state")) {
        log.push({ route: "authorize", refused: "pkce_or_state_missing" });
        return json(res, 400, { error: "invalid_request" });
      }
      log.push({ route: "authorize", provider: q.get("provider"), state_present: true, pkce: "S256" });
      const back = new URL(redirect);
      back.searchParams.set("state", q.get("state")!);
      if (!persona) {
        back.searchParams.set("error", "access_denied");
      } else {
        const code = crypto.randomBytes(16).toString("hex");
        codes.set(code, { persona, challenge: q.get("code_challenge")!, redirect, used: false });
        back.searchParams.set("code", code);
      }
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }

    if (req.method === "POST" && url.pathname === "/user_management/authenticate") {
      const b = JSON.parse((await readBody(req)) || "{}") as Record<string, string>;
      if (b.client_id !== opts.clientId || (opts.clientSecret && b.client_secret !== opts.clientSecret)) {
        log.push({ route: "authenticate", refused: "client" });
        return json(res, 401, { error: "invalid_client" });
      }
      if (b.grant_type === "authorization_code") {
        const c = codes.get(b.code);
        const okPkce = c && b.code_verifier && crypto.createHash("sha256").update(b.code_verifier).digest("base64url") === c.challenge;
        if (!c || c.used || !okPkce) {
          log.push({ route: "authenticate", grant: "authorization_code", refused: !c ? "unknown_code" : c.used ? "code_reused" : "pkce_mismatch" });
          return json(res, 400, { error: "invalid_grant" });
        }
        c.used = true;
        const sid = "sess_" + crypto.randomBytes(6).toString("hex");
        const rt = "rt_" + crypto.randomBytes(12).toString("hex");
        refreshTokens.set(rt, { persona: c.persona, sid });
        log.push({ route: "authenticate", grant: "authorization_code", ok: true, sid });
        return json(res, 200, { access_token: token(c.persona, sid), refresh_token: rt, user: { id: c.persona.sub, email: c.persona.email, email_verified: true }, ...answerFields(c.persona) });
      }
      if (b.grant_type === "refresh_token") {
        const r = refreshTokens.get(b.refresh_token);
        if (!r || ended.has(r.sid)) { log.push({ route: "authenticate", grant: "refresh_token", refused: "unknown_or_ended" }); return json(res, 400, { error: "invalid_grant" }); }
        refreshTokens.delete(b.refresh_token);
        const rt = "rt_" + crypto.randomBytes(12).toString("hex");
        refreshTokens.set(rt, r);
        log.push({ route: "authenticate", grant: "refresh_token", ok: true, sid: r.sid });
        return json(res, 200, { access_token: token(r.persona, r.sid), refresh_token: rt });
      }
      return json(res, 400, { error: "unsupported_grant_type" });
    }

    if (req.method === "GET" && url.pathname === "/user_management/sessions/logout") {
      const sid = q.get("session_id") ?? "";
      ended.add(sid);
      log.push({ route: "logout", session_id: sid });
      const to = q.get("return_to") ?? "";
      if ((opts.returnToPrefixes ?? []).some((p) => to.startsWith(p))) { res.writeHead(302, { location: to }); return res.end(); }
      return json(res, 200, { ok: true });
    }
    json(res, 404, { error: "not_found" });
  });

  return {
    async start(): Promise<{ url: string; jwksUrl: string; kid: string }> {
      await new Promise<void>((ok) => server.listen(opts.port ?? 0, "127.0.0.1", ok));
      issuer = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
      return { url: issuer, jwksUrl: issuer + "/jwks", kid };
    },
    stop: () => new Promise<void>((ok) => { server.closeAllConnections?.(); server.close(() => ok()); }),
  };
}

// Standalone: the stack script starts this as a child process and stops it on exit.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const arg = (n: string) => process.argv[process.argv.indexOf("--" + n) + 1];
  const redirects = process.argv.flatMap((a, i) => (a === "--redirect" ? [process.argv[i + 1]] : []));
  const returnTo = process.argv.flatMap((a, i) => (a === "--return-to" ? [process.argv[i + 1]] : []));
  const stub = createStubIssuer({ port: Number(arg("port")), clientId: arg("client-id"), clientSecret: process.argv.includes("--client-secret") ? arg("client-secret") : undefined, redirectUris: redirects, returnToPrefixes: returnTo });
  const info = await stub.start();
  console.log(JSON.stringify({ stub_ready: info }));
  const bye = () => stub.stop().then(() => process.exit(0));
  process.on("SIGTERM", bye);
  process.on("SIGINT", bye);
}
