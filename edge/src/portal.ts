// Portal Worker: the dashboard's one public door. /auth/* is sign-in (auth.ts), /v1/* is the gateway with session
// cookies (gateway.ts), everything else is the dashboard's static export.

import { handleAuth } from "./auth.ts";
import { handleGateway, vaultCaller, type GatewayDeps, type GatewayEnv } from "./gateway.ts";
import type { KV } from "./session.ts";

export { SessionGate } from "./session-gate.ts";

export interface PortalEnv extends GatewayEnv {
  AUTH_BASE_URL: string;
  AUTH_CLIENT_ID: string;
  PUBLIC_URL: string;
  SESSIONS: KV;
  ASSETS: { fetch(request: Request): Promise<Response> };
}

export async function handlePortal(request: Request, env: PortalEnv, deps: GatewayDeps): Promise<Response> {
  const path = new URL(request.url).pathname;
  const now = deps.now ?? Date.now;
  if (path.startsWith("/auth/")) {
    const res = await handleAuth(request, env, { fetch: deps.fetch, now, vault: vaultCaller(env, deps) });
    if (res) return res;
  }
  if (path.startsWith("/v1/")) return handleGateway(request, env, deps);
  if (!env.ASSETS) return new Response(JSON.stringify({ error: "misconfigured", message: "the dashboard static host is not bound" }), { status: 500, headers: { "content-type": "application/json" } });
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request: Request, env: PortalEnv): Promise<Response> {
    return handlePortal(request, env, { fetch: (...a) => fetch(...a) });
  },
};
