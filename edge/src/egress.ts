// Egress Worker: delivers one outbound suppression-sync webhook for the vault. https only; the host is
// resolved and refused when any address is private, loopback, link-local, metadata or otherwise non-public;
// 10 second timeout; the receiver's status is returned.

import { Refusal } from "./worker.ts";

export interface EgressEnv {
  EGRESS_SECRET: string; // shared with the sync worker; callers present it as a bearer
  TIMEOUT_MS?: string;
}

export interface EgressDeps {
  fetch: typeof fetch;
  resolve: (host: string) => Promise<string[]>;
}

const MAX_BODY_BYTES = 64 * 1024;
const FORWARD_HEADERS = ["x-consentvault-signature", "x-consentvault-delivery", "idempotency-key", "content-type"];

export function isPublicIPv4(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b, c] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if ([a, b, c, Number(m[4])].some((n) => n > 255)) return false;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
  if (a === 169 && b === 254) return false; // link-local, cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  if (a >= 224) return false; // multicast, reserved, broadcast
  return true;
}

export function isPublicIPv6(ip: string): boolean {
  const s = ip.toLowerCase().replace(/^\[|\]$/g, "");
  if (!s.includes(":")) return false;
  if (s === "::" || s === "::1") return false;
  const mapped = /^(?:0{0,4}:){0,5}(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s) || /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (mapped) return isPublicIPv4(mapped[1]);
  const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(s);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    return isPublicIPv4(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  }
  const first = parseInt(s.split(":")[0] || "0", 16);
  if ((first & 0xfe00) === 0xfc00) return false; // unique local
  if ((first & 0xffc0) === 0xfe80) return false; // link-local
  if ((first & 0xff00) === 0xff00) return false; // multicast
  if (s.startsWith("64:ff9b:")) return false; // NAT64
  if (s.startsWith("2001:db8:")) return false; // documentation
  if (s.startsWith("100::")) return false; // discard
  return true;
}

export function isPublicAddress(ip: string): boolean {
  return ip.includes(":") ? isPublicIPv6(ip) : isPublicIPv4(ip);
}

const IPV4_LITERAL = /^\d{1,3}(\.\d{1,3}){3}$/;

export async function dohResolve(host: string, f: typeof fetch = fetch): Promise<string[]> {
  const out: string[] = [];
  for (const type of ["A", "AAAA"]) {
    const res = await f(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
    });
    if (!res.ok) throw new Refusal(502, "dns_failed", `DNS lookup answered ${res.status}`);
    const data = (await res.json()) as { Answer?: { type: number; data: string }[] };
    for (const a of data.Answer || []) if (a.type === (type === "A" ? 1 : 28)) out.push(a.data);
  }
  return out;
}

function reply(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

export async function validateTarget(raw: unknown, deps: EgressDeps): Promise<URL> {
  if (typeof raw !== "string" || raw === "") throw new Refusal(400, "bad_shape", "field 'target_url' must be a non-empty string");
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Refusal(400, "bad_target", "target_url is not a valid URL");
  }
  if (u.protocol !== "https:") throw new Refusal(400, "target_not_https", "only https targets are allowed");
  if (u.username || u.password) throw new Refusal(400, "target_has_credentials", "target_url must not carry credentials");
  if (u.port && u.port !== "443") throw new Refusal(400, "target_port_refused", "only port 443 is allowed");
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal") || host.endsWith(".local")) {
    throw new Refusal(403, "target_address_refused", "target host is a local name");
  }
  let addrs: string[];
  if (IPV4_LITERAL.test(host) || host.includes(":")) {
    addrs = [host];
  } else {
    try {
      addrs = await deps.resolve(host);
    } catch (e) {
      if (e instanceof Refusal) throw e;
      throw new Refusal(502, "dns_failed", `could not resolve target host: ${(e as Error).message}`);
    }
  }
  if (addrs.length === 0) throw new Refusal(502, "dns_no_answer", "target host did not resolve to any address");
  const bad = addrs.filter((a) => !isPublicAddress(a));
  if (bad.length) throw new Refusal(403, "target_address_refused", `target resolves to a non-public address: ${bad.join(",")}`);
  return u;
}

export async function handleEgress(request: Request, env: EgressEnv, deps: EgressDeps): Promise<Response> {
  try {
    if (!env.EGRESS_SECRET) throw new Refusal(500, "misconfigured", "EGRESS_SECRET is not set");
    const url = new URL(request.url);
    if (url.pathname !== "/push") throw new Refusal(404, "not_found", "no such route");
    if (request.method !== "POST") throw new Refusal(405, "method_not_allowed", "use POST");
    if (request.headers.get("authorization") !== `Bearer ${env.EGRESS_SECRET}`) {
      throw new Refusal(401, "unauthorized", "egress caller is not authorized");
    }
    const text = await request.text();
    if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) throw new Refusal(413, "too_large", "body too large");
    let parsed: { target_url?: unknown; payload?: unknown; headers?: unknown };
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Refusal(400, "bad_json", "body is not valid JSON");
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Refusal(400, "bad_shape", "body must be a JSON object");
    if (typeof parsed.payload !== "string") throw new Refusal(400, "bad_shape", "field 'payload' must be the exact signed body as a string");
    const target = await validateTarget(parsed.target_url, deps);

    const headers = new Headers();
    const given = (parsed.headers && typeof parsed.headers === "object" ? parsed.headers : {}) as Record<string, unknown>;
    for (const [k, v] of Object.entries(given)) {
      if (!FORWARD_HEADERS.includes(k.toLowerCase())) throw new Refusal(400, "header_refused", `header '${k}' may not be forwarded`);
      if (typeof v !== "string") throw new Refusal(400, "bad_shape", `header '${k}' must be a string`);
      headers.set(k, v);
    }
    if (!headers.has("content-type")) headers.set("content-type", "application/json");

    const timeout = Number(env.TIMEOUT_MS || 10000);
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeout);
    let res: Response;
    try {
      res = await deps.fetch(target.toString(), { method: "POST", headers, body: parsed.payload, signal: ctl.signal, redirect: "manual" });
    } catch (e) {
      if ((e as Error).name === "AbortError") throw new Refusal(504, "receiver_timeout", `receiver did not answer within ${timeout} ms`);
      throw new Refusal(502, "receiver_unreachable", `receiver unreachable: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
    if (res.status >= 300 && res.status < 400) {
      return reply(502, { delivered: false, error: "receiver_redirect", receiver_status: res.status, message: "redirects are not followed" });
    }
    await res.arrayBuffer().catch(() => undefined);
    return reply(res.ok ? 200 : 502, { delivered: res.ok, receiver_status: res.status });
  } catch (e) {
    if (e instanceof Refusal) return reply(e.status, { delivered: false, error: e.code, message: e.message });
    return reply(500, { delivered: false, error: "internal", message: (e as Error).message });
  }
}

export default {
  async fetch(request: Request, env: EgressEnv): Promise<Response> {
    return handleEgress(request, env, { fetch: (...a) => fetch(...a), resolve: (h) => dohResolve(h) });
  },
};
