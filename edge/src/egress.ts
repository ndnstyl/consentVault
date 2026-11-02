// Egress Worker: delivers one outbound suppression-sync webhook for the vault (POST /push), or makes one call to a connected
// system's JSON API for a native connector (POST /call, the Twenty connector). https only; the host is resolved and refused
// when any address is private, loopback, link-local, metadata or otherwise non-public; port 443; no redirects; 10 second
// timeout. /push returns the receiver's status; /call also its rate-limit headers and its JSON body (256 KB at most). No body
// is ever logged.

import { Refusal } from "./worker.ts";

/** Every outbound request names itself; the caller cannot override it (user-agent is not a forwardable header). */
export const USER_AGENT = "ConsentVault/1.0 (+https://consentvault.ai)";

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
const CALL_HEADERS = ["authorization", "accept", "content-type"];
const CALL_METHODS = ["GET", "POST", "PATCH", "DELETE"];
const MAX_ANSWER_BYTES = 256 * 1024;
const ANSWER_HEADERS = /^(retry-after|x-ratelimit-[a-z0-9-]+)$/;

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

// Parse an IPv6 address to eight 16-bit words (a trailing dotted IPv4 quad included); null when it is not one.
export function parseIPv6(raw: string): number[] | null {
  const s = raw.toLowerCase().replace(/^\[|\]$/g, "");
  if (!s.includes(":") || s.includes("%")) return null;
  let tail: number[] = [];
  let body = s;
  const quad = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (quad) {
    const o = quad[2].split(".").map(Number);
    if (o.some((n) => n > 255)) return null;
    tail = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
    body = quad[1].endsWith("::") ? quad[1] : quad[1].slice(0, -1);
  }
  const halves = body.split("::");
  if (halves.length > 2) return null;
  const words = (part: string) => (part === "" ? [] : part.split(":"));
  const head = words(halves[0]);
  const rest = halves.length === 2 ? words(halves[1]) : [];
  if ([...head, ...rest].some((w) => !/^[0-9a-f]{1,4}$/.test(w))) return null;
  const known = head.length + rest.length + tail.length;
  if (halves.length === 1 ? known !== 8 : known > 7) return null;
  const fill = halves.length === 2 ? new Array(8 - known).fill(0) : [];
  return [...head.map((w) => parseInt(w, 16)), ...fill, ...rest.map((w) => parseInt(w, 16)), ...tail];
}

// Only global unicast (2000::/3) outside every special-purpose block that is not global or that embeds an IPv4 address:
// ::/64 (unspecified, loopback, IPv4-compatible, IPv4-mapped, IPv4-translated), 64:ff9b::/96 and 64:ff9b:1::/48 (NAT64),
// 100::/64, 2001::/23 (Teredo, ORCHID, benchmarking and the other IETF blocks), 2001:db8::/32, 2002::/16 (6to4), and outside
// 2000::/3 everything else (fc00::/7 unique local, fe80::/10 link-local, fec0::/10 site-local, ff00::/8 multicast).
export function isPublicIPv6(ip: string): boolean {
  const w = parseIPv6(ip);
  if (!w) return false;
  if ((w[0] & 0xe000) !== 0x2000) return false;
  if (w[0] === 0x2001 && w[1] < 0x0200) return false;
  if (w[0] === 0x2001 && w[1] === 0x0db8) return false;
  if (w[0] === 0x2002) return false;
  if (w[0] === 0x3fff && w[1] < 0x1000) return false; // documentation (3fff::/20)
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
    if (url.pathname !== "/push" && url.pathname !== "/call") throw new Refusal(404, "not_found", "no such route");
    if (request.method !== "POST") throw new Refusal(405, "method_not_allowed", "use POST");
    if (request.headers.get("authorization") !== `Bearer ${env.EGRESS_SECRET}`) {
      throw new Refusal(401, "unauthorized", "egress caller is not authorized");
    }
    if (url.pathname === "/call") return await handleCall(request, env, deps);
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

    headers.set("user-agent", USER_AGENT); // a receiver's firewall (Twenty Cloud) refuses a request with no or a library user-agent
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

async function readCapped(res: Response): Promise<Uint8Array> {
  const reader = res.body?.getReader();
  if (!reader) return new Uint8Array();
  const parts: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_ANSWER_BYTES) {
      await reader.cancel();
      throw new Refusal(502, "receiver_body_too_large", `the answer is over ${MAX_ANSWER_BYTES} bytes`);
    }
    parts.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

// POST /call: {target_url, method, headers, payload?} -> {receiver_status, receiver_headers, receiver_body}. The receiver's own
// error status is an answer (200 from the door); only the door's refusals and failures are door errors.
export async function handleCall(request: Request, env: EgressEnv, deps: EgressDeps): Promise<Response> {
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) throw new Refusal(413, "too_large", "body too large");
  let parsed: { target_url?: unknown; method?: unknown; headers?: unknown; payload?: unknown };
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Refusal(400, "bad_json", "body is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Refusal(400, "bad_shape", "body must be a JSON object");
  const method = typeof parsed.method === "string" ? parsed.method.toUpperCase() : "";
  if (!CALL_METHODS.includes(method)) throw new Refusal(400, "method_refused", "method must be GET, POST, PATCH or DELETE");
  const headers = new Headers();
  const given = (parsed.headers && typeof parsed.headers === "object" ? parsed.headers : {}) as Record<string, unknown>;
  for (const [k, v] of Object.entries(given)) {
    if (!CALL_HEADERS.includes(k.toLowerCase())) throw new Refusal(400, "header_refused", `header '${k}' may not be forwarded`);
    if (typeof v !== "string") throw new Refusal(400, "bad_shape", `header '${k}' must be a string`);
    headers.set(k, v);
  }
  const target = await validateTarget(parsed.target_url, deps);
  let body: string | undefined;
  if (parsed.payload !== undefined && parsed.payload !== null) {
    if (method === "GET") throw new Refusal(400, "bad_shape", "a GET carries no payload");
    body = typeof parsed.payload === "string" ? parsed.payload : JSON.stringify(parsed.payload);
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
  }
  headers.set("user-agent", USER_AGENT); // a receiver's firewall (Twenty Cloud) refuses a request with no or a library user-agent
  const timeout = Number(env.TIMEOUT_MS || 10000);
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout);
  let res: Response;
  let raw: Uint8Array;
  try {
    res = await deps.fetch(target.toString(), { method, headers, body, signal: ctl.signal, redirect: "manual" });
    if (res.status >= 300 && res.status < 400) {
      return reply(502, { error: "receiver_redirect", receiver_status: res.status, message: "redirects are not followed" });
    }
    raw = await readCapped(res);
  } catch (e) {
    if (e instanceof Refusal) throw e;
    if ((e as Error).name === "AbortError") throw new Refusal(504, "receiver_timeout", `receiver did not answer within ${timeout} ms`);
    throw new Refusal(502, "receiver_unreachable", `receiver unreachable: ${(e as Error).message}`);
  } finally {
    clearTimeout(timer);
  }
  const answerHeaders: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    if (ANSWER_HEADERS.test(k.toLowerCase())) answerHeaders[k.toLowerCase()] = v;
  });
  let json: unknown = null;
  try {
    json = raw.length ? JSON.parse(new TextDecoder().decode(raw)) : null;
  } catch {
    json = null; // the receiver's status is the answer; a body that is not JSON is carried as none
  }
  return reply(200, { receiver_status: res.status, receiver_headers: answerHeaders, receiver_body: json });
}

export default {
  async fetch(request: Request, env: EgressEnv): Promise<Response> {
    return handleEgress(request, env, { fetch: (...a) => fetch(...a), resolve: (h) => dohResolve(h) });
  },
};
