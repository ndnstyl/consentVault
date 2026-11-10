// Asks the cv-wake function (AWS Lambda, behind a function URL) to start the parked ConsentVault servers. The request is
// signed: HMAC-SHA256 over "<timestamp>.<body>" with the shared secret, hex, in x-cv-timestamp and x-cv-signature. The
// function refuses anything unsigned, wrongly signed or older than a minute. Never throws: a failure comes back named so the
// caller can say it and log it. The key is never in a result or a log line.

export const WAKE_BODY = '{"action":"wake"}';
export const WAKE_TIMEOUT_MS = 8000;

export interface WakeEnv { CV_WAKE_URL?: string; CV_WAKE_KEY?: string }
export type WakeResult = { ok: true; answer: { services: Record<string, unknown> } } | { ok: false; reason: string };

const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");

export async function signWake(key: string, timestamp: string, body: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(`${timestamp}.${body}`)));
}

export async function callWake(env: WakeEnv, fetchImpl: typeof fetch, nowMs = Date.now()): Promise<WakeResult> {
  if (!env.CV_WAKE_URL) return { ok: false, reason: "CV_WAKE_URL is not set" };
  if (!env.CV_WAKE_KEY) return { ok: false, reason: "CV_WAKE_KEY is not set" };
  const ts = String(Math.floor(nowMs / 1000));
  let res: Response;
  try {
    res = await fetchImpl(env.CV_WAKE_URL, {
      method: "POST",
      headers: { "content-type": "application/json", "x-cv-timestamp": ts, "x-cv-signature": await signWake(env.CV_WAKE_KEY, ts, WAKE_BODY) },
      body: WAKE_BODY,
      signal: AbortSignal.timeout(WAKE_TIMEOUT_MS),
    });
  } catch (e) {
    return { ok: false, reason: `wake function unreachable: ${e instanceof Error ? e.name : "error"}` };
  }
  const text = await res.text().catch(() => "");
  if (res.status < 200 || res.status >= 300) return { ok: false, reason: `wake function answered http ${res.status}: ${text.slice(0, 200)}` };
  let parsed: { services?: unknown } | null = null;
  try { parsed = JSON.parse(text); } catch { /* named below */ }
  if (!parsed || typeof parsed.services !== "object" || parsed.services === null) return { ok: false, reason: `wake function answered http ${res.status} without the wake answer: ${text.slice(0, 200)}` };
  return { ok: true, answer: parsed as { services: Record<string, unknown> } };
}
