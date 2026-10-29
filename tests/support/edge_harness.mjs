// Runs the real edge worker's fetch handler. The only thing mocked is the network: the worker's outbound
// fetch is replaced by a function that records the forwarded request and re-sends it to a live vault.
// stdin: {"live_url", "secret", "requests": [{"body": <string>, "ip": <string>}]}
// stdout: {"results": [{"status", "body", "forwarded": <object|null>}]}
import worker from "../../edge/src/worker.ts";

const input = JSON.parse(await new Promise((resolve, reject) => {
  let data = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (c) => (data += c));
  process.stdin.on("end", () => resolve(data));
  process.stdin.on("error", reject);
}));

const realFetch = globalThis.fetch;
let forwarded = null;
globalThis.fetch = async (url, init) => {
  const u = new URL(String(url));
  if (u.hostname !== "vault.example.com") throw new Error(`unexpected outbound call to ${u.hostname}`);
  forwarded = { path: u.pathname, headers: init.headers, body: JSON.parse(init.body) };
  return realFetch(input.live_url + u.pathname, { ...init, signal: AbortSignal.timeout(10000) });
};

const env = {
  ALLOWED_ORIGINS: "https://www.example.com",
  VAULT_URL: "https://vault.example.com",
  SIGNING_SECRET: input.secret,
  SOURCE_ID: "e2e-form",
};

const results = [];
for (const r of input.requests) {
  forwarded = null;
  const res = await worker.fetch(
    new Request("https://edge.example.com/consent", {
      method: "POST",
      headers: { origin: "https://www.example.com", "cf-connecting-ip": r.ip, "user-agent": "e2e/1" },
      body: r.body,
    }),
    env,
  );
  results.push({ status: res.status, body: await res.json(), forwarded });
}
process.stdout.write(JSON.stringify({ results }));
