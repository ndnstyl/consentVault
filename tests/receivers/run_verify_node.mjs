// Runs one Code node of the n8n template the way n8n does.
// stdin: {"template", "node", "hmacSecretHex", "ed25519Pem", "body", "headers", "items": [json...], "upstream": {nodeName: json}, "staticData": {}}
// stdout: {"out": [json...], "staticData": {...}}
import fs from 'node:fs';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const wf = JSON.parse(fs.readFileSync(input.template, 'utf8'));
const node = wf.nodes.find((n) => n.name === (input.node || 'Verify signature'));
if (!node) { console.error('no such node'); process.exit(2); }
let code = node.parameters.jsCode;
if (input.hmacSecretHex) code = code.replace('PASTE_HMAC_SECRET_HERE', input.hmacSecretHex);
if (input.ed25519Pem) code = code.replace('PASTE_ED25519_PUBLIC_KEY_HERE', input.ed25519Pem.replace(/\n/g, '\\n'));
if (input.blanket) code = code.replace("const BLANKET_FIELD = '';", `const BLANKET_FIELD = '${input.blanket}';`);
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const fn = new AsyncFunction('require', '$input', '$', '$getWorkflowStaticData', code);
const ctx = { helpers: { getBinaryDataBuffer: async () => Buffer.from(input.body ?? '', 'utf8') } };
const items = (input.items ?? [{ headers: input.headers }]).map((json) => ({ json }));
const staticData = input.staticData ?? {};
const up = (name) => ({ first: () => ({ json: input.upstream[name] }) });
const out = await fn.call(ctx, require, { first: () => items[0], all: () => items }, up, () => staticData);
process.stdout.write(JSON.stringify({ out: out.map((i) => i.json), staticData }));
