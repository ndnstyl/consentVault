// Runs the real checkbox widget under node with a minimal stand-in for the browser objects it touches.
// stdin: {"widget": <path>, "attributes": {<name>: <value>}, "box": <checkbox state at submit, default true>}
// stdin may also carry "answer": {"status", "body"}, what the edge answers.
// stdin may also carry "inputs": [{"name", "value"}] in document order, the hidden inputs on the host page.
// `--case passthrough` runs a built-in case (both issuer inputs filled) and exits 1 unless the post carries them byte for byte.
// stdout: {"posted": <the JSON body the widget sends to its endpoint>, "shown": <the text on screen>, "status": <the status line>}
import { readFileSync } from "node:fs";

const caseIndex = process.argv.indexOf("--case");
const caseName = caseIndex >= 0 ? process.argv[caseIndex + 1] : null;
const PASSTHROUGH_INPUTS = [
  { name: "xxTrustedFormCertUrl", value: "https://cert.trustedform.com/454a35b802f3e7b63ffabb4efedb7c6ebe67886c" },
  { name: "universal_leadid", value: "02bf1e5d-0c1e-4f0e-8d4b-0c9f7a3f9a11" },
];
const input = caseName === "passthrough"
  ? { widget: new URL("../../edge/widget/consent-checkbox.js", import.meta.url).pathname,
      attributes: { "data-disclosure": "I agree." }, inputs: PASSTHROUGH_INPUTS }
  : JSON.parse(await new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  }));

class Node_ {
  constructor() { this.children = []; this.attrs = {}; this.textContent = ""; }
  setAttribute(k, v) { this.attrs[k] = v; }
  appendChild(c) { this.children.push(c); return c; }
}
globalThis.HTMLElement = class extends Node_ {
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  attachShadow() { return new Node_(); }
  dispatchEvent() { return true; }
};
const pageInputs = (input.inputs || []).map((f, position) => ({
  name: f.name, value: f.value, position,
  compareDocumentPosition(other) { return other.position > this.position ? 4 : other.position < this.position ? 2 : 0; },
}));
globalThis.document = {
  createElement: () => new Node_(), getElementById: () => null,
  getElementsByName: (name) => pageInputs.filter((e) => e.name === name),
};
globalThis.CustomEvent = class { constructor(type, init) { this.type = type; this.detail = init && init.detail; } };
globalThis.location = { href: "https://www.example.com/signup" };
let defined = null;
globalThis.customElements = { get: () => undefined, define: (_name, cls) => { defined = cls; } };
let posted = null;
const fetched = [];
globalThis.fetch = async (url, init) => {
  fetched.push(String(url));
  posted = JSON.parse(init.body);
  const answer = input.answer || { status: 201, body: { stored: true } };
  return { ok: answer.status >= 200 && answer.status < 300, status: answer.status, json: async () => answer.body };
};

(0, eval)(readFileSync(input.widget, "utf8"));
const el = new defined();
el.attrs = { "data-endpoint": "https://edge.example.com/consent", ...input.attributes };
el.connectedCallback();
el._box.checked = input.box === undefined ? true : input.box;
let failed = null;
try {
  await el.submit("+15555550100");
} catch (e) {
  failed = String(e.message);
}
process.stdout.write(JSON.stringify({ posted, shown: el._span.textContent, status: el._status.textContent, failed, fetched }));
if (caseName === "passthrough") {
  const same = JSON.stringify(posted && posted.third_party) === JSON.stringify(PASSTHROUGH_INPUTS);
  if (!same) {
    process.stderr.write("passthrough: the post does not carry both certificate values byte for byte\n");
    process.exitCode = 1;
  }
}
