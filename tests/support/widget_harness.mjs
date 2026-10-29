// Runs the real checkbox widget under node with a minimal stand-in for the browser objects it touches.
// stdin: {"widget": <path>, "attributes": {<name>: <value>}}
// stdout: {"posted": <the JSON body the widget sends to its endpoint>, "shown": <the text on screen>}
import { readFileSync } from "node:fs";

const input = JSON.parse(await new Promise((resolve, reject) => {
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
globalThis.document = { createElement: () => new Node_(), getElementById: () => null };
globalThis.location = { href: "https://www.example.com/signup" };
let defined = null;
globalThis.customElements = { get: () => undefined, define: (_name, cls) => { defined = cls; } };
let posted = null;
globalThis.fetch = async (_url, init) => {
  posted = JSON.parse(init.body);
  return { ok: true, status: 200, json: async () => ({ recorded: true }) };
};

(0, eval)(readFileSync(input.widget, "utf8"));
const el = new defined();
el.attrs = { "data-endpoint": "https://edge.example.com/consent", ...input.attributes };
el.connectedCallback();
el._box.checked = true;
await el.submit("+15555550100");
process.stdout.write(JSON.stringify({ posted, shown: el._span.textContent }));
