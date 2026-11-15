/*! Embeddable consent checkbox web component. */
(function () {
  "use strict";

  var TAG = "consentvault-consent";

  function hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) {
      return b.toString(16).padStart(2, "0");
    }).join("");
  }

  function sha256Hex(text) {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)).then(hex);
  }

  function list(value) {
    return (value || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  }

  /** The hidden inputs an issuer's script fills (TrustedForm, Jornaya LeadiD). Names read from the issuers' own pages. */
  var PASSTHROUGH_DEFAULT = ["xxTrustedFormCertUrl", "universal_leadid"];

  /** Every non-empty value of the named hidden inputs on the host page, copied as it is (never trimmed), in document order.
   * An empty or absent input is left out. Nothing is fetched from any issuer. */
  function passthrough(attr) {
    var names = attr === null ? PASSTHROUGH_DEFAULT : list(attr);
    var found = [];
    names.forEach(function (name, i) {
      if (names.indexOf(name) !== i) return;
      var els = document.getElementsByName(name);
      for (var k = 0; k < els.length; k++) {
        if (!found.some(function (f) { return f.el === els[k]; })) found.push({ el: els[k], name: name });
      }
    });
    found.sort(function (a, b) {
      if (typeof a.el.compareDocumentPosition !== "function") return 0;
      var rel = a.el.compareDocumentPosition(b.el);
      return rel & 4 ? -1 : rel & 2 ? 1 : 0;
    });
    var out = [];
    found.forEach(function (f) {
      var v = f.el.value;
      if (typeof v === "string" && v !== "") out.push({ name: f.name, value: v });
    });
    return out;
  }

  /** The browser's clock with its UTC offset, read at the moment of the click (for example 2026-11-03T10:04:05.120-05:00). */
  function decidedAt() {
    var d = new Date();
    var off = -d.getTimezoneOffset();
    var sign = off < 0 ? "-" : "+";
    var abs = Math.abs(off);
    function p(n, w) { return String(n).padStart(w || 2, "0"); }
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + "T" + p(d.getHours()) + ":" + p(d.getMinutes()) +
      ":" + p(d.getSeconds()) + "." + p(d.getMilliseconds(), 3) + sign + p(Math.floor(abs / 60)) + ":" + p(abs % 60);
  }

  function randomId() {
    var a = new Uint8Array(16);
    crypto.getRandomValues(a);
    return hex(a.buffer);
  }

  var STYLE =
    ":host{display:block;font:inherit}" +
    "label{display:flex;gap:.5em;align-items:flex-start;cursor:pointer}" +
    "input{margin-top:.25em}" +
    ".text{white-space:pre-wrap}" +
    ".status{margin-top:.5em;font-size:.9em}" +
    ".status.error{color:#b00020}.status.ok{color:#1b5e20}";

  class ConsentVaultConsent extends HTMLElement {
    connectedCallback() {
      if (this._root) return;
      this._root = this.attachShadow({ mode: "open" });
      this._session = randomId();
      var text = this._readDisclosure();
      var style = document.createElement("style");
      style.textContent = STYLE;
      var label = document.createElement("label");
      this._box = document.createElement("input");
      this._box.type = "checkbox";
      this._box.setAttribute("aria-describedby", "disclosure");
      this._span = document.createElement("span");
      this._span.id = "disclosure";
      this._span.className = "text";
      this._span.textContent = text;
      label.appendChild(this._box);
      label.appendChild(this._span);
      this._status = document.createElement("div");
      this._status.className = "status";
      this._status.setAttribute("role", "status");
      this._root.appendChild(style);
      this._root.appendChild(label);
      this._root.appendChild(this._status);
    }

    _readDisclosure() {
      var tplId = this.getAttribute("data-template");
      var text;
      if (tplId) {
        var tpl = document.getElementById(tplId);
        if (!tpl) throw new Error("consentvault-consent: template '" + tplId + "' not found");
        text = (tpl.content ? tpl.content.textContent : tpl.textContent) || "";
      } else {
        text = this.getAttribute("data-disclosure") || "";
      }
      // Never trimmed: the hash is over the exact text, the same bytes the vault registered (one rule everywhere).
      if (!text.trim()) throw new Error("consentvault-consent: no disclosure text (use data-disclosure or data-template)");
      return text;
    }

    get checked() {
      return !!(this._box && this._box.checked);
    }

    /** Submit consent for a contact. Resolves with the worker's JSON answer; rejects on any failure. */
    submit(contact, extra) {
      var self = this;
      var endpoint = this.getAttribute("data-endpoint");
      if (!endpoint) return Promise.reject(new Error("consentvault-consent: data-endpoint is not set"));
      var boxState = this.checked; // read at submit, sent exactly as it is
      var certificates = passthrough(this.getAttribute("data-passthrough")); // read at submit, sent as found
      var decided = decidedAt(); // the moment of the decision, on the browser's clock, with its offset
      // Hash exactly the text on screen right now, at submit time, and send that text beside its hash.
      var shown = this._span.textContent;
      return sha256Hex(shown).then(function (hash) {
        var body = {
          contact: contact,
          checked: boxState,
          decided_at: decided,
          disclosure_text: shown,
          disclosure_sha256: hash,
          channels: list(self.getAttribute("data-channels")),
          purposes: list(self.getAttribute("data-purposes")),
          page_url: location.href,
          session: self._session,
        };
        if (certificates.length) body.third_party = certificates;
        if (extra && extra.turnstile_token) body.turnstile_token = extra.turnstile_token;
        return fetch(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
      }).then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (data.queued === true) {
            self._say("Not yet stored, queued. Your choice will be recorded as soon as the record store answers.", "ok");
            self.dispatchEvent(new CustomEvent("consentvault-queued", { detail: data, bubbles: true }));
            return data;
          }
          if (!res.ok || data.stored !== true) {
            self._say("Your choice could not be recorded. Please try again.", "error");
            throw new Error("consentvault-consent: " + (data.error || "http " + res.status));
          }
          self._say("Your choice was recorded.", "ok");
          self.dispatchEvent(new CustomEvent("consentvault-recorded", { detail: data, bubbles: true }));
          return data;
        });
      }, function (err) {
        self._say("Your choice could not be recorded. Please try again.", "error");
        throw err;
      });
    }

    _say(msg, kind) {
      this._status.textContent = msg;
      this._status.className = "status " + kind;
    }
  }

  if (!customElements.get(TAG)) customElements.define(TAG, ConsentVaultConsent);
})();
