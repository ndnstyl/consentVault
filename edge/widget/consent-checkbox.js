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
      text = text.trim();
      if (!text) throw new Error("consentvault-consent: no disclosure text (use data-disclosure or data-template)");
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
      if (!this.checked) {
        this._say("Consent was not given, so nothing was recorded.", "error");
        return Promise.reject(new Error("consentvault-consent: box not checked"));
      }
      // Hash exactly the text on screen right now, at submit time.
      var shown = this._span.textContent;
      return sha256Hex(shown).then(function (hash) {
        var body = {
          contact: contact,
          checked: true,
          disclosure_sha256: hash,
          channels: list(self.getAttribute("data-channels")),
          purposes: list(self.getAttribute("data-purposes")),
          page_url: location.href,
          session: self._session,
        };
        if (extra && extra.turnstile_token) body.turnstile_token = extra.turnstile_token;
        return fetch(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
      }).then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (!res.ok || data.recorded !== true) {
            self._say("Your consent could not be recorded. Please try again.", "error");
            throw new Error("consentvault-consent: " + (data.error || "http " + res.status));
          }
          self._say("Recorded.", "ok");
          self.dispatchEvent(new CustomEvent("consentvault-recorded", { detail: data, bubbles: true }));
          return data;
        });
      }, function (err) {
        self._say("Your consent could not be recorded. Please try again.", "error");
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
