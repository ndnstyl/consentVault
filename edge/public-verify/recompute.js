(function () {
  "use strict";
  var enc = new TextEncoder();
  function hex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }
  function sha256(text) { return crypto.subtle.digest("SHA-256", enc.encode(text)).then(hex); }
  var base = location.pathname.replace(/\/+$/, "");
  var targets = document.querySelectorAll("[data-recompute]");
  Array.prototype.forEach.call(targets, function (el) {
    var out = el.parentNode.querySelector(".browser");
    if (!out || !window.crypto || !crypto.subtle) { return; }
    sha256(el.textContent).then(function (h) {
      var want = el.getAttribute("data-expect");
      out.textContent = "Recomputed in this browser: " + h + (want ? ". Equal to the value on this page: " + (h === want ? "yes" : "no") + "." : ".");
    });
  });
  var file = document.getElementById("file");
  if (file) {
    var a = document.createElement("a");
    a.href = base + "/record.zip";
    a.textContent = "Download the one-record file";
    file.textContent = "";
    file.appendChild(a);
  }
  var form = document.getElementById("match");
  if (form) {
    var result = document.getElementById("match-result");
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var typed = form.elements.contact.value;
      result.textContent = "Checking.";
      fetch(base + "/match", {
        method: "POST", credentials: "omit", referrerPolicy: "no-referrer",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify({ contact: typed })
      }).then(function (r) { return r.json().then(function (j) { return { s: r.status, j: j }; }); })
        .then(function (r) {
          result.textContent = r.j.statement || r.j.message || "The match box did not answer.";
          if (r.s === 200) { form.elements.contact.value = ""; }
        })
        .catch(function () { result.textContent = "The match box could not be reached. Nothing was recorded about what you typed."; });
    });
  }
})();
