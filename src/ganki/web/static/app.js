// Polls the scan state while it runs and reloads when it finishes.
// No external resources; all text comes from the server-rendered page.
(function () {
  "use strict";
  var headers = { "X-Ganki": "1" };

  function poll() {
    fetch("/api/status", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.state === "running") { setTimeout(poll, 1500); } else { location.reload(); }
      })
      .catch(function () { setTimeout(poll, 3000); });
  }

  var button = document.getElementById("rescan");
  if (button) {
    button.addEventListener("click", function () {
      button.disabled = true;
      fetch("/api/rescan", { method: "POST", headers: headers, credentials: "same-origin" })
        .then(function () { location.reload(); });
    });
  }
  var copy = document.getElementById("copy");
  if (copy) {
    copy.addEventListener("click", function () {
      var text = document.getElementById(copy.dataset.target).textContent;
      navigator.clipboard.writeText(text).then(function () { copy.textContent = copy.dataset.done; });
    });
  }
  if (document.body.dataset.state === "running") { poll(); }
})();
