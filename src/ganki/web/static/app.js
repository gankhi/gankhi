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
  var run = document.getElementById("run");
  if (run) {
    var understood = document.getElementById("understood");
    var terminal = document.getElementById("terminal");
    var result = document.getElementById("run-result");
    function sync() { run.disabled = run.dataset.ack === "1" && !(understood && understood.checked); }
    if (understood) { understood.addEventListener("change", sync); }
    sync();

    function follow() {
      fetch("/api/run/status", { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (s) {
          terminal.textContent = "$ " + s.command + "\n" + s.lines.join("\n");
          terminal.scrollTop = terminal.scrollHeight;
          if (s.state === "running") { setTimeout(follow, 1000); return; }
          result.textContent = (s.state === "done" ? run.dataset.ok : run.dataset.failed) +
            (s.snapshot ? " " + run.dataset.saved + " " + s.snapshot : "");
        })
        .catch(function () { setTimeout(follow, 2000); });
    }

    run.addEventListener("click", function () {
      run.disabled = true;
      terminal.hidden = false;
      terminal.textContent = run.dataset.waiting;
      var body = { action: run.dataset.action, pkg: run.dataset.pkg, confirm: true,
                   understood: !!(understood && understood.checked) };
      fetch("/api/run", { method: "POST", headers: { "X-Ganki": "1", "Content-Type": "application/json" },
                          credentials: "same-origin", body: JSON.stringify(body) })
        .then(function (r) {
          if (r.status === 202) { follow(); } else { result.textContent = run.dataset.refused; }
        })
        .catch(function () { result.textContent = run.dataset.refused; });
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
