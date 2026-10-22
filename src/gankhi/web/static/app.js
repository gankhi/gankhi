// Polls the scan state while it runs and reloads when it finishes.
// No external resources; all text comes from the server-rendered page.
(function () {
  "use strict";
  var headers = { "X-Gankhi": "1" };

  function finished() {
    location.reload();
  }

  // While the scan runs: show each step and the first facts as they arrive.
  var panel = document.getElementById("progress");
  var stepsList = document.getElementById("steps");
  var factsList = document.getElementById("facts");
  var cardsBox = document.getElementById("cards");
  var shownCards = "";
  var barFill = document.getElementById("bar-fill");
  var shownFacts = "";

  function paint(data) {
    var rows = stepsList.children;
    data.steps.forEach(function (step, i) {
      var li = rows[i];
      if (!li) {
        li = document.createElement("li");
        var dot = document.createElement("span");
        dot.className = "dot";
        var label = document.createElement("span");
        var time = document.createElement("span");
        time.className = "time";
        li.appendChild(dot); li.appendChild(label); li.appendChild(time);
        stepsList.appendChild(li);
      }
      li.className = step.state;
      li.children[1].textContent = step.label;
      li.children[2].textContent = step.detail;
    });
    // A new fact can belong in the middle of the list, so the list is drawn again whenever it
    // changes (adding only the last lines would repeat some and lose others).
    var shown = data.facts.join("\n");
    if (shown !== shownFacts) {
      shownFacts = shown;
      factsList.textContent = "";
      data.facts.forEach(function (line) {
        var fact = document.createElement("li");
        // "Label: value" are two different things: draw them apart so they do not run together.
        var cut = line.indexOf(": ");
        if (cut > 0) {
          var label = document.createElement("span");
          label.className = "fact-label";
          label.textContent = line.slice(0, cut + 1);
          var value = document.createElement("span");
          value.className = "fact-value";
          value.textContent = line.slice(cut + 2);
          fact.appendChild(label);
          fact.appendChild(value);
        } else {
          fact.textContent = line;
        }
        factsList.appendChild(fact);
      });
    }
    var cardsKey = JSON.stringify(data.cards || []);
    if (cardsBox && cardsKey !== shownCards) {
      shownCards = cardsKey;
      cardsBox.textContent = "";
      (data.cards || []).forEach(function (card) {
        var box = document.createElement("div");
        box.className = "kpi";
        box.setAttribute("data-tone", card.tone || "");
        var title = document.createElement("span");
        title.className = "kpi-title";
        title.textContent = card.title;
        var value = document.createElement("strong");
        value.textContent = card.value;
        box.appendChild(title);
        box.appendChild(value);
        if (card.meter !== null && card.meter !== undefined) {
          var meter = document.createElement("meter");
          meter.min = 0; meter.max = 100; meter.value = card.meter;
          meter.setAttribute("aria-label", card.title);
          box.appendChild(meter);
        }
        if (card.sub) {
          var sub = document.createElement("span");
          sub.className = "kpi-sub";
          sub.textContent = card.sub;
          box.appendChild(sub);
        }
        cardsBox.appendChild(box);
      });
    }
    barFill.setAttribute("width", String(data.percent));
    panel.querySelector(".bar").setAttribute("aria-valuenow", String(data.percent));
  }

  function poll() {
    var url = panel ? "/api/progress" : "/api/status";
    fetch(url, { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (panel && data.steps) { paint(data); }
        if (data.state === "running") { setTimeout(poll, panel ? 700 : 1500); return; }
        finished();
      })
      .catch(function () { setTimeout(poll, 3000); });
  }

  // Delegated, because the page content can be replaced when a scan finishes.
  document.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest("#rescan") : null;
    if (!button) { return; }
    button.disabled = true;
    fetch("/api/rescan", { method: "POST", headers: headers, credentials: "same-origin" })
      .then(function () { location.reload(); });
  });
  var run = document.getElementById("run");
  if (run) {
    var understood = document.getElementById("understood");
    var terminal = document.getElementById("terminal");
    var result = document.getElementById("run-result");
    function sync() { run.disabled = run.dataset.ack === "1" && !(understood && understood.checked); }
    if (understood) { understood.addEventListener("change", sync); }
    sync();

    var toggle = document.getElementById("toggle-output");
    var leave = document.getElementById("leave");
    function status(kind, text) {
      result.hidden = false;
      result.className = "run-status " + kind;
      result.textContent = text;
    }
    if (toggle) {
      toggle.addEventListener("click", function () {
        terminal.hidden = !terminal.hidden;
        toggle.textContent = terminal.hidden ? run.dataset.show : run.dataset.hide;
      });
    }

    function follow() {
      fetch("/api/run/status", { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (s) {
          terminal.textContent = "$ " + s.command + "\n" + s.lines.join("\n");
          terminal.scrollTop = terminal.scrollHeight;
          if (s.state === "running") {
            status("working", run.dataset.working);
            setTimeout(follow, 1000);
            return;
          }
          var ok = s.state === "done";
          status(ok ? "ok" : "fail", (ok ? run.dataset.ok : run.dataset.failed) +
            (s.snapshot ? " " + run.dataset.saved + " " + s.snapshot : ""));
          if (leave) { leave.textContent = run.dataset.home; }
          if (ok && toggle) {  // success: fold the long output away, it stays one click away
            terminal.hidden = true;
            toggle.hidden = false;
            toggle.textContent = run.dataset.show;
          }
        })
        .catch(function () { setTimeout(follow, 2000); });
    }

    run.addEventListener("click", function () {
      run.disabled = true;
      terminal.hidden = false;
      terminal.textContent = run.dataset.waiting;
      var body = { action: run.dataset.action, pkg: run.dataset.pkg, confirm: true,
                   understood: !!(understood && understood.checked) };
      fetch("/api/run", { method: "POST", headers: { "X-Gankhi": "1", "Content-Type": "application/json" },
                          credentials: "same-origin", body: JSON.stringify(body) })
        .then(function (r) {
          if (r.status === 202) { follow(); return; }
          // Only one change runs at a time: say so, and let the person try again later.
          return r.json().catch(function () { return {}; }).then(function (data) {
            status("fail", data.error === "busy" ? run.dataset.busy : run.dataset.refused);
            if (data.error === "busy") { run.disabled = false; terminal.hidden = true; }
          });
        })
        .catch(function () { status("fail", run.dataset.refused); });
    });
  }

  // Downloads detail: show the folder that holds a file, so it can be looked at and deleted by hand.
  var openResult = document.getElementById("open-result");
  Array.prototype.forEach.call(document.querySelectorAll("button.open-folder"), function (button) {
    button.addEventListener("click", function () {
      fetch("/api/open-folder", { method: "POST", headers: { "X-Gankhi": "1", "Content-Type": "application/json" },
                                   credentials: "same-origin", body: JSON.stringify({ path: button.dataset.path }) })
        .then(function (r) { openResult.textContent = r.ok ? openResult.dataset.ok : openResult.dataset.failed; })
        .catch(function () { openResult.textContent = openResult.dataset.failed; });
    });
  });

  // "Back" goes back in the browser's history, so the page comes back at the same place it was left
  // (a plain link would load it again from the top). With no history (opened directly) it is a link.
  Array.prototype.forEach.call(document.querySelectorAll("a[data-back]"), function (link) {
    link.addEventListener("click", function (event) {
      if (window.history.length > 1) {
        event.preventDefault();
        window.history.back();
      }
    });
  });

  // Changing the language replaces the current history entry, so "Back" still leaves the page.
  Array.prototype.forEach.call(document.querySelectorAll("a[data-replace]"), function (link) {
    link.addEventListener("click", function (event) {
      event.preventDefault();
      window.location.replace(link.href);
    });
  });

  // A copy button: after copying it says "done" for a moment, then goes back to its label.
  function copyButton(button, getText) {
    var original = button.textContent;
    var restore = null;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(getText()).then(function () {
        button.textContent = button.dataset.done;
        window.clearTimeout(restore);
        restore = window.setTimeout(function () { button.textContent = original; }, 2500);
      });
    });
  }
  var copy = document.getElementById("copy");
  if (copy) {
    copyButton(copy, function () { return document.getElementById(copy.dataset.target).textContent; });
  }
  document.querySelectorAll(".ask-row").forEach(function (button) {
    copyButton(button, function () { return button.dataset.prompt; });
  });
  if (document.body.dataset.state === "running") { poll(); }
})();
