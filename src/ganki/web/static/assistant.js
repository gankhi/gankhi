// Written explanation of the dashboard. Nothing leaves this machine:
// the text comes from /api/narration (fixed rules, no AI, no network).
(function () {
  "use strict";
  var dock = document.getElementById("assistant");
  if (!dock) { return; }

  var caption = document.getElementById("assistant-caption");
  var btnExplain = document.getElementById("assistant-explain");
  var cache = null;      // last /api/narration answer
  var hoverTimer = null;
  var highlighted = null;

  function show(text) { caption.textContent = text; }

  function mark(section) {
    if (highlighted) { highlighted.classList.remove("speaking"); highlighted = null; }
    if (!section) { return; }
    var el = document.querySelector('[data-explain="' + section + '"]');
    if (el) {
      el.classList.add("speaking");
      highlighted = el;
    }
  }

  function load() {
    return fetch("/api/narration", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) { cache = data; return data; });
  }

  // The whole explanation, as text.
  function explainAll() {
    mark(null);
    load().then(function (data) {
      show(data.segments.map(function (s) { return s.text; }).join("\n\n"));
    });
  }

  // The cross puts the assistant away and leaves a small round button to bring it back.
  var btnClose = document.getElementById("assistant-close");
  var btnOpen = document.getElementById("assistant-open");
  function closeDock() {
    mark(null);
    dock.hidden = true;
    btnOpen.hidden = false;
    try { sessionStorage.setItem("ganki_dock", "closed"); } catch (e) { /* ignore */ }
  }
  function openDock() {
    dock.hidden = false;
    btnOpen.hidden = true;
    try { sessionStorage.removeItem("ganki_dock"); } catch (e) { /* ignore */ }
  }
  btnClose.addEventListener("click", closeDock);
  btnOpen.addEventListener("click", openDock);
  try { if (sessionStorage.getItem("ganki_dock") === "closed") { dock.hidden = true; btnOpen.hidden = false; } } catch (e) { /* ignore */ }

  btnExplain.addEventListener("click", explainAll);

  // Explain a section when the mouse (or keyboard focus) is on it. The page never scrolls.
  function explain(el) {
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(function () {
      var section = el.dataset.explain;
      (cache ? Promise.resolve(cache) : load()).then(function (data) {
        var item = data.segments.filter(function (s) { return s.section === section && !s.framing; });
        if (!item.length) { return; }
        mark(section);
        show(item.map(function (s) { return s.text; }).join(" "));
      });
    }, 500);
  }
  document.addEventListener("mouseover", function (e) {
    var el = e.target.closest ? e.target.closest("[data-explain]") : null;
    if (el) { explain(el); }
  });
  document.addEventListener("focusin", function (e) {
    var el = e.target.closest ? e.target.closest("[data-explain]") : null;
    if (el) { explain(el); }
  });
  document.addEventListener("mouseout", function (e) {
    var el = e.target.closest ? e.target.closest("[data-explain]") : null;
    if (el && !el.contains(e.relatedTarget)) {
      clearTimeout(hoverTimer);
      mark(null);
    }
  });

  show(dock.dataset.state === "done" ? dock.dataset.ready : dock.dataset.prompt);
})();
