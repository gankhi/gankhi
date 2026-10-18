// Spoken explanation of the dashboard. Nothing leaves this machine:
// the text comes from /api/narration (rules, no AI) and the voice is a LOCAL voice of the browser.
(function () {
  "use strict";
  var dock = document.getElementById("assistant");
  if (!dock) { return; }

  var synth = window.speechSynthesis;
  var caption = document.getElementById("assistant-caption");
  var btnOn = document.getElementById("voice-on");
  var btnPlay = document.getElementById("voice-play");
  var btnStop = document.getElementById("voice-stop");
  var hoverBox = document.getElementById("voice-hover");

  var enabled = false;   // the person pressed "turn on voice" (browsers require this gesture)
  var token = 0;         // changes whenever speech is cancelled, so old callbacks do nothing
  var cache = null;      // last /api/narration answer
  var hoverTimer = null;
  var highlighted = null;

  try { hoverBox.checked = localStorage.getItem("ganki_hover") !== "0"; } catch (e) { /* ignore */ }
  hoverBox.addEventListener("change", function () {
    try { localStorage.setItem("ganki_hover", hoverBox.checked ? "1" : "0"); } catch (e) { /* ignore */ }
  });

  function pickVoice(lang) {
    var voices = synth ? synth.getVoices() : [];
    var local = voices.filter(function (v) { return v.localService && v.lang.toLowerCase().indexOf(lang) === 0; });
    var order = lang === "es" ? ["es-ar", "es-419", "es-mx", "es-us", "es-es"] : ["en-us", "en-gb"];
    for (var i = 0; i < order.length; i++) {
      for (var j = 0; j < local.length; j++) {
        if (local[j].lang.toLowerCase().replace("_", "-") === order[i]) { return local[j]; }
      }
    }
    return local[0] || null;
  }

  function show(text) { caption.textContent = text; }

  function mark(section) {
    if (highlighted) { highlighted.classList.remove("speaking"); highlighted = null; }
    if (!section) { return; }
    var el = document.querySelector('[data-explain="' + section + '"]');
    if (el) {
      el.classList.add("speaking");
      highlighted = el;
      el.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }

  function sentences(text) {
    return text.match(/[^.!?]+[.!?]?/g).map(function (s) { return s.trim(); }).filter(Boolean);
  }

  // Speak one text, sentence by sentence (long utterances get cut off by some browsers).
  function speak(text, done) {
    var voice = pickVoice(dock.dataset.lang);
    show(text);
    if (!synth || !voice) {
      if (enabled) { show(dock.dataset.noVoice + "\n\n" + text); }
      setTimeout(done, Math.min(8000, 1500 + text.length * 40)); // keep the captions moving
      return;
    }
    var mine = token;
    var parts = sentences(text);
    (function next(i) {
      if (mine !== token) { return; }
      if (i >= parts.length) { done(); return; }
      var u = new SpeechSynthesisUtterance(parts[i]);
      u.voice = voice;
      u.lang = voice.lang;
      u.onend = function () { next(i + 1); };
      u.onerror = function () { if (mine === token) { done(); } };
      synth.speak(u);
    })(0);
  }

  function stop() {
    token += 1;
    if (synth) { synth.cancel(); }
    mark(null);
    btnStop.hidden = true;
    btnPlay.hidden = !enabled;
  }

  function load() {
    return fetch("/api/narration", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) { cache = data; return data; });
  }

  function playAll() {
    stop();
    var mine = token;
    btnStop.hidden = false;
    btnPlay.hidden = true;
    load().then(function (data) {
      var list = data.segments;
      (function next(i) {
        if (mine !== token) { return; }
        if (i >= list.length) { stop(); show(dock.dataset.ready); return; }
        mark(list[i].section);
        speak(list[i].text, function () { next(i + 1); });
      })(0);
    });
  }

  function enable() {
    enabled = true;
    btnOn.hidden = true;
    btnPlay.hidden = false;
    try { sessionStorage.setItem("ganki_voice", "1"); } catch (e) { /* ignore */ }
    if (synth) { synth.cancel(); synth.resume(); }
    if (dock.dataset.state === "running") {
      load().then(function (data) { speak(data.scanning, function () {}); });
    } else if (dock.dataset.state === "done") {
      playAll();
    }
  }

  btnOn.addEventListener("click", enable);
  btnPlay.addEventListener("click", playAll);
  btnStop.addEventListener("click", stop);

  // Explain a section when the mouse (or keyboard focus) is on it.
  function explain(el) {
    if (!enabled || !hoverBox.checked || !btnStop.hidden) { return; }
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(function () {
      var section = el.dataset.explain;
      (cache ? Promise.resolve(cache) : load()).then(function (data) {
        var item = data.segments.filter(function (s) { return s.section === section && !s.framing; });
        if (!item.length) { return; }
        token += 1;
        if (synth) { synth.cancel(); }
        mark(section);
        speak(item.map(function (s) { return s.text; }).join(" "), function () { mark(null); });
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
      if (btnStop.hidden && enabled) { token += 1; if (synth) { synth.cancel(); } mark(null); }
    }
  });

  // app.js calls this when a scan finishes. Keeping the same page (no reload) is what lets the
  // voice keep talking, because the browser only allows speech after a click on this page.
  window.GankiAssistant = {
    onScanDone: function () {
      if (!enabled) { return false; }
      return fetch("/", { credentials: "same-origin" })
        .then(function (r) { return r.text(); })
        .then(function (html) {
          var doc = new DOMParser().parseFromString(html, "text/html");
          var fresh = doc.querySelector("main");
          document.querySelector("main").replaceWith(fresh);
          document.body.dataset.state = "done";
          dock.dataset.state = "done";
          cache = null;
          playAll();
          return true;
        })
        .catch(function () { location.reload(); });
    }
  };

  if (dock.dataset.state === "running" && synth) {
    show(btnOn.textContent);
  } else if (dock.dataset.state === "done") {
    show(dock.dataset.ready);
  }
})();
