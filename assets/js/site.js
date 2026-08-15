/* personserver.dev — small progressive-enhancement layer.
   Theme toggle, tabs, copy buttons, nav scroll state. No dependencies, no
   external requests. Everything works without it; it only adds convenience.
   Adapted from apd (MIT OR Apache-2.0), github.com/AgentProvider/source-code. */
(function () {
  "use strict";

  /* ---- theme toggle ---- */
  var toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var cur = document.documentElement.getAttribute("data-theme");
      var next = cur === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("theme", next); } catch (e) {}
    });
  }

  /* ---- nav border on scroll ---- */
  var nav = document.getElementById("nav");
  if (nav) {
    var onScroll = function () { nav.classList.toggle("is-scrolled", window.scrollY > 8); };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  }

  /* ---- install tabs ---- */
  document.querySelectorAll("[data-tabs]").forEach(function (group) {
    var tabs = group.querySelectorAll(".tab");
    var panels = group.querySelectorAll(".tab-panel");
    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () {
        var key = tab.getAttribute("data-tab");
        tabs.forEach(function (t) { t.classList.toggle("active", t === tab); });
        panels.forEach(function (p) { p.classList.toggle("active", p.getAttribute("data-panel") === key); });
      });
    });
  });

  /* ---- copy buttons (landing: pre-authored; docs: injected) ---- */
  var COPY = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
  var CHECK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>';

  function wire(btn, getText) {
    btn.addEventListener("click", function () {
      var text = getText();
      var done = function () {
        btn.classList.add("copied");
        btn.innerHTML = CHECK + "Copied";
        setTimeout(function () {
          btn.classList.remove("copied");
          btn.innerHTML = COPY + (btn.dataset.label || "Copy");
        }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        var ta = document.createElement("textarea");
        ta.value = text; document.body.appendChild(ta); ta.select();
        try { document.execCommand("copy"); } catch (e) {}
        document.body.removeChild(ta); done();
      }
    });
  }

  // Landing: buttons already in markup with a data-copy target id.
  document.querySelectorAll(".copy[data-copy]").forEach(function (btn) {
    btn.dataset.label = "Copy";
    btn.innerHTML = COPY + "Copy";
    wire(btn, function () {
      var el = document.getElementById(btn.getAttribute("data-copy"));
      return el ? el.innerText.replace(/^\s*\$\s?/gm, "").trim() : "";
    });
  });

  // Docs: inject a copy button into every rouge code block.
  document.querySelectorAll(".prose div.highlighter-rouge, .prose figure.highlight").forEach(function (block) {
    if (block.querySelector(".copy")) return;
    var pre = block.querySelector("pre");
    if (!pre) return;
    block.classList.add("code-wrap");
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy";
    btn.dataset.label = "Copy";
    btn.innerHTML = COPY + "Copy";
    wire(btn, function () { return pre.innerText.trim(); });
    block.appendChild(btn);
  });
})();
