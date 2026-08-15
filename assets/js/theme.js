/* personserver.dev — apply the colour theme before first paint.
   Kept as a separate file (not inline) so the site works under a strict CSP.
   Adapted from apd (MIT OR Apache-2.0), github.com/AgentProvider/source-code. */
(function () {
  try {
    var t = localStorage.getItem("theme");
    if (t !== "light" && t !== "dark") {
      t = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    document.documentElement.setAttribute("data-theme", t);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "dark");
  }
})();
