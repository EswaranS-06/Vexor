// Theme before first paint (a separate classic script: the CSP allows no inline code).
// auto = follow the device; light / dark = chosen in the sidebar, kept in this browser.
(function () {
  var t = "auto";
  try { t = localStorage.getItem("vx-theme") || "auto"; } catch (e) { /* storage blocked */ }
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
})();
