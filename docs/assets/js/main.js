import { initHero } from "./hero.js";
import { initSim, runScenario, setSoc, toggleTool } from "./sim.js";
import { loadReleases, loadStatus, loadCommands, inlineMd } from "./live.js";

const esc = (s) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

// ---------------------------------------------------------------- copy + toast
let toastTimer;
function toast(msg) {
  const t = document.querySelector("[data-toast]");
  t.textContent = msg;
  t.classList.add("is-on");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("is-on"), 1800);
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch {
    const ta = Object.assign(document.createElement("textarea"), { value: text });
    ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand("copy"); ta.remove(); return ok;
  }
}
function flash(btn, label = "Copied") {
  const span = btn.querySelector("[data-copy-label]") || btn;
  const old = span.textContent;
  btn.dataset.state = "done"; span.textContent = label;
  setTimeout(() => { btn.dataset.state = ""; span.textContent = old; }, 1400);
}

// ---------------------------------------------------------------- command reference
let GROUPS = [];
let activeGroup = "All";
function highlight(text, q) {
  if (!q) return esc(text);
  const i = text.toLowerCase().indexOf(q);
  if (i < 0) return esc(text);
  return esc(text.slice(0, i)) + "<mark>" + esc(text.slice(i, i + q.length)) + "</mark>" + esc(text.slice(i + q.length));
}
function renderCommands() {
  const list = document.querySelector("[data-cmd-list]");
  const q = document.querySelector("[data-cmd-filter]").value.trim().toLowerCase();
  const html = GROUPS
    .filter((g) => activeGroup === "All" || g.name === activeGroup)
    .map((g) => {
      const rows = g.rows.filter((r) => !q || r.cmdText.toLowerCase().includes(q) || r.desc.toLowerCase().includes(q) || g.name.toLowerCase().includes(q));
      if (!rows.length) return "";
      return `<section class="cmd-group"><h3>${esc(g.name)}</h3>${rows.map((r) => `
        <div class="cmd-row">
          <div class="cmd-row__cmd">${highlight(r.cmdText, q)}</div>
          <div class="cmd-row__desc">${inlineMd(r.desc)}</div>
          ${r.copy ? `<button type="button" class="copy-mini" data-copy="${esc(r.copy)}" aria-label="Copy ${esc(r.copy)}">Copy</button>` : "<span></span>"}
        </div>`).join("")}</section>`;
    }).join("");
  list.innerHTML = html || `<p class="cmd-empty">No command matches “${esc(q)}”. Try a stack name: wazuh, elk, n8n, suricata, zeek.</p>`;
}
function renderGroupChips() {
  const box = document.querySelector("[data-cmd-groups]");
  const names = ["All", ...GROUPS.map((g) => g.name)];
  box.innerHTML = names.map((n) => `<button type="button" class="chip" aria-pressed="${n === activeGroup}" data-group="${esc(n)}">${esc(n)}</button>`).join("");
}
async function initCommands() {
  const list = document.querySelector("[data-cmd-list]");
  try {
    GROUPS = await loadCommands();
  } catch {
    list.innerHTML = `<p class="cmdref__status">VEXOR.md could not be loaded from GitHub. Read it on <a href="https://github.com/EswaranS-06/Vexor/blob/main/VEXOR.md">github.com</a>.</p>`;
    return;
  }
  // stacks first
  const order = ["Wazuh", "ELK", "n8n", "Suricata", "Zeek"];
  GROUPS.sort((a, b) => (order.indexOf(a.name) + 1 || 99) - (order.indexOf(b.name) + 1 || 99));
  renderGroupChips();
  renderCommands();
  document.querySelector("[data-cmd-filter]").addEventListener("input", renderCommands);
  document.querySelector("[data-cmd-groups]").addEventListener("click", (e) => {
    const b = e.target.closest("[data-group]");
    if (!b) return;
    activeGroup = b.dataset.group;
    renderGroupChips(); renderCommands();
  });
  paletteItems.push(...GROUPS.flatMap((g) => g.rows.filter((r) => r.copy).map((r) => ({
    kind: g.name, main: r.cmdText, sub: r.desc.replace(/[`*]/g, ""), run: () => copy(r.copy).then(() => toast(`Copied: ${r.copy}`)),
  }))));
}

// ---------------------------------------------------------------- command palette (⌘K)
const paletteItems = [
  { kind: "go", main: "Simulator", sub: "Pick a stack and watch it run", run: () => location.assign("#simulator") },
  { kind: "go", main: "Every command", sub: "The full reference from VEXOR.md", run: () => location.assign("#commands") },
  { kind: "go", main: "What's new", sub: "Releases, read live from GitHub", run: () => location.assign("#changes") },
  { kind: "run", main: "Scenario: network attack", sub: "Suricata → Wazuh → n8n", run: () => runScenario("network") },
  { kind: "run", main: "Scenario: SSH brute force", sub: "agent → rule 5712 → active response", run: () => runScenario("ssh") },
  { kind: "run", main: "Scenario: a container dies", sub: "watchdog + doctor --fix", run: () => runScenario("crash") },
  { kind: "set", main: "SOC=both", sub: "Wazuh + ELK in the simulator", run: () => { setSoc("both"); location.assign("#simulator"); } },
  { kind: "set", main: "Toggle n8n", sub: "N8N=true|false in the simulator", run: () => { toggleTool("n8n"); location.assign("#simulator"); } },
  { kind: "copy", main: "Install command", sub: "git clone … && sudo ./vexor install", run: () => copy(document.getElementById("install-cmd").textContent).then(() => toast("Copied: install command")) },
];
let pal = {}, sel = 0, shown = [], lastFocus = null;
function paletteRender() {
  const words = pal.input.value.toLowerCase().split(/\s+/).filter(Boolean);
  shown = paletteItems.filter((it) => {
    const hay = `${it.kind} ${it.main} ${it.sub}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  }).slice(0, 40);
  sel = Math.min(sel, Math.max(0, shown.length - 1));
  pal.list.innerHTML = shown.length ? shown.map((it, i) => `
    <li role="option" id="pal-${i}" aria-selected="${i === sel}" data-i="${i}">
      <span class="p-kind">${esc(it.kind)}</span>
      <span class="p-main">${esc(it.main)}<span class="p-sub">${esc(it.sub.slice(0, 140))}</span></span>
    </li>`).join("") : `<li aria-disabled="true"><span class="p-kind">none</span><span class="p-main">No match<span class="p-sub">Try: n8n, test, backup, elk</span></span></li>`;
  pal.input.setAttribute("aria-activedescendant", shown.length ? `pal-${sel}` : "");
  pal.list.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
}
function paletteOpen() {
  lastFocus = document.activeElement;
  pal.root.hidden = false;
  pal.input.value = ""; sel = 0;
  paletteRender();
  pal.input.focus();
}
function paletteClose() {
  pal.root.hidden = true;
  lastFocus?.focus?.();
}
function paletteRun(i) {
  const it = shown[i];
  if (!it) return;
  paletteClose();
  it.run();
}
function initPalette() {
  pal = {
    root: document.querySelector("[data-palette]"),
    input: document.querySelector("[data-palette-input]"),
    list: document.querySelector("[data-palette-list]"),
  };
  document.querySelectorAll("[data-open-palette]").forEach((b) => b.addEventListener("click", paletteOpen));
  document.querySelectorAll("[data-palette-close]").forEach((b) => b.addEventListener("click", paletteClose));
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); pal.root.hidden ? paletteOpen() : paletteClose(); }
    if (pal.root.hidden) return;
    if (e.key === "Escape") { e.preventDefault(); paletteClose(); }
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(shown.length - 1, sel + 1); paletteRender(); }
    if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(0, sel - 1); paletteRender(); }
    if (e.key === "Enter") { e.preventDefault(); paletteRun(sel); }
    if (e.key === "Tab") { e.preventDefault(); pal.input.focus(); }
  });
  pal.input.addEventListener("input", () => { sel = 0; paletteRender(); });
  pal.list.addEventListener("click", (e) => { const li = e.target.closest("[data-i]"); if (li) paletteRun(Number(li.dataset.i)); });
}

// ---------------------------------------------------------------- misc
function initCopyButtons() {
  document.addEventListener("click", async (e) => {
    const t = e.target.closest("[data-copy-target], [data-copy], [data-copy-target-el]");
    if (!t) return;
    let text = "";
    if (t.dataset.copyTarget) text = document.getElementById(t.dataset.copyTarget).textContent;
    else if (t.dataset.copyTargetEl) text = document.querySelector(`[data-${t.dataset.copyTargetEl}]`).dataset.copy || "";
    else text = t.dataset.copy;
    if (await copy(text)) flash(t);
  });
}
function initReveal() {
  const targets = document.querySelectorAll(".hero__copy > *, .session, .release, .steps li");
  if (!("IntersectionObserver" in window)) return;
  targets.forEach((el, i) => { el.classList.add("reveal"); el.style.setProperty("--i", String(i % 6)); });
  const io = new IntersectionObserver((entries) => entries.forEach((en) => {
    if (en.isIntersecting) { en.target.classList.add("is-in"); io.unobserve(en.target); }
  }), { rootMargin: "0px 0px -8% 0px" });
  targets.forEach((el) => io.observe(el));
}

document.querySelectorAll("[data-mod]").forEach((e) => (e.textContent = isMac ? "⌘" : "Ctrl"));
initCopyButtons();
initPalette();
initHero();
initSim();
initReveal();
loadReleases().then((tag) => { loadStatus(tag); initReveal(); });
initCommands();
