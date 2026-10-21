// Shared by every page: escaping, copy + toast, the ⌘K palette (pages + commands from VEXOR.md),
// copy buttons, reveal-on-scroll, nav state.
import { loadCommands } from "./live.js";

export const esc = (s) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
export const reduced = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

let toastTimer;
export function toast(msg) {
  const t = document.querySelector("[data-toast]");
  if (!t) return;
  t.textContent = msg;
  t.classList.add("is-on");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("is-on"), 1800);
}
export async function copy(text) {
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

// ---------------------------------------------------------------- reveal (one orchestrated entrance)
export function reveal(selector) {
  const targets = [...document.querySelectorAll(selector)].filter((el) => !el.classList.contains("reveal"));
  if (!("IntersectionObserver" in window)) return;
  targets.forEach((el, i) => { el.classList.add("reveal"); el.style.setProperty("--i", String(i % 6)); });
  const io = new IntersectionObserver((entries) => entries.forEach((en) => {
    if (en.isIntersecting) { en.target.classList.add("is-in"); io.unobserve(en.target); }
  }), { rootMargin: "0px 0px -8% 0px" });
  targets.forEach((el) => io.observe(el));
}

// ---------------------------------------------------------------- palette
const SITE = [
  { kind: "page", main: "Home", sub: "Hero, simulator, releases, commands", run: () => location.assign("./") },
  { kind: "page", main: "Guide", sub: "How Vexor works, with visuals", run: () => location.assign("guide.html") },
  { kind: "page", main: "Roadmap: V2", sub: "What comes after v1.2", run: () => location.assign("roadmap.html") },
  { kind: "page", main: "Simulator", sub: "Pick a stack and watch it run", run: () => location.assign("./#simulator") },
  { kind: "page", main: "Every command", sub: "The full reference", run: () => location.assign("./#commands") },
];
const items = [...SITE];
export function addPaletteItems(list) { items.push(...list); }

let pal = {}, sel = 0, shown = [], lastFocus = null;
function render() {
  const words = pal.input.value.toLowerCase().split(/\s+/).filter(Boolean);
  shown = items.filter((it) => {
    const hay = `${it.kind} ${it.main} ${it.sub}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  }).slice(0, 40);
  sel = Math.min(sel, Math.max(0, shown.length - 1));
  pal.list.innerHTML = shown.length ? shown.map((it, i) => `
    <li role="option" id="pal-${i}" aria-selected="${i === sel}" data-i="${i}">
      <span class="p-kind">${esc(it.kind)}</span>
      <span class="p-main">${esc(it.main)}<span class="p-sub">${esc(it.sub.slice(0, 140))}</span></span>
    </li>`).join("") : `<li aria-disabled="true"><span class="p-kind">none</span><span class="p-main">No match<span class="p-sub">Try: n8n, test, backup, roadmap</span></span></li>`;
  pal.input.setAttribute("aria-activedescendant", shown.length ? `pal-${sel}` : "");
  pal.list.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
}
function open() { lastFocus = document.activeElement; pal.root.hidden = false; pal.input.value = ""; sel = 0; render(); pal.input.focus(); }
function close() { pal.root.hidden = true; lastFocus?.focus?.(); }
function run(i) { const it = shown[i]; if (!it) return; close(); it.run(); }
function initPalette() {
  pal = { root: document.querySelector("[data-palette]"), input: document.querySelector("[data-palette-input]"), list: document.querySelector("[data-palette-list]") };
  if (!pal.root) return;
  document.querySelectorAll("[data-open-palette]").forEach((b) => b.addEventListener("click", open));
  document.querySelectorAll("[data-palette-close]").forEach((b) => b.addEventListener("click", close));
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); pal.root.hidden ? open() : close(); return; }
    if (pal.root.hidden) return;
    if (e.key === "Escape") { e.preventDefault(); close(); }
    if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(shown.length - 1, sel + 1); render(); }
    if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(0, sel - 1); render(); }
    if (e.key === "Enter") { e.preventDefault(); run(sel); }
    if (e.key === "Tab") { e.preventDefault(); pal.input.focus(); }
  });
  pal.input.addEventListener("input", () => { sel = 0; render(); });
  pal.list.addEventListener("click", (e) => { const li = e.target.closest("[data-i]"); if (li) run(Number(li.dataset.i)); });
}

// commands from VEXOR.md, shared by the palette and the home page reference
let commandsPromise;
export function commands() {
  if (!commandsPromise) {
    commandsPromise = loadCommands().then((groups) => {
      const order = ["Wazuh", "ELK", "n8n", "Suricata", "Zeek"];
      groups.sort((a, b) => (order.indexOf(a.name) + 1 || 99) - (order.indexOf(b.name) + 1 || 99));
      addPaletteItems(groups.flatMap((g) => g.rows.filter((r) => r.copy).map((r) => ({
        kind: g.name, main: r.cmdText, sub: r.desc.replace(/[`*]/g, ""), run: () => copy(r.copy).then(() => toast(`Copied: ${r.copy}`)),
      }))));
      return groups;
    });
  }
  return commandsPromise;
}

export function initCommon() {
  document.querySelectorAll("[data-mod]").forEach((e) => (e.textContent = isMac ? "⌘" : "Ctrl"));
  const here = location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll(".nav__links a[data-page]").forEach((a) => {
    if (a.dataset.page === here) a.setAttribute("aria-current", "page");
  });
  initCopyButtons();
  initPalette();
  commands().catch(() => {});
}
