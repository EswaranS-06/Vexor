// Roadmap page: ROADMAP.md (same-origin copy published with the site, else raw GitHub) rendered as an
// animated V1 → V2 architecture and a filterable phase board.
import { initCommon, esc, reduced, addPaletteItems } from "./common.js";
import { fetchCached, inlineMd } from "./live.js";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const PHASES = ["alpha", "beta", "2.0", "2.x"];
const PHASE_NOTE = { alpha: "foundations", beta: "feature-complete, on test stacks", "2.0": "stable release", "2.x": "after 2.0" };
const PRIORITIES = ["must", "should", "could"];

// ---------------------------------------------------------------- parse ROADMAP.md
export function parseRoadmap(md) {
  const lines = md.replace(/\r/g, "").split("\n");
  const intro = [];
  const items = [];
  let theme = null, cur = null, inIntro = true;
  for (const line of lines) {
    if (/^# /.test(line)) continue;
    const h2 = /^## (.+)$/.exec(line), h3 = /^### (.+)$/.exec(line);
    if (h2) { theme = h2[1].trim(); inIntro = false; cur = null; continue; }
    if (h3) { cur = { title: h3[1].trim(), theme, fields: {} }; items.push(cur); continue; }
    const f = /^- \*\*(\w+):\*\*\s*(.+)$/.exec(line);
    if (f && cur) { cur.fields[f[1].toLowerCase()] = f[2].trim(); continue; }
    if (inIntro && line.trim() && line.trim() !== "---" && !/renders this file live/.test(line)) intro.push(line.trim());
  }
  return { intro, items: items.filter((i) => i.fields.phase) };
}

// ---------------------------------------------------------------- V1 -> V2 architecture (FLIP)
const ARCH = {
  v1: { caption: "Today: every container on one Docker host. The clusters survive a failed container, not a failed host.",
    name: "soc-01 · everything",
    slots: {
      h1: ["vexor (bash)", "nginx", "wazuh.master", "workers", "indexers", "dashboard", "elasticsearch", "logstash", "kibana", "n8n", "suricata", "zeek"],
      h2: [], h3: [] } },
  v2: { caption: "V2: one binary with stack modules, storage and sensors placed on their own hosts, and new optional modules (dashed).",
    name: "soc-01 · control",
    slots: {
      h1: ["vexor (binary)", "nginx", "wazuh.master", "workers", "dashboard", "logstash", "kibana", "n8n", "console", "metrics"],
      h2: ["indexers", "elasticsearch", "snapshots"],
      h3: ["suricata", "zeek", "intel feeds"] } },
};
const NEW_IN_V2 = new Set(["console", "metrics", "snapshots", "intel feeds", "vexor (binary)"]);
const nodeEls = new Map();
function nodeEl(name) {
  if (!nodeEls.has(name)) {
    const el = document.createElement("span");
    el.className = `chip-node${NEW_IN_V2.has(name) ? " chip-node--new" : ""}`;
    el.textContent = name;
    nodeEls.set(name, el);
  }
  return nodeEls.get(name);
}
function setArch(ver, animate = true) {
  const stage = $("[data-arch]");
  const conf = ARCH[ver];
  const first = new Map([...nodeEls].map(([n, el]) => [n, el.isConnected ? el.getBoundingClientRect() : null]));
  stage.dataset.ver = ver;
  $("[data-host-name]").textContent = conf.name;
  const placed = new Set();
  Object.entries(conf.slots).forEach(([slot, names]) => {
    const box = $(`[data-slot="${slot}"]`, stage);
    names.forEach((n) => { box.appendChild(nodeEl(n)); placed.add(n); });
  });
  nodeEls.forEach((el, n) => { if (!placed.has(n)) el.remove(); });
  $("[data-arch-caption]").textContent = conf.caption;
  if (!animate || reduced()) return;
  nodeEls.forEach((el, n) => {
    if (!el.isConnected) return;
    const a = first.get(n), b = el.getBoundingClientRect();
    if (!a) { el.animate([{ opacity: 0, transform: "scale(0.94)" }, { opacity: 1, transform: "none" }], { duration: 420, easing: "cubic-bezier(0.16, 1, 0.3, 1)", delay: 180 }); return; }
    const dx = a.left - b.left, dy = a.top - b.top;
    if (!dx && !dy) return;
    el.animate([{ transform: `translate(${dx}px, ${dy}px)` }, { transform: "none" }], { duration: 560, easing: "cubic-bezier(0.16, 1, 0.3, 1)" });
  });
}
function initArch() {
  setArch("v1", false);
  $$("[data-arch-ver]").forEach((r) => r.addEventListener("change", () => setArch(r.value)));
}

// ---------------------------------------------------------------- board
let ITEMS = [], fPriority = "all", fTheme = "all";
function chip(group, value, label, active) {
  return `<button type="button" class="chip" data-${group}="${esc(value)}" aria-pressed="${value === active}">${esc(label)}</button>`;
}
function renderFilters() {
  const themes = [...new Set(ITEMS.map((i) => i.theme))];
  $("[data-f-priority]").innerHTML = chip("p", "all", "All priorities", fPriority) + PRIORITIES.map((p) => chip("p", p, p, fPriority)).join("");
  $("[data-f-theme]").innerHTML = chip("t", "all", "All themes", fTheme) + themes.map((t) => chip("t", t, t, fTheme)).join("");
}
function renderBoard() {
  const board = $("[data-board]");
  const vis = ITEMS.filter((i) => (fPriority === "all" || i.fields.priority === fPriority) && (fTheme === "all" || i.theme === fTheme));
  board.innerHTML = PHASES.map((ph) => {
    const col = vis.filter((i) => i.fields.phase === ph);
    return `<section class="col" aria-label="Phase ${esc(ph)}">
      <header class="col__head"><span class="phase phase--${ph.replace(".", "")}">${esc(ph)}</span><span class="col__note">${esc(PHASE_NOTE[ph])}</span><span class="col__count">${col.length}</span></header>
      <div class="col__cards">${col.length ? col.map((i, k) => `
        <details class="card" style="--i:${k}">
          <summary>
            <span class="card__title">${inlineMd(i.title)}</span>
            <span class="card__meta"><span class="prio prio--${esc(i.fields.priority)}">${esc(i.fields.priority)}</span><span class="card__theme">${esc(i.theme)}</span></span>
            ${i.fields.fixes ? `<span class="card__fixes">fixes: ${esc(i.fields.fixes)}</span>` : ""}
          </summary>
          <div class="card__body">
            ${i.fields.why ? `<p><span class="lbl">Why</span> ${inlineMd(i.fields.why)}</p>` : ""}
            ${i.fields.what ? `<p><span class="lbl">What</span> ${inlineMd(i.fields.what)}</p>` : ""}
          </div>
        </details>`).join("") : `<p class="col__empty">Nothing in this phase for the current filter.</p>`}</div>
    </section>`;
  }).join("");
}

async function load() {
  const src = $("[data-rm-src]");
  let md, from;
  try { md = await fetchCached("ROADMAP.md", "text"); from = "the copy published with this site"; }
  catch {
    try { md = await fetchCached("https://raw.githubusercontent.com/EswaranS-06/Vexor/main/ROADMAP.md", "text"); from = "GitHub (main)"; }
    catch { src.textContent = "ROADMAP.md could not be loaded. Try again later."; $("[data-board]").innerHTML = ""; return; }
  }
  const { intro, items } = parseRoadmap(md);
  ITEMS = items;
  if (intro.length) $("[data-rm-intro]").innerHTML = intro.map((p) => `<p>${inlineMd(p)}</p>`).join("");
  const counts = PRIORITIES.map((p) => `${items.filter((i) => i.fields.priority === p).length} ${p}`).join(" · ");
  src.innerHTML = `${items.length} items (${esc(counts)}), read from ${esc(from)}. Edit <code>ROADMAP.md</code> and this page follows.`;
  renderFilters();
  renderBoard();
  addPaletteItems(items.map((i) => ({ kind: `V2 ${i.fields.phase}`, main: i.title.replace(/`/g, ""), sub: i.fields.what || "", run: () => { fPriority = "all"; fTheme = "all"; renderFilters(); renderBoard(); const d = $$(".card").find((c) => c.querySelector(".card__title").textContent === i.title.replace(/`/g, "")); if (d) { d.open = true; d.scrollIntoView({ block: "center", behavior: reduced() ? "auto" : "smooth" }); } } })));
  $("[data-filters]").addEventListener("click", (e) => {
    const p = e.target.closest("[data-p]"), t = e.target.closest("[data-t]");
    if (p) fPriority = p.dataset.p;
    if (t) fTheme = t.dataset.t;
    if (p || t) { renderFilters(); renderBoard(); }
  });
}

initCommon();
initArch();
load();
