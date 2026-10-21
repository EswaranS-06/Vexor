import { initCommon, addPaletteItems, commands, copy, toast, esc, reveal } from "./common.js";
import { initHero } from "./hero.js";
import { initSim, runScenario, setSoc, toggleTool } from "./sim.js";
import { loadReleases, loadStatus, inlineMd } from "./live.js";

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
    GROUPS = await commands();
  } catch {
    list.innerHTML = `<p class="cmdref__status">The command list could not be loaded from GitHub. The <a href="guide.html#components">guide</a> lists the main commands per stack.</p>`;
    return;
  }
  renderGroupChips();
  renderCommands();
  document.querySelector("[data-cmd-filter]").addEventListener("input", renderCommands);
  document.querySelector("[data-cmd-groups]").addEventListener("click", (e) => {
    const b = e.target.closest("[data-group]");
    if (!b) return;
    activeGroup = b.dataset.group;
    renderGroupChips(); renderCommands();
  });
}

addPaletteItems([
  { kind: "run", main: "Scenario: network attack", sub: "Suricata → Wazuh → n8n", run: () => runScenario("network") },
  { kind: "run", main: "Scenario: SSH brute force", sub: "agent → rule 5712 → active response", run: () => runScenario("ssh") },
  { kind: "run", main: "Scenario: a container dies", sub: "watchdog + doctor --fix", run: () => runScenario("crash") },
  { kind: "set", main: "SOC=both", sub: "Wazuh + ELK in the simulator", run: () => { setSoc("both"); location.assign("#simulator"); } },
  { kind: "set", main: "Toggle n8n", sub: "N8N=true|false in the simulator", run: () => { toggleTool("n8n"); location.assign("#simulator"); } },
  { kind: "copy", main: "Install command", sub: "git clone … && sudo ./vexor install", run: () => copy(document.getElementById("install-cmd").textContent).then(() => toast("Copied: install command")) },
]);

initCommon();
initHero();
initSim();
reveal(".hero__copy > *, .session, .steps li");
loadReleases().then((tag) => { loadStatus(tag); reveal(".release"); });
initCommands();
