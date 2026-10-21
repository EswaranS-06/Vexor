// Live data from GitHub: latest tag, CI status, release notes (tag commit messages) and the
// command reference (VEXOR.md on main). Cached per tab for 10 minutes; static fallbacks on failure.
const REPO = "EswaranS-06/Vexor";
const API = `https://api.github.com/repos/${REPO}`;
const RAW = `https://raw.githubusercontent.com/${REPO}/main`;
const TTL = 10 * 60 * 1000;

const esc = (s) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));

export async function fetchCached(url, as = "json") {
  const key = `vexor:${url}`;
  try {
    const hit = JSON.parse(sessionStorage.getItem(key) || "null");
    if (hit && Date.now() - hit.t < TTL) return hit.v;
  } catch { /* storage unavailable */ }
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 8000);
  try {
    const r = await fetch(url, { signal: ctl.signal, headers: as === "json" ? { Accept: "application/vnd.github+json" } : {} });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const v = as === "json" ? await r.json() : await r.text();
    try { sessionStorage.setItem(key, JSON.stringify({ t: Date.now(), v })); } catch { /* quota / private mode */ }
    return v;
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------- inline markdown (escaped first)
export function inlineMd(s) {
  return esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
}

// ---------------------------------------------------------------- releases
const FALLBACK_RELEASES = [
  { tag: "v1.2", date: "2026-10-21", title: "n8n automation; Wazuh, ELK, n8n, Suricata and Zeek commands; CI/CD", items: [
    "n8n replaces Shuffle: `vexor n8n connect` sends alerts from every Wazuh manager, or from Logstash with SOC=elk",
    "Per-stack commands: wazuh, elk, suricata, zeek",
    "Wazuh reads only Suricata alert/anomaly records; doctor detects and repairs the JSON decoder overflow",
    "GitHub Actions: CI and Pages deployment",
  ] },
  { tag: "v1.0", date: "2026-10-20", title: "SOC stack CLI for Wazuh, ELK or both on one Docker host", items: [
    "vexor CLI: install, status, doctor with automatic repairs, updates with rollback, certificates, backups",
    "SOC=wazuh|elk|both and NODE_TYPE=single|multi",
    "Optional tools: Suricata, Zeek, Grafana, Portainer, n8n",
  ] },
];

function parseCommit(msg) {
  const lines = msg.split("\n");
  const title = lines[0].replace(/^Vexor v[\d.]+:\s*/i, "");
  const items = [];
  lines.slice(1).forEach((l) => {
    if (/^- /.test(l)) items.push(l.slice(2).trim());
    else if (/^\s{2,}\S/.test(l) && items.length) items[items.length - 1] += " " + l.trim();
  });
  return { title, items };
}

function verKey(t) { return t.replace(/^v/, "").split(".").map(Number); }
function newer(a, b) {
  const x = verKey(a), y = verKey(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (y[i] || 0) - (x[i] || 0);
  return 0;
}

function renderReleases(box, rel, live) {
  const card = (r, i) => `
    <article class="release${i ? " release--older" : ""}">
      <div class="release__head">
        <span class="release__tag">${esc(r.tag)}</span>
        <span class="release__meta">${esc(r.date)}${i === 0 ? " · latest" : ""}</span>
      </div>
      <p class="release__title">${inlineMd(r.title)}</p>
      <ul>${r.items.map((it) => `<li>${inlineMd(it)}</li>`).join("")}</ul>
      ${r.sha ? `<a href="https://github.com/${REPO}/commit/${esc(r.sha)}">Commit ${esc(r.sha.slice(0, 7))}</a>` : ""}
    </article>`;
  box.innerHTML = rel.map(card).join("") + (live ? "" : `<p class="changes__loading">GitHub could not be reached, so this is the list shipped with the page.</p>`);
}

export async function loadReleases() {
  const box = document.querySelector("[data-changes]");
  try {
    const [tags, commits] = await Promise.all([fetchCached(`${API}/tags?per_page=20`), fetchCached(`${API}/commits?per_page=50`)]);
    const bySha = Object.fromEntries(commits.map((c) => [c.sha, c]));
    const rel = tags
      .filter((t) => /^v\d/.test(t.name))
      .sort((a, b) => newer(a.name, b.name))
      .map((t) => {
        const c = bySha[t.commit.sha];
        const p = c ? parseCommit(c.commit.message) : { title: "", items: [] };
        return { tag: t.name, sha: t.commit.sha, date: c ? c.commit.author.date.slice(0, 10) : "", ...p };
      });
    if (!rel.length) throw new Error("no tags");
    renderReleases(box, rel, true);
    return rel[0].tag;
  } catch {
    renderReleases(box, FALLBACK_RELEASES, false);
    return FALLBACK_RELEASES[0].tag;
  }
}

export async function loadStatus(latestTag) {
  const chip = document.querySelector("[data-live-version]");
  if (!chip) return;
  chip.querySelector("[data-version-text]").textContent = `${latestTag} latest`;
  document.querySelectorAll("[data-foot-version]").forEach((e) => (e.textContent = latestTag));
  const ci = chip.querySelector("[data-ci-text]");
  try {
    const runs = await fetchCached(`${API}/actions/workflows/ci.yml/runs?branch=main&per_page=1`);
    const r = runs.workflow_runs?.[0];
    if (!r) throw new Error("no runs");
    const state = r.status !== "completed" ? "running" : r.conclusion === "success" ? "success" : "failure";
    chip.dataset.ci = state;
    ci.textContent = { success: "CI passing", failure: "CI failing", running: "CI running" }[state];
    chip.href = r.html_url;
  } catch {
    ci.textContent = "CI status unavailable";
  }
}

// ---------------------------------------------------------------- VEXOR.md -> command list
export function parseCommands(md) {
  const groups = [];
  let group = null, header = null, prev = "";
  for (const raw of md.split("\n")) {
    const line = raw.trimEnd();
    const h = /^##\s+(.+)$/.exec(line);
    if (h) { group = { name: h[1].replace(/`/g, ""), rows: [] }; groups.push(group); header = null; prev = line; continue; }
    if (!line.startsWith("|")) { header = null; prev = line; continue; }          // a table ended
    if (/^\|\s*-{3,}/.test(line)) { header = prev; prev = line; continue; }       // the line before is the header
    if (group && header && /^\|\s*Command\s*\|/i.test(header)) {
      const cells = line.split(/(?<!\\)\|/).slice(1, -1).map((c) => c.trim().replace(/\\\|/g, "|"));
      if (cells.length >= 2) {
        const first = /`([^`]+)`/.exec(cells[0]);
        group.rows.push({ cmdMd: cells[0], cmdText: cells[0].replace(/`/g, ""), copy: first ? `vexor ${first[1]}` : "", desc: cells[1] });
      }
    }
    prev = line;
  }
  return groups.filter((g) => g.rows.length);
}

export async function loadCommands() {
  let md;
  try { md = await fetchCached("VEXOR.md", "text"); }              // copy published with the site (same commit)
  catch { md = await fetchCached(`${RAW}/VEXOR.md`, "text"); }      // local preview / older deploys
  const groups = parseCommands(md);
  if (!groups.length) throw new Error("no command tables found");
  return groups;
}
