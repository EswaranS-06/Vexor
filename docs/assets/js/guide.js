// Guide page: the README, section by section, with interactive visuals.
import { initCommon, esc, reduced, sleep, reveal } from "./common.js";
import { services, ramGB, hostPorts, hasWazuh, isMulti, TOOLS } from "./stack.js";
import { fetchCached } from "./live.js";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const code = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");

// ---------------------------------------------------------------- content (from README + vexor 1.2)
const COMPONENTS = [
  { id: "wazuh", name: "Wazuh", ver: "4.14", when: "SOC=wazuh or both",
    role: "Agents on your endpoints, detection rules, alerts and active response. Single node, or a master with 1–3 workers and three indexers.",
    setup: ["Passwords, cluster key and every internal certificate generated", "OpenSearch demo users (public passwords) removed before the first start", "Dashboard on `8080` through nginx; agent traffic balanced over the managers", "Index retention by `INDEX_RETENTION_DAYS` (ISM)"],
    cmds: [["vexor wazuh", "indexer and manager cluster, API"], ["vexor wazuh alerts --level 10", "newest alerts of every manager"], ["vexor wazuh logtest", "test a log line against the rules"], ["vexor agents enroll-cmd windows --name pc-01", "install command for an endpoint"], ["vexor node-type multi", "master + workers + 3 indexers"]] },
  { id: "elk", name: "ELK", ver: "9.5", when: "SOC=elk or both",
    role: "Elasticsearch stores and searches everything, Kibana shows it, Logstash takes in Beats, Elastic Agent, sensor logs and (with SOC=both) every Wazuh alert.",
    setup: ["Elastic passwords generated", "`vexor_logstash`: a user that can only write `vexor-*`", "ILM retention by `ELK_RETENTION_DAYS`, 0 replicas on one node", "Kibana data views: Wazuh alerts, Suricata, Zeek, Beats", "Kibana on `55601` through nginx; Elasticsearch on `127.0.0.1:59200` only"],
    cmds: [["vexor soc both", "turn ELK on next to Wazuh"], ["vexor elk", "health, Kibana, events in the last hour"], ["vexor elk search 'rule.level:>=10' -n 20", "Lucene search across vexor-*"], ["vexor elk indices", "index sizes"], ["vexor elk beats-config", "filebeat.yml for other machines"]] },
  { id: "n8n", name: "n8n", ver: "2.40", when: "N8N=true",
    role: "The response engine. Receives alerts above the level you choose and runs your playbooks: notify, open a ticket, isolate a host through the Wazuh API, query Elasticsearch.",
    setup: ["`custom-n8n` integration installed on every manager (agents are balanced, so each manager sends its own alerts)", "With SOC=elk, Logstash forwards Suricata alerts and Zeek notices instead", "Every call carries `X-Vexor-Token`; the starter workflow drops anything without it", "`vexor-n8n` (Wazuh API: agent actions, active response) and `vexor_n8n` (read `vexor-*`)"],
    cmds: [["vexor n8n enable", "start n8n behind nginx on 55678"], ["vexor n8n connect --level 10", "forward alerts of level 10 and up"], ["vexor n8n workflow", "import + publish the starter workflow"], ["vexor n8n credentials", "least-privilege users for HTTP Request nodes"], ["vexor n8n test", "runs the real integration script with a test alert"]] },
  { id: "suricata", name: "Suricata", ver: "8.0", when: "SURICATA=true",
    role: "Network IDS on the host network. Inspects traffic on SNIFF_INTERFACE with the ET Open rules; alerts go to Wazuh, Elasticsearch and n8n.",
    setup: ["ET Open rules (53,000+) downloaded, ownership fixed, refreshed daily with a hot reload", "Wazuh reads only alert and anomaly records: stats records overflow its JSON decoder", "High severity becomes level 10, medium level 7 (rules 100720/100721)", "`eve.json` rotated daily, kept `TOOLS_LOG_RETENTION_DAYS`"],
    cmds: [["vexor suricata enable", "turn it on"], ["vexor suricata", "signatures, alerts in 24 h, top signatures"], ["vexor suricata alerts --since 1h", "newest alerts"], ["vexor suricata test", "real test traffic, checked hop by hop"], ["vexor suricata update-rules", "download + hot-reload rules"]] },
  { id: "zeek", name: "Zeek", ver: "8.2", when: "ZEEK=true",
    role: "Network logs: connections, DNS, HTTP, TLS, SSH. Notices and failed SSH logins become Wazuh alerts; everything is searchable in Elasticsearch.",
    setup: ["JSON logs, rotated hourly into `tools-data/zeek/logs`", "Wazuh reads `ZEEK_WAZUH_LOGS` (notice, weird, dns, http, ssl, ssh)", "Notices become level 6, failed SSH logins level 5", "Logstash ships every log to `vexor-zeek-*`"],
    cmds: [["vexor zeek enable", "turn it on"], ["vexor zeek", "current logs, size, who reads them"], ["vexor zeek show dns -n 20", "readable lines of one log"], ["vexor zeek top hosts", "top talkers (also ports, dns)"], ["vexor zeek test", "check a request lands in http.log"]] },
  { id: "tools", name: "Grafana · Portainer", ver: "13.0 · 2.45", when: "GRAFANA=true, PORTAINER=true",
    role: "A ready-made Wazuh alerts dashboard, and container management for the whole host.",
    setup: ["Grafana: OpenSearch datasource with a read-only indexer user limited to the Wazuh indices", "Grafana: a \"Wazuh alerts overview\" dashboard", "Portainer: admin password preset from `PORTAINER_ADMIN_PASSWORD`", "Both only through nginx, on `53000` and `59443`"],
    cmds: [["vexor tools enable grafana", "start Grafana"], ["vexor tools enable portainer", "start Portainer"], ["vexor tools", "every tool: enabled, state, URL"]] },
];

const FLOWS = [
  { id: "endpoint", name: "Endpoint events", caption: "Every Wazuh alert takes this path.",
    hops: [["agent", "event on pc-01"], ["nginx :1514", "balanced over managers"], ["manager", "decoders + rules"], ["alert", "level, groups, MITRE"], ["filebeat", "TLS to the indexer"], ["wazuh-alerts-*", "searchable in the dashboard"]] },
  { id: "network", name: "Network alerts", caption: "Only alert and anomaly records reach Wazuh, so its JSON decoder never chokes on stats.",
    hops: [["traffic", "on SNIFF_INTERFACE"], ["suricata", "ET Open match"], ["eve.json", "alert + anomaly records"], ["wazuh.master", "rule 100720 / 100721"], ["indexer", "alert stored"]] },
  { id: "logs", name: "Network logs", caption: "Zeek logs feed both stacks: alerts in Wazuh, every record in Elasticsearch.",
    hops: [["traffic", "on SNIFF_INTERFACE"], ["zeek", "conn, dns, http, ssl, ssh"], ["JSON logs", "rotated hourly"], ["wazuh.master", "rules 100700–100703"], ["logstash", "→ vexor-zeek-*"]] },
  { id: "wazuh-elk", name: "Wazuh → ELK", caption: "SOC=both: the same alerts in the Wazuh dashboard and in Kibana.",
    hops: [["managers", "alerts.json"], ["logstash", "tails each manager"], ["elasticsearch", "vexor-wazuh-alerts-*"], ["kibana", "data view: Vexor - Wazuh alerts"]] },
  { id: "to-n8n", name: "Alerts → n8n", caption: "Only alerts at or above N8N_ALERT_LEVEL are sent; each call carries the token.",
    hops: [["manager", "alert level ≥ 7"], ["custom-n8n", "on every manager"], ["POST webhook", "http://n8n:5678/webhook/vexor-alerts"], ["token check", "X-Vexor-Token"], ["severity route", "critical · high · medium · low"]] },
  { id: "from-n8n", name: "n8n → stack", caption: "Workflows act through least-privilege users, never as admin.",
    hops: [["workflow", "high severity branch"], ["Wazuh API", "user vexor-n8n"], ["active response", "firewall-drop"], ["agent", "blocks the source IP"]] },
];

const CHANGES = [
  { what: "Ports, heap sizes, log rotation, images", cmd: "vexor config apply", down: "only the changed containers" },
  { what: "SOC (wazuh · elk · both)", cmd: "vexor soc both", down: "1–3 min on ELK's first start", note: "Switching to elk stops Wazuh; its agent keys and alerts stay in their volumes." },
  { what: "NODE_TYPE or WORKER_COUNT", cmd: "vexor node-type multi\nvexor scale 2", down: "about 1–2 min", note: "Shards move first; `--dry-run` shows the plan." },
  { what: "A tool flag, SNIFF_INTERFACE, ZEEK_WAZUH_LOGS", cmd: "vexor tools apply", down: "the master is recreated when sensor sources change" },
  { what: "N8N_ALERT_LEVEL, N8N_ALERT_GROUPS, webhook path", cmd: "vexor n8n connect vexor-alerts --level 10", down: "managers recreated, about 30 s" },
  { what: "Any password", cmd: "vexor passwd admin\nvexor elk reset-password", down: "the containers that use it", warn: "Editing the password in .env alone breaks logins." },
  { what: "WAZUH_VERSION", cmd: "vexor update apply 4.14.8", down: "a few minutes", note: "Pulls first, backs up, records a rollback point; `vexor update rollback` goes back." },
  { what: "PUBLIC_HOST or certificate names", cmd: "vexor cert create", down: "nginx, seconds" },
  { what: "BACKUP_TIME, MAINT_TIME, HEALTH_INTERVAL", cmd: "vexor daemon install", down: "none" },
  { what: "config/wazuh_cluster/*.conf (ossec.conf)", cmd: "vexor restart managers", down: "managers are recreated", warn: "Edit every manager file, not only the master's." },
  { what: "config/nginx/nginx.conf.tpl", cmd: "vexor config apply", down: "none (reload)", note: "`nginx.conf` itself is generated; edit the template." },
];

const RETENTION = [
  { what: "Wazuh alerts", key: "INDEX_RETENTION_DAYS", days: 90, how: "ISM policy" },
  { what: "ELK events", key: "ELK_RETENTION_DAYS", days: 30, how: "ILM policy" },
  { what: "Manager logs", key: "MANAGER_LOG_RETENTION_DAYS", days: 30, how: "maintenance prune" },
  { what: "Backups + snapshots", key: "SNAPSHOT_RETENTION_DAYS", days: 14, how: "pruned after each backup" },
  { what: "Suricata + Zeek logs", key: "TOOLS_LOG_RETENTION_DAYS", days: 7, how: "maintenance prune" },
];

const REPAIRS = [
  ["Demo indexer users with public default passwords (readall/readall …)", "Removes them and pushes the security config"],
  ["Suricata stats records flooding Wazuh: Too many fields for JSON decoder", "Wazuh reads only alert and anomaly records; master recreated"],
  ["Suricata runs with 0 signatures", "Downloads the rules, fixes ownership, hot-reloads"],
  ["n8n integration script missing on a manager (new worker, reset volume)", "Installs it, recreates that manager"],
  ["n8n webhook not registered (workflow not published)", "Warns: vexor n8n workflow"],
  ["An integration target keeps failing", "Warns with the count of failed deliveries"],
  ["A manager runs an older ossec.conf than config/", "Recreates it"],
  ["Empty .env value followed by a comment; a key defined twice", "Moves the comment; comments out the earlier key"],
  ["Image download fails on a network or TLS error", "Retries with back-off"],
  ["Elasticsearch yellow on one node, read-only blocks, ILM missing", "Replicas 0, clears the block, applies ILM"],
  ["kibana_system or the Logstash writer cannot log in", "Resets the user or role"],
  ["nginx out of date, http:// on an HTTPS port", "Re-renders and reloads nginx"],
  ["Container stopped or exited", "Watchdog starts it within 5 minutes"],
  ["Wazuh indices read-only (disk flood stage)", "Clears the block once there is room"],
];

const EXPOSURE = [
  { who: "Endpoints", tone: "ok", ports: [["1514/tcp", "agent events"], ["1515/tcp", "enrollment"], ["514/udp", "syslog"]] },
  { who: "Administrators", tone: "accent", ports: [["8080", "Wazuh dashboard"], ["55601", "Kibana"], ["55678", "n8n"], ["53000", "Grafana"], ["59443", "Portainer"]] },
  { who: "Restricted", tone: "warn", ports: [["55000", "Wazuh API"], ["55044", "Beats input (no TLS)"]] },
  { who: "This host only", tone: "muted", ports: [["127.0.0.1:9200", "Wazuh indexer"], ["127.0.0.1:59200", "Elasticsearch"]] },
];

const TREE = [
  { p: "vexor", d: "The CLI: one bash script that installs, runs, checks and repairs the whole stack. See the command reference." },
  { p: ".env.example", d: "Every setting with its default. `vexor install` copies it to `.env` and fills in the passwords." },
  { p: "docker-compose.yml", d: "Wazuh managers, indexers, dashboard and nginx. Compose profiles select single or multi." },
  { p: "docker-compose.elk.yml", d: "Elasticsearch, Logstash and Kibana. Generated by vexor; CI checks it matches." },
  { p: "docker-compose.tools.yml", d: "n8n, Suricata, Zeek, Grafana and Portainer. Generated by vexor; CI checks it matches." },
  { p: "generate-indexer-certs.yml", d: "One-shot container that issues the internal certificates." },
  { p: "config/", d: "Configuration mounted into the containers.", kids: [
    { p: "certs.yml", d: "Which nodes get internal certificates." },
    { p: "wazuh_cluster/", d: "`ossec.conf` for the master and each worker. Edit every file, then `vexor restart managers`." },
    { p: "wazuh_indexer/", d: "OpenSearch settings per node, and the internal users (demo users removed)." },
    { p: "wazuh_dashboard/", d: "Dashboard settings and its Wazuh API connection." },
    { p: "nginx/nginx.conf.tpl", d: "The template `nginx.conf` is rendered from: TLS, the agent balancer, tool servers." },
  ] },
  { p: "docs/", d: "This site: plain HTML, CSS and JavaScript modules, published by the Pages workflow." },
  { p: ".github/workflows/", d: "`ci.yml` (checks on every push) and `pages.yml` (publishes docs/)." },
  { p: ".gitleaks.toml", d: "Secret-scan settings used by CI." },
  { p: "README.md · VEXOR.md · LICENSE", d: "Overview, command reference and license. The home page reads VEXOR.md live for its command list." },
  { p: "created at run time", d: "Ignored by git: `.env`, `.state/`, `backups/`, `reports/`, `tools-data/`, certificates, `config/tools/`, `config/elk/`, `docker-compose.override.yml`, `nginx.conf`.", ghost: true },
];

const LIMITS = [
  "Everything runs on one host; the clusters protect against a failed container, not a failed host.",
  "Up to three workers are predefined.",
  "Wazuh 5.x uses a different deployment layout and is not covered by vexor update apply.",
  "Elasticsearch runs as one node and is not yet in vexor backup.",
  "The Logstash Beats input has no TLS; use it on a trusted network.",
];

// ---------------------------------------------------------------- 1 explorer + 6 tabs
function initExplorer() {
  const list = $("[data-explorer-list]"), pane = $("[data-explorer-pane]");
  list.innerHTML = COMPONENTS.map((c, i) => `<button type="button" role="tab" id="ex-${c.id}" aria-selected="${i === 0}" tabindex="${i ? -1 : 0}" data-i="${i}"><span class="ex-name">${esc(c.name)}</span><span class="ex-ver">${esc(c.ver)}</span></button>`).join("");
  const show = (i) => {
    const c = COMPONENTS[i];
    $$("[role=tab]", list).forEach((b, k) => { b.setAttribute("aria-selected", String(k === i)); b.tabIndex = k === i ? 0 : -1; });
    pane.setAttribute("aria-labelledby", `ex-${c.id}`);
    pane.innerHTML = `<div class="ex-pane is-in-anim"><p class="ex-role">${esc(c.role)}</p>
      <p class="ex-when"><span class="lbl">Runs when</span> <code>${esc(c.when)}</code></p>
      <ul class="ex-cmds">${c.cmds.slice(0, 3).map(([k, d]) => `<li><code>${esc(k)}</code><span>${esc(d)}</span></li>`).join("")}</ul>
      <a class="link-arrow" href="#components" data-goto-comp="${i}">What Vexor sets up for ${esc(c.name)}</a></div>`;
  };
  list.addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (b) show(Number(b.dataset.i)); });
  list.addEventListener("keydown", (e) => arrowNav(e, list, (i) => show(i)));
  pane.addEventListener("click", (e) => { const a = e.target.closest("[data-goto-comp]"); if (a) showComp(Number(a.dataset.gotoComp)); });
  show(0);
}
function arrowNav(e, list, cb) {
  if (!["ArrowDown", "ArrowUp", "ArrowRight", "ArrowLeft"].includes(e.key)) return;
  const tabs = $$("[role=tab]", list), cur = tabs.indexOf(document.activeElement);
  if (cur < 0) return;
  e.preventDefault();
  const n = (cur + (e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length;
  tabs[n].focus(); cb(n);
}

const N8N_FLOW_SVG = `<svg class="wf" viewBox="0 0 640 170" role="img" aria-label="Starter workflow: webhook, token check, severity switch, four branches">
  <g class="wf-n"><rect x="6" y="64" width="120" height="40" rx="6"/><text x="66" y="88">Webhook</text></g>
  <g class="wf-n"><rect x="166" y="64" width="150" height="40" rx="6"/><text x="241" y="88">Token + normalise</text></g>
  <g class="wf-n"><rect x="356" y="64" width="110" height="40" rx="6"/><text x="411" y="88">Severity</text></g>
  ${["critical", "high", "medium", "low"].map((s, i) => `<g class="wf-n wf-n--out"><rect x="506" y="${8 + i * 40}" width="128" height="32" rx="6"/><text x="570" y="${29 + i * 40}">${s}</text></g>`).join("")}
  <path class="wf-e" d="M126,84 L166,84"/><path class="wf-e" d="M316,84 L356,84"/>
  ${[0, 1, 2, 3].map((i) => `<path class="wf-e" d="M466,84 C486,84 486,${24 + i * 40} 506,${24 + i * 40}"/>`).join("")}
  <circle class="wf-dot" r="5"><animateMotion dur="3.2s" repeatCount="3" fill="freeze" keyPoints="0;1" keyTimes="0;1" path="M66,84 L241,84 L411,84 C486,84 486,64 570,64"/></circle>
</svg>`;

let showComp = () => {};
function initCompTabs() {
  const list = $("[data-ctabs-list]"), pane = $("[data-ctabs-pane]");
  list.innerHTML = COMPONENTS.map((c, i) => `<button type="button" role="tab" id="ct-${c.id}" aria-selected="${i === 0}" tabindex="${i ? -1 : 0}" data-i="${i}">${esc(c.name)}</button>`).join("");
  showComp = (i, scroll = true) => {
    const c = COMPONENTS[i];
    $$("[role=tab]", list).forEach((b, k) => { b.setAttribute("aria-selected", String(k === i)); b.tabIndex = k === i ? 0 : -1; });
    pane.setAttribute("aria-labelledby", `ct-${c.id}`);
    pane.innerHTML = `<div class="ct-grid is-in-anim">
      <div><h3>What Vexor sets up</h3><ul class="checks">${c.setup.map((s) => `<li>${code(s)}</li>`).join("")}</ul>
        ${c.id === "n8n" ? `<h3 class="sub-h">The starter workflow</h3>${reduced() ? N8N_FLOW_SVG.replace(/<circle class="wf-dot"[\s\S]*?<\/circle>/, "") : N8N_FLOW_SVG}` : ""}</div>
      <div><h3>Commands</h3><ul class="cmd-list">${c.cmds.map(([k, d]) => `<li><div><code>${esc(k)}</code><span>${esc(d)}</span></div><button type="button" class="copy-mini" data-copy="${esc(k)}" aria-label="Copy ${esc(k)}">Copy</button></li>`).join("")}</ul></div>
    </div>`;
    if (scroll) $("#components").scrollIntoView({ behavior: reduced() ? "auto" : "smooth" });
  };
  list.addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (b) showComp(Number(b.dataset.i), false); });
  list.addEventListener("keydown", (e) => arrowNav(e, list, (i) => showComp(i, false)));
  showComp(0, false);
}

// ---------------------------------------------------------------- 2 requirements calculator
const RAM_SCALE = 32;
function initCalc() {
  const form = $("[data-calc-form]");
  const read = () => { const f = new FormData(form); return { soc: f.get("soc"), node: f.get("node"), workers: 1, tools: TOOLS.filter((t) => f.get(t) === "on") }; };
  const draw = () => {
    const c = read();
    $("[data-needs-wazuh]", form).disabled = !hasWazuh(c);
    const parts = [];
    if (c.soc !== "elk") parts.push(["Wazuh", isMulti(c) ? 16 : 8, "wz"]);
    if (c.soc === "elk") parts.push(["ELK", 6, "elk"]); else if (c.soc === "both") parts.push(["ELK", 4, "elk"]);
    const tr = { n8n: 0.5, grafana: 0.3, portainer: 0.3, suricata: 1, zeek: 1 };
    c.tools.forEach((t) => parts.push([t, tr[t], "tool"]));
    const total = ramGB(c);
    $("[data-calc-ram]").textContent = `${Number.isInteger(total) ? total : total.toFixed(1)} GB`;
    let x = 0;
    $("[data-ram-bar]").innerHTML = parts.map(([n, v, k]) => {
      const seg = `<span class="ram-seg ram-seg--${k}" style="--x:${(x / RAM_SCALE) * 100}%;--w:${v / RAM_SCALE}" title="${esc(n)} ${v} GB"></span>`;
      x += v; return seg;
    }).join("") + [8, 16, 24, 32].map((g) => `<i class="ram-tick" style="--x:${(g / RAM_SCALE) * 100}%"><b>${g}</b></i>`).join("");
    $("[data-ram-legend]").innerHTML = parts.map(([n, v, k]) => `<li><i class="ram-key ram-seg--${k}"></i>${esc(n)} <span>${v} GB</span></li>`).join("");
    $("[data-calc-ports]").innerHTML = hostPorts(c).map((p) => `<code>${esc(p)}</code>`).join(" ");
  };
  form.addEventListener("change", draw);
  draw();
}

// ---------------------------------------------------------------- 4 layout matrix
function initMatrix() {
  const grid = $("[data-matrix-grid]");
  const socs = ["wazuh", "elk", "both"], nodes = ["single", "multi"];
  grid.innerHTML = `<div class="mx-corner"></div>${nodes.map((n) => `<div class="mx-h" role="columnheader">NODE_TYPE=${n}</div>`).join("")}` +
    socs.map((s) => `<div class="mx-h mx-h--row" role="rowheader">SOC=${s}</div>${nodes.map((n) => {
      const na = s === "elk" && n === "multi";
      return `<button type="button" class="mx-cell${na ? " mx-cell--na" : ""}" data-soc="${s}" data-node="${n}" aria-pressed="false">${na ? "same as single" : `${services({ soc: s, node: n, workers: 1, tools: [] }).length} containers`}</button>`;
    }).join("")}`).join("");
  let prev = new Set();
  const show = (s, n) => {
    $$(".mx-cell", grid).forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.soc === s && b.dataset.node === n)));
    const c = { soc: s, node: s === "elk" ? "single" : n, workers: 1, tools: [] };
    const svc = services(c);
    $("[data-matrix-pills]").innerHTML = svc.map((x, i) => `<li class="${prev.size && !prev.has(x) ? "pill-new" : ""}" style="--i:${i}">${esc(x)}</li>`).join("");
    prev = new Set(svc);
    const cmds = [s !== "wazuh" ? `vexor soc ${s}` : "", c.node === "multi" ? "vexor node-type multi" : ""].filter(Boolean);
    $("[data-matrix-cmd]").innerHTML = cmds.length ? `<span class="lbl">Switch with</span> <code>${esc(cmds.join(" && "))}</code>` : `<span class="lbl">Default</span> <code>vexor install</code>`;
    $("[data-matrix-note]").textContent = s === "elk"
      ? "SOC=elk stops Wazuh; NODE_TYPE applies to Wazuh only. Agent keys and alerts stay in the Wazuh volumes."
      : `About ${ramGB(c)} GB RAM before tools. ${c.node === "multi" ? "Workers analyse events; three indexers keep a replica of every shard." : "One manager and one indexer."}`;
  };
  grid.addEventListener("click", (e) => { const b = e.target.closest(".mx-cell"); if (b) show(b.dataset.soc, b.dataset.node); });
  show("wazuh", "single");
}

// ---------------------------------------------------------------- 5 flow explorer
let flowToken = 0;
async function playFlow(i) {
  const f = FLOWS[i], my = ++flowToken;
  $$("[data-flows-picker] [role=tab]").forEach((b, k) => { b.setAttribute("aria-selected", String(k === i)); b.tabIndex = k === i ? 0 : -1; });
  const pipe = $("[data-pipe]");
  pipe.innerHTML = f.hops.map(([n, d]) => `<li class="hop"><span class="hop__n">${esc(n)}</span><span class="hop__d">${esc(d)}</span></li>`).join("");
  $("[data-flows-caption]").textContent = f.caption;
  const hops = $$(".hop", pipe);
  for (let k = 0; k < hops.length; k++) {
    if (my !== flowToken) return;
    hops[k].classList.add("is-on");
    await sleep(reduced() ? 60 : 520);
  }
}
function initFlows() {
  const picker = $("[data-flows-picker]");
  picker.innerHTML = FLOWS.map((f, i) => `<button type="button" role="tab" aria-selected="${i === 0}" tabindex="${i ? -1 : 0}" data-i="${i}">${esc(f.name)}</button>`).join("");
  picker.addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (b) playFlow(Number(b.dataset.i)); });
  picker.addEventListener("keydown", (e) => arrowNav(e, picker, playFlow));
  $("[data-flows-replay]").addEventListener("click", () => playFlow(Math.max(0, $$("[role=tab]", picker).findIndex((b) => b.getAttribute("aria-selected") === "true"))));
  let started = false;
  new IntersectionObserver((en, io) => { if (en[0].isIntersecting && !started) { started = true; playFlow(0); io.disconnect(); } }, { threshold: 0.35 }).observe($("[data-flows]"));
}

// ---------------------------------------------------------------- 7 change picker
function initChanger() {
  const sel = $("[data-changer-select]"), out = $("[data-changer-out]");
  sel.innerHTML = CHANGES.map((c, i) => `<option value="${i}">${esc(c.what)}</option>`).join("");
  const show = () => {
    const c = CHANGES[Number(sel.value)];
    const steps = ["vexor config validate", c.cmd, "vexor doctor"];
    out.innerHTML = `<ol class="chg-steps is-in-anim">${steps.map((s) => `<li><pre class="cmd"><code>${esc(s)}</code></pre><button type="button" class="copy-mini" data-copy="${esc(s)}" aria-label="Copy">Copy</button></li>`).join("")}</ol>
      <p class="chg-meta"><span class="lbl">Restarts</span> ${esc(c.down)}</p>
      ${c.warn ? `<p class="chg-warn">${code(c.warn)}</p>` : ""}${c.note ? `<p class="chg-note">${code(c.note)}</p>` : ""}`;
  };
  sel.addEventListener("change", show);
  show();
}

// ---------------------------------------------------------------- 8 retention
function initRetention() {
  const max = 90;
  $("[data-retention]").innerHTML = RETENTION.map((r) => `
    <div class="ret-row"><div class="ret-what"><span>${esc(r.what)}</span><code>${esc(r.key)}</code></div>
      <div class="ret-bar"><span style="--w:${r.days / max}"></span></div>
      <div class="ret-days">${r.days} d <small>${esc(r.how)}</small></div></div>`).join("") +
    `<div class="ret-row"><div class="ret-what"><span>Container logs</span><code>LOG_MAX_SIZE × LOG_MAX_FILE</code></div>
      <div class="ret-bar ret-bar--size"><span style="--w:0.18"></span></div><div class="ret-days">50 MB × 5 <small>per container</small></div></div>`;
  const box = $("[data-retention]");
  if (reduced()) { box.classList.add("is-on"); return; }
  new IntersectionObserver((en, io) => { if (en[0].isIntersecting) { box.classList.add("is-on"); io.disconnect(); } }, { threshold: 0.4 }).observe(box);
}

// ---------------------------------------------------------------- 9 a day of timers
const DAY_EVENTS = [
  [0.08, "watch", "watchdog", "every enabled container is running"],
  [1, "health", "health", "doctor --fix: 52 passed, 0 failed"],
  [1.5, "backup", "backup", "indexer snapshot, master state, n8n/Grafana/Portainer volumes, config"],
  [2, "health", "health", "doctor --fix: 0 failed"],
  [2.25, "maint", "maintenance", "logs pruned, retention applied, certificates checked, Suricata rules updated, sensor logs rotated"],
  [3.33, "watch", "watchdog", "zeek not running → docker compose up -d zeek (example)"],
  [4, "health", "health", "doctor --fix: zeek writes logs again, 0 failed"],
  [13, "health", "health", "still hourly; nothing to report"],
  [23, "health", "health", "doctor --fix: 0 failed, saved to .state/health.last"],
];
function initDay() {
  const track = $("[data-day-track]"), cursor = $("[data-day-cursor]"), log = $("[data-day-log]"), btn = $("[data-day-play]");
  const ticks = [];
  for (let m = 0; m < 1440; m += 5) ticks.push(`<i class="t t--watch" style="--x:${(m / 1440) * 100}%"></i>`);
  for (let h = 0; h < 24; h++) ticks.push(`<i class="t t--health" style="--x:${(h / 24) * 100}%"></i>`);
  ticks.push(`<i class="t t--backup" style="--x:${(1.5 / 24) * 100}%"></i>`, `<i class="t t--maint" style="--x:${(2.25 / 24) * 100}%"></i>`);
  track.insertAdjacentHTML("afterbegin", ticks.join(""));
  const fmt = (h) => `${String(Math.floor(h)).padStart(2, "0")}:${String(Math.round((h % 1) * 60)).padStart(2, "0")}`;
  const add = (e) => {
    const li = document.createElement("li");
    li.className = `ev ev--${e[1]}`;
    li.innerHTML = `<time>${fmt(e[0])}</time><span><b>${esc(e[2])}</b> ${esc(e[3])}</span>`;
    log.appendChild(li);
  };
  let playing = false;
  btn.addEventListener("click", async () => {
    if (playing) return;
    playing = true; btn.disabled = true; log.innerHTML = "";
    if (reduced()) { DAY_EVENTS.forEach(add); cursor.style.transform = `translateX(${track.clientWidth}px)`; playing = false; btn.disabled = false; return; }
    const dur = 9000, t0 = performance.now();
    let next = 0;
    await new Promise((done) => {
      const step = (now) => {
        const k = Math.min(1, (now - t0) / dur), hour = k * 24;
        cursor.style.transform = `translateX(${k * track.clientWidth}px)`;
        while (next < DAY_EVENTS.length && DAY_EVENTS[next][0] <= hour) add(DAY_EVENTS[next++]);
        if (k < 1) requestAnimationFrame(step); else done();
      };
      requestAnimationFrame(step);
    });
    playing = false; btn.disabled = false; btn.textContent = "Play again";
  });
}

function initRepairs() {
  const body = $("[data-repairs]"), input = $("[data-repairs-filter]");
  const draw = () => {
    const q = input.value.trim().toLowerCase();
    const rows = REPAIRS.filter(([p, r]) => !q || `${p} ${r}`.toLowerCase().includes(q));
    body.innerHTML = rows.length ? rows.map(([p, r]) => `<tr><td>${esc(p)}</td><td>${esc(r)}</td></tr>`).join("") : `<tr><td colspan="2" class="empty">Nothing matches. Run <code>vexor doctor</code>: problems without a repair come with a hint.</td></tr>`;
  };
  input.addEventListener("input", draw);
  draw();
}

// ---------------------------------------------------------------- 10 exposure
function initExposure() {
  $("[data-exposure]").innerHTML = EXPOSURE.map((g) => `
    <div class="exp exp--${g.tone}"><p class="exp__who">${esc(g.who)}</p>
      <ul>${g.ports.map(([p, d]) => `<li><code>${esc(p)}</code><span>${esc(d)}</span></li>`).join("")}</ul></div>`).join("");
}

// ---------------------------------------------------------------- 11 live pipeline
async function initPipeline() {
  const box = $("[data-pipeline]"), note = $("[data-pipeline-note]");
  const API = "https://api.github.com/repos/EswaranS-06/Vexor";
  const st = (r) => (r.status !== "completed" ? "run" : r.conclusion === "success" ? "ok" : r.conclusion === "skipped" ? "skip" : "bad");
  const label = { ok: "passed", bad: "failed", run: "running", skip: "skipped", wait: "…" };
  try {
    const runs = (await fetchCached(`${API}/actions/runs?branch=main&per_page=10`)).workflow_runs || [];
    const ci = runs.find((r) => r.name === "CI");
    if (!ci) throw new Error("no CI run");
    const pages = runs.find((r) => r.name === "Pages" && r.head_sha === ci.head_sha) || runs.find((r) => r.name === "Pages");
    const jobs = (await fetchCached(`${API}/actions/runs/${ci.id}/jobs`)).jobs || [];
    const commitTitle = (ci.head_commit?.message || "").split("\n")[0];
    box.innerHTML = `
      <li class="pl-step is-ok"><span class="pl-name">push ${esc(ci.head_sha.slice(0, 7))}</span><span class="pl-st">${esc(commitTitle.slice(0, 60))}</span></li>
      <li class="pl-step pl-step--group is-${st(ci)}"><span class="pl-name"><a href="${esc(ci.html_url)}">CI</a></span>
        <ul class="pl-jobs">${jobs.map((j) => `<li class="is-${st(j)}"><span>${esc(j.name)}</span><b>${label[st(j)]}</b></li>`).join("")}</ul></li>
      ${pages ? `<li class="pl-step is-${st(pages)}"><span class="pl-name"><a href="${esc(pages.html_url)}">Pages</a></span><span class="pl-st">${label[st(pages)]}${pages.head_sha !== ci.head_sha ? " (last docs change)" : ""}</span></li>` : ""}
      <li class="pl-step is-ok"><span class="pl-name"><a href="./">this site</a></span><span class="pl-st">live</span></li>`;
    note.textContent = `Read from the GitHub API just now; run started ${new Date(ci.created_at).toLocaleString()}.`;
  } catch {
    box.innerHTML = `<li class="pl-step"><span class="pl-name">push</span><span class="pl-st">bash -n · ShellCheck · compose per SOC · drift · gitleaks</span></li><li class="pl-step"><span class="pl-name">Pages</span><span class="pl-st">publishes docs/</span></li>`;
    note.textContent = "GitHub could not be reached, so this shows the pipeline's shape without live status.";
  }
}

// ---------------------------------------------------------------- 12 repo tree
function initTree() {
  const list = $("[data-tree-list]"), info = $("[data-tree-info]");
  const flat = [];
  const item = (n, depth) => {
    const i = flat.push(n) - 1;
    return `<li role="treeitem" aria-level="${depth}"${n.kids ? ' aria-expanded="true"' : ""}><button type="button" class="tr-btn${n.ghost ? " tr-btn--ghost" : ""}${n.kids ? " tr-btn--dir" : ""}" data-i="${i}">${esc(n.p)}</button>${n.kids ? `<ul role="group">${n.kids.map((k) => item(k, depth + 1)).join("")}</ul>` : ""}</li>`;
  };
  list.innerHTML = TREE.map((n) => item(n, 1)).join("");
  const show = (i) => {
    $$(".tr-btn", list).forEach((b) => b.classList.toggle("is-sel", Number(b.dataset.i) === i));
    const n = flat[i];
    info.innerHTML = `<p class="tr-path"><code>${esc(n.p)}</code></p><p>${code(n.d)}</p>${n.ghost ? '<p class="chg-note">Not in the repository.</p>' : ""}`;
  };
  list.addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (b) show(Number(b.dataset.i)); });
  show(0);
}

function initLimits() {
  $("[data-limits]").innerHTML = LIMITS.map((l) => `<li><span class="lim-now">${esc(l)}</span></li>`).join("");
}

// ---------------------------------------------------------------- table of contents
function initToc() {
  const links = $$("[data-toc] a"), bar = $("[data-toc-progress]");
  const secs = links.map((a) => document.getElementById(a.getAttribute("href").slice(1)));
  const io = new IntersectionObserver((entries) => entries.forEach((en) => {
    if (!en.isIntersecting) return;
    const i = secs.indexOf(en.target);
    links.forEach((a, k) => a.classList.toggle("is-cur", k === i));
    bar.style.transform = `scaleY(${(i + 1) / secs.length})`;
  }), { rootMargin: "-30% 0px -60% 0px" });
  secs.forEach((s) => io.observe(s));
}

initCommon();
initExplorer();
initCalc();
initMatrix();
initFlows();
initCompTabs();
initChanger();
initRetention();
initDay();
initRepairs();
initExposure();
initPipeline();
initTree();
initLimits();
initToc();
reveal(".doc__head > *, .g-sec > h2, .qs li");
