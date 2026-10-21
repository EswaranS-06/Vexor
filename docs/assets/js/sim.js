// Simulator: renders the stack as an SVG diagram, keeps the panel in sync, replays scenarios.
import {
  LANES, NODES, PORTS, TOOLS, DEFAULT_CONFIG, visibleNodes, edges, services, managers,
  hasWazuh, hasElk, isMulti, toolOn, ramGB, hostPorts, envText,
} from "./stack.js";

const SVG = "http://www.w3.org/2000/svg";
const reduced = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const esc = (s) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));

let cfg = { ...DEFAULT_CONFIG, tools: [...DEFAULT_CONFIG.tools] };
let geo = { nodes: {}, vertical: false };
let running = false;
let downSvc = null;
const prevVisible = new Set();
let els = {};

// ---------------------------------------------------------------- config <-> form <-> URL
function readForm(form) {
  const f = new FormData(form);
  return {
    soc: f.get("soc") || "wazuh",
    node: f.get("node") || "single",
    workers: Number(f.get("workers") || 1),
    tools: TOOLS.filter((t) => f.get(t) === "on"),
  };
}
function writeForm(form, c) {
  form.querySelector(`input[name=soc][value=${c.soc}]`).checked = true;
  form.querySelector(`input[name=node][value=${c.node}]`).checked = true;
  form.querySelector(`input[name=workers][value="${c.workers}"]`).checked = true;
  TOOLS.forEach((t) => (form.querySelector(`input[name=${t}]`).checked = c.tools.includes(t)));
}
function fromURL() {
  const q = new URLSearchParams(location.search);
  const c = { ...cfg, tools: [...cfg.tools] };
  if (["wazuh", "elk", "both"].includes(q.get("soc"))) c.soc = q.get("soc");
  if (["single", "multi"].includes(q.get("node"))) c.node = q.get("node");
  if (["1", "2", "3"].includes(q.get("workers"))) c.workers = Number(q.get("workers"));
  if (q.has("tools")) c.tools = q.get("tools").split(",").filter((t) => TOOLS.includes(t));
  return c;
}
function toURL(c) {
  const q = new URLSearchParams({ soc: c.soc, node: c.node, workers: String(c.workers), tools: c.tools.join(",") });
  try { history.replaceState(null, "", `?${q}${location.hash}`); } catch { /* file:// or sandboxed */ }
}
function syncDisabled(form, c) {
  const nodeSet = form.querySelector("[data-needs-wazuh]");
  const workSet = form.querySelector("[data-needs-multi]");
  nodeSet.disabled = !hasWazuh(c);
  workSet.disabled = !isMulti(c);
}

// ---------------------------------------------------------------- layout
function layout(c, width) {
  const vertical = width < 640;
  const ids = visibleNodes(c);
  const byLane = LANES.map((l) => ids.filter((id) => NODES[id].lane === l.id));
  const nodes = {};
  let W, H;
  if (!vertical) {
    W = 980;
    const colW = W / LANES.length, nw = 160, nh = 44, gap = 12, top = 40;
    const rows = Math.max(4, ...byLane.map((l) => l.length));
    H = top + rows * (nh + gap) + 18;
    byLane.forEach((lane, li) => {
      const stackH = lane.length * (nh + gap) - gap;
      const y0 = top + ((H - top - 18) - stackH) / 2;
      lane.forEach((id, i) => (nodes[id] = { x: li * colW + (colW - nw) / 2, y: y0 + i * (nh + gap), w: nw, h: nh, lane: li }));
    });
  } else {
    W = 360;
    const nw = 164, nh = 42, gapX = 12, gapY = 10, labelH = 22, laneGap = 26;
    let y = 10;
    byLane.forEach((lane, li) => {
      if (!lane.length) return;
      y += labelH;
      lane.forEach((id, i) => {
        const col = i % 2, row = Math.floor(i / 2);
        const x = lane.length === 1 ? (W - nw) / 2 : col * (nw + gapX) + (W - (2 * nw + gapX)) / 2;
        nodes[id] = { x, y: y + row * (nh + gapY), w: nw, h: nh, lane: li };
      });
      y += Math.ceil(lane.length / 2) * (nh + gapY) - gapY + laneGap;
    });
    H = y;
  }
  return { nodes, vertical, W, H, byLane };
}

function edgePath(a, b, vertical) {
  const A = geo.nodes[a], B = geo.nodes[b];
  if (!A || !B) return null;
  if (!vertical) {
    if (A.lane === B.lane) {
      const sx = A.x + A.w, sy = A.y + A.h / 2, ex = B.x + B.w, ey = B.y + B.h / 2;
      return `M${sx},${sy} C${sx + 26},${sy} ${ex + 26},${ey} ${ex},${ey}`;
    }
    const fwd = A.lane < B.lane;
    const sx = fwd ? A.x + A.w : A.x, sy = A.y + A.h / 2;
    const ex = fwd ? B.x : B.x + B.w, ey = B.y + B.h / 2;
    const k = Math.max(30, Math.abs(ex - sx) / 2);
    return `M${sx},${sy} C${fwd ? sx + k : sx - k},${sy} ${fwd ? ex - k : ex + k},${ey} ${ex},${ey}`;
  }
  if (A.lane === B.lane) {
    const sx = A.x + A.w / 2, sy = A.y + A.h, ex = B.x + B.w / 2, ey = B.y;
    if (Math.abs(A.y - B.y) < 2) return `M${A.x + A.w},${A.y + A.h / 2} L${B.x},${B.y + B.h / 2}`;
    return `M${sx},${sy} L${ex},${ey}`;
  }
  const fwd = A.lane < B.lane;
  const sx = A.x + A.w / 2, sy = fwd ? A.y + A.h : A.y;
  const ex = B.x + B.w / 2, ey = fwd ? B.y : B.y + B.h;
  const k = Math.max(18, Math.abs(ey - sy) / 2);
  return `M${sx},${sy} C${sx},${fwd ? sy + k : sy - k} ${ex},${fwd ? ey - k : ey + k} ${ex},${ey}`;
}

// ---------------------------------------------------------------- render
function render() {
  const box = els.diagram;
  const width = box.clientWidth || 900;
  const L = layout(cfg, width);
  geo = L;
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", `0 0 ${L.W} ${L.H}`);
  svg.setAttribute("aria-hidden", "true");

  // lane labels
  if (!L.vertical) {
    const colW = L.W / LANES.length;
    LANES.forEach((lane, i) => {
      const t = document.createElementNS(SVG, "text");
      t.setAttribute("x", i * colW + colW / 2); t.setAttribute("y", 20); t.setAttribute("text-anchor", "middle");
      t.setAttribute("class", "lane-label"); t.textContent = lane.label; svg.appendChild(t);
      if (i) {
        const r = document.createElementNS(SVG, "line");
        r.setAttribute("x1", i * colW); r.setAttribute("x2", i * colW); r.setAttribute("y1", 30); r.setAttribute("y2", L.H - 8);
        r.setAttribute("class", "lane-rule"); svg.appendChild(r);
      }
    });
  } else {
    L.byLane.forEach((lane, li) => {
      if (!lane.length) return;
      const first = L.nodes[lane[0]];
      const t = document.createElementNS(SVG, "text");
      t.setAttribute("x", 6); t.setAttribute("y", first.y - 8); t.setAttribute("class", "lane-label");
      t.textContent = LANES[li].label; svg.appendChild(t);
    });
  }

  // edges
  const eg = document.createElementNS(SVG, "g");
  edges(cfg).forEach(([a, b, kind]) => {
    const d = edgePath(a, b, L.vertical);
    if (!d) return;
    const p = document.createElementNS(SVG, "path");
    p.setAttribute("d", d);
    p.setAttribute("class", `edge${kind === "ui" ? " edge--ui" : kind === "act" ? " edge--act" : ""}`);
    p.dataset.edge = `${a}>${b}`;
    eg.appendChild(p);
  });
  svg.appendChild(eg);

  // nodes
  const ng = document.createElementNS(SVG, "g");
  const visible = visibleNodes(cfg);
  visible.forEach((id) => {
    const n = L.nodes[id], meta = NODES[id];
    const g = document.createElementNS(SVG, "g");
    const cls = ["node"];
    if (meta.ext) cls.push("node--ext");
    if (prevVisible.size && !prevVisible.has(id)) cls.push("is-new");
    if (id === downSvc) cls.push("is-down");
    g.setAttribute("class", cls.join(" "));
    g.dataset.node = id;
    g.setAttribute("transform", `translate(${n.x},${n.y})`);
    const r = document.createElementNS(SVG, "rect");
    r.setAttribute("width", n.w); r.setAttribute("height", n.h); r.setAttribute("rx", 6);
    const led = document.createElementNS(SVG, "circle");
    led.setAttribute("cx", 12); led.setAttribute("cy", n.h / 2); led.setAttribute("r", 3.5); led.setAttribute("class", "n-led");
    const t1 = document.createElementNS(SVG, "text");
    t1.setAttribute("x", 23); t1.setAttribute("y", n.h / 2 - 3); t1.setAttribute("class", "n-name"); t1.textContent = id;
    const t2 = document.createElementNS(SVG, "text");
    t2.setAttribute("x", 23); t2.setAttribute("y", n.h / 2 + 11); t2.setAttribute("class", "n-sub"); t2.textContent = meta.sub;
    g.append(r, led, t1, t2);
    ng.appendChild(g);
  });
  svg.appendChild(ng);
  box.replaceChildren(svg);
  els.svg = svg;
  prevVisible.clear(); visible.forEach((v) => prevVisible.add(v));
  box.setAttribute("aria-label", `Diagram: ${services(cfg).length} containers - ${services(cfg).join(", ")}`);
  renderPanel();
}

function renderPanel() {
  const svcs = services(cfg);
  els.stat.containers.textContent = String(svcs.length);
  els.stat.ram.textContent = `${Number.isInteger(ramGB(cfg)) ? ramGB(cfg) : ramGB(cfg).toFixed(1)} GB`;
  els.stat.ports.textContent = String(hostPorts(cfg).length);
  els.ps.innerHTML = svcs.map((s) => {
    const down = s === downSvc;
    return `<tr><td>${esc(s)}</td><td class="${down ? "st-down" : "st-up"}">${down ? "exited (137)" : "running"}</td><td>${esc(PORTS[s] || "-")}</td></tr>`;
  }).join("");
  const { lines, cmds } = envText(cfg);
  els.env.innerHTML = lines.map(([k, v]) => (k === "#" ? `<span class="c"># ${esc(v)}</span>` : `<span class="k">${esc(k)}</span>=<span class="v">${esc(v)}</span>`)).join("\n")
    + "\n\n" + cmds.map((l) => (l.startsWith("#") ? `<span class="c">${esc(l)}</span>` : esc(l))).join("\n");
  els.env.dataset.copy = lines.filter(([k]) => k !== "#").map(([k, v]) => `${k}=${v}`).join("\n") + "\n\n" + cmds.filter((l) => !l.startsWith("#")).join("\n");
}

// ---------------------------------------------------------------- log + animation
let clock = 0;
function stamp(addMs) {
  clock += addMs;
  const d = new Date(clock);
  return d.toTimeString().slice(0, 8);
}
function log(who, msg, cls = "", addMs = 400) {
  const li = document.createElement("li");
  if (cls) li.className = `is-${cls}`;
  li.innerHTML = `<time>${stamp(addMs)}</time><span><span class="who">${esc(who)}</span> ${esc(msg)}</span>`;
  els.log.querySelector(".log__empty")?.remove();
  els.log.appendChild(li);
  const pane = els.log.parentElement;
  pane.scrollTop = pane.scrollHeight;
}
function nodeEl(id) { return els.svg?.querySelector(`[data-node="${CSS.escape(id)}"]`); }
function edgeEl(a, b) {
  const fwd = els.svg?.querySelector(`[data-edge="${CSS.escape(`${a}>${b}`)}"]`);
  if (fwd) return { el: fwd, reverse: false };
  const rev = els.svg?.querySelector(`[data-edge="${CSS.escape(`${b}>${a}`)}"]`);
  return rev ? { el: rev, reverse: true } : null;
}
function heat(el, on) { el?.classList.toggle("is-hot", on); }

async function travel(a, b, bad = false) {
  const e = edgeEl(a, b);
  if (!e) return;
  heat(e.el, true);
  if (reduced()) { await sleep(260); heat(e.el, false); return; }
  const len = e.el.getTotalLength();
  const dot = document.createElementNS(SVG, "circle");
  dot.setAttribute("r", 4.5);
  dot.setAttribute("class", `packet${bad ? " packet--bad" : ""}`);
  els.svg.appendChild(dot);
  const dur = 620;
  await new Promise((resolve) => {
    const t0 = performance.now();
    const step = (now) => {
      const k = Math.min(1, (now - t0) / dur);
      const eased = 1 - Math.pow(1 - k, 3);
      const pt = e.el.getPointAtLength((e.reverse ? 1 - eased : eased) * len);
      dot.setAttribute("transform", `translate(${pt.x},${pt.y})`);
      if (k < 1) requestAnimationFrame(step); else resolve();
    };
    requestAnimationFrame(step);
  });
  dot.remove();
  heat(e.el, false);
}
async function pulse(id) {
  const n = nodeEl(id);
  if (!n) return;
  heat(n, true);
  await sleep(reduced() ? 120 : 260);
  heat(n, false);
}

// ---------------------------------------------------------------- scenarios
function pickManager() {
  const m = managers(cfg);
  return m[Math.min(m.length - 1, m.length > 1 ? 1 : 0)];
}

function scenario(name) {
  const s = [];
  const step = (o) => s.push(o);
  if (name === "network") {
    if (!toolOn(cfg, "suricata")) return { empty: "Suricata is off. Turn on SURICATA to inspect network traffic.", tool: "suricata" };
    step({ from: "traffic", to: "suricata", who: "suricata", msg: 'alert sid 2100498 "GPL ATTACK_RESPONSE id check returned root", severity 2', cls: "warn", bad: true });
    if (toolOn(cfg, "zeek")) step({ from: "traffic", to: "zeek", who: "zeek", msg: "http.log: GET /base64/… 200, host httpbin.org", add: 120 });
    if (hasWazuh(cfg)) {
      step({ from: "suricata", to: "wazuh.master", who: "wazuh.master", msg: "eve.json alert record read (stats records skipped) → rule 100721, level 7", bad: true });
      step({ from: "wazuh.master", to: "wazuh1.indexer", who: "filebeat", msg: "stored in wazuh-alerts-4.x-*" });
      step({ from: "wazuh1.indexer", to: "wazuh.dashboard", who: "wazuh.dashboard", msg: "visible in Threat Hunting · Suricata: medium severity alert", cls: "ok" });
      if (hasElk(cfg)) {
        step({ from: "wazuh.master", to: "logstash", who: "logstash", msg: "alerts.json → vexor-wazuh-alerts-*" });
        step({ from: "logstash", to: "elasticsearch", who: "elasticsearch", msg: "indexed · Kibana data view \"Vexor - Wazuh alerts\"", cls: "ok" });
      }
      if (toolOn(cfg, "n8n")) {
        step({ from: "wazuh.master", to: "n8n", who: "custom-n8n", msg: "level 7 ≥ N8N_ALERT_LEVEL 7 → POST /webhook/vexor-alerts with X-Vexor-Token" });
        step({ at: "n8n", who: "n8n", msg: 'workflow "Vexor - SOC alerts": token ok → severity high → your high-severity actions', cls: "ok" });
      }
    } else {
      step({ from: "suricata", to: "logstash", who: "logstash", msg: "eve.json tailed, tagged suricata" });
      step({ from: "logstash", to: "elasticsearch", who: "elasticsearch", msg: "stored in vexor-suricata-*" });
      step({ from: "elasticsearch", to: "kibana", who: "kibana", msg: 'data view "Vexor - Suricata"', cls: "ok" });
      if (toolOn(cfg, "n8n")) {
        step({ from: "logstash", to: "n8n", who: "logstash", msg: "severity 2 = level 7 ≥ 7 → http output posts the event to n8n" });
        step({ at: "n8n", who: "n8n", msg: "workflow routes it: source suricata, severity high", cls: "ok" });
      }
    }
    step({ who: "vexor", msg: "same path `vexor suricata test` checks, hop by hop", cls: "ok", add: 200 });
  }

  if (name === "ssh") {
    if (hasWazuh(cfg)) {
      const m = pickManager();
      step({ from: "agents", to: "nginx", who: "agent pc-01", msg: "sshd: 8 failed logins from 203.0.113.50 in 2 min", bad: true, cls: "warn" });
      step({ from: "nginx", to: m, who: "nginx", msg: `1514/tcp balanced to ${m}` });
      step({ at: m, who: m, msg: "rule 5712 level 10: sshd brute force trying to get access", cls: "warn" });
      step({ from: m, to: "wazuh1.indexer", who: "filebeat", msg: "stored in wazuh-alerts-4.x-*" });
      step({ from: "wazuh1.indexer", to: "wazuh.dashboard", who: "wazuh.dashboard", msg: "alert on the agent's security events", cls: "ok" });
      if (hasElk(cfg)) {
        step({ from: m, to: "logstash", who: "logstash", msg: "copied to vexor-wazuh-alerts-*" });
        step({ from: "logstash", to: "elasticsearch", who: "elasticsearch", msg: "searchable in Kibana", cls: "ok" });
      }
      if (toolOn(cfg, "n8n")) {
        step({ from: m, to: "n8n", who: "custom-n8n", msg: "level 10 → webhook, severity high" });
        step({ from: "n8n", to: "wazuh.master", who: "n8n", msg: "PUT /active-response firewall-drop (user vexor-n8n)" });
        step({ from: "wazuh.master", to: "nginx", who: "wazuh.master", msg: "active response sent to agent pc-01" });
        step({ from: "nginx", to: "agents", who: "agent pc-01", msg: "firewall-drop blocks 203.0.113.50", cls: "ok" });
      } else {
        step({ who: "tip", msg: "turn on N8N to answer it automatically with active response", add: 200 });
      }
    } else {
      step({ from: "beats", to: "logstash", who: "filebeat", msg: "auth.log: 8 failed sshd logins from 203.0.113.50", bad: true, cls: "warn" });
      step({ from: "logstash", to: "elasticsearch", who: "elasticsearch", msg: "stored in vexor-beats-*" });
      step({ from: "elasticsearch", to: "kibana", who: "kibana", msg: 'search it in "Vexor - Beats / Elastic Agent"', cls: "ok" });
      step({ who: "note", msg: "SOC=elk has no detection rules; use SOC=both for Wazuh rule 5712", cls: "warn", add: 200 });
    }
  }

  if (name === "crash") {
    const pool = services(cfg).filter((x) => x !== "nginx" || services(cfg).length < 3);
    const svc = pool[Math.floor(Math.random() * pool.length)];
    const fix = {
      "wazuh1.indexer": "indexer back; cluster green after the shards recovered",
      "wazuh.master": "master recreated with the current ossec.conf; agents reconnect",
      suricata: "rules present: 53,228 signatures loaded",
      elasticsearch: "elastic login ok; ILM retention + template present",
      kibana: "kibana_system login ok; data views present",
      n8n: "webhook registered; custom-n8n script current on every manager",
      logstash: "pipeline running; vexor_logstash can log in",
      "wazuh.dashboard": "dashboard answers through nginx (HTTP 302)",
      grafana: "grafana → indexer read-only user works",
    };
    step({ down: svc, who: "docker", msg: `${svc} exited (137): out of memory`, cls: "bad", add: 0 });
    step({ who: "watchdog", msg: `5-min timer: ${svc} is enabled but not running → docker compose up -d ${svc}`, cls: "warn", add: 228000 });
    step({ up: svc, who: "docker", msg: `${svc} started`, add: 4000 });
    step({ who: "doctor", msg: fix[svc] || `${svc} healthy`, cls: "ok", add: 52000 });
    step({ who: "health", msg: "hourly doctor --fix: 0 failed, saved to .state/health.last", cls: "ok", add: 1800000 });
  }
  return { steps: s };
}

async function play(name, btn) {
  if (running) return;
  const sc = scenario(name);
  els.log.innerHTML = "";
  clock = Date.now();
  selectTab("log");
  if (sc.empty) {
    const li = document.createElement("li");
    li.className = "log__empty";
    li.innerHTML = `${esc(sc.empty)} <button type="button" class="ghost-btn" data-enable="${sc.tool}">Turn on</button>`;
    els.log.appendChild(li);
    li.querySelector("button").addEventListener("click", () => { cfg.tools.push(sc.tool); writeForm(els.form, cfg); apply(); play(name, btn); });
    return;
  }
  running = true;
  els.form.inert = true;
  els.scnButtons.forEach((b) => (b.disabled = b !== btn));
  btn.setAttribute("aria-busy", "true");
  for (const st of sc.steps) {
    if (st.down) { downSvc = st.down; nodeEl(st.down)?.classList.add("is-down"); renderPanel(); }
    if (st.up) { downSvc = null; const n = nodeEl(st.up); n?.classList.remove("is-down"); n?.classList.add("is-warn"); renderPanel(); setTimeout(() => n?.classList.remove("is-warn"), 900); }
    if (st.from) await travel(st.from, st.to, st.bad);
    if (st.to || st.at) pulse(st.to || st.at);
    log(st.who, st.msg, st.cls, st.add ?? 380);
    await sleep(reduced() ? 120 : st.down || st.up ? 700 : 260);
  }
  btn.removeAttribute("aria-busy");
  els.scnButtons.forEach((b) => (b.disabled = false));
  els.form.inert = false;
  running = false;
}

// ---------------------------------------------------------------- tabs
function selectTab(key) {
  els.tabs.forEach((t) => {
    const on = t.id === `tab-${key}`;
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
    document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
  });
}

function apply() {
  syncDisabled(els.form, cfg);
  toURL(cfg);
  if (downSvc && !services(cfg).includes(downSvc)) downSvc = null;
  render();
}

export function setSoc(v) { cfg.soc = v; writeForm(els.form, cfg); apply(); }
export function toggleTool(t) {
  cfg.tools = cfg.tools.includes(t) ? cfg.tools.filter((x) => x !== t) : [...cfg.tools, t];
  writeForm(els.form, cfg); apply();
}
export function runScenario(name) {
  const btn = els.scnButtons.find((b) => b.dataset.scenario === name);
  document.getElementById("simulator").scrollIntoView({ behavior: reduced() ? "auto" : "smooth" });
  if (btn) play(name, btn);
}

export function initSim() {
  els = {
    form: document.querySelector("[data-sim-controls]"),
    diagram: document.querySelector("[data-diagram]"),
    log: document.querySelector("[data-log]"),
    ps: document.querySelector("[data-ps]"),
    env: document.querySelector("[data-env]"),
    stat: {
      containers: document.querySelector('[data-stat="containers"]'),
      ram: document.querySelector('[data-stat="ram"]'),
      ports: document.querySelector('[data-stat="ports"]'),
    },
    tabs: [...document.querySelectorAll("[data-tabs] [role=tab]")],
    scnButtons: [...document.querySelectorAll("[data-scenario]")],
  };
  if (!els.form) return;
  cfg = fromURL();
  writeForm(els.form, cfg);
  els.form.addEventListener("change", () => { cfg = readForm(els.form); apply(); });
  els.scnButtons.forEach((b) => b.addEventListener("click", () => play(b.dataset.scenario, b)));
  els.tabs.forEach((t, i) => {
    t.addEventListener("click", () => selectTab(t.id.replace("tab-", "")));
    t.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      const n = els.tabs[(i + (e.key === "ArrowRight" ? 1 : els.tabs.length - 1)) % els.tabs.length];
      n.focus(); selectTab(n.id.replace("tab-", ""));
    });
  });
  let rt;
  new ResizeObserver(() => { clearTimeout(rt); rt = setTimeout(() => { if (!running) render(); }, 120); }).observe(els.diagram);
  apply();
}
