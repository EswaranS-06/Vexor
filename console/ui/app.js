// Vexor Console - single-page UI over the console API. Every action is a vexor command run by the server.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let CSRF = "";
let STATE = {};

// ---------------------------------------------------------------- API
async function api(path, opts = {}) {
  const r = await fetch(path, {
    method: opts.body ? "POST" : "GET",
    headers: { "Content-Type": "application/json", "X-Vexor-CSRF": CSRF },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: "same-origin",
  });
  if (r.status === 401 && path !== "/api/login") { showLogin(); throw new Error("login required"); }
  const data = await r.json().catch(() => ({}));
  if (r.status === 403 && data.code === "password_change_required") { showPasswordChange(); throw new Error("login required"); }
  return { status: r.status, data };
}

// ---------------------------------------------------------------- login
function showLogin() { $("[data-app]").hidden = true; $("[data-pw]").hidden = true; $("[data-login]").hidden = false; $("[name=password]").focus(); }
function showPasswordChange() { $("[data-app]").hidden = true; $("[data-login]").hidden = true; $("[data-pw]").hidden = false; $("[name=current]").focus(); }
async function boot() {
  const { data } = await api("/api/session");
  if (!data.user) return showLogin();
  CSRF = data.csrf;
  if (data.mustChange) return showPasswordChange();
  $("[data-whoami]").textContent = data.user;
  $("[data-login]").hidden = true;
  $("[data-pw]").hidden = true;
  $("[data-app]").hidden = false;
  route();
}
$("[data-login-form]").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const btn = $("button[type=submit]", e.target);
  btn.disabled = true;
  const { status, data } = await api("/api/login", { body: { user: f.get("user"), password: f.get("password") } }).catch(() => ({ status: 0, data: {} }));
  btn.disabled = false;
  if (status !== 200) { $("[data-login-err]").textContent = data.error || "Sign-in failed."; return; }
  e.target.reset();
  boot();
});
const logout = async () => { await api("/api/logout", { body: {} }); location.hash = ""; showLogin(); };
$("[data-logout]").addEventListener("click", logout);
$("[data-pw-logout]").addEventListener("click", logout);
$("[data-pw-form]").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  const err = $("[data-pw-err]");
  err.textContent = "";
  if (f.new !== f.repeat) { err.textContent = "The two new passwords differ."; return; }
  if (f.new.length < 12) { err.textContent = "Use at least 12 characters."; return; }
  if (f.new === f.current) { err.textContent = "The new password must differ from the current one."; return; }
  const { status, data } = await api("/api/password", { body: f }).catch(() => ({ status: 0, data: {} }));
  if (status !== 200) { err.textContent = data.error || "The password was not changed."; return; }
  e.target.reset();
  boot();
});

// ---------------------------------------------------------------- confirm dialog
function confirmDialog({ cmd, level, word, text }) {
  const d = $("[data-confirm]");
  $("[data-confirm-title]").textContent = level === "danger" ? "This can stop services or delete data" : "Run this command?";
  $("[data-confirm-cmd]").textContent = cmd;
  $("[data-confirm-text]").textContent = text || (level === "danger" ? "Read the command carefully. Volumes and backups are kept unless the command says otherwise." : "It changes the running stack.");
  const box = $("[data-confirm-wordbox]"), input = $("[data-confirm-input]"), ok = $("[data-confirm-ok]");
  box.hidden = level !== "danger";
  input.value = "";
  $("[data-confirm-word]").textContent = word || "";
  ok.disabled = level === "danger";
  ok.classList.toggle("btn--danger", level === "danger");
  input.oninput = () => (ok.disabled = input.value !== word);
  d.showModal();
  (level === "danger" ? input : ok).focus();
  return new Promise((res) => d.addEventListener("close", () => res(d.returnValue === "ok" ? (word ? input.value : true) : false), { once: true }));
}

// ---------------------------------------------------------------- jobs + output panel
let currentJob = null, es = null;
function lineClass(l) {
  const t = l.trimStart();
  if (t.startsWith("✔")) return "ok";
  if (t.startsWith("✘")) return "bad";
  if (t.startsWith("!")) return "warn";
  if (t.startsWith("==>")) return "head";
  if (t.startsWith("→") || t.startsWith("$ ")) return "hint";
  return "";
}
function appendLines(lines) {
  const body = $("[data-out-body]");
  const nearBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 40;
  const frag = document.createDocumentFragment();
  lines.forEach((l) => { const s = document.createElement("span"); const c = lineClass(l); if (c) s.className = c; s.textContent = l + "\n"; frag.appendChild(s); });
  body.appendChild(frag);
  if (nearBottom) body.scrollTop = body.scrollHeight;
}
function openJob(job, onEnd) {
  es?.close();
  currentJob = job;
  const out = $("[data-out]");
  out.hidden = false;
  document.body.classList.add("has-out");
  $("[data-out-cmd]").textContent = job.cmd;
  $("[data-out-st]").textContent = "running";
  $("[data-out-st]").className = "out__st is-run";
  $("[data-out-body]").replaceChildren();
  $("[data-out-stop]").hidden = false;
  es = new EventSource(`/api/jobs/${job.id}/stream`);
  es.onmessage = (e) => appendLines(JSON.parse(e.data).lines);
  es.addEventListener("end", (e) => {
    const { code } = JSON.parse(e.data);
    $("[data-out-st]").textContent = code === 0 ? "done" : `exit ${code}`;
    $("[data-out-st]").className = `out__st ${code === 0 ? "is-ok" : "is-bad"}`;
    $("[data-out-stop]").hidden = true;
    es.close();
    onEnd?.(code);
    if (["#overview", "#containers", "#ports", "#volumes", "#stacks"].includes(location.hash || "#overview")) setTimeout(() => route(true), 400);
  });
  es.onerror = () => { $("[data-out-st]").textContent = "disconnected"; es.close(); };
}
$("[data-out-close]").addEventListener("click", () => { es?.close(); $("[data-out]").hidden = true; document.body.classList.remove("has-out"); });
$("[data-out-stop]").addEventListener("click", () => currentJob && api(`/api/jobs/${currentJob.id}/stop`, { body: {} }));

async function run(args, { onEnd, text } = {}) {
  let body = { args };
  let r = await api("/api/run", { body });
  if (r.status === 409) {
    const ans = await confirmDialog({ cmd: r.data.cmd, level: r.data.confirm, word: r.data.word, text });
    if (!ans) return null;
    body = r.data.confirm === "danger" ? { args, confirmWord: ans } : { args, confirmed: true };
    r = await api("/api/run", { body });
  }
  if (r.status !== 200) { toast(r.data.error || "The command was refused.", "bad"); return null; }
  openJob(r.data, onEnd);
  return r.data;
}
function toast(msg, kind = "") {
  let t = $(".toast");
  if (!t) { t = document.createElement("div"); t.className = "toast"; t.setAttribute("role", "status"); document.body.appendChild(t); }
  t.textContent = msg; t.dataset.kind = kind; t.classList.add("is-on");
  clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove("is-on"), 3200);
}

// ---------------------------------------------------------------- shared bits
const pill = (txt, kind = "") => `<span class="pill ${kind ? "pill--" + kind : ""}">${esc(txt)}</span>`;
const btn = (label, args, kind = "", extra = "") => `<button type="button" class="btn btn--sm ${kind}" data-run='${esc(JSON.stringify(args))}' ${extra}>${esc(label)}</button>`;
function bindRunButtons(root) {
  $$("[data-run]", root).forEach((b) => b.addEventListener("click", () => {
    let args = JSON.parse(b.dataset.run);
    const form = b.closest("[data-form]");
    if (form) {
      const vals = Object.fromEntries(new FormData(form));
      args = args.flatMap((a) => { const m = /^\{(\w+)\}$/.exec(a); return m ? (vals[m[1]] ? [vals[m[1]]] : []) : [a]; });
    }
    run(args);
  }));
}
function setTitle(t, meta = "") { $("[data-title]").textContent = t; $("[data-topmeta]").innerHTML = meta; document.title = `${t} · Vexor Console`; }
const view = () => $("[data-view]");
const loading = (what) => (view().innerHTML = `<p class="muted">Loading ${esc(what)}…</p>`);
function stateLine(c) {
  const st = c.state === "running" ? (c.health && c.health !== "healthy" ? "warn" : "ok") : "bad";
  return pill(c.state + (c.health ? ` · ${c.health}` : ""), st);
}

// ---------------------------------------------------------------- views
const fmtBytes = (b) => (b >= 1e12 ? (b / 1e12).toFixed(1) + " TB" : b >= 1e9 ? (b / 1e9).toFixed(1) + " GB" : b >= 1e6 ? (b / 1e6).toFixed(0) + " MB" : b >= 1e3 ? (b / 1e3).toFixed(0) + " KB" : (b || 0) + " B");
async function vOverview() {
  setTitle("Overview");
  loading("the stack");
  const [{ data: s }, { data: cs }, { data: pend }, { data: dk }] = await Promise.all([api("/api/state"), api("/api/containers"), api("/api/pending"), api("/api/disk")]);
  const fss = dk.filesystems || [];
  const worst = fss.reduce((a, f) => (!a || f.pct > a.pct ? f : a), null);
  const level = (pct) => (pct >= 95 ? "bad" : pct >= 85 ? "warn" : "");
  STATE = s;
  const exp = s.services || [];
  const running = cs.filter((c) => c.state === "running").length;
  const missing = exp.filter((x) => !cs.some((c) => c.service === x && c.state === "running"));
  const hl = s.health_last || {};
  $("[data-topmeta]").innerHTML = `${pill("vexor " + (s.vexor || "?"))} ${pill("Wazuh " + (s.wazuh_version || "?"))}`;
  const urls = Object.entries(s.urls || {}).filter(([, u]) => u);
  view().innerHTML = `
    <section class="cards">
      <article class="card"><h2>Stack</h2><p class="big">SOC=${esc(s.soc)}</p><p class="muted">${esc(s.layout || "")}</p></article>
      <article class="card ${!missing.length ? "" : running === 0 && !s.stopped ? "card--bad" : "card--warn"}"><h2>Containers</h2><p class="big">${running} / ${exp.length} running</p>
        <p class="muted">${!missing.length ? "every enabled service is up" : s.stopped ? "stopped with vexor stop - start it under Quick actions" : "not running: " + esc(missing.join(", "))}</p></article>
      <article class="card ${hl.fail > 0 ? "card--bad" : hl.warn > 0 ? "card--warn" : ""}"><h2>Last health check</h2>
        <p class="big">${hl.epoch ? `${hl.pass} passed · ${hl.warn} warn · ${hl.fail} failed` : "not run yet"}</p>
        <p class="muted">${hl.epoch ? new Date(hl.epoch * 1000).toLocaleString() : "the hourly timer runs it (vexor daemon install)"}</p></article>
      <article class="card ${level(worst?.pct ?? s.disk?.pct ?? 0) ? "card--" + level(worst?.pct ?? s.disk?.pct ?? 0) : ""}"><h2>Disk</h2><p class="big">${esc(worst?.pct ?? s.disk?.pct ?? "?")}% used</p><p class="muted">${esc(worst ? worst.mount + " (fullest)" : s.disk?.path || "")}</p></article>
    </section>
    ${s.legacy_project ? `<section class="pending"><p><b>The Docker project is still named <code>${esc(s.project)}</code>.</b> Vexor 2 names it <code>vexor</code>. <code>vexor migrate</code> copies and checks every volume, then switches. The old volumes are kept; once the stack works, run <code>vexor migrate --yes</code> in the Terminal to remove them. Take a backup first.</p><div class="actions">${btn("Migrate to vexor", ["migrate"], "btn--danger-ghost")}</div></section>` : ""}
    ${pend.keys?.length ? `<section class="pending"><p><b>${pend.keys.length} .env change${pend.keys.length > 1 ? "s" : ""} not applied yet:</b> <code>${esc(pend.keys.join(" "))}</code></p><div class="actions">${btn("Show plan", ["plan"])}${btn("Apply", ["config", "apply"], "btn--primary")}</div></section>` : ""}
    <section class="block"><h2>Disk usage</h2>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>Filesystem</th><th>Holds</th><th>Used / size</th><th>Free</th><th class="w-bar"><span class="vh">Usage</span></th><th>Used</th></tr></thead>
        <tbody>${fss.map((f) => `<tr><td class="mono"><b>${esc(f.mount)}</b></td><td class="small">${esc((f.roles || []).join(", ") || "-")}</td>
          <td class="num">${esc(fmtBytes(f.used))} / ${esc(fmtBytes(f.size))}</td><td class="num">${esc(fmtBytes(f.avail))}</td>
          <td class="w-bar"><span class="bar ${level(f.pct) ? "bar--" + level(f.pct) : ""}"><i data-w="${Math.min(100, f.pct) / 100}"></i></span></td>
          <td>${pill(f.pct + "%", level(f.pct) === "bad" ? "bad" : level(f.pct) === "warn" ? "warn" : "ok")}</td></tr>`).join("") || '<tr><td colspan="6" class="muted">Disk usage is not available.</td></tr>'}</tbody></table></div>
      <p class="muted small">Amber from 85%, red from 95%. Free space with <a href="#reset">Reset</a> (prune unused volumes or images).</p></section>
    <section class="block"><h2>Open</h2>
      <div class="links">${urls.map(([k, u]) => `<a class="linkcard" href="${esc(u)}" target="_blank" rel="noopener"><b>${esc(k)}</b><span>${esc(u)}</span></a>`).join("") || '<p class="muted">No web UIs enabled.</p>'}</div></section>
    ${(s.reminders || []).length ? `<section class="block"><h2>Reminders</h2><ul class="list">${s.reminders.map((r) => `<li><b>${esc(r.msg)}</b><code>${esc(r.cmd)}</code></li>`).join("")}</ul></section>` : ""}
    <section class="block"><h2>Quick actions</h2><div class="actions">
      ${btn("Status", ["status"])}${btn("Wait until ready", ["wait-ready", "--timeout", "600"])}${btn("Doctor", ["doctor"])}${btn("Doctor --fix", ["doctor", "--fix"], "btn--primary")}${btn("Start stack", ["start"])}${btn("Backup now", ["backup", "run"])}${btn("AI report", ["ai-context", "--print"])}
    </div></section>
    <section class="block"><h2>Services</h2><div class="svc-grid">${exp.map((x) => { const c = cs.find((y) => y.service === x); return `<a class="svc ${c?.state === "running" ? "" : "svc--down"}" href="#containers"><b>${esc(x)}</b>${c ? stateLine(c) : pill("missing", "bad")}</a>`; }).join("")}</div></section>`;
  $$("[data-w]").forEach((i) => (i.style.transform = `scaleX(${i.dataset.w})`));
  bindRunButtons(view());
}

async function vContainers() {
  setTitle("Containers");
  loading("containers");
  const { data: cs } = await api("/api/containers");
  view().innerHTML = `
    <div class="actions">${btn("Start all", ["start"])}${btn("Restart all", ["restart"])}${btn("Stop all", ["stop"], "btn--danger-ghost")}${btn("Errors (1h)", ["logs", "errors", "--since", "1h"])}</div>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>Service</th><th>State</th><th>Status</th><th>CPU</th><th>Memory</th><th>Ports</th><th>Image</th><th><span class="vh">Actions</span></th></tr></thead>
      <tbody>${cs.map((c) => `<tr>
        <td><b>${esc(c.service)}</b></td><td>${stateLine(c)}</td><td class="muted">${esc(c.status)}</td>
        <td class="num">${esc(c.cpu || "-")}</td><td class="num">${esc(c.mem || "-")}</td>
        <td class="mono">${esc([...new Set((c.ports || []).filter((p) => p.PublishedPort).map((p) => p.PublishedPort + (p.Protocol === "udp" ? "/udp" : "")))].join(" ") || "-")}</td>
        <td class="mono small">${esc(c.image)}</td>
        <td class="row-actions">${btn("Logs", ["logs", c.service, "-n", "300"])}${btn("Follow", ["logs", c.service, "-f", "-n", "50"])}${c.state === "running" ? btn("Restart", ["restart", c.service]) + btn("Stop", ["stop", c.service]) : btn("Start", ["start", c.service], "btn--primary")}</td>
      </tr>`).join("")}</tbody></table></div>
    <p class="muted small">Managers are recreated on restart, so they load the current ossec.conf. Data stays in volumes.</p>`;
  bindRunButtons(view());
}

async function vPorts() {
  setTitle("Ports");
  loading("ports");
  const { data: ps } = await api("/api/ports");
  view().innerHTML = `
    <p class="lede">Every port comes from <code>.env</code>. Change a value, check it, then apply: Vexor rewrites nginx and the compose override and recreates only what uses the port.</p>
    <form class="ports" data-ports-form>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>Setting</th><th>Port</th><th>For</th><th>Who connects</th><th>Listening</th></tr></thead>
        <tbody>${ps.map((p) => `<tr data-key="${esc(p.key)}">
          <td class="mono"><b>${esc(p.key)}</b></td>
          <td><input class="in in--port" name="${esc(p.key)}" value="${esc(p.value)}" inputmode="numeric" aria-label="${esc(p.key)}" data-orig="${esc(p.value)}"><span class="field-err" data-err="${esc(p.key)}"></span></td>
          <td>${esc(p.what)}${p.fiveX ? ' <span class="muted small">(50000-59999)</span>' : ""}</td>
          <td>${pill(p.audience, { endpoints: "ok", admins: "accent", restricted: "warn", host: "" }[p.audience])}</td>
          <td>${!p.inUse ? pill("not in use") : p.listening ? pill("yes", "ok") : pill("no", "bad")}</td></tr>`).join("")}</tbody></table></div>
      <div class="actions"><button class="btn btn--sm" type="button" data-ports-check>Check</button><button class="btn btn--sm btn--primary" type="submit" data-ports-apply disabled>Apply changes</button><span class="muted small" data-ports-msg>No changes.</span></div>
    </form>`;
  const form = $("[data-ports-form]");
  const changes = () => Object.fromEntries($$("input[data-orig]", form).filter((i) => i.value.trim() !== i.dataset.orig).map((i) => [i.name, i.value.trim()]));
  const refresh = () => {
    const ch = changes(), n = Object.keys(ch).length;
    $("[data-ports-apply]").disabled = !n;
    $("[data-ports-msg]").textContent = n ? `${n} change${n > 1 ? "s" : ""}: ${Object.entries(ch).map(([k, v]) => `${k}=${v}`).join(", ")}` : "No changes.";
    $$("input[data-orig]", form).forEach((i) => i.classList.toggle("is-changed", i.value.trim() !== i.dataset.orig));
  };
  const check = async () => {
    $$("[data-err]", form).forEach((e) => (e.textContent = ""));
    const { data } = await api("/api/ports/check", { body: { changes: changes() } });
    Object.entries(data.errors || {}).forEach(([k, m]) => { const e = $(`[data-err="${k}"]`, form); if (e) e.textContent = m; });
    return !Object.keys(data.errors || {}).length;
  };
  form.addEventListener("input", refresh);
  $("[data-ports-check]").addEventListener("click", async () => { const good = await check(); toast(good ? "Ports are valid and free." : "Fix the marked ports.", good ? "ok" : "bad"); });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!(await check())) return toast("Fix the marked ports first.", "bad");
    await applySettings(changes(), "Agents and browsers must use the new ports afterwards. Firewall rules are not changed.");
  });
}

function planText(p) {
  if (!p || p.error) return "The plan could not be computed; the output shows what the apply does.";
  const parts = [];
  if (p.recreate?.length) parts.push(`Recreates: ${p.recreate.join(", ")}.`);
  if (p.create?.length) parts.push(`Creates: ${p.create.join(", ")}.`);
  if (p.remove?.length) parts.push(`Removes: ${p.remove.join(", ")} (volumes kept).`);
  if (p.nginx_changes) parts.push(`nginx: ${p.nginx_changes} changed lines (reload).`);
  if (!parts.length) parts.push("No container is recreated.");
  return parts.join(" ") + (p.notes?.length ? " " + p.notes.join(". ") + "." : "");
}
async function applySettings(changes, text) {
  let r = await api("/api/settings/apply", { body: { changes } });
  if (r.status === 409) {
    const cmd = Object.entries(changes).map(([k, v]) => `vexor config set ${k} ${v}`).join("\n") + "\nvexor config apply";
    toast("Working out what this changes…");
    const { data: plan } = await api("/api/plan", { body: { changes } });
    if (!(await confirmDialog({ cmd, level: "change", text: planText(plan) + (text ? " " + text : "") }))) return;
    r = await api("/api/settings/apply", { body: { changes, confirmed: true } });
  }
  if (r.status !== 200) { toast(r.data.error || Object.entries(r.data.errors || {}).map(([k, v]) => `${k}: ${v}`).join("; ") || "Refused.", "bad"); return; }
  openJob(r.data, () => route(true));
}

async function vVolumes() {
  setTitle("Volumes");
  loading("volumes (sizes take a few seconds)");
  const { data: vs } = await api("/api/volumes");
  const total = vs.reduce((a, v) => a + (v.bytes || 0), 0);
  const fmt = (b) => (b >= 1e9 ? (b / 1e9).toFixed(1) + " GB" : b >= 1e6 ? (b / 1e6).toFixed(0) + " MB" : b >= 1e3 ? (b / 1e3).toFixed(0) + " KB" : b + " B");
  const max = Math.max(1, ...vs.map((v) => v.bytes || 0));
  view().innerHTML = `
    <p class="lede">${vs.length} volumes, ${fmt(total)} in total. Everything Vexor keeps lives here: alerts, agent keys, rules, workflows.</p>
    <div class="actions">${btn("Backup all (live)", ["volumes", "backup", "all"])}${btn("Full backup (snapshot + state)", ["backup", "run"], "btn--primary")}${btn("List backups", ["backup", "list"])}${btn("Show unused volumes", ["volumes", "orphans"])}${btn("Remove unused volumes", ["volumes", "prune"], "btn--danger-ghost")}<button class="btn btn--sm btn--ghost" type="button" data-vol-fresh>Recount sizes</button></div>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>Volume</th><th>Size</th><th class="w-bar"><span class="vh">Share</span></th><th>Used by</th><th><span class="vh">Actions</span></th></tr></thead>
      <tbody>${vs.map((v) => `<tr>
        <td class="mono"><b>${esc(v.name)}</b></td><td class="num">${esc(fmt(v.bytes || 0))}</td>
        <td class="w-bar"><span class="bar"><i data-w="${(v.bytes || 0) / max}"></i></span></td>
        <td class="small">${v.users?.length ? esc(v.users.join(", ")) : pill("unused", "warn")}</td>
        <td class="row-actions">${btn("Backup", ["volumes", "backup", v.short])}${v.users?.length ? "" : btn("Remove", ["volumes", "rm", v.short], "btn--danger-ghost")}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">No volumes yet - they are created when the stack starts.</td></tr>'}</tbody></table></div>
    <p class="muted small">A live volume backup of a running indexer can be inconsistent; the full backup uses an indexer snapshot. Restores run from the terminal: <code>vexor volumes restore &lt;volume&gt; &lt;file&gt;</code>.</p>`;
  $$("[data-w]").forEach((i) => (i.style.transform = `scaleX(${i.dataset.w})`));
  bindRunButtons(view());
  $("[data-vol-fresh]").addEventListener("click", async () => { loading("volumes"); await api("/api/volumes?fresh=1"); route(true); });
}

const STACKS = (s) => {
  const t = s.tools || {}, on = (x) => !!t[x];
  const soc = s.soc || "wazuh";
  return [
    { id: "wazuh", name: "Wazuh", on: soc !== "elk", note: s.layout,
      actions: [btn("Status", ["wazuh"]), btn("Alerts (level 7+)", ["wazuh", "alerts", "--level", "7", "-n", "40"]), btn("Agents", ["agents", "list"]), btn("Manager cluster", ["cluster"]), btn("Enroll cmd (Linux)", ["agents", "enroll-cmd", "linux"]), btn("Enroll cmd (Windows)", ["agents", "enroll-cmd", "windows"]), btn("Node type", ["node-type"])],
      form: `<div class="mini" data-form><label>NODE_TYPE <select name="nt" class="in"><option>single</option><option>multi</option></select></label>${btn("Switch", ["node-type", "{nt}"], "btn--danger-ghost")}<label>Workers <select name="w" class="in"><option>1</option><option>2</option><option>3</option></select></label>${btn("Scale", ["scale", "{w}"], "btn--danger-ghost")}</div>` },
    { id: "elk", name: "ELK", on: soc !== "wazuh", note: soc === "wazuh" ? "off - SOC=wazuh" : "Elasticsearch, Logstash, Kibana",
      actions: soc === "wazuh" ? [] : [btn("Status", ["elk"]), btn("Indices", ["elk", "indices"]), btn("Beats config", ["elk", "beats-config"]), btn("Explain allocation", ["elk", "explain"])],
      form: `<div class="mini" data-form><label>SOC <select name="soc" class="in"><option ${soc === "wazuh" ? "selected" : ""}>wazuh</option><option ${soc === "elk" ? "selected" : ""}>elk</option><option ${soc === "both" ? "selected" : ""}>both</option></select></label>${btn("Switch SOC", ["soc", "{soc}"], "btn--danger-ghost")}</div>` +
        (soc === "wazuh" ? "" : `<div class="mini" data-form><label class="grow">Search <input name="q" class="in" placeholder="rule.level:>=10"></label>${btn("Search", ["elk", "search", "{q}", "-n", "20"])}</div>`) },
    { id: "n8n", name: "n8n", on: on("n8n"), note: s.n8n?.hook ? `alerts level ≥ ${s.n8n.level} → ${s.n8n.hook}` : "not connected",
      actions: on("n8n") ? [btn("Status", ["n8n"]), btn("Import workflow", ["n8n", "workflow"]), btn("Credentials", ["n8n", "credentials"]), btn("Send test alert", ["n8n", "test"]), btn("Backup workflows", ["n8n", "backup"]), btn("Disconnect", ["n8n", "disconnect"])] : [],
      form: on("n8n") ? `<div class="mini" data-form><label>Path <input name="path" class="in" value="vexor-alerts"></label><label>Level <input name="lvl" class="in in--port" value="${esc(s.n8n?.level || 7)}"></label>${btn("Connect", ["n8n", "connect", "{path}", "--level", "{lvl}"], "btn--primary")}</div>` : "",
      toggle: "n8n" },
    { id: "suricata", name: "Suricata", on: on("suricata"), note: "network IDS",
      actions: on("suricata") ? [btn("Status", ["suricata"]), btn("Alerts (1h)", ["suricata", "alerts", "--since", "1h", "-n", "50"]), btn("Run test", ["suricata", "test"]), btn("Update rules", ["suricata", "update-rules"])] : [], toggle: "suricata" },
    { id: "zeek", name: "Zeek", on: on("zeek"), note: "network logs",
      actions: on("zeek") ? [btn("Status", ["zeek"]), btn("Notices", ["zeek", "notices"]), btn("Top hosts", ["zeek", "top", "hosts"]), btn("Top DNS", ["zeek", "top", "dns"]), btn("Run test", ["zeek", "test"])] : [],
      form: on("zeek") ? `<div class="mini" data-form><label>Log <select name="log" class="in">${["conn", "dns", "http", "ssl", "ssh", "notice", "weird"].map((l) => `<option>${l}</option>`).join("")}</select></label>${btn("Show", ["zeek", "show", "{log}", "-n", "40"])}</div>` : "", toggle: "zeek" },
    { id: "grafana", name: "Grafana", on: on("grafana"), note: "Wazuh alerts dashboard", actions: [], toggle: "grafana" },
    { id: "portainer", name: "Portainer", on: on("portainer"), note: "container management", actions: [], toggle: "portainer" },
  ];
};
async function vStacks() {
  setTitle("Stacks");
  loading("stacks");
  const { data: s } = await api("/api/state");
  STATE = s;
  view().innerHTML = `<div class="stacks">${STACKS(s).map((k) => `
    <article class="stack ${k.on ? "" : "stack--off"}" id="stack-${k.id}">
      <header class="stack__head"><h2>${esc(k.name)}</h2>${k.on ? pill("on", "ok") : pill("off")}
        ${k.toggle ? btn(k.on ? "Disable" : "Enable", ["tools", k.on ? "disable" : "enable", k.toggle], k.on ? "btn--danger-ghost" : "btn--primary") : ""}</header>
      <p class="muted small">${esc(k.note || "")}</p>
      ${k.actions.length ? `<div class="actions">${k.actions.join("")}</div>` : ""}
      ${k.form || ""}
    </article>`).join("")}</div>
    <section class="block"><h2>Certificates, backups, automation</h2><div class="actions">
      ${btn("Certificate status", ["cert", "status"])}${btn("Create local-CA cert", ["cert", "create"])}${btn("Renew", ["cert", "renew"])}
      ${btn("Retention", ["retention", "status"])}${btn("Apply retention", ["retention", "apply"])}${btn("Daemon status", ["daemon", "status"])}${btn("Install daemon", ["daemon", "install"])}${btn("Update check", ["update", "check"])}
    </div></section>`;
  bindRunButtons(view());
}

async function vHealth() {
  setTitle("Health");
  view().innerHTML = `
    <p class="lede">The doctor runs about 60 checks. With --fix it repairs what it safely can, the same as the hourly timer.</p>
    <div class="actions">${btn("Run doctor", ["doctor"], "btn--primary")}${btn("Doctor --fix", ["doctor", "--fix"])}${btn("Health details", ["health"])}${btn("Recent errors", ["logs", "errors", "--since", "1h"])}${btn("Reminders", ["reminders"])}${btn("AI report", ["ai-context", "--print"])}${btn("Watchdog pass", ["watchdog"])}</div>
    <section class="block"><h2>Notifications</h2>
      <p class="muted">The hourly check sends problems it could not fix to <code>NOTIFY_URL</code> (Slack, Teams, Discord or any JSON webhook), or to your n8n webhook when that is empty. Set the URL and <code>NOTIFY_ON</code> under Settings.</p>
      <div class="actions">${btn("Notification status", ["notify"])}${btn("Send a test", ["notify", "test"], "btn--primary")}</div></section>`;
  bindRunButtons(view());
}

async function vSettings() {
  setTitle("Settings");
  loading("settings");
  const { data: rows } = await api("/api/settings");
  view().innerHTML = `
    <p class="lede">All of <code>.env</code>. Passwords and keys are hidden; change them with their commands (Security below). Ports have their own page.</p>
    <label class="search"><span class="vh">Filter</span><input class="in" placeholder="Filter settings" data-set-filter></label>
    <form data-set-form><div class="table-wrap"><table class="table">
      <thead><tr><th>Setting</th><th>Value</th><th>About</th></tr></thead>
      <tbody>${rows.filter((r) => !r.port).map((r) => `<tr data-row="${esc(r.key.toLowerCase() + " " + (r.help || "").toLowerCase())}">
        <td class="mono"><b>${esc(r.key)}</b></td>
        <td>${r.secret ? pill(r.set ? "set" : "not set", r.set ? "ok" : "warn") : `<input class="in" name="${esc(r.key)}" value="${esc(r.value)}" data-orig="${esc(r.value)}" aria-label="${esc(r.key)}">`}</td>
        <td class="small muted">${esc(r.help || "")}</td></tr>`).join("")}</tbody></table></div>
      <div class="actions sticky-bar"><button class="btn btn--sm btn--primary" type="submit" data-set-apply disabled>Apply changes</button><span class="muted small" data-set-msg>No changes.</span></div>
    </form>
    <section class="block"><h2>Security</h2><div class="actions">
      ${btn("New admin password", ["passwd", "admin", "--generate"], "btn--danger-ghost")}${btn("New API password", ["passwd", "api", "--generate"], "btn--danger-ghost")}${btn("New dashboard password", ["passwd", "kibanaserver", "--generate"], "btn--danger-ghost")}${btn("Enrollment password on", ["agents", "password", "on"])}${btn("New console password", ["console", "password", "--generate"], "btn--danger-ghost")}
    </div><p class="muted small">New passwords appear in the output once; they are also stored in .env.</p></section>`;
  const form = $("[data-set-form]");
  const changes = () => Object.fromEntries($$("input[data-orig]", form).filter((i) => i.value !== i.dataset.orig).map((i) => [i.name, i.value]));
  form.addEventListener("input", () => {
    const ch = changes(), n = Object.keys(ch).length;
    $("[data-set-apply]").disabled = !n;
    $("[data-set-msg]").textContent = n ? Object.entries(ch).map(([k, v]) => `${k}=${v}`).join(", ") : "No changes.";
    $$("input[data-orig]", form).forEach((i) => i.classList.toggle("is-changed", i.value !== i.dataset.orig));
  });
  form.addEventListener("submit", (e) => { e.preventDefault(); applySettings(changes()); });
  $("[data-set-filter]").addEventListener("input", (e) => { const q = e.target.value.toLowerCase(); $$("[data-row]", form).forEach((r) => (r.hidden = q && !r.dataset.row.includes(q))); });
  bindRunButtons(view());
}

const RESETS = [
  { title: "Uninstall, keep data", args: ["uninstall", "--keep-data", "--yes"],
    what: "Stops and removes the Vexor containers and network. Volumes (alerts, agent keys, rules, workflows) and generated files are kept; images are not removed. Run vexor start to bring it back." },
  { title: "Uninstall everything", args: ["uninstall", "--yes"],
    what: "Stops and removes the containers and network, then removes the project volumes and generated files. All stored alerts and agent keys are lost. Images are not removed." },
  { title: "Remove unused volumes", args: ["volumes", "prune", "--yes"],
    what: "Deletes Vexor volumes the current layout no longer uses (e.g. old worker or indexer data after a switch to single). Volumes still attached to a container and tool data are kept." },
  { title: "Remove unused images", args: ["images", "prune", "--yes"],
    what: "Deletes old versions of the stack's images that the current setup no longer uses and no container runs. Running containers and volumes are untouched." },
];
async function vReset() {
  setTitle("Reset");
  view().innerHTML = `
    <p class="lede">Remove Vexor, or free disk space. Each action shows the command and asks you to type its name before it runs. Take a backup first (Volumes page).</p>
    <div class="resets">${RESETS.map((r, i) => `<article class="reset"><h2>${esc(r.title)}</h2><p class="small">${esc(r.what)}</p><code class="mono small">vexor ${esc(r.args.join(" "))}</code>
      <div class="actions"><button type="button" class="btn btn--sm btn--danger-ghost" data-reset="${i}">${esc(r.title)}…</button></div></article>`).join("")}</div>`;
  $$("[data-reset]").forEach((b) => b.addEventListener("click", () => { const r = RESETS[+b.dataset.reset]; run(r.args, { text: r.what }); }));
}

const SUGGEST = ["status", "doctor", "doctor --fix", "wazuh alerts -n 20", "agents list", "elk", "elk indices", "n8n", "n8n test", "suricata", "suricata alerts --since 1h", "suricata test", "zeek", "zeek top hosts", "tools", "soc", "volumes ls", "backup list", "cert status", "logs errors --since 1h", "logs nginx -n 100", "retention status", "disk", "volumes orphans", "wait-ready", "update check", "version", "reminders"];
async function vTerminal() {
  setTitle("Terminal");
  view().innerHTML = `
    <p class="lede">Type any vexor command. Reading runs at once; changes ask first; commands that delete or switch layouts ask you to type their name. Interactive ones (shell, exec, logtest, config edit) stay in SSH.</p>
    <form class="term" data-term><span class="term__p">vexor</span><input class="in in--term" name="cmd" list="vx-suggest" placeholder="suricata alerts --since 1h" autocomplete="off" spellcheck="false" autofocus><button class="btn btn--primary btn--sm">Run</button></form>
    <datalist id="vx-suggest">${SUGGEST.map((s) => `<option value="${esc(s)}">`).join("")}</datalist>
    <div class="chips">${SUGGEST.slice(0, 14).map((s) => `<button type="button" class="chip" data-fill="${esc(s)}">${esc(s)}</button>`).join("")}</div>
    <h2 class="sub">History</h2><ol class="hist" data-hist></ol>`;
  const f = $("[data-term]"), inp = $("[name=cmd]", f);
  const hist = JSON.parse(sessionStorage.getItem("vx-hist") || "[]");
  const drawHist = () => ($("[data-hist]").innerHTML = hist.slice(0, 20).map((h) => `<li><button type="button" class="link-btn mono" data-fill="${esc(h)}">vexor ${esc(h)}</button></li>`).join("") || '<li class="muted">Nothing yet.</li>');
  drawHist();
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const c = inp.value.trim().replace(/^vexor\s+/, "");
    if (!c) return;
    const ok = await run(c);
    if (ok) { hist.unshift(c); try { sessionStorage.setItem("vx-hist", JSON.stringify([...new Set(hist)].slice(0, 30))); } catch { /* private mode */ } drawHist(); inp.select(); }
  });
  view().onclick = (e) => { const b = e.target.closest("[data-fill]"); if (b) { inp.value = b.dataset.fill; inp.focus(); } };
}

async function vActivity() {
  setTitle("Activity");
  loading("activity");
  const [{ data: jobs }, { data: log }] = await Promise.all([api("/api/jobs"), api("/api/audit")]);
  view().innerHTML = `
    <section class="block"><h2>Commands this session of the console</h2>
      <div class="table-wrap"><table class="table"><thead><tr><th>Started</th><th>Command</th><th>By</th><th>Result</th><th></th></tr></thead>
      <tbody>${jobs.map((j) => `<tr><td class="num small">${new Date(j.started * 1000).toLocaleTimeString()}</td><td class="mono small">${esc(j.cmd)}</td><td>${esc(j.user)}</td>
        <td>${j.ended ? pill(j.code === 0 ? "done" : "exit " + j.code, j.code === 0 ? "ok" : "bad") : pill("running", "warn")}</td>
        <td><button type="button" class="btn btn--sm btn--ghost" data-job='${esc(JSON.stringify(j))}'>Output</button></td></tr>`).join("") || '<tr><td colspan="5" class="muted">No commands yet.</td></tr>'}</tbody></table></div></section>
    <section class="block"><h2>Audit log</h2><pre class="audit">${esc(log.join("\n")) || "empty"}</pre><p class="muted small">Kept in .state/console-audit.log on the host.</p></section>`;
  $$("[data-job]").forEach((b) => b.addEventListener("click", () => openJob(JSON.parse(b.dataset.job))));
}

async function vLogins() {
  setTitle("Logins");
  loading("logins");
  const { data: rows } = await api("/api/logins");
  view().innerHTML = `
    <p class="lede">Every login Vexor manages, for the stacks and tools that are on. Passwords stay hidden until you show or copy one; each one you reveal is written to the audit log. Same as <code>vexor login</code> on the host.</p>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>Service</th><th>Address</th><th>User</th><th>Password</th><th>About</th></tr></thead>
      <tbody>${rows.map((r) => `<tr>
        <td><b>${esc(r.name)}</b><div class="muted small mono">${esc(r.service)}</div></td>
        <td class="mono small">${r.url && /^https:\/\//.test(r.url) && !/\/\/(127\.0\.0\.1|localhost|wazuh[\w.]*|n8n|elasticsearch|kibana)[:/]/.test(r.url) ? `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.url)}</a>` : esc(r.url || "-")}</td>
        <td class="mono">${esc(r.user || "-")}${r.user && !r.user.startsWith("(") ? ` <button type="button" class="link-btn small" data-copy-text="${esc(r.user)}">copy</button>` : ""}</td>
        <td class="mono">${r.hasPassword ? `<span class="secret" data-secret="${esc(r.id)}">••••••••••</span>
            <button type="button" class="btn btn--xs btn--ghost" data-show="${esc(r.id)}">Show</button>
            <button type="button" class="btn btn--xs btn--ghost" data-copy-secret="${esc(r.id)}">Copy</button>` : r.key ? pill("not generated yet", "warn") : '<span class="muted">-</span>'}</td>
        <td class="small muted">${esc(r.note)}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">Nothing enabled has a login.</td></tr>'}</tbody></table></div>
    <p class="muted small">Grafana and Portainer apply their admin password on first start only; if you changed it inside the tool, Vexor no longer knows it. n8n keeps its own accounts.</p>`;
  const reveal = async (id) => {
    const { status, data } = await api("/api/logins/reveal", { body: { id } });
    if (status !== 200) { toast(data.error || "Could not read the password.", "bad"); return null; }
    return data.password;
  };
  const copyText = async (t) => { try { await navigator.clipboard.writeText(t); toast("Copied."); } catch { toast("Copy is blocked here; use Show and select it.", "bad"); } };
  view().onclick = async (e) => {
    const sh = e.target.closest("[data-show]"), cp = e.target.closest("[data-copy-secret]"), cu = e.target.closest("[data-copy-text]");
    if (sh) {
      const span = $(`[data-secret="${sh.dataset.show}"]`);
      if (sh.textContent === "Hide") { span.textContent = "••••••••••"; sh.textContent = "Show"; return; }
      const pw = await reveal(sh.dataset.show);
      if (pw != null) { span.textContent = pw; sh.textContent = "Hide"; setTimeout(() => { span.textContent = "••••••••••"; sh.textContent = "Show"; }, 30000); }
    }
    if (cp) { const pw = await reveal(cp.dataset.copySecret); if (pw != null) copyText(pw); }
    if (cu) copyText(cu.dataset.copyText);
  };
}

// ---------------------------------------------------------------- map
// Live map of the project's containers from /api/map: role layers top to bottom, edges only for connections the
// server saw in /proc. Polls every 3 s while the page is visible and #map is open.
const MAP_LAYERS = [
  ["external", "Outside the project"], ["edge", "Edge"], ["ingest", "Managers and ingest"], ["data", "Indexers and storage"],
  ["ui", "Dashboards"], ["tools", "Tools"], ["other", "Other containers"],
];
const MAP_STATUS = { ok: "running", issue: "issue", offline: "offline", missing: "missing" };
const SVG_NS = "http://www.w3.org/2000/svg";
let mapTimer = null, mapGen = 0, mapData = null, mapSel = null, mapRO = null;
function stopMap() { clearTimeout(mapTimer); mapTimer = null; mapGen++; mapRO?.disconnect(); mapRO = null; }
function mapLayer(n) {
  const s = n.service || "";
  if (n.id === "external") return "external";
  if (/nginx|proxy/.test(s)) return "edge";
  if (/^wazuh\d*\.(master|worker)$|^logstash/.test(s)) return "ingest";
  if (/indexer$|^elasticsearch/.test(s)) return "data";
  if (/dashboard$|^kibana/.test(s)) return "ui";
  if (/^(n8n|grafana|portainer|suricata|zeek)/.test(s)) return "tools";
  return "other";
}
const fmtRate = (b) => (b == null ? "–" : b >= 1e6 ? (b / 1e6).toFixed(1) + " MB/s" : b >= 1e3 ? (b / 1e3).toFixed(1) + " KB/s" : Math.round(b) + " B/s");
const nodeRate = (n) => (n?.traffic && n.traffic.rxRate != null ? n.traffic.rxRate + n.traffic.txRate : null);
function nodeStateText(n) {
  if (n.status === "missing") return "no container";
  if (n.state === "exited") return `exited (${n.exitCode ?? "?"})`;
  return n.state + (n.health ? ` · ${n.health}` : "");
}
function nodeRateText(n) {
  if (!n.traffic) return n.status === "ok" || n.status === "issue" ? (n.note ? "host network" : "no counters") : "";
  if (n.traffic.rxRate == null) return "measuring…";
  return `↓${fmtRate(n.traffic.rxRate)} ↑${fmtRate(n.traffic.txRate)}`;
}

function mapLayout(d, W) {
  const narrow = W < 560;
  const nw = narrow ? Math.min(168, Math.floor((W - 26) / 2)) : 168, nh = narrow ? 58 : 64, gx = narrow ? 10 : 22, pad = narrow ? 8 : 16, labelH = 20, gapY = narrow ? 34 : 44, cg = narrow ? 24 : 32;
  const ext = d.external || {};
  const nodes = [...d.nodes];
  if ((ext.inbound || 0) + (ext.outbound || 0) > 0) nodes.unshift({ id: "external", service: "External", status: "external", external: ext });
  const perRow = Math.max(1, Math.floor((W - 2 * pad + gx) / (nw + gx)));
  const pos = {}, labels = [];
  let y = pad;
  for (const [lid, label] of MAP_LAYERS) {
    const row = nodes.filter((n) => mapLayer(n) === lid);
    if (!row.length) continue;
    labels.push({ y: y + 12, label });
    let above = y - gapY / 2;            // middle of the gap above the row: where routed edges run sideways
    y += labelH;
    for (let i = 0; i < row.length; i += perRow) {
      const chunk = row.slice(i, i + perRow), more = i + perRow < row.length;
      const span = chunk.length * nw + (chunk.length - 1) * gx;
      let x = Math.max(pad, (W - span) / 2);
      const below = y + nh + (more ? cg : gapY) / 2;
      for (const n of chunk) { pos[n.id] = { x, y, w: nw, h: nh, n, above, below }; x += nw + gx; }
      y += nh + (more ? cg : gapY);
      above = y - cg / 2;
    }
  }
  return { pos, labels, W, H: Math.max(y - gapY + pad, 120), narrow };
}

function roundedPath(pts, r = 10) {
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 1; i < pts.length - 1; i++) {
    const [px, py] = pts[i - 1], [cx, cy] = pts[i], [nx, ny] = pts[i + 1];
    const d1 = Math.hypot(cx - px, cy - py), d2 = Math.hypot(nx - cx, ny - cy), rr = Math.min(r, d1 / 2, d2 / 2);
    if (!d1 || !d2) continue;
    const b = [cx - ((cx - px) / d1) * rr, cy - ((cy - py) / d1) * rr], a = [cx + ((nx - cx) / d2) * rr, cy + ((ny - cy) / d2) * rr];
    d += ` L${b[0].toFixed(1)},${b[1].toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${a[0].toFixed(1)},${a[1].toFixed(1)}`;
  }
  const z = pts[pts.length - 1];
  return d + ` L${z[0].toFixed(1)},${z[1].toFixed(1)}`;
}

function drawMap(d) {
  const wrap = $("[data-map-wrap]");
  if (!wrap) return;
  const W = Math.max(300, Math.round(wrap.clientWidth));
  const L = mapLayout(d, W);
  const live = (id) => (id === "external" ? true : (nodeRate(L.pos[id]?.n) || 0) > 0);
  // one drawn edge per client -> server pair; ports and counts are summed into it
  const pairs = {};
  for (const e of d.edges || []) {
    if (!L.pos[e.from] || !L.pos[e.to]) continue;
    const k = e.from + "\u0000" + e.to;
    (pairs[k] ||= { from: e.from, to: e.to, count: 0, ports: [] });
    pairs[k].count += e.count;
    pairs[k].ports.push(`${e.port}${e.proto === "udp" ? "/udp" : ""}${e.count > 1 ? " ×" + e.count : ""}`);
  }
  const lanes = { l: 0, r: 0 };
  const edgeSvg = Object.values(pairs).map((p) => {
    const a = L.pos[p.from], b = L.pos[p.to];
    const back = pairs[p.to + "\u0000" + p.from] ? (p.from < p.to ? -6 : 6) : 0;
    const ax = a.x + a.w / 2 + back, bx = b.x + b.w / 2 + back;
    let path, mx, my;
    if (Math.abs(a.y - b.y) < 1) {          // same row: arc over the top
      const y0 = a.y, lift = Math.min(40, 14 + Math.abs(ax - bx) / 6);
      path = `M${ax},${y0} C${ax},${y0 - lift} ${bx},${y0 - lift} ${bx},${y0 - 3}`;
      mx = (ax + bx) / 2; my = y0 - lift * 0.75;
    } else {
      const down = b.y > a.y;
      const [top, bot] = down ? [a, b] : [b, a];
      const tx = down ? ax : bx, bx2 = down ? bx : ax;
      const between = Object.values(L.pos).filter((q) => q.y > top.y + 1 && q.y < bot.y - 1);
      if (!between.length) {                 // neighbouring rows: one curve
        const y1 = down ? a.y + a.h : a.y, y2 = down ? b.y - 3 : b.y + b.h + 3, ym = (y1 + y2) / 2;
        path = `M${ax},${y1} C${ax},${ym} ${bx},${ym} ${bx},${y2}`;
        mx = (ax + bx) / 2; my = ym;
      } else {                               // rows in between: run down a lane beside them, never through a node
        const right = (ax + bx) / 2 >= L.W / 2;
        const k = right ? lanes.r++ : lanes.l++;
        const lx = Math.min(L.W - 3, Math.max(3, right ? Math.max(...between.map((q) => q.x + q.w)) + 12 + k * 7 : Math.min(...between.map((q) => q.x)) - 12 - k * 7));
        let pts = [[tx, top.y + top.h + (down ? 0 : 3)], [tx, top.below], [lx, top.below], [lx, bot.above], [bx2, bot.above], [bx2, bot.y - (down ? 3 : 0)]];
        if (!down) pts = pts.reverse();
        path = roundedPath(pts);
        mx = lx; my = (top.below + bot.above) / 2;
      }
    }
    const isLive = live(p.from) && live(p.to);
    const w = Math.min(7, 1.25 + Math.log2(p.count + 1) * 1.3).toFixed(2);
    const title = `${a.n.service} → ${b.n.service}: ${p.ports.join(", ")} (${p.count} established)`;
    return `<g class="medge ${isLive ? "is-live" : ""}"><title>${esc(title)}</title>
      <path class="medge__line" d="${path}" stroke-width="${w}" marker-end="url(#map-arrow)"/>
      ${L.narrow ? "" : `<text class="medge__lbl" x="${mx.toFixed(1)}" y="${(my + 4).toFixed(1)}" text-anchor="middle">${esc(p.ports.slice(0, 2).join(", ") + (p.ports.length > 2 ? " …" : ""))}</text>`}</g>`;
  }).join("");
  const cut = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
  const nodeSvg = Object.values(L.pos).map(({ x, y, w, h, n }) => {
    const ext = n.id === "external";
    const l2 = ext ? `${n.external.inbound} in · ${n.external.outbound} out` : nodeStateText(n);
    const l3 = ext ? `${n.external.peers} peer${n.external.peers === 1 ? "" : "s"}` : nodeRateText(n);
    const badge = !ext && n.restarts > 0 ? `<g class="mnode__badge"><rect x="${w - 34}" y="-9" width="40" height="18" rx="9"/><text x="${w - 14}" y="4" text-anchor="middle">↻${n.restarts}</text></g>` : "";
    const room = w - 16;             // characters that fit: mono name ~7.6 px, body text ~6 px, mono rate ~6.4 px
    return `<g class="mnode mnode--${n.status} ${mapSel === n.id ? "is-sel" : ""}" transform="translate(${x.toFixed(1)},${y.toFixed(1)})" data-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(n.service + ": " + (MAP_STATUS[n.status] || "outside connections") + ", " + l2)}">
      <rect class="mnode__box" width="${w}" height="${h}" rx="6"/><rect class="mnode__bar" width="4" height="${h}" rx="2"/>
      <text class="mnode__name" x="12" y="${L.narrow ? 18 : 20}">${esc(cut(n.service, Math.floor((room - (n.restarts > 0 ? 34 : 0)) / 7.6)))}</text>
      <text class="mnode__st" x="12" y="${L.narrow ? 34 : 38}">${esc(cut(l2, Math.floor(room / 6)))}</text>
      <text class="mnode__rate" x="12" y="${L.narrow ? 49 : 54}">${esc(cut(l3, Math.floor(room / 6.4)))}</text>${badge}</g>`;
  }).join("");
  const svg = $("[data-map-svg]");
  svg.setAttribute("viewBox", `0 0 ${L.W} ${L.H}`);
  svg.setAttribute("height", L.H);
  svg.innerHTML = `<defs><marker id="map-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" orient="auto-start-reverse" markerUnits="userSpaceOnUse"><path d="M0,0 L10,5 L0,10 z" class="medge__head"/></marker></defs>
    ${L.labels.map((l) => `<text class="mlayer" x="${L.narrow ? 8 : 16}" y="${l.y}">${esc(l.label.toUpperCase())}</text>`).join("")}
    <g>${edgeSvg}</g><g>${nodeSvg}</g>`;
}

function mapSummary(d) {
  const ns = d.nodes, by = (s) => ns.filter((n) => n.status === s).length;
  const rates = ns.filter((n) => n.traffic);
  const measured = rates.filter((n) => n.traffic.rxRate != null);
  const rx = measured.reduce((a, n) => a + n.traffic.rxRate, 0), tx = measured.reduce((a, n) => a + n.traffic.txRate, 0);
  const ext = d.external || {};
  $("[data-map-sum]").innerHTML = [
    pill(`${ns.filter((n) => n.state === "running").length} running`, "ok"),
    by("issue") ? pill(`${by("issue")} issue${by("issue") > 1 ? "s" : ""}`, "warn") : pill("0 issues"),
    by("offline") + by("missing") ? pill(`${by("offline")} offline · ${by("missing")} missing`, "bad") : pill("0 offline"),
    rates.length ? pill(measured.length ? `in ${fmtRate(rx)} · out ${fmtRate(tx)}` : "rates: measuring…") : "",
    d.limits ? "" : pill(`external: ${ext.inbound || 0} in · ${ext.outbound || 0} out`),
  ].join(" ");
  $("[data-map-nets]").textContent = d.networks.length ? `Project ${d.project} · networks: ${d.networks.map((n) => `${n.name} (${n.containers})`).join(", ")}` : `Project ${d.project}`;
  const lim = $("[data-map-limits]");
  lim.hidden = !d.limits;
  lim.textContent = d.limits || "";
}

function mapPanel(d) {
  const panel = $("[data-map-panel]");
  const n = mapSel === "external" ? { id: "external" } : d.nodes.find((x) => x.id === mapSel);
  if (!n) { panel.innerHTML = `<p class="muted small">Select a container on the map to see its state, networks, ports and connections.</p>`; return; }
  const dl = (rows) => `<dl class="kv">${rows.filter(([, v]) => v !== "" && v != null).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
  const name = (id) => esc(id === "external" ? "External" : d.nodes.find((x) => x.id === id)?.service || id);
  if (n.id === "external") {
    const ext = d.external || {};
    const rows = d.nodes.flatMap((x) => (x.connections || []).filter((c) => c.peer === "external").map((c) => ({ ...c, svc: x.service })));
    panel.innerHTML = `<h2>External</h2><p class="muted small">Connections to and from addresses outside the project's networks: agents, browsers, other hosts. Connections through a published port can show the Docker gateway as their address.</p>
      ${dl([["Inbound", ext.inbound], ["Outbound", ext.outbound], ["Peers", ext.peers], ["Ports", esc(Object.entries(ext.ports || {}).map(([p, c]) => `${p} ×${c}`).join(", "))]])}
      <h3>Connections</h3><ul class="conns">${rows.map((c) => `<li><span>${c.dir === "in" ? "in → " + esc(c.svc) : esc(c.svc) + " → out"} :${c.port}${c.proto === "udp" ? "/udp" : ""}</span><span class="muted">${c.count} · ${esc(c.ips.join(", "))}</span></li>`).join("") || '<li class="muted">None.</li>'}</ul>`;
    return;
  }
  const t = n.traffic;
  const svc = n.service;
  const conns = n.connections;
  panel.innerHTML = `<h2>${esc(svc)}</h2>
    <p>${pill(MAP_STATUS[n.status] || n.status, { ok: "ok", issue: "warn", offline: "bad", missing: "bad" }[n.status])} ${n.reasons?.length ? `<span class="small">${esc(n.reasons.join("; "))}</span>` : ""}</p>
    ${dl([["Container", esc(n.name)], ["State", esc(n.state)], ["Health", esc(n.health || "no healthcheck")], ["Restarts", n.restarts],
      ["Exit code", n.state === "running" || n.exitCode == null ? "" : esc(n.exitCode)], ["Out of memory", n.oom ? "yes, OOM-killed" : ""],
      ["Started", n.startedAt && !n.startedAt.startsWith("0001") ? esc(new Date(n.startedAt).toLocaleString()) : ""],
      ["Image", n.image ? `<span class="mono small">${esc(n.image)}</span>` : ""],
      ["Networks", (n.networks || []).map((x) => `<span class="mono small">${esc(x.name)} ${esc(x.ip || "")}${x.ip6 ? " " + esc(x.ip6) : ""}</span>`).join("<br>") || (n.networkMode === "host" ? "host" : "")],
      ["Listening", n.listening ? esc(n.listening.map((l) => l.port + (l.proto === "udp" ? "/udp" : "")).join(", ") || "none") : ""],
      ["Received", t ? `${esc(fmtBytes(t.rxBytes))} · ${esc(t.rxRate == null ? "rate on next sample" : fmtRate(t.rxRate))}` : ""],
      ["Sent", t ? `${esc(fmtBytes(t.txBytes))} · ${esc(t.txRate == null ? "rate on next sample" : fmtRate(t.txRate))}` : ""],
      ["Errors / drops", t ? `rx ${t.rxErrors} / ${t.rxDrops} · tx ${t.txErrors} / ${t.txDrops}` : ""]])}
    ${n.note ? `<p class="muted small">${esc(n.note)}</p>` : ""}
    ${conns ? `<h3>Connections</h3><ul class="conns">${conns.map((c) => `<li><span>${c.dir === "in" ? "← from" : "→ to"} ${name(c.peer)} :${c.port}${c.proto === "udp" ? "/udp" : ""}</span><span class="muted">${c.count}${c.ips ? " · " + esc(c.ips.join(", ")) : ""}</span></li>`).join("") || '<li class="muted">No established connections.</li>'}</ul>` : ""}
    <div class="actions">${btn("Logs", ["logs", svc, "-n", "200"])}${n.state === "running" ? btn("Restart", ["restart", svc]) : btn("Start", ["start", svc], "btn--primary")}</div>`;
  bindRunButtons(panel);
}

async function vMap() {
  setTitle("Map", `<span class="muted small" data-map-age></span>`);
  stopMap();
  const gen = mapGen;
  view().innerHTML = `
    <p class="lede">Vexor's containers, their networks and the connections between them, read live from Docker and each container's network namespace. Lines appear only for connections that are open now; they move while both ends carry traffic.</p>
    <div class="map-sum" data-map-sum><span class="muted">Loading the map…</span></div>
    <p class="map-limits" data-map-limits hidden></p>
    <div class="map-layout">
      <figure class="map-canvas" data-map-wrap><svg class="map-svg" data-map-svg role="group" aria-label="Container map" width="100%"></svg></figure>
      <aside class="map-panel" data-map-panel aria-live="polite"></aside>
    </div>
    <p class="muted small" data-map-nets></p>
    <ul class="map-legend" aria-label="Legend">
      <li><i class="lg lg--ok"></i>running</li><li><i class="lg lg--issue"></i>issue (unhealthy, restarting, 3+ restarts, OOM, network errors)</li>
      <li><i class="lg lg--offline"></i>offline (exited, created)</li><li><i class="lg lg--missing"></i>missing (the layout expects it)</li>
      <li><i class="lg lg--edge"></i>open connection, client → server (thicker = more)</li><li><i class="lg lg--live"></i>moving: both ends had traffic in the last 3 s</li>
    </ul>`;
  mapPanel({ nodes: [] });
  const svg = $("[data-map-svg]");
  const pick = (g) => { if (!g || !mapData) return; mapSel = g.dataset.node; drawMap(mapData); mapPanel(mapData); if (matchMedia("(max-width: 1080px)").matches) $("[data-map-panel]").scrollIntoView({ block: "nearest", behavior: "smooth" }); };
  svg.addEventListener("click", (e) => pick(e.target.closest("[data-node]")));
  svg.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(e.target.closest("[data-node]")); } });
  let lastW = 0;
  mapRO = new ResizeObserver(() => { const w = $("[data-map-wrap]")?.clientWidth || 0; if (mapData && Math.abs(w - lastW) > 4) { lastW = w; drawMap(mapData); } });
  mapRO.observe($("[data-map-wrap]"));
  const tick = async () => {
    if (gen !== mapGen || location.hash !== "#map") return;
    if (!document.hidden) {
      try {
        const { status, data } = await api("/api/map");
        if (gen !== mapGen) return;
        if (status === 200 && data.nodes) {
          mapData = data;
          if (mapSel && mapSel !== "external" && !data.nodes.some((n) => n.id === mapSel)) mapSel = null;
          drawMap(data); mapSummary(data); mapPanel(data);
          lastW = $("[data-map-wrap]").clientWidth;
          $("[data-map-age]").textContent = `updated ${new Date(data.time * 1000).toLocaleTimeString()}`;
          if (!data.nodes.length) $("[data-map-sum]").innerHTML = `<span class="muted">No containers in the Docker project <code>${esc(data.project)}</code>.</span>`;
        }
      } catch (e) { if (e.message === "login required") return; }
    }
    if (gen === mapGen) mapTimer = setTimeout(tick, 3000);
  };
  tick();
}

// ---------------------------------------------------------------- theme (auto -> light -> dark)
const THEMES = ["auto", "light", "dark"];
function themeNow() { try { return localStorage.getItem("vx-theme") || "auto"; } catch { return "auto"; } }
function setTheme(t) {
  if (t === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
  try { if (t === "auto") localStorage.removeItem("vx-theme"); else localStorage.setItem("vx-theme", t); } catch { /* storage blocked */ }
  $("[data-theme-toggle]").textContent = `Theme: ${t}`;
}
$("[data-theme-toggle]").addEventListener("click", () => setTheme(THEMES[(THEMES.indexOf(themeNow()) + 1) % THEMES.length]));
setTheme(themeNow());

// ---------------------------------------------------------------- router
const ROUTES = { overview: vOverview, map: vMap, containers: vContainers, ports: vPorts, volumes: vVolumes, stacks: vStacks, health: vHealth, logins: vLogins, settings: vSettings, terminal: vTerminal, activity: vActivity, reset: vReset };
let routing = false, again = null;
async function route(soft = false) {
  if (routing) { again = again === false ? false : soft; return; }   // a page change while one loads runs after it
  if (!soft) view().onclick = null;
  const key = (location.hash || "#overview").slice(1);
  const fn = ROUTES[key] || vOverview;
  if (key !== "map") stopMap();
  $$("[data-nav] a").forEach((a) => a.setAttribute("aria-current", a.getAttribute("href") === "#" + key ? "page" : "false"));
  if (soft && ["settings", "terminal", "ports"].includes(key)) return;
  routing = true;
  try { await fn(); } catch (e) { if (e.message !== "login required") view().innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  routing = false;
  if (again !== null) { const s = again; again = null; route(s); }
}
window.addEventListener("hashchange", () => route());
$("[data-refresh]").addEventListener("click", () => route());
setInterval(() => { if (!document.hidden && ["", "#overview"].includes(location.hash) && !$("[data-confirm]").open) route(true); }, 15000);
boot();
