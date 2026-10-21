// Vexor Console - single-page UI over the console API. Every action is a vexor command run by the server.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
let CSRF = "";
let STATE = {};

// ---------------------------------------------------------------- API
const FRESH_OK = /^\/api\/(state|containers|disk|volumes|proxy)$/;   // endpoints the server caches; fresh=1 waits for new data
async function api(path, opts = {}) {
  if (!opts.body && opts.fresh && FRESH_OK.test(path.split("?")[0])) path += (path.includes("?") ? "&" : "?") + "fresh=1";
  const r = await fetch(path, {
    method: opts.body ? "POST" : "GET",
    headers: { "Content-Type": "application/json", "X-Vexor-CSRF": CSRF },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: "same-origin",
    signal: opts.signal,
  });
  if (r.status === 401 && path !== "/api/login") { showLogin(); throw new Error("login required"); }
  const data = await r.json().catch(() => ({}));
  if (r.status === 403 && data.code === "password_change_required") { showPasswordChange(); throw new Error("login required"); }
  return { status: r.status, data };
}

// ---------------------------------------------------------------- login
function showLogin() { stopLive(); $("[data-app]").hidden = true; $("[data-pw]").hidden = true; $("[data-login]").hidden = false; $("[name=password]").focus(); }
function showPasswordChange() { stopLive(); $("[data-app]").hidden = true; $("[data-login]").hidden = true; $("[data-pw]").hidden = false; $("[name=current]").focus(); }
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
  $("[data-out-cmd]").title = job.cmd;
  $("[data-out-cmd]").classList.remove("is-full");
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
    afterJob();
  });
  es.onerror = () => { $("[data-out-st]").textContent = "disconnected"; es.close(); };
}
// copy to the clipboard (falls back to a hidden textarea where the Clipboard API is blocked)
async function copyText(text, btn) {
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch {
    const t = document.createElement("textarea"); t.value = text; t.setAttribute("readonly", ""); t.style.position = "fixed"; t.style.opacity = "0";
    document.body.appendChild(t); t.select(); try { ok = document.execCommand("copy"); } catch { ok = false; } t.remove();
  }
  toast(ok ? "Copied." : "Copy is blocked here - select the text instead.", ok ? "" : "bad");
  if (ok && btn) { btn.classList.add("is-copied"); setTimeout(() => btn.classList.remove("is-copied"), 1200); }
}
// long command: shortened with a fade; hovering (or focusing) it for 3 s shows it in full; a tap toggles
{
  const cmd = $("[data-out-cmd]"); let t = null;
  const full = (on) => { clearTimeout(t); cmd.classList.toggle("is-full", on); };
  cmd.addEventListener("mouseenter", () => { clearTimeout(t); t = setTimeout(() => full(true), 3000); });
  cmd.addEventListener("mouseleave", () => full(false));
  cmd.addEventListener("focus", () => { clearTimeout(t); t = setTimeout(() => full(true), 3000); });
  cmd.addEventListener("blur", () => full(false));
  cmd.addEventListener("click", () => full(!cmd.classList.contains("is-full")));
}
$("[data-copy-cmd]").addEventListener("click", (e) => copyText($("[data-out-cmd]").textContent, e.currentTarget));
$("[data-copy-out]").addEventListener("click", (e) => copyText($("[data-out-body]").textContent.replace(/\n$/, ""), e.currentTarget));
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
// One delegated listener for every [data-run] button, so buttons that a quiet refresh adds work without re-binding.
$("[data-view]").addEventListener("click", (e) => {
  const b = e.target.closest("[data-run]");
  if (!b) return;
  let args = JSON.parse(b.dataset.run);
  const form = b.closest("[data-form]");
  if (form) {
    const vals = Object.fromEntries(new FormData(form));
    args = args.flatMap((a) => { const m = /^\{(\w+)\}$/.exec(a); return m ? (vals[m[1]] ? [vals[m[1]]] : []) : [a]; });
  }
  run(args, { text: b.dataset.text });
});
function setMeta(html) { const m = $("[data-topmeta]"); if (m.dataset.html !== html) { m.innerHTML = html; m.dataset.html = html; } }
function setTitle(t, meta = "") { $("[data-title]").textContent = t; setMeta(meta); document.title = `${t} · Vexor Console`; }
const view = () => $("[data-view]");
// The placeholder shows only before a page's first paint; refreshes update the page in place.
const loading = (what) => { if (view().dataset.page !== PAGE.key) view().innerHTML = `<p class="muted">Loading ${esc(what)}…</p>`; };
const SK = '<span class="skel" aria-hidden="true">…</span>';

// ---------------------------------------------------------------- quiet rendering
// paint() replaces the view on a page's first render; after that it morphs the live DOM into the new markup, touching
// only what changed. Nodes are matched by key (data-key, data-svc, data-node, id) or position, so focus, scroll, typed
// text, checked boxes, open <details> and the row a ⋯ menu belongs to all survive a refresh.
const KEY_ATTRS = ["data-key", "data-svc", "data-node", "id"];
function keyOf(n) {
  if (n.nodeType !== 1) return null;
  for (const a of KEY_ATTRS) { const v = n.getAttribute(a); if (v != null) return `${n.nodeName}|${a}=${v}`; }
  return null;
}
const keepAttr = (el, name) => name === "style" || name === "aria-expanded" || (name === "open" && (el.tagName === "DETAILS" || el.tagName === "DIALOG"));
function syncAttrs(el, to) {
  if (el === document.activeElement && /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName)) return;
  for (const { name } of [...el.attributes]) if (!to.hasAttribute(name) && !keepAttr(el, name)) el.removeAttribute(name);
  for (const { name, value } of [...to.attributes]) if (el.getAttribute(name) !== value && !keepAttr(el, name)) el.setAttribute(name, value);
}
function morphChildren(from, to) {
  const old = [...from.childNodes], neu = [...to.childNodes], keyed = new Map(), used = new Set();
  old.forEach((n) => { const k = keyOf(n); if (k) keyed.set(k, n); });
  neu.forEach((nn, i) => {
    const k = keyOf(nn), cand = old[i];
    const match = k ? keyed.get(k) : cand && cand.nodeName === nn.nodeName && !keyOf(cand) ? cand : null;
    const ref = from.childNodes[i] || null;
    if (match && !used.has(match)) {
      used.add(match);
      if (match.nodeType === 1) {
        syncAttrs(match, nn);
        if (!(match === document.activeElement && match.tagName === "SELECT") && match.tagName !== "TEXTAREA") morphChildren(match, nn);
      } else if (match.nodeValue !== nn.nodeValue) match.nodeValue = nn.nodeValue;
      if (ref !== match) from.insertBefore(match, ref);
    } else from.insertBefore(nn, ref);
  });
  while (from.childNodes.length > neu.length) from.lastChild.remove();
}
function morphInto(root, html, svg = false) {
  const t = document.createElement("template");
  t.innerHTML = svg ? `<svg xmlns="${SVG_NS}">${html}</svg>` : html;
  morphChildren(root, svg ? t.content.firstElementChild : t.content);
}
function paint(html) {
  const v = view();
  if (v.dataset.page !== PAGE.key) { v.innerHTML = html; v.dataset.page = PAGE.key; } else morphInto(v, html);
  $$("[data-w]", v).forEach((i) => (i.style.transform = `scaleX(${i.dataset.w})`));
}
// GET for the current page: aborted when the page changes, kept as the page's last data for an instant repaint.
const LAST = {};
async function get(path) {
  const pg = PAGE;
  const r = await api(path, { signal: pg.ctl.signal, fresh: pg.fresh });
  if (pg.ctl.signal.aborted) throw new DOMException("page changed", "AbortError");
  if (r.status === 200) LAST[path] = r.data;
  return r;
}
// One endpoint: paint the last data at once (or a placeholder), then the new data.
async function load1(path, what, render) {
  if (!PAGE.soft) { if (LAST[path] !== undefined) render(LAST[path]); else loading(what); }
  const { status, data } = await get(path);
  if (data && typeof data === "object" && !Array.isArray(data)) Object.defineProperty(data, "httpStatus", { value: status, enumerable: false });
  render(data);
}
// Several endpoints fetched in parallel. A first render paints each part as it arrives; a refresh paints once at the end.
async function progressive(paths, draw) {
  const pg = PAGE, D = paths.map((p) => LAST[p]);
  if (!pg.soft) draw(D);
  await Promise.all(paths.map((p, i) => get(p).then(({ data }) => { D[i] = data; if (!pg.soft) draw(D); })));
  if (pg.soft) draw(D);
}
function stateLine(c) {
  const st = c.state === "running" ? (c.health && c.health !== "healthy" ? "warn" : "ok") : "bad";
  return pill(c.state + (c.health ? ` · ${c.health}` : ""), st);
}

// ---------------------------------------------------------------- views
const fmtBytes = (b) => (b >= 1e12 ? (b / 1e12).toFixed(1) + " TB" : b >= 1e9 ? (b / 1e9).toFixed(1) + " GB" : b >= 1e6 ? (b / 1e6).toFixed(0) + " MB" : b >= 1e3 ? (b / 1e3).toFixed(0) + " KB" : (b || 0) + " B");
async function vOverview() {
  setTitle("Overview");
  await progressive(["/api/state", "/api/containers?lite=1", "/api/pending", "/api/disk"], ([s, cs, pend, dk]) => paint(overviewHtml(s, cs, pend, dk)));
}
// Any of the four parts may still be on its way (first visit): those show a placeholder until they arrive.
const diskLevel = (pct) => (pct >= 95 ? "bad" : pct >= 85 ? "warn" : "");
function overviewHtml(st, csIn, pendIn, dk) {
  const s = st || {}, cs = csIn || [], pend = pendIn || {};
  const fss = dk?.filesystems || [];
  const worst = fss.reduce((a, f) => (!a || f.pct > a.pct ? f : a), null);
  if (st) STATE = s;
  const exp = s.services || [];
  const running = exp.length - exp.filter((x) => !cs.some((c) => c.service === x && c.state === "running")).length;   // of the services the layout expects
  const missing = exp.filter((x) => !cs.some((c) => c.service === x && c.state === "running"));
  const hl = s.health_last || {};
  if (st) setMeta(`${pill("vexor " + (s.vexor || "?"))} ${pill("Wazuh " + (s.wazuh_version || "?"))}`);
  const urls = Object.entries(s.urls || {}).filter(([, u]) => u);
  const diskPct = worst?.pct ?? s.disk?.pct;
  const rem = s.reminders || [];
  return `
    <section class="cards">
      <article class="card"><h2>Stack</h2><p class="big">${st ? `SOC=${esc(s.soc)}` : SK}</p><p class="muted">${esc(s.layout || "")}</p></article>
      <article class="card ${!st || !csIn || !missing.length ? "" : running === 0 && !s.stopped ? "card--bad" : "card--warn"}"><h2>Containers</h2><p class="big">${st && csIn ? `${running} / ${exp.length} running` : SK}</p>
        <p class="muted">${!st || !csIn ? "" : !missing.length ? "every enabled service is up" : s.stopped ? 'stopped with vexor stop - <a href="#containers">Start all</a> on Containers' : "not running: " + esc(missing.join(", "))}</p></article>
      <article class="card ${hl.fail > 0 ? "card--bad" : hl.warn > 0 ? "card--warn" : ""}"><h2>Last health check</h2>
        <p class="big">${!st ? SK : hl.epoch ? `${hl.pass} passed · ${hl.warn} warn · ${hl.fail} failed` : "not run yet"}</p>
        <p class="muted">${!st ? "" : hl.epoch ? new Date(hl.epoch * 1000).toLocaleString() : "the hourly timer runs it (vexor daemon install)"}</p></article>
      <article class="card ${diskLevel(diskPct ?? 0) ? "card--" + diskLevel(diskPct ?? 0) : ""}"><h2>Disk</h2><p class="big">${diskPct == null ? (st || dk ? "?% used" : SK) : `${esc(diskPct)}% used`}</p><p class="muted">${esc(worst ? worst.mount + " (fullest)" : s.disk?.path || "")} <a href="#storage">Storage</a></p></article>
    </section>
    ${s.legacy_project ? `<section class="pending"><p><b>The Docker project is still named <code>${esc(s.project)}</code>.</b> Vexor 2 names it <code>vexor</code>. <code>vexor migrate</code> copies and checks every volume, then switches. The old volumes are kept; once the stack works, run <code>vexor migrate --yes</code> in the Terminal to remove them. Take a backup first.</p><div class="actions">${btn("Migrate to vexor", ["migrate"], "btn--danger-ghost")}</div></section>` : ""}
    ${pend.keys?.length ? `<section class="pending"><p><b>${pend.keys.length} .env change${pend.keys.length > 1 ? "s" : ""} not applied yet:</b> <code>${esc(pend.keys.join(" "))}</code></p><div class="actions">${btn("Show plan", ["plan"])}${btn("Apply", ["config", "apply"], "btn--primary")}</div></section>` : ""}
    <section class="block"><h2>Quick actions</h2><div class="actions">${btn("Status", ["status"])}${btn("Wait until ready", ["wait-ready", "--timeout", "600"])}</div></section>
    <section class="block"><h2>Open</h2>
      <div class="links">${urls.map(([k, u]) => `<a class="linkcard" href="${esc(u)}" target="_blank" rel="noopener"><b>${esc(k)}</b><span>${esc(u)}</span></a>`).join("") || (st ? '<p class="muted">No web UIs enabled.</p>' : `<p class="muted">${SK}</p>`)}</div></section>
    <section class="block"><h2>Services</h2><div class="svc-grid">${st ? exp.map((x) => { const c = cs.find((y) => y.service === x); return `<a class="svc ${c?.state === "running" ? "" : "svc--down"}" href="#containers" data-key="${esc(x)}"><b>${esc(x)}</b>${c ? stateLine(c) : csIn ? pill("missing", "bad") : SK}</a>`; }).join("") : `<p class="muted">${SK}</p>`}</div></section>
    <section class="block" id="sec-health"><h2>Health</h2>
      <p class="muted">The doctor runs about 60 checks. With --fix it repairs what it safely can, the same as the hourly timer.</p>
      <div class="actions">${btn("Run doctor", ["doctor"], "btn--primary")}${btn("Doctor --fix", ["doctor", "--fix"])}${btn("Health details", ["health"])}${btn("Recent errors (1h)", ["logs", "errors", "--since", "1h"])}${btn("All reminders", ["reminders"])}${btn("AI report", ["ai-context", "--print"])}${btn("Watchdog pass", ["watchdog"])}</div>
      ${rem.length ? `<h3 class="sub3">Due reminders</h3><ul class="list">${rem.map((r) => `<li data-key="${esc(r.msg)}"><b>${esc(r.msg)}</b><code>${esc(r.cmd)}</code></li>`).join("")}</ul>` : ""}</section>
    <section class="block" id="sec-notify"><h2>Notifications</h2>
      <p class="muted">The hourly check sends problems it could not fix to <code>NOTIFY_URL</code> (Slack, Teams, Discord or any JSON webhook), or to your n8n webhook when that is empty. Set the URL and <code>NOTIFY_ON</code> under <a href="#settings">Settings</a>.</p>
      <div class="actions">${btn("Notification status", ["notify"])}${btn("Send a test", ["notify", "test"], "btn--primary")}</div></section>`;
}

// Row menu: one floating menu for the whole page, anchored to the button that opened it.
const MORE_ICON = '<svg class="ico" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="5" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="19" cy="12" r="1.2"/></svg>';
let openMenu = null;
function closeMenu(focusBack = true) {
  if (!openMenu) return;
  const { el, btn: b } = openMenu;
  openMenu = null;
  el.remove();
  b.setAttribute("aria-expanded", "false");
  if (focusBack) b.focus();
  document.removeEventListener("pointerdown", onMenuOutside, true);
  document.removeEventListener("keydown", onMenuKey, true);
  window.removeEventListener("resize", onMenuAway);
  window.removeEventListener("scroll", onMenuAway, true);
}
const onMenuOutside = (e) => { if (openMenu && !openMenu.el.contains(e.target) && !openMenu.btn.contains(e.target)) closeMenu(false); };
const onMenuAway = (e) => {
  if (!openMenu || (e && e.target instanceof Node && openMenu.el.contains(e.target))) return;
  const r = openMenu.btn.getBoundingClientRect(), o = openMenu.rect;       // a scroll that did not move the button is noise
  if (e?.type === "scroll" && Math.abs(r.top - o.top) < 2 && Math.abs(r.left - o.left) < 2) return;
  closeMenu(false);
};
function onMenuKey(e) {
  if (!openMenu) return;
  const items = $$('[role="menuitem"]', openMenu.el), i = items.indexOf(document.activeElement);
  const go = (n) => { e.preventDefault(); items[(n + items.length) % items.length].focus(); };
  if (e.key === "Escape") { e.preventDefault(); closeMenu(); }
  else if (e.key === "ArrowDown") go(i + 1);
  else if (e.key === "ArrowUp") go(i < 0 ? items.length - 1 : i - 1);
  else if (e.key === "Home") go(0);
  else if (e.key === "End") go(items.length - 1);
  else if (e.key === "Tab") closeMenu(false);
}
// items: [{label, onSelect}] or "-" for a divider
function showMenu(trigger, items, label) {
  closeMenu(false);
  const el = document.createElement("div");
  el.className = "menu";
  el.setAttribute("role", "menu");
  el.setAttribute("aria-label", label);
  items.forEach((it) => {
    if (it === "-") { const hr = document.createElement("hr"); hr.setAttribute("role", "separator"); el.appendChild(hr); return; }
    const b = document.createElement("button");
    b.type = "button"; b.setAttribute("role", "menuitem"); b.tabIndex = -1; b.textContent = it.label;
    b.addEventListener("click", () => { closeMenu(false); it.onSelect(); });
    el.appendChild(b);
  });
  el.style.visibility = "hidden";
  document.body.appendChild(el);
  const r = trigger.getBoundingClientRect(), w = el.offsetWidth, h = el.offsetHeight, vw = document.documentElement.clientWidth, vh = window.innerHeight, gap = 4, edge = 8;
  const below = vh - r.bottom - edge, above = r.top - edge;
  const up = below < h && above > below;                       // not enough room below: open upward
  let top = up ? r.top - h - gap : r.bottom + gap;
  top = Math.max(edge, Math.min(top, vh - h - edge));
  el.style.top = `${top}px`;
  el.style.left = `${Math.max(edge, Math.min(r.right - w, vw - w - edge))}px`;
  el.style.maxHeight = `${vh - 2 * edge}px`;
  el.style.overflowY = "auto";
  el.style.visibility = "";
  openMenu = { el, btn: trigger, rect: r };
  trigger.setAttribute("aria-expanded", "true");
  document.addEventListener("pointerdown", onMenuOutside, true);
  document.addEventListener("keydown", onMenuKey, true);
  window.addEventListener("resize", onMenuAway);
  window.addEventListener("scroll", onMenuAway, true);
  $('[role="menuitem"]', el).focus();
}

const SELECTED = new Set();   // container selection, keyed by service name; survives re-renders
let CS = [];                  // the containers on the page, for the ⋯ menu and bulk actions
function ctSync() {
  const boxes = $$("[data-sel]", view()), all = $("[data-sel-all]", view()), bar = $("[data-bulk]", view());
  if (!all || !bar) return;
  const n = boxes.filter((b) => b.checked).length;
  boxes.forEach((b) => b.closest("tr").classList.toggle("is-sel", b.checked));
  all.checked = n > 0 && n === boxes.length;
  all.indeterminate = n > 0 && n < boxes.length;
  bar.hidden = n === 0;
  $("[data-bulk-n]", bar).textContent = `${n} selected`;
}
async function vContainers() {
  setTitle("Containers");
  view().onchange = (e) => {
    const b = e.target;
    if (b.matches("[data-sel]")) b.checked ? SELECTED.add(b.dataset.sel) : SELECTED.delete(b.dataset.sel);
    else if (b.matches("[data-sel-all]")) $$("[data-sel]", view()).forEach((x) => { x.checked = b.checked; b.checked ? SELECTED.add(x.dataset.sel) : SELECTED.delete(x.dataset.sel); });
    else return;
    ctSync();
  };
  view().onclick = (e) => {
    const act = e.target.closest("[data-bulk-act]"), more = e.target.closest("[data-more]");
    if (act) {
      const sel = CS.map((c) => c.service).filter((n) => SELECTED.has(n)), k = act.dataset.bulkAct;
      if (k === "clear") { SELECTED.clear(); $$("[data-sel]", view()).forEach((x) => (x.checked = false)); ctSync(); return; }
      if (sel.length) run(k === "logs" ? ["logs", "-n", "300", ...sel] : [k, ...sel]);   // start/stop/restart/logs accept several services
    }
    if (more) {
      if (openMenu?.btn === more) return closeMenu();
      const c = CS.find((x) => x.service === more.dataset.more);
      if (!c) return;
      showMenu(more, [
        { label: "Logs (last 300)", onSelect: () => run(["logs", c.service, "-n", "300"]) },
        { label: "Follow logs", onSelect: () => run(["logs", c.service, "-f", "-n", "50"]) },
        "-",
        { label: "Restart", onSelect: () => run(["restart", c.service]) },
        c.state === "running" ? { label: "Stop", onSelect: () => run(["stop", c.service]) } : { label: "Start", onSelect: () => run(["start", c.service]) },
        "-",
        { label: "Show on map", onSelect: () => { location.hash = "#map"; } },
      ], `Actions for ${c.service}`);
    }
  };
  await load1("/api/containers", "containers", containersPaint);
}
function containersPaint(cs) {
  CS = cs;
  const names = cs.map((c) => c.service);
  [...SELECTED].forEach((n) => { if (!names.includes(n)) SELECTED.delete(n); });
  paint(`
    <div class="actions actions--compact">${btn("Start all", ["start"])}${btn("Restart all", ["restart"])}${btn("Stop all", ["stop"], "btn--danger-ghost")}</div>
    <div class="table-wrap"><table class="table">
      <thead><tr><th class="chk"><input type="checkbox" data-sel-all aria-label="Select all containers"></th><th>Service</th><th>State</th><th>Status</th><th>CPU</th><th>Memory</th><th>Ports</th><th>Image</th><th><span class="vh">Actions</span></th></tr></thead>
      <tbody>${cs.map((c) => `<tr data-svc="${esc(c.service)}"${SELECTED.has(c.service) ? ' class="is-sel"' : ""}>
        <td class="chk"><input type="checkbox" data-sel="${esc(c.service)}" aria-label="Select ${esc(c.service)}"></td>
        <td><b>${esc(c.service)}</b></td><td>${stateLine(c)}</td><td class="muted">${esc(c.status)}</td>
        <td class="num">${esc(c.cpu || "-")}</td><td class="num">${esc(c.mem || "-")}</td>
        <td class="mono">${esc([...new Set((c.ports || []).filter((p) => p.PublishedPort).map((p) => p.PublishedPort + (p.Protocol === "udp" ? "/udp" : "")))].join(" ") || "-")}</td>
        <td class="mono small">${esc(c.image)}</td>
        <td class="row-more"><button type="button" class="btn btn--ghost more" data-more="${esc(c.service)}" aria-haspopup="menu" aria-expanded="false" aria-label="Actions for ${esc(c.service)}">${MORE_ICON}</button></td>
      </tr>`).join("") || '<tr><td colspan="9" class="muted">No containers yet.</td></tr>'}</tbody></table></div>
    <div class="bulk" data-bulk role="region" aria-label="Bulk actions"${SELECTED.size ? "" : " hidden"}>
      <b data-bulk-n>${SELECTED.size} selected</b>
      <button type="button" class="btn btn--sm" data-bulk-act="start">Start</button>
      <button type="button" class="btn btn--sm" data-bulk-act="stop">Stop</button>
      <button type="button" class="btn btn--sm" data-bulk-act="restart">Restart</button>
      <button type="button" class="btn btn--sm" data-bulk-act="logs">Logs</button>
      <button type="button" class="btn btn--sm btn--ghost" data-bulk-act="clear">Clear</button>
    </div>
    <p class="muted small">Managers are recreated on restart, so they load the current ossec.conf. Data stays in volumes. Bulk actions run one vexor command for all selected services.</p>`);
  $$("[data-sel]", view()).forEach((b) => (b.checked = SELECTED.has(b.dataset.sel)));
  ctSync();
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
  const key = PAGE.key;
  openJob(r.data, (code) => { if (code === 0 && PAGE.key === key) route(); });
}

// Storage: disk per filesystem, every volume with its size, backups, and the actions that free space. The volume sizes
// come from du over every file, so this page reads them only when opened, after a command, or on Recount sizes.
const FREE = [
  { title: "Remove unused volumes", args: ["volumes", "prune", "--yes"],
    what: "Deletes Vexor volumes the current layout no longer uses (e.g. old worker or indexer data after a switch to single). Volumes still attached to a container and tool data are kept." },
  { title: "Remove unused images", args: ["images", "prune", "--yes"],
    what: "Deletes old versions of the stack's images that the current setup no longer uses and no container runs. Running containers and volumes are untouched." },
];
// Cards for commands that delete something: the command, what it does, and a button that asks for the typed name.
const dangerCards = (list) => `<div class="resets">${list.map((r) => `<article class="reset" data-key="${esc(r.args.join(" "))}"><h3>${esc(r.title)}</h3><p class="small">${esc(r.what)}</p><code class="mono small">vexor ${esc(r.args.join(" "))}</code>
  <div class="actions">${btn(r.title + "…", r.args, "btn--danger-ghost", `data-text="${esc(r.what)}"`)}</div></article>`).join("")}</div>`;
async function vStorage() {
  setTitle("Storage");
  view().onclick = (e) => {
    if (e.target.closest("[data-vol-fresh]")) refresh({ fresh: true, force: true });
    const j = e.target.closest("[data-jump]");
    if (j) { e.preventDefault(); jumpTo(j.dataset.jump); }
  };
  await progressive(["/api/disk", "/api/volumes"], ([dk, vsIn]) => paint(storageHtml(dk, vsIn)));
}
function storageHtml(dk, vsIn) {
  const fss = dk?.filesystems || [], vs = Array.isArray(vsIn) ? vsIn : [];
  const total = vs.reduce((a, v) => a + (v.bytes || 0), 0);
  const max = Math.max(1, ...vs.map((v) => v.bytes || 0));
  const lv = diskLevel;
  return `
    <section class="block" id="sec-disk"><h2>Disk usage</h2>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>Filesystem</th><th>Holds</th><th>Used / size</th><th>Free</th><th class="w-bar"><span class="vh">Usage</span></th><th>Used</th></tr></thead>
        <tbody>${fss.map((f) => `<tr data-key="${esc(f.mount)}"><td class="mono"><b>${esc(f.mount)}</b></td><td class="small">${esc((f.roles || []).join(", ") || "-")}</td>
          <td class="num">${esc(fmtBytes(f.used))} / ${esc(fmtBytes(f.size))}</td><td class="num">${esc(fmtBytes(f.avail))}</td>
          <td class="w-bar"><span class="bar ${lv(f.pct) ? "bar--" + lv(f.pct) : ""}"><i data-w="${Math.min(100, f.pct) / 100}"></i></span></td>
          <td>${pill(f.pct + "%", lv(f.pct) === "bad" ? "bad" : lv(f.pct) === "warn" ? "warn" : "ok")}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">${dk ? "Disk usage is not available." : SK}</td></tr>`}</tbody></table></div>
      <p class="muted small">Amber from 85%, red from 95%. Free space with the commands under <a href="#storage" data-jump="sec-free">Free space</a>, or lower <code>RETENTION_DAYS</code> (Stacks → Apply retention).</p></section>
    <section class="block" id="sec-volumes"><h2>Volumes</h2>
      <p class="lede">${vsIn ? `${vs.length} volumes, ${esc(fmtBytes(total))} in total.` : SK} Everything Vexor keeps lives here: alerts, agent keys, rules, workflows.</p>
      <div class="actions">${btn("Full backup (snapshot + state)", ["backup", "run"], "btn--primary")}${btn("Backup all volumes (live)", ["volumes", "backup", "all"])}${btn("List backups", ["backup", "list"])}<button class="btn btn--sm btn--ghost" type="button" data-vol-fresh>Recount sizes</button></div>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>Volume</th><th>Size</th><th class="w-bar"><span class="vh">Share</span></th><th>Used by</th><th><span class="vh">Actions</span></th></tr></thead>
        <tbody>${vs.map((v) => `<tr data-key="${esc(v.name)}">
          <td class="mono"><b>${esc(v.name)}</b></td><td class="num">${esc(fmtBytes(v.bytes || 0))}</td>
          <td class="w-bar"><span class="bar"><i data-w="${(v.bytes || 0) / max}"></i></span></td>
          <td class="small">${v.users?.length ? esc(v.users.join(", ")) : pill("unused", "warn")}</td>
          <td class="row-actions">${btn("Backup", ["volumes", "backup", v.short])}${v.users?.length ? "" : btn("Remove", ["volumes", "rm", v.short], "btn--danger-ghost")}</td></tr>`).join("") || `<tr><td colspan="5" class="muted">${vsIn ? "No volumes yet - they are created when the stack starts." : `${SK} sizes take a few seconds`}</td></tr>`}</tbody></table></div>
      <p class="muted small">A live volume backup of a running indexer can be inconsistent; the full backup uses an indexer snapshot. Restores run from the terminal: <code>vexor volumes restore &lt;volume&gt; &lt;file&gt;</code>.</p></section>
    <section class="block" id="sec-free"><h2>Free space</h2>
      <p class="muted">Each command shows what it removes and asks you to type its name. Take a full backup first.</p>
      <div class="actions">${btn("Show unused volumes", ["volumes", "orphans"])}</div>
      ${dangerCards(FREE)}</section>`;
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
  await load1("/api/state", "stacks", stacksPaint);
}
function stacksPaint(s) {
  STATE = s;
  paint(`<div class="stacks">${STACKS(s).map((k) => `
    <article class="stack ${k.on ? "" : "stack--off"}" id="stack-${k.id}">
      <header class="stack__head"><h2>${esc(k.name)}</h2>${k.on ? pill("on", "ok") : pill("off")}
        ${k.toggle ? btn(k.on ? "Disable" : "Enable", ["tools", k.on ? "disable" : "enable", k.toggle], k.on ? "btn--danger-ghost" : "btn--primary") : ""}</header>
      <p class="muted small">${esc(k.note || "")}</p>
      ${k.actions.length ? `<div class="actions">${k.actions.join("")}</div>` : ""}
      ${k.form || ""}
    </article>`).join("")}</div>
    <section class="block"><h2>Certificates, retention, automation</h2><div class="actions">
      ${btn("Certificate status", ["cert", "status"])}${btn("Create local-CA cert", ["cert", "create"])}${btn("Renew", ["cert", "renew"])}
      ${btn("Retention", ["retention", "status"])}${btn("Apply retention", ["retention", "apply"])}${btn("Daemon status", ["daemon", "status"])}${btn("Install daemon", ["daemon", "install"])}${btn("Update check", ["update", "check"])}
    </div></section>`);
}

// Settings: the ports, every other .env value, password rotation, and removing Vexor. Forms: never refreshed on their own;
// a successful apply repaints the page from the new values.
const UNINSTALL = [
  { title: "Uninstall, keep data", args: ["uninstall", "--keep-data", "--yes"],
    what: "Stops and removes the Vexor containers and network. Volumes (alerts, agent keys, rules, workflows) and generated files are kept; images are not removed. Run vexor start to bring it back." },
  { title: "Uninstall everything", args: ["uninstall", "--yes"],
    what: "Stops and removes the containers and network, then removes the project volumes and generated files. All stored alerts and agent keys are lost. Images are not removed." },
];
async function vSettings() {
  setTitle("Settings");
  const v = view();
  const portsForm = () => $("[data-ports-form]", v), setForm = () => $("[data-set-form]", v);
  const portChanges = () => Object.fromEntries($$("input[data-orig]", portsForm()).filter((i) => i.value.trim() !== i.dataset.orig).map((i) => [i.name, i.value.trim()]));
  const setChanges = () => Object.fromEntries($$("input[data-orig]", setForm()).filter((i) => i.value !== i.dataset.orig).map((i) => [i.name, i.value]));
  const checkPorts = async () => {
    const f = portsForm();
    $$("[data-err]", f).forEach((e) => (e.textContent = ""));
    const { data } = await api("/api/ports/check", { body: { changes: portChanges() } });
    Object.entries(data.errors || {}).forEach(([k, m]) => { const e = $(`[data-err="${k}"]`, f); if (e) e.textContent = m; });
    return !Object.keys(data.errors || {}).length;
  };
  v.oninput = (e) => {
    const t = e.target;
    if (t.matches("[data-set-filter]")) { const q = t.value.toLowerCase(); $$("[data-row]", setForm()).forEach((r) => (r.hidden = q && !r.dataset.row.includes(q))); return; }
    if (t.closest("[data-ports-form]")) {
      const ch = portChanges(), n = Object.keys(ch).length;
      $("[data-ports-apply]", v).disabled = !n;
      $("[data-ports-msg]", v).textContent = n ? `${n} change${n > 1 ? "s" : ""}: ${Object.entries(ch).map(([k, x]) => `${k}=${x}`).join(", ")}` : "No changes.";
      $$("input[data-orig]", portsForm()).forEach((i) => i.classList.toggle("is-changed", i.value.trim() !== i.dataset.orig));
    } else if (t.closest("[data-set-form]")) {
      const ch = setChanges(), n = Object.keys(ch).length;
      $("[data-set-apply]", v).disabled = !n;
      $("[data-set-msg]", v).textContent = n ? Object.entries(ch).map(([k, x]) => `${k}=${x}`).join(", ") : "No changes.";
      $$("input[data-orig]", setForm()).forEach((i) => i.classList.toggle("is-changed", i.value !== i.dataset.orig));
    }
  };
  v.onclick = async (e) => {
    if (!e.target.closest("[data-ports-check]")) return;
    const good = await checkPorts();
    toast(good ? "Ports are valid and free." : "Fix the marked ports.", good ? "ok" : "bad");
  };
  v.onsubmit = async (e) => {
    e.preventDefault();
    if (e.target.matches("[data-ports-form]")) {
      if (!(await checkPorts())) return toast("Fix the marked ports first.", "bad");
      await applySettings(portChanges(), "Agents and browsers must use the new ports afterwards. Firewall rules are not changed.");
    } else if (e.target.matches("[data-set-form]")) applySettings(setChanges());
  };
  // The last values this browser read paint at once; the fresh ones follow (one fetch each, in parallel).
  const draw = () => { if (LAST["/api/ports"] && LAST["/api/settings"]) paint(settingsHtml(LAST["/api/ports"], LAST["/api/settings"])); };
  if (LAST["/api/ports"] && LAST["/api/settings"]) draw(); else loading("settings");
  const rs = await Promise.all([get("/api/ports"), get("/api/settings")]);
  if (rs.some((r) => r.status !== 200)) throw new Error(rs.find((r) => r.status !== 200).data.error || "the settings could not be read");
  draw();
}
function settingsHtml(ps, rows) {
  return `
    <p class="lede">All of <code>.env</code>: ports first, then every other setting. Passwords and keys are hidden; change them with their commands under Security.</p>
    <section class="block" id="sec-ports"><h2>Ports</h2>
      <p class="muted">Change a value, check it, then apply: Vexor rewrites nginx and the compose override and recreates only what uses the port.</p>
      <form class="ports" data-ports-form>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>Setting</th><th>Port</th><th>For</th><th>Who connects</th><th>Listening</th></tr></thead>
          <tbody>${ps.map((p) => `<tr data-key="${esc(p.key)}">
            <td class="mono"><b>${esc(p.key)}</b></td>
            <td><input class="in in--port" name="${esc(p.key)}" value="${esc(p.value)}" inputmode="numeric" aria-label="${esc(p.key)}" data-orig="${esc(p.value)}"><span class="field-err" data-err="${esc(p.key)}"></span></td>
            <td>${esc(p.what)}${p.fiveX ? ' <span class="muted small">(50000-59999)</span>' : ""}</td>
            <td>${pill(p.audience, { endpoints: "ok", admins: "accent", restricted: "warn", host: "" }[p.audience])}</td>
            <td>${!p.inUse ? pill("not in use") : p.listening ? pill("yes", "ok") : pill("no", "bad")}</td></tr>`).join("")}</tbody></table></div>
        <div class="actions"><button class="btn btn--sm" type="button" data-ports-check>Check</button><button class="btn btn--sm btn--primary" type="submit" data-ports-apply disabled>Apply port changes</button><span class="muted small" data-ports-msg>No changes.</span></div>
      </form></section>
    <section class="block" id="sec-env"><h2>Settings</h2>
      <label class="search"><span class="vh">Filter</span><input class="in" placeholder="Filter settings" data-set-filter></label>
      <form data-set-form><div class="table-wrap"><table class="table">
        <thead><tr><th>Setting</th><th>Value</th><th>About</th></tr></thead>
        <tbody>${rows.filter((r) => !r.port).map((r) => `<tr data-key="${esc(r.key)}" data-row="${esc(r.key.toLowerCase() + " " + (r.help || "").toLowerCase())}">
          <td class="mono"><b>${esc(r.key)}</b></td>
          <td>${r.secret ? pill(r.set ? "set" : "not set", r.set ? "ok" : "warn") : `<input class="in" name="${esc(r.key)}" value="${esc(r.value)}" data-orig="${esc(r.value)}" aria-label="${esc(r.key)}">`}</td>
          <td class="small muted">${esc(r.help || "")}</td></tr>`).join("")}</tbody></table></div>
        <div class="actions sticky-bar"><button class="btn btn--sm btn--primary" type="submit" data-set-apply disabled>Apply changes</button><span class="muted small" data-set-msg>No changes.</span></div>
      </form></section>
    <section class="block" id="sec-security"><h2>Security</h2><div class="actions">
      ${btn("New admin password", ["passwd", "admin", "--generate"], "btn--danger-ghost")}${btn("New API password", ["passwd", "api", "--generate"], "btn--danger-ghost")}${btn("New dashboard password", ["passwd", "kibanaserver", "--generate"], "btn--danger-ghost")}${btn("Enrollment password on", ["agents", "password", "on"])}${btn("New console password", ["console", "password", "--generate"], "btn--danger-ghost")}
    </div><p class="muted small">New passwords appear in the output once; they are also stored in .env.</p></section>
    <section class="block" id="sec-remove"><h2>Remove Vexor</h2>
      <p class="muted">Each action shows the command and asks you to type its name before it runs. Take a full backup first (<a href="#storage">Storage</a>). To free disk space without removing Vexor, use Storage → Free space.</p>
      ${dangerCards(UNINSTALL)}</section>`;
}

const SUGGEST = ["status", "doctor", "doctor --fix", "wazuh alerts -n 20", "agents list", "elk", "elk indices", "n8n", "n8n test", "suricata", "suricata alerts --since 1h", "suricata test", "zeek", "zeek top hosts", "tools", "soc", "volumes ls", "backup list", "cert status", "logs errors --since 1h", "logs nginx -n 100", "retention status", "disk", "volumes orphans", "wait-ready", "update check", "version", "reminders"];
async function vTerminal() {
  setTitle("Terminal");
  paint(`
    <p class="lede">Type any vexor command. Reading runs at once; changes ask first; commands that delete or switch layouts ask you to type their name. Interactive ones (shell, exec, logtest, config edit) stay in SSH.</p>
    <form class="term" data-term><span class="term__p">vexor</span><input class="in in--term" name="cmd" list="vx-suggest" placeholder="suricata alerts --since 1h" autocomplete="off" spellcheck="false" autofocus><button type="button" class="btn btn--ghost btn--sm btn--icon" data-term-copy aria-label="Copy command" title="Copy command"><svg class="ico" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg></button><button class="btn btn--primary btn--sm">Run</button></form>
    <datalist id="vx-suggest">${SUGGEST.map((s) => `<option value="${esc(s)}">`).join("")}</datalist>
    <div class="chips">${SUGGEST.slice(0, 14).map((s) => `<button type="button" class="chip" data-fill="${esc(s)}">${esc(s)}</button>`).join("")}</div>
    <h2 class="sub">History</h2><ol class="hist" data-hist></ol>
    <div class="sections" id="sec-activity" data-activity></div>`);
  const f = $("[data-term]"), inp = $("[name=cmd]", f);
  const hist = JSON.parse(sessionStorage.getItem("vx-hist") || "[]");
  const drawHist = () => ($("[data-hist]").innerHTML = hist.slice(0, 20).map((h) => `<li><button type="button" class="link-btn mono" data-fill="${esc(h)}" title="vexor ${esc(h)}">vexor ${esc(h)}</button><button type="button" class="btn btn--ghost btn--xs btn--icon" data-copy-hist="${esc(h)}" aria-label="Copy command" title="Copy command"><svg class="ico" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg></button></li>`).join("") || '<li class="muted">Nothing yet.</li>');
  drawHist();
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const c = inp.value.trim().replace(/^vexor\s+/, "");
    if (!c) return;
    const ok = await run(c);
    if (ok) { hist.unshift(c); try { sessionStorage.setItem("vx-hist", JSON.stringify([...new Set(hist)].slice(0, 30))); } catch { /* private mode */ } drawHist(); inp.select(); termActivity().catch(() => {}); }
  });
  view().onclick = (e) => {
    const c = e.target.closest("[data-copy-hist]"); if (c) return copyText("vexor " + c.dataset.copyHist, c);
    const b = e.target.closest("[data-fill]"); if (b) { inp.value = b.dataset.fill; inp.focus(); }
    const j = e.target.closest("[data-job]"); if (j) openJob(JSON.parse(j.dataset.job));
  };
  $("[data-term-copy]").addEventListener("click", (e) => { const v = inp.value.trim().replace(/^vexor\s+/, ""); if (v) copyText("vexor " + v, e.currentTarget); else toast("Type a command first.", "bad"); });
  await termActivity();
}
// The Terminal's activity sections (commands run from this console, audit log). Only this part is re-read: on open,
// after a command starts or ends, and on Refresh. The command box and history above it are never touched.
async function termActivity() {
  const pg = PAGE;
  if (pg.key !== "terminal") return;
  const box = () => (PAGE === pg ? $("[data-activity]", view()) : null);
  await progressive(["/api/jobs", "/api/audit"], ([jobsIn, logIn]) => {
    const el = box();
    if (!el) return;
    const jobs = Array.isArray(jobsIn) ? jobsIn : [], log = Array.isArray(logIn) ? logIn : [];
    morphInto(el, `
    <section class="block"><h2>Commands in this console session</h2>
      <div class="table-wrap"><table class="table"><thead><tr><th>Started</th><th>Command</th><th>By</th><th>Result</th><th><span class="vh">Output</span></th></tr></thead>
      <tbody>${jobs.map((j) => `<tr data-key="${esc(j.id)}"><td class="num small">${new Date(j.started * 1000).toLocaleTimeString()}</td><td class="mono small">${esc(j.cmd)}</td><td>${esc(j.user)}</td>
        <td>${j.ended ? pill(j.code === 0 ? "done" : "exit " + j.code, j.code === 0 ? "ok" : "bad") : pill("running", "warn")}</td>
        <td><button type="button" class="btn btn--sm btn--ghost" data-job='${esc(JSON.stringify(j))}'>Output</button></td></tr>`).join("") || `<tr><td colspan="5" class="muted">${jobsIn ? "No commands yet." : SK}</td></tr>`}</tbody></table></div></section>
    <section class="block" id="sec-audit"><h2>Audit log</h2><pre class="audit">${logIn ? esc(log.join("\n")) || "empty" : SK}</pre><p class="muted small">Kept in .state/console-audit.log on the host.</p></section>`);
  });
}

async function vLogins() {
  setTitle("Logins");
  loading("logins");
  const { data: rows } = await get("/api/logins");
  paint(`
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
    <p class="muted small">Grafana and Portainer apply their admin password on first start only; if you changed it inside the tool, Vexor no longer knows it. n8n keeps its own accounts.</p>`);
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
// server saw in /proc. Refreshed every 3 s by the live loop (see "live refresh"), updated in place.
const MAP_LAYERS = [
  ["external", "Outside the project"], ["edge", "Edge"], ["ingest", "Managers and ingest"], ["data", "Indexers and storage"],
  ["ui", "Dashboards"], ["tools", "Tools"], ["other", "Other containers"],
];
const MAP_STATUS = { ok: "running", issue: "issue", offline: "offline", missing: "missing" };
const SVG_NS = "http://www.w3.org/2000/svg";
let mapData = null, mapSel = null, mapRO = null;
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
    return `<g class="medge ${isLive ? "is-live" : ""}" data-key="${esc(p.from + ">" + p.to)}"><title>${esc(title)}</title>
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
  morphInto(svg, `<defs><marker id="map-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" orient="auto-start-reverse" markerUnits="userSpaceOnUse"><path d="M0,0 L10,5 L0,10 z" class="medge__head"/></marker></defs>
    ${L.labels.map((l) => `<text class="mlayer" x="${L.narrow ? 8 : 16}" y="${l.y}">${esc(l.label.toUpperCase())}</text>`).join("")}
    <g>${edgeSvg}</g><g>${nodeSvg}</g>`, true);
}

function mapSummary(d) {
  const ns = d.nodes, by = (s) => ns.filter((n) => n.status === s).length;
  const rates = ns.filter((n) => n.traffic);
  const measured = rates.filter((n) => n.traffic.rxRate != null);
  const rx = measured.reduce((a, n) => a + n.traffic.rxRate, 0), tx = measured.reduce((a, n) => a + n.traffic.txRate, 0);
  const ext = d.external || {};
  morphInto($("[data-map-sum]"), [
    pill(`${ns.filter((n) => n.state === "running").length} running`, "ok"),
    by("issue") ? pill(`${by("issue")} issue${by("issue") > 1 ? "s" : ""}`, "warn") : pill("0 issues"),
    by("offline") + by("missing") ? pill(`${by("offline")} offline · ${by("missing")} missing`, "bad") : pill("0 offline"),
    rates.length ? pill(measured.length ? `in ${fmtRate(rx)} · out ${fmtRate(tx)}` : "rates: measuring…") : "",
    d.limits ? "" : pill(`external: ${ext.inbound || 0} in · ${ext.outbound || 0} out`),
  ].join(" "));
  $("[data-map-nets]").textContent = d.networks.length ? `Project ${d.project} · networks: ${d.networks.map((n) => `${n.name} (${n.containers})`).join(", ")}` : `Project ${d.project}`;
  const lim = $("[data-map-limits]");
  lim.hidden = !d.limits;
  lim.textContent = d.limits || "";
}

function mapPanel(d) {
  const panel = $("[data-map-panel]");
  const n = mapSel === "external" ? { id: "external" } : d.nodes.find((x) => x.id === mapSel);
  if (!n) { morphInto(panel, `<p class="muted small">Select a container on the map to see its state, networks, ports and connections.</p>`); return; }
  const dl = (rows) => `<dl class="kv">${rows.filter(([, v]) => v !== "" && v != null).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
  const name = (id) => esc(id === "external" ? "External" : d.nodes.find((x) => x.id === id)?.service || id);
  if (n.id === "external") {
    const ext = d.external || {};
    const rows = d.nodes.flatMap((x) => (x.connections || []).filter((c) => c.peer === "external").map((c) => ({ ...c, svc: x.service })));
    morphInto(panel, `<h2>External</h2><p class="muted small">Connections to and from addresses outside the project's networks: agents, browsers, other hosts. Connections through a published port can show the Docker gateway as their address.</p>
      ${dl([["Inbound", ext.inbound], ["Outbound", ext.outbound], ["Peers", ext.peers], ["Ports", esc(Object.entries(ext.ports || {}).map(([p, c]) => `${p} ×${c}`).join(", "))]])}
      <h3>Connections</h3><ul class="conns">${rows.map((c) => `<li><span>${c.dir === "in" ? "in → " + esc(c.svc) : esc(c.svc) + " → out"} :${c.port}${c.proto === "udp" ? "/udp" : ""}</span><span class="muted">${c.count} · ${esc(c.ips.join(", "))}</span></li>`).join("") || '<li class="muted">None.</li>'}</ul>`);
    return;
  }
  const t = n.traffic;
  const svc = n.service;
  const conns = n.connections;
  morphInto(panel, `<h2>${esc(svc)}</h2>
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
    <div class="actions">${btn("Logs", ["logs", svc, "-n", "200"])}${n.state === "running" ? btn("Restart", ["restart", svc]) : btn("Start", ["start", svc], "btn--primary")}</div>`);
}

function mapShow(d) {
  drawMap(d); mapSummary(d); mapPanel(d);
  if (!d.nodes.length) morphInto($("[data-map-sum]"), `<span class="muted">No containers in the Docker project <code>${esc(d.project)}</code>.</span>`);
}
async function vMap() {
  setTitle("Map");
  if (view().dataset.page !== "map") {          // first paint: the frame, its listeners and the last map this browser saw
    paint(`
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
    </ul>`);
    mapPanel({ nodes: [] });
    const svg = $("[data-map-svg]");
    const pick = (g) => { if (!g || !mapData) return; mapSel = g.dataset.node; drawMap(mapData); mapPanel(mapData); if (matchMedia("(max-width: 1080px)").matches) $("[data-map-panel]").scrollIntoView({ block: "nearest", behavior: "smooth" }); };
    svg.addEventListener("click", (e) => pick(e.target.closest("[data-node]")));
    svg.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(e.target.closest("[data-node]")); } });
    let lastW = $("[data-map-wrap]").clientWidth;
    mapRO = new ResizeObserver(() => { const w = $("[data-map-wrap]")?.clientWidth || 0; if (mapData && Math.abs(w - lastW) > 4) { lastW = w; drawMap(mapData); } });
    mapRO.observe($("[data-map-wrap]"));
    PAGE.cleanup = () => { mapRO?.disconnect(); mapRO = null; };
    if (mapData) mapShow(mapData);
  }
  const { status, data } = await get("/api/map");
  if (status !== 200 || !data.nodes) throw new Error(data.error || "the map could not be read");
  mapData = data;
  if (mapSel && mapSel !== "external" && !data.nodes.some((n) => n.id === mapSel)) mapSel = null;
  mapShow(data);
}

// ---------------------------------------------------------------- theme (auto -> light -> dark)
const THEMES = ["auto", "light", "dark"];
function themeNow() { try { return localStorage.getItem("vx-theme") || "auto"; } catch { return "auto"; } }
function setTheme(t) {
  if (t === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
  try { if (t === "auto") localStorage.removeItem("vx-theme"); else localStorage.setItem("vx-theme", t); } catch { /* storage blocked */ }
  $("[data-theme-label]").textContent = `Theme: ${t}`;
}
$("[data-theme-toggle]").addEventListener("click", () => setTheme(THEMES[(THEMES.indexOf(themeNow()) + 1) % THEMES.length]));
setTheme(themeNow());

// ---------------------------------------------------------------- sidebar (full / icons only)
const sideEl = $(".app"), sideBtn = $("[data-side-toggle]");
function setSide(collapsed, save = true) {
  sideEl.classList.toggle("is-collapsed", collapsed);
  sideBtn.setAttribute("aria-expanded", String(!collapsed));
  sideBtn.title = collapsed ? "Expand sidebar" : "Collapse sidebar";
  if (save) try { localStorage.setItem("vx-side", collapsed ? "1" : "0"); } catch { /* storage blocked */ }
}
sideBtn.addEventListener("click", () => setSide(!sideEl.classList.contains("is-collapsed")));
let storedSide = false;
try { storedSide = localStorage.getItem("vx-side") === "1"; } catch { /* storage blocked */ }
setSide(storedSide, false);

// Collapsed-sidebar tooltip: one fixed element placed on hover/focus, so the scrolling nav cannot clip it.
const sideTip = Object.assign(document.createElement("div"), { className: "side-tip", hidden: true });
document.body.appendChild(sideTip);
const hideTip = () => { sideTip.hidden = true; };
function showTip(e) {
  const t = e.target.closest?.("[data-tip]");
  if (!t || !sideEl.classList.contains("is-collapsed") || matchMedia("(max-width: 760px)").matches) return hideTip();
  if (e.type === "focusin" && !t.matches(":focus-visible")) return;
  const r = t.getBoundingClientRect();
  sideTip.textContent = t.dataset.tip;
  sideTip.style.left = r.right + 8 + "px";
  sideTip.style.top = r.top + r.height / 2 + "px";
  sideTip.hidden = false;
}
const sideRoot = $(".side");
["mouseover", "focusin"].forEach((ev) => sideRoot.addEventListener(ev, showTip));
["mouseleave", "focusout", "click"].forEach((ev) => sideRoot.addEventListener(ev, hideTip));
$("[data-nav]").addEventListener("scroll", hideTip, { passive: true });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") hideTip(); });

// Keep the current page's nav item in view (vertical list on desktop, horizontal row on phones); scrolls only the nav.
function revealNav() {
  const nav = $("[data-nav]"), cur = $("[data-nav] a[aria-current=page]");
  if (!cur || !nav.clientWidth) return;
  const n = nav.getBoundingClientRect(), c = cur.getBoundingClientRect();
  if (c.top < n.top + 4) nav.scrollTop += c.top - n.top - 4;
  else if (c.bottom > n.bottom - 4) nav.scrollTop += c.bottom - n.bottom + 4;
  if (c.left < n.left) nav.scrollLeft += c.left - n.left - 16;
  else if (c.right > n.right) nav.scrollLeft += c.right - n.right + 16;
}
new MutationObserver(() => requestAnimationFrame(revealNav)).observe($("[data-nav]"), { attributes: true, attributeFilter: ["aria-current"], subtree: true });   // route() marks the page; follow it
window.addEventListener("resize", revealNav);
sideBtn.addEventListener("click", () => setTimeout(revealNav, 250));
// Desktop: the wheel over the sidebar's head or footer must not scroll the page (the nav list scrolls natively).
sideRoot.addEventListener("wheel", (e) => {
  if (!matchMedia("(max-width: 760px)").matches && !$("[data-nav]").contains(e.target)) e.preventDefault();
}, { passive: false });
// Fade the nav's top/bottom edge while more pages are hidden there, so it is obvious the list scrolls.
function navHint() {
  const n = $("[data-nav]");
  n.classList.toggle("more-above", n.scrollTop > 2);
  n.classList.toggle("more-below", n.scrollTop + n.clientHeight < n.scrollHeight - 2);
}
$("[data-nav]").addEventListener("scroll", navHint, { passive: true });
window.addEventListener("resize", navHint);
new ResizeObserver(navHint).observe($("[data-nav]"));
// Small screens: the Menu button opens the grouped page list as a drawer; picking a page, Esc or resizing closes it.
const menuBtn = $("[data-side-menu]");
function setMenu(open) {
  sideRoot.classList.toggle("is-open", open);
  document.body.classList.toggle("nav-open", open);
  menuBtn.setAttribute("aria-expanded", String(open));
  menuBtn.setAttribute("aria-label", open ? "Close the page menu" : "Open the page menu");
  if (open) { requestAnimationFrame(() => { revealNav(); navHint(); $("[data-nav] a[aria-current=page]")?.focus({ preventScroll: true }); }); }
}
menuBtn.addEventListener("click", () => setMenu(!sideRoot.classList.contains("is-open")));
$("[data-nav]").addEventListener("click", (e) => { if (e.target.closest("a")) setMenu(false); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && sideRoot.classList.contains("is-open")) { setMenu(false); menuBtn.focus(); } });
matchMedia("(max-width: 760px)").addEventListener("change", () => setMenu(false));
// the Menu button names the current page
new MutationObserver(() => { const c = $("[data-nav] a[aria-current=page] .lbl"); $("[data-side-current]").textContent = c ? c.textContent : "Menu"; })
  .observe($("[data-nav]"), { attributes: true, attributeFilter: ["aria-current"], subtree: true });

// ---------------------------------------------------------------- router
// ---------------------------------------------------------------- Proxy page: named hosts through nginx (vexor proxy)
const PX_HOST = /^(?=.{1,253}$)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)$/;
const PX_TARGET = /^(?:https?:\/\/)?[a-z0-9][a-z0-9._-]{0,62}:\d{1,5}\/?$/;
const PX_SIZE = /^\d{1,5}[kmg]?$/;
const PX_TLS = { local: "Local CA", letsencrypt: "Let's Encrypt", off: "Off (HTTP)" };
const PX_STATUS = { active: ["active", "ok"], "no-cert": ["no certificate", "warn"], "bad-cert": ["bad certificate", "bad"], expired: ["expired", "bad"],
  "not-rendered": ["not applied", "warn"], "nginx-down": ["nginx down", "bad"], invalid: ["invalid", "bad"] };
function pxCert(r) {
  if (r.tls === "off") return `<span class="muted">—</span>`;
  const c = r.cert || {};
  if (!c.exists) return pill("missing", "warn");
  if (c.days === undefined) return pill("unreadable", "bad");
  const when = c.expires ? new Date(c.expires * 1000).toLocaleDateString() : "";
  return `${pill(c.days < 0 ? "expired" : `${c.days} days`, c.days < 0 ? "bad" : c.days < 21 ? "warn" : c.days < 30 ? "accent" : "ok")} <span class="muted small">${esc(when)}</span>`;
}
async function pxDownload(host, what) {
  const r = await fetch(`/api/proxy/download?what=${encodeURIComponent(what)}${host ? "&host=" + encodeURIComponent(host) : ""}`, { credentials: "same-origin" });
  if (r.status === 401) { showLogin(); return; }
  if (!r.ok) { const d = await r.json().catch(() => ({})); toast(d.error === "no certificate yet" ? "No certificate yet - issue one first." : d.error || "Download refused.", "bad"); return; }
  const name = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "")?.[1] || "certificate.crt";
  const a = document.createElement("a");
  a.href = URL.createObjectURL(await r.blob());
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}
function pxArgs(f, mode) {
  const v = Object.fromEntries(new FormData(f));
  const host = mode === "add" ? (v.host || "").trim().toLowerCase() : f.dataset.host, target = (v.target || "").trim().toLowerCase(), size = (v.max_body || "").trim().toLowerCase() || "100m";
  const errs = {};
  if (mode === "add" && !PX_HOST.test(host)) errs.host = "A domain like soc.example.com or an IPv4 address (no wildcard).";
  if (!PX_TARGET.test(target)) errs.target = "service:port (n8n:5678) or [http(s)://]IP:PORT.";
  if (!PX_SIZE.test(size)) errs.max_body = "Like 100m, 512k, 1g or 0 (no limit).";
  if (v.tls === "letsencrypt" && /^[\d.]+$/.test(host)) errs.tls = "Let's Encrypt needs a domain name.";
  $$("[data-px-err]", f).forEach((e) => (e.textContent = errs[e.dataset.pxErr] || ""));
  if (Object.keys(errs).length) return null;
  return mode === "add"
    ? ["proxy", "add", host, target, "--tls", v.tls, "--max-body", size, ...(v.websocket ? ["--websocket"] : [])]
    : ["proxy", "edit", f.dataset.host, "--target", target, "--tls", v.tls, "--max-body", size, v.websocket ? "--websocket" : "--no-websocket"];
}
const pxFields = (r = {}, list = "px-targets") => `
  <label class="px-field"><span>Target</span><input class="in" name="target" list="${list}" value="${esc(r.target || "")}" placeholder="wazuh.dashboard:5601" autocomplete="off" spellcheck="false" required><small class="field-err" data-px-err="target"></small></label>
  <label class="px-field"><span>TLS</span><select class="in" name="tls">${Object.entries(PX_TLS).map(([k, l]) => `<option value="${k}" ${(r.tls || "local") === k ? "selected" : ""}>${esc(l)}</option>`).join("")}</select><small class="field-err" data-px-err="tls"></small></label>
  <label class="px-field px-field--sm"><span>Max body</span><input class="in" name="max_body" value="${esc(r.max_body || "100m")}" spellcheck="false"><small class="field-err" data-px-err="max_body"></small></label>
  <label class="px-check"><input type="checkbox" name="websocket" ${r.websocket ? "checked" : ""}> <span>WebSocket</span></label>`;
let PX = { routes: [] };      // what the Proxy page shows, for its delegated buttons
async function vProxy() {
  setTitle("Proxy");
  const runP = (args, text, onEnd) => run(args, { text, onEnd });
  const v = view();
  v.onclick = (e) => {
    const t = e.target, at = (a) => t.closest(`[${a}]`);
    const routes = PX.routes || [];
    if (at("data-px-ca")) return pxDownload("", "ca");
    if (at("data-px-cancel")) return $("[data-px-dialog]").close();
    let b = at("data-px-edit");
    if (b) {
      const r = routes[+b.dataset.pxEdit], ef = $("[data-px-editform]");
      if (!r) return;
      ef.dataset.host = r.host;
      $("[data-px-edit-host]").textContent = r.host;
      $("[data-px-edit-fields]").innerHTML = pxFields(r);
      $("[data-px-dialog]").showModal();
      $("[name=target]", ef).focus();
      return;
    }
    if ((b = at("data-px-cert"))) {
      const r = routes[+b.dataset.pxCert];
      if (r) runP(["proxy", "cert", r.host, ...(r.cert?.exists ? ["--renew"] : [])], r.tls === "letsencrypt" ? "Asks Let's Encrypt for a new certificate (HTTP-01 on port 80)." : "Issues a new certificate from the local CA and reloads nginx.");
      return;
    }
    if ((b = at("data-px-dl"))) { const r = routes[+b.dataset.pxDl]; if (r) pxDownload(r.host, "cert"); return; }
    if ((b = at("data-px-rm"))) {
      const r = routes[+b.dataset.pxRm];
      if (r) runP(["proxy", "rm", r.host], `Removes ${r.host} → ${r.target} and its certificate. ${routes.length === 1 ? "It is the last route: nginx stops publishing the route ports." : ""}`);
    }
  };
  v.onsubmit = (e) => {
    const f = e.target;
    if (f.matches("[data-px-add]")) {
      e.preventDefault();
      const args = pxArgs(f, "add");
      if (args) runP(args, args.includes("letsencrypt") ? "Adds the route, then asks Let's Encrypt for a certificate (the name must point here, port 80 open)." : "Adds the route; nginx config is tested before the reload.",
        (code) => { if (code === 0) f.reset(); });
    } else if (f.matches("[data-px-editform]")) {
      e.preventDefault();
      const args = pxArgs(f, "edit");
      if (!args) return;
      $("[data-px-dialog]").close();
      runP(args, "nginx config is tested before the reload; a failing change is rolled back.");
    }
  };
  await load1("/api/proxy", "proxy routes", proxyPaint);
}
function proxyPaint(d) {
  PX = d;
  const routes = d.routes || [];
  const portTxt = (p, def) => (String(p) === def ? "" : ":" + p);
  // nginx state is known only when the status call worked; never report "down" for a failed request
  const code = d.httpStatus ?? 200;
  const known = code === 200 && !d.error && typeof d.nginx_running === "boolean";
  if (code === 404) d.error = "This console server is older than the page (updated with git pull?). Restart it on the host: sudo vexor console restart";
  else if (code !== 200 && !d.error) d.error = `The proxy status could not be read (HTTP ${code}).`;
  setMeta(`${pill(`https${portTxt(d.https_port, "443")} · http${portTxt(d.http_port, "80")}`)} ${!known ? pill("nginx: unknown", "warn") : pill(d.nginx_running ? "nginx up" : "nginx down", d.nginx_running ? "ok" : "bad")}`);
  paint(`
    <p class="lede">Open a Vexor service or anything on this host or your LAN under its own name, like <code>soc.example.com</code>. nginx answers on port ${esc(d.https_port || 443)} (HTTPS) and ${esc(d.http_port || 80)} (HTTP, redirects and Let's Encrypt) once the first route exists. Every change is tested with <code>nginx -t</code> before nginx reloads.</p>
    ${d.error ? `<p class="err">${esc(d.error)}</p>` : ""}
    <section class="px-ca">
      <div><h2>Local CA certificate</h2><p class="muted small">Install it once on each computer or phone that opens these routes: browsers then trust every <b>Local CA</b> certificate without a warning.</p></div>
      <button type="button" class="btn btn--sm btn--primary" data-px-ca ${d.ca ? "" : "disabled"}>CA certificate (install once on your computer/phone)</button>
    </section>
    <section class="block"><h2>Routes</h2>
      ${routes.length ? `<div class="table-wrap px-wrap"><table class="table px-table">
        <thead><tr><th>Host</th><th>Target</th><th>TLS</th><th>Certificate</th><th>WebSocket</th><th>Status</th><th><span class="vh">Actions</span></th></tr></thead>
        <tbody>${routes.map((r, i) => { const st = PX_STATUS[r.status] || [r.status, ""]; return `<tr data-key="${esc(r.host)}">
          <td data-label="Host"><a class="mono px-host" href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.host)}</a></td>
          <td data-label="Target" class="mono small px-target">${esc(r.target)}<span class="muted"> · ${esc(r.max_body)}</span></td>
          <td data-label="TLS">${pill(PX_TLS[r.tls] || r.tls, r.tls === "off" ? "warn" : "")}</td>
          <td data-label="Certificate">${pxCert(r)}</td>
          <td data-label="WebSocket">${r.websocket ? pill("on", "accent") : `<span class="muted small">off</span>`}</td>
          <td data-label="Status">${pill(st[0], st[1])}</td>
          <td class="px-acts"><div class="row-actions px-row-actions">
            <button type="button" class="btn btn--xs" data-px-edit="${i}">Edit</button>
            ${r.tls !== "off" ? `<button type="button" class="btn btn--xs" data-px-cert="${i}">${r.cert?.exists ? "Renew cert" : "Issue cert"}</button>` : ""}
            ${r.tls !== "off" && r.cert?.exists ? `<button type="button" class="btn btn--xs" data-px-dl="${i}">Certificate</button>` : ""}
            <button type="button" class="btn btn--xs btn--danger-ghost" data-px-rm="${i}">Remove</button>
          </div></td></tr>`; }).join("")}</tbody></table></div>`
        : `<p class="muted">No routes yet. Add one below - for example <code>soc.example.com</code> → <code>wazuh.dashboard:5601</code>.</p>`}
    </section>
    <section class="block"><h2>Add a route</h2>
      <form class="px-form" data-px-add novalidate>
        <label class="px-field"><span>Host</span><input class="in" name="host" placeholder="soc.example.com" autocomplete="off" spellcheck="false" autocapitalize="off" required><small class="field-err" data-px-err="host"></small></label>
        ${pxFields()}
        <button class="btn btn--sm btn--primary px-submit" type="submit">Add route</button>
      </form>
      <datalist id="px-targets">${(d.suggestions || []).map((s) => `<option value="${esc(s)}"></option>`).join("")}<option value="127.0.0.1:"></option><option value="https://192.168.1.10:443"></option></datalist>
      <p class="muted small">Targets: a Vexor service and port (the list shows the enabled ones), <code>127.0.0.1:PORT</code> for a program on this host (it must listen on 0.0.0.0 or the Docker bridge), or <code>http(s)://IP:PORT</code> on your LAN.</p>
    </section>
    <section class="px-help">
      <h2>Before it works</h2>
      <details open><summary>DNS: point the name at this server</summary>
        <p class="small">Create an <b>A record</b> for the host (e.g. <code>soc.example.com</code>) with this server's IP address in your DNS provider or internal DNS (AD, Pi-hole, router). For a quick test, a hosts-file line on the client works too: <code>SERVER-IP soc.example.com</code>. Behind NAT, use the public IP and forward ports ${esc(d.https_port || 443)} and ${esc(d.http_port || 80)} here. The doctor warns when a name does not resolve to this machine.</p></details>
      <details><summary>Trust the local CA on each device</summary>
        <ul class="px-os small">
          <li><b>Windows</b> - double-click the downloaded <code>.crt</code> → Install certificate → Local Machine → "Trusted Root Certification Authorities". Or in an admin PowerShell: <code>Import-Certificate -FilePath .\\vexor-local-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root</code></li>
          <li><b>macOS</b> - <code>sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain vexor-local-ca.crt</code> (or Keychain Access → System → import, then "Always Trust").</li>
          <li><b>Linux</b> - <code>sudo cp vexor-local-ca.crt /usr/local/share/ca-certificates/ &amp;&amp; sudo update-ca-certificates</code>. Firefox: Settings → Privacy &amp; Security → Certificates → View → Authorities → Import.</li>
          <li><b>Android</b> - Settings → Security → Encryption &amp; credentials → Install a certificate → CA certificate → pick the file.</li>
          <li><b>iPhone / iPad</b> - open the file in Safari → Allow → Settings → Profile Downloaded → Install, then Settings → General → About → Certificate Trust Settings → turn on full trust for the CA.</li>
          <li><b>Company-wide</b> - Group Policy → Public Key Policies → Trusted Root Certification Authorities → Import.</li>
        </ul></details>
      <details><summary>Let's Encrypt instead</summary>
        <p class="small">Choose TLS <b>Let's Encrypt</b> for a public domain: the name must resolve to this server and port 80 must be reachable from the internet (HTTP-01 challenge on ROUTES_HTTP_PORT). Nothing to install on the devices. IP addresses need the local CA.</p></details>
    </section>
    <dialog class="confirm px-dialog" data-px-dialog>
      <form class="confirm__box px-edit" data-px-editform novalidate>
        <h2>Edit <span class="mono" data-px-edit-host></span></h2>
        <div class="px-form px-form--stack" data-px-edit-fields></div>
        <div class="confirm__actions"><button class="btn btn--ghost" type="button" data-px-cancel>Cancel</button><button class="btn btn--primary" type="submit">Save</button></div>
      </form>
    </dialog>`);
}

const ROUTES = { overview: vOverview, map: vMap, containers: vContainers, stacks: vStacks, storage: vStorage, proxy: vProxy, logins: vLogins, settings: vSettings, terminal: vTerminal };
// Pages that were merged into others: the old address opens the new page at the matching section.
const MOVED = { health: ["overview", "sec-health"], ports: ["settings", "sec-ports"], volumes: ["storage", "sec-volumes"], activity: ["terminal", "sec-activity"], reset: ["settings", "sec-remove"] };
// Scroll a section of the page on screen into view (below the sticky bar on phones) and move focus there for keyboards.
function jumpTo(id) {
  const el = id && document.getElementById(id);
  if (!el || !view().contains(el)) return false;
  el.scrollIntoView({ block: "start" });
  if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1");
  el.focus({ preventScroll: true });
  return true;
}
// The page on screen: its fetches share one AbortController, aborted as soon as another page opens.
let PAGE = { key: "", ctl: new AbortController(), soft: false, fresh: false };
async function route() {
  closeMenu(false);
  let key = (location.hash || "#overview").slice(1), jump = "";
  if (MOVED[key]) { [key, jump] = MOVED[key]; history.replaceState(null, "", "#" + key); }
  if (!ROUTES[key]) key = "overview";
  PAGE.ctl.abort();
  PAGE.cleanup?.();
  clearTimeout(liveTimer);
  const pg = (PAGE = { key, ctl: new AbortController(), soft: false, fresh: false });
  const v = view();
  v.onclick = v.onchange = v.onsubmit = v.oninput = null;
  v.dataset.page = "";
  liveAt = 0; liveErr = "";
  $$("[data-nav] a").forEach((a) => a.setAttribute("aria-current", a.getAttribute("href") === "#" + key ? "page" : "false"));
  if (matchMedia("(max-width: 760px)").matches) { const nav = $("[data-nav]"), cur = $("[data-nav] a[aria-current=page]"); if (cur) nav.scrollLeft = Math.max(0, cur.offsetLeft - 16); }   // top bar scrolls: keep the current page in view
  liveShow();
  try {
    await ROUTES[key]();
    if (PAGE === pg) liveAt = Date.now();
    if (PAGE === pg && jump) requestAnimationFrame(() => PAGE === pg && jumpTo(jump));
  } catch (e) {
    if (PAGE !== pg || e.name === "AbortError" || e.message === "login required") return;
    if (v.dataset.page === key) liveErr = e.message || "update failed";      // keep what is on screen
    else { v.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  }
  if (PAGE === pg) { liveShow(); liveSchedule(LIVE[key]); }
}

// ---------------------------------------------------------------- live refresh
// Pages with live data refresh quietly in place: no placeholder, no scroll jump, focus and open menus stay. A tick is
// skipped while the user is busy (menu or dialog open, typing, selecting text, pressing) or the tab is hidden, never
// overlaps the previous one, and backs off when the server is slow. Forms (Settings, Terminal, ...) never refresh
// on their own. A small indicator in the header says when the data was read.
const LIVE = { overview: 15000, containers: 10000, map: 3000 };
const AFTER_JOB = new Set(["overview", "containers", "storage", "stacks", "proxy", "map"]);   // + the Terminal's activity part
let liveTimer = null, liveRun = null, liveAt = 0, liveErr = "", pointerDown = 0;
document.addEventListener("pointerdown", () => (pointerDown = Date.now()), true);
for (const ev of ["pointerup", "pointercancel"]) document.addEventListener(ev, () => (pointerDown = 0), true);
window.addEventListener("blur", () => (pointerDown = 0));
function busy() {
  if ($("[data-app]").hidden || document.hidden || Date.now() - pointerDown < 5000 || openMenu || document.querySelector("dialog[open]")) return true;
  const a = document.activeElement;
  if (a && view().contains(a) && (a.isContentEditable || /^(TEXTAREA|SELECT)$/.test(a.tagName) || (a.tagName === "INPUT" && !/^(checkbox|radio|button|submit|reset|range|color)$/.test(a.type)))) return true;
  const sel = getSelection();
  return !!(sel && !sel.isCollapsed && sel.toString().trim() && view().contains(sel.anchorNode));
}
function stopLive() { clearTimeout(liveTimer); liveTimer = null; PAGE.ctl.abort(); }
// Re-read the current page's data and update it in place. fresh: the server waits for new data instead of its cache.
async function refresh({ fresh = false, force = false } = {}) {
  const pg = PAGE;
  if (!AFTER_JOB.has(pg.key) || pg.ctl.signal.aborted) return false;
  if (liveRun) { if (!fresh) return liveRun; await liveRun; if (PAGE !== pg) return false; }
  if (!force && busy()) return false;
  pg.soft = true; pg.fresh = fresh;
  const t0 = performance.now();
  liveShow(true);
  const run1 = (async () => {
    try { await ROUTES[pg.key](); if (PAGE === pg) { liveAt = Date.now(); liveErr = ""; } return true; }
    catch (e) { if (PAGE === pg && e.name !== "AbortError" && e.message !== "login required") liveErr = e.message || "update failed"; return false; }
    finally { pg.soft = pg.fresh = false; pg.took = performance.now() - t0; }
  })();
  liveRun = run1;
  const ok = await run1;
  if (liveRun === run1) liveRun = null;
  liveShow();
  return ok;
}
function liveSchedule(ms) { clearTimeout(liveTimer); liveTimer = ms ? setTimeout(liveTick, ms) : null; }
async function liveTick() {
  const pg = PAGE, base = LIVE[pg.key];
  if (!base) return;
  if (busy()) return liveSchedule(Math.min(base, 2000));       // try again soon, not on top of the user
  const ok = await refresh();
  if (PAGE !== pg) return;
  // slow answers stretch the interval (up to a minute); failures double it
  pg.delay = ok ? Math.min(60000, Math.max(base, (pg.took || 0) * 4)) : Math.min(60000, (pg.delay || base) * 2);
  liveSchedule(pg.delay);
}
// After a command ends: one quiet, fresh refresh of the page on screen, once the user is not in the middle of something.
function afterJob() {
  const pg = PAGE;
  if (pg.key === "terminal") { setTimeout(() => termActivity().catch(() => {}), 400); return; }
  if (!AFTER_JOB.has(pg.key)) return;
  let tries = 0;
  const go = () => {
    if (PAGE !== pg) return;
    if (busy() && tries++ < 60) return setTimeout(go, 1000);
    if (tries <= 60) refresh({ fresh: true, force: true });
  };
  setTimeout(go, 400);
}
document.addEventListener("visibilitychange", () => {
  const base = LIVE[PAGE.key];
  if (!document.hidden && base && Date.now() - liveAt > base) liveSchedule(300);   // back on the tab: catch up at once
});
function ago(ms) { const s = Math.round(ms / 1000); return s < 5 ? "just now" : s < 90 ? `${s}s ago` : `${Math.round(s / 60)}m ago`; }
function liveShow(spin = !!liveRun) {
  const el = $("[data-live]");
  if (!el) return;
  const shown = AFTER_JOB.has(PAGE.key) && (liveAt || spin);
  el.hidden = !shown;
  if (!shown) return;
  el.classList.toggle("is-busy", spin);
  el.classList.toggle("is-err", !spin && !!liveErr);
  const txt = spin ? "updating…" : liveErr ? `update failed · ${ago(Date.now() - liveAt)}` : `updated ${ago(Date.now() - liveAt)}`;
  const t = $("[data-live-txt]", el);
  if (t.textContent !== txt) t.textContent = txt;
  el.title = liveErr ? liveErr : LIVE[PAGE.key] ? `Refreshes on its own every ${Math.round((PAGE.delay || LIVE[PAGE.key]) / 1000)} s` : "Refreshes after each command";
}
setInterval(() => { if (!document.hidden) liveShow(); }, 1000);

window.addEventListener("hashchange", () => route());
$("[data-refresh]").addEventListener("click", () => (AFTER_JOB.has(PAGE.key) ? refresh({ fresh: true, force: true }) : PAGE.key === "terminal" ? termActivity().catch(() => {}) : route()));
boot();
