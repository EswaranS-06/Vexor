# shellcheck shell=bash
# vexor lib/19-console.sh - notifications, plan, login, console (web UI) + JSON for it
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== notifications: health results off the host
# NOTIFY_URL  Slack / Teams / Discord incoming webhook, or any URL that takes JSON. Empty + n8n connected ->
#             the n8n webhook, as a Wazuh-shaped alert (rule.level 12 fail / 7 warn / 3 recovered), so the
#             starter workflow routes it by severity. NOTIFY_VIA_N8N=no turns that off.
# NOTIFY_ON   fail (default) | warn | off      NOTIFY_REPEAT_HOURS   re-send a problem that persists (default 6)
notify_target() {
  local u; u="$(env_get NOTIFY_URL)"
  [ -z "$u" ] && [ -n "$(n8n_hook)" ] && [ "$(env_def NOTIFY_VIA_N8N yes)" = yes ] && u="n8n"
  echo "$u"
}
notify_send() {                # notify_send <fail|warn|ok|info> <title> <body>  -> 0 when delivered
  local url; url="$(notify_target)"; [ -n "$url" ] || return 1
  local n8n_url=""
  if [ "$url" = n8n ]; then  # the managers' internal n8n address is not reachable from the host: go through nginx
    n8n_url="$(n8n_hook | sed -E -e "s#^https?://n8n:5678#https://$(local_ip):$(tool_port n8n)#" \
                                 -e "s#^https://($(public_host)|localhost):$(tool_port n8n)/#https://$(local_ip):$(tool_port n8n)/#")"
  fi
  python3 -I - "$url" "$1" "$2" "$3" "$(hostname)" "$(public_host)" "$(env_get N8N_HOOK_TOKEN)" "$n8n_url" "$(env_def NOTIFY_FORMAT auto)" "$STATE_DIR/notify.err" "$(local_ip)" <<'PY'
import json, ssl, sys, time, urllib.request
url, level, title, body, host, pub, token, n8n_url, fmt, errf, own = sys.argv[1:12]
headers = {"Content-Type": "application/json", "User-Agent": "vexor-notify"}
ctx = None
if url == "n8n":
    url = n8n_url
    lvl = {"fail": 12, "warn": 7, "ok": 3, "info": 3}.get(level, 3)
    payload = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000%z"), "id": f"vexor-{int(time.time())}",
               "rule": {"level": lvl, "id": "vexor-health", "description": title, "groups": ["vexor", "health"]},
               "agent": {"id": "000", "name": host}, "manager": {"name": host}, "full_log": body, "location": "vexor"}
    headers.update({"X-Vexor-Token": token, "X-Vexor-Source": "vexor-health"})
    if url.startswith("https://%s:" % own):
        ctx = ssl._create_unverified_context()   # our own nginx, self-signed by default
else:
    icon = {"fail": "🔴", "warn": "🟠", "ok": "🟢", "info": "🔵"}.get(level, "")
    text = f"{icon} {title}\n{body}"
    kind = fmt if fmt != "auto" else ("slack" if "hooks.slack.com" in url else "discord" if "discord.com/api/webhooks" in url
                                      else "teams" if ("webhook.office.com" in url or "logic.azure.com" in url) else "json")
    payload = {"slack": {"text": text}, "teams": {"text": text.replace("\n", "<br>")}, "discord": {"content": text[:1900]},
               "json": {"source": "vexor", "level": level, "title": title, "body": body, "host": host, "public_host": pub,
                        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z")}}[kind]
try:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
        code = r.status
    if code >= 300:
        raise RuntimeError(f"HTTP {code}")
    open(errf, "w").close()
except Exception as e:  # noqa: BLE001 - any delivery failure is reported the same way
    open(errf, "w").write(f"{time.strftime('%F %T')} {type(e).__name__}: {e}\n")
    sys.exit(1)
PY
}
notify_health() {              # called by autoheal with the new status; decides whether to send
  local status="$1" detail="$2" on prev pepoch now repeat
  on="$(env_def NOTIFY_ON fail)"; [ "$on" = off ] && return 0
  [ -n "$(notify_target)" ] || return 0
  IFS='|' read -r prev pepoch < "$STATE_DIR/notify.last" 2>/dev/null || { prev=OK; pepoch=0; }
  now="$(date +%s)"; repeat=$(( $(env_def NOTIFY_REPEAT_HOURS 6) * 3600 ))
  local bad=0; [ "$status" = FAIL ] && bad=1; [ "$status" = WARN ] && [ "$on" = warn ] && bad=1
  if [ "$bad" = 1 ]; then
    if [ "$prev" != "$status" ] || [ $(( now - ${pepoch:-0} )) -ge "$repeat" ]; then
      notify_send "$(tr 'A-Z' 'a-z' <<<"$status")" "Vexor on $(hostname): health check $status" "$detail" \
        && { echo "$status|$now" > "$STATE_DIR/notify.last"; log "notification sent ($status)"; } || log "notification failed: $(cat "$STATE_DIR/notify.err" 2>/dev/null)"
    fi
  elif [ "$prev" != OK ]; then
    notify_send ok "Vexor on $(hostname): recovered" "$detail" && { echo "OK|$now" > "$STATE_DIR/notify.last"; log "notification sent (recovered)"; }
  fi
  return 0
}
cmd_notify() {
  case "${1:-status}" in
    status)
      hdr "Notifications"
      local t; t="$(notify_target)"
      if [ -z "$t" ]; then warn "no target: set NOTIFY_URL (Slack, Teams, Discord or JSON webhook), or connect n8n (vexor n8n connect)"; return 0; fi
      [ "$t" = n8n ] && say "target : n8n webhook $(n8n_hook) (as a Wazuh-shaped alert)" || say "target : $(sed -E 's#(https?://[^/]+/).{6,}#\1…#' <<<"$t")"
      say "when   : NOTIFY_ON=$(env_def NOTIFY_ON fail), repeat every $(env_def NOTIFY_REPEAT_HOURS 6) h while it lasts, plus a recovered message"
      [ -s "$STATE_DIR/notify.err" ] && bad "last delivery failed: $(cat "$STATE_DIR/notify.err")" || ok "last delivery ok (or nothing sent yet)"
      [ -f "$STATE_DIR/notify.last" ] && say "last sent: $(cut -d'|' -f1 "$STATE_DIR/notify.last") at $(date -d "@$(cut -d'|' -f2 "$STATE_DIR/notify.last")" '+%F %H:%M')" ;;
    test)
      notify_send info "Vexor on $(hostname): test notification" "If you can read this, health alerts from vexor reach you. $(date '+%F %T')" \
        && ok "test notification delivered" || die "delivery failed: $(cat "$STATE_DIR/notify.err" 2>/dev/null || echo 'no target - set NOTIFY_URL')" ;;
    send)
      local lvl="${2:-info}"; shift 2 2>/dev/null || true
      [[ "$lvl" =~ ^(fail|warn|ok|info)$ ]] || die "usage: vexor notify send <fail|warn|ok|info> <message>"
      notify_send "$lvl" "Vexor on $(hostname)" "$*" && ok "sent" || die "delivery failed: $(cat "$STATE_DIR/notify.err" 2>/dev/null)" ;;
    *) die "usage: vexor notify [status] | test | send <fail|warn|ok|info> <message>" ;;
  esac
}

# ============================================================== plan: preview what an apply would change
# vexor plan                 -> .env edits since the last apply, and what `config apply` would recreate
# vexor plan KEY=VALUE ...   -> the same for a change that is not written yet (nothing is modified)
# The new override + nginx.conf are rendered into a temp dir and `docker compose --dry-run up -d` runs against them.
record_applied_env() { mkdir -p "$STATE_DIR"; cp "$ENV_FILE" "$STATE_DIR/env.applied" 2>/dev/null && chmod 600 "$STATE_DIR/env.applied"; return 0; }
cmd_plan() {
  local json=0 kv d base cf
  local -a sets=()
  for kv in "$@"; do
    [ "$kv" = --json ] && { json=1; continue; }
    [[ "$kv" =~ ^[A-Z][A-Z0-9_]*=.*$ ]] || die "usage: vexor plan [KEY=VALUE ...] [--json]"
    case "${kv%%=*}" in *PASSWORD) die "passwords are not planned - vexor passwd" ;; esac
    sets+=("$kv")
  done
  d="$RUN_TMP/plan"; mkdir -p "$d"
  cp "$ENV_FILE" "$d/.env"
  base="$STATE_DIR/env.applied"; [ -f "$base" ] || base="$ENV_FILE"
  (
    ENV_FILE="$d/.env"; OVERRIDE_FILE="$d/override.yml"; NGINX_CONF="$d/nginx.conf"
    for kv in "${sets[@]}"; do env_set "${kv%%=*}" "${kv#*=}"; done
    sync_profiles; render_override; render_nginx
    enabled_services > "$d/enabled"
  ) >/dev/null 2>&1
  cf="docker-compose.yml:docker-compose.tools.yml:docker-compose.elk.yml:$d/override.yml"
  (cd "$ROOT" && COMPOSE_FILE="$cf" COMPOSE_PROFILES="$(grep -E '^COMPOSE_PROFILES=' "$d/.env" | tail -1 | cut -d= -f2-)" \
     docker compose --env-file "$d/.env" --dry-run up -d --pull never 2>&1) > "$d/dry"   # never: a dry run would still pull missing images
  running_services > "$d/running" 2>/dev/null
  dc_all ps -a --services > "$d/existing" 2>/dev/null
  diff -u "$NGINX_CONF" "$d/nginx.conf" > "$d/nginx.diff" 2>/dev/null
  volume_orphans 2>/dev/null | cut -f1,2 > "$d/orphans"
  python3 -I - "$base" "$d/.env" "$d/dry" "$d/enabled" "$d/running" "$d/nginx.diff" "$json" "$(project)" "$( [ -f "$STATE_DIR/env.applied" ] && echo 1 || echo 0)" "$d/orphans" "$d/existing" <<'PY'
import json, re, sys
base, new, dry, enabled, running, ndiff, as_json, proj, have_base, orphans, existing = sys.argv[1:12]
def env(p):
    out = {}
    for line in open(p, errors="replace"):
        m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line.rstrip("\n"))
        if not m:
            continue
        v = m.group(2)
        c = re.search(r"\s+#", v)
        if c and not v.startswith("#"):
            v = v[: c.start()]
        out[m.group(1)] = v.strip().strip('"').strip("'")
    return out
SECRET = re.compile(r"(PASSWORD|SECRET|TOKEN|_KEY)$")
IGNORE = {"COMPOSE_PROFILES", "COMPOSE_FILE"}
a, b = env(base), env(new)
settings = []
for k in sorted(set(a) | set(b)):
    if k in IGNORE or a.get(k) == b.get(k):
        continue
    secret = bool(SECRET.search(k))
    settings.append({"key": k, "old": "(set)" if secret and a.get(k) else a.get(k), "new": "(changed)" if secret else b.get(k)})
recreate, create = [], []
for line in open(dry, errors="replace"):
    m = re.match(r"\s*Container\s+(\S+)\s+(Recreate|Creating)\s*$", line)
    if not m:
        continue
    name = re.sub(r"^[0-9a-f]{12}_", "", m.group(1))
    svc = re.sub(rf"^{re.escape(proj)}-(.*)-\d+$", r"\1", name)
    (recreate if m.group(2) == "Recreate" else create).append(svc)
en = set(open(enabled).read().split())
create += [x for x in en if x not in set(open(existing).read().split())]   # enabled, no container yet
recreate, create = sorted(set(recreate)), sorted(set(create) - set(recreate))
remove = sorted(s for s in open(running).read().split() if s not in en)
nginx_lines = [l for l in open(ndiff, errors="replace") if l[:1] in "+-" and not l.startswith(("+++", "---"))]
DOWN = {
    "wazuh.master": "agents reconnect within about a minute; enrollment and the API pause",
    "nginx": "every web UI and the agent port drop for a few seconds",
    "wazuh.dashboard": "the dashboard is unavailable for about a minute",
    "elasticsearch": "Kibana and Logstash wait for Elasticsearch (about a minute)",
    "suricata": "a short gap in IDS alerts", "zeek": "a short gap in network logs",
}
notes = []
for s in recreate + create:
    if s in DOWN:
        notes.append(f"{s}: {DOWN[s]}")
    elif s.startswith("wazuh") and "worker" in s:
        notes.append(f"{s}: its agents move to another manager and come back")
    elif "indexer" in s:
        notes.append(f"{s}: the cluster is yellow while it restarts; filebeat queues alerts")
keys = {x["key"] for x in settings}
if {"NODE_TYPE", "WORKER_COUNT", "INDEXER_COUNT"} & keys:
    notes.append("layout changes are applied by vexor node-type / scale / indexers, which move the data first")
if {"SOC"} & keys:
    notes.append("SOC changes are applied by vexor soc, which also sets up ELK users, retention and data views")
if any(k.endswith("_PORT") for k in keys):
    notes.append("clients, agents and firewall rules must use the new ports; Vexor does not change firewall rules")
if keys & {"SURICATA", "ZEEK", "ZEEK_WAZUH_LOGS", "N8N"}:
    notes.append("tools apply also updates the master's log sources / integration, which recreates the master")
if "WAZUH_SCA" in keys:
    notes.append("WAZUH_SCA changes ossec.conf, which recreates every manager; agents follow the manager's SCA setting only if their own ossec.conf has it enabled")
if "WAZUH_VULN_DETECTION" in keys:
    notes.append("WAZUH_VULN_DETECTION changes ossec.conf, which recreates every manager (turning it off also deletes the downloaded CVE feed; on downloads it again, about 13 GB per manager)")
orph = []
for line in open(orphans, errors="replace"):
    v, _, b = line.rstrip("\n").partition("\t")
    if v:
        orph.append({"volume": v, "bytes": int(b or 0)})
if orph:
    notes.append(f"{len(orph)} unused volume(s) take {sum(o['bytes'] for o in orph) // 1048576} MB: vexor volumes orphans (remove: vexor volumes prune)")
if not (settings or recreate or create or remove or nginx_lines):
    notes.append("nothing to apply")
res = {"settings": settings, "recreate": recreate, "create": create, "remove": remove,
       "nginx_changes": len(nginx_lines), "orphan_volumes": orph, "notes": notes, "baseline": "last apply" if have_base == "1" else "current .env (no apply recorded yet)"}
if as_json == "1":
    print(json.dumps(res)); sys.exit()
print(f"==> Plan (compared with the {res['baseline']})")
if settings:
    print("  settings:")
    for x in settings:
        print(f"    {x['key']}: {x['old'] if x['old'] is not None else '(new)'} -> {x['new'] if x['new'] is not None else '(removed)'}")
else:
    print("  settings: no changes")
for label, items in (("recreate", recreate), ("create", create), ("remove", remove)):
    if items:
        print(f"  {label}: {' '.join(items)}")
if nginx_lines:
    print(f"  nginx.conf: {len(nginx_lines)} changed lines (reload)")
for n in notes:
    print(f"  → {n}")
PY
}

# ============================================================== login: every user + password Vexor manages
# vexor login [service|container ...] [--json]   (root only - prints secrets; also on the console's Logins page)
cmd_login() {
  local json=0 a; local -a want=()
  for a in "$@"; do [ "$a" = --json ] && json=1 || want+=("$a"); done
  local h; h="$(public_host)"
  local on_w=0 on_e=0; soc_wazuh && on_w=1; soc_elk && on_e=1
  python3 -I - "$json" "$h" "$on_w" "$on_e" "$(enabled_tools | tr '\n' ' ')" "$(console_on && echo 1 || echo 0)" "$ENV_FILE" "${want[@]}" <<'PY'
import json, re, sys
as_json, host, on_w, on_e, tools, con, envf, *want = sys.argv[1:]
on_w, on_e, con, tools = on_w == "1", on_e == "1", con == "1", set(tools.split())
env = {}
for line in open(envf, errors="replace"):
    m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line.rstrip("\n"))
    if m:
        v = m.group(2); c = re.search(r"\s+#", v)
        env[m.group(1)] = (v[: c.start()] if c and not v.startswith("#") else v).strip().strip('"').strip("'")
g = lambda k, d="": env.get(k) or d
pw = lambda k: "" if g(k) in ("", "CHANGE_ME") else g(k)
# id, service (container), name, url, user, password key, enabled, note
E = [
    ("dashboard", "wazuh.dashboard", "Wazuh dashboard", f"https://{host}:{g('PROXY_PORT', '8080')}", g("INDEXER_USERNAME", "admin"), "INDEXER_PASSWORD", on_w, "same user as the indexer admin"),
    ("indexer", "wazuh1.indexer", "Wazuh indexer API", f"https://127.0.0.1:{g('INDEXER_HOST_PORT', '9200')}", g("INDEXER_USERNAME", "admin"), "INDEXER_PASSWORD", on_w, "bound to INDEXER_BIND (this host only by default)"),
    ("kibanaserver", "wazuh.dashboard", "Dashboard -> indexer (internal)", "", g("DASHBOARD_USERNAME", "kibanaserver"), "DASHBOARD_PASSWORD", on_w, "used by the dashboard container; change with vexor passwd kibanaserver"),
    ("api", "wazuh.master", "Wazuh API", f"https://{host}:{g('API_PORT', '55000')}", g("API_USERNAME", "wazuh-wui"), "API_PASSWORD", on_w, "POST /security/user/authenticate for a token"),
    ("api-n8n", "wazuh.master", "Wazuh API for n8n", "https://wazuh.master:55000", g("WAZUH_N8N_USER", "vexor-n8n"), "WAZUH_N8N_PASSWORD", on_w and bool(pw("WAZUH_N8N_PASSWORD")), "least privilege: agents, active response (vexor n8n credentials)"),
    ("enroll", "wazuh.master", "Agent enrollment", f"{host}:{g('ENROLL_PORT', '1515')}", "", "AGENT_ENROLL_PASSWORD", on_w and bool(pw("AGENT_ENROLL_PASSWORD")), "agents send it when they enroll (vexor agents enroll-cmd includes it)"),
    ("kibana", "kibana", "Kibana", f"https://{host}:{g('KIBANA_PORT', '55601')}", "elastic", "ELASTIC_PASSWORD", on_e, "the Elastic superuser"),
    ("elasticsearch", "elasticsearch", "Elasticsearch API", f"http://127.0.0.1:{g('ES_PORT', '59200')}", "elastic", "ELASTIC_PASSWORD", on_e, "bound to ES_BIND (this host only by default)"),
    ("kibana_system", "kibana", "Kibana -> Elasticsearch (internal)", "", "kibana_system", "KIBANA_SYSTEM_PASSWORD", on_e, "used by the Kibana container"),
    ("logstash", "logstash", "Logstash writer (internal)", "http://elasticsearch:9200", "vexor_logstash", "LOGSTASH_ES_PASSWORD", on_e, "can only write vexor-*"),
    ("es-n8n", "elasticsearch", "Elasticsearch for n8n", "http://elasticsearch:9200", "vexor_n8n", "ES_N8N_PASSWORD", on_e and bool(pw("ES_N8N_PASSWORD")), "read vexor-* (vexor n8n credentials)"),
    ("grafana", "grafana", "Grafana", f"https://{host}:{g('GRAFANA_PORT', '53000')}", "admin", "GRAFANA_ADMIN_PASSWORD", "grafana" in tools, "applied on Grafana's first start; a change made inside Grafana is not tracked"),
    ("grafana-indexer", "grafana", "Grafana -> indexer (internal)", "https://wazuh1.indexer:9200", "grafana", "GRAFANA_INDEXER_PASSWORD", "grafana" in tools and on_w, "read-only on the Wazuh indices"),
    ("portainer", "portainer", "Portainer", f"https://{host}:{g('PORTAINER_PORT', '59443')}", "admin", "PORTAINER_ADMIN_PASSWORD", "portainer" in tools, "applied on Portainer's first start; a change made inside Portainer is not tracked"),
    ("n8n", "n8n", "n8n", f"https://{host}:{g('N8N_PORT', '55678')}", "(the owner you created)", "", "n8n" in tools, "n8n keeps its own accounts; lost the owner? vexor n8n reset-owner"),
    ("n8n-token", "n8n", "n8n webhook token (X-Vexor-Token)", g("N8N_HOOK_URL"), "", "N8N_HOOK_TOKEN", "n8n" in tools and bool(pw("N8N_HOOK_TOKEN")), "sent with every alert; the starter workflow checks it"),
    ("console", "console", "Vexor Console", f"https://{host}:{g('CONSOLE_PORT', '50443')}", g("CONSOLE_USER", "admin"), "CONSOLE_PASSWORD", con, "vexor console password --generate rotates it"),
]
NOLOGIN = {"nginx": "nginx has no login; it serves the UIs above", "suricata": "Suricata has no login (vexor suricata)",
           "zeek": "Zeek has no login (vexor zeek)"}
ALIAS = {"wazuh": "wazuh.master", "master": "wazuh.master", "manager": "wazuh.master", "workers": "wazuh.master",
         "wazuh.worker": "wazuh.master", "wazuh2.worker": "wazuh.master", "wazuh3.worker": "wazuh.master",
         "indexer1": "wazuh1.indexer", "wazuh2.indexer": "wazuh1.indexer", "wazuh3.indexer": "wazuh1.indexer",
         "indexers": "wazuh1.indexer", "es": "elasticsearch", "elastic": "elasticsearch", "elk": "elk", "ui": "console"}
rows = []
for eid, svc, name, url, user, key, en, note in E:
    if want:
        hit = False
        for w in want:
            w = ALIAS.get(w.lower(), w.lower())
            if w in (eid, svc, name.lower()) or (w == "elk" and svc in ("kibana", "elasticsearch", "logstash")) or (w == "wazuh" and svc.startswith("wazuh")):
                hit = True
        if not hit:
            continue
    elif not en:
        continue
    rows.append({"id": eid, "service": svc, "name": name, "url": url, "user": user, "password": pw(key) if key else "",
                 "key": key, "enabled": bool(en), "note": note})
missing = [w for w in want if not any(ALIAS.get(w.lower(), w.lower()) in (r["id"], r["service"]) or w.lower() in ("elk", "wazuh") for r in rows)]
if as_json == "1":
    print(json.dumps({"logins": rows, "nologin": {w: NOLOGIN[w] for w in want if w in NOLOGIN}})); sys.exit()
if not rows and not missing:
    print("  nothing enabled has a login"); sys.exit()
print("==> Logins  (secrets shown - keep this output private)")
for r in rows:
    off = "" if r["enabled"] else "   [not running: its stack/tool is off]"
    print(f"\n  {r['name']}{off}")
    if r["url"]:
        print(f"    url       {r['url']}")
    if r["user"]:
        print(f"    user      {r['user']}")
    if r["key"]:
        print(f"    password  {r['password'] or '(not generated yet - starts with the service)'}")
    print(f"    note      {r['note']}")
for w in missing:
    print(f"\n  {w}: {NOLOGIN.get(w.lower(), 'no login known for this name - try: vexor login (all) or a service name from vexor status')}")
PY
}

# ============================================================== console (web UI) + JSON for it
# vexor-console.service runs console/server.py (python3 stdlib) as root on CONSOLE_BIND:CONSOLE_PORT with the
# dashboard certificate. Every action in the UI is a `vexor` command from an allowlist (see console/server.py).
console_on() { [[ "$(env_def CONSOLE true)" =~ ^(true|yes|on|1)$ ]]; }
console_port() { env_def CONSOLE_PORT 50443; }
console_bind() { env_def CONSOLE_BIND "$(bind_ip)"; }     # empty CONSOLE_BIND follows BIND_IP
console_url() { echo "https://$(public_host):$(console_port)"; }
console_fingerprint() {        # restart the console only when something it reads at start changed
  { cat "$ROOT/console/server.py" 2>/dev/null; echo "$(console_port) $(console_bind) $(env_get PROXY_CERT) $(env_get PROXY_KEY)";
    stat -c %Y "$ROOT/$(env_def PROXY_CERT ./config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem)" 2>/dev/null; } | md5sum | cut -d' ' -f1
}
console_unit() {
  cat > "$SYSTEMD_DIR/$UNIT-console.service.tmp" <<EOF
[Unit]
Description=Vexor Console - web UI for vexor ($ROOT)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT
ExecStart=/usr/bin/env python3 -I $ROOT/console/server.py
Restart=on-failure
RestartSec=5
# a restart must not kill a vexor command the console started (e.g. a config apply that changed CONSOLE_PORT)
KillMode=process
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  if cmp -s "$SYSTEMD_DIR/$UNIT-console.service.tmp" "$SYSTEMD_DIR/$UNIT-console.service"; then
    rm -f "$SYSTEMD_DIR/$UNIT-console.service.tmp"; return 1
  fi
  mv "$SYSTEMD_DIR/$UNIT-console.service.tmp" "$SYSTEMD_DIR/$UNIT-console.service"; return 0
}
console_sync() {               # make the service match CONSOLE in .env (called by start/apply/daemon install)
  command -v systemctl >/dev/null || return 0
  [ -f "$ROOT/console/server.py" ] || return 0
  if ! console_on; then
    if systemctl is-enabled -q "$UNIT-console.service" 2>/dev/null || systemctl is-active -q "$UNIT-console.service" 2>/dev/null; then
      systemctl disable --now "$UNIT-console.service" >/dev/null 2>&1; ok "console stopped (CONSOLE=false)"
    fi
    return 0
  fi
  local p; p="$(console_port)"
  [[ "$p" =~ ^5[0-9]{4}$ ]] || { bad "CONSOLE_PORT=$p - use a port in 50000-59999"; return 1; }
  if port_listening "$p" && ! ss -Hltnp "( sport = :$p )" 2>/dev/null | has 'python3'; then
    bad "CONSOLE_PORT=$p is used by another program: $(ss -Hltnp "( sport = :$p )" | awk '{print $NF}' | head -1)"; return 1
  fi
  gen_secret CONSOLE_PASSWORD
  local changed=0 fp; console_unit && changed=1
  systemctl daemon-reload
  systemctl enable "$UNIT-console.service" >/dev/null 2>&1
  fp="$(console_fingerprint)"
  if [ "$changed" = 1 ] || [ "$fp" != "$(cat "$STATE_DIR/console.fingerprint" 2>/dev/null)" ] || ! systemctl is-active -q "$UNIT-console.service"; then
    systemctl restart "$UNIT-console.service" && echo "$fp" > "$STATE_DIR/console.fingerprint"
    local i; for i in $(seq 1 20); do console_answers && break; sleep 0.5; done
    console_answers && ok "console: $(console_url)  (user $(env_def CONSOLE_USER admin))" || bad "console did not start - vexor console logs"
  fi
  return 0
}
console_answers() { [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 "https://$(local_ip "$(console_bind)"):$(console_port)/api/session" 2>/dev/null)" = 200 ]; }
cmd_console() {
  local sub="${1:-status}"; shift || true
  case "$sub" in
    status)
      hdr "Vexor Console"
      console_on || { warn "CONSOLE=false - turn it on: vexor console enable"; return 0; }
      systemctl is-active -q "$UNIT-console.service" && ok "service $UNIT-console running" || bad "service $UNIT-console not running - vexor console restart"
      console_answers && ok "answers on $(console_url)" || bad "nothing answers on port $(console_port)"
      say "user: $(env_def CONSOLE_USER admin)   password: vexor console password"
      say "actions are logged to $STATE_DIR/console-audit.log" ;;
    enable|on) take_lock; env_set CONSOLE true; console_sync ;;
    disable|off) take_lock; env_set CONSOLE false; console_sync ;;
    restart) take_lock; rm -f "$STATE_DIR/console.fingerprint"; console_sync ;;
    url) console_url ;;
    password)
      if [ "${1:-}" = "--generate" ]; then
        env_set CONSOLE_PASSWORD "$(gen_pw)"; chmod 600 "$ENV_FILE"
        ok "new console password: $(env_get CONSOLE_PASSWORD)   (sessions stay valid until they expire)"
      else
        gen_secret CONSOLE_PASSWORD >/dev/null; say "user $(env_def CONSOLE_USER admin)  password $(env_get CONSOLE_PASSWORD)"
      fi ;;
    logs) journalctl --no-pager -n "${1:-80}" -u "$UNIT-console.service" ;;
    *) die "usage: vexor console [status] | enable | disable | restart | url | password [--generate] | logs [N]" ;;
  esac
}

cmd_json() {                   # machine-readable state for the console (and scripts)
  case "${1:-state}" in
    state)
      local tools="" t urls=()
      for t in "${TOOLS[@]}"; do tool_on "$t" && tools+="$t "; done
      soc_wazuh && urls+=("Wazuh dashboard|https://$(public_host):$(env_def PROXY_PORT 8080)")
      soc_elk && urls+=("Kibana|https://$(public_host):$(env_def KIBANA_PORT 55601)")
      for t in $(web_tools); do [ "$t" = kibana ] || urls+=("$t|https://$(public_host):$(tool_port "$t")"); done
      console_on && urls+=("Console|$(console_url)")
      python3 -I - "$VEXOR_VERSION" "$(cur_version 2>/dev/null)" "$(soc)" "$(node_type 2>/dev/null)" "$(desired_node_type 2>/dev/null)" \
        "$(env_def WORKER_COUNT 1)" "$(indexer_count 2>/dev/null)" "$(public_host)" "$(layout_desc 2>/dev/null)" \
        "$(enabled_services | tr '\n' ' ')" "$tools" "$(cat "$STATE_DIR/health.last" 2>/dev/null)" "$(docker_root)" \
        "$(disk_pct "$(docker_root)")" "$(n8n_hook)" "$(n8n_level)" "$(reminders_due | tr '\n' $'\x1e')" \
        "$( [ -f "$STATE_DIR/stopped" ] && echo 1 || echo 0)" "$(printf '%s\x1e' "${urls[@]}")" \
        "$(project)" "$(project_is_legacy && echo 1 || echo 0)" <<'PY'
import json, sys
a = sys.argv[1:]
hl = a[11].split("|")
health = {"epoch": int(hl[0]), "status": hl[1], "pass": int(hl[2]), "warn": int(hl[3]), "fail": int(hl[4])} if len(hl) >= 5 and hl[0].isdigit() else {}
rem = [dict(zip(("msg", "cmd"), r.split("|", 1))) for r in a[16].split("\x1e") if r.strip()]
urls = dict(u.split("|", 1) for u in a[18].split("\x1e") if "|" in u)
print(json.dumps({
    "vexor": a[0], "wazuh_version": a[1], "soc": a[2], "node_type": a[3], "node_type_env": a[4],
    "workers": a[5], "indexers": a[6], "public_host": a[7], "layout": a[8],
    "services": a[9].split(), "tools": {t: True for t in a[10].split()}, "health_last": health,
    "disk": {"path": a[12], "pct": int(a[13]) if a[13].isdigit() else None},
    "n8n": {"hook": a[14], "level": a[15]}, "reminders": rem, "stopped": a[17] == "1", "urls": urls,
    "project": a[19], "legacy_project": a[20] == "1"}))
PY
      ;;
    volumes)
      local v mp first=1
      printf '['
      for v in $(project_volumes); do
        mp="$(docker volume inspect -f '{{.Mountpoint}}' "$v" 2>/dev/null)"
        [ "$first" = 1 ] || printf ','; first=0
        python3 -I -c 'import json,sys; print(json.dumps({"name": sys.argv[1], "short": sys.argv[1].split("_", 1)[-1], "bytes": int(sys.argv[2] or 0), "users": sys.argv[3].split()}), end="")' \
          "$v" "$(du -sb "$mp" 2>/dev/null | cut -f1)" "$(vol_users "$v")"
      done
      printf ']\n' ;;
    *) die "usage: vexor json state | volumes" ;;
  esac
}

