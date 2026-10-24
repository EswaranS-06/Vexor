# shellcheck shell=bash
# vexor lib/06-status.sh - status / health, doctor, logs / exec, info / config
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== status / health
container_rows() {             # svc|status|restarts|oom|health|image|started
  local ids; ids="$(dc_all ps -aq 2>/dev/null)"
  [ -n "$ids" ] || return 0
  docker inspect $ids > "$RUN_TMP/inspect.json" 2>/dev/null || return 0
  python3 -I - "$RUN_TMP/inspect.json" <<'PY'
import json, sys
for x in json.load(open(sys.argv[1])):
    st = x["State"]
    print("|".join(str(v) for v in (
        x["Config"]["Labels"].get("com.docker.compose.service", "?"), st.get("Status", "?"),
        x.get("RestartCount", 0), "oom" if st.get("OOMKilled") else "-",
        (st.get("Health") or {}).get("Status", "-"), x["Config"]["Image"], st.get("StartedAt", ""))))
PY
}
cmd_status() {
  docker_ok || die "Docker daemon is not running"
  printf '%sVexor  |  SOC=%s  |  project %s%s%s\n\n' "$C_BD" "$(soc)" "$(project)" "$(soc_wazuh && echo "  |  Wazuh $(cur_version), $(layout_desc)")" "$C_0"
  project_is_legacy && { hint "the Docker project is still named '$(project)' - rename it with: vexor migrate"; echo; }
  container_rows > "$RUN_TMP/rows"
  python3 -I - "$RUN_TMP/rows" "$(enabled_services | tr '\n' ' ')" "${C_G:+1}" <<'PY'
import datetime, sys
rows = {}
for line in open(sys.argv[1]):
    p = line.rstrip("\n").split("|")
    if len(p) == 7:
        rows[p[0]] = p[1:]
expected = sys.argv[2].split()
color = sys.argv[3] == "1"
def c(code, s): return f"\033[{code}m{s}\033[0m" if color else s
def uptime(started):
    try:
        t = datetime.datetime.fromisoformat(started[:19] + "+00:00")
        s = int((datetime.datetime.now(datetime.timezone.utc) - t).total_seconds())
    except Exception:
        return "-"
    if s >= 86400: return f"{s // 86400}d {s % 86400 // 3600}h"
    if s >= 3600:  return f"{s // 3600}h {s % 3600 // 60}m"
    return f"{s // 60}m {s % 60}s"
print(f"  {'SERVICE':<17}{'STATE':<11}{'UPTIME':<10}{'RESTARTS':<10}IMAGE")
for svc in expected + sorted(s for s in rows if s not in expected):
    if svc not in rows:
        print(f"  {svc:<17}" + c("31", f"{'missing':<11}") + f"{'-':<10}{'-':<10}-")
        continue
    state, rc, oom, health, image, started = rows[svc]
    shown = state if health in ("-", "") else f"{state}/{health}"
    col = "32" if state == "running" and health in ("-", "healthy") else ("33" if state == "running" else "31")
    note = (" OOM-killed" if oom == "oom" else "") + ("" if svc in expected else " (not enabled)")
    up = uptime(started) if state == "running" else "-"
    rcs = c("33", f"{rc:<10}") if int(rc) >= 3 else f"{rc:<10}"
    print(f"  {svc:<17}" + c(col, f"{shown:<11}") + f"{up:<10}" + rcs + image + c("33", note))
PY
  echo
  if soc_wazuh; then
  local h
  if [ "$(ix_code)" = 200 ]; then
    h="$(ix GET /_cluster/health | pj 'print("%s  (%s nodes, %s shards, %s unassigned)" % (d["status"], d["number_of_nodes"], d["active_shards"], d["unassigned_shards"]))')"
    case "$h" in green*) ok "Indexer cluster: $h" ;; yellow*) warn "Indexer cluster: $h" ;; *) bad "Indexer cluster: $h" ;; esac
  else
    bad "Indexer cluster: unreachable (HTTP $(ix_code))"
  fi
  if is_running wazuh.master; then
    local nodes; nodes="$(dc exec -T wazuh.master /var/ossec/bin/cluster_control -l 2>/dev/null | awk 'NR>1 && NF {print $1}' | paste -sd' ')"
    local want=$(( $(active_workers) + 1 )) got; got="$(wc -w <<<"$nodes")"
    if [ "$got" -ge "$want" ]; then ok "Manager cluster: $got/$want nodes ($nodes)"
    else warn "Manager cluster: $got/$want nodes (${nodes:-none})"; fi
  fi
  local s
  if s="$(api GET /agents/summary/status 2>/dev/null | pj '
c = d["data"].get("connection", d["data"])
print("%s active, %s disconnected, %s never connected, %s pending" % (c.get("active", 0), c.get("disconnected", 0), c.get("never_connected", 0), c.get("pending", 0)))' 2>/dev/null)"; then
    ok "Agents: $s"
  else
    warn "Agents: Wazuh API not answering"
  fi
  local pc; pc="$(proxy_code)"
  if [[ "$pc" =~ ^(200|302)$ ]]; then ok "Dashboard: https://$(public_host):$(env_def PROXY_PORT 8080)  (HTTP $pc, via nginx)"
  else bad "Dashboard: HTTP ${pc:-000} on port $(env_def PROXY_PORT 8080) (via nginx)"; fi
  node_type_pending && warn "NODE_TYPE=$(pending_target) in .env, the stack runs as $(node_type) - apply with: vexor node-type $(pending_target)"
  fi
  soc_elk && elk_status_lines
  [ -n "$(n8n_hook)" ] && ok "Alerts -> n8n: level >= $(n8n_level) to $(n8n_hook)"
  local dr dp; dr="$(docker_root)"; dp="$(disk_pct "$dr")"
  if [ "${dp:-0}" -ge "$(env_def DISK_WARN_PCT 85)" ]; then warn "Disk: $dr ${dp}% used"; else ok "Disk: $dr ${dp}% used"; fi
  [ -f "$STATE_DIR/stopped" ] && warn "Marked as stopped (watchdog idle) - vexor start clears it"
  local hl; hl="$(cat "$STATE_DIR/health.last" 2>/dev/null)"
  if [ -n "$hl" ]; then
    local he hs hp hw hf; IFS='|' read -r he hs hp hw hf <<<"$hl"
    say "Last scheduled health check: $(date -d "@$he" '+%F %H:%M') - $hs ($hp passed, $hw warnings, $hf failed)"
  fi
  show_due_reminders
  return 0
}
cmd_health() {
  [ "$(ix_code)" = 200 ] || die "Indexer unreachable (HTTP $(ix_code)) - try: vexor doctor"
  hdr "Indexer cluster";   ix GET /_cluster/health | pretty
  hdr "Indexer nodes";     ix GET "/_cat/nodes?v&h=name,node.role,cluster_manager,heap.percent,ram.percent,cpu,load_1m,disk.used_percent"
  hdr "Disk allocation";   ix GET "/_cat/allocation?v"
  hdr "Wazuh indices";     ix GET "/_cat/indices/wazuh-*?v&s=index&h=health,status,index,docs.count,store.size" | tail -n 25
  hdr "Shards per node";   ix GET "/_cat/shards?h=node" | sort | uniq -c
  if is_running wazuh.master; then
    hdr "Manager cluster"; dc exec -T wazuh.master /var/ossec/bin/cluster_control -l
    hdr "Master daemons";  dc exec -T wazuh.master /var/ossec/bin/wazuh-control status
  fi
  hdr "Wazuh API";         api GET "/manager/info" | pj 'x = d["data"]["affected_items"][0]; print("  version %s  type %s  installed in %s" % (x.get("version"), x.get("type"), x.get("path")))' || bad "API not answering"
}

# ============================================================== doctor
D_PASS=0 D_WARN=0 D_FAIL=0 DO_FIX=0
d_pass() { D_PASS=$((D_PASS + 1)); ok "$1"; }
d_warn() { D_WARN=$((D_WARN + 1)); warn "$1"; [ -n "${2:-}" ] && hint "$2"; return 0; }
d_fail() { D_FAIL=$((D_FAIL + 1)); bad "$1"; [ -n "${2:-}" ] && hint "$2"; return 0; }
d_fix()  { [ "$DO_FIX" = 1 ] || return 1; printf '      %sfixing:%s %s\n' "$C_B" "$C_0" "$1"; return 0; }

local_agent_doctor() {         # a wazuh-agent on the vexor host itself: its manager address must be one of this host's (DHCP moves it)
  local conf=/var/ossec/etc/ossec.conf a bad="" h
  [ -r "$conf" ] && grep -q '<client>' "$conf" 2>/dev/null || return 0
  for a in $(sed -n '/<client>/,/<\/client>/s#.*<address>\(.*\)</address>.*#\1#p' "$conf"); do
    case "$a" in localhost|127.0.0.1|"$(hostname)"|"$(hostname -f 2>/dev/null)"|"$(public_host)") continue ;; esac
    host_has_ip "$a" || bad="$bad $a"
  done
  if [ -z "$bad" ]; then d_pass "wazuh-agent on this host points at this manager"; return 0; fi
  h="$(public_host)"
  d_fail "wazuh-agent on this host sends to${bad} - not an address of this machine (address changed, e.g. DHCP), so it never enrolls" \
    "vexor doctor --fix   (sets <address>$h</address> and restarts wazuh-agent; for a stable address set PUBLIC_HOST to a DNS name or reserve the IP in DHCP)"
  if d_fix "point the local wazuh-agent at $h"; then
    for a in $bad; do sed -i "s#<address>$a</address>#<address>$h</address>#" "$conf"; done
    systemctl restart wazuh-agent 2>/dev/null
  fi
  return 0
}
cmd_doctor() {
  [ "${1:-}" = "--fix" ] && { DO_FIX=1; take_lock; }
  local dr dp warn_pct v
  warn_pct="$(env_def DISK_WARN_PCT 85)"

  hdr "Host"
  command -v docker >/dev/null || { d_fail "docker is not installed"; return 1; }
  if docker_ok; then d_pass "docker daemon running ($(docker version -f '{{.Server.Version}}' 2>/dev/null))"
  else d_fail "docker daemon not running" "systemctl start docker"; return 1; fi
  docker compose version >/dev/null 2>&1 && d_pass "docker compose $(docker compose version --short)" || d_fail "docker compose v2 plugin missing"
  for v in python3 openssl curl ss; do command -v "$v" >/dev/null || d_fail "$v not installed"; done
  v="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
  if [ "$v" -ge 262144 ]; then d_pass "vm.max_map_count = $v"
  else d_fail "vm.max_map_count = $v (indexers need 262144)" "vexor doctor --fix"; d_fix "sysctl" && ensure_sysctl; fi
  local mt ma rw; mt=$(awk '/MemTotal/ {printf "%d", $2/1048576}' /proc/meminfo); ma=$(awk '/MemAvailable/ {printf "%.1f", $2/1048576}' /proc/meminfo)
  rw="$(ram_want_gb "$(node_type)")"
  if [ "$mt" -lt $(( rw - 2 )) ]; then d_warn "RAM ${mt} GB total, ${ma} GB available (${rw} GB+ recommended for node type $(node_type))" "$(is_single && echo 'lower INDEXER_HEAP' || echo 'node type single needs about half: vexor node-type single')"
  else d_pass "RAM ${mt} GB total, ${ma} GB available"; fi
  local fail_pct dmount dsize dused davail dpct droles dfree dlow=0
  fail_pct="$(env_def DISK_FAIL_PCT 95)"; dfree="$(env_def DISK_MIN_FREE_GB 5)"
  while IFS=$'\t' read -r dmount dsize dused davail dpct droles; do      # every disk Docker uses, not just one
    if   [ "${dpct:-0}" -ge "$fail_pct" ]; then d_fail "disk $dmount (${droles//,/, }) ${dpct}% used - indexers stop writing at 95% and go read-only" "free space (vexor volumes orphans, vexor images prune) or lower RETENTION_DAYS, then: vexor retention apply"; dlow=1
    elif [ "${dpct:-0}" -ge "$warn_pct" ]; then d_warn "disk $dmount (${droles//,/, }) ${dpct}% used (the indexer stops allocating new replicas at 85%)" "vexor disk | vexor volumes orphans | vexor images prune"; dlow=1
    elif [ $(( davail / 1073741824 )) -lt "$dfree" ]; then d_warn "disk $dmount (${droles//,/, }) has only $(( davail / 1073741824 )) GB free"; dlow=1
    else d_pass "disk $dmount (${droles//,/, }) ${dpct}% used, $(( davail / 1073741824 )) GB free"; fi
  done < <(disk_rows tsv)
  if [ "$dlow" = 1 ]; then
    d_fix "delete old rotated manager logs + unused images" && { prune_logs; docker image prune -f >/dev/null 2>&1; }
  fi
  if [ -n "$(volume_orphans 2>/dev/null)" ]; then d_warn "unused volumes of project $(project) take disk space" "vexor volumes orphans   (remove: vexor volumes prune)"; fi
  if command -v timedatectl >/dev/null; then
    [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ] && d_pass "clock is NTP-synchronised" \
      || d_warn "clock not NTP-synchronised (alerts/agent timestamps drift)" "timedatectl set-ntp true"
  fi

  hdr "Configuration"
  if [ ! -f "$ENV_FILE" ]; then d_fail ".env missing"; return 1; fi
  if grep -qE '^(INDEXER|DASHBOARD|API)_PASSWORD=CHANGE_ME' "$ENV_FILE"; then d_fail "passwords still CHANGE_ME" "vexor install"; fi
  if [ "$(stat -c %a "$ENV_FILE")" != 600 ]; then
    d_warn ".env permissions $(stat -c %a "$ENV_FILE") (holds passwords)" "chmod 600 .env"; d_fix "chmod 600 .env" && chmod 600 "$ENV_FILE"
  else d_pass ".env permissions 600"; fi
  local blanks; blanks="$(grep -cE '^[A-Za-z_][A-Za-z0-9_]*=[[:space:]]+#' "$ENV_FILE" 2>/dev/null)"
  if [ "${blanks:-0}" -gt 0 ]; then
    d_warn ".env has $blanks empty key(s) followed by a comment - docker compose would use the comment as the value" "vexor doctor --fix"
    d_fix "move those comments onto their own line" && env_fix_empty_comments >/dev/null
  fi
  local dups; dups="$(env_dupes)"
  if [ -n "$dups" ]; then
    d_warn ".env defines keys twice: $dups(docker compose uses the LAST one)" "vexor doctor --fix comments out the earlier lines"
    d_fix "comment out earlier duplicate keys in .env" && env_dedupe
  else d_pass ".env has no duplicate keys"; fi
  local cerr; if cerr="$(dc config -q 2>&1)"; then d_pass "docker-compose.yml + .env valid"; else d_fail "compose config invalid: $cerr"; fi
  if project_is_legacy; then d_warn "Docker project is still named '$(project)' (before vexor 2.0)" "vexor migrate   (renames it to $(project_target); data is copied and verified)"
  elif migrate_leftovers | has .; then d_warn "old volumes of project '$(cat "$MIGRATED_FROM_FILE")' are left from vexor migrate" "check the stack, then: vexor migrate --yes"
  else d_pass "Docker project '$(project)'"; fi
  shuffle_images | has . && d_warn "old Shuffle Wazuh app images on disk: $(shuffle_images | tr '\n' ' ')" "vexor migrate removes the unused ones"
  local f missing=()
  for f in root-ca.pem root-ca-manager.pem admin.pem admin-key.pem wazuh.dashboard.pem wazuh.master.pem wazuh.worker.pem \
           wazuh2.worker.pem wazuh3.worker.pem wazuh1.indexer.pem wazuh2.indexer.pem wazuh3.indexer.pem; do
    [ -f "$INT_CERT_DIR/$f" ] || missing+=("$f")
  done
  if [ ${#missing[@]} -eq 0 ]; then
    local mind=99999 d
    for f in "$INT_CERT_DIR"/*.pem; do
      [[ "$f" == *-key.pem ]] && continue
      d="$(cert_days_left "$f")"; [ -n "$d" ] && [ "$d" -lt "$mind" ] && mind="$d"
    done
    if [ "$mind" -lt 30 ]; then d_warn "internal certificates expire in $mind days" "vexor cert internal-regen"
    else d_pass "internal certificates present (earliest expiry in $mind days)"; fi
  else
    d_fail "internal certificates missing: ${missing[*]}" "vexor cert internal-regen"
  fi
  # ---- addresses: this machine may have moved or got a new IP since install
  local eph bip ph cur; eph="$(env_get PUBLIC_HOST)"; bip="$(bind_ip)"; ph="$(public_host)"; cur="$(primary_ip)"
  if [[ "$eph" =~ ^[0-9]+(\.[0-9]+){3}$ ]] && ! host_has_ip "$eph"; then
    d_warn "PUBLIC_HOST=$eph is not an address of this machine (moved, or a new IP? this machine: $cur)" \
      "empty PUBLIC_HOST in .env to detect the address each time (keep it only for a NAT/public address), then: vexor cert create"
  fi
  if [ "$bip" != 0.0.0.0 ] && ! host_has_ip "$bip"; then
    d_fail "BIND_IP=$bip is not an address of this machine - containers with published ports cannot start" "set BIND_IP=0.0.0.0 (all interfaces) in .env, then: vexor config apply"
  fi
  local pc pdays mode; pc="$(proxy_cert_path)"; mode="$(cert_mode)"
  if [ -f "$pc" ]; then
    pdays="$(cert_days_left "$pc")"
    if [ "${pdays:-0}" -lt 0 ]; then d_fail "dashboard certificate EXPIRED" "vexor cert renew --force"
    elif [ "${pdays:-0}" -lt 30 ]; then d_warn "dashboard certificate expires in $pdays days" "vexor cert renew"
    fi
    if [ "$mode" = default ]; then
      d_warn "dashboard uses the built-in self-signed cert (browser warning)" "vexor cert create   (then trust the CA: vexor cert export-ca)"
    elif ! cert_covers "$pc" "$ph"; then
      if [ -n "$eph" ]; then d_warn "dashboard cert does not cover PUBLIC_HOST=$ph (browser name mismatch)" "vexor cert create   (or set PUBLIC_HOST in .env)"
      else d_warn "this machine's address $ph (detected, PUBLIC_HOST is empty) is not in the dashboard certificate - the IP changed?" "vexor cert create   (or set PUBLIC_HOST in .env)"; fi
    elif [ "$mode" = local ] && [ "$cur" != "$ph" ] && ! cert_covers "$pc" "$cur"; then
      d_warn "dashboard cert covers $ph, but not this machine's current address $cur (the IP changed?)" "vexor cert create"
    else
      d_pass "dashboard certificate ($mode) covers $ph, $pdays days left"
    fi
  else
    d_fail "dashboard certificate file not found: $pc" "vexor cert create"
  fi
  local keys; keys="$(grep -ho '<key>[0-9a-f]\{32\}</key>' "$CLUSTER_DIR"/*.conf 2>/dev/null | sort -u | wc -l)"
  if [ "$keys" = 1 ]; then d_pass "cluster key identical on all managers"
  else d_fail "cluster key differs between manager configs ($keys keys)" "vexor doctor --fix"
       d_fix "sync cluster key + restart managers" && { ensure_cluster_key >/dev/null; dc_restart $(enabled_managers); }; fi
  # ---- node type (single | multi)
  local nt dnt; nt="$(node_type)"; dnt="$(desired_node_type)"
  if [ -f "$NODE_SWITCH_FILE" ]; then
    d_warn "switch to node type $(pending_target) was interrupted (stack runs as $nt)" "vexor node-type $(pending_target)   (resumes where it stopped)"
  elif [ "$nt" != "$dnt" ]; then
    d_warn "NODE_TYPE=$dnt in .env, but the stack runs as $nt" "vexor node-type $dnt   (or set NODE_TYPE=$nt in .env to keep it)"
  else
    d_pass "$(layout_desc)"
  fi
  if is_single && [ "$(indexer_count)" = 3 ]; then
    d_fail "node type single, but INDEXER_COUNT=3" "vexor node-type single   (moves the data to wazuh1, then removes indexer 2+3)"
  fi
  # nginx owns AGENT_PORT + PROXY_PORT in both node types; master/dashboard must not publish them
  local stale=()
  is_running wazuh.master && host_published wazuh.master 1514 && stale+=(wazuh.master)
  is_running wazuh.dashboard && host_published wazuh.dashboard 5601 && stale+=(wazuh.dashboard)
  if [ ${#stale[@]} -gt 0 ]; then
    d_fail "${stale[*]} still publish the old direct ports (nginx cannot bind $(env_def AGENT_PORT 1514)/$(env_def PROXY_PORT 8080))" "vexor doctor --fix   (or: vexor config apply)"
    d_fix "recreate ${stale[*]} without direct ports, then start nginx" && { dc up -d --no-deps --force-recreate "${stale[@]}" >/dev/null 2>&1; dc up -d >/dev/null 2>&1; }
  else d_pass "ports: agents + dashboard go through nginx (node type $nt)"; fi
  local want_ups have_ups; want_ups="$(active_workers)"; have_ups="$(grep -cE 'server wazuh[0-9]?\.worker:1514;' "$NGINX_CONF" 2>/dev/null)"; have_ups="${have_ups:-0}"
  if [ "$have_ups" != "$want_ups" ] || ! grep -q 'error_page 497' "$NGINX_CONF" 2>/dev/null || ! tools_nginx_current; then
    d_warn "nginx.conf out of date (worker upstreams $have_ups/$want_ups, http->https redirect, or tool servers)" "vexor doctor --fix"
    d_fix "re-render nginx.conf + reload" && { render_nginx; nginx_reload; }
  else d_pass "nginx.conf matches the layout ($want_ups worker upstream(s), $(enabled_tools | wc -w) tool server(s)), http->https redirect on"; fi

  hdr "Containers"
  container_rows > "$RUN_TMP/rows"
  if ! running_services | has .; then
    if [ -f "$STATE_DIR/stopped" ]; then d_warn "stack is stopped on purpose" "vexor start"
    else d_fail "stack is not running" "vexor start"; fi
    local p
    for p in "$(env_def PROXY_PORT 8080)" "$(env_def AGENT_PORT 1514)" "$(env_def ENROLL_PORT 1515)" "$(env_def API_PORT 55000)"; do
      port_listening "$p" && d_fail "port $p already used by another process: $(ss -Hltnp "( sport = :$p )" | awk '{print $NF}' | head -1)" "free it or change the port in .env"
    done
    d_fix "start the stack" && { rm -f "$STATE_DIR/stopped"; dc up -d; wait_indexer 300; }
    running_services | has . || { doctor_summary; return; }
  fi
  local svc row st rc oom
  for svc in $(enabled_services); do
    row="$(grep "^$svc|" "$RUN_TMP/rows" || true)"
    if [ -z "$row" ]; then d_fail "$svc does not exist" "vexor start"; d_fix "pull images (with retries) + create $svc" && { pull_missing_images; dc up -d "$svc"; }; continue; fi
    IFS='|' read -r _ st rc oom _ _ _ <<<"$row"
    if [ "$st" != running ]; then
      d_fail "$svc is $st" "vexor logs $svc"; d_fix "start $svc" && dc up -d "$svc"
    elif [ "$oom" = oom ]; then d_warn "$svc was OOM-killed earlier ($rc restarts)" "more RAM, or lower INDEXER_HEAP"
    elif [ "$rc" -ge 3 ]; then d_warn "$svc restarted $rc times" "vexor logs $svc -n 300"
    else d_pass "$svc running"; fi
  done
  local extra=0
  while IFS='|' read -r svc st _; do
    [[ " $(enabled_services | tr '\n' ' ') " == *" $svc "* ]] && continue
    [ "$st" = running ] || continue
    extra=1
    d_warn "$svc runs, but the layout ($(node_type)) / tool settings do not use it" "vexor doctor --fix   (removes it, volumes kept)"
  done < "$RUN_TMP/rows"
  [ "$extra" = 1 ] && d_fix "remove containers the layout does not use (volumes kept)" && prune_disabled_containers

  if soc_wazuh; then
  hdr "Indexer"
  local code; code="$(ix_code)"
  case "$code" in
    200) d_pass "indexer API reachable, admin login OK" ;;
    401) d_fail "indexer rejects INDEXER_PASSWORD from .env (HTTP 401)" "vexor passwd admin  (sets the same value in .env and the indexer)" ;;
    *)   if ! d_starting wazuh1.indexer; then
           if [ "$code" = 503 ]; then d_fail "indexer security not initialised / cluster forming (HTTP 503)" "vexor logs indexer1"
           else d_fail "indexer unreachable (HTTP ${code:-000})" "vexor logs indexer1"; fi
         fi ;;
  esac
  if [ "$code" = 200 ]; then
    local open_demo; open_demo="$(demo_logins_open | tr '\n' ' ')"
    if [ -n "${open_demo// /}" ]; then
      d_fail "demo users log in with their PUBLIC default passwords: $open_demo(anyone on the network can open the dashboard)" "vexor doctor --fix"
      d_fix "remove the OpenSearch demo users" && remove_demo_users
    else d_pass "no demo users with default passwords"; fi
    local hj st2 un nodes act
    hj="$(ix GET /_cluster/health)"
    st2="$(pj 'print(d["status"])' <<<"$hj")"; un="$(pj 'print(d["unassigned_shards"])' <<<"$hj")"
    nodes="$(pj 'print(d["number_of_nodes"])' <<<"$hj")"; act="$(pj 'print(d["active_shards"])' <<<"$hj")"
    case "$st2" in
      green)  d_pass "cluster green, $nodes nodes" ;;
      yellow) d_warn "cluster yellow, $un unassigned shards" "vexor indexer GET /_cluster/allocation/explain" ;;
      *)      d_fail "cluster $st2, $un unassigned shards" "vexor indexer GET /_cluster/allocation/explain" ;;
    esac
    if [ "$st2" != green ]; then
      if [ "$(indexer_count)" = 1 ] && [ -n "$(ix_explicit_replicas)" ]; then
        hint "single indexer: indices with replica copies can never be fully allocated"
        d_fix "set replicas to 0 (single indexer)" && ix_zero_replicas
      else
        d_fix "retry failed shard allocations" && ix POST '/_cluster/reroute?retry_failed=true' -o /dev/null
      fi
    fi
    [ -f "$STATE_DIR/indexer-cluster-excluded" ] && d_warn "an indexer shrink was started but not finished" "vexor indexers 1 (resume) or vexor indexers abort"
    [ "$nodes" = "$(indexer_count)" ] || d_fail "$nodes/$(indexer_count) indexer nodes in the cluster" "vexor logs indexers"
    local limit; limit="$(ix GET '/_cluster/settings?include_defaults=true&flat_settings=true' | pj 'print(d["persistent"].get("cluster.max_shards_per_node") or d["defaults"].get("cluster.max_shards_per_node","1000"))')"
    [[ "$limit" =~ ^[0-9]+$ ]] || limit=1000; [[ "$nodes" =~ ^[0-9]+$ ]] || nodes=3; [[ "$act" =~ ^[0-9]+$ ]] || act=0
    if [ "$act" -gt $(( limit * nodes * 80 / 100 )) ]; then
      d_warn "$act shards open, limit $(( limit * nodes )) - new daily indices will fail near the limit" "lower RETENTION_DAYS + vexor retention apply"
    else d_pass "$act shards open (limit $(( ${limit:-1000} * ${nodes:-3} )))"; fi
    local ro; ro="$(ix GET '/_all/_settings/index.blocks.read_only_allow_delete' | pj 'print(sum(1 for v in d.values() if v.get("settings",{}).get("index",{}).get("blocks",{}).get("read_only_allow_delete") == "true"))')"
    if [ "${ro:-0}" -gt 0 ]; then
      d_fail "$ro indices are READ-ONLY (disk flood stage hit) - new alerts are dropped" "free disk, then: vexor doctor --fix"
      d_fix "clear read-only blocks" && ix PUT '/_all/_settings' -d '{"index.blocks.read_only_allow_delete": null}' >/dev/null
    else d_pass "no read-only index blocks"; fi
    local alloc; alloc="$(ix GET '/_cat/allocation?format=json' | pj 'print(max(int(x.get("disk.percent") or 0) for x in d if x.get("node") != "UNASSIGNED"))')"
    [ "${alloc:-0}" -ge 85 ] && d_warn "indexer data disk ${alloc}% (low watermark 85%)"
    local wd; wd="$(retention_days INDEX_RETENTION_DAYS)" || wd=bad
    if [ "$wd" = bad ]; then d_warn "INDEX_RETENTION_DAYS / RETENTION_DAYS is not a whole number of days" "vexor config set RETENTION_DAYS 30"
    elif [ "$(ism_policy_age)" = "$(retention_expect "$wd")" ]; then d_pass "retention policy '$ISM_POLICY' matches ($(retention_words "$wd"))"
    else d_warn "retention policy is $(ism_policy_age), expected $(retention_expect "$wd") - indices are not deleted as configured" "vexor retention apply"; d_fix "apply retention" && retention_apply; fi
    if [ "$(ix_code "/_snapshot/$SNAP_REPO")" = 200 ]; then d_pass "snapshot repository '$SNAP_REPO' registered"
    else d_warn "snapshot repository not registered" "vexor backup register"; d_fix "register snapshot repo" && snapshot_register; fi
    local n24; n24="$(ix POST '/wazuh-alerts-*/_count' -d '{"query":{"range":{"timestamp":{"gte":"now-24h"}}}}' | pj 'print(d.get("count",0))')"
    if [ "${n24:-0}" -gt 0 ]; then d_pass "$n24 alerts indexed in the last 24h"
    else d_warn "no alerts indexed in the last 24h" "fine without agents; otherwise check filebeat below"; fi
  fi

  hdr "Managers"
  if is_running wazuh.master; then
    local cl want got miss
    cl="$(dc exec -T wazuh.master /var/ossec/bin/cluster_control -l 2>&1)"
    want=$(( $(active_workers) + 1 )); got="$(awk 'NR>1 && NF' <<<"$cl" | wc -l)"
    if [ "$got" -ge "$want" ]; then d_pass "manager cluster: $got/$want nodes connected$(is_single && echo ' (single: master only)')"
    elif [ "$got" = 0 ] && d_starting wazuh.master; then :     # wazuh-clusterd comes up last
    elif [ "$got" != 0 ] && [ "$(active_workers)" -gt 0 ] && d_starting "$(enabled_managers | tail -1)"; then :
    elif [ "$got" = 0 ]; then
      d_fail "manager cluster not answering (wazuh-clusterd down on the master?)" "vexor logs cluster master"
      d_fix "restart the master" && dc_restart wazuh.master
    else
      d_fail "manager cluster: $got/$want nodes connected" "vexor logs cluster worker   (workers resync from the master after a node-type switch: give them 2-3 min)"
      [ "$(active_workers)" -gt 0 ] && [ "$(svc_uptime_s wazuh.worker)" -ge 180 ] && d_fix "restart workers" && dc_restart $(enabled_managers | grep -v wazuh.master)
    fi
    for svc in $(enabled_managers); do
      is_running "$svc" || continue
      local down; down="$(dc exec -T "$svc" /var/ossec/bin/wazuh-control status 2>/dev/null \
        | grep -E '^(wazuh-analysisd|wazuh-remoted|wazuh-db|wazuh-modulesd|wazuh-clusterd|wazuh-apid|wazuh-authd) (is )?not running' | awk '{print $1}' | tr '\n' ' ')"
      if [ "$svc" != wazuh.master ]; then down="${down/wazuh-authd /}"; fi
      if [ -n "${down// /}" ]; then d_fail "$svc daemons down: $down" "vexor logs ossec $svc"; d_fix "restart $svc" && dc_restart "$svc"
      else d_pass "$svc core daemons running"; fi
      local cm cr
      cm="$(dc exec -T "$svc" md5sum /wazuh-config-mount/etc/ossec.conf 2>/dev/null | cut -d' ' -f1)"
      cr="$(dc exec -T "$svc" md5sum /var/ossec/etc/ossec.conf 2>/dev/null | cut -d' ' -f1)"
      if [ -n "$cm" ] && [ "$cm" != "$cr" ]; then
        d_warn "$svc runs an older ossec.conf than config/wazuh_cluster (edits not loaded)" "vexor restart $svc  (recreates it)"
        d_fix "recreate $svc to load its config" && dc_restart "$svc" >/dev/null 2>&1
      else d_pass "$svc runs the current ossec.conf"; fi
      if ! vuln_on; then                       # detection off, but an earlier feed still fills the queue volume
        local vb; vb="$(vuln_feed_bytes "$svc")"
        if [ "${vb:-0}" -gt 104857600 ]; then
          d_warn "$svc keeps a $((vb / 1073741824)) GB vulnerability feed although WAZUH_VULN_DETECTION=false" "vexor doctor --fix  (deletes /var/ossec/queue/vd)"
          d_fix "delete the unused vulnerability feed in $svc" && dc exec -T "$svc" rm -rf /var/ossec/queue/vd /var/ossec/queue/vd_updater >/dev/null 2>&1
        fi
      fi
      if dc exec -T "$svc" filebeat test output >/dev/null 2>&1; then d_pass "$svc filebeat -> indexer OK"
      else d_fail "$svc filebeat cannot reach the indexer (alerts not shipped)" "vexor exec $(echo "$svc") filebeat test output"
           d_fix "restart $svc" && dc_restart "$svc"; fi
    done
    if api_login; then d_pass "Wazuh API login OK ($(env_def API_USERNAME wazuh-wui))"
    else d_fail "Wazuh API login failed" "vexor passwd api"; fi
    det_doctor
    # outgoing integrations (n8n, Slack, VirusTotal...): a dead target only shows up in ossec.log
    local isvc ierr
    for isvc in $(enabled_managers); do
      is_running "$isvc" || continue
      ierr="$(dc exec -T "$isvc" bash -c 'c="$(date -u -d "-1 hour" "+%Y/%m/%d %H:%M:%S")"
        awk -v c="$c" "substr(\$0,1,19) >= c && /wazuh-integratord: ERROR: Unable to run integration/" /var/ossec/logs/ossec.log 2>/dev/null \
          | sed -E "s/.*integration for ([^ ]+).*/\1/" | sort | uniq -c | tr "\n" " "' 2>/dev/null)"
      local jtf; jtf="$(dc exec -T "$isvc" sh -c 'tail -n 20000 /var/ossec/logs/ossec.log | grep -c "Too many fields for JSON decoder"' 2>/dev/null)"
      if [ "${jtf:-0}" -gt 50 ]; then
        d_warn "$isvc: $jtf events rejected by the JSON decoder (too many fields - usually Suricata stats/flow records)" "vexor tools apply   (Wazuh then reads only Suricata alerts/anomalies)"
        [ "$isvc" = wazuh.master ] && d_fix "restrict the Suricata source + recreate the master"           && { [ "$(sync_master_localfiles)" = changed ] && dc_restart wazuh.master >/dev/null 2>&1; }
      fi
      if [ -n "${ierr// /}" ]; then
        d_warn "$isvc: integration deliveries failing in the last hour (count name): $ierr" "target down or moved - fix the URL in config/wazuh_cluster/*.conf, or remove the <integration> block; then: vexor restart managers"
      fi
    done
  else
    d_fail "wazuh.master not running"
  fi

  local port; port="$(env_def PROXY_PORT 8080)"
  hdr "Proxy / dashboard (nginx)"
  if is_running nginx; then
    dc exec -T nginx nginx -t -q >/dev/null 2>&1 && d_pass "nginx config valid" || d_fail "nginx config invalid" "vexor exec nginx nginx -t"
    local hc s; hc="$(proxy_code)"
    case "$hc" in
      200|302) d_pass "https://$(local_ip):$port -> dashboard (HTTP $hc)" ;;
      502|503|504) if ! d_starting wazuh.dashboard; then
               d_fail "nginx up, dashboard not answering (HTTP $hc)" "vexor logs dashboard"
               [ "$(svc_uptime_s wazuh.dashboard)" -ge 300 ] && d_fix "restart the dashboard" && dc_restart wazuh.dashboard >/dev/null
             fi ;;
      *)       d_fail "dashboard via nginx: HTTP ${hc:-000}" "vexor logs nginx dashboard" ;;
    esac
    s="$(proxy_code http)"
    if [ "$s" = 301 ]; then d_pass "http:// is redirected to https://"
    else d_warn "http:// on port $port returns $s (browsers show 400)" "vexor doctor --fix"
         d_fix "enable redirect" && { render_nginx; nginx_reload; }; fi
  else
    d_fail "nginx not running" "vexor logs nginx   ('port is already allocated' = the master/dashboard still hold 1514/$port: vexor doctor --fix)"
    d_fix "recreate master + dashboard without direct ports, start nginx" && { dc up -d --no-deps --force-recreate wazuh.master wazuh.dashboard >/dev/null 2>&1; dc up -d >/dev/null 2>&1; }
  fi
  hdr "Agent ports"
  local who; who="nginx -> $(is_single && echo 'master' || echo 'managers')"
  if tcp_open "$(local_ip)" "$(env_def AGENT_PORT 1514)"; then d_pass "agent events port $(env_def AGENT_PORT 1514)/tcp open ($who)"
  else d_fail "agent port $(env_def AGENT_PORT 1514) closed ($who) - agents cannot send events" "vexor doctor --fix   (recreates the container that must publish it)"
       d_fix "recreate nginx" && { prune_disabled_containers; dc up -d --no-deps --force-recreate nginx >/dev/null 2>&1; }; fi
  tcp_open "$(local_ip)" "$(env_def ENROLL_PORT 1515)" && d_pass "enrollment port $(env_def ENROLL_PORT 1515)/tcp open" || d_fail "enrollment port $(env_def ENROLL_PORT 1515) closed" "vexor logs ossec master"
  local_agent_doctor
  if command -v ufw >/dev/null && ufw status 2>/dev/null | has "Status: active"; then
    d_warn "ufw firewall active - make sure ports $port,$(env_def AGENT_PORT 1514),$(env_def ENROLL_PORT 1515)/tcp are allowed"
  fi

  fi
  soc_elk && elk_doctor
  [ "$(routes_count)" -gt 0 ] && proxy_doctor

  if [ -n "$(enabled_tools)" ]; then
    hdr "Tools ($(enabled_tools | tr '\n' ' '))"
    local tl tc
    for tl in $(web_tools); do
      tc="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$(local_ip):$(tool_port "$tl")/" 2>/dev/null)"
      case "$tc" in
        200|301|302|303|307|308|401) d_pass "$tl https://$(public_host):$(tool_port "$tl") (HTTP $tc)" ;;
        502|503|504) if ! d_starting "$tl"; then
                       d_fail "$tl: nginx answers, $tl does not (HTTP $tc)" "vexor logs $tl"
                       [ "$(svc_uptime_s "$tl")" -ge 180 ] && d_fix "restart $tl" && dc restart "$tl" >/dev/null 2>&1
                     fi ;;
        *) d_fail "$tl: nothing answers on port $(tool_port "$tl") (HTTP ${tc:-000})" "vexor doctor --fix   (renders nginx + publishes the port)"
           d_fix "render nginx + recreate it with the tool ports" && { render_override; render_nginx; dc up -d --no-deps --force-recreate nginx >/dev/null 2>&1; } ;;
      esac
    done
    if tool_on grafana && is_running wazuh1.indexer; then
      if grafana_user_ok; then d_pass "grafana -> indexer read-only user works"
      else d_fail "grafana indexer user cannot query the alerts" "vexor tools apply"
           d_fix "re-create the grafana indexer user" && grafana_indexer_user add; fi
    fi
    if tool_on suricata || tool_on zeek; then
      if ip -o link show "$(sniff_iface)" >/dev/null 2>&1; then d_pass "SNIFF_INTERFACE $(sniff_iface) exists"
      else d_fail "SNIFF_INTERFACE $(sniff_iface) does not exist" "set SNIFF_INTERFACE in .env (ip -br link), then: vexor tools apply"; fi
      if is_running wazuh.master && ! dc exec -T wazuh.master test -r /var/ossec/etc/rules/vexor_tools_rules.xml 2>/dev/null; then
        d_fail "the master does not see the sensor logs/rules (not recreated after enabling)" "vexor tools apply"
        d_fix "recreate the master with the sensor mounts" && { render_override; dc up -d --no-deps --force-recreate wazuh.master >/dev/null 2>&1; }
      fi
    fi
    if tool_on suricata && is_running suricata; then
      file_fresh "$TOOLS_DATA/suricata/log/eve.json" 15 && d_pass "suricata writes eve.json" \
        || d_warn "suricata eve.json not updated for 15 min (no traffic on $(sniff_iface)?)" "vexor logs suricata"
      if [ "$(suricata_sig_count)" -gt 0 ]; then d_pass "suricata engine has $(suricata_sig_count) signatures loaded"
      else d_warn "suricata runs with 0 signatures (no alerts)" "vexor tools update-rules"; d_fix "download + load suricata rules" && suricata_rules_ensure; fi
    fi
    if tool_on zeek && is_running zeek; then
      local zf; zf="$(find "$TOOLS_DATA/zeek/logs" -maxdepth 1 -name '*.log' -mmin -15 2>/dev/null | head -1)"
      [ -n "$zf" ] && d_pass "zeek writes logs ($(find "$TOOLS_DATA/zeek/logs" -maxdepth 1 -name '*.log' | wc -l) log files)" \
        || d_warn "zeek logs not updated for 15 min" "vexor logs zeek"
    fi
    local du; du="$(du -sh "$TOOLS_DATA" 2>/dev/null | cut -f1)"; [ -n "$du" ] && say "sensor logs on disk: $du (kept $(env_def TOOLS_LOG_RETENTION_DAYS 7) days)"
  fi

  [ -n "$(n8n_hook)" ] && n8n_doctor
  if [ -n "$(notify_target)" ] && [ -s "$STATE_DIR/notify.err" ]; then
    hdr "Notifications"
    d_warn "the last health notification was not delivered: $(cat "$STATE_DIR/notify.err")" "vexor notify test"
  fi
  if console_on && command -v systemctl >/dev/null; then
    hdr "Console"
    if console_answers; then d_pass "console answers on $(console_url)"
    else d_fail "console not answering on port $(console_port)" "vexor console logs"
         d_fix "install + restart the console service" && { rm -f "$STATE_DIR/console.fingerprint"; console_sync >/dev/null; }; fi
  fi

  hdr "Logs (last 15 min)"
  local cid name cnt
  for cid in $(dc_all ps -q 2>/dev/null); do
    name="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$cid")"
    cnt="$(docker logs --since 15m "$cid" 2>&1 | grep -ciE '\b(error|critical|fatal|exception)\b' || true)"
    [ "${cnt:-0}" -gt 0 ] && say "$(printf '%-17s %s error-like lines' "$name" "$cnt")"
  done
  hint "details: vexor logs errors --since 15m"
  doctor_summary
}
doctor_summary() {
  [ -n "$(reminders_due)" ] && { echo; show_due_reminders; }
  printf '\n  %s%d passed%s, %s%d warnings%s, %s%d failed%s\n' "$C_G" "$D_PASS" "$C_0" "$C_Y" "$D_WARN" "$C_0" "$C_R" "$D_FAIL" "$C_0"
  [ "$DO_FIX" = 0 ] && [ $((D_WARN + D_FAIL)) -gt 0 ] && say "Run ${C_BD}vexor doctor --fix${C_0} to repair what can be fixed automatically."
  [ "$D_FAIL" -eq 0 ]
}

# ============================================================== logs / exec
cmd_logs() {
  local follow=0 n=200 since="" what=()
  while [ $# -gt 0 ]; do
    case "$1" in
      -f|--follow) follow=1 ;;
      -n|--tail)   n="${2:?}"; shift ;;
      --since)     since="${2:?}"; shift ;;
      *)           what+=("$1") ;;
    esac; shift
  done
  local first="${what[0]:-}" t=(); [ -t 0 ] || t=(-T)
  case "$first" in
    ossec|api|cluster|alerts|archives|integrations)
      local node file; node="$(resolve_svc "${what[1]:-master}")"
      case "$first" in
        ossec) file=/var/ossec/logs/ossec.log ;;           api) file=/var/ossec/logs/api.log ;;
        cluster) file=/var/ossec/logs/cluster.log ;;       alerts) file=/var/ossec/logs/alerts/alerts.json ;;
        archives) file=/var/ossec/logs/archives/archives.json ;; integrations) file=/var/ossec/logs/integrations.log ;;
      esac
      if [ "$follow" = 1 ]; then dc exec "${t[@]}" "$node" tail -n "$n" -F "$file"
      else dc exec -T "$node" tail -n "$n" "$file"; fi ;;
    errors)
      local svc
      for svc in $(running_services); do
        local lines; lines="$(dc logs --no-log-prefix --since "${since:-1h}" "$svc" 2>&1 | grep -iE '\b(error|critical|fatal|exception)\b' | tail -n "${n:-20}")"
        [ -n "$lines" ] || continue
        printf '\n%s== %s ==%s\n%s\n' "$C_BD" "$svc" "$C_0" "$(cut -c1-400 <<<"$lines")"
      done ;;
    size) logs_size ;;
    *)
      local args=(--tail "$n"); [ "$follow" = 1 ] && args+=(-f); [ -n "$since" ] && args+=(--since "$since")
      if [ ${#what[@]} -gt 0 ]; then dc_all logs "${args[@]}" $(resolve_many "${what[@]}")
      else dc_all logs "${args[@]}"; fi ;;
  esac
}
logs_size() {
  hdr "Docker container logs (rotated at $(env_def LOG_MAX_SIZE 50m) x $(env_def LOG_MAX_FILE 5))"
  local cid name lp
  for cid in $(dc_all ps -aq 2>/dev/null); do
    name="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$cid")"
    lp="$(docker inspect -f '{{.LogPath}}' "$cid")"
    [ -n "$lp" ] && printf '  %-17s %s\n' "$name" "$(du -ch "$lp"* 2>/dev/null | tail -1 | cut -f1)"
  done
  hdr "Manager log folders (/var/ossec/logs)"
  local svc
  for svc in $(enabled_managers); do
    is_running "$svc" || continue
    printf '  %-17s %s\n' "$svc" "$(dc exec -T "$svc" du -sh /var/ossec/logs 2>/dev/null | cut -f1)"
  done
  hint "old rotated files: vexor prune-logs (keeps $(env_def MANAGER_LOG_RETENTION_DAYS 30) days)"
}
cmd_shell() { local s; s="$(resolve_svc "${1:-master}")"; dc exec "$s" bash 2>/dev/null || dc exec "$s" sh; }
cmd_exec() {
  [ $# -ge 2 ] || die "usage: vexor exec <service> <command...>"
  local s t=(); s="$(resolve_svc "$1")"; shift; [ -t 0 ] || t=(-T)
  dc exec "${t[@]}" "$s" "$@"
}
cmd_indexer() {
  [ $# -ge 2 ] || die "usage: vexor indexer <GET|PUT|POST|DELETE> </path> ['json body']   e.g. vexor indexer GET '/_cat/indices?v'"
  local m="${1^^}" p="$2" body="${3:-}"
  if [ -n "$body" ]; then ix "$m" "$p" -d "$body" | pretty; else ix "$m" "$p" | pretty; fi
}
cmd_api() {
  [ $# -ge 2 ] || die "usage: vexor api <GET|PUT|POST|DELETE> </path> ['json body']   e.g. vexor api GET /agents/summary/status"
  local m="${1^^}" p="$2" body="${3:-}"
  if [ -n "$body" ]; then api "$m" "$p" -d "$body" | pretty; else api "$m" "$p" | pretty; fi
}

# ============================================================== info / config
cert_mode() {
  local m; m="$(env_get PROXY_CERT_MODE)"
  if [ -z "$(env_get PROXY_CERT)" ]; then echo default; else echo "${m:-custom}"; fi
}
cmd_info() {
  local show=0; [ "${1:-}" = "--show-secrets" ] && show=1
  local h port pw ip; h="$(public_host)"; port="$(env_def PROXY_PORT 8080)"
  pw="$(env_get INDEXER_PASSWORD)"; [ "$show" = 1 ] || pw="$(mask "$pw") $(printf '%s' "${C_D}(--show-secrets)${C_0}")"
  hdr "Vexor  |  SOC=$(soc)$(soc_wazuh && echo "  |  Wazuh $(cur_version), $(layout_desc)")"
  if soc_wazuh; then
  printf '  %-12s %s\n' "Dashboard" "${C_BD}https://$h:$port${C_0}"
  for ip in $(host_ips); do [ "$ip" != "$h" ] && printf '  %-12s %s\n' "" "https://$ip:$port"; done
  printf '  %-12s %s\n' "" "${C_D}http:// is redirected to https://${C_0}"
  case "$(cert_mode)" in
    default)     printf '  %-12s %s\n' "Certificate" "self-signed -> browsers warn. Fix: ${C_BD}vexor cert create${C_0}, then trust the CA on each PC (vexor cert export-ca)" ;;
    local)       printf '  %-12s %s\n' "Certificate" "local CA - trust it once per PC to remove the warning: vexor cert export-ca" ;;
    letsencrypt) printf '  %-12s %s\n' "Certificate" "Let's Encrypt for $(env_get LE_DOMAIN) (open https://$(env_get LE_DOMAIN):$port)" ;;
    custom)      printf '  %-12s %s\n' "Certificate" "custom: $(env_get PROXY_CERT)" ;;
  esac
  printf '  %-12s %s\n' "Login" "$(env_def INDEXER_USERNAME admin) / $pw"
  printf '  %-12s %s\n' "Agents" "events $h:$(env_def AGENT_PORT 1514)/tcp (nginx -> $(is_single && echo 'the master' || echo 'all managers'); same address in both node types)"
  printf '  %-12s %s\n' "" "enroll $h:$(env_def ENROLL_PORT 1515)/tcp   -> install commands: vexor agents enroll-cmd"
  printf '  %-12s %s\n' "Wazuh API" "https://$h:$(api_port)  user $(env_def API_USERNAME wazuh-wui)"
  printf '  %-12s %s\n' "Syslog" "$h:$(env_def SYSLOG_PORT 514)/udp"
  fi
  if soc_elk; then
    printf '  %-12s %s\n' "Kibana" "${C_BD}https://$h:$(env_def KIBANA_PORT 55601)${C_0}  login elastic / $( [ "$show" = 1 ] && env_get ELASTIC_PASSWORD || echo '******** (--show-secrets)')"
    printf '  %-12s %s\n' "Elastic" "http://127.0.0.1:$(es_port) (this host only)   Beats/Elastic Agent -> $h:$(env_def LOGSTASH_BEATS_PORT 55044)"
    [ "$(soc)" = both ] && printf '  %-12s %s\n' "" "Wazuh alerts are copied into Elasticsearch: vexor-wazuh-alerts-*"
  fi
  printf '  %-12s %s\n' "Settings" "$ENV_FILE   (vexor config show)"
  node_type_pending && printf '  %-12s %s\n' "Pending" "NODE_TYPE=$(pending_target) in .env - apply with: vexor node-type $(pending_target)"
  printf '  %-12s %s\n' "Backups" "$(backup_dir)"
  local tl; for tl in $(web_tools); do [ "$tl" = kibana ] && continue; printf '  %-12s %s\n' "$tl" "https://$h:$(tool_port "$tl")  ($(tool_desc "$tl"))"; done
  tool_on suricata && printf '  %-12s %s\n' "suricata" "IDS on $(sniff_iface) -> Wazuh alerts (rule groups: suricata)"
  tool_on zeek && printf '  %-12s %s\n' "zeek" "network logs on $(sniff_iface) -> Wazuh (rule groups: zeek)"
  console_on && printf '  %-12s %s\n' "Console" "${C_BD}$(console_url)${C_0}  user $(env_def CONSOLE_USER admin) / $( [ "$show" = 1 ] && env_get CONSOLE_PASSWORD || echo '******** (--show-secrets)')"
  return 0
}
cmd_config() {
  local sub="${1:-show}"; shift || true
  case "$sub" in
    show)
      local show=0; [ "${1:-}" = "--show-secrets" ] && show=1
      if [ "$show" = 1 ]; then cat "$ENV_FILE"
      else sed -E 's/^([A-Z0-9_]*(PASSWORD|_KEY|TOKEN|SECRET)=)([^[:space:]#]+)/\1********/' "$ENV_FILE"; fi ;;
    get)  [ -n "${1:-}" ] || die "usage: vexor config get KEY"; env_get "$1" ;;
    set)
      local k="${1:-}" v="${2-}"
      [ -n "$k" ] && [ $# -ge 2 ] || die "usage: vexor config set KEY VALUE"
      case "$k" in
        *PASSWORD) die "Use: vexor passwd (it also updates the running stack)" ;;
        WAZUH_VERSION) die "Use: vexor update apply $v (pulls, backs up, restarts)" ;;
        WORKER_COUNT) cmd_scale "$v"; return ;;
        NODE_TYPE) cmd_node_type "$v"; return ;;
        INDEXER_COUNT) die "Use: vexor indexers 1|3 (moves the data first)" ;;
        COMPOSE_PROFILES) die "COMPOSE_PROFILES follows NODE_TYPE, WORKER_COUNT and INDEXER_COUNT - do not set it" ;;
        *PORT|RETENTION_DAYS|INDEX_RETENTION_DAYS|ELK_RETENTION_DAYS|MANAGER_LOG_RETENTION_DAYS|SNAPSHOT_RETENTION_DAYS|DISK_WARN_PCT|DISK_FAIL_PCT|DISK_WARN_FREE_GB|DISK_MIN_FREE_GB|CERT_DAYS|LOG_MAX_FILE|NGINX_WORKER_CONNECTIONS)
          [[ "$v" =~ ^[0-9]+$ ]] || die "$k must be a number" ;;
        WAZUH_VULN_DETECTION) [[ "$v" =~ ^(true|false)$ ]] || die "WAZUH_VULN_DETECTION must be true or false" ;;
        WAZUH_SCA) [[ "$v" =~ ^(true|false)$ ]] || die "WAZUH_SCA must be true or false" ;;
        INDEXER_HEAP) [[ "$v" =~ ^[0-9]+[mg]$ ]] || die "INDEXER_HEAP like 1g or 2048m" ;;
        BIND_IP) [[ "$v" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || die "BIND_IP must be an IPv4 address (0.0.0.0 = all interfaces)" ;;
        BACKUP_TIME|MAINT_TIME) [[ "$v" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "$k must be HH:MM" ;;
      esac
      env_has "$k" || warn "$k is a new key"
      env_set "$k" "$v"; ok "$k=$v"
      case "$k" in
        PUBLIC_HOST|CERT_EXTRA_SANS) say "Re-issue the dashboard cert for the new name: vexor cert create" ;;
        BACKUP_TIME|MAINT_TIME) say "Apply to timers: vexor daemon install" ;;
        *) say "Apply with: vexor config apply" ;;
      esac ;;
    edit)
      cp "$ENV_FILE" "$RUN_TMP/env.bak"
      "${EDITOR:-nano}" "$ENV_FILE"
      if ! dc config -q; then
        bad "compose rejects the new .env"
        confirm "Restore the previous .env?" && cp "$RUN_TMP/env.bak" "$ENV_FILE" && ok "restored"
      else
        ok ".env valid - apply with: vexor config apply"
      fi ;;
    validate) dc config -q && ok "docker-compose.yml + .env valid" ;;
    apply)
      take_lock; preflight
      if [ "${ASSUME_YES:-0}" != 1 ] && [ -t 0 ]; then
        cmd_plan; confirm "Apply this?" || die "Aborted - nothing changed"
      else
        cmd_plan 2>/dev/null | sed -n '1,40p'
      fi
      if soc_wazuh && maybe_switch_node_type; then ok "Settings applied (node type switched)"; record_applied_env; return 0; fi
      render_nginx; render_override
      apply_all
      ok "Settings applied (only changed containers were recreated)" ;;
    plan) shift 0; cmd_plan "$@" ;;
    *) die "usage: vexor config show|get|set|edit|validate|plan|apply" ;;
  esac
}

