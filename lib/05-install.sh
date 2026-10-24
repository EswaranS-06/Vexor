# shellcheck shell=bash
# vexor lib/05-install.sh - waits (wait-ready), install, lifecycle (start/stop/restart/down/scale)
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== waits
# One readiness rule for install / start / restart / upgrade / doctor / CI: `vexor wait-ready`.
# A service is ready when its container runs, its Docker healthcheck (if any) is healthy,
# and the service-specific probe in svc_not_ready answers.
WAIT_READY_TIMEOUT=900         # seconds: default for wait-ready, and how long after a start doctor says "still starting"
WAIT_POLL=5                    # seconds between probe rounds
WAIT_PRINT=15                  # seconds between "waiting:" progress lines
declare -A WAIT_WHY=()
svc_cid() { docker ps -aq --filter "label=com.docker.compose.project=$(project)" --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -1; }
fmt_dur() { local s="$1"; if [ "$s" -ge 60 ]; then echo "$((s / 60))m$(printf '%02d' $((s % 60)))s"; else echo "${s}s"; fi; }
svc_not_ready() {              # svc_not_ready <svc>: why it is not ready (prints nothing when ready); a leading ! = will not fix itself
  local svc="$1" cid st hl c want got
  cid="$(svc_cid "$svc")"
  [ -n "$cid" ] || { echo "not running (no container)"; return 0; }
  st="$(docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid" 2>/dev/null)"
  hl="${st#*|}"; st="${st%%|*}"
  [ "$st" = running ] || { echo "not running (${st:-unknown})"; return 0; }
  case "$hl" in ""|healthy) ;; *) echo "healthcheck $hl"; return 0 ;; esac
  case "$svc" in
    wazuh1.indexer)
      c="$(ix_code)"
      case "$c" in 200) ;; 401) echo "!indexer rejects INDEXER_PASSWORD (HTTP 401)" ;; *) echo "indexer API HTTP ${c:-000}" ;; esac ;;
    wazuh.master)
      if ! dc exec -T wazuh.master /var/ossec/bin/cluster_control -l >/dev/null 2>&1; then echo "cluster (wazuh-clusterd) not answering"
      elif ! api_login; then echo "Wazuh API login not answering"; fi ;;
    wazuh.worker|wazuh2.worker|wazuh3.worker)
      if ! daemon_list "$svc" | has '^wazuh-clusterd is running'; then echo "wazuh-clusterd not running"
      else
        want=$(( $(active_workers) + 1 ))
        got="$(dc exec -T wazuh.master /var/ossec/bin/cluster_control -l 2>/dev/null | awk 'NR>1 && NF' | wc -l)"
        [ "${got:-0}" -ge "$want" ] || echo "master lists ${got:-0}/$want cluster nodes"
      fi ;;
    wazuh.dashboard)
      c="$(proxy_code)"; [[ "$c" =~ ^(200|302)$ ]] || echo "dashboard via nginx HTTP ${c:-000}" ;;
    elasticsearch)
      c="$(es_code /_cluster/health)"
      case "$c" in 200) ;; 401) echo "!Elasticsearch rejects ELASTIC_PASSWORD (HTTP 401)" ;; *) echo "Elasticsearch API HTTP ${c:-000}" ;; esac ;;
    kibana)
      c="$(kibana_code)"; [ "$c" = 200 ] || echo "Kibana HTTP ${c:-000}" ;;
    logstash)
      c="$(dc exec -T logstash curl -s -o /dev/null -w '%{http_code}' localhost:9600 2>/dev/null)"
      [ "$c" = 200 ] || echo "Logstash API HTTP ${c:-000}" ;;
    n8n)
      c="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$(local_ip):$(tool_port n8n)/healthz" 2>/dev/null)"
      [ "$c" = 200 ] || echo "n8n /healthz HTTP ${c:-000}" ;;
    grafana)
      c="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$(local_ip):$(tool_port grafana)/api/health" 2>/dev/null)"
      [ "$c" = 200 ] || echo "Grafana /api/health HTTP ${c:-000}" ;;
    portainer)
      c="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$(local_ip):$(tool_port portainer)/" 2>/dev/null)"
      [[ "$c" =~ ^(200|30[0-9]|401)$ ]] || echo "Portainer HTTP ${c:-000}" ;;
  esac
  return 0
}
svc_starting() {               # true while <svc> runs, is not ready yet and was started less than WAIT_READY_TIMEOUT s ago
  local cid why; cid="$(svc_cid "$1")"; [ -n "$cid" ] || return 1
  [ "$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null)" = true ] || return 1
  [ "$(svc_uptime_s "$1")" -lt "$WAIT_READY_TIMEOUT" ] || return 1
  why="$(svc_not_ready "$1")"; [ -n "$why" ] && [ "${why:0:1}" != '!' ]
}
d_starting() {                 # doctor: a warning (not a failure) for a service that is still coming up; true when it warned
  svc_starting "$1" || return 1
  d_warn "$1 still starting ($(svc_not_ready "$1"))" "give it a few minutes (up to $((WAIT_READY_TIMEOUT / 60)) min after a start), then: vexor wait-ready $1"
}
wait_spin() {                  # wait_spin <seconds> <start> <svc..>: animated sleep, one line naming what is still pending
  local secs="$1" start="$2" end i=0 svc txt=""; shift 2
  for svc in "$@"; do txt+="${txt:+, }$svc${WAIT_WHY[$svc]:+ (${WAIT_WHY[$svc]})}"; done
  [ "$SPIN_CURSOR" = 1 ] || cursor_hide
  end=$(( SECONDS + secs ))
  while [ "$SECONDS" -lt "$end" ]; do
    spin_line "$i" "waiting $(fmt_dur $(( SECONDS - start ))) · $txt"
    i=$((i + 1)); sleep 0.1 2>/dev/null || sleep 1
  done
}
wait_ready_run() {           # wait_ready_run <timeout-s> <json 0|1> <svc..>  -> 0 all ready, 1 otherwise (lists what is not ready)
  local t="$1" js="$2" start="$SECONDS" lastp=-999 now why svc s rows="" nfail=0 printed live=0
  shift 2
  local pending=("$@") still
  [ "$js" = 1 ] || ! step_live || live=1      # tty: one live spinner line instead of "waiting:" lines
  while [ ${#pending[@]} -gt 0 ]; do
    now=$(( SECONDS - start )); still=(); printed=0
    for svc in "${pending[@]}"; do
      why="$(svc_not_ready "$svc")"
      if [ -z "$why" ]; then
        [ "$live" = 1 ] && spin_clear
        [ "$js" = 1 ] || ok "ready: $svc $(fmt_dur "$now")"
        rows+="$svc|1|$now|"$'\n'
      elif [ "${why:0:1}" = '!' ]; then
        [ "$live" = 1 ] && spin_clear
        [ "$js" = 1 ] || bad "$svc: ${why:1}"
        rows+="$svc|0|$now|${why:1}"$'\n'; nfail=$((nfail + 1))
      else
        still+=("$svc"); WAIT_WHY["$svc"]="$why"
        if [ "$js" != 1 ] && [ "$live" = 0 ] && [ $((now - lastp)) -ge "$WAIT_PRINT" ]; then say "waiting: $svc ($why) $(fmt_dur "$now")"; printed=1; fi
      fi
    done
    [ "$printed" = 1 ] && lastp=$now
    pending=("${still[@]}")
    [ ${#pending[@]} -gt 0 ] || break
    [ $(( SECONDS - start )) -ge "$t" ] && break
    now=$(( t - (SECONDS - start) )); [ "$now" -gt "$WAIT_POLL" ] && now="$WAIT_POLL"
    if [ "$live" = 1 ]; then wait_spin "$now" "$start" "${pending[@]}"; else sleep "$now"; fi
  done
  [ "$live" = 1 ] && spin_stop
  for svc in "${pending[@]}"; do rows+="$svc|0|$t|${WAIT_WHY[$svc]:-not ready}"$'\n'; done
  if [ "$js" = 1 ]; then
    python3 -I -c '
import json, sys
rows = [l.split("|", 3) for l in sys.stdin.read().splitlines() if l]
svcs = [{"name": r[0], "ready": r[1] == "1", "seconds": int(r[2]), "reason": r[3]} for r in rows]
print(json.dumps({"ready": all(s["ready"] for s in svcs), "timeout": int(sys.argv[1]), "services": svcs}, indent=2))' "$t" <<<"$rows"
  elif [ ${#pending[@]} -gt 0 ] || [ "$nfail" -gt 0 ]; then
    bad "not ready after $(fmt_dur $(( SECONDS - start ))):"
    while IFS='|' read -r svc s _ why; do if [ -n "$svc" ] && [ "$s" = 0 ]; then printf '      - %s: %s\n' "$svc" "$why"; fi; done <<<"$rows"
  fi
  [ ${#pending[@]} -eq 0 ] && [ "$nfail" -eq 0 ]
}
wait_stack() {                 # everything the current settings enable (install, start, restart, upgrade)
  local t="${1:-$WAIT_READY_TIMEOUT}" s; s=($(enabled_services))
  [ ${#s[@]} -gt 0 ] || return 0
  say "Waiting until the stack is ready (up to $(fmt_dur "$t"))..."
  wait_ready_run "$t" 0 "${s[@]}"
}
cmd_wait_ready() {
  local t="$WAIT_READY_TIMEOUT" js=0 a svcs=() known s
  while [ $# -gt 0 ]; do
    case "$1" in
      --timeout|-t) [[ "${2:-}" =~ ^[0-9]+$ ]] || die "usage: vexor wait-ready [--timeout SECONDS] [--json] [service..]"; t="$2"; shift ;;
      --timeout=*) t="${1#*=}"; [[ "$t" =~ ^[0-9]+$ ]] || die "--timeout takes seconds" ;;
      --json) js=1 ;;
      -*) die "unknown option $1 - usage: vexor wait-ready [--timeout SECONDS] [--json] [service..]" ;;
      *) for a in $(resolve_many "$1"); do svcs+=("$a"); done ;;
    esac
    shift
  done
  docker_ok || die "Docker daemon is not running"
  known=" wazuh.master wazuh.worker wazuh2.worker wazuh3.worker ${INDEXERS[*]} wazuh.dashboard nginx ${ELK_SERVICES[*]} ${TOOLS[*]} "
  for s in "${svcs[@]}"; do [[ "$known" == *" $s "* ]] || die "unknown service '$s' (try: master worker indexer dashboard nginx elasticsearch kibana logstash n8n grafana portainer suricata zeek)"; done
  [ ${#svcs[@]} -gt 0 ] || svcs=($(enabled_services))
  [ ${#svcs[@]} -gt 0 ] || die "no services are enabled"
  [ "$js" = 1 ] || say "Waiting for: ${svcs[*]} (up to $(fmt_dur "$t"))"
  wait_ready_run "$t" "$js" "${svcs[@]}"
}
wait_indexer() {
  local t="${1:-240}"
  wait_ready_run "$t" 0 wazuh1.indexer || { warn "Indexer not ready after ${t}s - check: vexor logs indexer1"; return 1; }
}
wait_dashboard() {
  local t="${1:-180}"
  wait_ready_run "$t" 0 wazuh.dashboard || { warn "Dashboard not answering after ${t}s - check: vexor logs dashboard"; return 1; }
}
post_start() {                 # idempotent indexer-side setup
  [ "$(ix_code)" = 200 ] || return 0
  QUIET=1 retention_apply >/dev/null 2>&1 || warn "retention policy not applied yet (vexor retention apply)"
  snapshot_register >/dev/null 2>&1 || warn "snapshot repository not registered yet (vexor backup register)"
}

# ============================================================== install
check_prereqs() {
  local b missing=()
  for b in docker python3 openssl curl ss flock; do command -v "$b" >/dev/null || missing+=("$b"); done
  if [ ${#missing[@]} -gt 0 ]; then
    bad "Missing tools: ${missing[*]}"
    hint "Ubuntu/Debian: apt install -y python3 openssl curl iproute2 util-linux"
    hint "Docker: https://docs.docker.com/engine/install/  (then: systemctl enable --now docker)"
    exit 1
  fi
  docker_ok || die "Docker daemon is not running (systemctl start docker)"
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 plugin is required (apt install docker-compose-plugin)"
  ok "docker $(docker version -f '{{.Server.Version}}' 2>/dev/null), compose $(docker compose version --short 2>/dev/null)"
  local cv; cv="$(docker compose version --short 2>/dev/null | sed 's/^v//')"
  [ -n "$cv" ] && ver_gt 2.20.0 "$cv" && warn "docker compose $cv is old - 2.20+ is recommended (profiles, override merging)"
  disk_preflight
  local mem want; mem=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo); want="$(ram_want_gb "$(desired_node_type)")"
  if [ "$mem" -lt $(( want - 2 )) ]; then warn "${mem} GB RAM - node type $(desired_node_type) wants ${want} GB or more"
  else ok "${mem} GB RAM"; fi
}
ram_want_gb() { local b=16; [ "$1" = single ] && b=8; [ "$(soc)" = elk ] && b=2; soc_elk && b=$((b + 4)); echo "$b"; }
ensure_sysctl() {
  if [ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -lt 262144 ]; then
    sysctl -qw vm.max_map_count=262144
    echo "vm.max_map_count=262144" > /etc/sysctl.d/99-wazuh.conf
    ok "vm.max_map_count set to 262144 (persisted in /etc/sysctl.d/99-wazuh.conf)"
  else
    ok "vm.max_map_count = $(sysctl -n vm.max_map_count)"
  fi
}
gen_internal_certs() {
  local mm; mm="$(cur_version | cut -d. -f1,2)"
  sed -i -E "s/(CERT_TOOL_VERSION=)[0-9.]+/\1$mm/" "$CERTGEN_FILE"
  mkdir -p "$INT_CERT_DIR"
  pull_image_list $(cd "$ROOT" && docker compose -f "$CERTGEN_FILE" config --images 2>/dev/null | sort -u)
  run_step "Generating the internal TLS certificates" certgen_run || return 1
  (cd "$ROOT" && docker compose -p "$(project)-certs" -f "$CERTGEN_FILE" down) >/dev/null 2>&1
  [ -f "$INT_CERT_DIR/root-ca.pem" ]
}
certgen_run() { (cd "$ROOT" && docker compose -p "$(project)-certs" -f "$CERTGEN_FILE" run -T --rm generator); }
cmd_install() {
  local fresh_req=0 a
  for a in "$@"; do
    case "$a" in
      --fresh)  fresh_req=1 ;;
      --force)  INSTALL_FORCE=1 ;;      # install even when a disk is nearly full
      -y|--yes) ASSUME_YES=1 ;;
      *) die "usage: vexor install [--fresh] [--force] [--yes]" ;;
    esac
  done
  take_lock
  lc_fresh "$fresh_req"
  if [ ! -f "$ENV_FILE" ]; then
    [ -f "$ROOT/.env.example" ] || die ".env and .env.example not found in $ROOT"
    cp "$ROOT/.env.example" "$ENV_FILE"; chmod 600 "$ENV_FILE"; ok "created .env from .env.example (edit it any time: vexor config edit)"
    project_install_env
  fi
  hdr "1/9 Prerequisites";        check_prereqs
  hdr "2/9 Kernel (vm.max_map_count for the indexers)"; ensure_sysctl
  hdr "3/9 Settings"
  ensure_env_defaults
  if [ -n "$(env_get PUBLIC_HOST)" ]; then ok "PUBLIC_HOST = $(public_host)   (from .env)"
  else ok "PUBLIC_HOST = $(public_host)   (detected each time - set PUBLIC_HOST in .env if clients use another IP/name)"; fi
  fresh_install_layout
  ok "$(layout_desc)"
  hdr "4/9 Credentials"
  local key
  for key in INDEXER_PASSWORD DASHBOARD_PASSWORD API_PASSWORD; do
    if [ "$(env_get "$key")" = "CHANGE_ME" ] || [ -z "$(env_get "$key")" ]; then env_set "$key" "$(gen_pw)"; ok "generated $key"; fi
  done
  chmod 600 "$ENV_FILE"
  hdr "5/9 Cluster key";          ensure_cluster_key >/dev/null && ok "all managers share one cluster key"
  hdr "6/9 Passwords into the indexer/dashboard config"
  mkdir -p "$STATE_DIR"
  remove_demo_users
  if [ ! -f "$STATE_DIR/passwords-applied" ]; then
    local h1 h2
    is_running wazuh1.indexer || pull_image_list "wazuh/wazuh-indexer:$(cur_version)"   # hash_pw runs it once
    h1="$(hash_pw "$(env_get INDEXER_PASSWORD)")"; h2="$(hash_pw "$(env_get DASHBOARD_PASSWORD)")"
    [ -n "$h1" ] && [ -n "$h2" ] || die "Could not generate password hashes (is the wazuh-indexer image reachable?)"
    set_user_hash admin "$h1" && set_user_hash kibanaserver "$h2" || die "Could not update internal_users.yml"
    set_api_pw_yml "$(env_get API_PASSWORD)"
    touch "$STATE_DIR/passwords-applied"; ok "applied"
  else
    ok "already applied (change later with: vexor passwd ...)"
  fi
  hdr "7/9 Internal TLS certificates"
  if [ -f "$INT_CERT_DIR/root-ca.pem" ]; then ok "present"
  else gen_internal_certs || die "Certificate generation failed"; ok "root CA + node certificates are in config/wazuh_indexer_ssl_certs"; fi
  hdr "8/9 Dashboard certificate (port $(env_def PROXY_PORT 8080))"
  if [ -z "$(env_get PROXY_CERT)" ]; then cert_issue_local || warn "falling back to the built-in self-signed cert"
  else ok "using $(env_get PROXY_CERT) ($(cert_mode))"; fi
  hdr "9/9 Starting the stack"
  local fresh=0; docker volume inspect "$(project)_master-wazuh-etc" >/dev/null 2>&1 || fresh=1
  local bdir; bdir="$(backup_dir)"
  mkdir -p "$bdir/snapshots" "$bdir/config"; chown 1000:1000 "$bdir/snapshots"
  rm -f "$STATE_DIR/stopped"
  apply_all
  wait_stack || warn "some services are not ready yet - vexor wait-ready   |   vexor doctor"
  if [ "$fresh" = 1 ] && soc_wazuh && [ -z "$(env_get AGENT_ENROLL_PASSWORD)" ] && [ "$(env_def ENROLL_PASSWORD_ON_INSTALL no)" = yes ]; then
    agents_password on && say "agents need this password to enroll; vexor agents enroll-cmd includes it"
  fi
  cmd_info
  say ""
  say "Next: ${C_BD}vexor doctor${C_0}   |   ${C_BD}vexor daemon install${C_0} (watchdog, backups, maintenance)"
}

# ============================================================== lifecycle
preflight() {
  docker_ok || die "Docker daemon is not running (systemctl start docker)"
  if soc_wazuh; then
    grep -qE '^(INDEXER|DASHBOARD|API)_PASSWORD=CHANGE_ME' "$ENV_FILE" && die "Not installed yet - run: vexor install"
    [ -f "$INT_CERT_DIR/root-ca.pem" ] || die "Certificates missing - run: vexor install"
  fi
  [ "$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)" -ge 262144 ] || ensure_sysctl
  disk_preflight quiet
  return 0
}
node_type_pending() {          # NODE_TYPE in .env differs from the applied layout, or a switch is unfinished
  [ -f "$NODE_SWITCH_FILE" ] || [ "$(desired_node_type)" != "$(node_type)" ]
}
pending_target() { local t; t="$(cat "$NODE_SWITCH_FILE" 2>/dev/null)"; [[ "$t" =~ ^(single|multi)$ ]] || t="$(desired_node_type)"; echo "$t"; }
maybe_switch_node_type() {     # start/restart/config apply: carry out a NODE_TYPE edited in .env
  node_type_pending || return 1
  local t; t="$(pending_target)"
  if [ "$ASSUME_YES" = 1 ] || [ -t 0 ]; then
    say "NODE_TYPE=$t in .env, the stack runs as $(node_type) - switching now"
    node_type_switch "$t"; return 0
  fi
  warn "NODE_TYPE=$t in .env, but the stack runs as $(node_type); not switching unattended - run: vexor node-type $t"
  return 1
}
cmd_start() {
  take_lock; preflight
  if [ $# -eq 0 ] && soc_wazuh && maybe_switch_node_type; then rm -f "$STATE_DIR/stopped"; [ "$QUIET" = 1 ] || cmd_status; return; fi
  render_nginx; render_override
  rm -f "$STATE_DIR/stopped"
  if [ $# -gt 0 ]; then
    run_step "Starting $(resolve_many "$@" | tr '\n' ' ')" dc up -d $(resolve_many "$@") || return 1
    wait_ready_run "$WAIT_READY_TIMEOUT" 0 $(resolve_many "$@") || warn "not ready yet - vexor wait-ready   |   vexor doctor"
    return 0
  fi
  apply_all
  wait_stack || warn "some services are not ready yet - vexor wait-ready   |   vexor doctor"
  [ "$QUIET" = 1 ] || cmd_status
}
cmd_stop() {
  take_lock
  if [ $# -gt 0 ]; then
    dc stop $(resolve_many "$@")
    systemctl is-active -q "$UNIT-watchdog.timer" 2>/dev/null && \
      warn "the watchdog starts enabled services again within 5 min (stop the whole stack with: vexor stop)"
    return 0
  fi
  mkdir -p "$STATE_DIR"; touch "$STATE_DIR/stopped"      # tells the watchdog to leave it alone
  dc_all stop && ok "Stack stopped (data kept). Start again with: vexor start"
}
cmd_restart() {
  take_lock; preflight
  if [ $# -gt 0 ]; then
    dc_restart $(resolve_many "$@") || return 1
    wait_ready_run "$WAIT_READY_TIMEOUT" 0 $(resolve_many "$@") || warn "not ready yet - vexor wait-ready   |   vexor doctor"
    return 0
  fi
  maybe_switch_node_type && return 0
  render_nginx; render_override; dc_restart && wait_stack
}
cmd_down() {
  take_lock
  mkdir -p "$STATE_DIR"; touch "$STATE_DIR/stopped"
  dc_all down --remove-orphans && ok "Containers and network removed - volumes (all data) kept"
}
cmd_scale() {
  local n="${1:-}"
  [[ "$n" =~ ^[1-3]$ ]] || die "usage: vexor scale <1|2|3>   (worker managers, now $(worker_count))"
  take_lock
  env_set WORKER_COUNT "$n"; render_nginx
  if is_single; then
    ok "WORKER_COUNT=$n saved - node type is single, so the workers start with: vexor node-type multi"
    return 0
  fi
  ok "WORKER_COUNT=$n, nginx balances agents over master + $n worker(s)"
  local i; for i in 2 3; do [ "$n" -lt "$i" ] && dc_all rm -sf "wazuh${i}.worker" >/dev/null 2>&1; done
  if is_running nginx; then
    dc up -d && nginx_reload
    say "Agents rebalance as they reconnect. Check: vexor cluster"
  else
    say "Stack not running - applied on next: vexor start"
  fi
}

