# shellcheck shell=bash
# vexor lib/03-docker.sh - docker / compose helpers, network helpers, indexer + Wazuh API helpers
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== docker helpers
dc()      { (cd "$ROOT" && PUBLIC_HOST="$(public_host)" docker compose "$@"); }
dc_all()  { (cd "$ROOT" && PUBLIC_HOST="$(public_host)" COMPOSE_PROFILES=wazuh,elk,multi,w2,w3,ix3,n8n,grafana,portainer,suricata,zeek docker compose "$@"); }    # every service of both node types
project() { env_def COMPOSE_PROJECT_NAME vexor; }   # .env always has it (project_resolve); "wazuh" before vexor 2.0
dc_restart() {                 # restart services; MANAGERS ARE RECREATED instead:
  # the wazuh-manager image copies the mounted ossec.conf (/wazuh-config-mount) only when a container
  # is created - on a plain `docker restart` its init script exits early and keeps the old config.
  # Recreating is safe: all manager data lives in named volumes.
  local s m=() o=()
  [ $# -gt 0 ] || set -- $(enabled_services)
  for s in "$@"; do case "$s" in wazuh.master|wazuh*.worker) m+=("$s") ;; *) o+=("$s") ;; esac; done
  if [ ${#o[@]} -gt 0 ]; then dc restart "${o[@]}" || return 1; fi
  if [ ${#m[@]} -gt 0 ]; then dc up -d --force-recreate --no-deps "${m[@]}" || return 1; fi
  return 0
}
daemon_list() { dc exec -T "$1" /var/ossec/bin/wazuh-control status 2>/dev/null || true; }   # exits 1 when optional daemons are off
wait_daemon() {                # wait_daemon <svc> <wazuh daemon> [timeout-s]
  local i=0 t="${3:-120}"
  while [ "$i" -lt "$t" ]; do
    daemon_list "$1" | has "^$2 is running" && return 0
    sleep 5; i=$((i + 5))
  done
  return 1
}
cur_version() { env_def WAZUH_VERSION 4.14.8; }
# Node type. multi  = master + WORKER_COUNT workers, INDEXER_COUNT indexers
#            single = master + wazuh1.indexer
# In BOTH, nginx is in front: agents -> nginx:AGENT_PORT -> managers, browser -> nginx:PROXY_PORT -> dashboard,
# so agents and users always use the same address.
# Both use the SAME volumes for the master (agent keys, rules, groups, API users), wazuh1.indexer
# (all alerts) and the dashboard, so agents and data stay when switching. node_type() is the layout
# that is applied; NODE_TYPE in .env is the wanted one (vexor node-type makes them equal).
node_type() { local t; t="$(cat "$NODE_TYPE_FILE" 2>/dev/null)"; [[ "$t" =~ ^(single|multi)$ ]] || t=multi; echo "$t"; }
desired_node_type() { local t; t="$(env_def NODE_TYPE multi)"; t="${t,,}"; [[ "$t" =~ ^(single|multi)$ ]] || t=multi; echo "$t"; }
is_single() { [ "$(node_type)" = single ]; }
worker_count() { local n; n="$(env_def WORKER_COUNT 1)"; [[ "$n" =~ ^[1-3]$ ]] || n=1; echo "$n"; }   # workers used in multi
active_workers() { if is_single; then echo 0; else worker_count; fi; }
enabled_managers() {
  soc_wazuh || return 0
  local n; n="$(active_workers)"
  echo wazuh.master
  [ "$n" -ge 1 ] && echo wazuh.worker
  [ "$n" -ge 2 ] && echo wazuh2.worker
  [ "$n" -ge 3 ] && echo wazuh3.worker
  return 0
}
indexer_count() { local n; n="$(env_def INDEXER_COUNT 3)"; [[ "$n" =~ ^(1|3)$ ]] || n=3; echo "$n"; }
enabled_indexers() { soc_wazuh || return 0; if [ "$(indexer_count)" = 1 ]; then echo wazuh1.indexer; else echo "${INDEXERS[@]}"; fi; }
enabled_services() { enabled_managers; enabled_indexers; soc_wazuh && echo wazuh.dashboard; echo nginx; soc_elk && echo "${ELK_SERVICES[@]}"; enabled_tools; }
proxy_svc() { echo nginx; }      # nginx serves PROXY_PORT (and AGENT_PORT) in both node types
layout_desc() {
  if is_single; then echo "node type single: 1 manager, 1 indexer, dashboard behind nginx"
  else echo "node type multi: master + $(worker_count) worker(s), $(indexer_count) indexer(s), dashboard behind nginx"; fi
}
running_services() { dc_all ps --status running --services 2>/dev/null; }
is_running() { running_services | has -x "$1"; }
docker_ok() { docker info >/dev/null 2>&1; }
svc_uptime_s() {               # seconds since the service container started (0 if not running)
  local id st; id="$(svc_cid "$1")"; [ -n "$id" ] || { echo 0; return; }
  st="$(docker inspect -f '{{.State.StartedAt}}' "$id" 2>/dev/null)"
  echo $(( $(date +%s) - $(date -d "$st" +%s 2>/dev/null || date +%s) ))
}
resolve_svc() {
  case "$1" in
    master|manager)        echo wazuh.master ;;
    worker|worker1)        echo wazuh.worker ;;
    worker2)               echo wazuh2.worker ;;
    worker3)               echo wazuh3.worker ;;
    indexer|indexer1)      echo wazuh1.indexer ;;
    indexer2)              echo wazuh2.indexer ;;
    indexer3)              echo wazuh3.indexer ;;
    dashboard|ui)          echo wazuh.dashboard ;;
    proxy|nginx)           echo nginx ;;
    managers)              enabled_managers ;;
    indexers)              enabled_indexers ;;
    *)                     echo "$1" ;;
  esac
}
resolve_many() { local a out=(); for a in "$@"; do out+=($(resolve_svc "$a")); done; echo "${out[@]}"; }
abspath() { case "$1" in /*) echo "$1" ;; *) echo "$ROOT/${1#./}" ;; esac; }
backup_dir() { abspath "$(env_def BACKUP_DIR ./backups)"; }
docker_root() { docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker; }
disk_pct() { df -P "$1" 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print $5}'; }

take_lock() {
  [ "$LOCK_HELD" = 1 ] && return 0
  mkdir -p "$(dirname "$LOCK_FILE")"
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    [ "${1:-}" = quiet ] && exit 0
    say "another vexor operation is running (watchdog / health check?) - waiting up to 3 min ..."
    flock -w 180 9 || die "still locked after 3 min (lock $LOCK_FILE) - see: vexor daemon logs"
  fi
  LOCK_HELD=1
}

# ============================================================== network helpers
primary_ip() {
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [ -n "$ip" ] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "${ip:-127.0.0.1}"
}
host_ips() {
  if command -v ip >/dev/null 2>&1; then
    ip -o -4 addr show scope global 2>/dev/null \
      | awk '$2 !~ /^(docker|br-|veth|virbr|cni|flannel|cali|vxlan)/ {split($4,a,"/"); print a[1]}'
  else
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' | grep -v '^127\.'
  fi
  return 0
}
public_host() { local h; h="$(env_get PUBLIC_HOST)"; echo "${h:-$(primary_ip)}"; }   # empty PUBLIC_HOST = detected each run, never saved
bind_ip() { env_def BIND_IP 0.0.0.0; }
local_ip() {                   # local_ip [bind]: address vexor uses to reach its own published ports
  local b="${1:-$(bind_ip)}"
  case "$b" in 0.0.0.0|::|"[::]") echo 127.0.0.1 ;; *) echo "$b" ;; esac
}
host_has_ip() { [ "$1" = 127.0.0.1 ] || [ "$1" = "$(primary_ip)" ] || host_ips | has -xF "$1"; }
port_listening() { ss -Hltn "( sport = :$1 )" 2>/dev/null | has .; }
tcp_open() { timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
host_published() {             # host_published <svc> <container-port>: the port is bound on the host
  # (not `docker compose port`: it prints "invalid IP:0" and exits 0 for ports the image only EXPOSEs)
  local id; id="$(dc_all ps -q "$1" 2>/dev/null | head -1)"; [ -n "$id" ] || return 1
  docker port "$id" "$2/tcp" 2>/dev/null | has -E ':[0-9]+$'
}

# ============================================================== API helpers
indexer_curl() {
  local bind; bind="$(env_def INDEXER_BIND 127.0.0.1)"; [ "$bind" = 0.0.0.0 ] && bind=127.0.0.1
  curl -sS --connect-timeout 5 --cacert "$INT_CERT_DIR/root-ca.pem" --resolve "wazuh1.indexer:$(indexer_port):$bind" \
       -u "$(env_def INDEXER_USERNAME admin):$(env_get INDEXER_PASSWORD)" "$@"
}
indexer_port() { env_def INDEXER_HOST_PORT 9200; }
indexer_base() { echo "https://wazuh1.indexer:$(indexer_port)"; }
ix() { local m="$1" p="$2"; shift 2; indexer_curl -X "$m" "$(indexer_base)$p" -H 'Content-Type: application/json' "$@"; }
ix_code() { indexer_curl -o /dev/null -w '%{http_code}' --max-time 10 "$(indexer_base)${1:-/}" 2>/dev/null || true; }
pj() {                         # pj 'python using d' [args]  - JSON from stdin as d
  local code="$1"; shift
  python3 -I -c "import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(3)
$code" "$@"
}
API_TOKEN=""
api_port() { env_def API_PORT 55000; }
api_login() {
  [ -n "$API_TOKEN" ] && return 0
  local t
  t="$(curl -sk --connect-timeout 5 --max-time 20 -X POST \
        -u "$(env_def API_USERNAME wazuh-wui):$(env_get API_PASSWORD)" \
        "https://$(local_ip):$(api_port)/security/user/authenticate?raw=true" 2>/dev/null)" || return 1
  [[ "$t" == ey* ]] || return 1
  API_TOKEN="$t"
}
api() {
  local m="$1" p="$2"; shift 2
  api_login || { echo '{"error":1,"message":"Wazuh API authentication failed"}'; return 1; }
  curl -sk --connect-timeout 5 --max-time 60 -X "$m" -H "Authorization: Bearer $API_TOKEN" \
       -H 'Content-Type: application/json' "https://$(local_ip):$(api_port)$p" "$@"
}
proxy_code() { curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "${1:-https}://$(local_ip):$(env_def PROXY_PORT 8080)/" 2>/dev/null || true; }
pretty() { local out; out="$(cat)"; printf '%s' "$out" | python3 -I -m json.tool 2>/dev/null || printf '%s\n' "$out"; }

ver_gt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]; }

