# shellcheck shell=bash
# vexor lib/01-core.sh - paths and globals, output helpers (colors, ok/warn/die), progress helpers (run_step, spinner, image pulls)
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
ENV_FILE="$ROOT/.env"
STATE_DIR="$ROOT/.state"
INT_CERT_DIR="$ROOT/config/wazuh_indexer_ssl_certs"
PROXY_CERT_DIR="$ROOT/config/nginx/certs"
LE_DIR="$ROOT/config/nginx/letsencrypt"
ROUTES_FILE="$ROOT/config/nginx/routes.json"              # proxy routes (vexor proxy), written atomically
ROUTES_CERT_DIR="$ROOT/config/nginx/routes-certs"         # <host>.pem + <host>-key.pem per route
ACME_DIR="$ROOT/config/nginx/acme"                        # http-01 webroot nginx serves on ROUTES_HTTP_PORT
NGINX_TPL="$ROOT/config/nginx/nginx.conf.tpl"
NGINX_CONF="$ROOT/config/nginx/nginx.conf"
CLUSTER_DIR="$ROOT/config/wazuh_cluster"
INTERNAL_USERS="$ROOT/config/wazuh_indexer/internal_users.yml"
DASH_WAZUH_YML="$ROOT/config/wazuh_dashboard/wazuh.yml"
CERTGEN_FILE="$ROOT/generate-indexer-certs.yml"
SNAP_REPO="wazuh-fs"
ISM_POLICY="wazuh-retention"
HASH_SH="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"
ALPINE_IMAGE="alpine:3.20"
UNIT="vexor"
SYSTEMD_DIR="/etc/systemd/system"
LOCK_FILE="/run/lock/vexor.lock"
INDEXERS=(wazuh1.indexer wazuh2.indexer wazuh3.indexer)        # all defined; INDEXER_COUNT picks 1 or 3
REMINDERS_FILE="$ROOT/.state/reminders"
HISTORY_FILE="$ROOT/.state/history.log"
REPORT_DIR="$ROOT/reports"
OVERRIDE_FILE="$ROOT/docker-compose.override.yml"
TOOLS=(n8n grafana portainer suricata zeek)                # optional tools: <NAME>=true in .env
WEB_TOOLS=(n8n grafana portainer)                         # published through nginx on <NAME>_PORT
TOOLS_COMPOSE="$ROOT/docker-compose.tools.yml"
TOOLS_DIR="$ROOT/config/tools"
TOOLS_DATA="$ROOT/tools-data"
TOOL_RULES="$ROOT/config/tools/wazuh/vexor_tools_rules.xml"
TOOLS_MASTER_CHANGED=0
VULN_CHANGED=0
INSTALL_FORCE=0
ELK_SERVICES=(elasticsearch kibana logstash)              # SOC=elk|both
ELK_COMPOSE="$ROOT/docker-compose.elk.yml"
ELK_DIR="$ROOT/config/elk"
COMPOSE_FILES="docker-compose.yml:docker-compose.tools.yml:docker-compose.elk.yml:docker-compose.override.yml"
NODE_TYPE_FILE="$ROOT/.state/node-type"          # layout that is APPLIED (NODE_TYPE in .env = the wanted one)
NODE_SWITCH_FILE="$ROOT/.state/node-type-switch" # target of a switch that has not finished yet
LOCK_HELD=0
MASTER_STATE_VOLUMES=(master-wazuh-etc master-wazuh-api-configuration master-wazuh-var-multigroups
                      master-wazuh-integrations master-wazuh-active-response)

ASSUME_YES=0
QUIET=0
USE_COLOR=1
RUN_TMP=""

# ============================================================== output helpers
setup_colors() {
  if [ "$USE_COLOR" = 1 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_R=$'\e[31m' C_G=$'\e[32m' C_Y=$'\e[33m' C_B=$'\e[36m' C_D=$'\e[2m' C_BD=$'\e[1m' C_0=$'\e[0m'
  else
    C_R="" C_G="" C_Y="" C_B="" C_D="" C_BD="" C_0=""
  fi
}
hdr()  { [ "$QUIET" = 1 ] && return 0; printf '\n%s==> %s%s\n' "$C_BD$C_B" "$*" "$C_0"; }
say()  { [ "$QUIET" = 1 ] && return 0; printf '  %s\n' "$*"; }
ok()   { [ "$QUIET" = 1 ] && return 0; printf '  %s✔%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_Y" "$C_0" "$*"; }
bad()  { printf '  %s✘%s %s\n' "$C_R" "$C_0" "$*"; }
hint() { printf '      %s→ %s%s\n' "$C_D" "$*" "$C_0"; }
die()  { printf '%s✘ %s%s\n' "$C_R" "$*" "$C_0" >&2; exit 1; }
ts()   { date '+%F %T'; }
has()  { grep "$@" >/dev/null; }   # like grep -q, but reads all input (no SIGPIPE under pipefail)
log()  { printf '%s %s\n' "$(ts)" "$*"; }          # plain lines for journald (watchdog/timers)

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || die "'$1' needs confirmation - re-run with --yes"
  local a; read -r -p "  $1 [y/N] " a
  [[ "$a" =~ ^([yY]|[yY][eE][sS])$ ]]
}
confirm_word() {               # confirm_word WORD "warning text"
  local word="$1"; shift
  [ "$ASSUME_YES" = 1 ] && return 0
  [ -t 0 ] || die "Needs confirmation - re-run with --yes"
  local a; printf '  %s%s%s\n' "$C_R" "$*" "$C_0"
  read -r -p "  Type $word to continue: " a
  [ "$a" = "$word" ]
}
mask() { local v="$1"; [ ${#v} -le 4 ] && { echo "****"; return; }; echo "${v:0:2}$(printf '%*s' $(( ${#v} - 2 )) '' | tr ' ' '*')"; }

# ============================================================== progress helpers (run_step, live spinner, image pulls)
# run_step "<label>" <cmd...>   runs the command with its output captured in $STATE_DIR/logs/<label>.log.
#   on a terminal: one live line  "⠋ label (12s) · latest output line", then "✔ label (12s)" / "✘ label (12s)"
#   in CI / pipes / TERM=dumb / --no-color: no animation - the label once, then ✔/✘ with the time
#   on failure: the last lines of the log + its path; returns the command's exit code
#   VEXOR_VERBOSE=1 or --verbose: the command's full output streams as before
VERBOSE="${VEXOR_VERBOSE:-0}"
SPIN_PID=""
SPIN_CURSOR=0
SPIN_FRAMES=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
step_live() {                  # true when animations may be drawn (colour terminal, not CI, not dumb)
  [ -n "$C_0" ] && [ -t 1 ] && [ "$QUIET" != 1 ] && [ "$VERBOSE" != 1 ] \
    && [ -z "${CI:-}" ] && [ "${TERM:-dumb}" != dumb ]
}
step_cols() {
  local c="${COLUMNS:-}"
  [[ "$c" =~ ^[0-9]+$ ]] || c="$(tput cols 2>/dev/null)"
  { [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -ge 20 ]; } || c=80
  echo "$c"
}
cursor_hide() { tput civis 2>/dev/null || printf '\e[?25l'; SPIN_CURSOR=1; }
cursor_show() { [ "$SPIN_CURSOR" = 1 ] || return 0; tput cnorm 2>/dev/null; printf '\e[?25h'; SPIN_CURSOR=0; }
spin_line() {                  # spin_line <frame-index> <text>: redraw the live line in place, cut to the terminal width
  local cols txt="$2"; cols="$(step_cols)"
  txt="${txt:0:$((cols - 5))}"
  printf '\r  %s%s%s %s\e[K' "$C_B" "${SPIN_FRAMES[$(( $1 % 10 ))]}" "$C_0" "$txt"
}
spin_clear() { printf '\r\e[K'; }
spin_stop() {                  # kill the spinner, wipe its line, show the cursor (also called from the EXIT trap)
  if [ -n "$SPIN_PID" ]; then
    kill "$SPIN_PID" 2>/dev/null; wait "$SPIN_PID" 2>/dev/null; SPIN_PID=""
    spin_clear
  fi
  cursor_show
}
step_last_line() {             # newest non-empty line of a log; \r progress redraws and ANSI codes are dropped
  local esc=$'\e'
  tail -c 4096 "$1" 2>/dev/null | tr '\r' '\n' | sed -E "s/${esc}\[[0-9;?]*[A-Za-z]//g" \
    | tr -cd '\11\12\40-\176' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | grep -v '^$' | tail -n 1
}
step_spin() {                  # background subshell: step_spin <label> <log> <start-SECONDS> <parent-pid>
  local label="$1" log="$2" start="$3" par="$4" i=0 detail=""
  trap 'exit 0' TERM
  trap 'spin_clear; cursor_show' EXIT
  SPIN_CURSOR=1
  while kill -0 "$par" 2>/dev/null; do     # ends by itself when vexor dies without cleaning up
    [ $((i % 5)) = 0 ] && detail="$(step_last_line "$log")"
    spin_line "$i" "$label ($(fmt_dur $(( SECONDS - start ))))${detail:+ · $detail}"
    i=$((i + 1)); sleep 0.1 2>/dev/null || sleep 1
  done
}
run_step() {
  local label="$1" slug log t0 rc=0 el mode=plain; shift
  step_live && mode=live
  [ "$VERBOSE" = 1 ] && mode=verbose
  slug="$(printf '%s' "$label" | tr -c 'A-Za-z0-9' '-' | sed -E 's/-+/-/g; s/^-//; s/-$//' | cut -c1-48)"
  log="$STATE_DIR/logs/${slug:-step}.log"
  mkdir -p "$STATE_DIR/logs" 2>/dev/null || log="${RUN_TMP:-/tmp}/${slug:-step}.log"
  : > "$log" 2>/dev/null || log=/dev/null
  t0=$SECONDS
  case "$mode" in
    verbose) say "$label ..."; "$@" </dev/null; rc=$? ;;
    plain)   say "$label ..."; "$@" >"$log" 2>&1 </dev/null; rc=$? ;;
    live)
      cursor_hide
      step_spin "$label" "$log" "$t0" "$BASHPID" & SPIN_PID=$!
      "$@" >"$log" 2>&1 </dev/null; rc=$?
      spin_stop ;;
  esac
  el="$(fmt_dur $(( SECONDS - t0 )))"
  if [ "$rc" = 0 ]; then ok "$label ($el)"
  else
    bad "$label ($el, exit $rc)"
    if [ "$mode" != verbose ] && [ -s "$log" ]; then
      printf '      %s--- last lines of the output ---%s\n' "$C_D" "$C_0"
      tail -n 25 "$log" | tr -d '\r' | sed 's/^/      /'
      hint "full log: $log"
    fi
  fi
  return "$rc"
}
pull_image_list() {            # pull_image_list <image..>: pulls the ones missing locally (all with PULL_ALL=1), 4 tries each
  local img todo=() n
  for img in "$@"; do
    if [ "${PULL_ALL:-0}" = 1 ] || ! docker image inspect "$img" >/dev/null 2>&1; then todo+=("$img"); fi
  done
  n=${#todo[@]}; [ "$n" -gt 0 ] || return 0
  run_step "pulling $n image$([ "$n" = 1 ] || echo s)" pull_images_loop "$n" "${todo[@]}"
}
pull_images_loop() {           # pull_images_loop <total> <image..>: progress goes to stdout (live line / log)
  local n="$1" img i=0 t fail=0 err; shift
  err="$(mktemp)"
  for img in "$@"; do
    i=$((i + 1))
    for t in 1 2 3 4; do
      echo "pulling $i/$n images - $img"
      docker pull -q "$img" >/dev/null 2>"$err" && break
      cat "$err"
      [ "$t" = 4 ] && { echo "could not pull $img (network/registry) - retry later: vexor start"; fail=1; break; }
      echo "pull of $img failed - retry $t/3 in $((t * 10))s"; sleep $((t * 10))
    done
  done
  rm -f "$err"
  return "$fail"
}

