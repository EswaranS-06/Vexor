# shellcheck shell=bash
# vexor lib/18-daemon.sh - daemon / watchdog / maintenance, support bundle, completion, migrate (wazuh -> vexor)
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== daemon / watchdog / maintenance
cmd_watchdog() {
  take_lock quiet
  docker_ok || { log "docker daemon not running"; exit 1; }
  [ -f "$STATE_DIR/stopped" ] && exit 0
  grep -qE '^(INDEXER|DASHBOARD|API)_PASSWORD=CHANGE_ME' "$ENV_FILE" && exit 0
  local heal; heal="$(env_def WATCHDOG_AUTOHEAL yes)"
  local svc run started=""; run="$(running_services)"
  for svc in $(enabled_services); do
    grep -qx "$svc" <<<"$run" && continue
    if [ "$heal" = yes ]; then log "$svc not running - starting it"; dc up -d "$svc" >/dev/null 2>&1 && started+="$svc " || log "failed to start $svc"
    else log "$svc not running (WATCHDOG_AUTOHEAL=no)"; started+="$svc(down) "; fi
  done
  if [ -n "$started" ] && [ "$(env_def NOTIFY_ON fail)" != off ] && ! file_fresh "$STATE_DIR/notify.watchdog" 60; then
    notify_send warn "Vexor on $(hostname): watchdog acted" "Containers that were not running: $started" && touch "$STATE_DIR/notify.watchdog"
  fi
  local dp warn_pct; warn_pct="$(env_def DISK_WARN_PCT 85)"; dp="$(disk_pct "$(docker_root)")"
  [ "${dp:-0}" -ge "$warn_pct" ] && log "WARNING docker disk ${dp}% used"
  if [ "$(ix_code)" = 200 ]; then
    local st; st="$(ix GET /_cluster/health | pj 'print(d["status"])')"
    [ "$st" = green ] || log "indexer cluster is $st"
    local ro; ro="$(ix GET '/_all/_settings/index.blocks.read_only_allow_delete' | pj 'print(sum(1 for v in d.values() if v.get("settings",{}).get("index",{}).get("blocks",{}).get("read_only_allow_delete") == "true"))')"
    if [ "${ro:-0}" -gt 0 ]; then
      if [ "$heal" = yes ] && [ "${dp:-100}" -lt 90 ]; then
        ix PUT '/_all/_settings' -d '{"index.blocks.read_only_allow_delete": null}' >/dev/null && log "cleared read-only block on $ro indices (disk ${dp}%)"
      else log "WARNING $ro indices read-only (disk ${dp}%)"; fi
    fi
  elif grep -qx wazuh1.indexer <<<"$run"; then
    log "indexer not answering (HTTP $(ix_code))"
  fi
  local pc; pc="$(proxy_code)"
  [[ "$pc" =~ ^(200|302)$ ]] || log "dashboard on port $(env_def PROXY_PORT 8080) ($(proxy_svc)) returns HTTP ${pc:-000}"
  node_type_pending && log "NODE_TYPE=$(pending_target) in .env, running $(node_type) - run: vexor node-type $(pending_target)"
  return 0
}
cmd_maintenance() {
  take_lock quiet
  log "maintenance start"
  prune_logs
  tools_maintenance
  [ "$(ix_code)" = 200 ] && retention_apply
  soc_elk && [ "$(es_code /_cluster/health)" = 200 ] && elk_retention_apply
  cert_renew
  proxy_renew_due
  docker image prune -f >/dev/null 2>&1
  log "maintenance done"
}
daemon_units() {
  local bt mt; bt="$(env_def BACKUP_TIME 01:30)"; mt="$(env_def MAINT_TIME 02:15)"
  cat > "$SYSTEMD_DIR/$UNIT.service" <<EOF
[Unit]
Description=Wazuh multi-node Docker stack ($ROOT)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$ROOT
ExecStart=$SELF --quiet --no-color start
ExecStop=$SELF --quiet --no-color stop
TimeoutStartSec=900
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
EOF
  local name desc cmd cal rep
  while IFS='|' read -r name desc cmd cal rep; do
    cat > "$SYSTEMD_DIR/$UNIT-$name.service" <<EOF
[Unit]
Description=Wazuh stack: $desc
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=$ROOT
ExecStart=$SELF --no-color $cmd
EOF
    cat > "$SYSTEMD_DIR/$UNIT-$name.timer" <<EOF
[Unit]
Description=Wazuh stack: $desc

[Timer]
$cal
${rep:+OnUnitActiveSec=$rep}
Persistent=true
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
EOF
  done <<EOF
watchdog|self-healing watchdog|watchdog|OnBootSec=5min|5min
health|health check with auto-fix (doctor --fix)|autoheal|OnBootSec=15min|$(env_def HEALTH_INTERVAL 1h)
backup|daily backup|backup run|OnCalendar=*-*-* $bt:00|
maintenance|daily maintenance (log pruning, retention, cert renewal)|maintenance|OnCalendar=*-*-* $mt:00|
EOF
  sed -i '/^$/d' "$SYSTEMD_DIR/$UNIT"-*.timer
  # login message with health + reminders (Ubuntu/Debian update-motd)
  if [ -d /etc/update-motd.d ]; then
    printf '#!/bin/sh\n[ -x %s ] && %s --no-color motd 2>/dev/null\nexit 0\n' "$SELF" "$SELF" > /etc/update-motd.d/99-vexor
    chmod 755 /etc/update-motd.d/99-vexor
  fi
}
legacy_cleanup() {             # units, link, completion and motd of the pre-rename name (wazuhctl / wazuh-stack)
  command -v systemctl >/dev/null || return 0
  local t found=0
  for t in watchdog health backup maintenance; do
    [ -f "$SYSTEMD_DIR/wazuh-stack-$t.timer" ] || continue
    systemctl disable --now "wazuh-stack-$t.timer" >/dev/null 2>&1; rm -f "$SYSTEMD_DIR/wazuh-stack-$t".{timer,service}; found=1
  done
  if [ -f "$SYSTEMD_DIR/wazuh-stack.service" ]; then systemctl disable wazuh-stack.service >/dev/null 2>&1; rm -f "$SYSTEMD_DIR/wazuh-stack.service"; found=1; fi
  [ -L /usr/local/bin/wazuhctl ] && rm -f /usr/local/bin/wazuhctl && found=1
  rm -f /etc/bash_completion.d/wazuhctl /etc/update-motd.d/99-wazuhctl
  [ "$found" = 1 ] && { systemctl daemon-reload; ok "removed the old wazuhctl / wazuh-stack units"; }
  return 0
}
daemon_uninstall() {
  command -v systemctl >/dev/null || return 0
  local t
  for t in watchdog health backup maintenance; do systemctl disable --now "$UNIT-$t.timer" >/dev/null 2>&1; rm -f "$SYSTEMD_DIR/$UNIT-$t".{timer,service}; done
  legacy_cleanup
  rm -f /etc/update-motd.d/99-vexor
  systemctl disable "$UNIT.service" >/dev/null 2>&1      # not --now: that would stop the stack
  systemctl disable --now "$UNIT-console.service" >/dev/null 2>&1; rm -f "$SYSTEMD_DIR/$UNIT-console.service"
  rm -f "$SYSTEMD_DIR/$UNIT.service"
  systemctl daemon-reload
  [ "$(readlink -f /usr/local/bin/vexor 2>/dev/null)" = "$SELF" ] && rm -f /usr/local/bin/vexor
  rm -f /etc/bash_completion.d/vexor
  ok "systemd units, PATH link and completion removed (the stack keeps running)"
}
cmd_daemon() {
  local sub="${1:-status}"
  command -v systemctl >/dev/null || die "systemd is required for the daemon"
  case "$sub" in
    install)
      legacy_cleanup
      daemon_units
      ln -sf "$SELF" /usr/local/bin/vexor
      completion_script > /etc/bash_completion.d/vexor
      systemctl daemon-reload
      console_sync || true
      systemctl enable "$UNIT.service" >/dev/null 2>&1
      systemctl is-active -q "$UNIT.service" || systemctl start "$UNIT.service" --no-block
      local t; for t in watchdog health backup maintenance; do systemctl enable --now "$UNIT-$t.timer" >/dev/null 2>&1; done
      ok "vexor is on PATH: /usr/local/bin/vexor  (bash completion installed - open a new shell)"
      ok "$UNIT.service: starts the stack at boot  (systemctl start|stop|status $UNIT)"
      ok "watchdog every 5 min, health check + auto-fix every $(env_def HEALTH_INTERVAL 1h), backup daily $(env_def BACKUP_TIME 01:30), maintenance daily $(env_def MAINT_TIME 02:15)"
      [ -f /etc/update-motd.d/99-vexor ] && ok "SSH login message shows the last health check and due reminders"
      say "Timers: vexor daemon status    Logs: vexor daemon logs" ;;
    uninstall|remove) daemon_uninstall ;;
    status)
      systemctl --no-pager status "$UNIT.service" 2>/dev/null | head -n 5 || warn "$UNIT.service not installed (vexor daemon install)"
      echo; systemctl --no-pager list-timers "$UNIT-*" 2>/dev/null ;;
    logs) journalctl --no-pager -n "${2:-100}" -u "$UNIT*" ;;
    *) die "usage: vexor daemon install|uninstall|status|logs [N]" ;;
  esac
}

# ============================================================== support bundle / completion
cmd_support_bundle() {
  local stamp dir out; stamp="$(date +%Y%m%d-%H%M%S)"; dir="$RUN_TMP/wazuh-support-$stamp"; mkdir -p "$dir/logs"
  hdr "Collecting diagnostics"
  { echo "vexor $VEXOR_VERSION  $(date)"; uname -a; cat /etc/os-release 2>/dev/null; free -h; df -h; } > "$dir/host.txt" 2>&1
  docker info > "$dir/docker-info.txt" 2>&1
  dc_all ps -a > "$dir/ps.txt" 2>&1
  USE_COLOR=0; setup_colors
  cmd_doctor > "$dir/doctor.txt" 2>&1
  cmd_status > "$dir/status.txt" 2>&1
  local svc
  for svc in $(dc_all ps -a --services 2>/dev/null); do dc_all logs --no-color --tail 1000 "$svc" > "$dir/logs/$svc.log" 2>&1; done
  for svc in $(enabled_managers); do
    is_running "$svc" || continue
    dc exec -T "$svc" tail -n 2000 /var/ossec/logs/ossec.log  > "$dir/logs/$svc-ossec.log" 2>&1
    dc exec -T "$svc" tail -n 1000 /var/ossec/logs/cluster.log > "$dir/logs/$svc-cluster.log" 2>&1
  done
  if [ "$(ix_code)" = 200 ]; then
    { ix GET /_cluster/health?pretty; ix GET '/_cat/nodes?v'; ix GET '/_cat/allocation?v'; ix GET '/_cat/indices?v&s=index'
      ix GET '/_cluster/allocation/explain?pretty' 2>/dev/null; } > "$dir/indexer.txt" 2>&1
  fi
  mkdir -p "$dir/config"
  sed -E 's/^([A-Z_]*PASSWORD=).*/\1***masked***/' "$ENV_FILE" > "$dir/config/env.txt"
  cp -r "$ROOT/config/wazuh_cluster" "$ROOT/config/wazuh_dashboard" "$ROOT/config/wazuh_indexer" "$ROOT/config/nginx/nginx.conf" "$ROOT/docker-compose.yml" "$dir/config/" 2>/dev/null
  [ -f "$OVERRIDE_FILE" ] && cp "$OVERRIDE_FILE" "$dir/config/"
  { echo "applied: $(node_type)   .env NODE_TYPE: $(desired_node_type)   unfinished switch: $(cat "$NODE_SWITCH_FILE" 2>/dev/null || echo none)"; } > "$dir/node-type.txt"
  grep -rlZ . "$dir/config" | xargs -0 sed -i -E 's/((password|hash|<key>)[":[:space:]]*)[^<[:space:]]+/\1***masked***/I'
  out="$ROOT/support-$stamp.tar.gz"
  tar czf "$out" -C "$RUN_TMP" "wazuh-support-$stamp" && chmod 600 "$out"
  ok "$out  (passwords, hashes and the cluster key are masked - review before sharing)"
}
completion_script() {
  cat <<'EOF'
# bash completion for vexor
_vexor() {
  local cur="${COMP_WORDS[COMP_CWORD]}" cmd="${COMP_WORDS[1]:-}" words
  local svcs="master worker worker2 worker3 indexer1 indexer2 indexer3 dashboard nginx managers indexers"
  if [ "$COMP_CWORD" -eq 1 ]; then
    words="install uninstall migrate info config start stop restart down scale wait-ready node-type status health doctor logs shell exec indexer api support-bundle update version cert proxy passwd agents cluster wazuh elk n8n suricata zeek console plan notify login tools soc indexers autoheal ai-context reminders motd backup retention prune-logs volumes disk images reset daemon watchdog maintenance completion help"
  else
    case "$cmd" in
      start|stop|restart|shell|exec) words="$svcs" ;;
      wait-ready|wait) words="$svcs elasticsearch kibana logstash n8n grafana portainer --timeout --json" ;;
      install) words="--fresh --force --yes" ;;
      uninstall) words="--keep-data --images --yes" ;;
      logs)    words="$svcs ossec api cluster alerts archives errors size -f -n --since" ;;
      config)
        if [ "${COMP_WORDS[2]:-}" = set ] || [ "${COMP_WORDS[2]:-}" = get ]; then
          local envx; envx="$(dirname "$(readlink -f "$(command -v "${COMP_WORDS[0]}")" 2>/dev/null)")/.env.example"
          words="$(sed -n 's/^#\{0,1\} \{0,1\}\([A-Z][A-Z0-9_]*\)=.*/\1/p' "$envx" 2>/dev/null | sort -u)"
        else words="show get set edit validate plan apply --show-secrets"; fi ;;
      plan)    words="--json" ;;
      migrate) words="--yes" ;;
      notify)  words="status test send fail warn ok info" ;;
      login)   words="dashboard indexer api enroll kibana elasticsearch logstash grafana portainer n8n console wazuh elk --json" ;;
      update)  words="check apply rollback images latest --no-backup --force" ;;
      volumes) words="ls orphans backup restore rm prune --stop --out --yes" ;;
      disk)    words="--json" ;;
      images)  words="prune --yes" ;;
      cert)    words="status create export-ca serve-ca import letsencrypt renew use-default internal-regen --force --email --staging --dns" ;;
      proxy)   words="ls show add edit rm cert cert-file apply --json --tls local letsencrypt off --websocket --no-websocket --max-body --target --renew ca cert" ;;
      passwd)  words="admin kibanaserver api --generate" ;;
      agents)
        if [ "${COMP_WORDS[2]:-}" = password ]; then words="on off show"
        else words="list summary outdated remove enroll-cmd password linux rpm windows macos --name --group"; fi ;;
      wazuh)   words="status alerts logtest rules decoders lists integrations config detection agents cluster ls show put rm reset history restore templates add del edit test set custom --from --json --format --location --hook-url --api-key --api-key-file --level --group --rule-id --scope -n --grep" ;;
      console) words="status enable disable restart url password logs --generate" ;;
      n8n)     words="status enable disable connect disconnect test workflow credentials backup reset-owner logs --level --groups --srcip import file" ;;
      suricata) words="status enable disable alerts test update-rules logs -n --since" ;;
      zeek)    words="status enable disable show notices top test logs hosts ports dns conn dns http ssl ssh notice weird -n" ;;
      tools)   words="status apply enable disable update-rules n8n grafana portainer suricata zeek" ;;
      soc)     words="status wazuh elk both" ;;
      elk)     words="status indices search data-views retention beats-config beats-ca es explain reset-password logs -n --index" ;;
      indexers) words="status 1 3 abort cleanup --dry-run --no-backup" ;;
      node-type) words="status single multi --dry-run --no-backup --indexers" ;;
      reminders) words="list done" ;;
      ai-context) words="--print" ;;
      backup)  words="run list register restore-snapshot restore-es restore-manager restore-config --rename --indices --kibana" ;;
      retention) words="status show apply purge --older-than --agent --rule-id --sca --query --index --dry-run --compact" ;;
      volumes) words="ls backup restore rm prune all --stop --out" ;;
      reset)   words="containers data full purge" ;;
      daemon)  words="install uninstall status logs" ;;
      doctor)  words="--fix" ;;
      scale)   words="1 2 3" ;;
      info)    words="--show-secrets" ;;
      indexer|api) words="GET PUT POST DELETE" ;;
      completion) words="install" ;;
    esac
  fi
  COMPREPLY=($(compgen -W "$words" -- "$cur"))
}
complete -F _vexor vexor ./vexor
EOF
}
suggest_command() {            # suggest_command <typed>: " - did you mean: a, b?" from the completion's command list
  local m
  m="$(completion_script | sed -n 's/^    words="\([^"]*\)".*/\1/p' | head -n 1 \
       | python3 -I -c "import difflib, sys; print(', '.join(difflib.get_close_matches(sys.argv[1], sys.stdin.read().split(), 3, 0.6)))" "$1" 2>/dev/null)"
  [ -n "$m" ] && printf ' - did you mean: %s?' "$m"
  return 0
}
cmd_completion() {
  if [ "${1:-}" = install ]; then completion_script > /etc/bash_completion.d/vexor && ok "installed - open a new shell"
  else completion_script; fi
}

# ============================================================== project name: wazuh -> vexor (vexor migrate)
# Docker Compose reads COMPOSE_PROJECT_NAME from .env; project() is the only place vexor takes it from.
# Before 2.0 the project was named "wazuh" (containers wazuh-n8n-1, volumes wazuh_n8n-data, network
# wazuh_default). Such installs keep that name until `vexor migrate` copies their volumes to vexor_*.
LEGACY_PROJECT="wazuh"
MIGRATE_MARK=".vexor-migrate-partial"          # inside a target volume while its copy is not verified
MIGRATED_FROM_FILE="$ROOT/.state/migrated-from"
project_target() { echo "${VEXOR_MIGRATE_TO:-vexor}"; }      # VEXOR_MIGRATE_TO: for tests
project_volumes_of() { docker volume ls -q --filter "label=com.docker.compose.project=$1" 2>/dev/null | sort; }
compose_volume_keys() {        # top-level volume names of the compose files
  local f; for f in "$ROOT/docker-compose.yml" "$TOOLS_COMPOSE" "$ELK_COMPOSE"; do
    [ -f "$f" ] && awk '/^volumes:/ {v=1; next} /^[^ #]/ {v=0} v && /^  [A-Za-z0-9_.-]+:/ {sub(":.*", "", $1); print $1}' "$f"
  done | sort -u
}
legacy_project_detect() {      # true when a "wazuh" project of THIS checkout exists (containers or volumes)
  local p="${1:-$LEGACY_PROJECT}" ids wd mine=0 other=0 k
  ids="$(docker ps -aq --filter "label=com.docker.compose.project=$p" 2>/dev/null)"
  if [ -n "$ids" ]; then
    while read -r wd; do
      if [ "$(readlink -f "$wd" 2>/dev/null || echo "$wd")" = "$ROOT" ]; then mine=1; else other=1; fi
    done < <(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' $ids 2>/dev/null)
  fi
  [ "$mine" = 1 ] && return 0
  [ "$other" = 1 ] && return 1             # that project belongs to another checkout
  for k in $(compose_volume_keys); do      # containers removed (down), data kept
    [ "$(docker volume inspect -f '{{index .Labels "com.docker.compose.project"}}' "${p}_$k" 2>/dev/null)" = "$p" ] && return 0
  done
  return 1
}
project_resolve() {            # .env without COMPOSE_PROJECT_NAME: keep "wazuh" for an old stack, else vexor
  [ -f "$ENV_FILE" ] && ! env_has COMPOSE_PROJECT_NAME || return 0
  docker_ok || return 0                    # decided once docker answers (compose cannot run before that anyway)
  if legacy_project_detect; then
    env_set COMPOSE_PROJECT_NAME "$LEGACY_PROJECT"
    warn "existing Docker project '$LEGACY_PROJECT' kept in .env - rename it with: vexor migrate"
  else env_set COMPOSE_PROJECT_NAME "$(project_target)"; fi
}
project_install_env() {        # cmd_install: a new .env from .env.example says vexor; keep an old stack's name
  docker_ok && legacy_project_detect || return 0
  env_set COMPOSE_PROJECT_NAME "$LEGACY_PROJECT"; say "existing Docker project '$LEGACY_PROJECT' found and kept (rename it with: vexor migrate)"
}
project_is_legacy() { [ "$(project)" = "$LEGACY_PROJECT" ] && [ "$(project_target)" != "$LEGACY_PROJECT" ]; }
migrate_leftovers() {          # old volumes still there after a migrate
  local from; from="$(cat "$MIGRATED_FROM_FILE" 2>/dev/null)"
  [ -n "$from" ] && [ "$from" != "$(project)" ] || return 0
  project_volumes_of "$from"
}
mig_vol_key() { docker volume inspect -f '{{index .Labels "com.docker.compose.volume"}}' "$1" 2>/dev/null; }
mig_vol_sig() {                # md5 of a listing of every entry (path type size mode owner; no dir sizes) + entry count
  docker run --rm -v "$1:/v:ro" "$ALPINE_IMAGE" sh -c \
    "cd /v && { find . ! -type d ! -path './$MIGRATE_MARK' -exec stat -c '%n|%F|%s|%a|%u|%g' {} +; find . -type d -exec stat -c '%n|%F|%a|%u|%g' {} +; } | sort | md5sum && find . ! -path './$MIGRATE_MARK' | wc -l" \
    2>/dev/null | tr -s ' \n' ' '
}
mig_vol_kb() { docker run --rm -v "$1:/v:ro" "$ALPINE_IMAGE" du -sk /v 2>/dev/null | awk '{print $1}'; }
mig_vol_free_kb() { docker run --rm -v "$1:/v:ro" "$ALPINE_IMAGE" df -Pk /v 2>/dev/null | awk 'NR==2 {print $4}'; }
mig_vol_state() {              # mig_vol_state <volume>: none | empty | partial | data
  docker volume inspect "$1" >/dev/null 2>&1 || { echo none; return; }
  docker run --rm -v "$1:/v:ro" "$ALPINE_IMAGE" sh -c \
    "if [ -e '/v/$MIGRATE_MARK' ]; then echo partial; elif [ -z \"\$(ls -A /v)\" ]; then echo empty; else echo data; fi" 2>/dev/null || echo none
}
mig_vol_verified() { local a b; a="$(mig_vol_sig "$1")"; b="$(mig_vol_sig "$2")"; [ -n "$a" ] && [ "$a" = "$b" ]; }
mig_target() { echo "$3${1#"$2"}"; }   # mig_target <volume> <from> <to>: wazuh_n8n-data -> vexor_n8n-data
migrate_copy_volume() {        # migrate_copy_volume <from-volume> <to-volume> <to-project>
  local src="$1" dst="$2" to="$3" key ver
  key="$(mig_vol_key "$src")"; ver="$(docker volume inspect -f '{{index .Labels "com.docker.compose.version"}}' "$src" 2>/dev/null)"
  case "$(mig_vol_state "$dst")" in
    data)    if mig_vol_verified "$src" "$dst"; then ok "$dst already copied"; return 0; fi
             bad "$dst exists with other data - not overwritten (remove it yourself if it is not needed)"; return 1 ;;
    none)    docker volume create --label "com.docker.compose.project=$to" --label "com.docker.compose.volume=$key" \
               ${ver:+--label "com.docker.compose.version=$ver"} "$dst" >/dev/null || { bad "could not create $dst"; return 1; } ;;
    partial) say "$dst: an earlier copy did not finish - copying again" ;;
  esac
  docker run --rm -v "$src:/from:ro" -v "$dst:/to" "$ALPINE_IMAGE" sh -c \
    "touch '/to/$MIGRATE_MARK' && find /to -mindepth 1 -maxdepth 1 ! -name '$MIGRATE_MARK' -exec rm -rf {} + && cp -a /from/. /to/" \
    || { bad "copy $src -> $dst failed"; return 1; }
  mig_vol_verified "$src" "$dst" || { bad "$dst differs from $src after the copy"; return 1; }
  docker run --rm -v "$src:/from:ro" -v "$dst:/to" "$ALPINE_IMAGE" sh -c "rm -f '/to/$MIGRATE_MARK' && touch -r /from /to" || return 1
  ok "$src -> $dst ($(mig_vol_kb "$dst") KB, verified)"
}
migrate_copy_volumes() {       # migrate_copy_volumes <from> <to>: every volume of project <from>; 2 = not enough disk
  local from="$1" to="$2" v c need=0 kb free n=0 vols
  vols="$(project_volumes_of "$from")"
  [ -n "$vols" ] || { ok "project $from has no volumes"; return 0; }
  for v in $vols; do
    for c in $(vol_users "$v"); do
      [ "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$c" 2>/dev/null)" = "$from" ] \
        || { bad "$v is used by container $c, which is not part of project $from"; return 1; }
    done
    [ "$(mig_vol_state "$(mig_target "$v" "$from" "$to")")" = data ] && continue
    kb="$(mig_vol_kb "$v")"; need=$(( need + ${kb:-0} ))
  done
  free="$(mig_vol_free_kb "$(head -1 <<<"$vols")")"
  if [ $(( need + need / 10 + 262144 )) -gt "${free:-0}" ]; then
    bad "not enough free disk for the copy: need $(( need / 1024 )) MB + 10% + 256 MB, free $(( ${free:-0} / 1024 )) MB"
    hint "free space (see: vexor volumes ls), then run vexor migrate again"
    return 2
  fi
  say "copying $(( need / 1024 )) MB ($(( ${free:-0} / 1024 )) MB free)"
  for v in $vols; do
    migrate_copy_volume "$v" "$(mig_target "$v" "$from" "$to")" "$to" || return 1; n=$((n + 1))
  done
  ok "$n volume(s) copied to project $to"
}
migrate_remove_old() {         # migrate_remove_old <from> <to>: old volumes with a verified copy, after asking
  local from="$1" to="$2" v t rm=() keep=()
  for v in $(project_volumes_of "$from"); do
    t="$(mig_target "$v" "$from" "$to")"
    if [ -z "$(vol_users "$v")" ] && [[ "$(mig_vol_state "$t")" =~ ^(data|empty)$ ]] && mig_vol_verified "$v" "$t"; then rm+=("$v")
    else keep+=("$v"); fi
  done
  [ ${#keep[@]} -gt 0 ] && warn "kept ${#keep[@]} old volume(s) that are in use or differ from their copy: ${keep[*]}"
  if [ ${#rm[@]} -eq 0 ]; then [ ${#keep[@]} -eq 0 ] && rm -f "$MIGRATED_FROM_FILE"; return 0; fi
  say "${#rm[@]} old volume(s) of project $from match their copy in project $to"
  # right after the switch (3rd arg "first") --yes does not delete them: only a person at a terminal, or a later
  # "vexor migrate --yes" once the stack has been checked
  if { [ "${3:-}" != first ] && [ "$ASSUME_YES" = 1 ]; } \
     || { [ -t 0 ] && [ "$ASSUME_YES" != 1 ] && confirm "Remove the old '$from' volumes now (keep them if you want to check the stack first)?"; }; then
    docker volume rm "${rm[@]}" >/dev/null && ok "removed ${#rm[@]} old volume(s)"
    [ ${#keep[@]} -eq 0 ] && rm -f "$MIGRATED_FROM_FILE"
  else
    say "old volumes kept - remove them later with: vexor migrate --yes"
  fi
  return 0
}
shuffle_images() {             # images of the old Shuffle Wazuh app (Shuffle was replaced by n8n in 1.2.0)
  docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
    | grep -iE '^((registry\.hub\.docker\.com|docker\.io)/)?frikky/shuffle:.*wazuh' || true
}
migrate_shuffle_images() {
  local i id rm=()
  for i in $(shuffle_images); do
    id="$(docker image inspect -f '{{.Id}}' "$i" 2>/dev/null)" || continue
    if docker ps -aq --filter "ancestor=$id" | has .; then say "kept $i (used by a container)"; else rm+=("$i"); fi
  done
  [ ${#rm[@]} -gt 0 ] || { ok "no unused Shuffle Wazuh app images"; return 0; }
  say "old Shuffle Wazuh app image(s), unused since n8n replaced Shuffle:"; printf '    %s\n' "${rm[@]}"
  if [ "$ASSUME_YES" = 1 ] || { [ -t 0 ] && confirm "Remove them?"; }; then
    docker rmi "${rm[@]}" >/dev/null && ok "removed ${#rm[@]} Shuffle image(s)"
  else say "kept - remove them later with: vexor migrate --yes"; fi
}
cmd_migrate() {
  case "${1:-}" in ""|--yes|-y) ;; *) die "usage: vexor migrate [--yes]" ;; esac
  [ -f "$ENV_FILE" ] || die ".env not found - nothing to migrate (new installs use project $(project_target))"
  docker_ok || die "Docker daemon is not running"
  local from to was=0 rc
  from="$(project)"; to="$(project_target)"
  hdr "Docker project name"
  if [ "$from" = "$to" ]; then
    ok "project is already '$to'"
    if migrate_leftovers | has .; then take_lock; migrate_remove_old "$(cat "$MIGRATED_FROM_FILE")" "$to"; fi
  else
    say "Renames project '$from' to '$to': stops the stack, copies every ${from}_* volume to ${to}_*,"
    say "removes the old containers and network, then starts the stack as '$to'."
    say "The old volumes stay until their copies are verified and you confirm."
    confirm "Migrate now?" || die "Aborted"
    take_lock
    running_services | has . && was=1
    if [ "$was" = 1 ]; then
      hdr "Stopping the stack"; mkdir -p "$STATE_DIR"; touch "$STATE_DIR/stopped"
      dc_all stop >/dev/null 2>&1; ok "stopped"
    fi
    hdr "Copying volumes"
    migrate_copy_volumes "$from" "$to"; rc=$?
    if [ "$rc" != 0 ]; then
      if [ "$was" = 1 ]; then rm -f "$STATE_DIR/stopped"; dc_all start >/dev/null 2>&1 && say "stack started again as '$from'"; fi
      die "migration stopped - the project is still '$from', its volumes are untouched"
    fi
    hdr "Switching to '$to'"
    dc_all down --remove-orphans >/dev/null 2>&1 && ok "old containers and network of '$from' removed (volumes kept)"
    env_set COMPOSE_PROJECT_NAME "$to"; mkdir -p "$STATE_DIR"; echo "$from" > "$MIGRATED_FROM_FILE"
    ok "COMPOSE_PROJECT_NAME=$to in .env"
    if [ "$was" = 1 ]; then
      hdr "Starting the stack as '$to'"; rm -f "$STATE_DIR/stopped"
      QUIET=1 cmd_start || warn "start reported a problem - see: vexor doctor"
    else say "the stack was not running - start it with: vexor start"; fi
    hdr "Old volumes"
    migrate_remove_old "$from" "$to" first
  fi
  hdr "Old Shuffle images"
  migrate_shuffle_images
}

