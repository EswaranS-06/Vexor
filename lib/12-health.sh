# shellcheck shell=bash
# vexor lib/12-health.sh - reminders, health automation, AI context
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== reminders / health / AI context
reminder_add() {               # reminder_add <id> <days> <message> <command>
  mkdir -p "$STATE_DIR"; reminder_rm "$1"
  printf '%s\t%s\t%s\t%s\n' "$1" "$(( $(date +%s) + $2 * 86400 ))" "$3" "$4" >> "$REMINDERS_FILE"
}
reminder_rm() {
  [ -f "$REMINDERS_FILE" ] || return 0
  awk -F'\t' -v id="$1" '$1 != id' "$REMINDERS_FILE" > "$REMINDERS_FILE.tmp" && mv "$REMINDERS_FILE.tmp" "$REMINDERS_FILE"
}
reminders_due() {              # "message|command" lines that are due now
  [ -f "$REMINDERS_FILE" ] || return 0
  awk -F'\t' -v now="$(date +%s)" '$2 <= now {print $3 "|" $4}' "$REMINDERS_FILE"
}
show_due_reminders() {
  while IFS='|' read -r msg cmd; do
    [ -n "$msg" ] || continue
    warn "Reminder: $msg"; hint "$cmd"
  done < <(reminders_due)
}
cmd_reminders() {
  case "${1:-list}" in
    list|ls)
      [ -s "$REMINDERS_FILE" ] || { ok "no reminders"; return 0; }
      local id due msg cmd now d; now="$(date +%s)"
      while IFS=$'\t' read -r id due msg cmd; do
        [ -n "$id" ] || continue
        if [ "$due" -le "$now" ]; then d="DUE"; else d="$(date -d "@$due" +%F)"; fi
        printf '  %-18s %-10s %s\n      -> %s\n' "$id" "$d" "$msg" "$cmd"
      done < "$REMINDERS_FILE" ;;
    done|rm) [ -n "${2:-}" ] || die "usage: vexor reminders done <id>"; reminder_rm "$2"; ok "removed $2" ;;
    *) die "usage: vexor reminders [list] | done <id>" ;;
  esac
}
cmd_motd() {                   # shown at SSH login (installed by: vexor daemon install); no docker calls
  local h epoch status p w f age due
  due="$(reminders_due)"
  h="$(cat "$STATE_DIR/health.last" 2>/dev/null)"
  local pend=""; node_type_pending 2>/dev/null && pend="$(pending_target)"
  [ -z "$h" ] && [ -z "$due" ] && [ -z "$pend" ] && return 0
  echo
  echo "  Wazuh stack ($ROOT) - $(layout_desc)"
  [ -n "$pend" ] && echo "    NODE TYPE: .env asks for $pend, the stack runs as $(node_type) -> vexor node-type $pend"
  if [ -n "$h" ]; then
    IFS='|' read -r epoch status p w f <<<"$h"
    age=$(( ($(date +%s) - epoch) / 60 ))
    echo "    health check ${age} min ago: $status  ($p passed, $w warnings, $f failed)"
    [ "$status" = FAIL ] && echo "    -> vexor doctor      AI-ready report: vexor ai-context"
  fi
  while IFS='|' read -r msg cmd; do
    [ -n "$msg" ] && { echo "    REMINDER: $msg"; echo "    -> $cmd"; }
  done <<<"$due"
  echo
}
cmd_autoheal() {               # timer: doctor --fix, re-check, record result, report what is left
  take_lock quiet
  [ -f "$STATE_DIR/stopped" ] && exit 0
  docker_ok || { log "docker daemon not running"; exit 1; }
  grep -qE '^(INDEXER|DASHBOARD|API)_PASSWORD=CHANGE_ME' "$ENV_FILE" && exit 0
  USE_COLOR=0; setup_colors
  ( cmd_doctor --fix ) > "$RUN_TMP/doctor-fix.txt" 2>&1
  ( cmd_doctor )       > "$RUN_TMP/doctor.txt" 2>&1
  local sum p w f status
  sum="$(grep -E '[0-9]+ passed, [0-9]+ warnings, [0-9]+ failed' "$RUN_TMP/doctor.txt" | tail -1)"
  p="$(grep -oE '[0-9]+ passed' <<<"$sum" | cut -d' ' -f1)"; w="$(grep -oE '[0-9]+ warnings' <<<"$sum" | cut -d' ' -f1)"
  f="$(grep -oE '[0-9]+ failed' <<<"$sum" | cut -d' ' -f1)"
  status=OK; [ "${w:-0}" -gt 0 ] && status=WARN; [ "${f:-0}" -gt 0 ] && status=FAIL; [ -z "$sum" ] && status=FAIL
  mkdir -p "$STATE_DIR"; echo "$(date +%s)|$status|${p:-0}|${w:-0}|${f:-0}" > "$STATE_DIR/health.last"
  log "health: $status - ${p:-0} passed, ${w:-0} warnings, ${f:-0} failed"
  grep -E 'fixing:' "$RUN_TMP/doctor-fix.txt" | sed 's/^ */  auto-fix: /' | while read -r l; do log "$l"; done
  grep -E '✘' "$RUN_TMP/doctor.txt" | sed 's/^ *✘ */  still failing: /' | while read -r l; do log "$l"; done
  if [ "$status" = FAIL ]; then
    local report first; report="$(ai_context_write)"
    first="$(grep -m1 '✘' "$RUN_TMP/doctor.txt" | sed 's/^ *✘ *//')"
    reminder_add health-problem 0 "Health check $(date '+%F %H:%M') could not fix: ${first:-unknown problem}. AI report: $report" \
      "vexor doctor   |   vexor ai-context --print   (paste into any AI)"
    log "problems remain - AI-ready report written to $report"
  else
    reminder_rm health-problem
  fi
  while IFS='|' read -r msg cmd; do [ -n "$msg" ] && log "REMINDER: $msg -> $cmd"; done < <(reminders_due)
  local detail
  detail="${p:-0} passed, ${w:-0} warnings, ${f:-0} failed.
$(grep -E '✘|!' "$RUN_TMP/doctor.txt" | grep -v 'Run vexor doctor' | sed -E 's/^ *(✘|!) */- /' | head -n 8)
$(grep -E 'fixing:' "$RUN_TMP/doctor-fix.txt" | sed -E 's/^ *[^a-z]*fixing: */- repaired: /' | head -n 5)
$( [ "$status" = FAIL ] && echo "AI report: $(ls -1t "$REPORT_DIR"/ai-context-*.md 2>/dev/null | head -1)")"
  notify_health "$status" "$detail"
  return 0
}
mask_secrets() {
  sed -E 's/^([A-Z0-9_]*(PASSWORD|SECRET|TOKEN|APIKEY|_KEY)[A-Z_]*=)[^[:space:]#]+/\1***/;
          s/(password|hash|"key"|<key>|<api_key>)([":[:space:]=]*)[^<",[:space:]]+/\1\2***/Ig;
          s/ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_.-]+/***jwt***/g;
          s/webhook_[0-9a-fA-F-]{8,}/webhook_***/g'
}
ai_context_body() {
  local h port flow; h="$(public_host)"; port="$(env_def PROXY_PORT 8080)"
  if is_single; then
    flow="- Agents --TCP $(env_def AGENT_PORT 1514)--> nginx (stream) --> wazuh.master (node type single: no workers)
- Browser --HTTPS $port--> nginx --> wazuh.dashboard:5601"
  else
    flow="- Agents --TCP $(env_def AGENT_PORT 1514)--> nginx (stream, hash \$remote_addr) --> managers: wazuh.master + $(worker_count) worker(s)
- Browser --HTTPS $port--> nginx --> wazuh.dashboard:5601
- Workers sync rules/agent keys from the master over the manager cluster (port 1516, cluster key in configs)"
  fi
  cat <<EOF
# Wazuh SIEM stack - status report for troubleshooting

Generated $(date '+%F %T %Z') by vexor $VEXOR_VERSION on host $(hostname). Secrets are masked.

**Instructions for the AI reading this:** you are an expert in Wazuh 4.x, OpenSearch and Docker Compose.
Below is the full context of a self-hosted Wazuh deployment and its current state.
1. Say whether the stack is healthy.
2. For every line marked "✘" (failed) or "!" (warning), explain the most likely root cause.
3. Give exact, safe commands to fix it - prefer the \`vexor\` commands listed below, otherwise
   \`docker compose ...\` run in \`$ROOT\`. Never suggest deleting volumes without a backup step.
4. If you need more data, name the exact command to run (e.g. \`vexor logs indexer1 -n 300\`).

## Architecture and data flow
- Wazuh $(cur_version), Docker Compose project "$(project)" on ONE Linux host, directory $ROOT
- Layout: $(layout_desc). NODE_TYPE in .env: $(desired_node_type)$(node_type_pending && echo " (NOT applied yet / switch unfinished: vexor node-type $(pending_target))")
  (\`vexor node-type single|multi\` switches; master volumes, wazuh1.indexer data and dashboard volumes are shared by both layouts)
$flow
- Agents --TCP $(env_def ENROLL_PORT 1515)--> wazuh.master (enrollment / authd)$( grep -q '<use_password>yes' "$CLUSTER_DIR/wazuh_manager.conf" && echo ", password required" )
- Managers analyse events -> alerts -> filebeat (inside each manager) --> indexer cluster: $(indexer_count) node(s) ($(enabled_indexers | tr '\n' ' '))
- Dashboard --> indexer (wazuh1.indexer:9200) + Wazuh API (wazuh.master:55000)
- SOC=$(soc) (wazuh | elk | both); ELK $(soc_elk && echo "on: Elastic $(elk_version), Kibana via nginx :$(env_def KIBANA_PORT 55601), Logstash beats :$(env_def LOGSTASH_BEATS_PORT 55044)$( [ "$(soc)" = both ] && echo ', Wazuh alerts copied to vexor-wazuh-alerts-*')" || echo off)
- Optional tools enabled: $(enabled_tools | tr '\n' ' ')(web tools via nginx on their 5XXXX ports; Suricata/Zeek sniff $(sniff_iface), logs read by the master)
- Wazuh API published on host port $(api_port); indexer API on $(env_def INDEXER_BIND 127.0.0.1):$(indexer_port)
- n8n automation: $( [ -n "$(n8n_hook)" ] && echo "alerts level >= $(n8n_level) posted to $(n8n_hook) ($(soc_wazuh && echo 'Wazuh integration custom-n8n on every manager')$( [ "$(soc)" = elk ] && echo 'Logstash http output: Suricata alerts + Zeek notices'))" || echo "not connected" ); Wazuh API user for n8n: $( [ -n "$(env_get WAZUH_N8N_PASSWORD)" ] && env_def WAZUH_N8N_USER vexor-n8n || echo none )
- Dashboard certificate mode: $(cert_mode); internal TLS between all components from config/wazuh_indexer_ssl_certs
- Automation: watchdog every 5 min, health check (doctor --fix) every $(env_def HEALTH_INTERVAL 1h), daily backup $(env_def BACKUP_TIME 01:30), maintenance $(env_def MAINT_TIME 02:15) - installed: $(systemctl is-enabled "$UNIT-health.timer" 2>/dev/null || echo no)

## Management CLI (vexor)
status | doctor [--fix] | logs <svc> [-n N] | logs ossec|cluster|api <node> | logs errors --since 1h |
restart <svc> | indexer GET <path> | api GET <path> | node-type status|single|multi [--dry-run] | indexers status|1|3 |
scale <1-3> | backup | update | cert status | passwd | agents list | reminders | ai-context |
wazuh alerts | elk status|search | n8n status|test | suricata status|alerts|test | zeek status|show <log>|top
Service names: wazuh.master wazuh.worker wazuh2.worker wazuh3.worker wazuh1.indexer wazuh2.indexer wazuh3.indexer wazuh.dashboard nginx
(in node type single only wazuh.master, wazuh1.indexer and wazuh.dashboard exist)

## Settings (.env, comments removed)
\`\`\`
$(grep -vE '^\s*(#|$)' "$ENV_FILE" | sed -E 's/[[:space:]]+#.*$//')
\`\`\`

## Host
\`\`\`
$(uname -sr); $(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME"); uptime: $(uptime -p 2>/dev/null); load: $(cut -d' ' -f1-3 /proc/loadavg)
$(free -h | head -2)
$(df -h / "$(docker_root)" "$(backup_dir)" 2>/dev/null | awk '!seen[$0]++')
docker $(docker version -f '{{.Server.Version}}' 2>/dev/null), compose $(docker compose version --short 2>/dev/null), vm.max_map_count=$(sysctl -n vm.max_map_count)
\`\`\`

## Container status + summary
\`\`\`
$(cmd_status 2>&1)
\`\`\`

## Container resource use
\`\`\`
$(docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}' $(dc_all ps -q 2>/dev/null) 2>/dev/null)
\`\`\`

## Doctor (all checks)
\`\`\`
$( (cmd_doctor) 2>&1)
\`\`\`
EOF
  if [ "$(ix_code)" = 200 ]; then
    printf '\n## Indexer\n```\n'
    ix GET /_cluster/health?pretty
    ix GET '/_cat/nodes?v&h=name,node.role,cluster_manager,heap.percent,ram.percent,cpu,load_1m,disk.used_percent'
    ix GET '/_cat/allocation?v'
    ix GET '/_cat/indices?v&s=index&h=health,status,index,pri,rep,docs.count,store.size' | head -n 60
    [ "$(ix_health_field status)" != green ] && ix GET '/_cluster/allocation/explain?pretty' 2>/dev/null | head -n 60
    printf '```\n'
  fi
  if is_running wazuh.master; then
    printf '\n## Manager cluster + agents\n```\n'
    dc exec -T wazuh.master /var/ossec/bin/cluster_control -l 2>&1
    dc exec -T wazuh.master /var/ossec/bin/agent_control -l 2>&1 | head -n 40
    printf '```\n'
  fi
  printf '\n## Recent error lines per container (last 1h, max 15 each)\n'
  local svc lines
  for svc in $(dc_all ps --services 2>/dev/null); do
    lines="$(dc logs --no-log-prefix --since 1h "$svc" 2>&1 | grep -iE '\b(error|critical|fatal|exception|failed)\b' | tail -n 15 | cut -c1-300)"
    [ -n "$lines" ] && printf '\n### %s\n```\n%s\n```\n' "$svc" "$lines"
  done
  for svc in $(enabled_managers); do
    is_running "$svc" || continue
    lines="$(dc exec -T "$svc" grep -E 'ERROR|CRITICAL|WARNING' /var/ossec/logs/ossec.log 2>/dev/null | tail -n 15 | cut -c1-300)"
    [ -n "$lines" ] && printf '\n### %s ossec.log (errors/warnings)\n```\n%s\n```\n' "$svc" "$lines"
  done
  if [ -s "$HISTORY_FILE" ]; then
    printf '\n## Recent vexor actions on this host\n```\n'; tail -n 30 "$HISTORY_FILE"; printf '```\n'
  fi
  if [ -s "$REMINDERS_FILE" ]; then
    printf '\n## Open reminders\n```\n'; cut -f1,3,4 "$REMINDERS_FILE"; printf '```\n'
  fi
  printf '\n## Question\n(Describe what you noticed, e.g. "agents show never connected" or "no alerts since 10:00".)\n'
}
ai_context_write() {           # writes the report, prints its path
  local out; mkdir -p "$REPORT_DIR"; chmod 700 "$REPORT_DIR"
  out="$REPORT_DIR/ai-context-$(date +%Y%m%d-%H%M%S).md"
  ( USE_COLOR=0; setup_colors; ai_context_body ) 2>&1 | mask_secrets > "$out"
  chmod 600 "$out"
  ls -1t "$REPORT_DIR"/ai-context-*.md 2>/dev/null | tail -n +21 | xargs -r rm -f
  echo "$out"
}
cmd_ai_context() {
  local print=0; [ "${1:-}" = "--print" ] && print=1
  [ "$print" = 0 ] && hdr "Collecting the full stack context (takes ~30 s)"
  local out; out="$(ai_context_write)"
  if [ "$print" = 1 ]; then cat "$out"; return 0; fi
  ok "$out  ($(wc -c < "$out") bytes, secrets masked)"
  say "Give it to any AI:   cat $out     (copy the whole text into the chat, add your question at the end)"
  say "Or straight to your terminal: vexor ai-context --print"
}

