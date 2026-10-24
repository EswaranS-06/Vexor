# shellcheck shell=bash
# vexor lib/20-main.sh - help and main (argument parsing + command dispatch)
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== help / main
cmd_help() {
  cat <<EOF
${C_BD}vexor${C_0} $VEXOR_VERSION - Vexor SOC stack manager: Wazuh, ELK, n8n, Suricata, Zeek     ($ROOT)
Layout: $(layout_desc)

${C_BD}Setup${C_0}
  install [--fresh] [--force]    first-time setup: kernel, passwords, certificates, start (safe to re-run);
                                 asks reuse/start clean when a setup exists, --fresh starts clean (backups kept);
                                 --force installs although a disk is nearly full
  uninstall [--keep-data] [--images] [--yes]
                                 remove this project's containers, network, volumes, generated files and
                                 systemd units (plan + confirm first); --keep-data keeps volumes and files
  info [--show-secrets]          dashboard URL, login, agent ports, certificate mode
  config show|get|set|edit|validate|apply     view / change .env settings, apply them
  plan [KEY=VALUE ..] [--json]   what an apply would change: settings, containers recreated/created/removed,
                                 nginx, downtime - without changing anything (config apply prints it first)

${C_BD}Run${C_0} (everything SOC and the tool flags in .env enable)
  start [svc..]                  start the stack (or services) and wait until it is ready
  stop [svc..]                   stop containers (the watchdog leaves a stopped stack alone)
  restart [svc..]                restart everything or the given services
  down                           remove containers + network (volumes/data kept)
  wait-ready [--timeout S] [--json] [svc..]   wait until services are running, healthy and answering (exit 1 + list on timeout)
  scale <1|2|3>                  number of worker managers (multi); nginx balancer updated
  status                         containers + indexer/manager cluster, agents, dashboard, disk

${C_BD}Console${C_0} (web UI - CONSOLE=true, https://PUBLIC_HOST:CONSOLE_PORT)
  console [status] | url         is it up, where
  console enable | disable       start / stop the vexor-console service
  console password [--generate]  show / rotate the login (user CONSOLE_USER)
  console restart | logs [N]     restart it / its journal
  json state | volumes           machine-readable state (what the console reads)

${C_BD}SOC stack${C_0} (SOC in .env: wazuh | elk | both)
  soc [status]                   which stacks run, Kibana / Beats endpoints
  soc wazuh | elk | both         switch: wazuh = Wazuh only, elk = Elasticsearch + Logstash + Kibana,
                                 both = Wazuh + ELK with every Wazuh alert copied into Elasticsearch

${C_BD}Wazuh${C_0} (SOC=wazuh|both)
  wazuh [status]                 indexer / manager cluster / API details
  wazuh alerts [-n N] [--level N] [--grep TEXT]   newest alerts of every manager
  wazuh logtest ["line"] [--format F] [--location L] [--json]
                                 run one line through the master's decoders and rules (no line: interactive)
  wazuh rules|decoders ls|show|put|rm|reset|history|restore|templates [--json]
                                 custom files in config/wazuh_custom: put <name> --from <path|-> is checked by Wazuh
                                 (wazuh-analysisd -t) and rolled back when refused, then loaded without a restart;
                                 built-in files (NNNN-...xml) can be edited too (the shipped one is excluded), reset <name>
                                 brings the shipped file back
  wazuh lists ls|show|put|rm|reset|history|restore | add <name> <key>[:<value>] | del <name> <key>
                                 CDB lists; the <list> line in ossec.conf follows (the managers are recreated);
                                 built-in lists (audit-keys, amazon/aws-eventnames ...) are edited in place, reset undoes it
  wazuh integrations ls | add|edit <name> [--hook-url URL] [--api-key K|--api-key-file F] [--level N] [--group G]
                                 [--rule-id IDS] | rm <name> | test <name>   (slack pagerduty virustotal shuffle maltiverse custom-<id>;
                                 custom-n8n = vexor n8n connect: --hook-url is the webhook path or URL, no key needed)
  wazuh integrations raw show | put --from <path|->     the managed integrations as XML, edited by hand
  wazuh config ls | set <key> <value> [<key> <value> ..] | custom show | custom put --from <f> [--scope master|all] | custom rm
                                 curated ossec.conf settings / a raw XML block; checked by Wazuh first, managers recreated
  wazuh detection status [--json]  custom file counts, last change, last error

${C_BD}ELK${C_0} (SOC=elk|both)
  elk [status]                   Elasticsearch health, Kibana, events in the last hour
  elk indices | search [query] [-n N] [--index P]   vexor-* indices | Lucene search, newest first
  elk data-views | retention     re-create Kibana data views | re-apply ILM retention (ELK_RETENTION_DAYS)
  elk beats-config | beats-ca    filebeat.yml for other machines | the CA they trust (LOGSTASH_BEATS_TLS=true)
  elk es <METHOD> <path> [json]  raw Elasticsearch API      e.g. vexor elk es GET /_cat/health?v
  elk explain | reset-password   shard allocation explain | new "elastic" password (+ .env)

${C_BD}n8n${C_0} (automation / SOAR - N8N=true)
  n8n [status]                   n8n, owner account, alert forwarding, webhook, credentials
  n8n enable | disable           start / remove n8n (data kept in its volume)
  n8n connect [path|url] [--level N] [--groups G]
                                 send alerts (level >= N, default 7) to an n8n webhook: Wazuh on every
                                 manager, or Logstash (Suricata/Zeek) with SOC=elk. Default path vexor-alerts
  n8n workflow [import|file]     import + publish the "Vexor - SOC alerts" starter (routes by severity)
  n8n credentials                Wazuh API user (agents, active response) + Elasticsearch read user for n8n
  n8n test [--level N] [--srcip IP]
                                 send a fake alert (default level 12) through the published workflow and show
                                 which steps ran; reads n8n executions for up to 40 s
  n8n disconnect | backup [dir] | reset-owner | logs

${C_BD}Suricata${C_0} (network IDS - SURICATA=true)
  suricata [status]              signatures, eve.json, alerts in 24 h, top signatures, where alerts go
  suricata alerts [-n N] [--since 1h]   newest alerts
  suricata test                  real test traffic (sid 2100498) -> Suricata -> Wazuh / Elasticsearch
  suricata update-rules | enable | disable | logs

${C_BD}Zeek${C_0} (network logs - ZEEK=true)
  zeek [status]                  log files, size, freshness, which go to Wazuh / ELK
  zeek show <log> [-n N] | notices   readable conn/dns/http/ssl/ssh/notice/weird lines
  zeek top [hosts|ports|dns]     top talkers, ports, DNS names in the current log
  zeek test | enable | disable | logs

${C_BD}Other tools${C_0} (N8N / GRAFANA / PORTAINER / SURICATA / ZEEK = true|false in .env)
  tools [status]                 enabled, state, URL of every tool
  tools apply                    start enabled / remove disabled tools, wire them in (also done by start, config apply)
  tools enable|disable <tool>    set the flag in .env and apply
                                 web tools: https://PUBLIC_HOST:<NAME>_PORT through nginx; sensors sniff SNIFF_INTERFACE

${C_BD}Node type${C_0} (NODE_TYPE in .env: multi | single)
  node-type [status]             applied layout, the .env value, what is shared, an unfinished switch
  node-type single [--dry-run] [--no-backup]
                                 -> 1 manager, 1 indexer, dashboard, nginx in front: data moved to wazuh1,
                                    workers removed (volumes kept), agents keep their keys and the same address
  node-type multi [--indexers 1|3] [--dry-run] [--no-backup]
                                 -> master + WORKER_COUNT workers, 3 indexers (default), nginx balances them
                                 Re-running a switch resumes it. Editing NODE_TYPE in .env and running
                                 start / restart / config apply does the same switch (asks first).
  health                         detailed indexer / manager / API state

${C_BD}Troubleshoot${C_0}
  doctor [--fix]                 ~60 checks (Wazuh, ELK, tools, n8n) with hints; --fix repairs what is safe
  logs [svc..] [-f] [-n N] [--since 10m]       container logs
  logs ossec|api|cluster|alerts [node] [-f]    Wazuh log files inside a manager (default master)
  logs errors [--since 1h]       recent error lines of every container
  logs size                      disk used by container and manager logs
  shell [svc]  |  exec <svc> <cmd..>           shell / command inside a container
  indexer <METHOD> <path> [json] raw indexer API     e.g. vexor indexer GET '/_cat/indices?v'
  api <METHOD> <path> [json]     raw Wazuh API       e.g. vexor api GET /agents/summary/status
  support-bundle                 diagnostics archive (secrets masked)

${C_BD}Update${C_0}
  update [check]                 current vs latest 4.x release (offers to upgrade)
  update apply [VER|latest] [--no-backup] [--force]   pull, backup, switch version, restart, verify
  update rollback                return to the version before the last upgrade
  update images                  re-pull current images (security rebuilds) + nginx
  version

${C_BD}Certificates${C_0} (dashboard on port $(env_def PROXY_PORT 8080))
  cert status                    names, issuer, expiry; internal node certificates
  cert create [name|ip ..]       local CA + certificate for this host -> no browser warning once the CA is trusted
  cert export-ca [dir]           CA file + install steps for Windows / macOS / Linux / Firefox / AD
  cert serve-ca [port]           temporary http download of the CA (default 8081)
  cert import <crt> <key> [chain]          use a certificate from your own / company CA
  cert letsencrypt <domain> [--email E] [--staging] [--dns]   public certificate
  cert renew [--force]           renew local / Let's Encrypt cert when < 30 days left
  cert use-default               back to the built-in self-signed certificate
  cert internal-regen            re-issue internal node certificates (restarts the stack)

${C_BD}Proxy routes${C_0} (names like soc.example.com through nginx on ROUTES_HTTPS_PORT / ROUTES_HTTP_PORT, default 443 / 80;
                                 published on BIND_IP only while a route exists)
  proxy ls [--json] | show <host>          routes, target, TLS mode, certificate expiry, DNS check
  proxy add <host> <target> [--tls local|letsencrypt|off] [--websocket] [--max-body SIZE]
                                 host = domain, subdomain or IPv4 address; target = a Vexor service:port
                                 (wazuh.dashboard:5601, n8n:5678, grafana:3000, kibana:5601) or [http(s)://]IP:PORT
                                 on this host (127.0.0.1 -> host.docker.internal) or the LAN; --tls local (default)
                                 issues a certificate from the local CA, letsencrypt uses http-01 on port 80
  proxy edit <host> [--target T] [--tls M] [--websocket|--no-websocket] [--max-body SIZE]
  proxy rm <host>                remove a route and its certificate
  proxy cert <host> [--renew]    issue / re-issue the route certificate (maintenance renews < 30 days)
  proxy cert-file <host> [ca|cert]         path of the route certificate or the local CA (public files only)
  proxy apply                    re-render, test with nginx -t, reload; a config nginx rejects is rolled back

${C_BD}Logins${C_0}
  login [service|container ..]   url, user and password of every login Vexor manages (all enabled ones without
                                 arguments); names like wazuh.master, kibana, grafana, elk, console work. --json

${C_BD}Security${C_0}
  passwd admin|kibanaserver|api [--generate]  change a password on the running stack (+ .env)
  agents password on [pw]|off|show            require a password for agent enrollment

${C_BD}Wazuh agents${C_0}
  agents list|summary|outdated
  agents enroll-cmd [linux|rpm|windows|macos] [--name N] [--group G]   copy-paste install commands
  agents remove <id[,id..]>
  cluster                        manager cluster nodes

${C_BD}Indexer cluster${C_0}
  indexers status                show node count, shards per node, leftovers
  indexers 1 [--dry-run] [--no-backup]   3 -> 1 indexer: backup, move all shards to wazuh1, leave the vote,
                                 switch configs, stop wazuh2/3 (volumes kept), verify, reminder to clean up
  indexers 3 [--dry-run] [--no-backup]   1 -> 3 indexers: fresh wazuh2/3 join, replica copies restored
  indexers abort | cleanup       undo an unfinished shrink | delete the old wazuh2/3 volumes

${C_BD}Health automation${C_0}
  autoheal                       doctor --fix, re-check, record result; unknown problems -> AI report + reminder
  notify [status] | test | send <level> <msg>   health alerts to NOTIFY_URL (Slack/Teams/Discord/JSON) or n8n
  ai-context [--print]           one Markdown file with architecture, settings, status, doctor, errors (masked)
                                 - paste it into any AI chat to get a diagnosis
  reminders [list] | done <id>   follow-up tasks (e.g. indexer cleanup); shown in status, doctor, SSH login
  motd                           the login summary (installed by: daemon install)

${C_BD}Data${C_0}
  backup [run]|list|register     indexer snapshot + manager state + config (keeps SNAPSHOT_RETENTION_DAYS)
  backup restore-snapshot <id> [--indices P] [--rename] | restore-manager <stamp> | restore-config <file>
  backup restore-es <es-snap-id> [--indices P] [--rename] [--kibana]   Elasticsearch (SOC=elk|both) is in every backup
  retention [status|apply]       delete Wazuh and ELK data older than RETENTION_DAYS (0 = keep forever)
  prune-logs                     delete rotated manager logs older than MANAGER_LOG_RETENTION_DAYS
  volumes ls | orphans | backup <vol|all> [--stop] [--out DIR] | restore <vol> <file> | rm <vol> | prune [--yes]
                                 orphans lists volumes no service of the current layout uses (old worker/indexer data),
                                 prune removes them after you confirm (tool data of switched-off tools is kept)
  disk [--json]                  free/used space of every filesystem Docker uses (Docker root, volumes, images, backups,
                                 this folder) and the size of Vexor's volumes and images; install/doctor check all of them
  images prune [--yes]           remove old image versions of this stack (after an upgrade); offered at the end of update
  reset [containers|data|full|purge]          interactive menu without a level
  migrate [--yes]                rename the Docker project "wazuh" (before 2.0) to "vexor": copies the volumes,
                                 verifies them, restarts; also removes unused old Shuffle Wazuh app images

${C_BD}Automation${C_0}
  daemon install|uninstall|status|logs        PATH link, completion, boot service, login message, timers:
                                 watchdog 5 min, health $(env_def HEALTH_INTERVAL 1h), backup $(env_def BACKUP_TIME 01:30), maintenance $(env_def MAINT_TIME 02:15)
  watchdog                       one self-heal pass (start missing containers, clear read-only blocks)
  maintenance                    prune logs + retention + certificate renewal + image cleanup
  completion [install]           bash completion

Options: -y/--yes (no prompts)  -q/--quiet  --no-color  --verbose (stream the full docker output; same as VEXOR_VERBOSE=1)
Service names: master worker worker2 worker3 indexer1 indexer2 indexer3 dashboard nginx | managers | indexers
               (node type single: master indexer1 dashboard)
EOF
}

is_info_cmd() {                # help/version/completion: no root needed, nothing logged (used twice in main)
  case "$1" in help|version|--version|-v|completion) return 0 ;; esac
  return 1
}

main() {
  local args=() a cmd=""
  for a in "$@"; do
    if [ -z "$cmd" ] || [[ "$cmd" != exec && "$cmd" != indexer && "$cmd" != api ]]; then
      case "$a" in
        -y|--yes)   ASSUME_YES=1; continue ;;
        -q|--quiet) QUIET=1; continue ;;
        --no-color) USE_COLOR=0; continue ;;
        --verbose)  VERBOSE=1; continue ;;
        -h|--help) [ -z "$cmd" ] && { cmd=help; continue; } ;;
      esac
    fi
    [ -z "$cmd" ] && { cmd="$a"; continue; }
    args+=("$a")
  done
  cmd="${cmd:-help}"
  setup_colors

  if ! is_info_cmd "$cmd" && [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null || die "run as root"
    exec sudo -E "$SELF" "$@"
  fi
  RUN_TMP="$(mktemp -d /tmp/vexor.XXXXXX)"; trap 'spin_stop; rm -rf "$RUN_TMP"' EXIT
  if [ -f "$ENV_FILE" ] && [ "$(id -u)" -eq 0 ] && [[ "$cmd" != help && "$cmd" != completion ]]; then
    project_resolve; ensure_env_defaults >/dev/null; env_drop_legacy >/dev/null; migrate_layout
    is_info_cmd "$cmd" || case "$cmd" in   # action history (feeds ai-context); read-only commands are not logged
      status|st|ps|health|info|urls|logs|log|motd|reminders|ai-context|indexer|ix|api|cluster|watchdog|autoheal|health-check|suricata|zeek|json|plan|login|logins|creds|disk|uninstall) ;;
      wazuh) [[ "${args[1]:-}" =~ ^(put|save|rm|remove|delete|restore|add|del|edit|set|custom)$ ]] && { mkdir -p "$STATE_DIR"; echo "$(ts) wazuh ${args[*]:0:3}" | mask_secrets >> "$HISTORY_FILE"; } ;;
      doctor|troubleshoot|check) [ "${args[0]:-}" = --fix ] && echo "$(ts) doctor --fix" >> "$HISTORY_FILE" ;;
      proxy|proxies|routes) [[ "${args[0]:-ls}" =~ ^(ls|list|status|show|cert-file)$ ]] || { mkdir -p "$STATE_DIR"; echo "$(ts) proxy ${args[*]:0:3}" >> "$HISTORY_FILE"; } ;;
      *) mkdir -p "$STATE_DIR"; echo "$(ts) $cmd ${args[0]:-} ${args[1]:-}" | mask_secrets >> "$HISTORY_FILE" ;;
    esac
  fi

  case "$cmd" in
    install|setup)         cmd_install "${args[@]}" ;;
    uninstall)             cmd_uninstall "${args[@]}" ;;
    info|urls)             cmd_info "${args[@]}" ;;
    config|conf)           cmd_config "${args[@]}" ;;
    start|up)              cmd_start "${args[@]}" ;;
    stop)                  cmd_stop "${args[@]}" ;;
    restart)               cmd_restart "${args[@]}" ;;
    down)                  cmd_down ;;
    scale)                 cmd_scale "${args[@]}" ;;
    wait-ready|wait)       cmd_wait_ready "${args[@]}" ;;
    node-type|nodetype|node_type|mode) cmd_node_type "${args[@]}" ;;
    status|st)             cmd_status ;;
    ps)                    dc_all ps ;;
    health)                cmd_health ;;
    doctor|troubleshoot|check) cmd_doctor "${args[@]}" ;;
    fix)                   cmd_doctor --fix ;;
    logs|log)              cmd_logs "${args[@]}" ;;
    shell|sh)              cmd_shell "${args[@]}" ;;
    exec)                  cmd_exec "${args[@]}" ;;
    indexer|ix)            cmd_indexer "${args[@]}" ;;
    api)                   cmd_api "${args[@]}" ;;
    support-bundle|bundle) cmd_support_bundle ;;
    update|upgrade)        cmd_update "${args[@]}" ;;
    version|--version|-v)  echo "vexor $VEXOR_VERSION  |  Wazuh $(cur_version 2>/dev/null)" ;;
    cert|certs|certificate) cmd_cert "${args[@]}" ;;
    proxy|proxies|routes)  cmd_proxy "${args[@]}" ;;
    passwd|password)       cmd_passwd "${args[@]}" ;;
    agents|agent)          cmd_agents "${args[@]}" ;;
    cluster)               cmd_cluster ;;
    wazuh)                 cmd_wazuh "${args[@]}" ;;
    n8n|soar)              cmd_n8n "${args[@]}" ;;
    suricata|ids)          cmd_suricata "${args[@]}" ;;
    zeek)                  cmd_zeek "${args[@]}" ;;
    console|ui)            cmd_console "${args[@]}" ;;
    plan)                  cmd_plan "${args[@]}" ;;
    notify)                cmd_notify "${args[@]}" ;;
    login|logins|creds)    cmd_login "${args[@]}" ;;
    json)                  cmd_json "${args[@]}" ;;
    shuffle)               die "Shuffle was replaced by n8n in vexor 1.2.0 - see: vexor n8n" ;;
    tools|tool)            cmd_tools "${args[@]}" ;;
    soc)                   cmd_soc "${args[@]}" ;;
    elk)                   cmd_elk "${args[@]}" ;;
    indexers)              cmd_indexers "${args[@]}" ;;
    autoheal|health-check) cmd_autoheal ;;
    ai-context|ai-report)  cmd_ai_context "${args[@]}" ;;
    reminders|reminder)    cmd_reminders "${args[@]}" ;;
    motd)                  cmd_motd ;;
    backup|backups)        cmd_backup "${args[@]}" ;;
    retention)             cmd_retention "${args[@]}" ;;
    prune-logs)            take_lock; prune_logs ;;
    volumes|volume|vol)    cmd_volumes "${args[@]}" ;;
    disk|disks)            cmd_disk "${args[@]}" ;;
    images|image)          cmd_images "${args[@]}" ;;
    reset)                 cmd_reset "${args[@]}" ;;
    migrate)               cmd_migrate "${args[@]}" ;;
    daemon|service)        cmd_daemon "${args[@]}" ;;
    watchdog)              cmd_watchdog ;;
    maintenance|maint)     cmd_maintenance ;;
    completion)            cmd_completion "${args[@]}" ;;
    help)                  cmd_help ;;
    *)                     die "unknown command '$cmd'$(suggest_command "$cmd") - see: vexor help" ;;
  esac
}

