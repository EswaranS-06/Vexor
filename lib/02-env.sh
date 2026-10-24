# shellcheck shell=bash
# vexor lib/02-env.sh - .env helpers (env_get/env_set/env_def, defaults, legacy keys)
# Sourced by ./vexor in a fixed order (see the loader there); not executable on its own.
# ============================================================== .env helpers
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- \
    | sed -E 's/[[:space:]]+#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//; s/^"(.*)"$/\1/' || true
}
env_def() { local v; v="$(env_get "$1")"; echo "${v:-$2}"; }
env_has() { grep -qE "^$1=" "$ENV_FILE" 2>/dev/null; }
env_set() {                    # keeps any trailing inline comment
  python3 -I - "$ENV_FILE" "$1" "$2" <<'PY'
import re, sys
path, key, val = sys.argv[1:4]
lines = open(path).read().rstrip("\n").split("\n")
hits = [i for i, line in enumerate(lines) if line.startswith(key + "=")]
if hits:
    i = hits[-1]                       # docker compose uses the last definition
    m = re.match(r"^[^=]*=[^#]*?(\s+#.*)?$", lines[i])
    comment = (m.group(1) or "") if m else ""
    lines[i] = f"{key}={val}{comment}"
    for j in hits[:-1]:
        lines[j] = "# duplicate, overridden below: " + lines[j]
else:
    lines.append(f"{key}={val}")
open(path, "w").write("\n".join(lines) + "\n")
PY
}
env_unset() {
  python3 -I - "$ENV_FILE" "$1" <<'PY'
import sys
path, key = sys.argv[1:3]
lines = [l for l in open(path).read().split("\n") if not l.startswith(key + "=")]
open(path, "w").write("\n".join(lines).rstrip("\n") + "\n")
PY
}
env_dupes() { grep -oE '^[A-Z_][A-Z0-9_]*=' "$ENV_FILE" 2>/dev/null | sort | uniq -d | tr -d '=' | tr '\n' ' '; }
env_dedupe() {                 # comment out earlier definitions of keys that appear twice
  python3 -I - "$ENV_FILE" <<'PY'
import sys
path = sys.argv[1]
lines = open(path).read().rstrip("\n").split("\n")
last = {}
for i, l in enumerate(lines):
    if "=" in l and not l.lstrip().startswith("#"):
        last[l.split("=", 1)[0]] = i
for i, l in enumerate(lines):
    if "=" in l and not l.lstrip().startswith("#") and last[l.split("=", 1)[0]] != i:
        lines[i] = "# duplicate, overridden below: " + l
open(path, "w").write("\n".join(lines) + "\n")
PY
}
env_fix_empty_comments() {     # `KEY=   # text` -> `# text` + `KEY=` (compose would use "# text" as the value)
  python3 -I - "$ENV_FILE" <<'PY'
import re, sys
path = sys.argv[1]
src = open(path).read().split("\n"); out = []
for l in src:
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=\s+#\s?(.*)$", l)
    if m:
        out += [f"# {m.group(1)}: {m.group(2)}", f"{m.group(1)}="]
    else:
        out.append(l)
if out != src:
    open(path, "w").write("\n".join(out))
    print("fixed")
PY
}
env_drop_legacy() {            # settings of removed features (Shuffle was replaced by n8n in 1.2.0)
  grep -q '^SHUFFLE_' "$ENV_FILE" 2>/dev/null || return 0
  sed -i '/^SHUFFLE_/d' "$ENV_FILE"; say "removed the old SHUFFLE_* settings from .env (Shuffle was replaced by n8n)"
}
ensure_env_defaults() {        # adds settings introduced by vexor to older .env files
  local added=0 line key
  while IFS= read -r line; do
    key="${line%%=*}"
    env_has "$key" && continue
    [ "$added" = 0 ] && printf '\n# ---- Added by vexor (edit freely, then: vexor config apply) ----\n' >> "$ENV_FILE"
    printf '%s\n' "$line" >> "$ENV_FILE"; added=1
  done <<'EOF'
PUBLIC_HOST=                   # IP or DNS name clients use for this server (empty = detected each time vexor runs)
BIND_IP=0.0.0.0                # address the published ports listen on; 0.0.0.0 = all interfaces
CERT_EXTRA_SANS=               # extra names/IPs for the dashboard certificate, comma separated
CERT_DAYS=397                  # dashboard cert validity in days (browsers reject more than 398)
PROXY_CERT_MODE=default        # default | local | custom | letsencrypt  (managed by: vexor cert ...)
LE_DOMAIN=                     # Let's Encrypt domain (set by: vexor cert letsencrypt)
LE_EMAIL=
AGENT_ENROLL_PASSWORD=         # set by: vexor agents password on
DISK_WARN_PCT=85               # doctor/watchdog warn above this disk usage (indexer stops allocating at 85%)
DISK_FAIL_PCT=95               # doctor fails above this disk usage on any disk Docker uses (indexers go read-only)
DISK_WARN_FREE_GB=15           # install warns when a disk Docker uses has less free space than this
DISK_MIN_FREE_GB=5             # install refuses below this free space (override: vexor install --force)
WAZUH_SCA=false                # true = Security Configuration Assessment scans on every manager and agent (data.sca alerts); off by default
WAZUH_VULN_DETECTION=false     # true = Wazuh vulnerability detection in every manager (its CVE feed needs about 13 GB of disk per manager)
WATCHDOG_AUTOHEAL=yes          # watchdog restarts stopped containers / clears read-only index blocks
BACKUP_TIME=01:30              # daily backup time (systemd timer, vexor daemon install)
MAINT_TIME=02:15               # daily maintenance time: log pruning, retention, cert renewal
INDEXER_COUNT=3                # 3 or 1 - change ONLY with: vexor indexers 1|3 (moves the data safely)
INDEXER_HOST_PORT=9200         # host port of the indexer API (bound to INDEXER_BIND)
INDEXER_MOVE_TIMEOUT=3600      # seconds to wait for shards to move when changing the indexer count
HEALTH_INTERVAL=1h             # how often the health timer runs doctor --fix (systemd span: 30min, 1h, 6h)
CLEANUP_REMIND_DAYS=3          # remind to delete old indexer volumes this many days after: vexor indexers 1
NODE_TYPE=multi                # multi | single - switch with: vexor node-type single|multi (agents, alerts, settings kept)
N8N=false                      # optional tools: true = start it (vexor tools apply / start / config apply)
GRAFANA=false
PORTAINER=false
SURICATA=false
ZEEK=false
N8N_PORT=55678                 # web tool ports (50000-59999), HTTPS through nginx with the dashboard certificate
GRAFANA_PORT=53000
PORTAINER_PORT=59443
N8N_IMAGE=n8nio/n8n:2.40.0
GRAFANA_IMAGE=grafana/grafana-oss:13.0.2
PORTAINER_IMAGE=portainer/portainer-ce:2.45.1
SURICATA_IMAGE=jasonish/suricata:8.0.5
ZEEK_IMAGE=zeek/zeek:8.2.2
SNIFF_INTERFACE=               # interface Suricata/Zeek listen on (empty = interface of the default route)
ZEEK_WAZUH_LOGS=notice,weird,dns,http,ssl,ssh   # Zeek logs the master reads (conn is very large - add it on purpose)
TOOLS_LOG_RETENTION_DAYS=7     # rotated Suricata/Zeek logs older than this are deleted
GRAFANA_ADMIN_PASSWORD=CHANGE_ME     # generated when GRAFANA=true (grafana login: admin)
GRAFANA_INDEXER_PASSWORD=CHANGE_ME   # read-only indexer user "grafana" used by the datasource
PORTAINER_ADMIN_PASSWORD=CHANGE_ME   # portainer login: admin (applied on its first start)
N8N_ENCRYPTION_KEY=CHANGE_ME         # encrypts n8n credentials - keep it, back it up
N8N_EXTRA_HOOKS=                     # more custom-n8n blocks: url|level|groups;... (set by: vexor wazuh integrations raw put)
N8N_ALERT_LEVEL=7                    # alerts with this level or higher go to n8n (vexor n8n connect)
N8N_HOOK_URL=
N8N_ALERT_GROUPS=
N8N_HOOK_TOKEN=
WAZUH_N8N_USER=vexor-n8n
SOC=wazuh                      # wazuh | elk | both  - switch with: vexor soc <value>
LOGSTASH_BEATS_TLS=false       # true = TLS on the Beats input (vexor elk beats-config shows the sender settings)
N8N_NOTIFY_URL=
N8N_ABUSEIPDB_KEY=
N8N_AUTO_BLOCK=off             # approve = critical alerts with a public source IP ask in chat, then firewall-drop on the agent
ENROLL_PASSWORD_ON_INSTALL=no  # yes = fresh installs turn on the agent enrollment password (or later: vexor agents password on)
NOTIFY_ON=fail                 # health alerts off the host: fail | warn | off (vexor notify)
NOTIFY_URL=
NOTIFY_REPEAT_HOURS=6          # re-send a problem that persists
CONSOLE=true                   # Vexor Console web UI (vexor console enable|disable)
CONSOLE_PORT=50443             # console port (50000-59999), HTTPS with the dashboard certificate
CONSOLE_BIND=                  # address the console listens on (empty = BIND_IP)
CONSOLE_USER=admin
CONSOLE_PASSWORD=CHANGE_ME     # generated when the console starts (vexor console password)
ROUTES_HTTPS_PORT=443          # proxy routes (vexor proxy): HTTPS port for named hosts, published only while a route exists
ROUTES_HTTP_PORT=80            # proxy routes: HTTP port (ACME http-01 challenges + redirect to https)
ELK_VERSION=9.5.4              # Elasticsearch / Logstash / Kibana version
ELK_HEAP=1g                    # Elasticsearch JVM heap
LOGSTASH_HEAP=512m
KIBANA_PORT=55601              # https://PUBLIC_HOST:KIBANA_PORT through nginx
ES_PORT=59200                  # Elasticsearch API on ES_BIND (host only by default)
ES_BIND=127.0.0.1
LOGSTASH_BEATS_PORT=55044      # Beats / Elastic Agent -> Logstash
RETENTION_DAYS=30              # Wazuh alerts and ELK events older than this are deleted (0 = keep forever)
ELK_RETENTION_DAYS=            # optional ELK-only override of RETENTION_DAYS (empty = RETENTION_DAYS)
ELASTIC_PASSWORD=CHANGE_ME           # Kibana / Elasticsearch login "elastic" (applied on the FIRST start only)
KIBANA_SYSTEM_PASSWORD=CHANGE_ME     # internal Kibana -> Elasticsearch user
LOGSTASH_ES_PASSWORD=CHANGE_ME       # Logstash writer user vexor_logstash
KIBANA_ENCRYPTION_KEY=CHANGE_ME      # Kibana saved-objects encryption key - keep it
EOF
  [ "$added" = 1 ] && say "Added new vexor settings to .env"
  env_fix_empty_comments >/dev/null
  return 0
}

