# Vexor

[![CI](https://github.com/EswaranS-06/Vexor/actions/workflows/ci.yml/badge.svg)](https://github.com/EswaranS-06/Vexor/actions/workflows/ci.yml)
[![Pages](https://github.com/EswaranS-06/Vexor/actions/workflows/pages.yml/badge.svg)](https://eswarans-06.github.io/Vexor/)

Vexor runs a complete Security Operations Center on one Docker host and manages it with a single command-line tool, `vexor`:

- **Wazuh** for SIEM and endpoint detection
- the **Elastic Stack (ELK)** for search and dashboards
- **n8n** for automated response
- **Suricata** for network intrusion detection
- **Zeek** for network logs

You choose what runs in `.env`, and `vexor` wires everything together: certificates, passwords, an nginx reverse proxy, alert forwarding between the stacks, retention, backups and a self-healing watchdog. When something breaks, `vexor doctor` says what and why, and repairs the problems it knows.

**Landing page:** <https://eswarans-06.github.io/Vexor/> · **Guide:** <https://eswarans-06.github.io/Vexor/guide.html> · **CLI reference:** [VEXOR.md](VEXOR.md)

---

## Contents

1. [What you get](#what-you-get)
2. [Requirements](#requirements)
3. [Quick start](#quick-start)
4. [Choosing what runs](#choosing-what-runs)
5. [How the pieces connect](#how-the-pieces-connect)
6. [The components](#the-components): [Wazuh](#wazuh) · [ELK](#elk) · [n8n](#n8n) · [Suricata](#suricata) · [Zeek](#zeek) · [Grafana and Portainer](#grafana-and-portainer) · [Vexor Console](#vexor-console)
7. [Change management](#change-management)
8. [Data, retention and backups](#data-retention-and-backups)
9. [Self-healing and troubleshooting](#self-healing-and-troubleshooting)
10. [Security](#security)
11. [CI/CD and the landing page](#cicd-and-the-landing-page)
12. [Repository layout](#repository-layout)
13. [Limitations](#limitations)

---

## What you get

| Component | Version | Role in the SOC | Main commands |
|---|---|---|---|
| **Wazuh** | 4.14 | Agents on your endpoints, detection rules, alerts, active response. Single node or a master with 1–3 workers and 3 indexers. | `vexor wazuh`, `vexor agents` |
| **ELK** | Elastic 9.5 | Elasticsearch stores and searches everything; Kibana shows it; Logstash takes in Beats, Elastic Agent, sensor logs and (with `SOC=both`) every Wazuh alert. | `vexor elk` |
| **n8n** | 2.40 | Receives alerts above a level you choose and runs your playbooks: notify, open a ticket, isolate a host through the Wazuh API, query Elasticsearch. | `vexor n8n` |
| **Suricata** | 8.0 | Inspects traffic on a network interface with the ET Open rules (53,000+). Alerts go to Wazuh, Elasticsearch and n8n. | `vexor suricata` |
| **Zeek** | 8.2 | Writes connection, DNS, HTTP, TLS and SSH logs. Notices and failed SSH logins become Wazuh alerts; logs are searchable in Elasticsearch. | `vexor zeek` |
| Grafana, Portainer | 13.0, 2.45 | A ready-made Wazuh alerts dashboard; container management. | `vexor tools` |

Around these, `vexor` handles certificates (local CA, your own, or Let's Encrypt), password changes on a running stack, upgrades with rollback, backups and restore, index retention, a 5-minute watchdog, an hourly health check with automatic repairs, and an AI-ready diagnostic report (`vexor ai-context`).

---

## Requirements

| Resource | Needed |
|---|---|
| OS | Linux with systemd (tested on Ubuntu 24.04) |
| Docker | Docker Engine 24 or later with the Compose v2 plugin |
| RAM | `SOC=wazuh`: 8 GB (single) or 16 GB (multi). `SOC=both`: add about 4 GB. `SOC=elk`: about 6 GB. Each tool: 0.3–1 GB. |
| Disk | 100 GB or more for the Docker data root. The Wazuh vulnerability feed alone needs about 13 GB per manager; `WAZUH_VULN_DETECTION=false` turns it off. `vexor install` and `vexor doctor` check every disk Docker uses (data root, volumes, image store, backups, the checkout), not only one. |
| Packages | `python3`, `openssl`, `curl`, `ss`, `flock` (`apt install python3 openssl curl iproute2 util-linux`) |
| Ports | Wazuh: 8080, 1514, 1515, 514/udp, 55000. ELK and tools: their 5XXXX ports from `.env`. |

`vexor install` sets the kernel setting the indexers need (`vm.max_map_count=262144`).

---

## Quick start

```bash
git clone https://github.com/EswaranS-06/Vexor.git
cd Vexor
sudo ./vexor install          # creates .env, generates passwords and certificates, starts the stack
sudo ./vexor daemon install   # vexor on PATH, start at boot, watchdog, health checks, backups
vexor info --show-secrets     # URLs and logins
vexor console password        # login for the web console
vexor login                   # url, user and password of every login Vexor manages
```

On a terminal, long steps (image pulls, certificate generation, `docker compose up`) show one live progress line; `--verbose` (or `VEXOR_VERBOSE=1`) prints the full docker output instead, and CI logs get one plain line per step.

If `install` finds an earlier setup (`.env`, certificates, state or volumes), it asks whether to reuse it (the default) or start clean. `sudo ./vexor install --fresh` starts clean without asking: it deletes the old containers, volumes and generated files, and keeps backups.

To remove Vexor, run `sudo ./vexor uninstall`. It shows what it will remove and asks first. It removes only this project's containers, network, volumes, generated files and systemd units. `--keep-data` keeps the volumes and files, and `--images` also removes the images.

Open the Wazuh dashboard at `https://<host>:8080` and log in as `admin`. The first start takes 1–2 minutes. Everything below can also be done from the **Vexor Console** at `https://<host>:50443`.

Add the rest of the SOC:

```bash
vexor suricata enable          # network IDS on the default-route interface
vexor zeek enable              # network logs
vexor soc both                 # Elasticsearch + Logstash + Kibana next to Wazuh
vexor n8n enable               # then open https://<host>:55678 and create the owner account
vexor n8n connect              # alerts of level 7+ go to n8n
vexor n8n workflow             # import + publish the "Vexor - SOC alerts" starter workflow
vexor n8n test                 # fake alert through the published workflow; shows which steps ran
```

Enroll an agent and remove the browser certificate warning:

```bash
vexor agents enroll-cmd windows --name pc-01     # also: linux, rpm, macos
vexor cert create && vexor cert export-ca        # local CA certificate + how to trust it
```

`PUBLIC_HOST` is empty by default: Vexor detects the machine's address each time it runs, so the same checkout keeps working after a move or a new DHCP address. Set it in `.env` only when clients use a DNS name or a NAT address. Nothing in the checkout is tied to one machine or path.

---

## Choosing what runs

Everything is decided in `.env`. Each setting has a command that changes it safely; your agents and data stay.

| Setting | Values | Change with |
|---|---|---|
| `SOC` | `wazuh` · `elk` · `both` | `vexor soc both` |
| `NODE_TYPE` | `single` · `multi` | `vexor node-type multi` |
| `WORKER_COUNT` | `1`–`3` (multi) | `vexor scale 2` |
| `N8N`, `SURICATA`, `ZEEK`, `GRAFANA`, `PORTAINER` | `true` · `false` | `vexor <tool> enable` or `vexor tools enable <tool>` |

- **`SOC=wazuh`** (default): Wazuh only.
- **`SOC=elk`**: Elasticsearch, Logstash and Kibana only. Suricata, Zeek, Beats and Elastic Agent feed Logstash. Wazuh is stopped, but its agent keys and alerts stay in their volumes.
- **`SOC=both`**: both stacks. Logstash copies every Wazuh alert into `vexor-wazuh-alerts-*`.
- **`NODE_TYPE=single`** runs one manager and one indexer. **`multi`** runs a master, `WORKER_COUNT` workers and three indexers. Switching moves every shard first. `--dry-run` shows the plan.

---

## How the pieces connect

```
 Endpoints (Wazuh agents) ─ 1514/1515 ─┐        ┌───────────────────── one Docker host ─────────────────────┐
 Browsers ── 8080 / 5XXXX HTTPS ───────┼──────► │ nginx ─┬─► wazuh.master (+ workers) ── alerts ──┐            │
 Beats / Elastic Agent ── 55044 ───────┘        │        ├─► wazuh.dashboard ──► wazuh indexer(s) ◄┘            │
                                                │        ├─► kibana ──► elasticsearch ◄── logstash ◄─┐          │
                                                │        └─► n8n, grafana, portainer                 │          │
                                                │                                                    │          │
                                                │ suricata, zeek ── tools-data/ ──► wazuh.master + logstash     │
                                                │ every manager ── alerts ≥ N8N_ALERT_LEVEL ──► n8n webhook      │
                                                │ n8n ──► Wazuh API (vexor-n8n user) / Elasticsearch (read-only) │
                                                └────────────────────────────────────────────────────────────────┘
```

| Flow | Path |
|---|---|
| Endpoint events | Agent → nginx (1514) → a manager → rules → alert → filebeat → Wazuh indexer |
| Network alerts | Suricata `eve.json` → master (alert and anomaly records only) → rules 100720/100721 → alert |
| Network logs | Zeek JSON logs → master (`ZEEK_WAZUH_LOGS`) → rules 100700–100703; all logs → Logstash |
| Wazuh to ELK | `SOC=both`: Logstash reads each manager's `alerts.json` → `vexor-wazuh-alerts-*` |
| Alerts to n8n | Every manager's `custom-n8n` integration posts the alert JSON to `http://n8n:5678/webhook/…` with an `X-Vexor-Token` header. With `SOC=elk`, Logstash posts Suricata alerts and Zeek notices instead. |
| n8n back into the stack | HTTP Request nodes call the Wazuh API (`https://wazuh.master:55000`) and Elasticsearch (`http://elasticsearch:9200`) with users from `vexor n8n credentials` |

Compose files: `docker-compose.yml` (Wazuh and nginx), `docker-compose.elk.yml`, `docker-compose.tools.yml` and the generated `docker-compose.override.yml`. `COMPOSE_FILE` and `COMPOSE_PROFILES` in `.env` select what starts, so always use `vexor`, not plain `docker compose up`.

The Docker Compose project is named `vexor` (`COMPOSE_PROJECT_NAME` in `.env`), so containers, volumes and the network are called `vexor-…`, `vexor_…` and `vexor_default`. Installs from before 2.0 used `wazuh` and keep that name until you run `vexor migrate`: it stops the stack, copies every `wazuh_*` volume to `vexor_*`, checks each copy, removes the old containers and network and starts the stack again. The old volumes stay until you confirm (or run `vexor migrate --yes` later), and it refuses to start without enough free disk for the copy. It also offers to remove unused images of the old Shuffle Wazuh app (`frikky/shuffle:*wazuh*`). `vexor doctor` and `vexor status` remind you while the old name is in use.

---

## The components

### Wazuh

`vexor install` generates the passwords, the cluster key and every internal certificate. It also removes the OpenSearch demo users, whose passwords are public, before the first start. The dashboard is served at `PROXY_PORT` (8080) through nginx, which also balances agent traffic over the managers.

```bash
vexor wazuh                      # indexer and manager cluster, API
vexor wazuh alerts --level 10    # newest alerts of every manager
vexor wazuh logtest              # test a log line against the rules
vexor agents list                # agents, status, node, version
vexor node-type multi            # grow to master + workers + 3 indexers
```

### ELK

`vexor soc both` (or `elk`) does the following:

- generates the Elastic passwords
- creates `vexor_logstash`, a user that can only write `vexor-*`
- applies ILM retention (`RETENTION_DAYS`, or `ELK_RETENTION_DAYS`) with 0 replicas
- adds Kibana data views for Wazuh alerts, Suricata, Zeek and Beats

Kibana is served at `KIBANA_PORT` (55601) through nginx. Elasticsearch listens on `127.0.0.1:ES_PORT` only.

```bash
vexor elk                                     # health, Kibana, events in the last hour
vexor elk search 'rule.level:>=10' -n 20      # Lucene search across vexor-*
vexor elk indices                             # index sizes
vexor elk beats-config                        # filebeat.yml for other machines
vexor elk es GET /_cat/health?v               # raw API
```

### n8n

n8n is the response engine. `vexor n8n connect [path]` sets up alert delivery to an n8n webhook (default path `vexor-alerts`). Only alerts at or above `N8N_ALERT_LEVEL` (default 7) are sent, optionally limited to `N8N_ALERT_GROUPS`.

- **`SOC=wazuh` or `both`:** vexor installs a `custom-n8n` integration on every manager. Agents are balanced across managers, so each manager must send its own alerts.
- **`SOC=elk`:** Logstash forwards Suricata alerts and Zeek notices instead.

Every call carries `X-Vexor-Token` (`N8N_HOOK_TOKEN`), so the workflow can reject anything else.

`vexor n8n workflow` imports and publishes a starter workflow, **Vexor - SOC alerts**:

1. A webhook receives the alert.
2. A code step checks the token and gives Wazuh, Suricata and Zeek events the same fields: `source`, `severity`, `level`, `title`, `where`, `alert`.
3. A switch routes by severity: critical (12+), high (7–11), medium (4–6) and low.
4. **Chat** (`N8N_NOTIFY_URL`): critical and high alerts are posted to Slack, Teams, Discord or any JSON webhook.
5. **AbuseIPDB** (`N8N_ABUSEIPDB_KEY`): public source IPs get a reputation score in the message.
6. **Block with approval** (`N8N_AUTO_BLOCK=approve`): a critical alert with a public source IP posts an approve link; when it is opened within an hour, n8n runs `firewall-drop` on that agent through the Wazuh API.

Each step is skipped when its setting is empty. The credentials (Wazuh API, Elasticsearch, AbuseIPDB) are created inside n8n, so nothing secret is stored in the workflow.

`vexor n8n credentials` creates least-privilege accounts for those actions:

- **Wazuh API user `vexor-n8n`:** can read and run agent commands, active response and syscheck.
- **Elasticsearch user `vexor_n8n`:** can read `vexor-*`.

```bash
vexor n8n                        # owner account, forwarding per manager, webhook registered, errors
vexor n8n connect --level 10     # change the threshold
vexor n8n test                   # fake alert through the published workflow; shows which steps ran
vexor n8n backup                 # export workflows + credentials (credentials stay encrypted)
```

n8n has no account until someone opens it: the first visitor becomes the owner, so open it right after enabling it.

`vexor n8n test [--level N] [--srcip IP]` posts a fake alert (default level 12, source 192.0.2.10) from inside the n8n container with the `X-Vexor-Token`, then reads the run for up to 40 seconds and prints one line per workflow step: ✔ ran, – not reached, ✘ error. It tells you when the workflow is not published or when it checks another token. With `N8N_AUTO_BLOCK=approve` the test also sends an approval request to chat; nothing is blocked unless someone opens the link.

### Suricata

Suricata runs on the host network and sniffs `SNIFF_INTERFACE` (default: the interface of the default route). vexor downloads the ET Open rules and fixes their ownership so Suricata can read them. It refreshes the rules daily without a restart.

Wazuh reads only alert and anomaly records. Stats and flow records have hundreds of fields that Wazuh's JSON decoder rejects. High-severity alerts become level 10, medium level 7.

```bash
vexor suricata                   # signatures, eve.json, alerts in 24 h, top signatures
vexor suricata alerts --since 1h
vexor suricata test              # real test traffic -> Suricata -> Wazuh -> Elasticsearch
vexor suricata update-rules
```

### Zeek

Zeek writes JSON logs and rotates them hourly into `tools-data/zeek/logs`; copies are kept for `TOOLS_LOG_RETENTION_DAYS`.

- **Wazuh** reads the logs listed in `ZEEK_WAZUH_LOGS` (default: notice, weird, dns, http, ssl, ssh; `conn` is large, so add it on purpose). Notices become level 6, failed SSH logins level 5.
- **Logstash** sends them to `vexor-zeek-*`.

```bash
vexor zeek                       # current logs, size, freshness, who reads them
vexor zeek show dns -n 20        # readable lines of one log
vexor zeek top hosts             # top talkers (also: ports, dns)
vexor zeek test
```

### Grafana and Portainer

Grafana gets an OpenSearch datasource with the read-only indexer user `grafana` and a **Wazuh alerts overview** dashboard. Portainer's admin password comes from `PORTAINER_ADMIN_PASSWORD`. Both are served only through nginx, on `GRAFANA_PORT` (53000) and `PORTAINER_PORT` (59443).

### Vexor Console

A web UI for the whole stack at `https://<host>:CONSOLE_PORT` (50443), on by default (`CONSOLE=true`). It runs on the host as the `vexor-console` service, uses the dashboard certificate, and signs in with `CONSOLE_USER` / `CONSOLE_PASSWORD` (`vexor console password`). The generated password works for the first sign-in only: the console asks for a new one (12 characters or more) before it shows anything else.

| Page | What you can do |
|---|---|
| Overview | Stack, containers running, last health check, disk usage per drive (amber from 85%, red from 95%), links to every UI, reminders, quick actions |
| Containers | State, CPU, memory, ports, image; logs and live log follow; start, stop, restart |
| Ports | Every port from `.env` with what uses it and whether it listens; edit, check (range, duplicates, in use), apply |
| Volumes | Every volume with its size and users; back up one or all, full backup, remove unused |
| Stacks | Per stack: status, tests, alerts, n8n connect, Zeek logs, enable or disable tools, switch SOC, node type, workers |
| Health | Doctor, doctor --fix, recent errors, AI report, notifications |
| Logins | Every login Vexor manages (url, user, password); passwords stay hidden until you show or copy one, and each reveal is audited |
| Settings | Every `.env` value (secrets hidden), edit and apply; rotate passwords |
| Terminal | Any `vexor` command, with suggestions and history |
| Activity | Every command run from the console, and the audit log |
| Reset | `uninstall --keep-data` (keeps volumes and generated files), `uninstall` (removes project volumes and generated files), remove unused volumes, remove unused images. Neither uninstall removes images. Each asks you to type its name |

Every action is a `vexor` command, run without a shell from an allowlist, so the console and the CLI behave the same. Reading runs at once, changes ask for confirmation, and anything that deletes data or switches layout asks you to type the command name. Commands that need a terminal (`shell`, `exec`, `wazuh logtest`, `config edit`) stay in SSH. All actions go to `.state/console-audit.log`.

```bash
vexor console                 # is it up, where
vexor console disable         # stop it (CONSOLE=false)
vexor console password --generate
```

---

## Change management

After editing `.env`, validate and apply. **Never use `down -v` or `reset` to apply settings**: they delete the volumes that hold every alert, agent key, rule and workflow.

```bash
vexor plan                    # what the apply would change: settings, containers, downtime
vexor config validate && vexor config apply && vexor doctor
```

`vexor plan KEY=VALUE` previews a change before you write it, and `config apply` prints the plan first (and asks, when you run it in a terminal). The console shows the same plan in its confirmation.

| You changed | Apply with |
|---|---|
| Ports, heap sizes, log rotation, images | `vexor config apply` |
| `SOC`, `NODE_TYPE`, `WORKER_COUNT` | `vexor soc …`, `vexor node-type …`, `vexor scale …` |
| A tool flag, `SNIFF_INTERFACE`, `ZEEK_WAZUH_LOGS` | `vexor tools apply` |
| `N8N_ALERT_LEVEL`, `N8N_ALERT_GROUPS`, webhook path | `vexor n8n connect [path] --level N --groups G` |
| Any password | `vexor passwd admin\|kibanaserver\|api`, `vexor elk reset-password`; editing `.env` alone breaks logins |
| `WAZUH_VERSION` | `vexor update apply <version>` |
| `PUBLIC_HOST`, certificate names | `vexor cert create` |
| `BIND_IP` | `vexor config apply` |
| `BACKUP_TIME`, `MAINT_TIME`, `HEALTH_INTERVAL` | `vexor daemon install` |
| `config/wazuh_cluster/*.conf` | Edit **every** manager file, then `vexor restart managers` |
| `config/nginx/nginx.conf.tpl` | `vexor config apply` (`nginx.conf` is generated) |

`vexor restart` **recreates** manager containers: the Wazuh image applies the mounted `ossec.conf` only to a fresh container. The data lives in volumes, so this is safe.

Never put a comment on the same line as an **empty** value in `.env`: Docker Compose reads `KEY=   # comment` as the value `# comment`. `vexor doctor --fix` repairs such lines.

---

## Data, retention and backups

| Data | Where | Retention |
|---|---|---|
| Wazuh alerts | `wazuh-alerts-*` and `wazuh-archives-*` in the Wazuh indexer | `RETENTION_DAYS` (ISM; `INDEX_RETENTION_DAYS` overrides) |
| ELK events | `vexor-wazuh-alerts-*`, `vexor-suricata-*`, `vexor-zeek-*`, `vexor-beats-*` | `RETENTION_DAYS` (ILM; `ELK_RETENTION_DAYS` overrides) |
| Suricata and Zeek logs | `tools-data/` | `TOOLS_LOG_RETENTION_DAYS` |
| n8n workflows and credentials | `n8n-data` volume | kept; `vexor n8n backup` exports them |
| Manager logs | `/var/ossec/logs` (volume) | `MANAGER_LOG_RETENTION_DAYS` |
| Container logs | Docker `json-file` | `LOG_MAX_SIZE` × `LOG_MAX_FILE` |

Disk space: `vexor disk` shows free space on every filesystem Docker uses (add `--json` for scripts). Volumes left behind by a layout change, such as worker or indexer data after `vexor node-type single`, are listed by `vexor volumes orphans` and removed by `vexor volumes prune` after you confirm. Volumes of switched-off tools are never counted as unused. After an upgrade, `vexor images prune` removes the old image versions of this stack; `vexor update apply` offers it at the end. Both only touch this Docker Compose project.

`RETENTION_DAYS` (default 30) is how long alerts and events are kept; `0` keeps them forever. The indexers delete old data by themselves: an ISM policy `wazuh-retention` on the Wazuh indexer and an ILM policy `vexor-retention` in Elasticsearch. `vexor retention status` shows both and how many indices they cover, and `vexor retention apply` sets them. The policies are applied at start, after install and in the daily maintenance. An existing `.env` keeps its `INDEX_RETENTION_DAYS=90`, so delete that line to use `RETENTION_DAYS`.

`vexor backup` (daily with the daemon) saves an indexer snapshot, the master's state, the n8n, Grafana and Portainer volumes, and the configuration. Restore with `vexor backup restore-snapshot | restore-manager | restore-config`. Keep `.env`: it holds `N8N_ENCRYPTION_KEY`, without which n8n credentials cannot be decrypted. With `SOC=elk` or `both` the backup also takes an Elasticsearch snapshot of `vexor-*` and the Kibana saved objects (repository `backups/es-snapshots`); restore with `vexor backup restore-es <id>`.

---

## Self-healing and troubleshooting

`vexor daemon install` sets up `vexor.service` (start at boot) and four timers:

- **Watchdog**, every 5 minutes: starts enabled containers that are down and clears read-only index blocks.
- **Health check**, every hour (`HEALTH_INTERVAL`): runs `doctor --fix` and re-checks. Anything still broken produces an AI-ready report, a reminder, and a notification.
- **Backup**, daily (`BACKUP_TIME`).
- **Maintenance**, daily (`MAINT_TIME`): prunes logs, applies retention, renews certificates, updates the Suricata rules and rotates the sensor logs.

### Problems Vexor detects and repairs

Each of these came from a real failure while building and running the stack:

| Problem | Repair |
|---|---|
| Demo indexer users with public default passwords (`readall`/`readall` …) | Removes them |
| Suricata stats records flooding Wazuh with *Too many fields for JSON decoder* | Lets Wazuh read only alert and anomaly records |
| Suricata runs with 0 signatures | Downloads the rules, fixes ownership, reloads |
| The n8n integration script missing on a manager (new worker, reset volume) | Installs it, recreates the manager |
| n8n webhook not registered (workflow not published) | Warns; `vexor n8n workflow` |
| An integration target down | Warns with the count of failed deliveries |
| A manager runs an older `ossec.conf` than `config/` | Recreates it |
| An empty `.env` value followed by a comment; a key defined twice | Moves the comment; comments out the earlier key |
| An image download fails on a network or TLS error | Retries with back-off |
| Elasticsearch yellow on one node, read-only blocks, ILM missing | Replicas 0, clears the block, applies ILM |
| `kibana_system` or the Logstash writer cannot log in | Resets the user or role |
| nginx out of date, http:// on an HTTPS port | Re-renders and reloads nginx |

Notifications go to `NOTIFY_URL` (a Slack, Teams or Discord incoming webhook, or any URL that takes JSON). When it is empty and n8n is connected, they go to your n8n webhook as a Wazuh-shaped alert, so the starter workflow routes them by severity. `NOTIFY_ON=fail|warn|off` decides when; a problem that lasts is sent again every `NOTIFY_REPEAT_HOURS`, and a recovered message follows. The watchdog also reports containers it had to start.

```bash
vexor notify test         # send a test notification
vexor doctor              # about 60 checks, each problem with a hint
vexor doctor --fix        # repair what can be repaired
vexor wait-ready          # wait until every enabled service answers (--timeout 300, --json, or name services)
vexor ai-context --print  # one report to paste into any AI assistant (secrets masked)
```

| Symptom | What to check |
|---|---|
| Agent stays *never connected* | Normal for about a minute. Otherwise 1514/tcp is not reachable from the endpoint. |
| Browser warns about the certificate | `vexor cert create`, then trust the CA (`vexor cert export-ca`) |
| The machine got a new IP or moved | Nothing to edit while `PUBLIC_HOST` is empty. `vexor doctor` says when the certificate no longer covers the address: `vexor cert create`. |
| n8n shows no executions | `vexor n8n`: is the webhook registered and is the level threshold right? Then `vexor n8n test`. |
| Suricata has no alerts | `vexor suricata test`; is `SNIFF_INTERFACE` the interface the traffic uses? |
| Kibana returns 502 | Still starting (2–3 min on the first run) |
| Grafana "Test connection" shows *Index not found* | A quirk of the plugin's health check; dashboard queries work |

---

## Security

- `.env`, the certificate folders and `backups/` hold secrets. `vexor` keeps them root-only and `.gitignore` keeps them out of git.
- Every UI is served only through nginx (TLS 1.2/1.3). The Wazuh indexer and Elasticsearch APIs bind to `127.0.0.1`. n8n is reached by the stack on the internal Docker network.
- Generated accounts get only what they need:
  - Grafana: read the Wazuh indices.
  - Logstash: write `vexor-*`.
  - `vexor-n8n`: agent actions and active response.
  - `vexor_n8n`: read `vexor-*`.
- Alerts sent to n8n carry a secret token (`N8N_HOOK_TOKEN`); the starter workflow drops calls without it.
- Fresh installs require a password for agent enrollment (`ENROLL_PASSWORD_ON_INSTALL=yes`); `vexor agents enroll-cmd` includes it. On older installs turn it on with `vexor agents password on`.
- The Logstash Beats input uses TLS with a certificate from the internal CA (`LOGSTASH_BEATS_TLS=true` on new installs; existing installs keep plain TCP until you switch, and doctor warns). Senders get their settings from `vexor elk beats-config` and the CA from `vexor elk beats-ca`.
- Published ports listen on `BIND_IP` (default `0.0.0.0`, all interfaces). Set it to one address of the machine to publish only there. The console follows it unless `CONSOLE_BIND` is set.
- Firewall:
  - Allow 1514 and 1515/tcp, and 514/udp, from endpoints.
  - Allow 8080 and the tool ports from administrators.
  - Keep 55000 and 55044 restricted.
- `vexor ai-context` and `vexor support-bundle` mask passwords, hashes, tokens and keys. Review them anyway before sharing.

---

## CI/CD and the landing page

Two GitHub Actions workflows live in `.github/workflows/`:

| Workflow | Runs on | What it does |
|---|---|---|
| `ci.yml` | every push and pull request | Checks `vexor` with `bash -n` and ShellCheck. Validates the compose files for each SOC mode with `.env.example`. Checks that the committed tool and ELK compose files match what `vexor` generates. Scans for leaked secrets with gitleaks. |
| `pages.yml` | pushes to `main` that touch `docs/` (or a manual run) | Publishes `docs/` to GitHub Pages: <https://eswarans-06.github.io/Vexor/> |

To enable Pages on a fork, set **Settings → Pages → Source** to **GitHub Actions**.

---

## Repository layout

```
Vexor/
├── vexor                         # the CLI (see VEXOR.md)
├── .env.example                  # every setting; copied to .env by `vexor install`
├── docker-compose.yml            # Wazuh services + nginx (profiles select the layout)
├── docker-compose.elk.yml        # Elasticsearch, Logstash, Kibana (generated by vexor)
├── docker-compose.tools.yml      # n8n, Suricata, Zeek, Grafana, Portainer (generated by vexor)
├── generate-indexer-certs.yml    # one-shot internal certificate generator
├── config/
│   ├── certs.yml                 # nodes the internal certificates are issued for
│   ├── wazuh_cluster/            # ossec.conf for the master and each worker
│   ├── wazuh_indexer/            # opensearch.yml per node + internal users
│   ├── wazuh_dashboard/          # dashboard config + Wazuh API connection
│   └── nginx/nginx.conf.tpl      # the template nginx.conf is rendered from
├── console/                      # Vexor Console: server.py (python3 stdlib) + ui/
├── docs/                         # landing page: index.html + assets/ (GitHub Pages, no build step)
├── .github/workflows/            # ci.yml, pages.yml
├── .gitleaks.toml                # secret-scan settings used by CI
└── README.md · VEXOR.md · LICENSE
```

Created at run time and ignored by git: `.env`, `.state/`, `backups/`, `reports/`, `tools-data/`, certificates, `config/tools/` (n8n workflow file, integration script, Grafana provisioning, Zeek script, tool rules), `config/elk/`, `docker-compose.override.yml` and `nginx.conf`.

---

## Limitations

- Everything runs on one host. The clusters protect against a failed container, not a failed host.
- Up to three workers are predefined.
- Wazuh 5.x uses a different deployment layout and is not covered by `vexor update apply`.
- Elasticsearch runs as a single node.

## License

MIT. See [LICENSE](LICENSE). Wazuh, Elasticsearch, Logstash, Kibana, n8n, Suricata, Zeek, Grafana and Portainer belong to their authors and keep their own licenses. Vexor contains deployment configuration and tooling around their official images.
