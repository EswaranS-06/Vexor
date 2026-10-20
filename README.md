# Vexor

Vexor runs a Security Operations Center stack on one Docker host — **Wazuh**, the **Elastic Stack (ELK)**, or **both** — and keeps it healthy with a single command-line tool, `vexor`.

You choose what runs in `.env`, and `vexor` wires it up: certificates, passwords, an nginx reverse proxy, retention, backups, a self-healing watchdog, and optional network sensors and tools. When something breaks, `vexor doctor` tells you what and why, and repairs the problems it knows how to fix.

**Landing page:** <https://eswarans-06.github.io/Vexor/> · **CLI reference:** [VEXOR.md](VEXOR.md)

---

## Contents

1. [What you get](#what-you-get)
2. [Requirements](#requirements)
3. [Quick start](#quick-start)
4. [Choosing what runs](#choosing-what-runs)
5. [Architecture](#architecture)
6. [Optional tools](#optional-tools)
7. [Change management](#change-management)
8. [Operations](#operations)
9. [Data, retention and backups](#data-retention-and-backups)
10. [Self-healing and troubleshooting](#self-healing-and-troubleshooting)
11. [Security](#security)
12. [Repository layout](#repository-layout)
13. [Limitations](#limitations)

---

## What you get

| | |
|---|---|
| **Wazuh SIEM** | Wazuh 4.14 managers, indexers and dashboard. Agents enroll on `1515` and send events on `1514`; nginx balances them across the managers. |
| **Elastic Stack** | Elasticsearch, Logstash and Kibana 9.5. Kibana is served over HTTPS through nginx; Beats and Elastic Agent send to Logstash. |
| **Both together** | With `SOC=both`, Logstash copies every Wazuh alert into Elasticsearch, so you can search the same alerts in the Wazuh dashboard and in Kibana. |
| **Single or multi node** | `NODE_TYPE=single` (1 manager, 1 indexer, about 8 GB RAM) or `multi` (master plus 1–3 workers, 3 indexers, about 16 GB). Switch any time; agents and alerts stay. |
| **Sensors** | Suricata IDS and Zeek network logs, fed into Wazuh and into Elasticsearch, with severity mapping and Zeek rules included. |
| **Tools** | Grafana (with a ready-made Wazuh alerts dashboard), Portainer and n8n, each on its own HTTPS port. |
| **Operations** | Certificates (local CA, your own, or Let's Encrypt), password changes on a running stack, upgrades with rollback, backups and restore, index retention. |
| **Self-healing** | A 5-minute watchdog, an hourly health check that runs about 60 checks and repairs known problems, reminders, and a status summary when you log in over SSH. |
| **AI-ready diagnostics** | `vexor ai-context` writes one Markdown report (architecture, settings, state, errors, secrets masked) to paste into any AI assistant. |

---

## Requirements

| Resource | Needed |
|---|---|
| OS | Linux with systemd (tested on Ubuntu 24.04) |
| Docker | Docker Engine 24 or later, with the Compose v2 plugin |
| RAM | `SOC=wazuh`: 8 GB (single) or 16 GB (multi). Add about 4 GB for ELK (`SOC=both`). `SOC=elk` alone: about 6 GB. |
| Disk | 100 GB or more for the Docker data root |
| Tools | `python3`, `openssl`, `curl`, `ss`, `flock` (`apt install python3 openssl curl iproute2 util-linux`) |
| Network | Free host ports: 8080, 1514, 1515, 514/udp and 55000 for Wazuh; the 5XXXX ports for ELK and tools |

`vexor install` sets the kernel setting the indexers need (`vm.max_map_count=262144`).

---

## Quick start

```bash
git clone https://github.com/EswaranS-06/Vexor.git
cd Vexor
sudo ./vexor install          # creates .env from .env.example, generates passwords and certificates, starts the stack
sudo ./vexor daemon install   # `vexor` on PATH, start at boot, watchdog, health checks, backups
vexor info --show-secrets     # dashboard URL and login
```

Open the Wazuh dashboard at `https://<host>:8080` and log in as `admin`. The first start takes 1–2 minutes.

To remove the browser certificate warning:

```bash
vexor cert create        # a certificate from a local CA, covering this host's IPs and names
vexor cert export-ca     # how to trust the CA on Windows, macOS, Linux, Firefox and Active Directory
```

To enroll a first agent:

```bash
vexor agents enroll-cmd windows --name pc-01     # also: linux, rpm, macos
```

---

## Choosing what runs

Three settings in `.env` decide the layout. Change them with a command; each one moves the data safely and keeps your agents.

| Setting | Values | Switch with |
|---|---|---|
| `SOC` | `wazuh` · `elk` · `both` | `vexor soc both` |
| `NODE_TYPE` | `single` · `multi` | `vexor node-type multi` |
| `WORKER_COUNT` | `1`–`3` (multi only) | `vexor scale 2` |

**`SOC=wazuh`** runs Wazuh only. This is the default.

**`SOC=elk`** runs Elasticsearch, Logstash and Kibana only. Suricata, Zeek and any Beats or Elastic Agent you point at `LOGSTASH_BEATS_PORT` feed Logstash. Wazuh is stopped: agents cannot report until you switch back, but their keys and every alert stay in the Wazuh volumes.

**`SOC=both`** runs the two side by side. Logstash reads the managers' `alerts.json` and writes `vexor-wazuh-alerts-*` indices in Elasticsearch.

**`NODE_TYPE=single`** runs one manager and one indexer. **`multi`** runs a master plus `WORKER_COUNT` workers and three indexers. Switching from multi to single first moves every shard onto the remaining indexer, then removes the others. Nothing is lost, and `--dry-run` shows the plan without changing anything.

---

## Architecture

```
            Agents ── 1514 events ──►┐            ┌──────────── one Docker host ────────────────────────┐
            Agents ── 1515 enroll ──►┼───────────►│ nginx ── stream ──► wazuh.master (+ workers)        │
            Browser ── 8080 HTTPS ──►┤            │   │                    │ filebeat (TLS)             │
            Browser ── 5XXXX HTTPS ─►┘            │   │                    ▼                            │
                                                   │   ├── 8080 ──► wazuh.dashboard ──► wazuh indexer(s) │
                                                   │   ├── 55601 ─► kibana ──────────► elasticsearch     │
                                                   │   └── 53000 / 59443 / 55678 ─► grafana, portainer,  │
                                                   │                                  n8n                │
            Beats / Elastic Agent ── 55044 ──────►│ logstash ◄── alerts.json, suricata, zeek            │
                                                   │ suricata, zeek (host network, SNIFF_INTERFACE)      │
                                                   └─────────────────────────────────────────────────────┘
```

| Service | Role | Runs when |
|---|---|---|
| `wazuh.master` | Enrollment, Wazuh API, rules and agent keys; analyses events | `SOC` = wazuh or both |
| `wazuh.worker`, `wazuh2.worker`, `wazuh3.worker` | Analyse events, ship alerts; sync from the master | `NODE_TYPE=multi` |
| `wazuh1.indexer` (+ 2, 3) | Wazuh alert store (OpenSearch) | wazuh or both (three in multi) |
| `wazuh.dashboard` | Wazuh UI | wazuh or both |
| `elasticsearch`, `logstash`, `kibana` | Elastic Stack | `SOC` = elk or both |
| `nginx` | HTTPS for every UI; balances agent traffic across managers | always |
| `suricata`, `zeek` | Network sensors on `SNIFF_INTERFACE` | `SURICATA=true`, `ZEEK=true` |
| `grafana`, `portainer`, `n8n` | Optional tools | `GRAFANA=true` and so on |

Compose files: `docker-compose.yml` (Wazuh and nginx), `docker-compose.elk.yml`, `docker-compose.tools.yml`, plus `docker-compose.override.yml`, which `vexor` generates. `COMPOSE_FILE` and `COMPOSE_PROFILES` in `.env` select what starts, so always use `vexor` rather than plain `docker compose up`.

---

## Optional tools

Turn a tool on with `vexor tools enable <name>`, or set `<NAME>=true` in `.env` and run `vexor tools apply`.

| Tool | Port (`.env`) | What `vexor` wires up |
|---|---|---|
| Suricata | — | Sniffs `SNIFF_INTERFACE`; downloads the ET Open rules (53,000+); `eve.json` goes to Wazuh, where high-severity alerts are raised to level 10 and medium to level 7, and to Elasticsearch when ELK runs. Logs are rotated daily. |
| Zeek | — | Network logs in JSON format, rotated hourly. Wazuh reads `ZEEK_WAZUH_LOGS`: notices become level 6, failed SSH logins level 5. |
| Grafana | `GRAFANA_PORT` 53000 | A read-only indexer user limited to the Wazuh indices, an OpenSearch datasource, and a "Wazuh alerts overview" dashboard |
| Portainer | `PORTAINER_PORT` 59443 | The admin password is set on first start (`PORTAINER_ADMIN_PASSWORD`) |
| n8n | `N8N_PORT` 55678 | HTTPS URLs and an encryption key. The first person to open it creates the owner account, so open it right after enabling. |

Every web tool is served only through nginx, over HTTPS, with the same certificate as the dashboard.

---

## Change management

After editing `.env`, validate the file and apply it. **Never use `down -v` or `reset` to apply settings**: they delete the volumes that hold every alert, agent key and rule.

```bash
vexor config validate
vexor config apply      # re-renders nginx and the override, recreates only what changed
vexor doctor
```

| You changed | Apply with |
|---|---|
| Ports, heap sizes, log rotation, images, plain values | `vexor config apply` |
| `SOC`, `NODE_TYPE`, `WORKER_COUNT` | `vexor soc …`, `vexor node-type …`, `vexor scale …` (or `config apply`, which asks first) |
| A tool flag (`GRAFANA=true` …) | `vexor tools apply` |
| Any password | `vexor passwd admin\|kibanaserver\|api`; editing `.env` alone breaks logins |
| `WAZUH_VERSION` | `vexor update apply <version>` |
| `PUBLIC_HOST`, certificate names | `vexor cert create` |
| `BACKUP_TIME`, `MAINT_TIME`, `HEALTH_INTERVAL` | `vexor daemon install` |
| `config/wazuh_cluster/*.conf` (`ossec.conf`) | Edit **every** manager file, then `vexor restart managers` |
| `config/nginx/nginx.conf.tpl` | `vexor config apply` (do not edit `nginx.conf`; it is generated) |
| `config/wazuh_indexer/*.yml` | `vexor restart indexer1`, waiting for green before the next indexer |

`vexor restart` **recreates** manager containers rather than restarting them. The Wazuh manager image copies the mounted `ossec.conf` only into a fresh container; a plain `docker restart` keeps the old config. Recreating is safe because the data lives in volumes.

One `.env` rule matters: never put a comment on the same line as an **empty** value. Docker Compose reads `KEY=   # comment` as the value `# comment`. Put comments on their own line; `vexor doctor --fix` repairs such lines.

---

## Operations

```bash
vexor status                       # containers, clusters, agents, ELK, disk, reminders
vexor logs master -f               # container logs;  vexor logs ossec worker  for Wazuh's own log files
vexor update                       # newer Wazuh 4.x? `update apply` pulls, backs up, switches, verifies
vexor passwd admin                 # change a password on the running stack
vexor agents list                  # agents, status, node, version, OS
vexor agents password on           # require a password for enrollment
vexor backup && vexor backup list
vexor stop | start                 # data stays; the watchdog leaves a stopped stack alone
```

The full command list is in [VEXOR.md](VEXOR.md).

---

## Data, retention and backups

| Data | Where | Retention |
|---|---|---|
| Wazuh alerts and archives | `wazuh-alerts-*` in the Wazuh indexer | `INDEX_RETENTION_DAYS` (ISM policy) |
| Alerts, sensors and Beats in ELK | `vexor-*` indices in Elasticsearch | `ELK_RETENTION_DAYS` (ILM policy, 0 replicas) |
| Manager logs | `/var/ossec/logs` (volume) | `MANAGER_LOG_RETENTION_DAYS` |
| Sensor logs | `tools-data/` | `TOOLS_LOG_RETENTION_DAYS` |
| Container logs | Docker `json-file` | `LOG_MAX_SIZE` × `LOG_MAX_FILE` |

`vexor backup` saves an indexer snapshot, the master's state (agent keys, rules, groups, API users), the tool data volumes and the configuration. It runs daily when the daemon is installed. Restore with `vexor backup restore-snapshot | restore-manager | restore-config`. Elasticsearch data is not part of the backup yet; copy the `elk-es-data` volume with `vexor volumes backup <volume> --stop`.

---

## Self-healing and troubleshooting

`vexor daemon install` sets up:

| Unit | When | What it does |
|---|---|---|
| `vexor.service` | boot | Starts the stack |
| `vexor-watchdog.timer` | every 5 min | Starts enabled containers that are down; clears read-only index blocks when the disk has room |
| `vexor-health.timer` | `HEALTH_INTERVAL` (1 h) | `doctor --fix`, then a re-check. If problems remain, it writes an AI-ready report and adds a reminder. |
| `vexor-backup.timer` | `BACKUP_TIME` | `vexor backup` |
| `vexor-maintenance.timer` | `MAINT_TIME` | Prunes logs, applies retention, renews certificates, updates Suricata rules, rotates sensor logs |

### Problems Vexor detects and repairs

These come from real failures seen while building and running the stack:

| Problem | Repair |
|---|---|
| Demo indexer users with public default passwords (`readall`/`readall` …) | Removes them (doctor fails until they are gone) |
| A manager runs an older `ossec.conf` than the one in `config/` | Recreates that manager |
| An empty `.env` value followed by a comment | Moves the comment onto its own line |
| A key defined twice in `.env` | Comments out the earlier definition (Compose uses the last one) |
| An image download fails on a network or TLS error | Retries each missing image four times with back-off |
| Another `vexor` run holds the lock (watchdog or health check) | Waits up to 3 minutes instead of failing |
| Suricata runs with 0 signatures (the rules folder was unreadable) | Downloads the rules, fixes ownership, reloads |
| An integration (webhook) target is down | Warns, with the count of failed deliveries |
| Elasticsearch yellow on one node, or a read-only block | Sets replicas to 0; clears the block |
| Kibana `kibana_system` login fails; Logstash writer cannot log in | Resets the user or role |
| A worker missing from the cluster; filebeat cannot reach the indexer | Restarts the affected node |
| http:// on the dashboard port gives 400; nginx config out of date | Re-renders and reloads nginx |

Anything else is reported with a hint. For a full picture:

```bash
vexor doctor              # ~60 checks, each problem with a hint
vexor doctor --fix        # repair what can be repaired
vexor ai-context --print  # paste into any AI assistant
```

| Symptom | What to check |
|---|---|
| Agent stays *never connected* | Normal for about a minute. Otherwise `1514/tcp` is not reachable from the endpoint; check the agent's `ossec.log`. |
| Browser warns about the certificate | `vexor cert create`, then trust `ca.crt` on the client (`vexor cert export-ca`) |
| Kibana returns 502 | It is still starting (2–3 min on the first run); `vexor doctor` explains |
| No alerts in Elasticsearch | `vexor doctor` checks the Logstash pipeline and its Elasticsearch user |
| Grafana "Test connection" shows *Index not found* | A known quirk of the OpenSearch plugin's health check; dashboard queries work. `vexor doctor` tests the datasource with a real query. |

---

## Security

- `.env`, `config/wazuh_indexer_ssl_certs/`, `config/nginx/certs/` and `backups/` hold secrets. `vexor` keeps them root-only, and `.gitignore` keeps them out of git.
- Every UI is reachable only through nginx (TLS 1.2/1.3). The Wazuh indexer and Elasticsearch APIs bind to `127.0.0.1`.
- Generated users get the least they need: Grafana gets read-only access to the Wazuh indices, Logstash can write `vexor-*` only, and the optional Shuffle user has read access plus active response.
- Agent enrollment is open by default. Protect it with `vexor agents password on`.
- Firewall: allow `1514`, `1515`/tcp and `514`/udp from endpoints; `8080` and the tool ports from administrators; keep `55000` and `55044` restricted.
- Reports from `vexor ai-context` and `vexor support-bundle` mask passwords, hashes, tokens and webhook IDs. Review them anyway before sharing.

---

## Repository layout

```
Vexor/
├── vexor                         # the CLI (see VEXOR.md)
├── .env.example                  # every setting; copied to .env by `vexor install`
├── docker-compose.yml            # Wazuh services + nginx (profiles select the layout)
├── docker-compose.elk.yml        # Elasticsearch, Logstash, Kibana (generated by vexor)
├── docker-compose.tools.yml      # Suricata, Zeek, Grafana, Portainer, n8n (generated by vexor)
├── generate-indexer-certs.yml    # one-shot internal certificate generator
├── config/
│   ├── certs.yml                 # nodes the internal certificates are issued for
│   ├── wazuh_cluster/            # ossec.conf for the master and each worker
│   ├── wazuh_indexer/            # opensearch.yml per node + internal users
│   ├── wazuh_dashboard/          # dashboard config + Wazuh API connection
│   └── nginx/nginx.conf.tpl      # the template vexor renders nginx.conf from
├── docs/index.html               # landing page (GitHub Pages)
├── README.md · VEXOR.md · LICENSE
```

Created at run time and ignored by git: `.env`, `.state/`, `backups/`, `reports/`, `tools-data/`, certificates, `config/tools/`, `config/elk/`, `docker-compose.override.yml` and `nginx.conf`.

---

## Limitations

- Everything runs on one host. The clusters protect against a failed container, not a failed host.
- Up to three workers are predefined. More workers need another compose service and certificate.
- Wazuh 5.x uses a different deployment layout and is not covered by `vexor update apply`.
- Elasticsearch runs as a single node and is not yet included in `vexor backup`.

## License

MIT. See [LICENSE](LICENSE). Wazuh, Elasticsearch, Logstash, Kibana, Suricata, Zeek, Grafana, Portainer and n8n are the work of their respective authors, under their own licenses; Vexor contains deployment configuration and tooling around their official images.
